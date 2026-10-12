// Fail2ban UI - A Swiss made, management interface for Fail2ban.
//
// Copyright (C) 2026 Swissmakers GmbH (https://swissmakers.ch)
//
// Licensed under the GNU Affero General Public License, Version 3 (AGPL-3.0)
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.gnu.org/licenses/agpl-3.0.en.html
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fail2ban

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/swissmakers/fail2ban-ui/internal/shared"
)

// Minimal connector: only the methods the retirement flow touches are real.
type retireFakeConnector struct {
	Connector
	id     string
	closed atomic.Bool
}

func (c *retireFakeConnector) Server() shared.Fail2banServer {
	return shared.Fail2banServer{ID: c.id, Type: "local"}
}

func (c *retireFakeConnector) Close() error {
	c.closed.Store(true)
	return nil
}

func newRetirementManager(id, socket string, conn Connector) *Manager {
	m := &Manager{
		connectors:       map[string]Connector{id: conn},
		operationTargets: map[string]string{id: "local:" + socket},
		configSync:       map[string]*configSyncState{},
		health:           map[string]ServerHealth{},
		repairAt:         map[string]time.Time{},
		monitorKick:      make(chan struct{}, 1),
	}
	return m
}

func TestMarkRetiringDetainsConnectorAndFencesOperations(t *testing.T) {
	ctx := context.Background()
	const id = "rt-fence"
	fake := &retireFakeConnector{id: id}
	m := newRetirementManager(id, "/tmp/rt-fence.sock", fake)

	// An operation admitted before retirement keeps its lease.
	held, release, err := m.BeginOperation(ctx, id, "op-before", "jail.manage")
	if err != nil {
		t.Fatal(err)
	}
	defer release()

	srv := shared.Fail2banServer{ID: id, Type: "local", Enabled: true,
		SocketPath: "/tmp/rt-fence.sock", RetirementPhase: "retiring", RetirementGeneration: 7}
	m.MarkRetiring(srv)
	m.MarkRetiring(srv) // idempotent

	if _, live := m.connectors[id]; live {
		t.Fatal("live connector registry still contains the retiring server")
	}
	if !m.IsRetiring(id) {
		t.Fatal("IsRetiring false after mark")
	}
	if gen := m.RetirementGeneration(id); gen != 7 {
		t.Fatalf("generation=%d, want 7", gen)
	}
	if c, err := m.Connector(id); err != nil || c == nil {
		t.Fatalf("detained connector must stay reachable during drain: %v", err)
	}
	// New admissions are fenced; the already admitted lease remains valid.
	if _, _, err := m.BeginOperation(ctx, id, "op-after", "jail.manage"); !errors.Is(err, ErrServerRetiring) {
		t.Fatalf("new admission error=%v, want ErrServerRetiring", err)
	}
	heldAgain, reenter, err := m.BeginOperation(held, id, "op-before", "jail.manage")
	if err != nil || heldAgain == nil {
		t.Fatalf("reentrant admission broke after retirement: %v", err)
	}
	reenter()

	// Config sync is frozen and must not recreate its state.
	m.RequestConfigSync(id, true, true)
	if m.configSync[id] != nil {
		t.Fatal("config sync state recreated for a retiring server")
	}
	if err := m.SyncServerConfig(ctx, id); !errors.Is(err, ErrServerRetiring) {
		t.Fatalf("SyncServerConfig error=%v, want ErrServerRetiring", err)
	}

	// Release closes the detained local connector once, then idempotently.
	if err := m.ReleaseRetirement(ctx, id); err != nil {
		t.Fatalf("release: %v", err)
	}
	if !fake.closed.Load() {
		t.Fatal("detained connector was not closed at release")
	}
	if err := m.ReleaseRetirement(ctx, id); err != nil {
		t.Fatalf("second release: %v", err)
	}

	m.RemoveRetirement(id)
	if m.IsRetiring(id) {
		t.Fatal("retirement state survived removal")
	}
	if _, err := m.Connector(id); err == nil {
		t.Fatal("connector still resolvable after removal")
	}
	if _, ok := m.operationGates.Load("local:/tmp/rt-fence.sock"); ok {
		t.Fatal("operation gate survived removal")
	}
}

func TestReloadSkipsRetiringServersButKeepsOthersLive(t *testing.T) {
	const retireID, liveID = "rt-skip", "rt-live"
	retireFake := &retireFakeConnector{id: retireID}
	liveConn := NewLocalConnector(shared.Fail2banServer{ID: liveID, Type: "local", Enabled: true,
		SocketPath: "/tmp/rt-live.sock", ConfigPath: "/tmp/rt-live-cfg"})
	m := &Manager{
		connectors: map[string]Connector{retireID: retireFake, liveID: liveConn},
		operationTargets: map[string]string{
			retireID: "local:/tmp/rt-skip.sock",
			liveID:   "local:/tmp/rt-live.sock",
		},
		configSync:  map[string]*configSyncState{},
		health:      map[string]ServerHealth{},
		repairAt:    map[string]time.Time{},
		monitorKick: make(chan struct{}, 1),
	}
	t.Cleanup(m.Close)

	servers := []shared.Fail2banServer{
		{ID: retireID, Name: "Retiring", Type: "local", Enabled: true, SocketPath: "/tmp/rt-skip.sock",
			ConfigPath: "/tmp/rt-skip-cfg", RetirementPhase: "retiring", RetirementGeneration: 3},
		{ID: liveID, Name: "Live", Type: "local", Enabled: true, SocketPath: "/tmp/rt-live.sock",
			ConfigPath: "/tmp/rt-live-cfg"},
	}
	if err := m.ReloadFromServers(servers); err != nil {
		t.Fatalf("reload: %v", err)
	}

	if _, built := m.connectors[retireID]; built {
		t.Fatal("retiring server received a new live connector")
	}
	if !m.IsRetiring(retireID) || m.RetirementGeneration(retireID) != 3 {
		t.Fatal("retiring registry not reconciled from persisted servers")
	}
	entry := m.retiring[retireID]
	if entry == nil {
		t.Fatal("retiring entry missing")
	}
	entry.mu.Lock()
	detained := entry.conn
	entry.mu.Unlock()
	if detained != retireFake {
		t.Fatal("the previous connector was not detained for staged release")
	}
	if retireFake.closed.Load() {
		t.Fatal("reload closed the detained connector instead of detaining it")
	}
	if c := m.connectors[liveID]; c == nil {
		t.Fatal("unrelated live server lost its connector during retirement reload")
	}
	if id := m.defaultServerID; id != liveID {
		t.Fatalf("default=%s, want the surviving live server", id)
	}
}

func TestAgentRetirementDeregistersAndIsRetryable(t *testing.T) {
	var deregisters atomic.Int32
	var status atomic.Int32
	status.Store(http.StatusInternalServerError)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete && r.URL.Path == "/v1/callback/config" {
			deregisters.Add(1)
			w.WriteHeader(int(status.Load()))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	server := shared.Fail2banServer{ID: "rt-agent", Name: "agent", Type: "agent",
		AgentURL: srv.URL, AgentSecret: "secret",
		RetirementPhase: "releasing", RetirementGeneration: 9}
	conn, err := NewAgentConnector(server)
	if err != nil {
		t.Fatal(err)
	}
	m := &Manager{
		connectors:       map[string]Connector{server.ID: conn},
		operationTargets: map[string]string{server.ID: "agent:" + srv.URL},
		configSync:       map[string]*configSyncState{},
		health:           map[string]ServerHealth{},
		repairAt:         map[string]time.Time{},
		monitorKick:      make(chan struct{}, 1),
	}
	m.MarkRetiring(server)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Agent is reachable but failing: the phase stays retryable.
	if err := m.ReleaseRetirement(ctx, server.ID); err == nil {
		t.Fatal("expected deregistration failure to be returned for retry")
	}
	if deregisters.Load() != 1 {
		t.Fatalf("deregister calls=%d, want 1", deregisters.Load())
	}
	entry := m.retiring[server.ID]
	entry.mu.Lock()
	released := entry.released
	stillDetained := entry.conn != nil
	entry.mu.Unlock()
	if released || !stillDetained {
		t.Fatal("failed release must keep the connector detained")
	}

	// Agent recovers: deregistration succeeds and the connector closes.
	status.Store(http.StatusOK)
	if err := m.ReleaseRetirement(ctx, server.ID); err != nil {
		t.Fatalf("retry release: %v", err)
	}
	if deregisters.Load() != 2 {
		t.Fatalf("deregister calls=%d, want 2", deregisters.Load())
	}
	m.RemoveRetirement(server.ID)
}

func TestAgentDeregisterTreatsUnknownEndpointAsSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	conn, err := NewAgentConnector(shared.Fail2banServer{ID: "rt-old-agent", Type: "agent",
		AgentURL: srv.URL, AgentSecret: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.(*AgentConnector).Deregister(context.Background()); err != nil {
		t.Fatalf("404 from an old agent must be success: %v", err)
	}
}
