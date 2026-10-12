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

package web

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/swissmakers/fail2ban-ui/internal/config"
	"github.com/swissmakers/fail2ban-ui/internal/fail2ban"
)

func retirementWebServer(t *testing.T, id string, enabled, isDefault bool) config.Fail2banServer {
	t.Helper()
	srv, err := config.UpsertServer(config.Fail2banServer{
		ID: id, Name: "Retire Web " + id, Type: "local",
		Enabled: enabled, EnabledSet: true, IsDefault: isDefault,
		SocketPath: "/tmp/" + id + "-web.sock", ConfigPath: "/config/f2b-" + id,
	})
	if err != nil {
		t.Fatalf("create %s: %v", id, err)
	}
	t.Cleanup(func() {
		_ = config.DeleteServer(id)
		fail2ban.GetManager().RemoveRetirement(id)
	})
	return srv
}

func deleteRetirementPhase(t *testing.T, body []byte) string {
	t.Helper()
	var resp struct {
		Retirement RetirementView `json:"retirement"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode %q: %v", string(body), err)
	}
	return resp.Retirement.Phase
}

// A disabled local server retires fully in the synchronous fallback path, and
// both repeated deletes and status queries are idempotent.
func TestDeleteServerRetiresToCompletionIdempotently(t *testing.T) {
	victim := retirementWebServer(t, "web-retire-victim", false, false)
	survivor := retirementWebServer(t, "web-retire-survivor", false, false)

	callDelete := func() (int, []byte) {
		c, w := newTestContext(http.MethodDelete, "/api/servers/"+victim.ID, "")
		c.Params = gin.Params{{Key: "id", Value: victim.ID}}
		DeleteServerHandler(c)
		return w.Code, w.Body.Bytes()
	}

	code, body := callDelete()
	if code != http.StatusAccepted {
		t.Fatalf("first delete status=%d body=%s", code, body)
	}
	if phase := deleteRetirementPhase(t, body); phase != config.RetirementRemoved {
		t.Fatalf("phase after drive=%q, want removed", phase)
	}
	if _, found := config.GetServerByID(victim.ID); found {
		t.Fatal("server configuration survived retirement")
	}
	if fail2ban.GetManager().IsRetiring(victim.ID) {
		t.Fatal("runtime retirement state survived removal")
	}

	// Second delete of the now-missing server is idempotent.
	code, body = callDelete()
	if code != http.StatusOK || deleteRetirementPhase(t, body) != config.RetirementRemoved {
		t.Fatalf("repeated delete status=%d body=%s", code, body)
	}

	// Status endpoint reports the terminal phase for a missing server.
	c, w := newTestContext(http.MethodGet, "/api/servers/"+victim.ID+"/retirement", "")
	c.Params = gin.Params{{Key: "id", Value: victim.ID}}
	GetServerRetirementHandler(c)
	if w.Code != http.StatusOK || deleteRetirementPhase(t, w.Body.Bytes()) != config.RetirementRemoved {
		t.Fatalf("status after removal code=%d body=%s", w.Code, w.Body.String())
	}

	// The unrelated server is untouched.
	if got, ok := config.GetServerByID(survivor.ID); !ok || got.Name != survivor.Name {
		t.Fatalf("survivor changed: %+v ok=%v", got, ok)
	}
}

// A delete that arrives while retirement is running reports progress and does
// not start a second generation.
func TestDeleteServerIsIdempotentWhileRetiring(t *testing.T) {
	srv := retirementWebServer(t, "web-retire-again", false, false)
	server, r, err := beginRetirement(srv.ID)
	if err != nil {
		t.Fatal(err)
	}
	if r.Generation == 0 {
		t.Fatal("missing retirement generation")
	}

	c, w := newTestContext(http.MethodDelete, "/api/servers/"+srv.ID, "")
	c.Params = gin.Params{{Key: "id", Value: srv.ID}}
	DeleteServerHandler(c)
	if w.Code != http.StatusAccepted {
		t.Fatalf("delete during retirement status=%d body=%s", w.Code, w.Body.String())
	}
	if phase := deleteRetirementPhase(t, w.Body.Bytes()); phase != config.RetirementRetiring {
		t.Fatalf("phase=%q, want retiring", phase)
	}
	if gen := fail2ban.GetManager().RetirementGeneration(srv.ID); gen != r.Generation {
		t.Fatalf("generation changed on repeated delete: %d != %d", gen, r.Generation)
	}

	// Finish the flow so cleanup has nothing left behind.
	if _, err := config.AdvanceServerRetirement(srv.ID, config.RetirementDraining); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	temp := newRetirementCoordinator(nil)
	temp.begin(server)
	temp.drive(ctx, srv.ID)
	if _, found := config.GetServerByID(srv.ID); found {
		t.Fatal("server should be gone after manual drive")
	}
}

// Retiring servers reject edits, tests and ban/unban callbacks.
func TestRetiringServerRejectsEditsAndCallbacks(t *testing.T) {
	srv := retirementWebServer(t, "web-retire-frozen", false, false)
	if _, _, err := beginRetirement(srv.ID); err != nil {
		t.Fatal(err)
	}

	body, _ := json.Marshal(srv)
	c, w := newTestContext(http.MethodPost, "/api/servers", string(body))
	UpsertServerHandler(c)
	if w.Code != http.StatusConflict {
		t.Fatalf("upsert status=%d body=%s", w.Code, w.Body.String())
	}

	if _, err := resolveServerForNotification(srv.ID, ""); err == nil {
		t.Fatal("callback for a retiring server must be rejected")
	}
	if _, err := resolveServerForNotification("", srv.Hostname); err == nil && srv.Hostname != "" {
		t.Fatal("hostname callback for a retiring server must be rejected")
	}
}

// After a restart there is no detained connector: the persisted phase drives a
// fresh runtime, which builds a temporary connector for release and finishes.
func TestRetirementResumesFromPersistedPhaseAfterRestart(t *testing.T) {
	srv := retirementWebServer(t, "web-retire-restart", false, false)

	if _, _, err := config.BeginServerRetirement(srv.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := config.AdvanceServerRetirement(srv.ID, config.RetirementDraining); err != nil {
		t.Fatal(err)
	}
	if _, err := config.AdvanceServerRetirement(srv.ID, config.RetirementReleasing); err != nil {
		t.Fatal(err)
	}
	if fail2ban.GetManager().IsRetiring(srv.ID) {
		t.Fatal("a fresh process must start without runtime retirement state")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	c := newRetirementCoordinator(nil)
	c.drive(ctx, srv.ID)

	if _, found := config.GetServerByID(srv.ID); found {
		t.Fatal("retirement did not finish from the persisted releasing phase")
	}
	if fail2ban.GetManager().IsRetiring(srv.ID) {
		t.Fatal("runtime state not cleaned up after resumed retirement")
	}
}

// A crash in the final removing phase repeats the config removal idempotently.
func TestRetirementRemovingPhaseIsIdempotentAfterRestart(t *testing.T) {
	srv := retirementWebServer(t, "web-retire-removing", false, false)
	if _, _, err := config.BeginServerRetirement(srv.ID); err != nil {
		t.Fatal(err)
	}
	for _, phase := range []string{config.RetirementDraining, config.RetirementReleasing, config.RetirementRemoving} {
		if _, err := config.AdvanceServerRetirement(srv.ID, phase); err != nil {
			t.Fatal(err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	newRetirementCoordinator(nil).drive(ctx, srv.ID)

	if _, found := config.GetServerByID(srv.ID); found {
		t.Fatal("server in removing phase was not removed")
	}
	// Driving a finished retirement again is a no-op.
	newRetirementCoordinator(nil).drive(ctx, srv.ID)
}
