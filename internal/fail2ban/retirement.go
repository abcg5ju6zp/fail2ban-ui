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
	"sync"

	"github.com/swissmakers/fail2ban-ui/internal/shared"
)

// ErrServerRetiring is returned when a new operation is admitted against a
// server whose deletion is in progress.
var ErrServerRetiring = errors.New("server is retiring and rejects new operations")

// retiringRuntime holds everything the retirement flow still needs after the
// connector left the live registry: the detained connector (so running
// reconciliation can finish and agent deregistration stays retryable), the
// persisted generation used as a fencing token, and the release outcome.
type retiringRuntime struct {
	mu         sync.Mutex
	conn       Connector
	server     shared.Fail2banServer
	generation int64
	released   bool
}

// MarkRetiring freezes a server at runtime. Its live connector is detained
// (never closed here), health probes, config sync and repair state are dropped,
// and the endpoint starts rejecting new operations. Idempotent.
func (m *Manager) MarkRetiring(server shared.Fail2banServer) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.markRetiringLocked(server)
}

func (m *Manager) markRetiringLocked(server shared.Fail2banServer) *retiringRuntime {
	if m.retiring == nil {
		m.retiring = make(map[string]*retiringRuntime)
	}
	if m.retiringTargets == nil {
		m.retiringTargets = make(map[string]int64)
	}
	entry := m.retiring[server.ID]
	if entry == nil {
		entry = &retiringRuntime{}
		m.retiring[server.ID] = entry
	}
	entry.mu.Lock()
	entry.server = server
	entry.generation = server.RetirementGeneration
	// Detain the live connector on first mark; later marks (or retries after
	// restart, where no live connector exists) leave the detained one alone.
	if entry.conn == nil {
		if conn := m.connectors[server.ID]; conn != nil {
			entry.conn = conn
			delete(m.connectors, server.ID)
		}
	}
	entry.mu.Unlock()
	target := m.operationTargets[server.ID]
	if target == "" {
		target = "server:" + server.ID
	}
	m.retiringTargets[target] = server.RetirementGeneration
	delete(m.configSync, server.ID)
	delete(m.health, server.ID)
	delete(m.repairAt, server.ID)
	return entry
}

// IsRetiring reports whether the server entry is frozen for deletion.
func (m *Manager) IsRetiring(serverID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.retiring[serverID] != nil
}

// RetirementGeneration returns the persisted fencing generation of a retiring
// server, or zero for live servers. Late workers and callbacks compare the
// generation they were admitted under with this value.
func (m *Manager) RetirementGeneration(serverID string) int64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if entry := m.retiring[serverID]; entry != nil {
		entry.mu.Lock()
		defer entry.mu.Unlock()
		return entry.generation
	}
	return 0
}

func (m *Manager) targetIsRetiringLocked(targetKey string) bool {
	_, ok := m.retiringTargets[targetKey]
	return ok
}

// reconcileRetiringLocked aligns the runtime retirement registry with the
// persisted server list during a manager reload. Live connectors of retiring
// entries are detained instead of released, and retirements that already
// disappeared are cleaned up.
func (m *Manager) reconcileRetiringLocked(servers []shared.Fail2banServer, old map[string]Connector) map[string]*retiringRuntime {
	if m.retiring == nil {
		m.retiring = make(map[string]*retiringRuntime)
	}
	if m.retiringTargets == nil {
		m.retiringTargets = make(map[string]int64)
	}
	detained := make(map[string]*retiringRuntime)
	for _, srv := range servers {
		if srv.RetirementPhase == "" {
			continue
		}
		entry := m.markRetiringLocked(srv)
		if entry.conn == nil && old[srv.ID] != nil {
			entry.mu.Lock()
			entry.conn = old[srv.ID]
			entry.mu.Unlock()
		}
		detained[srv.ID] = entry
	}
	for id, entry := range m.retiring {
		if detained[id] != nil {
			continue
		}
		entry.mu.Lock()
		conn := entry.conn
		entry.conn = nil
		entry.mu.Unlock()
		if conn != nil {
			if err := conn.Close(); err != nil {
				debugf("failed to close retired connector %s: %v", id, err)
			}
		}
		target := m.operationTargets[id]
		delete(m.retiring, id)
		delete(m.retiringTargets, target)
		m.operationGates.Delete(target)
		delete(m.operationTargets, id)
	}
	return detained
}

// ReleaseRetirement performs connection-type-specific teardown:
// agent connectors deregister their callbacks, SSH/local connectors release
// their local resources. Every step is idempotent and retryable; after a
// restart a temporary connector is created when no live one was detained.
func (m *Manager) ReleaseRetirement(ctx context.Context, serverID string) error {
	m.mu.RLock()
	entry := m.retiring[serverID]
	m.mu.RUnlock()
	if entry == nil {
		return nil
	}
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if entry.released {
		return nil
	}
	conn := entry.conn
	temporary := false
	if conn == nil {
		c, err := NewConnector(entry.server)
		if err != nil {
			return err
		}
		conn = c
		temporary = true
	}
	releaseErr := releaseRetiredConnector(ctx, conn)
	if temporary {
		_ = conn.Close()
	}
	if releaseErr != nil {
		return releaseErr
	}
	if !temporary {
		entry.conn = nil
	}
	entry.released = true
	return nil
}

func releaseRetiredConnector(ctx context.Context, conn Connector) error {
	if agent, ok := conn.(*AgentConnector); ok {
		if err := agent.Deregister(ctx); err != nil {
			return err
		}
	}
	return conn.Close()
}

// RemoveRetirement drops the detained connector, operation gate, target alias
// and all health/sync state of a retired server. Called once configuration has
// been removed. Idempotent.
func (m *Manager) RemoveRetirement(serverID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry := m.retiring[serverID]
	if entry != nil {
		entry.mu.Lock()
		conn := entry.conn
		entry.conn = nil
		entry.mu.Unlock()
		if conn != nil {
			if err := conn.Close(); err != nil {
				debugf("failed to close retired connector %s: %v", serverID, err)
			}
		}
		delete(m.retiring, serverID)
	}
	target := m.operationTargets[serverID]
	delete(m.retiringTargets, target)
	delete(m.operationTargets, serverID)
	m.operationGates.Delete(target)
	delete(m.configSync, serverID)
	delete(m.health, serverID)
	delete(m.repairAt, serverID)
}
