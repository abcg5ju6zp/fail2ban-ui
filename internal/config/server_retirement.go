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

package config

import (
	"errors"
	"fmt"
	"sort"
	"time"
)

// Retirement phases form a strictly ordered, recoverable state machine.
// Every transition is persisted before its side effects, so a process restart
// resumes from the same phase.
const (
	// RetirementRetiring: persisted fence; new operations and edits are rejected.
	RetirementRetiring = "retiring"
	// RetirementDraining: queued jobs are cancelled and running ones are awaited.
	RetirementDraining = "draining"
	// RetirementReleasing: agent deregistration or SSH/local resource release.
	RetirementReleasing = "releasing"
	// RetirementRemoving: configuration row and runtime connector are removed.
	RetirementRemoving = "removing"
	// RetirementRemoved is reported only after the row and runtime state are gone.
	RetirementRemoved = "removed"
)

// ErrServerRetiring is returned when an edit or operation targets a frozen server.
var ErrServerRetiring = errors.New("server is retiring and cannot be changed")

// retirementPhases in transition order.
var retirementPhases = []string{RetirementRetiring, RetirementDraining, RetirementReleasing, RetirementRemoving}

func validRetirementPhase(phase string) bool {
	return retirementPhaseRank(phase) >= 0
}

func retirementPhaseRank(phase string) int {
	for i, p := range retirementPhases {
		if p == phase {
			return i
		}
	}
	return -1
}

// Retirement is the queryable state of one server retirement.
type Retirement struct {
	ServerID   string    `json:"serverId"`
	Phase      string    `json:"phase"`
	Generation int64     `json:"generation"`
	Error      string    `json:"error,omitempty"`
	UpdatedAt  time.Time `json:"updatedAt,omitzero"`
}

func retirementFromServer(srv Fail2banServer) Retirement {
	return Retirement{
		ServerID:   srv.ID,
		Phase:      srv.RetirementPhase,
		Generation: srv.RetirementGeneration,
		Error:      srv.RetirementError,
		UpdatedAt:  srv.RetirementUpdatedAt,
	}
}

// BeginServerRetirement persistently marks a server as retiring and decides the
// default-server outcome. It is idempotent: a repeated call returns the stored
// state without changing its generation. A missing server is reported so the
// caller can treat the request as an already-completed deletion.
func BeginServerRetirement(id string) (Fail2banServer, Retirement, error) {
	settingsLock.Lock()
	defer settingsLock.Unlock()

	srv, found := serverByIDLocked(id)
	if !found {
		return Fail2banServer{}, Retirement{}, fmt.Errorf("server %s not found", id)
	}
	if srv.RetirementPhase != "" {
		return srv, retirementFromServer(srv), nil
	}

	now := time.Now().UTC()
	entry := srv
	entry.RetirementPhase = RetirementRetiring
	entry.RetirementGeneration = nextRetirementGenerationLocked()
	entry.RetirementError = ""
	entry.RetirementUpdatedAt = now

	// The default outcome is decided deterministically up front: when the
	// retiring server is the default, the earliest created other enabled server
	// replaces it; with no candidate there is simply no default afterwards.
	// The decision is applied to the persisted IsDefault flags immediately.
	entry.IsDefault = false
	if srv.IsDefault {
		if replacement := pickDefaultReplacementLocked(id); replacement != "" {
			for idx := range currentSettings.Servers {
				if currentSettings.Servers[idx].ID == replacement {
					currentSettings.Servers[idx].IsDefault = true
					break
				}
			}
		}
	}

	for idx := range currentSettings.Servers {
		if currentSettings.Servers[idx].ID == id {
			currentSettings.Servers[idx] = entry
			break
		}
	}
	if err := persistServersLocked(); err != nil {
		return Fail2banServer{}, Retirement{}, err
	}
	return cloneServer(entry), retirementFromServer(entry), nil
}

// ChooseDefaultReplacement reports which enabled server (if any) would become
// the default when the given server retires. Empty string means "no default".
func ChooseDefaultReplacement(id string) string {
	settingsLock.RLock()
	defer settingsLock.RUnlock()
	return pickDefaultReplacementLocked(id)
}

// Earliest-created other enabled, non-retiring server; deterministic and order independent.
func pickDefaultReplacementLocked(retiringID string) string {
	candidates := make([]Fail2banServer, 0, len(currentSettings.Servers))
	for _, srv := range currentSettings.Servers {
		if srv.ID == retiringID || !srv.Enabled || srv.RetirementPhase != "" {
			continue
		}
		candidates = append(candidates, srv)
	}
	if len(candidates) == 0 {
		return ""
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		return candidates[i].CreatedAt.Before(candidates[j].CreatedAt)
	})
	return candidates[0].ID
}

func nextRetirementGenerationLocked() int64 {
	var max int64
	for _, srv := range currentSettings.Servers {
		if srv.RetirementGeneration > max {
			max = srv.RetirementGeneration
		}
	}
	return max + 1
}

// AdvanceServerRetirement persists a forward phase transition and clears the
// previous error. It never moves backwards and refuses a non-retiring server.
func AdvanceServerRetirement(id, phase string) (Retirement, error) {
	if !validRetirementPhase(phase) {
		return Retirement{}, fmt.Errorf("invalid retirement phase %q", phase)
	}
	settingsLock.Lock()
	defer settingsLock.Unlock()
	for idx := range currentSettings.Servers {
		srv := &currentSettings.Servers[idx]
		if srv.ID != id {
			continue
		}
		if srv.RetirementPhase == "" {
			return Retirement{}, fmt.Errorf("server %s is not retiring", id)
		}
		if retirementPhaseRank(phase) < retirementPhaseRank(srv.RetirementPhase) {
			return retirementFromServer(*srv), nil
		}
		srv.RetirementPhase = phase
		srv.RetirementError = ""
		srv.RetirementUpdatedAt = time.Now().UTC()
		if err := persistServersLocked(); err != nil {
			return Retirement{}, err
		}
		return retirementFromServer(*srv), nil
	}
	return Retirement{}, fmt.Errorf("server %s not found", id)
}

// RecordRetirementError stores a retryable failure while staying in the phase,
// so the background driver repeats the failed side effect after restart.
func RecordRetirementError(id, errMsg string) (Retirement, error) {
	settingsLock.Lock()
	defer settingsLock.Unlock()
	for idx := range currentSettings.Servers {
		srv := &currentSettings.Servers[idx]
		if srv.ID != id {
			continue
		}
		if srv.RetirementPhase == "" {
			return Retirement{}, fmt.Errorf("server %s is not retiring", id)
		}
		srv.RetirementError = errMsg
		srv.RetirementUpdatedAt = time.Now().UTC()
		if err := persistServersLocked(); err != nil {
			return Retirement{}, err
		}
		return retirementFromServer(*srv), nil
	}
	return Retirement{}, fmt.Errorf("server %s not found", id)
}

// FinishServerRetirement removes the configuration row. Runtime connector
// teardown happens before this is called, so a crash here simply repeats a
// configuration delete on restart.
func FinishServerRetirement(id string) error {
	settingsLock.Lock()
	defer settingsLock.Unlock()
	index := -1
	for i, srv := range currentSettings.Servers {
		if srv.ID == id {
			index = i
			break
		}
	}
	if index == -1 {
		return nil
	}
	currentSettings.Servers = append(currentSettings.Servers[:index], currentSettings.Servers[index+1:]...)
	normalizeServersLocked()
	return persistServersLocked()
}

// GetServerRetirement returns the persisted retirement state of a server.
func GetServerRetirement(id string) (Retirement, bool) {
	settingsLock.RLock()
	defer settingsLock.RUnlock()
	srv, found := serverByIDLocked(id)
	if !found || srv.RetirementPhase == "" {
		return Retirement{}, false
	}
	return retirementFromServer(srv), true
}

// ListServerRetirements returns every in-progress retirement, phase order.
func ListServerRetirements() []Retirement {
	settingsLock.RLock()
	defer settingsLock.RUnlock()
	out := make([]Retirement, 0, len(currentSettings.Servers))
	for _, srv := range currentSettings.Servers {
		if srv.RetirementPhase != "" {
			out = append(out, retirementFromServer(srv))
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := retirementPhaseRank(out[i].Phase), retirementPhaseRank(out[j].Phase)
		if ri != rj {
			return ri < rj
		}
		return out[i].ServerID < out[j].ServerID
	})
	return out
}
