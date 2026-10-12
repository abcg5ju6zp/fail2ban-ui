// Fail2ban UI - A Swiss made, management interface for Fail2ban.
//
// Copyright (C) 2026 Swissmakers GmbH (https://swissmakers/ch)
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
	"errors"
	"log"
	"sync"
	"time"

	"github.com/swissmakers/fail2ban-ui/internal/config"
	"github.com/swissmakers/fail2ban-ui/internal/fail2ban"
	"github.com/swissmakers/fail2ban-ui/internal/operations"
	"github.com/swissmakers/fail2ban-ui/internal/storage"
)

// retirementTick bounds how quickly a blocked phase (agent unreachable,
// in-flight op) is retried.
const retirementTick = 2 * time.Second

// releaseTimeout bounds a single agent deregistration / connector close attempt.
const retirementReleaseTimeout = 30 * time.Second

// RetirementView is the queryable status of one server retirement.
type RetirementView struct {
	ServerID         string    `json:"serverId"`
	Phase            string    `json:"phase"`
	Generation       int64     `json:"generation"`
	Error            string    `json:"error,omitempty"`
	DefaultServerID  string    `json:"defaultServerId,omitempty"`
	ActiveOperations int       `json:"activeOperations"`
	UpdatedAt        time.Time `json:"updatedAt,omitzero"`
}

// Drives persisted retirements through their phases, with every side effect
// retried until it succeeds. A restart reconstructs it from the persisted rows
// and resumes at the recorded phase.
type serverRetirementCoordinator struct {
	manager *fail2ban.Manager
	engine  *operations.Engine
	store   *storage.OperationStore

	mu      sync.Mutex
	driving map[string]bool
	kick    chan struct{}
}

var retirementSvc *serverRetirementCoordinator

func newRetirementCoordinator(engine *operations.Engine) *serverRetirementCoordinator {
	return &serverRetirementCoordinator{
		manager: fail2ban.GetManager(),
		engine:  engine,
		store:   storage.SharedOperationStore(),
		driving: make(map[string]bool),
		kick:    make(chan struct{}, 1),
	}
}

// startRetirementLoop resumes every persisted retirement after a restart.
func startRetirementLoop(ctx context.Context) {
	if retirementSvc == nil {
		return
	}
	c := retirementSvc
	go func() {
		ticker := time.NewTicker(retirementTick)
		defer ticker.Stop()
		c.driveAll(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				c.driveAll(ctx)
			case <-c.kick:
				c.driveAll(ctx)
			}
		}
	}()
}

func (c *serverRetirementCoordinator) trigger() {
	select {
	case c.kick <- struct{}{}:
	default:
	}
}

func (c *serverRetirementCoordinator) driveAll(ctx context.Context) {
	for _, r := range config.ListServerRetirements() {
		c.mu.Lock()
		if c.driving[r.ServerID] {
			c.mu.Unlock()
			continue
		}
		c.driving[r.ServerID] = true
		c.mu.Unlock()
		go func(id string) {
			defer func() {
				c.mu.Lock()
				delete(c.driving, id)
				c.mu.Unlock()
			}()
			c.drive(ctx, id)
		}(r.ServerID)
	}
}

// drive advances a single retirement as far as its current phase allows.
func (c *serverRetirementCoordinator) drive(ctx context.Context, id string) {
	r, ok := config.GetServerRetirement(id)
	if !ok {
		// Row disappeared outside the flow: make sure the runtime is gone too.
		c.manager.RemoveRetirement(id)
		return
	}
	server, found := config.GetServerByID(id)
	if !found {
		c.manager.RemoveRetirement(id)
		return
	}
	// The runtime fence must always match the persisted state, even right
	// after a restart before any reload ran.
	c.manager.MarkRetiring(server)

	switch r.Phase {
	case config.RetirementRetiring:
		// Reload freezes connectors/default for all servers while preserving
		// the detained connector. Failure keeps the phase retryable.
		if err := config.ReloadFail2banManager(); err != nil {
			c.recordError(id, "freezing runtime before retirement: "+err.Error())
			return
		}
		if _, err := config.AdvanceServerRetirement(id, config.RetirementDraining); err != nil {
			c.recordError(id, err.Error())
			return
		}
		c.drive(ctx, id)
	case config.RetirementDraining:
		c.drain(ctx, id)
	case config.RetirementReleasing:
		c.release(ctx, id)
	case config.RetirementRemoving:
		c.remove(id)
	}
}

// drain cancels unclaimed jobs, settles interrupted ones and waits for every
// in-flight operation to leave the server.
func (c *serverRetirementCoordinator) drain(ctx context.Context, id string) {
	if _, err := c.cancelQueued(ctx, id); err != nil {
		c.recordError(id, "cancelling queued operations: "+err.Error())
		return
	}
	if err := c.settleInterrupted(ctx, id); err != nil {
		c.recordError(id, "settling interrupted operations: "+err.Error())
		return
	}
	active, err := c.inFlightCount(ctx, id)
	if err != nil {
		c.recordError(id, "counting in-flight operations: "+err.Error())
		return
	}
	if active > 0 {
		// Not a failure: the phase stays queryable until the job finishes.
		_, _ = config.RecordRetirementError(id, "waiting for in-flight operations to finish")
		return
	}
	if _, err := config.AdvanceServerRetirement(id, config.RetirementReleasing); err != nil {
		c.recordError(id, err.Error())
		return
	}
	c.drive(ctx, id)
}

// settleInterrupted finalises reconciling jobs that can no longer be verified
// because the process restarted without detaining their connector.
func (c *serverRetirementCoordinator) settleInterrupted(ctx context.Context, id string) error {
	if c.engine == nil {
		return nil
	}
	if _, err := c.manager.Connector(id); err == nil {
		// A detained connector exists: the reconcile loop can still verify the
		// real outcome; do not pre-empt it.
		return nil
	}
	ops, err := c.engine.InFlight(ctx)
	if err != nil {
		return err
	}
	for _, op := range ops {
		if op.ServerID != id || op.State != "reconciling" {
			continue
		}
		outcome := errors.New("server retired before the operation outcome could be verified")
		result := json.RawMessage(`{"error":"Operation cancelled because its server was retired"}`)
		if _, err := c.engine.Resolve(ctx, op.ID, result, outcome); err != nil &&
			!errors.Is(err, operations.ErrConflict) && !errors.Is(err, operations.ErrNotFound) {
			return err
		}
	}
	return nil
}

// release performs connection-type-specific teardown and keeps the phase
// retryable while the agent cannot be reached.
func (c *serverRetirementCoordinator) release(ctx context.Context, id string) {
	releaseCtx, cancel := context.WithTimeout(ctx, retirementReleaseTimeout)
	err := c.manager.ReleaseRetirement(releaseCtx, id)
	cancel()
	if err != nil {
		c.recordError(id, "releasing server resources (will retry): "+err.Error())
		return
	}
	if _, err := config.AdvanceServerRetirement(id, config.RetirementRemoving); err != nil {
		c.recordError(id, err.Error())
		return
	}
	c.drive(ctx, id)
}

// remove is the final, atomic-ish step: runtime state has already been
// detached and released; now the configuration row disappears.
func (c *serverRetirementCoordinator) remove(id string) {
	c.manager.RemoveRetirement(id)
	if err := config.FinishServerRetirement(id); err != nil {
		c.recordError(id, "removing server configuration (will retry): "+err.Error())
		return
	}
	// Best-effort reconciliation for the remaining servers/default. A failure
	// here no longer affects the retired server and is retried on the next
	// settings change or restart.
	if err := config.ReloadFail2banManager(); err != nil {
		log.Printf("warning: manager reload after server retirement failed: %v", err)
	}
}

func (c *serverRetirementCoordinator) recordError(id, msg string) {
	if _, err := config.RecordRetirementError(id, msg); err != nil {
		log.Printf("warning: could not record retirement error for %s: %v", id, err)
	}
}

func (c *serverRetirementCoordinator) cancelQueued(ctx context.Context, id string) (int64, error) {
	if c.engine != nil {
		return c.engine.CancelQueuedForServer(ctx, id)
	}
	return c.store.CancelQueuedForServer(ctx, id)
}

func (c *serverRetirementCoordinator) inFlightCount(ctx context.Context, id string) (int, error) {
	if c.engine != nil {
		return c.engine.InFlightCountForServer(ctx, id)
	}
	return c.store.InFlightCountForServer(ctx, id)
}

// begin marks the server retiring at runtime after its configuration was
// persisted. Called while operation admission is locked.
func (c *serverRetirementCoordinator) begin(server config.Fail2banServer) {
	c.manager.MarkRetiring(server)
	c.trigger()
}

// beginRetirement persists the retirement fence and detains the connector.
func beginRetirement(id string) (config.Fail2banServer, config.Retirement, error) {
	server, r, err := config.BeginServerRetirement(id)
	if err != nil {
		return config.Fail2banServer{}, config.Retirement{}, err
	}
	if retirementSvc != nil {
		retirementSvc.begin(server)
	} else {
		fail2ban.GetManager().MarkRetiring(server)
	}
	return server, r, nil
}

// retirementView assembles the persisted phase with live counters.
func retirementView(id string) RetirementView {
	r, ok := config.GetServerRetirement(id)
	if !ok {
		return RetirementView{ServerID: id, Phase: config.RetirementRemoved}
	}
	view := RetirementView{
		ServerID:   r.ServerID,
		Phase:      r.Phase,
		Generation: r.Generation,
		Error:      r.Error,
		UpdatedAt:  r.UpdatedAt,
	}
	if def := config.GetDefaultServer(); def.ID != "" && def.ID != id {
		view.DefaultServerID = def.ID
	}
	svc := retirementSvc
	if svc != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		if n, err := svc.inFlightCount(ctx, id); err == nil {
			view.ActiveOperations = n
		}
		cancel()
	}
	return view
}
