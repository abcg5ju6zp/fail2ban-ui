// Fail2ban UI - A Swiss made, management interface for Fail2Ban.
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
	"log"
	"time"

	"github.com/swissmakers/fail2ban-ui/internal/config"
	"github.com/swissmakers/fail2ban-ui/internal/integrations"
	"github.com/swissmakers/fail2ban-ui/internal/storage"
)

// Periodic background convergence for permanent firewall actions:
//   - flushes outcomes that succeeded externally but missed their SQLite
//     write (no firewall calls are repeated);
//   - resumes rows left pending/unknown by cancellation, a process restart
//     or an inconclusive integration response, continuing each one's
//     original action through the same generation-aware commit.
const (
	permanentOutboxInterval  = 10 * time.Second
	permanentRecoverInterval = 30 * time.Second
	permanentRecoverBatch    = 100
)

// StartPermanentActionRecovery runs convergence immediately and then until
// rootCtx is canceled.
func StartPermanentActionRecovery(rootCtx context.Context) {
	if rootCtx == nil {
		rootCtx = context.Background()
	}
	go func() {
		runPermanentActionConvergence(rootCtx)
	}()
}

func runPermanentActionConvergence(rootCtx context.Context) {
	flushPermanentOutbox(rootCtx)
	recoverPermanentActions(rootCtx)

	outboxTicker := time.NewTicker(permanentOutboxInterval)
	defer outboxTicker.Stop()
	recoverTicker := time.NewTicker(permanentRecoverInterval)
	defer recoverTicker.Stop()

	for {
		select {
		case <-rootCtx.Done():
			return
		case <-outboxTicker.C:
			flushPermanentOutbox(rootCtx)
		case <-recoverTicker.C:
			flushPermanentOutbox(rootCtx)
			recoverPermanentActions(rootCtx)
		}
	}
}

func flushPermanentOutbox(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	flushCtx, cancel := context.WithTimeout(ctx, permanentWriteTimeout)
	defer cancel()
	if err := storage.FlushPendingPermanentBlocks(flushCtx); err != nil {
		log.Printf("WARNING: permanent block writeback incomplete: %v", err)
	}
}

// recoverPermanentActions resumes every interrupted generation through the
// shared committer, which verifies the integration side first and only
// dispatches when the remote fact contradicts the desired action.
func recoverPermanentActions(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	rows, err := storage.ListRecoverablePermanentActions(ctx, permanentRecoverBatch)
	if err != nil {
		if ctx.Err() == nil {
			log.Printf("WARNING: failed to list recoverable permanent actions: %v", err)
		}
		return
	}
	if len(rows) == 0 {
		return
	}

	settings := config.GetSettings()
	for _, row := range rows {
		if ctx.Err() != nil {
			return
		}
		action := row.DesiredAction
		if action != storage.PermanentActionBlock && action != storage.PermanentActionUnblock {
			continue
		}
		integration, ok := integrations.Get(row.Integration)
		if !ok {
			continue
		}
		// Use the persisted row's integration identity; its vendor section
		// in the current settings determines whether it is still usable.
		entrySettings := settings
		entrySettings.AdvancedActions.Integration = row.Integration
		if err := integration.Validate(entrySettings.AdvancedActions); err != nil {
			continue
		}
		result := commitPermanentAction(ctx, entrySettings, action, row.IP, row.ServerID, map[string]any{
			"reason":     "recovery",
			"generation": row.Generation,
			"attempts":   row.Attempts,
		})
		if result.Err != nil {
			log.Printf("WARNING: permanent action recovery for %s on %s still unresolved: %v", row.IP, row.Integration, result.Err)
		}
	}
}
