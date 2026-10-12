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

package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Stable action identity for a permanent firewall rule is the (integration,
// IP) pair. Every entry point (manual, bulk, automatic threshold) joins
// the same row; each action turn is distinguished by its generation.
const (
	PermanentActionBlock   = "block"
	PermanentActionUnblock = "unblock"

	// PermanentPhasePending: the intent was committed but the external
	// outcome is not confirmed yet.
	PermanentPhasePending = "pending"
	// PermanentPhaseSucceeded: the external rule state matches the action.
	PermanentPhaseSucceeded = "succeeded"
	// PermanentPhaseFailed: the integration explicitly rejected the action.
	PermanentPhaseFailed = "failed"
	// PermanentPhaseUnknown: the external response was inconclusive and the
	// integration-side fact could not be established yet.
	PermanentPhaseUnknown = "unknown"

	// PermanentStatusPending is shown while an action is not confirmed.
	PermanentStatusPending = "pending"
	PermanentStatusBlocked = "blocked"
	PermanentStatusUnblock = "unblocked"
	PermanentStatusError   = "error"
	PermanentStatusUnknown = "unknown"
)

// PermanentBlockKey returns the stable identity shared by every entry point
// operating on the same integration/IP combination.
func PermanentBlockKey(ip, integration string) string {
	return integration + "\x00" + ip
}

// PermanentActionStart is the result of beginning a durable action turn.
type PermanentActionStart struct {
	Record       PermanentBlockRecord
	AlreadyDone  bool // same action already confirmed; no external call needed
	Continuation bool // an earlier turn for the same action was interrupted/failed
	PriorPhase   string
}

// BeginPermanentAction commits the intent for action (block/unblock) before
// any external call. Repeated requests for the same action on an unfinished
// row join the existing generation; an action flip starts a new generation
// so late results of the old generation can never overwrite the new state.
func BeginPermanentAction(ctx context.Context, ip, integration, action, serverID, details, message string) (PermanentActionStart, error) {
	if db == nil {
		return PermanentActionStart{}, errors.New("storage not initialised")
	}
	if ip == "" || integration == "" {
		return PermanentActionStart{}, errors.New("ip and integration are required")
	}
	if action != PermanentActionBlock && action != PermanentActionUnblock {
		return PermanentActionStart{}, fmt.Errorf("unsupported permanent action %q", action)
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return PermanentActionStart{}, err
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().UTC()
	row := tx.QueryRowContext(ctx, `
SELECT `+permanentBlockColumns+`
FROM permanent_blocks
WHERE ip = ? AND integration = ?`, ip, integration)

	existing, scanErr := scanPermanentBlock(row)
	switch {
	case scanErr == nil:
		if existing.DesiredAction == action && existing.Phase == PermanentPhaseSucceeded {
			if err := tx.Commit(); err != nil {
				return PermanentActionStart{}, err
			}
			return PermanentActionStart{Record: existing, AlreadyDone: true}, nil
		}

		next := existing
		next.Status = PermanentStatusPending
		next.Details = details
		next.Message = message
		next.ServerID = serverID
		next.UpdatedAt = now
		priorPhase := existing.Phase
		if existing.DesiredAction != action {
			// Action turn changed: later generation wins, whatever the
			// in-flight call of the old generation eventually reports.
			next.DesiredAction = action
			next.Generation = existing.Generation + 1
			next.Phase = PermanentPhasePending
			next.Attempts = 0
			next.ConfirmedAt = time.Time{}
		} else {
			next.Phase = PermanentPhasePending
		}
		if err := updatePermanentActionTx(ctx, tx, next); err != nil {
			return PermanentActionStart{}, err
		}
		if err := tx.Commit(); err != nil {
			return PermanentActionStart{}, err
		}
		return PermanentActionStart{Record: next, Continuation: true, PriorPhase: priorPhase}, nil

	case errors.Is(scanErr, sql.ErrNoRows):
		rec := PermanentBlockRecord{
			IP:            ip,
			Integration:   integration,
			Status:        PermanentStatusPending,
			Details:       details,
			Message:       message,
			ServerID:      serverID,
			DesiredAction: action,
			Generation:    1,
			Phase:         PermanentPhasePending,
			CreatedAt:     now,
			UpdatedAt:     now,
		}
		res, err := tx.ExecContext(ctx, `
INSERT INTO permanent_blocks
	(ip, integration, status, details, message, server_id, desired_action, generation, phase, attempts, confirmed_at, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			rec.IP, rec.Integration, rec.Status, rec.Details, rec.Message, rec.ServerID,
			rec.DesiredAction, rec.Generation, rec.Phase, rec.Attempts, nil,
			rec.CreatedAt.Format(time.RFC3339Nano), rec.UpdatedAt.Format(time.RFC3339Nano),
		)
		if err != nil {
			return PermanentActionStart{}, err
		}
		if id, err := res.LastInsertId(); err == nil {
			rec.ID = id
		}
		if err := tx.Commit(); err != nil {
			return PermanentActionStart{}, err
		}
		return PermanentActionStart{Record: rec}, nil

	default:
		return PermanentActionStart{}, scanErr
	}
}

func updatePermanentActionTx(ctx context.Context, tx *sql.Tx, rec PermanentBlockRecord) error {
	_, err := tx.ExecContext(ctx, `
UPDATE permanent_blocks SET
	status = ?, details = ?, message = ?, server_id = ?,
	desired_action = ?, generation = ?, phase = ?, attempts = ?,
	confirmed_at = ?, updated_at = ?
WHERE ip = ? AND integration = ?`,
		rec.Status, rec.Details, rec.Message, rec.ServerID,
		rec.DesiredAction, rec.Generation, rec.Phase, rec.Attempts,
		timestampArg(rec.ConfirmedAt), rec.UpdatedAt.Format(time.RFC3339Nano),
		rec.IP, rec.Integration,
	)
	return err
}

func timestampArg(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// FinishPermanentAction stores the outcome of generation rec.Generation.
// saved is false when the row no longer belongs to that generation (a newer
// action turn superseded it, or the log was cleared): the late result is
// discarded instead of overwriting the current state.
func FinishPermanentAction(ctx context.Context, rec PermanentBlockRecord) (saved bool, err error) {
	if db == nil {
		return false, errors.New("storage not initialised")
	}
	if rec.IP == "" || rec.Integration == "" {
		return false, errors.New("ip and integration are required")
	}
	rec.UpdatedAt = time.Now().UTC()
	res, err := db.ExecContext(ctx, `
UPDATE permanent_blocks SET
	status = ?, details = ?, message = ?, server_id = ?,
	phase = ?, attempts = ?, confirmed_at = ?, updated_at = ?
WHERE ip = ? AND integration = ? AND generation = ?`,
		rec.Status, rec.Details, rec.Message, rec.ServerID,
		rec.Phase, rec.Attempts, timestampArg(rec.ConfirmedAt), rec.UpdatedAt.Format(time.RFC3339Nano),
		rec.IP, rec.Integration, rec.Generation,
	)
	if err != nil {
		return false, err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return affected > 0, nil
}

// ListRecoverablePermanentActions returns action rows interrupted before
// their external outcome was confirmed (process restart, cancellation or an
// inconclusive response), oldest first.
func ListRecoverablePermanentActions(ctx context.Context, limit int) ([]PermanentBlockRecord, error) {
	if db == nil {
		return nil, errors.New("storage not initialised")
	}
	if limit <= 0 {
		limit = 100
	}
	rows, err := db.QueryContext(ctx, `
SELECT `+permanentBlockColumns+`
FROM permanent_blocks
WHERE phase IN (?, ?)
ORDER BY updated_at ASC
LIMIT ?`, PermanentPhasePending, PermanentPhaseUnknown, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []PermanentBlockRecord
	for rows.Next() {
		rec, err := scanPermanentBlock(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, rec)
	}
	return records, rows.Err()
}

// =========================================================================
//  Pending write outbox
//
//  When the external rule was applied but the SQLite update failed, the
//  outcome is kept in-process and retried. A later entry for the same action
//  only backfills the record; the external block is never called twice.
// =========================================================================

type pendingPermanentWrite struct {
	rec PermanentBlockRecord
}

var (
	permanentWriteMu    sync.Mutex
	pendingPermanentOut = map[string]pendingPermanentWrite{}
)

// EnqueuePendingPermanentBlock keeps an external outcome that could not be
// persisted. The newest outcome for a stable action identity replaces any
// older queued one.
func EnqueuePendingPermanentBlock(rec PermanentBlockRecord) {
	if rec.IP == "" || rec.Integration == "" {
		return
	}
	permanentWriteMu.Lock()
	defer permanentWriteMu.Unlock()
	pendingPermanentOut[PermanentBlockKey(rec.IP, rec.Integration)] = pendingPermanentWrite{rec: rec}
}

// PendingPermanentBlockWrite returns the queued outcome for an identity, if
// any, so a new entry can converge on it without touching the firewall.
func PendingPermanentBlockWrite(ip, integration string) (PermanentBlockRecord, bool) {
	permanentWriteMu.Lock()
	defer permanentWriteMu.Unlock()
	item, ok := pendingPermanentOut[PermanentBlockKey(ip, integration)]
	if !ok {
		return PermanentBlockRecord{}, false
	}
	return item.rec, true
}

// DropPendingPermanentBlockWrites is exported for tests.
func DropPendingPermanentBlockWrites() { dropPendingPermanentBlockWrites() }

func dropPendingPermanentBlockWrites() {
	permanentWriteMu.Lock()
	defer permanentWriteMu.Unlock()
	pendingPermanentOut = map[string]pendingPermanentWrite{}
}

// FlushPendingPermanentBlocks retries every queued outcome once. Outcomes
// whose generation was superseded (or whose row was cleared) are dropped.
func FlushPendingPermanentBlocks(ctx context.Context) error {
	if db == nil {
		return errors.New("storage not initialised")
	}
	permanentWriteMu.Lock()
	items := make([]PermanentBlockRecord, 0, len(pendingPermanentOut))
	for _, item := range pendingPermanentOut {
		items = append(items, item.rec)
	}
	permanentWriteMu.Unlock()

	var firstErr error
	for _, rec := range items {
		saved, err := FinishPermanentAction(ctx, rec)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		permanentWriteMu.Lock()
		if current, ok := pendingPermanentOut[PermanentBlockKey(rec.IP, rec.Integration)]; ok && current.rec.Generation == rec.Generation {
			delete(pendingPermanentOut, PermanentBlockKey(rec.IP, rec.Integration))
		}
		permanentWriteMu.Unlock()
		_ = saved
	}
	return firstErr
}
