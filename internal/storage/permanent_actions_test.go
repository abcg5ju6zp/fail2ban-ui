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

package storage

import (
	"context"
	"testing"
)

func TestBeginPermanentActionGenerations(t *testing.T) {
	initTestStorage(t)
	ctx := context.Background()
	const ip, integ = "203.0.113.10", "pfsense"

	// A fresh identity starts at generation 1, pending.
	start, err := BeginPermanentAction(ctx, ip, integ, PermanentActionBlock, "", "{}", "pending")
	if err != nil {
		t.Fatalf("begin block: %v", err)
	}
	if start.AlreadyDone || start.Continuation || start.Record.Generation != 1 || start.Record.Phase != PermanentPhasePending {
		t.Fatalf("unexpected start: %+v", start)
	}

	// Repeating the same unfinished action joins the same generation.
	again, err := BeginPermanentAction(ctx, ip, integ, PermanentActionBlock, "", "{}", "pending")
	if err != nil {
		t.Fatalf("re-begin block: %v", err)
	}
	if !again.Continuation || again.Record.Generation != 1 || again.PriorPhase != PermanentPhasePending {
		t.Fatalf("same-action continuation should join gen 1: %+v", again)
	}

	// Flipping the action opens a new generation.
	flip, err := BeginPermanentAction(ctx, ip, integ, PermanentActionUnblock, "", "{}", "pending")
	if err != nil {
		t.Fatalf("begin unblock: %v", err)
	}
	if flip.Record.Generation != 2 || flip.Record.DesiredAction != PermanentActionUnblock || flip.PriorPhase != PermanentPhasePending {
		t.Fatalf("action flip should start gen 2: %+v", flip)
	}

	// A late result of the old generation must not save.
	stale := flip.Record
	stale.Generation = 1
	stale.Phase = PermanentPhaseSucceeded
	stale.Status = PermanentStatusBlocked
	saved, err := FinishPermanentAction(ctx, stale)
	if err != nil {
		t.Fatalf("stale finish: %v", err)
	}
	if saved {
		t.Fatal("stale generation result must be discarded")
	}

	// Current generation finishes normally.
	current := flip.Record
	current.Phase = PermanentPhaseSucceeded
	current.Status = PermanentStatusUnblock
	saved, err = FinishPermanentAction(ctx, current)
	if err != nil || !saved {
		t.Fatalf("current finish saved=%v err=%v", saved, err)
	}

	// Same action on a confirmed row is already done and is not rewritten.
	done, err := BeginPermanentAction(ctx, ip, integ, PermanentActionUnblock, "", "{}", "pending")
	if err != nil || !done.AlreadyDone || done.Record.Generation != 2 {
		t.Fatalf("expected already-done join, got %+v err=%v", done, err)
	}

	active, err := IsPermanentBlockActive(ctx, ip, integ)
	if err != nil || active {
		t.Fatalf("unblocked row must not be active: active=%v err=%v", active, err)
	}
}

func TestFinishPermanentActionCAS(t *testing.T) {
	initTestStorage(t)
	ctx := context.Background()
	const ip, integ = "198.51.100.7", "opnsense"

	start, err := BeginPermanentAction(ctx, ip, integ, PermanentActionBlock, "srv-1", `{"manual":true}`, "pending")
	if err != nil {
		t.Fatal(err)
	}
	rec := start.Record
	rec.Phase = PermanentPhaseSucceeded
	rec.Status = PermanentStatusBlocked
	rec.Attempts = 1
	rec.ConfirmedAt = rec.CreatedAt
	saved, err := FinishPermanentAction(ctx, rec)
	if err != nil || !saved {
		t.Fatalf("finish saved=%v err=%v", saved, err)
	}

	got, found, err := GetPermanentBlock(ctx, ip, integ)
	if err != nil || !found {
		t.Fatalf("get: found=%v err=%v", found, err)
	}
	if got.Phase != PermanentPhaseSucceeded || got.Status != PermanentStatusBlocked ||
		got.Generation != 1 || got.Attempts != 1 || got.ConfirmedAt.IsZero() {
		t.Fatalf("persisted outcome wrong: %+v", got)
	}
	if active, _ := IsPermanentBlockActive(ctx, ip, integ); !active {
		t.Fatal("confirmed block must be active")
	}
}

func TestListRecoverablePermanentActions(t *testing.T) {
	initTestStorage(t)
	ctx := context.Background()

	mustBegin := func(ip, phase string) {
		t.Helper()
		start, err := BeginPermanentAction(ctx, ip, "mikrotik", PermanentActionBlock, "", "{}", "pending")
		if err != nil {
			t.Fatal(err)
		}
		if phase != PermanentPhasePending {
			rec := start.Record
			rec.Phase = phase
			rec.Status = phase
			if _, err := FinishPermanentAction(ctx, rec); err != nil {
				t.Fatal(err)
			}
		}
	}
	mustBegin("203.0.113.21", PermanentPhasePending)
	mustBegin("203.0.113.22", PermanentPhaseUnknown)
	mustBegin("203.0.113.23", PermanentPhaseFailed)
	mustBegin("203.0.113.24", PermanentPhaseSucceeded)

	rows, err := ListRecoverablePermanentActions(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	var pending, unknown int
	for _, row := range rows {
		switch row.Phase {
		case PermanentPhasePending:
			pending++
		case PermanentPhaseUnknown:
			unknown++
		default:
			t.Fatalf("unexpected recoverable phase %q", row.Phase)
		}
	}
	if pending != 1 || unknown != 1 {
		t.Fatalf("got pending=%d unknown=%d, want 1/1", pending, unknown)
	}
}

func TestPendingWriteOutboxBackfill(t *testing.T) {
	initTestStorage(t)
	ctx := context.Background()
	const ip, integ = "203.0.113.31", "unifi"

	// Intent committed, external call succeeded, but the outcome write
	// "failed": it is queued for writeback.
	start, err := BeginPermanentAction(ctx, ip, integ, PermanentActionBlock, "", "{}", "pending")
	if err != nil {
		t.Fatal(err)
	}
	queued := start.Record
	queued.Phase = PermanentPhaseSucceeded
	queued.Status = PermanentStatusBlocked
	EnqueuePendingPermanentBlock(queued)

	if _, ok := PendingPermanentBlockWrite(ip, integ); !ok {
		t.Fatal("queued outcome missing")
	}
	if err := FlushPendingPermanentBlocks(ctx); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if _, ok := PendingPermanentBlockWrite(ip, integ); ok {
		t.Fatal("queued outcome should be removed after flush")
	}
	if active, _ := IsPermanentBlockActive(ctx, ip, integ); !active {
		t.Fatal("backfilled record must be active")
	}
}

func TestPendingWriteOutboxDropsSuperseded(t *testing.T) {
	initTestStorage(t)
	ctx := context.Background()
	const ip, integ = "203.0.113.32", "pfsense"

	start, err := BeginPermanentAction(ctx, ip, integ, PermanentActionBlock, "", "{}", "pending")
	if err != nil {
		t.Fatal(err)
	}
	outdated := start.Record // gen 1 block, still pending
	if _, err := BeginPermanentAction(ctx, ip, integ, PermanentActionUnblock, "", "{}", "pending"); err != nil {
		t.Fatal(err)
	}
	EnqueuePendingPermanentBlock(outdated)
	if err := FlushPendingPermanentBlocks(ctx); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if _, ok := PendingPermanentBlockWrite(ip, integ); ok {
		t.Fatal("superseded queued outcome must be dropped")
	}
	rec, found, _ := GetPermanentBlock(ctx, ip, integ)
	if !found || rec.Generation != 2 || rec.DesiredAction != PermanentActionUnblock {
		t.Fatalf("newer generation must survive flush: %+v", rec)
	}
}

func TestLegacyPermanentBlockRowsBackfilled(t *testing.T) {
	initTestStorage(t)
	ctx := context.Background()

	// Rows written before the generation/phase model have empty new columns.
	if _, err := db.ExecContext(ctx, `
INSERT INTO permanent_blocks (ip, integration, status, details, message, server_id, desired_action, generation, phase, attempts, created_at, updated_at)
VALUES ('203.0.113.40', 'pfsense', 'blocked', '{}', '', '', '', 0, '', 0, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `
INSERT INTO permanent_blocks (ip, integration, status, details, message, server_id, desired_action, generation, phase, attempts, created_at, updated_at)
VALUES ('203.0.113.41', 'pfsense', 'error', '{}', 'boom', '', '', 0, '', 0, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if err := ensureSchema(ctx); err != nil {
		t.Fatalf("re-run ensureSchema: %v", err)
	}

	blocked, found, err := GetPermanentBlock(ctx, "203.0.113.40", "pfsense")
	if err != nil || !found {
		t.Fatalf("get blocked row: found=%v err=%v", found, err)
	}
	if blocked.DesiredAction != PermanentActionBlock || blocked.Generation != 1 || blocked.Phase != PermanentPhaseSucceeded {
		t.Fatalf("blocked legacy row backfill wrong: %+v", blocked)
	}
	if active, _ := IsPermanentBlockActive(ctx, blocked.IP, blocked.Integration); !active {
		t.Fatal("legacy blocked row must remain active")
	}

	failed, found, err := GetPermanentBlock(ctx, "203.0.113.41", "pfsense")
	if err != nil || !found {
		t.Fatalf("get error row: found=%v err=%v", found, err)
	}
	if failed.Phase != PermanentPhaseFailed || failed.DesiredAction != PermanentActionBlock {
		t.Fatalf("error legacy row backfill wrong: %+v", failed)
	}
	if active, _ := IsPermanentBlockActive(ctx, failed.IP, failed.Integration); active {
		t.Fatal("legacy error row must not be active")
	}
}

func TestClearPermanentBlocksDropsOutbox(t *testing.T) {
	initTestStorage(t)
	ctx := context.Background()
	const ip, integ = "203.0.113.33", "pfsense"
	start, err := BeginPermanentAction(ctx, ip, integ, PermanentActionBlock, "", "{}", "pending")
	if err != nil {
		t.Fatal(err)
	}
	EnqueuePendingPermanentBlock(start.Record)

	if _, err := ClearPermanentBlocks(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := PendingPermanentBlockWrite(ip, integ); ok {
		t.Fatal("clear must also discard queued writes")
	}
	if err := FlushPendingPermanentBlocks(ctx); err != nil {
		t.Fatalf("flush after clear: %v", err)
	}
	if _, found, _ := GetPermanentBlock(ctx, ip, integ); found {
		t.Fatal("cleared row must not be resurrected by the outbox")
	}
}
