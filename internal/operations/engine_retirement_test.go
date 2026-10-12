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

package operations

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestRetirementGateFencesSubmissionAndLateClaims(t *testing.T) {
	store := testStore(t)
	var retired atomic.Bool
	started := make(chan struct{}, 1)
	releaseFirst := make(chan struct{})
	e := startEngine(t, store, func(ctx context.Context, op Operation) (json.RawMessage, error) {
		if op.Kind == "first" {
			started <- struct{}{}
			<-releaseFirst
		}
		return json.RawMessage(`{}`), nil
	})
	e.SetRetirementGate(func(serverID string) bool { return serverID == "rt-engine" && retired.Load() })

	ctx := context.Background()
	first, err := e.Submit(ctx, "rt-engine", "first", "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	<-started

	// Queued before the fence, claimed after it.
	late, err := e.Submit(ctx, "rt-engine", "late", "", "", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Once retiring, new submissions are rejected.
	retired.Store(true)
	if _, err := e.Submit(ctx, "rt-engine", "blocked", "", "", nil); !errors.Is(err, ErrServerRetiring) {
		t.Fatalf("submit error=%v, want ErrServerRetiring", err)
	}

	close(releaseFirst)
	lateFinal := awaitState(t, e, late.ID, "cancelled")
	if lateFinal.Message == "" {
		t.Fatal("cancelled late operation should explain the retirement")
	}
	awaitState(t, e, first.ID, "succeeded")

	// Retired stays rejected; another server is unaffected.
	if _, err := e.Submit(ctx, "rt-engine", "again", "", "", nil); !errors.Is(err, ErrServerRetiring) {
		t.Fatalf("second submit error=%v", err)
	}
	other, err := e.Submit(ctx, "rt-other-engine", "ok", "", "", nil)
	if err != nil {
		t.Fatalf("unrelated server submit: %v", err)
	}
	awaitState(t, e, other.ID, "succeeded")
}

func TestCancelQueuedAndInFlightCountForServer(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	insert := func(id, serverID, state string) Operation {
		op := Operation{ID: id, ServerID: serverID, Kind: "kind", Target: "", State: state, Phase: state,
			Message: "", CreatedAt: now, UpdatedAt: now, Payload: json.RawMessage(`{}`)}
		if _, _, err := store.Insert(ctx, op); err != nil {
			t.Fatal(err)
		}
		return op
	}
	insert("q1", "rt-count", "queued")
	insert("q2", "rt-count", "queued")
	insert("q3", "rt-other-count", "queued")

	n, err := store.CancelQueuedForServer(ctx, "rt-count")
	if err != nil || n != 2 {
		t.Fatalf("cancel n=%d err=%v", n, err)
	}
	if n, _ := store.InFlightCountForServer(ctx, "rt-count"); n != 0 {
		t.Fatalf("in-flight=%d, want 0", n)
	}
	// Claim on the other server still works; the running job then counts.
	op, err := store.ClaimNext(ctx, "rt-other-count")
	if err != nil || op.ID != "q3" {
		t.Fatalf("claim other server: %+v %v", op, err)
	}
	if n, _ := store.InFlightCountForServer(ctx, "rt-other-count"); n != 1 {
		t.Fatalf("in-flight=%d, want 1", n)
	}
	// Cancelling twice changes nothing.
	if n, err := store.CancelQueuedForServer(ctx, "rt-count"); err != nil || n != 0 {
		t.Fatalf("second cancel n=%d err=%v", n, err)
	}
}
