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
	"testing"
	"time"
)

func retireTestServer(t *testing.T, id, name string, enabled, isDefault bool) Fail2banServer {
	t.Helper()
	srv, err := UpsertServer(Fail2banServer{
		ID:         id,
		Name:       name,
		Type:       "local",
		Enabled:    enabled,
		EnabledSet: true,
		IsDefault:  isDefault,
		SocketPath: "/tmp/" + id + ".sock",
		ConfigPath: "/config/fail2ban-" + id,
	})
	if err != nil {
		t.Fatalf("create %s: %v", id, err)
	}
	t.Cleanup(func() { _ = DeleteServer(id) })
	return srv
}

func TestBeginServerRetirementIsPersistedAndIdempotent(t *testing.T) {
	srv := retireTestServer(t, "retire-begin", "Retire Begin", false, false)

	marked, r, err := BeginServerRetirement(srv.ID)
	if err != nil {
		t.Fatal(err)
	}
	if r.Phase != RetirementRetiring || r.Generation <= 0 || !marked.IsRetiring() {
		t.Fatalf("unexpected retirement: %+v server=%+v", r, marked)
	}
	if marked.Enabled != srv.Enabled {
		t.Fatalf("retirement must not change enabled state: got %v", marked.Enabled)
	}
	firstGen := r.Generation

	// Repeated begin is idempotent and keeps the generation.
	again, r2, err := BeginServerRetirement(srv.ID)
	if err != nil {
		t.Fatal(err)
	}
	if r2.Generation != firstGen || r2.Phase != RetirementRetiring {
		t.Fatalf("second begin changed retirement: %+v", r2)
	}
	if again.RetirementError != "" {
		t.Fatalf("fresh retirement must carry no error: %q", again.RetirementError)
	}

	// The state is durable.
	stored, ok := GetServerRetirement(srv.ID)
	if !ok || stored.Phase != RetirementRetiring || stored.Generation != firstGen {
		t.Fatalf("retirement not persisted: %+v ok=%v", stored, ok)
	}
}

func TestBeginServerRetirementUnknownServer(t *testing.T) {
	if _, _, err := BeginServerRetirement("does-not-exist"); err == nil {
		t.Fatal("begin for unknown server must fail")
	}
}

func TestRetirementReassignsDefaultToEarliestCandidate(t *testing.T) {
	// The default is the earliest created; the next candidate must take over.
	def := retireTestServer(t, "retire-def-a", "Retire Default A", true, true)
	time.Sleep(2 * time.Millisecond)
	other := retireTestServer(t, "retire-def-b", "Retire Default B", true, false)

	if got := GetDefaultServer(); got.ID != def.ID {
		t.Fatalf("setup default=%s, want %s", got.ID, def.ID)
	}
	if _, r, err := BeginServerRetirement(def.ID); err != nil {
		t.Fatal(err)
	} else if r.Phase != RetirementRetiring {
		t.Fatalf("phase=%s", r.Phase)
	}
	if got := GetDefaultServer(); got.ID != other.ID {
		t.Fatalf("default after retirement=%s, want %s", got.ID, other.ID)
	}
	remaining, ok := GetServerByID(def.ID)
	if !ok || remaining.IsDefault {
		t.Fatal("retiring server must lose its default flag")
	}
	replacement, ok := GetServerByID(other.ID)
	if !ok || !replacement.IsDefault {
		t.Fatal("replacement server must be default")
	}
}

func TestRetiringDefaultLeavesNoDefaultWithoutCandidates(t *testing.T) {
	def := retireTestServer(t, "retire-def-only", "Retire Only Default", true, true)
	retireTestServer(t, "retire-disabled-other", "Retire Disabled Other", false, false)

	if _, _, err := BeginServerRetirement(def.ID); err != nil {
		t.Fatal(err)
	}
	if got := GetDefaultServer(); got.ID != "" {
		t.Fatalf("expected no default, got %s", got.ID)
	}
}

func TestRetirementAdvanceRecordAndFinish(t *testing.T) {
	srv := retireTestServer(t, "retire-lifecycle", "Retire Lifecycle", false, false)
	if _, _, err := BeginServerRetirement(srv.ID); err != nil {
		t.Fatal(err)
	}

	r, err := AdvanceServerRetirement(srv.ID, RetirementDraining)
	if err != nil || r.Phase != RetirementDraining {
		t.Fatalf("advance draining: %+v %v", r, err)
	}
	r, err = RecordRetirementError(srv.ID, "boom")
	if err != nil || r.Error != "boom" || r.Phase != RetirementDraining {
		t.Fatalf("record error: %+v %v", r, err)
	}
	// Advancing clears the error.
	r, err = AdvanceServerRetirement(srv.ID, RetirementReleasing)
	if err != nil || r.Error != "" || r.Phase != RetirementReleasing {
		t.Fatalf("advance releasing: %+v %v", r, err)
	}
	// The phase never moves backwards.
	if _, err := AdvanceServerRetirement(srv.ID, RetirementRetiring); err != nil {
		t.Fatal(err)
	}
	if got, _ := GetServerRetirement(srv.ID); got.Phase != RetirementReleasing {
		t.Fatalf("phase moved backwards: %s", got.Phase)
	}

	if _, err := AdvanceServerRetirement(srv.ID, RetirementRemoving); err != nil {
		t.Fatal(err)
	}
	if err := FinishServerRetirement(srv.ID); err != nil {
		t.Fatal(err)
	}
	if _, found := GetServerByID(srv.ID); found {
		t.Fatal("server still configured after finish")
	}
	if _, ok := GetServerRetirement(srv.ID); ok {
		t.Fatal("retirement state survived finish")
	}
	// Finishing twice is idempotent.
	if err := FinishServerRetirement(srv.ID); err != nil {
		t.Fatalf("second finish: %v", err)
	}
}

func TestListServerRetirementsOrderedByPhase(t *testing.T) {
	a := retireTestServer(t, "retire-list-a", "Retire List A", false, false)
	b := retireTestServer(t, "retire-list-b", "Retire List B", false, false)
	if _, _, err := BeginServerRetirement(a.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := BeginServerRetirement(b.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := AdvanceServerRetirement(b.ID, RetirementDraining); err != nil {
		t.Fatal(err)
	}

	list := ListServerRetirements()
	var ids []string
	for _, r := range list {
		if r.ServerID == a.ID || r.ServerID == b.ID {
			ids = append(ids, r.ServerID)
		}
	}
	// Ascending phase order: retiring precedes draining.
	if len(ids) != 2 || ids[0] != a.ID || ids[1] != b.ID {
		t.Fatalf("retirements not phase-ordered: %v", ids)
	}
}

func TestRetiringServerRejectsEditsAndDefault(t *testing.T) {
	srv := retireTestServer(t, "retire-locked", "Retire Locked", false, false)
	if _, _, err := BeginServerRetirement(srv.ID); err != nil {
		t.Fatal(err)
	}

	edited := srv
	edited.Name = "Renamed While Retiring"
	if _, err := UpsertServer(edited); !errors.Is(err, ErrServerRetiring) {
		t.Fatalf("upsert error=%v, want ErrServerRetiring", err)
	}
	if _, err := SetDefaultServer(srv.ID); !errors.Is(err, ErrServerRetiring) {
		t.Fatalf("setdefault error=%v, want ErrServerRetiring", err)
	}
	stored, ok := GetServerByID(srv.ID)
	if !ok || stored.Name != srv.Name {
		t.Fatal("blocked edit changed persisted server")
	}
}

func TestUnrelatedServerUnaffectedByRetirement(t *testing.T) {
	victim := retireTestServer(t, "retire-victim", "Retire Victim", false, false)
	survivor := retireTestServer(t, "retire-survivor", "Retire Survivor", false, false)

	if _, _, err := BeginServerRetirement(victim.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := AdvanceServerRetirement(victim.ID, RetirementDraining); err != nil {
		t.Fatal(err)
	}

	// The survivor can still be edited while another server is retiring.
	edited := survivor
	edited.Name = "Retire Survivor Renamed"
	saved, err := UpsertServer(edited)
	if err != nil {
		t.Fatalf("editing survivor: %v", err)
	}
	if saved.Name != "Retire Survivor Renamed" {
		t.Fatalf("survivor edit not saved: %s", saved.Name)
	}
}
