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
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/swissmakers/fail2ban-ui/internal/config"
	"github.com/swissmakers/fail2ban-ui/internal/integrations"
	"github.com/swissmakers/fail2ban-ui/internal/storage"
)

// =========================================================================
//  Fake integration
// =========================================================================

const fakePermanentIntegrationID = "fake-permanent"

type fakePermanentIntegration struct {
	mu           sync.Mutex
	state        map[string]bool
	blockCalls   map[string]int
	unblockCalls map[string]int
	blockScript  map[string]func(call int) error
	unblockScript map[string]func(call int) error
	factError    map[string]error
	hooked       map[string]bool
	blockHook    func(ip string)
}

func init() {
	integrations.Register(&fakePermanentIntegration{})
}

func (f *fakePermanentIntegration) ID() string { return fakePermanentIntegrationID }

func (f *fakePermanentIntegration) Validate(_ config.AdvancedActionsConfig) error { return nil }

func (f *fakePermanentIntegration) BlockIP(req integrations.Request) error {
	ip := req.IP
	f.mu.Lock()
	call := f.blockCalls[ip] + 1
	f.blockCalls[ip] = call
	script := f.blockScript[ip]
	if !f.hooked[ip] {
		f.hooked[ip] = true
		hook := f.blockHook
		f.mu.Unlock()
		if hook != nil {
			hook(ip)
		}
	} else {
		f.mu.Unlock()
	}
	var err error
	if script != nil {
		err = script(call)
	}
	if err == nil {
		f.mu.Lock()
		f.state[ip] = true
		f.mu.Unlock()
	}
	return err
}

func (f *fakePermanentIntegration) UnblockIP(req integrations.Request) error {
	ip := req.IP
	f.mu.Lock()
	call := f.unblockCalls[ip] + 1
	f.unblockCalls[ip] = call
	script := f.unblockScript[ip]
	f.mu.Unlock()
	var err error
	if script != nil {
		err = script(call)
	}
	if err == nil {
		f.mu.Lock()
		delete(f.state, ip)
		f.mu.Unlock()
	}
	return err
}

func (f *fakePermanentIntegration) IsIPBlocked(req integrations.Request) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.factError[req.IP]; err != nil {
		return false, err
	}
	return f.state[req.IP], nil
}

func (f *fakePermanentIntegration) calls(ip string) (block, unblock int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.blockCalls[ip], f.unblockCalls[ip]
}

func fakeIntegration() *fakePermanentIntegration {
	integ, _ := integrations.Get(fakePermanentIntegrationID)
	fake := integ.(*fakePermanentIntegration)
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.state = map[string]bool{}
	fake.blockCalls = map[string]int{}
	fake.unblockCalls = map[string]int{}
	fake.blockScript = map[string]func(call int) error{}
	fake.unblockScript = map[string]func(call int) error{}
	fake.factError = map[string]error{}
	fake.hooked = map[string]bool{}
	fake.blockHook = nil
	return fake
}

func useFakeIntegrationSettings(t *testing.T) config.AppSettings {
	t.Helper()
	original := config.GetSettings()
	s := original
	s.AdvancedActions.Enabled = true
	s.AdvancedActions.Threshold = 2
	s.AdvancedActions.Integration = fakePermanentIntegrationID
	if _, err := config.UpdateSettings(s); err != nil {
		t.Fatalf("update settings: %v", err)
	}
	t.Cleanup(func() {
		_, _ = config.UpdateSettings(original)
		_, _ = storage.ClearPermanentBlocks(context.Background())
		storage.DropPendingPermanentBlockWrites()
	})
	return config.GetSettings()
}

func assertActive(t *testing.T, ip string, want bool) {
	t.Helper()
	got, err := storage.IsPermanentBlockActive(context.Background(), ip, fakePermanentIntegrationID)
	if err != nil {
		t.Fatalf("active lookup %s: %v", ip, err)
	}
	if got != want {
		t.Fatalf("IsPermanentBlockActive(%s) = %v, want %v", ip, got, want)
	}
}

// =========================================================================
//  Committer: unified identity and recoverable outcomes
// =========================================================================

func TestPermanentCommitBlockAndDedup(t *testing.T) {
	fake := fakeIntegration()
	settings := useFakeIntegrationSettings(t)
	const ip = "203.0.113.1"

	res := commitPermanentAction(context.Background(), settings, storage.PermanentActionBlock, ip, "", map[string]any{"manual": true})
	if res.Err != nil || res.Phase != storage.PermanentPhaseSucceeded || res.Generation != 1 || res.ExternalCalls != 1 {
		t.Fatalf("first commit: %+v", res)
	}
	assertActive(t, ip, true)

	// Manual, bulk or repeated threshold entries share the identity and must
	// not call the firewall again.
	res2 := commitPermanentAction(context.Background(), settings, storage.PermanentActionBlock, ip, "srv-1", map[string]any{"reason": "bulk_insights"})
	if res2.Err != nil || !res2.AlreadyDone || res2.ExternalCalls != 0 {
		t.Fatalf("second commit should be already-done without a call: %+v", res2)
	}
	block, _ := fake.calls(ip)
	if block != 1 {
		t.Fatalf("block calls = %d, want 1", block)
	}
}

func TestPermanentCommitExplicitFailureNotActive(t *testing.T) {
	fake := fakeIntegration()
	settings := useFakeIntegrationSettings(t)
	const ip = "203.0.113.2"
	fake.blockScript[ip] = func(int) error { return errors.New("400 Bad Request: rejected") }

	res := commitPermanentAction(context.Background(), settings, storage.PermanentActionBlock, ip, "", nil)
	if res.Err == nil || res.Phase != storage.PermanentPhaseFailed || res.Status != storage.PermanentStatusError {
		t.Fatalf("expected explicit failure, got %+v", res)
	}
	assertActive(t, ip, false)

	// The queryable state must agree with the failure response.
	rec, found, _ := storage.GetPermanentBlock(context.Background(), ip, fakePermanentIntegrationID)
	if !found || rec.Status != storage.PermanentStatusError || rec.Phase != storage.PermanentPhaseFailed {
		t.Fatalf("stored row must record the failure: %+v", rec)
	}

	// Once the integration accepts it, the same action retries and succeeds.
	delete(fake.blockScript, ip)
	res2 := commitPermanentAction(context.Background(), settings, storage.PermanentActionBlock, ip, "", nil)
	if res2.Err != nil || res2.Phase != storage.PermanentPhaseSucceeded || res2.ExternalCalls != 1 {
		t.Fatalf("retry should succeed: %+v", res2)
	}
	assertActive(t, ip, true)
}

func TestPermanentCommitUncertainThenFactPresent(t *testing.T) {
	fake := fakeIntegration()
	settings := useFakeIntegrationSettings(t)
	const ip = "203.0.113.3"
	// The external rule actually applies even though the response is lost.
	fake.blockScript[ip] = func(int) error {
		fake.mu.Lock()
		fake.state[ip] = true
		fake.mu.Unlock()
		return integrations.MarkUncertain(errors.New("read tcp: i/o timeout"))
	}

	res := commitPermanentAction(context.Background(), settings, storage.PermanentActionBlock, ip, "", nil)
	if res.Err != nil || res.Phase != storage.PermanentPhaseSucceeded {
		t.Fatalf("fact check should confirm the block: %+v", res)
	}
	block, _ := fake.calls(ip)
	if block != 1 {
		t.Fatalf("block calls = %d, want 1 (no blind repeat)", block)
	}
	assertActive(t, ip, true)
}

func TestPermanentCommitUncertainFactAbsentThenVerifiesWithoutRepeat(t *testing.T) {
	fake := fakeIntegration()
	settings := useFakeIntegrationSettings(t)
	const ip = "203.0.113.4"
	// Every response gets lost and the rule never appears: after one informed
	// resend the action stays unknown rather than looping forever.
	fake.blockScript[ip] = func(int) error {
		return integrations.MarkUncertain(errors.New("502 Bad Gateway"))
	}

	res := commitPermanentAction(context.Background(), settings, storage.PermanentActionBlock, ip, "", nil)
	if res.Err == nil || res.Phase != storage.PermanentPhaseUnknown || res.Status != storage.PermanentStatusUnknown {
		t.Fatalf("expected unknown outcome: %+v", res)
	}
	if res.ExternalCalls != 2 {
		t.Fatalf("external calls = %d, want initial + one informed resend", res.ExternalCalls)
	}
	assertActive(t, ip, false)
	if rec, _, _ := storage.GetPermanentBlock(context.Background(), ip, fakePermanentIntegrationID); rec.Phase != storage.PermanentPhaseUnknown {
		t.Fatalf("stored phase = %q, want unknown", rec.Phase)
	}

	// The delayed rule finally appears. The next entry must only verify the
	// integration-side fact and never call block again.
	fake.mu.Lock()
	fake.state[ip] = true
	fake.mu.Unlock()
	res2 := commitPermanentAction(context.Background(), settings, storage.PermanentActionBlock, ip, "", nil)
	if res2.Err != nil || res2.Phase != storage.PermanentPhaseSucceeded || res2.ExternalCalls != 0 {
		t.Fatalf("fact verification should close the action: %+v", res2)
	}
	block, _ := fake.calls(ip)
	if block != 2 {
		t.Fatalf("block calls = %d, still want 2", block)
	}
	assertActive(t, ip, true)
}

func TestPermanentCommitUnverifiableFactDoesNotRepeat(t *testing.T) {
	fake := fakeIntegration()
	settings := useFakeIntegrationSettings(t)
	const ip = "203.0.113.5"
	fake.blockScript[ip] = func(int) error {
		return integrations.MarkUncertain(errors.New("connection refused"))
	}
	fake.factError[ip] = errors.New("lookup unavailable")

	res := commitPermanentAction(context.Background(), settings, storage.PermanentActionBlock, ip, "", nil)
	if res.Err == nil || res.Phase != storage.PermanentPhaseUnknown {
		t.Fatalf("unverifiable state must stay unknown: %+v", res)
	}
	if res.ExternalCalls != 1 {
		t.Fatalf("external calls = %d, fact unverifiable means no resend", res.ExternalCalls)
	}
	assertActive(t, ip, false)
	if rec, _, _ := storage.GetPermanentBlock(context.Background(), ip, fakePermanentIntegrationID); rec.Phase != storage.PermanentPhaseUnknown {
		t.Fatalf("stored phase = %q, want unknown", rec.Phase)
	}
}

func TestPermanentCommitPendingWriteBackfillWithoutReBlock(t *testing.T) {
	fake := fakeIntegration()
	settings := useFakeIntegrationSettings(t)
	const ip = "203.0.113.6"

	// Simulate: intent committed, external call succeeded, outcome write
	// failed and was queued in the outbox.
	start, err := storage.BeginPermanentAction(context.Background(), ip, fakePermanentIntegrationID,
		storage.PermanentActionBlock, "", `{"manual":true}`, "pending")
	if err != nil {
		t.Fatal(err)
	}
	queued := start.Record
	queued.Phase = storage.PermanentPhaseSucceeded
	queued.Status = storage.PermanentStatusBlocked
	queued.ConfirmedAt = time.Now().UTC()
	storage.EnqueuePendingPermanentBlock(queued)

	res := commitPermanentAction(context.Background(), settings, storage.PermanentActionBlock, ip, "", nil)
	if res.Err != nil || !res.RecordPending && res.Phase != storage.PermanentPhaseSucceeded {
		t.Fatalf("pending-write join should succeed by backfilling only: %+v", res)
	}
	block, _ := fake.calls(ip)
	if block != 0 {
		t.Fatalf("block calls = %d, must not re-block", block)
	}
	assertActive(t, ip, true)
	if _, ok := storage.PendingPermanentBlockWrite(ip, fakePermanentIntegrationID); ok {
		t.Fatal("outbox should be drained after backfill")
	}
}

func TestPermanentCommitLateGenerationResultCannotOverwrite(t *testing.T) {
	settings := useFakeIntegrationSettings(t)
	const ip = "203.0.113.7"

	block := commitPermanentAction(context.Background(), settings, storage.PermanentActionBlock, ip, "", nil)
	if block.Err != nil {
		t.Fatal(block.Err)
	}
	unblock := commitPermanentAction(context.Background(), settings, storage.PermanentActionUnblock, ip, "", nil)
	if unblock.Err != nil || unblock.Generation != 2 {
		t.Fatalf("unblock should start generation 2: %+v", unblock)
	}
	assertActive(t, ip, false)

	// A delayed block result of generation 1 arrives now: it must be dropped.
	stale := block
	staleRec := storage.PermanentBlockRecord{
		IP: ip, Integration: fakePermanentIntegrationID,
		DesiredAction: storage.PermanentActionBlock, Generation: 1,
		Phase: storage.PermanentPhaseSucceeded, Status: storage.PermanentStatusBlocked,
		ConfirmedAt: time.Now().UTC(),
	}
	saved, err := storage.FinishPermanentAction(context.Background(), staleRec)
	if err != nil {
		t.Fatal(err)
	}
	if saved {
		t.Fatal("late generation-1 result must not overwrite generation 2")
	}
	rec, _, _ := storage.GetPermanentBlock(context.Background(), ip, fakePermanentIntegrationID)
	if rec.Generation != 2 || rec.Status != storage.PermanentStatusUnblock {
		t.Fatalf("final state must follow the newest generation: %+v", rec)
	}
	_ = stale
}

func TestPermanentCommitBlockUnblockConcurrency(t *testing.T) {
	fake := fakeIntegration()
	settings := useFakeIntegrationSettings(t)
	const ip = "203.0.113.8"

	started := make(chan struct{}, 1)
	release := make(chan struct{})
	fake.blockHook = func(string) {
		started <- struct{}{}
		<-release
	}

	blockDone := make(chan permanentActionResult, 1)
	go func() {
		blockDone <- commitPermanentAction(context.Background(), settings, storage.PermanentActionBlock, ip, "", nil)
	}()
	<-started

	// Unblock must wait behind the in-flight block for the same identity.
	unblockDone := make(chan permanentActionResult, 1)
	go func() {
		unblockDone <- commitPermanentAction(context.Background(), settings, storage.PermanentActionUnblock, ip, "", nil)
	}()

	select {
	case <-unblockDone:
		t.Fatal("unblock must not overtake the in-flight block")
	case <-time.After(50 * time.Millisecond):
	}

	close(release)
	blockRes := <-blockDone
	unblockRes := <-unblockDone
	if blockRes.Err != nil || blockRes.Generation != 1 {
		t.Fatalf("block result: %+v", blockRes)
	}
	if unblockRes.Err != nil || unblockRes.Generation != 2 {
		t.Fatalf("unblock result: %+v", unblockRes)
	}
	callsBlock, callsUnblock := fake.calls(ip)
	if callsBlock != 1 || callsUnblock != 1 {
		t.Fatalf("calls block=%d unblock=%d, want 1/1", callsBlock, callsUnblock)
	}
	assertActive(t, ip, false)
}

// =========================================================================
//  Automatic threshold
// =========================================================================

func TestEvaluateAdvancedActionsThresholdDedup(t *testing.T) {
	fake := fakeIntegration()
	settings := useFakeIntegrationSettings(t)
	const ip = "203.0.113.9"
	server := config.Fail2banServer{ID: "srv-1", Name: "srv-1"}
	ctx := context.Background()

	recordBan := func(callback string) {
		t.Helper()
		_, inserted, err := storage.RecordBanEventOnce(ctx, storage.BanEventRecord{
			ServerID: server.ID, ServerName: server.Name, Jail: "sshd", IP: ip,
			EventType: "ban", OccurredAt: time.Now().UTC(),
			CallbackID: callback + "-" + strconv.FormatInt(time.Now().UnixNano(), 10),
		})
		if err != nil || !inserted {
			t.Fatalf("record ban %s: inserted=%v err=%v", callback, inserted, err)
		}
	}
	recordBan("cb-1")
	recordBan("cb-2")

	evaluateAdvancedActions(ctx, settings, server, ip)
	evaluateAdvancedActions(ctx, settings, server, ip) // repeated threshold event
	block, _ := fake.calls(ip)
	if block != 1 {
		t.Fatalf("threshold evaluations produced %d block calls, want 1", block)
	}
	assertActive(t, ip, true)
}

// =========================================================================
//  HTTP entry compatibility
// =========================================================================

func manualRequest(action, ip string) (*gin.Context, *httptest.ResponseRecorder) {
	body, _ := json.Marshal(map[string]string{"action": action, "ip": ip})
	c, w := newTestContext(http.MethodPost, "/api/advanced-actions/manual", string(body))
	c.Request.Header.Set("Content-Type", "application/json")
	return c, w
}

func TestManualAdvancedActionHandlerCompatibility(t *testing.T) {
	fake := fakeIntegration()
	useFakeIntegrationSettings(t)
	const ip = "203.0.113.10"

	// Invalid and reserved addresses keep their 400 behavior.
	for _, bad := range []string{"10.0.0.1", "2001:db8::/32", "not-an-ip"} {
		c, w := manualRequest("block", bad)
		ManualAdvancedActionHandler(c)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("%s: code=%d want 400", bad, w.Code)
		}
	}

	// First block: 200 success.
	c, w := manualRequest("block", ip)
	ManualAdvancedActionHandler(c)
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), `"info":true`) {
		t.Fatalf("first block: code=%d body=%s", w.Code, w.Body.String())
	}

	// Already blocked stays a 200 info response and never calls again.
	c, w = manualRequest("block", ip)
	ManualAdvancedActionHandler(c)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"info":true`) {
		t.Fatalf("already blocked: code=%d body=%s", w.Code, w.Body.String())
	}
	block, _ := fake.calls(ip)
	if block != 1 {
		t.Fatalf("block calls = %d, want 1", block)
	}
}

func TestManualAdvancedActionHandlerExplicitFailure(t *testing.T) {
	fake := fakeIntegration()
	useFakeIntegrationSettings(t)
	const ip = "203.0.113.11"
	fake.blockScript[ip] = func(int) error { return errors.New("403 forbidden") }

	c, w := manualRequest("block", ip)
	ManualAdvancedActionHandler(c)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("code=%d want 500, body=%s", w.Code, w.Body.String())
	}
	assertActive(t, ip, false)
}

func bulkRequest(ips []string) (*gin.Context, *httptest.ResponseRecorder) {
	body, _ := json.Marshal(map[string]any{"ips": ips})
	c, w := newTestContext(http.MethodPost, "/api/advanced-actions/blocks", string(body))
	c.Request.Header.Set("Content-Type", "application/json")
	return c, w
}

type bulkResponse struct {
	Summary map[string]int `json:"summary"`
}

func TestBulkPermanentBlockClassificationAndAbort(t *testing.T) {
	fake := fakeIntegration()
	useFakeIntegrationSettings(t)

	// One IP blocked beforehand -> already_blocked.
	commitPermanentAction(context.Background(), config.GetSettings(), storage.PermanentActionBlock, "203.0.113.50", "", nil)

	for _, ip := range []string{"203.0.113.60", "203.0.113.61", "203.0.113.62", "203.0.113.63", "203.0.113.64"} {
		ip := ip
		fake.blockScript[ip] = func(int) error { return errors.New("synthetic failure") }
	}

	ips := []string{
		"not-an-ip",          // invalid
		"192.168.1.10",       // skipped_private
		"203.0.113.50",       // already_blocked
		"203.0.113.51",       // blocked
		"203.0.113.60",       // error 1
		"203.0.113.61",       // error 2
		"203.0.113.62",       // error 3
		"203.0.113.63",       // error 4
		"203.0.113.64",       // error 5 -> abort threshold
		"203.0.113.65",       // aborted, never called
	}
	c, w := bulkRequest(ips)
	BulkPermanentBlockHandler(c)
	if w.Code != http.StatusOK {
		t.Fatalf("code=%d body=%s", w.Code, w.Body.String())
	}
	var resp bulkResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	want := map[string]int{
		"requested": 10, "invalid": 1, "skipped": 1, "alreadyBlocked": 1,
		"blocked": 1, "failed": 5, "aborted": 1,
	}
	for key, value := range want {
		if resp.Summary[key] != value {
			t.Fatalf("summary[%s] = %d, want %d (full: %v)", key, resp.Summary[key], value, resp.Summary)
		}
	}
	block, _ := fake.calls("203.0.113.65")
	if block != 0 {
		t.Fatalf("aborted IP had %d block calls, want 0", block)
	}
	assertActive(t, "203.0.113.51", true)
}

func TestBulkPermanentBlockCancelPreservesStartedItem(t *testing.T) {
	fake := fakeIntegration()
	useFakeIntegrationSettings(t)

	started := make(chan struct{}, 1)
	release := make(chan struct{})
	fake.blockHook = func(ip string) {
		if ip == "203.0.113.70" {
			started <- struct{}{}
			<-release
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	c, w := newTestContext(http.MethodPost, "/api/advanced-actions/blocks", `{"ips":["203.0.113.70","203.0.113.71"]}`)
	c.Request.Header.Set("Content-Type", "application/json")
	c.Request = c.Request.WithContext(ctx)

	done := make(chan struct{})
	go func() {
		BulkPermanentBlockHandler(c)
		close(done)
	}()

	<-started
	// The second item must not start after cancellation.
	cancel()
	time.Sleep(50 * time.Millisecond)
	close(release)
	<-done

	var resp struct {
		Results []struct {
			IP     string `json:"ip"`
			Status string `json:"status"`
		} `json:"results"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	statuses := map[string]string{}
	for _, r := range resp.Results {
		statuses[r.IP] = r.Status
	}
	if statuses["203.0.113.70"] != "blocked" {
		t.Fatalf("started item should complete as blocked: %v", statuses)
	}
	if statuses["203.0.113.71"] != "aborted" {
		t.Fatalf("item after cancel should be aborted: %v", statuses)
	}
	// Detached completion persisted the started item; the other never ran.
	assertActive(t, "203.0.113.70", true)
	block, _ := fake.calls("203.0.113.71")
	if block != 0 {
		t.Fatalf("canceled item had %d block calls, want 0", block)
	}
}

// =========================================================================
//  Restart recovery
// =========================================================================

func TestRecoverPermanentActionsContinuesOriginalAction(t *testing.T) {
	fake := fakeIntegration()
	settings := useFakeIntegrationSettings(t)
	_ = settings

	// Row left pending by a crashed process; externally the rule exists.
	presentIP := "203.0.113.80"
	if _, err := storage.BeginPermanentAction(context.Background(), presentIP, fakePermanentIntegrationID,
		storage.PermanentActionBlock, "srv-1", `{}`, "pending"); err != nil {
		t.Fatal(err)
	}
	fake.state[presentIP] = true

	// Another pending row whose rule never made it to the firewall: recovery
	// must continue the original block action once.
	missingIP := "203.0.113.81"
	if _, err := storage.BeginPermanentAction(context.Background(), missingIP, fakePermanentIntegrationID,
		storage.PermanentActionBlock, "srv-1", `{}`, "pending"); err != nil {
		t.Fatal(err)
	}

	recoverPermanentActions(context.Background())

	presentBlock, _ := fake.calls(presentIP)
	if presentBlock != 0 {
		t.Fatalf("already-applied rule recovered %d calls, want 0", presentBlock)
	}
	assertActive(t, presentIP, true)

	missingBlock, _ := fake.calls(missingIP)
	if missingBlock != 1 {
		t.Fatalf("missing rule recovered %d calls, want 1", missingBlock)
	}
	assertActive(t, missingIP, true)
}
