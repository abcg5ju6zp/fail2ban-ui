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
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/swissmakers/fail2ban-ui/internal/config"
	"github.com/swissmakers/fail2ban-ui/internal/integrations"
	"github.com/swissmakers/fail2ban-ui/internal/shared"
	"github.com/swissmakers/fail2ban-ui/internal/storage"
)

// =========================================================================
//  Threshold Evaluation
// =========================================================================

func evaluateAdvancedActions(ctx context.Context, settings config.AppSettings, server config.Fail2banServer, ip string) {
	cfg := settings.AdvancedActions
	if !cfg.Enabled || cfg.Threshold <= 0 || cfg.Integration == "" {
		return
	}

	count, err := storage.CountBanEventsByIP(ctx, ip, server.ID)
	if err != nil {
		log.Printf("WARNING: Failed to count ban events for %s: %v", ip, err)
		return
	}
	if int(count) < cfg.Threshold {
		return
	}

	// The committer itself dedupes manual, bulk and repeated threshold
	// events through the stable (integration, IP) action identity.
	result := commitPermanentAction(ctx, settings, storage.PermanentActionBlock, ip, server.ID, map[string]any{
		"reason":    "automatic_threshold",
		"count":     count,
		"threshold": cfg.Threshold,
	})
	if result.Err != nil {
		log.Printf("WARNING: Failed to permanently block %s: %v", ip, result.Err)
	}
}

// =========================================================================
//  Target validation
// =========================================================================

var (
	errCIDRNotSupported = errors.New("only single IP addresses can be blocked permanently")
	errReservedIP       = errors.New("private or reserved addresses cannot be blocked permanently")
)

// Validates a permanent block target; unblock accepts any single IP so stale entries can be removed.
func permanentBlockTargetError(action, ip string) error {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		if _, _, err := net.ParseCIDR(ip); err == nil {
			return withKey(errCIDRNotSupported, "settings.advanced.errors.cidr_not_supported")
		}
		return fmt.Errorf("invalid IP address %q", ip)
	}
	if action == storage.PermanentActionBlock && shared.IsReservedIP(parsed) {
		return withKey(errReservedIP, "settings.advanced.errors.reserved_ip")
	}
	return nil
}

// =========================================================================
//  Unified, recoverable permanent-action commit
//
//  Manual, bulk and automatic entries all converge here. For a stable
//  identity (integration, IP) the flow is:
//
//  1. commit intent (pending, generation) BEFORE touching the firewall;
//  2. on an interrupted/uncertain turn read the integration-side fact first;
//  3. dispatch the mutation at most once per informed decision;
//  4. persist the outcome with a generation CAS — a late result of an old
//     generation never overwrites a newer block/unblock turn;
//  5. when the write fails but the rule was applied, keep it in the pending
//     write outbox: later entries backfill the record, never re-block.
// =========================================================================

type permanentActionResult struct {
	IP          string
	Integration string
	Action      string
	Generation  int64
	Phase       string
	Status      string
	Message     string
	// AlreadyDone: the same action was already confirmed; no external call.
	AlreadyDone bool
	// RecordPending: the external outcome is confirmed but its record is
	// queued for a later write.
	RecordPending bool
	// Superseded: the outcome's generation lost to a newer action turn.
	Superseded bool
	// ExternalCalls counts mutating integration calls made during this commit.
	ExternalCalls int
	Err           error
}

const (
	permanentWriteTimeout  = 15 * time.Second
	permanentDispatchLimit = 2 // initial attempt + one informed resend
)

// detachedContext keeps persistence and fact verification alive when the
// caller's request is canceled; the vendor clients enforce their own call
// timeouts.
func detachedContext(ctx context.Context) context.Context {
	return context.WithoutCancel(ctx)
}

// ---- per-identity in-process serialization ------------------------------

type keyedLocks struct {
	mu    sync.Mutex
	locks map[string]*lockEntry
}

type lockEntry struct {
	mu  sync.Mutex
	ref int
}

func newKeyedLocks() *keyedLocks {
	return &keyedLocks{locks: map[string]*lockEntry{}}
}

// lock returns an unlock function for key. block/unblock turns for one
// identity are therefore serialized within the process, while different
// identities proceed concurrently.
func (k *keyedLocks) lock(key string) func() {
	k.mu.Lock()
	entry, ok := k.locks[key]
	if !ok {
		entry = &lockEntry{}
		k.locks[key] = entry
	}
	entry.ref++
	k.mu.Unlock()

	entry.mu.Lock()
	return func() {
		entry.mu.Unlock()
		k.mu.Lock()
		entry.ref--
		if entry.ref == 0 {
			delete(k.locks, key)
		}
		k.mu.Unlock()
	}
}

var permanentActionKeyedLocks = newKeyedLocks()

// ---- commit --------------------------------------------------------------

func commitPermanentAction(ctx context.Context, settings config.AppSettings, action, ip, serverID string, details map[string]any) permanentActionResult {
	result := permanentActionResult{IP: ip, Action: action, Integration: settings.AdvancedActions.Integration}

	cfg := settings.AdvancedActions
	integration, res := resolvePermanentIntegration(cfg, action, ip)
	if res != nil {
		return *res
	}

	if details == nil {
		details = map[string]any{}
	}
	details["action"] = action
	detailsBytes, _ := json.Marshal(details)
	detailsJSON := string(detailsBytes)

	key := storage.PermanentBlockKey(ip, cfg.Integration)
	unlock := permanentActionKeyedLocks.lock(key)
	defer unlock()

	writeCtx := detachedContext(ctx)

	// 1. An earlier confirmed outcome may only be waiting for its writeback.
	//    Same action → backfill the record only, never touch the firewall.
	if queued, ok := storage.PendingPermanentBlockWrite(ip, cfg.Integration); ok && queued.DesiredAction == action {
		if flushed := convergePendingWrite(writeCtx, ip, cfg.Integration, queued, &result); flushed {
			return result
		}
	}

	// 2. Commit the intent (or join the current generation).
	start, err := storage.BeginPermanentAction(writeCtx, ip, cfg.Integration, action, serverID, detailsJSON, pendingMessage(action))
	if err != nil {
		result.Err = fmt.Errorf("failed to open permanent action: %w", err)
		return result
	}
	result.Generation = start.Record.Generation
	if start.AlreadyDone {
		rec := start.Record
		result.Phase = rec.Phase
		result.Status = rec.Status
		result.Message = rec.Message
		result.AlreadyDone = true
		return result
	}

	logger := func(format string, args ...interface{}) {
		if settings.Debug {
			log.Printf(format, args...)
		}
	}
	req := integrations.Request{Context: ctx, IP: ip, Config: cfg, Logger: logger}

	rec := start.Record
	rec.Details = detailsJSON
	rec.ServerID = serverID

	// 3. A previous attempt for this same action was interrupted (cancel,
	//    restart) or ended inconclusive: read the integration-side fact
	//    before doing anything else.
	if start.Continuation && (start.PriorPhase == storage.PermanentPhasePending ||
		start.PriorPhase == storage.PermanentPhaseUnknown) {
		if present, known := readRemoteBlocked(detachedContext(ctx), integration, req); known {
			if remoteMatchesAction(present, action) {
				finishPermanent(&result, writeCtx, &rec, action)
				return result
			}
			// fact contradicts the desired state → informed convergence below
		} else {
			// Cannot establish the fact: never repeat the mutation blindly.
			rec.Attempts++
			finishUnknownOutcome(&result, writeCtx, &rec, action, nil,
				"integration state could not be verified for %s of %s", action, ip)
			return result
		}
	}

	// 4. Dispatch, classifying the response; uncertain responses trigger a
	//    fact check and at most one informed resend.
	var callErr error
	for attempt := 1; attempt <= permanentDispatchLimit; attempt++ {
		result.ExternalCalls++
		if action == storage.PermanentActionBlock {
			callErr = integration.BlockIP(req)
		} else {
			callErr = integration.UnblockIP(req)
		}
		rec.Attempts++

		switch {
		case callErr == nil:
			finishPermanent(&result, writeCtx, &rec, action)
			return result

		case action == storage.PermanentActionBlock && errors.Is(callErr, integrations.ErrAlreadyBlocked):
			finishPermanent(&result, writeCtx, &rec, action)
			return result

		case errors.Is(callErr, integrations.ErrOutcomeUncertain):
			present, known := readRemoteBlocked(detachedContext(ctx), integration, req)
			switch {
			case known && remoteMatchesAction(present, action):
				finishPermanent(&result, writeCtx, &rec, action)
				return result
			case known && attempt < permanentDispatchLimit:
				// Informed convergence: the fact proves the rule is missing,
				// resend the original action once.
				logger("integration response for %s %s was inconclusive but the rule is absent; retrying once", action, ip)
				continue
			default:
				finishUnknownOutcome(&result, writeCtx, &rec, action, callErr,
					"integration response for %s of %s was inconclusive", action, ip)
				return result
			}

		default:
			// Explicit rejection: never record an active state.
			rec.Status = storage.PermanentStatusError
			rec.Phase = storage.PermanentPhaseFailed
			rec.Message = callErr.Error()
			result.Phase = rec.Phase
			result.Status = rec.Status
			result.Message = rec.Message
			result.Err = callErr
			persistOutcome(writeCtx, &result, &rec)
			return result
		}
	}

	// Unreachable in practice; keep the compiler happy with a safe terminal.
	finishUnknownOutcome(&result, writeCtx, &rec, action, callErr, "integration response for %s of %s stayed inconclusive", action, ip)
	return result
}

func resolvePermanentIntegration(cfg config.AdvancedActionsConfig, action, ip string) (integrations.Integration, *permanentActionResult) {
	if cfg.Integration == "" {
		return nil, &permanentActionResult{IP: ip, Action: action, Err: errors.New("no integration configured")}
	}
	integration, ok := integrations.Get(cfg.Integration)
	if !ok {
		return nil, &permanentActionResult{IP: ip, Action: action, Integration: cfg.Integration, Err: fmt.Errorf("integration %s not registered", cfg.Integration)}
	}
	if err := permanentBlockTargetError(action, ip); err != nil {
		return nil, &permanentActionResult{IP: ip, Action: action, Integration: cfg.Integration, Err: err}
	}
	if err := integration.Validate(cfg); err != nil {
		return nil, &permanentActionResult{IP: ip, Action: action, Integration: cfg.Integration, Err: fmt.Errorf("integration configuration is invalid: %w", err)}
	}
	return integration, nil
}

func pendingMessage(action string) string {
	return fmt.Sprintf("%s pending", cases.Title(language.English).String(action))
}

func successMessage(action, integrationID string) string {
	return fmt.Sprintf("%s via %s", cases.Title(language.English).String(action), integrationID)
}

// readRemoteBlocked queries the integration-side fact. known is false when
// the integration cannot report its state; callers must then treat the
// action as unresolved rather than repeating it.
func readRemoteBlocked(ctx context.Context, integration integrations.Integration, req integrations.Request) (present bool, known bool) {
	checker, ok := integration.(integrations.StateChecker)
	if !ok {
		return false, false
	}
	present, err := checker.IsIPBlocked(reqWith(req, ctx))
	if err != nil {
		if req.Logger != nil {
			req.Logger("integration state lookup failed: %v", err)
		}
		return false, false
	}
	return present, true
}

func reqWith(req integrations.Request, ctx context.Context) integrations.Request {
	req.Context = ctx
	return req
}

func remoteMatchesAction(present bool, action string) bool {
	if action == storage.PermanentActionBlock {
		return present
	}
	return !present
}

func finishPermanent(result *permanentActionResult, ctx context.Context, rec *storage.PermanentBlockRecord, action string) {
	rec.Phase = storage.PermanentPhaseSucceeded
	if action == storage.PermanentActionBlock {
		rec.Status = storage.PermanentStatusBlocked
	} else {
		rec.Status = storage.PermanentStatusUnblock
	}
	rec.Message = successMessage(action, rec.Integration)
	rec.ConfirmedAt = time.Now().UTC()
	result.Phase = rec.Phase
	result.Status = rec.Status
	result.Message = rec.Message
	persistOutcome(ctx, result, rec)
}

func finishUnknownOutcome(result *permanentActionResult, ctx context.Context, rec *storage.PermanentBlockRecord, action string, cause error, format string, args ...any) {
	rec.Phase = storage.PermanentPhaseUnknown
	rec.Status = storage.PermanentStatusUnknown
	rec.Message = fmt.Sprintf(format, args...)
	if cause != nil {
		rec.Message += ": " + cause.Error()
	}
	result.Phase = rec.Phase
	result.Status = rec.Status
	result.Message = rec.Message
	result.Err = errors.New(rec.Message)
	persistOutcome(ctx, result, rec)
}

// persistOutcome writes the outcome with a generation CAS and keeps it in
// the outbox when the write fails.
func persistOutcome(ctx context.Context, result *permanentActionResult, rec *storage.PermanentBlockRecord) {
	saved, err := storage.FinishPermanentAction(ctx, *rec)
	if err != nil {
		log.Printf("WARNING: failed to persist permanent %s outcome for %s (%s); queued for writeback: %v",
			rec.DesiredAction, rec.IP, rec.Integration, err)
		storage.EnqueuePendingPermanentBlock(*rec)
		result.RecordPending = true
		if rec.Phase == storage.PermanentPhaseSucceeded {
			// The external rule is confirmed; only the record is behind.
			result.Err = nil
		}
		return
	}
	if !saved {
		result.Superseded = true
		if rec.Phase == storage.PermanentPhaseSucceeded {
			result.Err = nil
		}
	}
}

// convergePendingWrite handles an identity whose confirmed outcome only
// awaits persistence. Returns true when this commit must not call the
// firewall anymore.
func convergePendingWrite(ctx context.Context, ip, integrationID string, queued storage.PermanentBlockRecord, result *permanentActionResult) bool {
	if err := storage.FlushPendingPermanentBlocks(ctx); err != nil {
		log.Printf("WARNING: writeback of permanent action still pending for %s (%s): %v", ip, integrationID, err)
	}
	rec, found, err := storage.GetPermanentBlock(ctx, ip, integrationID)
	if err == nil && found && rec.Generation == queued.Generation && rec.Phase == storage.PermanentPhaseSucceeded {
		result.Generation = rec.Generation
		result.Phase = rec.Phase
		result.Status = rec.Status
		result.Message = rec.Message
		result.RecordPending = false
		return true
	}
	// Flush did not land yet: trust the queued external fact and do not
	// re-block; the record stays queued for the reconciler.
	result.Generation = queued.Generation
	result.Phase = queued.Phase
	result.Status = queued.Status
	result.Message = queued.Message
	result.RecordPending = true
	if queued.Phase == storage.PermanentPhaseSucceeded {
		result.Err = nil
		return true
	}
	return false
}
