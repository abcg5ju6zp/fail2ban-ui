// Fail2ban UI - A Swiss made, management interface for Fail2ban.
//
// Copyright (C) 2026 Swissmakers GmbH (https://swissmakers.ch)
//
// Licensed under the GNU Affero General Public License, Version 3 (AGPL-3.0)
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	https://www.gnu.org/licenses/agpl-3.0.en.html
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Detection of changed-host-key failures, the durable issue registry surfaced
// in the server manager, and the admin-approved accept flow that re-pins
// known_hosts atomically, verifies the new key and rolls back on failure.

package fail2ban

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/swissmakers/fail2ban-ui/internal/shared"
	"github.com/swissmakers/fail2ban-ui/internal/storage"
)

// =========================================================================
//  Typed Error
// =========================================================================

type SSHHostKeyError struct {
	ServerID    string
	Host        string
	Port        int
	Fingerprint string
	Err         error
}

func (e *SSHHostKeyError) Error() string {
	if e.Fingerprint != "" {
		return fmt.Sprintf("ssh host key for %s has changed (presented %s)", e.Host, e.Fingerprint)
	}
	return fmt.Sprintf("ssh host key verification failed for %s", e.Host)
}

func (e *SSHHostKeyError) Unwrap() error {
	return e.Err
}

type HostKeyMismatchError struct {
	Approved  string
	Presented string
}

func (e *HostKeyMismatchError) Error() string {
	return fmt.Sprintf("remote host key %s does not match the approved fingerprint %s", e.Presented, e.Approved)
}

// ErrNoPendingHostKey is returned when an accept is attempted without a current, displayed alert.
var ErrNoPendingHostKey = errors.New("no pending host key change for this server")

// ErrHostKeyAcceptBusy is returned when another accept for the same server is in flight.
var ErrHostKeyAcceptBusy = errors.New("a host key acceptance for this server is already in progress")

// HostKeyAcceptStaleError means the pinned server configuration generation was superseded before commit.
type HostKeyAcceptStaleError struct {
	ServerID string
	Reason   string
}

func (e *HostKeyAcceptStaleError) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("server configuration changed while accepting the host key (%s); reload the server and try again", e.Reason)
	}
	return "server configuration changed while accepting the host key; reload the server and try again"
}

func SSHErrorMessageKey(err error) string {
	var hk *SSHHostKeyError
	if errors.As(err, &hk) {
		return "servers.errors.host_key_changed"
	}
	return ""
}

// =========================================================================
//  Detection
// =========================================================================

var (
	hostKeyBannerRe      = regexp.MustCompile(`(?i)REMOTE HOST IDENTIFICATION HAS CHANGED|POSSIBLE DNS SPOOFING DETECTED|host key verification failed`)
	hostKeyFingerprintRe = regexp.MustCompile(`SHA256:[A-Za-z0-9+/]{43}`)
)

// Classifies ssh stderr as a host-key failure; nil when it is something else.
func (sc *SSHConnector) parseHostKeyError(stderr string, cause error) *SSHHostKeyError {
	if !hostKeyBannerRe.MatchString(stderr) {
		return nil
	}
	return &SSHHostKeyError{
		ServerID:    sc.server.ID,
		Host:        sc.server.Host,
		Port:        sc.server.Port,
		Fingerprint: hostKeyFingerprintRe.FindString(stderr),
		Err:         cause,
	}
}

// =========================================================================
//  Issue registry (memory mirror + durable SQLite generation record)
// =========================================================================

var (
	hostKeyIssuesMu sync.RWMutex
	hostKeyIssues   = make(map[string]*SSHHostKeyError)
)

// Stores the alert in memory and refreshes its durable pending record. A
// published (accept-in-flight) row is never downgraded by a late detection.
func RecordHostKeyIssue(e *SSHHostKeyError) {
	rememberHostKeyIssue(e)
	if e == nil || e.ServerID == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := storage.RecordPendingHostKeyAlert(ctx, storage.HostKeyAlertRecord{
		ServerID:    e.ServerID,
		Host:        e.Host,
		Port:        effectiveHostKeyPort(e.Port),
		Fingerprint: e.Fingerprint,
		UpdatedAt:   time.Now().UTC(),
	})
	if err != nil && !storageUnavailable(err) {
		debugf("warning: failed to persist host key alert for %s: %v", e.ServerID, err)
	}
}

func rememberHostKeyIssue(e *SSHHostKeyError) {
	if e == nil || e.ServerID == "" {
		return
	}
	hostKeyIssuesMu.Lock()
	defer hostKeyIssuesMu.Unlock()
	hostKeyIssues[e.ServerID] = e
}

// ClearHostKeyIssue removes the alert in memory and in storage, regardless of phase.
func ClearHostKeyIssue(serverID string) {
	hostKeyIssuesMu.Lock()
	delete(hostKeyIssues, serverID)
	hostKeyIssuesMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := storage.DeleteHostKeyAlert(ctx, serverID); err != nil && !storageUnavailable(err) {
		debugf("warning: failed to clear durable host key alert for %s: %v", serverID, err)
	}
}

// SettleHostKeyIssue clears a waiting alert only; a published-but-unverified
// accept generation stays protected until it settles itself.
func SettleHostKeyIssue(serverID string) {
	hostKeyIssuesMu.Lock()
	delete(hostKeyIssues, serverID)
	hostKeyIssuesMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := storage.SettlePendingHostKeyAlert(ctx, serverID); err != nil && !storageUnavailable(err) {
		debugf("warning: failed to settle durable host key alert for %s: %v", serverID, err)
	}
}

func HostKeyIssue(serverID string) *SSHHostKeyError {
	hostKeyIssuesMu.RLock()
	defer hostKeyIssuesMu.RUnlock()
	if e, ok := hostKeyIssues[serverID]; ok {
		cp := *e
		return &cp
	}
	return nil
}

func pruneHostKeyIssues(keep map[string]struct{}) {
	hostKeyIssuesMu.Lock()
	for id := range hostKeyIssues {
		if _, ok := keep[id]; !ok {
			delete(hostKeyIssues, id)
		}
	}
	hostKeyIssuesMu.Unlock()

	ids := make([]string, 0, len(keep))
	for id := range keep {
		ids = append(ids, id)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := storage.DeleteHostKeyAlertsExcept(ctx, ids); err != nil && !storageUnavailable(err) {
		debugf("warning: failed to prune durable host key alerts: %v", err)
	}
}

func storageUnavailable(err error) bool {
	return err != nil && strings.Contains(err.Error(), "storage not initialised")
}

// =========================================================================
//  Configuration generations and per-server accept serialization
// =========================================================================

var (
	serverConfigLookupMu sync.RWMutex
	serverConfigLookup   func(id string) (shared.Fail2banServer, bool)

	hostKeyAcceptGates sync.Map // server ID -> *sync.Mutex
)

// SetServerConfigLookup registers the bridge to the live server configuration.
func SetServerConfigLookup(fn func(id string) (shared.Fail2banServer, bool)) {
	serverConfigLookupMu.Lock()
	serverConfigLookup = fn
	serverConfigLookupMu.Unlock()
}

func lookupServerConfig(id string) (shared.Fail2banServer, bool) {
	serverConfigLookupMu.RLock()
	fn := serverConfigLookup
	serverConfigLookupMu.RUnlock()
	if fn == nil {
		return shared.Fail2banServer{}, false
	}
	return fn(id)
}

// Commits are only allowed while the live server still matches the generation
// this accept pinned: address, port, SSH identity and key file must be unchanged.
func ensureCurrentServerGeneration(pinned shared.Fail2banServer) error {
	current, ok := lookupServerConfig(pinned.ID)
	if !ok {
		return &HostKeyAcceptStaleError{ServerID: pinned.ID, Reason: "server no longer exists"}
	}
	switch {
	case current.Type != "ssh":
		return &HostKeyAcceptStaleError{ServerID: pinned.ID, Reason: "server is no longer an SSH server"}
	case !current.Enabled:
		return &HostKeyAcceptStaleError{ServerID: pinned.ID, Reason: "server was disabled"}
	case current.Host != pinned.Host:
		return &HostKeyAcceptStaleError{ServerID: pinned.ID, Reason: "host changed"}
	case effectiveHostKeyPort(current.Port) != effectiveHostKeyPort(pinned.Port):
		return &HostKeyAcceptStaleError{ServerID: pinned.ID, Reason: "port changed"}
	case current.SSHUser != pinned.SSHUser:
		return &HostKeyAcceptStaleError{ServerID: pinned.ID, Reason: "SSH user changed"}
	case current.SSHKeyPath != pinned.SSHKeyPath:
		return &HostKeyAcceptStaleError{ServerID: pinned.ID, Reason: "SSH key path changed"}
	}
	return nil
}

func hostKeyAcceptGate(serverID string) *sync.Mutex {
	if v, ok := hostKeyAcceptGates.Load(serverID); ok {
		return v.(*sync.Mutex)
	}
	mu := &sync.Mutex{}
	actual, _ := hostKeyAcceptGates.LoadOrStore(serverID, mu)
	return actual.(*sync.Mutex)
}

func effectiveHostKeyPort(port int) int {
	if port <= 0 {
		return 22
	}
	return port
}

// =========================================================================
//  Accept Flow
// =========================================================================

func NormalizeFingerprint(fp string) string {
	fp = strings.TrimSpace(fp)
	if fp == "" {
		return ""
	}
	if !strings.HasPrefix(fp, "SHA256:") {
		fp = "SHA256:" + fp
	}
	return fp
}

// Test seams: replaced in unit tests to avoid a live sshd.
var (
	scanSSHHostKey = scanHostKey
	verifyHostKey  = func(ctx context.Context, sc *SSHConnector) error {
		return sc.verifyHostKeyConnection(ctx)
	}
)

// AcceptHostKey re-pins the known_hosts entry for the pinned server generation,
// but only when the key the remote presents matches the fingerprint the admin
// reviewed. The new file is fully persisted before it replaces the trusted one;
// a failed connection check restores the trusted file and keeps a retry alert.
func AcceptHostKey(ctx context.Context, server shared.Fail2banServer, approvedFP string) (string, error) {
	approvedFP = NormalizeFingerprint(approvedFP)
	if approvedFP == "" {
		return "", fmt.Errorf("approved fingerprint is required")
	}

	// One commit per server at a time: concurrent admins are serialized so a
	// stale fingerprint cannot overwrite the current generation.
	gate := hostKeyAcceptGate(server.ID)
	if !gate.TryLock() {
		return "", ErrHostKeyAcceptBusy
	}
	defer gate.Unlock()

	if err := ensureCurrentServerGeneration(server); err != nil {
		return "", err
	}

	sc, err := newSSHConnector(server)
	if err != nil {
		return "", err
	}
	khPath := sc.knownHostsPath()
	if khPath == "" {
		return "", fmt.Errorf("cannot determine known_hosts path for server %s", server.Name)
	}

	// The approved fingerprint must match the currently displayed alert.
	if err := authorizeHostKeyAccept(ctx, server.ID, approvedFP); err != nil {
		return "", err
	}

	key, err := scanSSHHostKey(ctx, server.Host, server.Port)
	if err != nil {
		return "", fmt.Errorf("failed to read current host key from %s: %w", server.Host, err)
	}
	presentedFP := ssh.FingerprintSHA256(key)
	if subtle.ConstantTimeCompare([]byte(presentedFP), []byte(approvedFP)) != 1 {
		RecordHostKeyIssue(&SSHHostKeyError{
			ServerID: server.ID, Host: server.Host, Port: server.Port, Fingerprint: presentedFP,
		})
		return "", &HostKeyMismatchError{Approved: approvedFP, Presented: presentedFP}
	}

	if err := ensureCurrentServerGeneration(server); err != nil {
		return "", err
	}

	pattern := knownHostsPattern(server.Host, server.Port)
	old, oldExisted, mode, err := readKnownHostsFile(khPath)
	if err != nil {
		return "", fmt.Errorf("failed to read known_hosts %s: %w", khPath, err)
	}
	newContent := buildKnownHostsContent(old, pattern, key)
	previousFP := firstMatchingFingerprint(old, pattern)
	changed := !oldExisted || !bytesEqual(old, newContent)

	if changed {
		// Keep the trusted content aside before anything is replaced.
		if oldExisted {
			if err := replaceFileAtomic(khPath+backupSuffix, old, mode); err != nil {
				return "", fmt.Errorf("back up known_hosts: %w", err)
			}
		}
		// Journal the generation before the rename so a crash always leaves
		// (file content + durable row) with a deterministic reconciliation.
		if err := storage.UpsertHostKeyAlert(ctx, storage.HostKeyAlertRecord{
			ServerID:            server.ID,
			Host:                server.Host,
			Port:                effectiveHostKeyPort(server.Port),
			Fingerprint:         presentedFP,
			ApprovedFingerprint: presentedFP,
			PreviousFingerprint: previousFP,
			Phase:               storage.HostKeyPhasePublished,
			UpdatedAt:           time.Now().UTC(),
		}); err != nil {
			return "", fmt.Errorf("record host key accept state: %w", err)
		}
		if err := replaceFileAtomic(khPath, newContent, mode); err != nil {
			if landed := reconcileUncertainPublish(ctx, khPath, old, oldExisted, newContent, server, presentedFP, err); !landed {
				return "", err
			}
		}
	}

	// The address must still be the one the admin reviewed; if it moved, undo
	// the publish so this late generation cannot own the new configuration.
	if err := ensureCurrentServerGeneration(server); err != nil {
		rollbackPublishedKnownHosts(khPath, pattern, old, oldExisted, mode)
		_ = resetPendingHostKeyAlert(ctx, server, presentedFP)
		return "", err
	}

	// Fresh, strict connection check: no ControlMaster reuse, the pinned key
	// must be exactly what the remote presents.
	if err := verifyHostKey(ctx, sc); err != nil {
		if ctx.Err() != nil {
			// Canceled before the outcome is known: leave the published file and
			// durable row untouched; a retry or restart reconciliation decides.
			return "", fmt.Errorf("host key accept canceled before connection verification: %w", ctx.Err())
		}
		rollbackPublishedKnownHosts(khPath, pattern, old, oldExisted, mode)
		fp := presentedFP
		rescanCtx, rescanCancel := detachedHostKeyContext()
		if latest, scanErr := scanSSHHostKey(rescanCtx, server.Host, server.Port); scanErr == nil {
			fp = ssh.FingerprintSHA256(latest)
		}
		rescanCancel()
		_ = resetPendingHostKeyAlert(ctx, server, fp)
		return "", fmt.Errorf("host key accepted but connection check failed; trusted known_hosts restored: %w", err)
	}

	resolveHostKeyAccept(server.ID, khPath)
	sc.shutdownControlMaster()
	return presentedFP, nil
}

// Confirms the durable/memory alert exists and still displays the approved fingerprint.
func authorizeHostKeyAccept(ctx context.Context, serverID, approvedFP string) error {
	row, err := storage.GetHostKeyAlert(ctx, serverID)
	if err != nil && !storageUnavailable(err) {
		return err
	}
	if row != nil {
		if row.Fingerprint != "" && row.Fingerprint != approvedFP {
			return &HostKeyMismatchError{Approved: approvedFP, Presented: row.Fingerprint}
		}
		return nil
	}
	// Fallback for tests / storage-less setups: the in-memory alert rules.
	issue := HostKeyIssue(serverID)
	if issue == nil {
		return ErrNoPendingHostKey
	}
	if issue.Fingerprint != "" && issue.Fingerprint != approvedFP {
		return &HostKeyMismatchError{Approved: approvedFP, Presented: issue.Fingerprint}
	}
	return nil
}

// After a failed rename, inspects what actually landed. Returns true when the
// new content is on disk and the accept should proceed to verification.
func reconcileUncertainPublish(ctx context.Context, khPath string, old []byte, oldExisted bool, newContent []byte,
	server shared.Fail2banServer, presentedFP string, publishErr error) bool {
	cur, readErr := os.ReadFile(khPath)
	if readErr == nil && bytesEqual(cur, newContent) {
		debugf("known_hosts rename reported an error but the new content is on disk for %s; continuing", server.ID)
		return true
	}
	if (readErr == nil && bytesEqual(cur, old)) || (!oldExisted && os.IsNotExist(readErr)) {
		debugf("known_hosts rename failed without changing the trusted file for %s: %v", server.ID, publishErr)
		_ = resetPendingHostKeyAlert(ctx, server, presentedFP)
		if !oldExisted {
			_ = os.Remove(khPath + backupSuffix)
		}
		return false
	}
	// Genuinely undecidable: leave the published generation recorded; the next
	// accept or restart reconciliation resolves it from file content + row.
	debugf("known_hosts replacement result for %s is uncertain: %v", server.ID, publishErr)
	return false
}

// resetPendingHostKeyAlert downgrades the durable row to a retryable pending
// alert and refreshes the in-memory banner.
func resetPendingHostKeyAlert(ctx context.Context, server shared.Fail2banServer, fingerprint string) error {
	rememberHostKeyIssue(&SSHHostKeyError{
		ServerID:    server.ID,
		Host:        server.Host,
		Port:        server.Port,
		Fingerprint: fingerprint,
	})
	return storage.UpsertHostKeyAlert(ctx, storage.HostKeyAlertRecord{
		ServerID:    server.ID,
		Host:        server.Host,
		Port:        effectiveHostKeyPort(server.Port),
		Fingerprint: fingerprint,
		Phase:       storage.HostKeyPhasePending,
		UpdatedAt:   time.Now().UTC(),
	})
}

func resolveHostKeyAccept(serverID, khPath string) {
	ClearHostKeyIssue(serverID)
	if khPath != "" {
		if err := os.Remove(khPath + backupSuffix); err != nil && !os.IsNotExist(err) {
			debugf("warning: failed to remove known_hosts backup for %s: %v", serverID, err)
		}
	}
}

func detachedHostKeyContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 12*time.Second)
}

func knownHostsPattern(host string, port int) string {
	return knownhosts.Normalize(net.JoinHostPort(host, strconv.Itoa(effectiveHostKeyPort(port))))
}

func scanHostKey(ctx context.Context, host string, port int) (ssh.PublicKey, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(effectiveHostKeyPort(port)))
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	errKeyCaptured := errors.New("host key captured")
	var captured ssh.PublicKey
	cfg := &ssh.ClientConfig{
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			captured = key
			return errKeyCaptured
		},
		Timeout: 10 * time.Second,
	}
	_, _, _, err = ssh.NewClientConn(conn, addr, cfg)
	if captured != nil {
		return captured, nil
	}
	if err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("ssh handshake with %s completed without presenting a host key", addr)
}

// verifyHostKeyConnection authenticates against the freshly pinned key on a new
// TCP connection. StrictHostKeyChecking=yes forbids accept-new, and
// ControlPath=none bypasses any multiplexed master created under the old key.
func (sc *SSHConnector) verifyHostKeyConnection(ctx context.Context) error {
	args := []string{
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=10",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "LogLevel=ERROR",
		"-o", "ControlMaster=no",
		"-o", "ControlPath=none",
	}
	if kh := sc.knownHostsPath(); kh != "" {
		args = append(args, "-o", "UserKnownHostsFile="+kh)
	}
	if sc.server.SSHKeyPath != "" {
		args = append(args, "-i", sc.server.SSHKeyPath)
	}
	if sc.server.Port > 0 {
		args = append(args, "-p", strconv.Itoa(sc.server.Port))
	}
	args = append(args, "--", sc.sshTarget(), "true")

	_, stderr, err := sc.execSSH(ctx, args, nil)
	if err != nil {
		if hk := sc.parseHostKeyError(stderr, err); hk != nil {
			return hk
		}
		return fmt.Errorf("ssh connection check against the pinned host key failed: %w (output: %s)",
			err, truncateForLog(strings.TrimSpace(stderr), maxLoggedOutputBytes))
	}
	return nil
}

// Disposes any ControlMaster socket left over from the previous trusted generation.
func (sc *SSHConnector) shutdownControlMaster() {
	sc.masterMu.Lock()
	defer sc.masterMu.Unlock()
	sc.exitControlMasterLocked()
}
