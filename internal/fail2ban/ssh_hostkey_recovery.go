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

// Restart and uncertainty recovery for the host-key accept flow. The durable
// alert row plus the current known_hosts content always determine a single
// outcome: finish and confirm the published key, or return to the trusted
// previous file; nothing is decided from in-memory state alone.

package fail2ban

import (
	"bytes"
	"context"
	"os"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/swissmakers/fail2ban-ui/internal/shared"
	"github.com/swissmakers/fail2ban-ui/internal/storage"
)

// LoadPersistentHostKeyIssues mirrors durable alerts into the in-memory
// registry and discards rows for servers that were removed or whose
// coordinates changed since the alert was recorded. Local file work only.
func LoadPersistentHostKeyIssues(servers []shared.Fail2banServer) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rows, err := storage.ListHostKeyAlerts(ctx)
	if err != nil {
		if !storageUnavailable(err) {
			debugf("warning: failed to load durable host key alerts: %v", err)
		}
		return
	}
	current := make(map[string]shared.Fail2banServer, len(servers))
	ids := make([]string, 0, len(servers))
	for _, srv := range servers {
		current[srv.ID] = srv
		ids = append(ids, srv.ID)
	}
	if err := storage.DeleteHostKeyAlertsExcept(ctx, ids); err != nil && !storageUnavailable(err) {
		debugf("warning: failed to prune durable host key alerts: %v", err)
	}

	for _, row := range rows {
		srv, ok := current[row.ServerID]
		if !ok || !hostKeyRowMatchesServer(row, srv) {
			if err := storage.DeleteHostKeyAlert(ctx, row.ServerID); err != nil && !storageUnavailable(err) {
				debugf("warning: failed to drop stale host key alert for %s: %v", row.ServerID, err)
			}
			continue
		}
		rememberHostKeyIssue(&SSHHostKeyError{
			ServerID:    srv.ID,
			Host:        row.Host,
			Port:        row.Port,
			Fingerprint: alertDisplayFingerprint(row),
		})
	}
}

func hostKeyRowMatchesServer(row storage.HostKeyAlertRecord, srv shared.Fail2banServer) bool {
	return srv.Type == "ssh" && srv.Host == row.Host &&
		effectiveHostKeyPort(srv.Port) == effectiveHostKeyPort(row.Port)
}

func alertDisplayFingerprint(row storage.HostKeyAlertRecord) string {
	if row.Fingerprint != "" {
		return row.Fingerprint
	}
	return row.ApprovedFingerprint
}

// RecoverHostKeyStates reconciles every durable row against the known_hosts
// content and, where a new key was already published, finishes the connection
// verification (or rolls back). Runs at startup; safe to run again.
func RecoverHostKeyStates(ctx context.Context) {
	rows, err := storage.ListHostKeyAlerts(ctx)
	if err != nil {
		if !storageUnavailable(err) {
			debugf("warning: host key recovery cannot load alerts: %v", err)
		}
		return
	}
	for _, row := range rows {
		if ctx.Err() != nil {
			return
		}
		srv, ok := lookupServerConfig(row.ServerID)
		if !ok {
			_ = storage.DeleteHostKeyAlert(ctx, row.ServerID)
			continue
		}
		if !hostKeyRowMatchesServer(row, srv) {
			_ = storage.DeleteHostKeyAlert(ctx, row.ServerID)
			continue
		}
		if err := reconcileHostKeyState(ctx, srv); err != nil {
			debugf("warning: host key recovery for %s incomplete: %v", row.ServerID, err)
		}
	}
}

// reconcileHostKeyState reaches a deterministic state for one server.
func reconcileHostKeyState(ctx context.Context, srv shared.Fail2banServer) error {
	row, err := storage.GetHostKeyAlert(ctx, srv.ID)
	if err != nil {
		return err
	}
	if row == nil {
		return nil
	}
	sc, err := newSSHConnector(srv)
	if err != nil {
		return err
	}
	khPath := sc.knownHostsPath()
	if khPath == "" {
		return nil
	}
	content, existed, _, err := readKnownHostsFile(khPath)
	if err != nil {
		return err
	}
	pattern := knownHostsPattern(srv.Host, srv.Port)
	approvedLive := row.ApprovedFingerprint != "" && knownHostsFilePins(content, pattern, row.ApprovedFingerprint)
	oldLive := row.PreviousFingerprint != "" && knownHostsFilePins(content, pattern, row.PreviousFingerprint)
	pendingLive := row.Fingerprint != "" && knownHostsFilePins(content, pattern, row.Fingerprint)

	switch {
	case approvedLive:
		// The accepted generation is on disk: finish its verification.
		return finishPublishedAccept(ctx, sc, srv, khPath, pattern, row)
	case row.Phase == storage.HostKeyPhasePending && pendingLive:
		// The displayed key is already trusted (external fix or a rename that
		// landed after the phase row was written): confirm it like an accept.
		return confirmAlreadyTrusted(ctx, sc, srv, khPath, alertDisplayFingerprint(*row))
	case oldLive || (row.Phase == storage.HostKeyPhasePublished && !existed):
		// The replacement never landed; the trusted previous file is intact.
		_ = os.Remove(khPath + backupSuffix)
		fp := row.ApprovedFingerprint
		if fp == "" {
			fp = row.Fingerprint
		}
		return resetPendingHostKeyAlert(ctx, srv, fp)
	default:
		// Neither key is on disk (admin-edited file, partial crash). Do not
		// overwrite anything; downgrade to a retryable pending alert.
		fp := row.Fingerprint
		if row.Phase == storage.HostKeyPhasePublished {
			fp = alertDisplayFingerprint(*row)
		}
		return resetPendingHostKeyAlert(ctx, srv, fp)
	}
}

func finishPublishedAccept(ctx context.Context, sc *SSHConnector, srv shared.Fail2banServer,
	khPath, pattern string, row *storage.HostKeyAlertRecord) error {
	verifyCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if err := verifyHostKey(verifyCtx, sc); err == nil {
		resolveHostKeyAccept(srv.ID, khPath)
		return nil
	} else if ctx.Err() != nil {
		return ctx.Err()
	}

	// New key unusable: restore the trusted previous generation if we can.
	fp := presentedFingerprintOr(srv, row.Fingerprint)
	rescanCtx, rescanCancel := detachedHostKeyContext()
	if latest, scanErr := scanSSHHostKey(rescanCtx, srv.Host, srv.Port); scanErr == nil {
		fp = ssh.FingerprintSHA256(latest)
	}
	rescanCancel()
	if !restoreKnownHostsBackup(khPath) && row.PreviousFingerprint != "" {
		// No backup file: at least unpin the new entry, other lines survive.
		cur, existed, mode, readErr := readKnownHostsFile(khPath)
		if readErr == nil && existed {
			stripped := stripKnownHostsEntries(cur, pattern)
			if len(bytes.TrimSpace(stripped)) > 0 {
				_ = replaceFileAtomic(khPath, stripped, mode)
			} else if err := os.Remove(khPath); err != nil && !os.IsNotExist(err) {
				debugf("warning: failed to remove %s during recovery rollback: %v", khPath, err)
			}
		}
	}
	return resetPendingHostKeyAlert(ctx, srv, fp)
}

func confirmAlreadyTrusted(ctx context.Context, sc *SSHConnector, srv shared.Fail2banServer, khPath, fingerprint string) error {
	verifyCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if err := verifyHostKey(verifyCtx, sc); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		rememberHostKeyIssue(&SSHHostKeyError{
			ServerID: srv.ID, Host: srv.Host, Port: srv.Port, Fingerprint: fingerprint,
		})
		return nil
	}
	resolveHostKeyAccept(srv.ID, khPath)
	return nil
}

func presentedFingerprintOr(srv shared.Fail2banServer, fallback string) string {
	if issue := HostKeyIssue(srv.ID); issue != nil && issue.Fingerprint != "" {
		return issue.Fingerprint
	}
	return fallback
}
