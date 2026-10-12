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

package fail2ban

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/swissmakers/fail2ban-ui/internal/shared"
	"github.com/swissmakers/fail2ban-ui/internal/storage"
)

// The accept flow persists generation state, so the package tests run
// against a real temporary SQLite database.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "f2bui-hostkey-test-*")
	if err != nil {
		panic(err)
	}
	if err := storage.Init(filepath.Join(dir, "test.db")); err != nil {
		panic(err)
	}
	code := m.Run()
	_ = storage.Close()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func newHostSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

// Minimal SSH server that completes the key exchange (which is all the host
// key scanner needs) and then drops the connection.
func startFakeSSHServer(t *testing.T, signer ssh.Signer) (string, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				cfg := &ssh.ServerConfig{NoClientAuth: true}
				cfg.AddHostKey(signer)
				conn, _, _, sErr := ssh.NewServerConn(c, cfg)
				if sErr == nil {
					_ = conn.Close()
				}
			}(c)
		}
	}()
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	return host, port
}

func acceptTestServer(t *testing.T, id string, port int) (shared.Fail2banServer, string) {
	t.Helper()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(keyPath, []byte("dummy key"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv := shared.Fail2banServer{
		ID: id, Name: "hk-" + id, Type: "ssh",
		Host: "127.0.0.1", Port: port, SSHUser: "f2b",
		SSHKeyPath: keyPath, Enabled: true, EnabledSet: true,
	}
	return srv, filepath.Join(dir, "known_hosts")
}

func seedPendingHostKey(t *testing.T, srv shared.Fail2banServer, fp string) {
	t.Helper()
	RecordHostKeyIssue(&SSHHostKeyError{
		ServerID: srv.ID, Host: srv.Host, Port: srv.Port, Fingerprint: fp,
	})
	t.Cleanup(func() { ClearHostKeyIssue(srv.ID) })
}

func setFixedConfigLookup(t *testing.T, srv shared.Fail2banServer) {
	t.Helper()
	SetServerConfigLookup(func(id string) (shared.Fail2banServer, bool) {
		if id == srv.ID {
			return srv, true
		}
		return shared.Fail2banServer{}, false
	})
	t.Cleanup(func() { SetServerConfigLookup(nil) })
}

func setVerifyStub(t *testing.T, fn func(context.Context, *SSHConnector) error) {
	t.Helper()
	original := verifyHostKey
	verifyHostKey = fn
	t.Cleanup(func() { verifyHostKey = original })
}

func getHostKeyRow(t *testing.T, id string) *storage.HostKeyAlertRecord {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	row, err := storage.GetHostKeyAlert(ctx, id)
	if err != nil {
		t.Fatalf("load alert row: %v", err)
	}
	return row
}

func writeKnownHosts(t *testing.T, path string, lines ...string) []byte {
	t.Helper()
	content := []byte{}
	for _, l := range lines {
		content = append(content, []byte(l+"\n")...)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return content
}

// =========================================================================
//  Accept flow
// =========================================================================

func TestAcceptHostKeyHappyPath(t *testing.T) {
	signer := newHostSigner(t)
	host, port := startFakeSSHServer(t, signer)
	srv, khPath := acceptTestServer(t, "hka1", 0)
	srv.Host, srv.Port = host, port
	fp := ssh.FingerprintSHA256(signer.PublicKey())
	seedPendingHostKey(t, srv, fp)
	setFixedConfigLookup(t, srv)
	setVerifyStub(t, func(context.Context, *SSHConnector) error { return nil })

	got, err := AcceptHostKey(context.Background(), srv, fp)
	if err != nil {
		t.Fatalf("accept failed: %v", err)
	}
	if got != fp {
		t.Errorf("accepted fp = %q, want %q", got, fp)
	}

	data, err := os.ReadFile(khPath)
	if err != nil {
		t.Fatalf("known_hosts missing: %v", err)
	}
	pins := matchingKnownHostFingerprints(data, knownHostsPattern(srv.Host, srv.Port))
	if len(pins) != 1 || pins[0] != fp {
		t.Errorf("known_hosts must pin exactly the new key, got %v", pins)
	}
	if info, err := os.Stat(khPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("known_hosts perms = %v, err = %v", info, err)
	}
	if _, err := os.Stat(khPath + backupSuffix); !os.IsNotExist(err) {
		t.Error("backup must be removed after successful verification")
	}
	if row := getHostKeyRow(t, srv.ID); row != nil {
		t.Errorf("durable alert must be cleared, got %+v", row)
	}
	if HostKeyIssue(srv.ID) != nil {
		t.Error("in-memory alert must be cleared")
	}
}

func TestAcceptHostKeyMismatchDoesNotTouchFile(t *testing.T) {
	signer := newHostSigner(t)
	host, port := startFakeSSHServer(t, signer)
	srv, khPath := acceptTestServer(t, "hka2", 0)
	srv.Host, srv.Port = host, port
	presented := ssh.FingerprintSHA256(signer.PublicKey())
	seedPendingHostKey(t, srv, presented)
	setFixedConfigLookup(t, srv)
	verifyCalled := atomic.Bool{}
	setVerifyStub(t, func(context.Context, *SSHConnector) error {
		verifyCalled.Store(true)
		return nil
	})

	_, err := AcceptHostKey(context.Background(), srv, "SHA256:"+stringsRepeats(43))
	var mismatch *HostKeyMismatchError
	if !errors.As(err, &mismatch) || mismatch.Presented != presented {
		t.Fatalf("want mismatch carrying the real presented fingerprint, got %v", err)
	}
	if verifyCalled.Load() {
		t.Error("verification must never run on fingerprint mismatch")
	}
	if _, err := os.Stat(khPath); !os.IsNotExist(err) {
		t.Error("known_hosts must not be created on mismatch")
	}
	row := getHostKeyRow(t, srv.ID)
	if row == nil || row.Fingerprint != presented || row.Phase != storage.HostKeyPhasePending {
		t.Fatalf("durable alert must keep showing the presented fp, got %+v", row)
	}
}

func TestAcceptHostKeyVerifyFailureRestoresTrustedFile(t *testing.T) {
	signer := newHostSigner(t)
	host, port := startFakeSSHServer(t, signer)
	srv, khPath := acceptTestServer(t, "hka3", 0)
	srv.Host, srv.Port = host, port
	pattern := knownHostsPattern(srv.Host, srv.Port)
	oldKey := generateHostKey(t)
	newFP := ssh.FingerprintSHA256(signer.PublicKey())

	// Trusted file: comment + plain old key + hashed old key + unrelated host.
	original := writeKnownHosts(t, khPath,
		"# keep me",
		knownhosts.Line([]string{pattern}, oldKey),
		knownhosts.Line([]string{knownhosts.HashHostname(pattern)}, generateHostKey(t)),
		knownhosts.Line([]string{"unrelated.example"}, generateHostKey(t)),
	)
	seedPendingHostKey(t, srv, newFP)
	setFixedConfigLookup(t, srv)
	setVerifyStub(t, func(context.Context, *SSHConnector) error {
		return errors.New("host key verification failed")
	})

	_, err := AcceptHostKey(context.Background(), srv, newFP)
	if err == nil {
		t.Fatal("accept must surface the verification failure")
	}

	after, err := os.ReadFile(khPath)
	if err != nil {
		t.Fatalf("trusted known_hosts must exist: %v", err)
	}
	if string(after) != string(original) {
		t.Errorf("trusted known_hosts must be restored byte-for-byte\nwant %q\ngot  %q", original, after)
	}
	if _, err := os.Stat(khPath + backupSuffix); !os.IsNotExist(err) {
		t.Error("backup must be removed after rollback")
	}
	row := getHostKeyRow(t, srv.ID)
	if row == nil || row.Phase != storage.HostKeyPhasePending || row.Fingerprint != newFP {
		t.Fatalf("retryable pending alert must remain, got %+v", row)
	}
	if issue := HostKeyIssue(srv.ID); issue == nil || issue.Fingerprint != newFP {
		t.Fatalf("in-memory retry alert must remain, got %+v", issue)
	}
}

func TestAcceptHostKeyVerifyFailureFirstTrustRemovesFile(t *testing.T) {
	signer := newHostSigner(t)
	host, port := startFakeSSHServer(t, signer)
	srv, khPath := acceptTestServer(t, "hka4", 0)
	srv.Host, srv.Port = host, port
	fp := ssh.FingerprintSHA256(signer.PublicKey())
	seedPendingHostKey(t, srv, fp)
	setFixedConfigLookup(t, srv)
	setVerifyStub(t, func(context.Context, *SSHConnector) error { return errors.New("boom") })

	if _, err := AcceptHostKey(context.Background(), srv, fp); err == nil {
		t.Fatal("expected verification error")
	}
	if _, err := os.Stat(khPath); !os.IsNotExist(err) {
		t.Error("first-trust rollback must remove the newly created file")
	}
	row := getHostKeyRow(t, srv.ID)
	if row == nil || row.Phase != storage.HostKeyPhasePending {
		t.Fatalf("pending alert must remain for retry, got %+v", row)
	}
}

func TestAcceptHostKeyRejectsConcurrentAccept(t *testing.T) {
	srv, _ := acceptTestServer(t, "hka5", 2222)
	seedPendingHostKey(t, srv, "SHA256:"+stringsRepeats(43))
	setFixedConfigLookup(t, srv)

	gate := hostKeyAcceptGate(srv.ID)
	gate.Lock()
	defer gate.Unlock()
	_, err := AcceptHostKey(context.Background(), srv, "SHA256:"+stringsRepeats(43))
	if !errors.Is(err, ErrHostKeyAcceptBusy) {
		t.Fatalf("want ErrHostKeyAcceptBusy, got %v", err)
	}
}

func TestAcceptHostKeyStaleGenerationBeforePublish(t *testing.T) {
	signer := newHostSigner(t)
	host, port := startFakeSSHServer(t, signer)
	srv, khPath := acceptTestServer(t, "hka6", 0)
	srv.Host, srv.Port = host, port
	fp := ssh.FingerprintSHA256(signer.PublicKey())
	seedPendingHostKey(t, srv, fp)

	var calls atomic.Int32
	SetServerConfigLookup(func(id string) (shared.Fail2banServer, bool) {
		if calls.Add(1) >= 2 {
			changed := srv
			changed.Host = "10.255.255.1"
			return changed, true
		}
		return srv, true
	})
	t.Cleanup(func() { SetServerConfigLookup(nil) })
	setVerifyStub(t, func(context.Context, *SSHConnector) error {
		t.Error("verification must not run for a stale generation")
		return nil
	})

	_, err := AcceptHostKey(context.Background(), srv, fp)
	var stale *HostKeyAcceptStaleError
	if !errors.As(err, &stale) {
		t.Fatalf("want HostKeyAcceptStaleError, got %v", err)
	}
	if _, err := os.Stat(khPath); !os.IsNotExist(err) {
		t.Error("stale generation must not publish known_hosts")
	}
}

func TestAcceptHostKeyStaleGenerationAfterPublishRollsBack(t *testing.T) {
	signer := newHostSigner(t)
	host, port := startFakeSSHServer(t, signer)
	srv, khPath := acceptTestServer(t, "hka7", 0)
	srv.Host, srv.Port = host, port
	pattern := knownHostsPattern(srv.Host, srv.Port)
	oldKey := generateHostKey(t)
	original := writeKnownHosts(t, khPath, knownhosts.Line([]string{pattern}, oldKey))
	fp := ssh.FingerprintSHA256(signer.PublicKey())
	seedPendingHostKey(t, srv, fp)

	var calls atomic.Int32
	SetServerConfigLookup(func(id string) (shared.Fail2banServer, bool) {
		if calls.Add(1) >= 3 {
			changed := srv
			changed.Host = "10.255.255.2"
			return changed, true
		}
		return srv, true
	})
	t.Cleanup(func() { SetServerConfigLookup(nil) })
	setVerifyStub(t, func(context.Context, *SSHConnector) error {
		t.Error("verification must not run for a stale generation")
		return nil
	})

	_, err := AcceptHostKey(context.Background(), srv, fp)
	var stale *HostKeyAcceptStaleError
	if !errors.As(err, &stale) {
		t.Fatalf("want HostKeyAcceptStaleError, got %v", err)
	}
	after, err := os.ReadFile(khPath)
	if err != nil || string(after) != string(original) {
		t.Fatalf("late generation must restore the trusted file, got %q err %v", after, err)
	}
	row := getHostKeyRow(t, srv.ID)
	if row == nil || row.Phase != storage.HostKeyPhasePending {
		t.Fatalf("retryable alert must remain, got %+v", row)
	}
}

func TestAcceptHostKeyCanceledLeavesReconcilableState(t *testing.T) {
	signer := newHostSigner(t)
	host, port := startFakeSSHServer(t, signer)
	srv, khPath := acceptTestServer(t, "hka8", 0)
	srv.Host, srv.Port = host, port
	fp := ssh.FingerprintSHA256(signer.PublicKey())
	seedPendingHostKey(t, srv, fp)
	setFixedConfigLookup(t, srv)

	reachedVerify := make(chan struct{})
	setVerifyStub(t, func(ctx context.Context, _ *SSHConnector) error {
		close(reachedVerify)
		<-ctx.Done()
		return ctx.Err()
	})

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-reachedVerify
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	if _, err := AcceptHostKey(ctx, srv, fp); err == nil {
		t.Fatal("canceled accept must return an error")
	}

	// New key landed and the durable row marks an unfinished verification.
	data, err := os.ReadFile(khPath)
	if err != nil {
		t.Fatalf("published file must survive cancellation: %v", err)
	}
	if !knownHostsFilePins(data, knownHostsPattern(srv.Host, srv.Port), fp) {
		t.Fatal("published key must still be on disk")
	}
	row := getHostKeyRow(t, srv.ID)
	if row == nil || row.Phase != storage.HostKeyPhasePublished || row.ApprovedFingerprint != fp {
		t.Fatalf("row must stay published for reconciliation, got %+v", row)
	}

	// Restart-style reconciliation with healthy verification settles it.
	setVerifyStub(t, func(context.Context, *SSHConnector) error { return nil })
	recoveryCtx, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()
	if err := reconcileHostKeyState(recoveryCtx, srv); err != nil {
		t.Fatalf("reconciliation failed: %v", err)
	}
	if row := getHostKeyRow(t, srv.ID); row != nil {
		t.Errorf("reconciliation must settle the row, got %+v", row)
	}
	if HostKeyIssue(srv.ID) != nil {
		t.Error("reconciliation must clear the banner")
	}
}

// =========================================================================
//  Restart recovery and durable alert loading
// =========================================================================

func TestReconcilePublishedAcceptRollbackFromBackup(t *testing.T) {
	signer := newHostSigner(t)
	host, port := startFakeSSHServer(t, signer)
	srv, khPath := acceptTestServer(t, "hkr1", 0)
	srv.Host, srv.Port = host, port
	pattern := knownHostsPattern(srv.Host, srv.Port)
	oldKey := generateHostKey(t)
	newFP := ssh.FingerprintSHA256(signer.PublicKey())
	oldLine := knownhosts.Line([]string{pattern}, oldKey)
	newLine := knownhosts.Line([]string{pattern}, signer.PublicKey())

	// Simulate a crash after rename: new content live, backup holds old content.
	writeKnownHosts(t, khPath+backupSuffix, oldLine)
	writeKnownHosts(t, khPath, newLine)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := storage.UpsertHostKeyAlert(ctx, storage.HostKeyAlertRecord{
		ServerID: srv.ID, Host: srv.Host, Port: srv.Port,
		Fingerprint: newFP, ApprovedFingerprint: newFP,
		PreviousFingerprint: ssh.FingerprintSHA256(oldKey),
		Phase:               storage.HostKeyPhasePublished, UpdatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	setFixedConfigLookup(t, srv)
	setVerifyStub(t, func(context.Context, *SSHConnector) error { return errors.New("still failing") })

	if err := reconcileHostKeyState(context.Background(), srv); err != nil {
		t.Fatalf("reconciliation failed: %v", err)
	}
	data, err := os.ReadFile(khPath)
	if err != nil {
		t.Fatalf("trusted file must be restored: %v", err)
	}
	if !knownHostsFilePins(data, pattern, ssh.FingerprintSHA256(oldKey)) {
		t.Error("restored file must pin the old trusted key")
	}
	if knownHostsFilePins(data, pattern, newFP) {
		t.Error("restored file must not pin the rejected new key")
	}
	if _, err := os.Stat(khPath + backupSuffix); !os.IsNotExist(err) {
		t.Error("backup must be consumed by recovery")
	}
	row := getHostKeyRow(t, srv.ID)
	if row == nil || row.Phase != storage.HostKeyPhasePending || row.Fingerprint != newFP {
		t.Fatalf("retryable pending alert expected, got %+v", row)
	}
}

func TestLoadPersistentHostKeyIssues(t *testing.T) {
	good := shared.Fail2banServer{
		ID: "hkl1", Type: "ssh", Host: "127.0.0.1", Port: 2222,
		SSHUser: "f2b", Enabled: true, EnabledSet: true,
	}
	addressChanged := good
	addressChanged.ID = "hkl2"
	missing := good
	missing.ID = "hkl3"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rows := []storage.HostKeyAlertRecord{
		{ServerID: good.ID, Host: good.Host, Port: good.Port, Fingerprint: "SHA256:good123", Phase: storage.HostKeyPhasePending, UpdatedAt: time.Now().UTC()},
		{ServerID: addressChanged.ID, Host: "10.9.9.9", Port: 2222, Fingerprint: "SHA256:old12345", Phase: storage.HostKeyPhasePending, UpdatedAt: time.Now().UTC()},
		{ServerID: missing.ID, Host: "127.0.0.1", Port: 22, Fingerprint: "SHA256:gone1234", Phase: storage.HostKeyPhasePending, UpdatedAt: time.Now().UTC()},
	}
	for _, r := range rows {
		if err := storage.UpsertHostKeyAlert(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_ = storage.DeleteHostKeyAlert(context.Background(), good.ID)
	})

	LoadPersistentHostKeyIssues([]shared.Fail2banServer{good, addressChanged})

	if issue := HostKeyIssue(good.ID); issue == nil || issue.Fingerprint != "SHA256:good123" || issue.Port != 2222 {
		t.Errorf("matching alert must be restored to memory, got %+v", issue)
	}
	if getHostKeyRow(t, addressChanged.ID) != nil {
		t.Error("alert whose address changed must be deleted")
	}
	if getHostKeyRow(t, missing.ID) != nil {
		t.Error("alert for a removed server must be deleted")
	}
}

func TestEnsureCurrentServerGeneration(t *testing.T) {
	pinned := shared.Fail2banServer{
		ID: "hkgen", Type: "ssh", Host: "h.example", Port: 2200,
		SSHUser: "f2b", SSHKeyPath: "/etc/key", Enabled: true,
	}
	// Without a configuration bridge the generation cannot be proven, so it fails closed.
	SetServerConfigLookup(nil)
	if err := ensureCurrentServerGeneration(pinned); err == nil {
		t.Error("missing configuration lookup must fail closed")
	}

	SetServerConfigLookup(func(string) (shared.Fail2banServer, bool) {
		return shared.Fail2banServer{}, false
	})
	if err := ensureCurrentServerGeneration(pinned); err == nil {
		t.Error("removed server must be stale")
	}

	for _, mutate := range []func(*shared.Fail2banServer){
		func(s *shared.Fail2banServer) { s.Host = "other.example" },
		func(s *shared.Fail2banServer) { s.Port = 2201 },
		func(s *shared.Fail2banServer) { s.SSHUser = "root" },
		func(s *shared.Fail2banServer) { s.SSHKeyPath = "/etc/other" },
		func(s *shared.Fail2banServer) { s.Enabled = false },
		func(s *shared.Fail2banServer) { s.Type = "local" },
	} {
		current := pinned
		mutate(&current)
		SetServerConfigLookup(func(string) (shared.Fail2banServer, bool) { return current, true })
		if err := ensureCurrentServerGeneration(pinned); err == nil {
			t.Errorf("mutation %+v must be stale", current)
		}
	}
	SetServerConfigLookup(func(string) (shared.Fail2banServer, bool) { return pinned, true })
	if err := ensureCurrentServerGeneration(pinned); err != nil {
		t.Errorf("identical generation must commit: %v", err)
	}
	SetServerConfigLookup(nil)
}

// stringsRepeats builds a syntactically valid but meaningless SHA256 body.
func stringsRepeats(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = "A"[0]
	}
	return string(b)
}
