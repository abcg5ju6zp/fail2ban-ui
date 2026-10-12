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
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/swissmakers/fail2ban-ui/internal/shared"
)

const changedKeyBanner = `@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!
Someone could be eavesdropping on you right now (man-in-the-middle attack)!
It is also possible that a host key has just been changed.
The fingerprint for the ED25519 key sent by the remote host is
SHA256:31qptbbgMC2I2FWQsTsaKadlJA0UUgZFHYOr+83qzlA.
Please contact your system administrator.
Add correct host key in /config/.ssh/known_hosts to get rid of this message.
Offending ED25519 key in /config/.ssh/known_hosts:1
Host key for [127.0.0.1]:2222 has changed and you have requested strict checking.
Host key verification failed.`

func hostKeyTestConnector() *SSHConnector {
	return &SSHConnector{server: shared.Fail2banServer{
		ID: "srv-1", Name: "mySSH", Host: "127.0.0.1", Port: 2222, SSHUser: "f2b",
	}}
}

func TestParseHostKeyError(t *testing.T) {
	sc := hostKeyTestConnector()

	t.Run("full banner", func(t *testing.T) {
		hk := sc.parseHostKeyError(changedKeyBanner, nil)
		if hk == nil {
			t.Fatal("banner must be classified as host-key error")
		}
		if hk.Fingerprint != "SHA256:31qptbbgMC2I2FWQsTsaKadlJA0UUgZFHYOr+83qzlA" {
			t.Errorf("fingerprint = %q", hk.Fingerprint)
		}
		if hk.Host != "127.0.0.1" || hk.ServerID != "srv-1" {
			t.Errorf("server identity not carried: %+v", hk)
		}
	})

	t.Run("bare verification failure", func(t *testing.T) {
		hk := sc.parseHostKeyError("Host key verification failed.", nil)
		if hk == nil {
			t.Fatal("bare failure must still be classified")
		}
		if hk.Fingerprint != "" {
			t.Errorf("no fingerprint expected, got %q", hk.Fingerprint)
		}
	})

	t.Run("unrelated errors are not classified", func(t *testing.T) {
		for _, s := range []string{"Permission denied (publickey).", "Connection refused", ""} {
			if hk := sc.parseHostKeyError(s, nil); hk != nil {
				t.Errorf("stderr %q must not be a host-key error", s)
			}
		}
	})
}

func TestHostKeyIssueRegistry(t *testing.T) {
	t.Cleanup(func() { pruneHostKeyIssues(map[string]struct{}{}) })

	if HostKeyIssue("reg-1") != nil {
		t.Fatal("registry must start empty for reg-1")
	}
	RecordHostKeyIssue(&SSHHostKeyError{ServerID: "reg-1", Fingerprint: "SHA256:aaa"})
	RecordHostKeyIssue(&SSHHostKeyError{ServerID: "reg-2", Fingerprint: "SHA256:bbb"})
	if got := HostKeyIssue("reg-1"); got == nil || got.Fingerprint != "SHA256:aaa" {
		t.Fatalf("recorded issue not returned: %+v", got)
	}

	// Overwrite with a newer fingerprint
	RecordHostKeyIssue(&SSHHostKeyError{ServerID: "reg-1", Fingerprint: "SHA256:ccc"})
	if got := HostKeyIssue("reg-1"); got.Fingerprint != "SHA256:ccc" {
		t.Fatalf("newer issue must overwrite, got %+v", got)
	}

	// Returned value is a copy
	HostKeyIssue("reg-1").Fingerprint = "mutated"
	if HostKeyIssue("reg-1").Fingerprint != "SHA256:ccc" {
		t.Fatal("HostKeyIssue must return a copy")
	}

	ClearHostKeyIssue("reg-1")
	if HostKeyIssue("reg-1") != nil {
		t.Fatal("cleared issue must be gone")
	}

	pruneHostKeyIssues(map[string]struct{}{})
	if HostKeyIssue("reg-2") != nil {
		t.Fatal("pruned issue must be gone")
	}
}

func TestNormalizeFingerprint(t *testing.T) {
	cases := map[string]string{
		"":              "",
		"SHA256:abc":    "SHA256:abc",
		"abc":           "SHA256:abc",
		"  SHA256:abc ": "SHA256:abc",
	}
	for in, want := range cases {
		if got := NormalizeFingerprint(in); got != want {
			t.Errorf("NormalizeFingerprint(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestKnownHostsPattern(t *testing.T) {
	cases := []struct {
		host string
		port int
		want string
	}{
		{"example.com", 0, "example.com"},
		{"example.com", 22, "example.com"},
		{"127.0.0.1", 2222, "[127.0.0.1]:2222"},
		{"2001:db8::1", 2222, "[2001:db8::1]:2222"},
	}
	for _, c := range cases {
		if got := knownHostsPattern(c.host, c.port); got != c.want {
			t.Errorf("knownHostsPattern(%q, %d) = %q, want %q", c.host, c.port, got, c.want)
		}
	}
}

func generateHostKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// Parses every entry line, returning host tokens and the pinned fingerprint per line.
func parseKnownHostsEntries(t *testing.T, data []byte) []struct {
	hosts []string
	fp    string
} {
	t.Helper()
	var out []struct {
		hosts []string
		fp    string
	}
	rest := data
	for len(bytes.TrimSpace(rest)) > 0 {
		_, hosts, key, _, next, err := ssh.ParseKnownHosts(rest)
		if err != nil {
			t.Fatalf("generated known_hosts must parse: %v\n%s", err, rest)
		}
		out = append(out, struct {
			hosts []string
			fp    string
		}{hosts: hosts, fp: ssh.FingerprintSHA256(key)})
		rest = next
	}
	return out
}

func TestBuildKnownHostsContentReplacesAllTargetEntries(t *testing.T) {
	pattern := knownHostsPattern("127.0.0.1", 2222) // [127.0.0.1]:2222
	oldKey := generateHostKey(t)
	newKey := generateHostKey(t)
	otherKey := generateHostKey(t)
	hashedOld := knownhosts.Line([]string{knownhosts.HashHostname(pattern)}, oldKey)
	plainOld := knownhosts.Line([]string{pattern}, oldKey)
	other := knownhosts.Line([]string{"other.example", pattern}, otherKey)
	old := []byte("# managed by ops\n" + plainOld + "\n\n" + hashedOld + "\n" + other + "\n")

	content := buildKnownHostsContent(old, pattern, newKey)
	entries := parseKnownHostsEntries(t, content)

	var targetFPs, otherFPs []string
	for _, e := range entries {
		coversTarget := false
		for _, h := range e.hosts {
			if h == "other.example" {
				otherFPs = append(otherFPs, e.fp)
			}
			if knownHostTokenAuthorizes(h, pattern) {
				coversTarget = true
			}
		}
		if coversTarget {
			targetFPs = append(targetFPs, e.fp)
		}
	}
	if len(targetFPs) != 1 || targetFPs[0] != ssh.FingerprintSHA256(newKey) {
		t.Errorf("target must pin exactly the new key, got %v", targetFPs)
	}
	if len(otherFPs) != 1 || otherFPs[0] != ssh.FingerprintSHA256(otherKey) {
		t.Errorf("unrelated host entry must survive, got %v", otherFPs)
	}
	if !bytes.Contains(content, []byte("# managed by ops")) {
		t.Error("comments must be preserved")
	}
	// No duplicate or leftover old entries.
	if !bytes.Contains(content, []byte(knownhosts.Line([]string{pattern}, newKey))) {
		t.Error("new entry missing")
	}
}

func TestBuildKnownHostsContentFirstTrust(t *testing.T) {
	pattern := knownHostsPattern("host.example", 0) // default port 22, no brackets
	key := generateHostKey(t)
	content := buildKnownHostsContent(nil, pattern, key)
	entries := parseKnownHostsEntries(t, content)
	if len(entries) != 1 || entries[0].hosts[0] != "host.example" ||
		entries[0].fp != ssh.FingerprintSHA256(key) {
		t.Fatalf("first-trust content = %+v", entries)
	}
}

func TestStripKnownHostsKeepsUnreadableLines(t *testing.T) {
	pattern := knownHostsPattern("127.0.0.1", 2222)
	garbage := []byte("this line is not a valid known_hosts record\n")
	stripped := stripKnownHostsEntries(garbage, pattern)
	if !bytes.Equal(stripped, garbage) {
		t.Errorf("unparseable lines must be kept verbatim, got %q", stripped)
	}
}

func TestKnownHostTokenAuthorizes(t *testing.T) {
	pattern := "[127.0.0.1]:2222"
	if !knownHostTokenAuthorizes(pattern, pattern) {
		t.Error("plain token must match")
	}
	if knownHostTokenAuthorizes("other.example", pattern) {
		t.Error("unrelated plain token must not match")
	}
	if !knownHostTokenAuthorizes(knownhosts.HashHostname(pattern), pattern) {
		t.Error("hashed token for this authority must match")
	}
	if knownHostTokenAuthorizes(knownhosts.HashHostname("127.0.0.1"), pattern) {
		t.Error("hashed token of the port-22 authority must not match port 2222")
	}
	if knownHostTokenAuthorizes("|1|not-base64!!", pattern) {
		t.Error("malformed hash token must not match")
	}
	// A negated entry for the same authority must be dropped on re-pin,
	// otherwise it would revoke the newly appended key.
	if !knownHostTokenAuthorizes("!"+pattern, pattern) {
		t.Error("negated token for the same authority must be classified as covering it")
	}
}

func TestMatchingKnownHostFingerprints(t *testing.T) {
	pattern := knownHostsPattern("127.0.0.1", 2222)
	plainKey := generateHostKey(t)
	hashKey := generateHostKey(t)
	otherKey := generateHostKey(t)
	content := []byte(knownhosts.Line([]string{pattern}, plainKey) + "\n" +
		knownhosts.Line([]string{knownhosts.HashHostname(pattern)}, hashKey) + "\n" +
		knownhosts.Line([]string{"other.example"}, otherKey) + "\n")

	got := matchingKnownHostFingerprints(content, pattern)
	want := map[string]bool{
		ssh.FingerprintSHA256(plainKey): true,
		ssh.FingerprintSHA256(hashKey):  true,
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 matching fingerprints (plain+hashed), got %v", got)
	}
	for _, fp := range got {
		if !want[fp] {
			t.Errorf("unexpected fingerprint %s", fp)
		}
	}
	if first := firstMatchingFingerprint(content, pattern); first == "" {
		t.Error("firstMatchingFingerprint must find an entry")
	}
	if first := firstMatchingFingerprint(nil, pattern); first != "" {
		t.Error("empty file must have no matching fingerprint")
	}
}
