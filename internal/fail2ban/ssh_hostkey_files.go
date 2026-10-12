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

// Whole-file known_hosts rewriting: the accept flow never edits the trusted
// file in place. It reads the current content, drops every entry (plain or
// hashed, any key algorithm) authorizing the server, appends the approved
// key, and publishes the result through the fsync+rename primitive.

package fail2ban

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func bytesEqual(a, b []byte) bool { return bytes.Equal(a, b) }

func readKnownHostsFile(khPath string) (content []byte, existed bool, mode os.FileMode, err error) {
	content, err = os.ReadFile(khPath)
	if err == nil {
		mode = os.FileMode(0o600)
		if info, statErr := os.Stat(khPath); statErr == nil && info.Mode().Perm() != 0 {
			mode = info.Mode().Perm()
		}
		return content, true, mode, nil
	}
	if os.IsNotExist(err) {
		return nil, false, 0o600, nil
	}
	return nil, false, 0o600, err
}

// stripKnownHostsEntries removes every line authorizing pattern, preserving
// comments, blank lines, unrelated entries and lines this parser cannot read.
// A multi-host line loses only the matching host token.
func stripKnownHostsEntries(old []byte, pattern string) []byte {
	var out bytes.Buffer
	lines := bytes.Split(old, []byte("\n"))
	for i, raw := range lines {
		line := bytes.TrimRight(raw, "\r")
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 {
			if i < len(lines)-1 {
				out.Write(line)
				out.WriteByte('\n')
			}
			continue
		}
		if trimmed[0] == '#' {
			out.Write(line)
			out.WriteByte('\n')
			continue
		}
		marker, hosts, pubKey, comment, _, perr := ssh.ParseKnownHosts(line)
		if perr != nil || pubKey == nil || len(hosts) == 0 {
			// Keep unknown lines verbatim rather than destroying them.
			out.Write(line)
			out.WriteByte('\n')
			continue
		}
		kept := make([]string, 0, len(hosts))
		matched := false
		for _, h := range hosts {
			if knownHostTokenAuthorizes(h, pattern) {
				matched = true
			} else {
				kept = append(kept, h)
			}
		}
		if !matched {
			out.Write(line)
			out.WriteByte('\n')
			continue
		}
		if len(kept) > 0 {
			rebuilt := knownhosts.Line(kept, pubKey)
			if marker != "" {
				rebuilt = marker + " " + rebuilt
			}
			if comment != "" {
				rebuilt += " " + comment
			}
			out.WriteString(rebuilt)
			out.WriteByte('\n')
		}
	}
	return out.Bytes()
}

// buildKnownHostsContent returns the complete new known_hosts content.
func buildKnownHostsContent(old []byte, pattern string, key ssh.PublicKey) []byte {
	stripped := stripKnownHostsEntries(old, pattern)
	return append(bytes.TrimRight(stripped, "\n"), []byte("\n"+knownhosts.Line([]string{pattern}, key)+"\n")...)
}

// knownHostTokenAuthorizes reports whether one known_hosts host token covers
// the normalized authority pattern, supporting plaintext and |1| hashed hosts.
func knownHostTokenAuthorizes(token, pattern string) bool {
	token = strings.TrimPrefix(token, "!")
	if token == pattern {
		return true
	}
	if !strings.HasPrefix(token, "|1|") {
		return false
	}
	parts := strings.Split(token, "|")
	if len(parts) != 4 || parts[1] != "1" {
		return false
	}
	salt, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	want, err := base64.StdEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}
	mac := hmac.New(sha1.New, salt)
	mac.Write([]byte(pattern))
	return hmac.Equal(mac.Sum(nil), want)
}

// matchingKnownHostFingerprints returns fingerprints of every key entry in
// content that authorizes pattern.
func matchingKnownHostFingerprints(content []byte, pattern string) []string {
	seen := make(map[string]struct{})
	var out []string
	collect := func(line []byte) {
		_, hosts, pubKey, _, _, err := ssh.ParseKnownHosts(line)
		if err != nil || pubKey == nil {
			return
		}
		for _, h := range hosts {
			if knownHostTokenAuthorizes(h, pattern) {
				fp := ssh.FingerprintSHA256(pubKey)
				if _, ok := seen[fp]; !ok {
					seen[fp] = struct{}{}
					out = append(out, fp)
				}
				return
			}
		}
	}
	lines := bytes.Split(content, []byte("\n"))
	for _, raw := range lines {
		line := bytes.TrimSpace(bytes.TrimRight(raw, "\r"))
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		collect(line)
	}
	return out
}

func firstMatchingFingerprint(content []byte, pattern string) string {
	fps := matchingKnownHostFingerprints(content, pattern)
	if len(fps) == 0 {
		return ""
	}
	return fps[0]
}

func knownHostsFilePins(content []byte, pattern, fingerprint string) bool {
	for _, fp := range matchingKnownHostFingerprints(content, pattern) {
		if fp == fingerprint {
			return true
		}
	}
	return false
}

// rollbackPublishedKnownHosts restores the exact trusted content of the
// previous generation after verification failed or the generation went stale.
func rollbackPublishedKnownHosts(khPath, pattern string, old []byte, oldExisted bool, mode os.FileMode) {
	if !oldExisted {
		// First-trust rollback: only remove what this accept had pinned.
		cur, existed, curMode, err := readKnownHostsFile(khPath)
		switch {
		case err != nil:
			debugf("warning: cannot inspect %s during rollback: %v", khPath, err)
		case !existed:
			// nothing to do
		default:
			stripped := stripKnownHostsEntries(cur, pattern)
			if len(bytes.TrimSpace(stripped)) == 0 {
				if err := os.Remove(khPath); err != nil && !os.IsNotExist(err) {
					debugf("warning: failed to remove %s during rollback: %v", khPath, err)
				}
			} else if err := replaceFileAtomic(khPath, stripped, curMode); err != nil {
				debugf("warning: failed to roll back first-trust known_hosts %s: %v", khPath, err)
			}
		}
		_ = os.Remove(khPath + backupSuffix)
		return
	}
	if err := replaceFileAtomic(khPath, old, mode); err != nil {
		debugf("warning: failed to restore trusted known_hosts %s: %v", khPath, err)
		return
	}
	_ = os.Remove(khPath + backupSuffix)
}

// restoreKnownHostsBackup publishes the pre-accept backup during restart
// reconciliation. Returns false when no usable backup exists.
func restoreKnownHostsBackup(khPath string) bool {
	backup, err := os.ReadFile(khPath + backupSuffix)
	if err != nil {
		return false
	}
	mode := os.FileMode(0o600)
	if info, statErr := os.Stat(khPath + backupSuffix); statErr == nil && info.Mode().Perm() != 0 {
		mode = info.Mode().Perm()
	}
	if err := replaceFileAtomic(khPath, backup, mode); err != nil {
		return false
	}
	_ = os.Remove(khPath + backupSuffix)
	return true
}
