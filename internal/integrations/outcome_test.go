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

package integrations

import (
	"errors"
	"fmt"
	"net/http"
	"testing"
)

func TestMarkUncertain(t *testing.T) {
	cause := errors.New("connection reset")
	err := MarkUncertain(cause)
	if !errors.Is(err, ErrOutcomeUncertain) {
		t.Fatalf("expected ErrOutcomeUncertain, got %v", err)
	}
	if MarkUncertain(nil) != nil {
		t.Fatal("nil should stay nil")
	}
	if !errors.Is(MarkUncertain(err), ErrOutcomeUncertain) {
		t.Fatal("re-wrapping must stay idempotent")
	}
}

func TestMikrotikMutationClassification(t *testing.T) {
	m := &mikrotikIntegration{}

	// RouterOS rejected a duplicate add: that is a confirmed existing rule.
	dup := fmt.Errorf("mikrotik command failed: %w (output: failure: already have such entry)",
		errors.New("exit status 1"))
	err := m.classifyMutationError(dup, true, []byte("failure: already have such entry"))
	if !errors.Is(err, ErrAlreadyBlocked) {
		t.Fatalf("duplicate add should map to ErrAlreadyBlocked, got %v", err)
	}

	// Connection never reached command dispatch: explicit, retryable failure.
	beforeDispatch := errors.New("failed to connect to mikrotik")
	if got := m.classifyMutationError(beforeDispatch, false, nil); errors.Is(got, ErrOutcomeUncertain) {
		t.Fatalf("pre-dispatch failure must stay explicit, got %v", got)
	}

	// Connection lost after dispatch: outcome is uncertain.
	afterDispatch := errors.New("unexpected EOF")
	if got := m.classifyMutationError(afterDispatch, true, nil); !errors.Is(got, ErrOutcomeUncertain) {
		t.Fatalf("post-dispatch transport failure must be uncertain, got %v", got)
	}
}

func TestResponseStatusUncertain(t *testing.T) {
	uncertain := []int{
		http.StatusRequestTimeout,
		http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout,
	}
	for _, code := range uncertain {
		if !ResponseStatusUncertain(code) {
			t.Errorf("status %d must be uncertain", code)
		}
	}
	explicit := []int{
		http.StatusBadRequest,
		http.StatusUnauthorized,
		http.StatusForbidden,
		http.StatusNotFound,
		http.StatusUnprocessableEntity,
	}
	for _, code := range explicit {
		if ResponseStatusUncertain(code) {
			t.Errorf("status %d must be an explicit failure", code)
		}
	}
}
