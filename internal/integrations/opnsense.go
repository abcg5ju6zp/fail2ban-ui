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

package integrations

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/swissmakers/fail2ban-ui/internal/config"
	"github.com/swissmakers/fail2ban-ui/internal/httpx"
	"github.com/swissmakers/fail2ban-ui/internal/shared"
)

type opnsenseIntegration struct{}

func init() {
	Register(&opnsenseIntegration{})
}

// =========================================================================
//  Interface Implementation
// =========================================================================

func (o *opnsenseIntegration) ID() string {
	return "opnsense"
}

func (o *opnsenseIntegration) Validate(cfg config.AdvancedActionsConfig) error {
	if err := ValidateOutboundURL(cfg.OPNsense.BaseURL, "OPNsense base URL"); err != nil {
		return err
	}
	if cfg.OPNsense.APIKey == "" || cfg.OPNsense.APISecret == "" {
		return fmt.Errorf("OPNsense API key and secret are required")
	}
	if err := ValidateIdentifier(cfg.OPNsense.Alias, "OPNsense alias"); err != nil {
		return err
	}
	return nil
}

// =========================================================================
//  Block/Unblock
// =========================================================================

func (o *opnsenseIntegration) BlockIP(req Request) error {
	if err := o.Validate(req.Config); err != nil {
		return err
	}
	if err := shared.ValidateIP(req.IP); err != nil {
		return fmt.Errorf("opnsense block: %w", err)
	}
	return o.callAPI(req, "add", req.IP)
}

func (o *opnsenseIntegration) UnblockIP(req Request) error {
	if err := o.Validate(req.Config); err != nil {
		return err
	}
	if err := shared.ValidateIP(req.IP); err != nil {
		return fmt.Errorf("opnsense unblock: %w", err)
	}
	return o.callAPI(req, "delete", req.IP)
}

// IsIPBlocked reports whether the IP is listed in the configured alias.
func (o *opnsenseIntegration) IsIPBlocked(req Request) (bool, error) {
	if err := o.Validate(req.Config); err != nil {
		return false, err
	}
	if err := shared.ValidateIP(req.IP); err != nil {
		return false, fmt.Errorf("opnsense lookup: %w", err)
	}
	cfg := req.Config.OPNsense
	if err := ValidateOutboundURL(cfg.BaseURL, "OPNsense base URL"); err != nil {
		return false, err
	}
	if err := ValidateIdentifier(cfg.Alias, "OPNsense alias"); err != nil {
		return false, err
	}
	base, err := url.Parse(cfg.BaseURL)
	if err != nil {
		return false, fmt.Errorf("invalid OPNsense base URL: %w", err)
	}
	apiURL := base.JoinPath("api", "firewall", "alias_util", "list", cfg.Alias).String()

	httpClient := httpx.Client(10*time.Second, cfg.SkipTLSVerify)
	httpReq, err := http.NewRequestWithContext(ContextFor(req.Context), http.MethodGet, apiURL, nil)
	if err != nil {
		return false, fmt.Errorf("failed to create OPNsense request: %w", err)
	}
	auth := base64.StdEncoding.EncodeToString([]byte(cfg.APIKey + ":" + cfg.APISecret))
	httpReq.Header.Set("Authorization", "Basic "+auth)

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return false, fmt.Errorf("OPNsense API request to %s failed: %w", apiURL, err)
	}
	defer resp.Body.Close()
	bodyBytes, _ := httpx.ReadLimited(resp.Body)

	if resp.StatusCode == http.StatusNotFound {
		// Alias does not exist, so it cannot contain the IP.
		return false, nil
	}
	if resp.StatusCode >= 300 {
		return false, fmt.Errorf("OPNsense API request failed: status %s", resp.Status)
	}

	// The list payload nests entries in different shapes across releases;
	// accept every one of them.
	var payload struct {
		Rows []struct {
			IP      string `json:"ip"`
			Address string `json:"address"`
			Value   string `json:"value"`
		} `json:"rows"`
		Data []struct {
			IP      string `json:"ip"`
			Address string `json:"address"`
			Value   string `json:"value"`
		} `json:"data"`
	}
	if err := json.Unmarshal(bodyBytes, &payload); err != nil {
		return false, fmt.Errorf("failed to decode OPNsense alias list: %w", err)
	}
	for _, entry := range payload.Rows {
		if entry.IP == req.IP || entry.Address == req.IP || entry.Value == req.IP {
			return true, nil
		}
	}
	for _, entry := range payload.Data {
		if entry.IP == req.IP || entry.Address == req.IP || entry.Value == req.IP {
			return true, nil
		}
	}
	return false, nil
}

// =========================================================================
//  OPNsense API
// =========================================================================

func (o *opnsenseIntegration) callAPI(req Request, action, ip string) error {
	cfg := req.Config.OPNsense
	if err := ValidateOutboundURL(cfg.BaseURL, "OPNsense base URL"); err != nil {
		return err
	}
	if err := ValidateIdentifier(cfg.Alias, "OPNsense alias"); err != nil {
		return err
	}
	base, err := url.Parse(cfg.BaseURL)
	if err != nil {
		return fmt.Errorf("invalid OPNsense base URL: %w", err)
	}
	apiURL := base.JoinPath("api", "firewall", "alias_util", action, cfg.Alias).String()
	payload := map[string]string{
		"address": ip,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to encode OPNsense payload: %w", err)
	}

	httpClient := httpx.Client(10*time.Second, cfg.SkipTLSVerify)

	reqLogger := "OPNsense"
	if req.Logger != nil {
		req.Logger("Calling OPNsense API %s action=%s payload=%s", apiURL, action, string(data))
	}

	httpReq, err := http.NewRequestWithContext(ContextFor(req.Context), http.MethodPost, apiURL, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create OPNsense request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	auth := base64.StdEncoding.EncodeToString([]byte(cfg.APIKey + ":" + cfg.APISecret))
	httpReq.Header.Set("Authorization", "Basic "+auth)

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return MarkUncertain(fmt.Errorf("OPNsense API request to %s failed: %w (check base URL, network connectivity, and API credentials)", apiURL, err))
	}
	defer resp.Body.Close()
	bodyBytes, _ := httpx.ReadLimited(resp.Body)
	bodyStr := strings.TrimSpace(string(bodyBytes))

	if resp.StatusCode >= 300 {
		apiErr := fmt.Errorf("OPNsense API request failed: status %s, response: %s", resp.Status, bodyStr)
		if bodyStr == "" {
			apiErr = fmt.Errorf("OPNsense API request failed: status %s (check API credentials and alias name)", resp.Status)
		}
		if ResponseStatusUncertain(resp.StatusCode) {
			return MarkUncertain(apiErr)
		}
		return apiErr
	}

	if req.Logger != nil {
		req.Logger("%s API call succeeded", reqLogger)
		if bodyStr != "" {
			req.Logger("%s API response: %s", reqLogger, bodyStr)
		}
	}
	return nil
}
