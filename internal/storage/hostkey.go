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

// Persistent state for SSH host-key change alerts and in-flight accept
// operations. A row survives request cancellation and process restarts, so
// the true on-disk state can always be reconciled against known_hosts.

package storage

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

const (
	// HostKeyPhasePending waits for an admin to review and accept the presented fingerprint.
	HostKeyPhasePending = "pending"
	// HostKeyPhasePublished marks an accepted key that has been atomically
	// published to known_hosts but whose connection verification is still
	// unfinished (or whose replacement result was uncertain).
	HostKeyPhasePublished = "published"
)

// HostKeyAlertRecord is the durable generation record for one server's host-key alert.
type HostKeyAlertRecord struct {
	ServerID            string
	Host                string
	Port                int
	Fingerprint         string // the fingerprint currently presented/displayed
	ApprovedFingerprint string // fingerprint the admin approved ("" while pending)
	PreviousFingerprint string // fingerprint the old known_hosts entry pinned ("" on first trust)
	Phase               string
	UpdatedAt           time.Time
}

func ensureHostKeyAlertSchema(ctx context.Context) error {
	_, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS host_key_alerts (
		server_id TEXT PRIMARY KEY,
		host TEXT NOT NULL,
		port INTEGER NOT NULL DEFAULT 22,
		fingerprint TEXT NOT NULL,
		approved_fingerprint TEXT NOT NULL DEFAULT '',
		previous_fingerprint TEXT NOT NULL DEFAULT '',
		phase TEXT NOT NULL DEFAULT 'pending',
		updated_at TEXT NOT NULL
	)`)
	return err
}

func scanHostKeyAlertRow(row interface {
	Scan(dest ...any) error
}) (HostKeyAlertRecord, error) {
	var rec HostKeyAlertRecord
	var updated string
	if err := row.Scan(&rec.ServerID, &rec.Host, &rec.Port, &rec.Fingerprint,
		&rec.ApprovedFingerprint, &rec.PreviousFingerprint, &rec.Phase, &updated); err != nil {
		return HostKeyAlertRecord{}, err
	}
	rec.UpdatedAt = parseStorageTime(updated)
	if rec.Phase == "" {
		rec.Phase = HostKeyPhasePending
	}
	return rec, nil
}

// GetHostKeyAlert loads the durable alert for a server; a nil record with no error means no row exists.
func GetHostKeyAlert(ctx context.Context, serverID string) (*HostKeyAlertRecord, error) {
	if db == nil {
		return nil, errors.New("storage not initialised")
	}
	row := db.QueryRowContext(ctx, `SELECT server_id, host, port, fingerprint, approved_fingerprint,
		previous_fingerprint, phase, updated_at FROM host_key_alerts WHERE server_id = ?`, serverID)
	rec, err := scanHostKeyAlertRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &rec, nil
}

// ListHostKeyAlerts returns every durable alert, oldest first.
func ListHostKeyAlerts(ctx context.Context) ([]HostKeyAlertRecord, error) {
	if db == nil {
		return nil, errors.New("storage not initialised")
	}
	rows, err := db.QueryContext(ctx, `SELECT server_id, host, port, fingerprint, approved_fingerprint,
		previous_fingerprint, phase, updated_at FROM host_key_alerts ORDER BY updated_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HostKeyAlertRecord
	for rows.Next() {
		rec, err := scanHostKeyAlertRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

// UpsertHostKeyAlert unconditionally stores the alert generation record.
func UpsertHostKeyAlert(ctx context.Context, rec HostKeyAlertRecord) error {
	if db == nil {
		return errors.New("storage not initialised")
	}
	if rec.Phase == "" {
		rec.Phase = HostKeyPhasePending
	}
	_, err := db.ExecContext(ctx, `INSERT INTO host_key_alerts(
		server_id, host, port, fingerprint, approved_fingerprint, previous_fingerprint, phase, updated_at)
		VALUES(?,?,?,?,?,?,?,?)
		ON CONFLICT(server_id) DO UPDATE SET
			host=excluded.host, port=excluded.port, fingerprint=excluded.fingerprint,
			approved_fingerprint=excluded.approved_fingerprint,
			previous_fingerprint=excluded.previous_fingerprint,
			phase=excluded.phase, updated_at=excluded.updated_at`,
		rec.ServerID, rec.Host, rec.Port, rec.Fingerprint, rec.ApprovedFingerprint,
		rec.PreviousFingerprint, rec.Phase, formatStorageTime(rec.UpdatedAt))
	return err
}

// RecordPendingHostKeyAlert refreshes a pending alert without ever downgrading a
// row whose key was already published (an accept is in flight and authoritative).
func RecordPendingHostKeyAlert(ctx context.Context, rec HostKeyAlertRecord) error {
	if db == nil {
		return errors.New("storage not initialised")
	}
	rec.Phase = HostKeyPhasePending
	rec.ApprovedFingerprint = ""
	_, err := db.ExecContext(ctx, `INSERT INTO host_key_alerts(
		server_id, host, port, fingerprint, approved_fingerprint, previous_fingerprint, phase, updated_at)
		VALUES(?,?,?,?,'','','pending',?)
		ON CONFLICT(server_id) DO UPDATE SET
			host=excluded.host, port=excluded.port, fingerprint=excluded.fingerprint,
			approved_fingerprint='', previous_fingerprint='', phase='pending',
			updated_at=excluded.updated_at
		WHERE host_key_alerts.phase = 'pending'`,
		rec.ServerID, rec.Host, rec.Port, rec.Fingerprint, formatStorageTime(rec.UpdatedAt))
	return err
}

// DeleteHostKeyAlert removes the row regardless of its phase.
func DeleteHostKeyAlert(ctx context.Context, serverID string) error {
	if db == nil {
		return errors.New("storage not initialised")
	}
	_, err := db.ExecContext(ctx, `DELETE FROM host_key_alerts WHERE server_id = ?`, serverID)
	return err
}

// SettlePendingHostKeyAlert removes the row only while it waits for approval;
// a published, not-yet-verified accept must not be cleared by unrelated traffic.
func SettlePendingHostKeyAlert(ctx context.Context, serverID string) error {
	if db == nil {
		return errors.New("storage not initialised")
	}
	_, err := db.ExecContext(ctx, `DELETE FROM host_key_alerts WHERE server_id = ? AND phase = ?`,
		serverID, HostKeyPhasePending)
	return err
}

// DeleteHostKeyAlertsExcept removes rows for servers that no longer exist.
func DeleteHostKeyAlertsExcept(ctx context.Context, keep []string) error {
	if db == nil {
		return errors.New("storage not initialised")
	}
	if len(keep) == 0 {
		_, err := db.ExecContext(ctx, `DELETE FROM host_key_alerts`)
		return err
	}
	placeholders := strings.Repeat("?,", len(keep))
	placeholders = placeholders[:len(placeholders)-1]
	args := make([]any, len(keep))
	for i, id := range keep {
		args[i] = id
	}
	_, err := db.ExecContext(ctx, `DELETE FROM host_key_alerts WHERE server_id NOT IN (`+placeholders+`)`, args...)
	return err
}
