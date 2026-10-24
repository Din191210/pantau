package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// SecurityEvent is one finding from CVE-Sentinel, Wazuh, Suricata or Pantau itself.
// Repeated occurrences share a DedupKey and only bump Count/LastSeen.
type SecurityEvent struct {
	ID             int64      `json:"id"`
	DedupKey       string     `json:"dedup_key"`
	Source         string     `json:"source"`
	Category       string     `json:"category"`
	Severity       string     `json:"severity"`
	Title          string     `json:"title"`
	Detail         string     `json:"detail"`
	Host           string     `json:"host"`
	Ref            string     `json:"ref"`
	Count          int64      `json:"count"`
	FirstSeen      time.Time  `json:"first_seen"`
	LastSeen       time.Time  `json:"last_seen"`
	AcknowledgedAt *time.Time `json:"acknowledged_at"`
}

var severityRank = map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}

// SecurityCategories: vulnerability = known CVE; attack = something is being tried now;
// integrity = files/config changed; system = the monitoring itself is broken.
var SecurityCategories = map[string]bool{"vulnerability": true, "attack": true, "integrity": true, "system": true}

func ValidSeverity(s string) bool { return severityRank[s] > 0 }

// SeverityAlerts reports whether a severity warrants an interruptive popup.
func SeverityAlerts(s string) bool { return severityRank[s] >= severityRank["high"] }

const securityRetention = 90 * 24 * time.Hour

const securityCols = `id, dedup_key, source, category, severity, title, detail, host, ref, count, first_seen, last_seen, acknowledged_at`

func scanSecurityEvent(row interface{ Scan(...any) error }) (*SecurityEvent, error) {
	var e SecurityEvent
	var ack sql.NullTime
	if err := row.Scan(&e.ID, &e.DedupKey, &e.Source, &e.Category, &e.Severity, &e.Title, &e.Detail,
		&e.Host, &e.Ref, &e.Count, &e.FirstSeen, &e.LastSeen, &ack); err != nil {
		return nil, err
	}
	if ack.Valid {
		t := ack.Time
		e.AcknowledgedAt = &t
	}
	return &e, nil
}

// UpsertSecurityEvent records one occurrence and reports whether it deserves a fresh alert:
// a new finding, a severity escalation, or an acknowledged attack/integrity event that came back.
// Acknowledged vulnerabilities stay acknowledged while CVE-Sentinel keeps re-reporting them nightly.
func (d *DB) UpsertSecurityEvent(e SecurityEvent, at time.Time) (*SecurityEvent, bool, error) {
	tx, err := d.Begin()
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()

	var id int64
	var oldSeverity string
	var ack sql.NullTime
	err = tx.QueryRow(`SELECT id, severity, acknowledged_at FROM security_events WHERE dedup_key = ?`, e.DedupKey).
		Scan(&id, &oldSeverity, &ack)
	alert := false
	switch {
	case errors.Is(err, sql.ErrNoRows):
		res, err := tx.Exec(`INSERT INTO security_events (dedup_key, source, category, severity, title, detail, host, ref, count, first_seen, last_seen)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)`,
			e.DedupKey, e.Source, e.Category, e.Severity, e.Title, e.Detail, e.Host, e.Ref, at, at)
		if err != nil {
			return nil, false, err
		}
		id, _ = res.LastInsertId()
		alert = true
	case err != nil:
		return nil, false, err
	default:
		reopen := ack.Valid && e.Category != "vulnerability"
		escalated := severityRank[e.Severity] > severityRank[oldSeverity]
		if _, err := tx.Exec(`UPDATE security_events SET count = count + 1, last_seen = ?, severity = ?, title = ?, detail = ?,
			host = ?, ref = ?, acknowledged_at = CASE WHEN ? THEN NULL ELSE acknowledged_at END WHERE id = ?`,
			at, e.Severity, e.Title, e.Detail, e.Host, e.Ref, reopen || escalated, id); err != nil {
			return nil, false, err
		}
		alert = reopen || escalated
	}

	if _, err := tx.Exec(`DELETE FROM security_events WHERE last_seen < ?`, at.Add(-securityRetention)); err != nil {
		return nil, false, err
	}
	stored, err := scanSecurityEvent(tx.QueryRow(`SELECT `+securityCols+` FROM security_events WHERE id = ?`, id))
	if err != nil {
		return nil, false, err
	}
	return stored, alert, tx.Commit()
}

// ListSecurityEvents returns open events first, worst severity first, newest first.
func (d *DB) ListSecurityEvents(openOnly bool, limit int) ([]SecurityEvent, error) {
	if limit <= 0 || limit > 1000 {
		limit = 300
	}
	where := ""
	if openOnly {
		where = "WHERE acknowledged_at IS NULL"
	}
	rows, err := d.Query(fmt.Sprintf(`SELECT %s FROM security_events %s
		ORDER BY acknowledged_at IS NOT NULL,
		CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END DESC,
		last_seen DESC LIMIT ?`, securityCols, where), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SecurityEvent{}
	for rows.Next() {
		e, err := scanSecurityEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *e)
	}
	return out, rows.Err()
}

// OpenSecurityCounts counts unacknowledged events per severity.
func (d *DB) OpenSecurityCounts() (map[string]int, error) {
	counts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}
	rows, err := d.Query(`SELECT severity, COUNT(*) FROM security_events WHERE acknowledged_at IS NULL GROUP BY severity`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var sev string
		var n int
		if err := rows.Scan(&sev, &n); err != nil {
			return nil, err
		}
		counts[sev] = n
	}
	return counts, rows.Err()
}

// AcknowledgeSecurityEvents marks events handled; id 0 acknowledges every open event.
func (d *DB) AcknowledgeSecurityEvents(id int64, at time.Time) (int64, error) {
	var res sql.Result
	var err error
	if id == 0 {
		res, err = d.Exec(`UPDATE security_events SET acknowledged_at = ? WHERE acknowledged_at IS NULL`, at)
	} else {
		res, err = d.Exec(`UPDATE security_events SET acknowledged_at = ? WHERE id = ? AND acknowledged_at IS NULL`, at, id)
	}
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// IngestTokenFile holds the bearer token local feeders (CVE-Sentinel, Wazuh) use to post events.
func IngestTokenFile(dbPath string) string { return dbPath + ".ingest-token" }

// EnsureIngestToken returns the feeder token, creating an owner-only file on first use.
func EnsureIngestToken(dbPath string) (string, error) {
	path := IngestTokenFile(dbPath)
	if b, err := os.ReadFile(path); err == nil {
		if tok := strings.TrimSpace(string(b)); len(tok) >= 32 {
			return tok, nil
		}
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(b)
	if err := os.WriteFile(path, []byte(tok+"\n"), 0600); err != nil {
		return "", err
	}
	return tok, nil
}
