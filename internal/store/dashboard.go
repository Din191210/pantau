package store

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

type SecuritySourceSummary struct {
	Source        string    `json:"source"`
	OpenCount     int       `json:"open_count"`
	TotalHits     int64     `json:"total_hits"`
	CriticalCount int       `json:"critical_count"`
	HighCount     int       `json:"high_count"`
	LastSeen      time.Time `json:"last_seen"`
}

type SecurityCategorySummary struct {
	Category  string `json:"category"`
	OpenCount int    `json:"open_count"`
	TotalHits int64  `json:"total_hits"`
}

type RecentInspectionRun struct {
	ID         int64     `json:"id"`
	HostID     int64     `json:"host_id"`
	HostName   string    `json:"host_name"`
	StartedAt  time.Time `json:"started_at"`
	DurationMs int64     `json:"duration_ms"`
	Status     string    `json:"status"`
	Summary    string    `json:"summary"`
}

type RecentIncident struct {
	ID        int64     `json:"id"`
	HostID    int64     `json:"host_id"`
	HostName  string    `json:"host_name"`
	Kind      string    `json:"kind"`
	Target    string    `json:"target"`
	EventType string    `json:"event_type"`
	Summary   string    `json:"summary"`
	CreatedAt time.Time `json:"created_at"`
}

type DashboardSecurityStats struct {
	CountsBySeverity map[string]int            `json:"counts_by_severity"`
	OpenTotal        int                       `json:"open_total"`
	AckedTotal       int                       `json:"acked_total"`
	Last24hEvents    int                       `json:"last_24h_events"`
	Last24hHits      int64                     `json:"last_24h_hits"`
	BySource         []SecuritySourceSummary   `json:"by_source"`
	ByCategory       []SecurityCategorySummary `json:"by_category"`
	TopRecurring     []SecurityEvent           `json:"top_recurring"`
	RecentUrgent     []SecurityEvent           `json:"recent_urgent"`
}

type DashboardDBStats struct {
	Security            DashboardSecurityStats `json:"security"`
	DesiredRulesTotal   int                    `json:"desired_rules_total"`
	DesiredRulesEnabled int                    `json:"desired_rules_enabled"`
	ActualItemsOK       int                    `json:"actual_items_ok"`
	ActualItemsDrift    int                    `json:"actual_items_drift"`
	FilePinsCount       int                    `json:"file_pins_count"`
	PresetsCount        int                    `json:"presets_count"`
	PackagesCount       int                    `json:"packages_count"`
	RecentRuns          []RecentInspectionRun  `json:"recent_runs"`
	RecentIncidents     []RecentIncident       `json:"recent_incidents"`
	GlobalNotes         string                 `json:"global_notes"`
}

func parseSQLiteTime(raw any) time.Time {
	switch v := raw.(type) {
	case time.Time:
		return v
	case string:
		return parseSQLiteTimeString(v)
	case []byte:
		return parseSQLiteTimeString(string(v))
	default:
		return time.Time{}
	}
}

func parseSQLiteTimeString(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	if idx := strings.Index(s, " m="); idx != -1 {
		s = s[:idx]
	}
	layouts := []string{
		"2006-01-02 15:04:05.999999999 -0700 MST",
		"2006-01-02 15:04:05.999999999 -0700 -0700",
		"2006-01-02 15:04:05.999999999-07:00",
		"2006-01-02 15:04:05.999999999Z07:00",
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05",
	}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// GetDashboardDBStats aggregates live telemetry, security events, drift status, and workspace counts for the operations dashboard.
func (d *DB) GetDashboardDBStats(now time.Time) (*DashboardDBStats, error) {
	stats := &DashboardDBStats{
		Security: DashboardSecurityStats{
			CountsBySeverity: map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0},
			BySource:         []SecuritySourceSummary{},
			ByCategory:       []SecurityCategorySummary{},
			TopRecurring:     []SecurityEvent{},
			RecentUrgent:     []SecurityEvent{},
		},
		RecentRuns:      []RecentInspectionRun{},
		RecentIncidents: []RecentIncident{},
	}

	cutoff := now.Add(-24 * time.Hour)
	srcMap := make(map[string]*SecuritySourceSummary)
	catMap := make(map[string]*SecurityCategorySummary)

	rows, err := d.Query(`SELECT source, category, severity, count, last_seen, acknowledged_at IS NOT NULL FROM security_events`)
	if err != nil {
		return nil, fmt.Errorf("query security_events summary: %w", err)
	}
	for rows.Next() {
		var source, category, severity string
		var count int64
		var lastSeenRaw any
		var acked bool
		if err := rows.Scan(&source, &category, &severity, &count, &lastSeenRaw, &acked); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan security_events summary: %w", err)
		}
		lastSeen := parseSQLiteTime(lastSeenRaw)
		if !lastSeen.IsZero() && !lastSeen.Before(cutoff) {
			stats.Security.Last24hEvents++
			stats.Security.Last24hHits += count
		}
		if acked {
			stats.Security.AckedTotal++
			continue
		}
		stats.Security.OpenTotal++
		stats.Security.CountsBySeverity[severity]++

		ss := srcMap[source]
		if ss == nil {
			ss = &SecuritySourceSummary{Source: source}
			srcMap[source] = ss
		}
		ss.OpenCount++
		ss.TotalHits += count
		if severity == "critical" {
			ss.CriticalCount++
		} else if severity == "high" {
			ss.HighCount++
		}
		if !lastSeen.IsZero() && (ss.LastSeen.IsZero() || lastSeen.After(ss.LastSeen)) {
			ss.LastSeen = lastSeen
		}

		cs := catMap[category]
		if cs == nil {
			cs = &SecurityCategorySummary{Category: category}
			catMap[category] = cs
		}
		cs.OpenCount++
		cs.TotalHits += count
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	for _, ss := range srcMap {
		stats.Security.BySource = append(stats.Security.BySource, *ss)
	}
	sort.Slice(stats.Security.BySource, func(i, j int) bool {
		ui := stats.Security.BySource[i].CriticalCount + stats.Security.BySource[i].HighCount
		uj := stats.Security.BySource[j].CriticalCount + stats.Security.BySource[j].HighCount
		if ui != uj {
			return ui > uj
		}
		if stats.Security.BySource[i].OpenCount != stats.Security.BySource[j].OpenCount {
			return stats.Security.BySource[i].OpenCount > stats.Security.BySource[j].OpenCount
		}
		return stats.Security.BySource[i].Source < stats.Security.BySource[j].Source
	})

	for _, cs := range catMap {
		stats.Security.ByCategory = append(stats.Security.ByCategory, *cs)
	}
	sort.Slice(stats.Security.ByCategory, func(i, j int) bool {
		if stats.Security.ByCategory[i].OpenCount != stats.Security.ByCategory[j].OpenCount {
			return stats.Security.ByCategory[i].OpenCount > stats.Security.ByCategory[j].OpenCount
		}
		return stats.Security.ByCategory[i].Category < stats.Security.ByCategory[j].Category
	})

	topRows, err := d.Query(fmt.Sprintf(`SELECT %s FROM security_events WHERE acknowledged_at IS NULL ORDER BY count DESC, last_seen DESC LIMIT 6`, securityCols))
	if err != nil {
		return nil, fmt.Errorf("query top recurring security_events: %w", err)
	}
	for topRows.Next() {
		ev, err := scanSecurityEvent(topRows)
		if err != nil {
			topRows.Close()
			return nil, err
		}
		stats.Security.TopRecurring = append(stats.Security.TopRecurring, *ev)
	}
	if err := topRows.Err(); err != nil {
		topRows.Close()
		return nil, err
	}
	topRows.Close()

	urgRows, err := d.Query(fmt.Sprintf(`SELECT %s FROM security_events WHERE acknowledged_at IS NULL
		ORDER BY CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END DESC,
		last_seen DESC LIMIT 10`, securityCols))
	if err != nil {
		return nil, fmt.Errorf("query urgent security_events: %w", err)
	}
	for urgRows.Next() {
		ev, err := scanSecurityEvent(urgRows)
		if err != nil {
			urgRows.Close()
			return nil, err
		}
		stats.Security.RecentUrgent = append(stats.Security.RecentUrgent, *ev)
	}
	if err := urgRows.Err(); err != nil {
		urgRows.Close()
		return nil, err
	}
	urgRows.Close()

	if err := d.QueryRow(`SELECT COUNT(*), COALESCE(SUM(CASE WHEN enabled = 1 THEN 1 ELSE 0 END), 0) FROM desired_rules`).
		Scan(&stats.DesiredRulesTotal, &stats.DesiredRulesEnabled); err != nil {
		return nil, fmt.Errorf("query desired_rules counts: %w", err)
	}

	if err := d.QueryRow(`SELECT COALESCE(SUM(CASE WHEN status = 'ok' THEN 1 ELSE 0 END), 0), COALESCE(SUM(CASE WHEN status = 'drift' THEN 1 ELSE 0 END), 0) FROM actual_items`).
		Scan(&stats.ActualItemsOK, &stats.ActualItemsDrift); err != nil {
		return nil, fmt.Errorf("query actual_items counts: %w", err)
	}

	if err := d.QueryRow(`SELECT COUNT(*) FROM host_file_pins`).Scan(&stats.FilePinsCount); err != nil {
		return nil, fmt.Errorf("query host_file_pins count: %w", err)
	}
	if err := d.QueryRow(`SELECT COUNT(*) FROM terminal_presets`).Scan(&stats.PresetsCount); err != nil {
		return nil, fmt.Errorf("query terminal_presets count: %w", err)
	}
	if err := d.QueryRow(`SELECT COUNT(*) FROM host_packages`).Scan(&stats.PackagesCount); err != nil {
		return nil, fmt.Errorf("query host_packages count: %w", err)
	}

	runRows, err := d.Query(`SELECT r.id, r.host_id, COALESCE(h.name, 'Unknown'), r.started_at, r.duration_ms, r.status, r.summary
		FROM inspection_runs r LEFT JOIN hosts h ON r.host_id = h.id ORDER BY r.id DESC LIMIT 10`)
	if err != nil {
		return nil, fmt.Errorf("query recent inspection runs: %w", err)
	}
	for runRows.Next() {
		var r RecentInspectionRun
		var startedRaw any
		if err := runRows.Scan(&r.ID, &r.HostID, &r.HostName, &startedRaw, &r.DurationMs, &r.Status, &r.Summary); err != nil {
			runRows.Close()
			return nil, err
		}
		r.StartedAt = parseSQLiteTime(startedRaw)
		stats.RecentRuns = append(stats.RecentRuns, r)
	}
	if err := runRows.Err(); err != nil {
		runRows.Close()
		return nil, err
	}
	runRows.Close()

	incRows, err := d.Query(`SELECT i.id, i.host_id, COALESCE(h.name, 'Unknown'), i.kind, i.target, i.event_type, i.summary, i.created_at
		FROM incidents i LEFT JOIN hosts h ON i.host_id = h.id ORDER BY i.id DESC LIMIT 10`)
	if err != nil {
		return nil, fmt.Errorf("query recent incidents: %w", err)
	}
	for incRows.Next() {
		var inc RecentIncident
		var createdRaw any
		if err := incRows.Scan(&inc.ID, &inc.HostID, &inc.HostName, &inc.Kind, &inc.Target, &inc.EventType, &inc.Summary, &createdRaw); err != nil {
			incRows.Close()
			return nil, err
		}
		inc.CreatedAt = parseSQLiteTime(createdRaw)
		stats.RecentIncidents = append(stats.RecentIncidents, inc)
	}
	if err := incRows.Err(); err != nil {
		incRows.Close()
		return nil, err
	}
	incRows.Close()

	notes, err := d.GetGlobalNotes()
	if err != nil {
		return nil, fmt.Errorf("query global notes: %w", err)
	}
	stats.GlobalNotes = notes

	return stats, nil
}
