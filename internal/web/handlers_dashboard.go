package web

import (
	"net/http"
	"strconv"
	"time"

	"pantau/internal/store"
)

type dashboardDesiredState struct {
	RulesTotal   int `json:"rules_total"`
	RulesEnabled int `json:"rules_enabled"`
	ItemsOK      int `json:"items_ok"`
	ItemsDrift   int `json:"items_drift"`
}

type dashboardPosture struct {
	PollIntervalSec      int    `json:"poll_interval_sec"`
	BackgroundPaused     bool   `json:"background_paused"`
	InspectInFlight      int    `json:"inspect_in_flight"`
	TOTPEnabled          bool   `json:"totp_enabled"`
	TelegramConfigured   bool   `json:"telegram_configured"`
	WebhookConfigured    bool   `json:"webhook_configured"`
	DesktopNotifyEnabled bool   `json:"desktop_notify_enabled"`
	GitHubBackupEnabled  bool   `json:"github_backup_enabled"`
	LastBackupTime       string `json:"last_backup_time"`
	LastBackupStatus     string `json:"last_backup_status"`
	ActiveTransfers      int    `json:"active_transfers"`
	TotalTransfers       int    `json:"total_transfers"`
}

type dashboardWorkspace struct {
	FilePinsCount int    `json:"file_pins_count"`
	PresetsCount  int    `json:"presets_count"`
	PackagesCount int    `json:"packages_count"`
	GlobalNotes   string `json:"global_notes"`
}

type dashboardOverviewResponse struct {
	GeneratedAt     time.Time                    `json:"generated_at"`
	Hosts           []store.Host                 `json:"hosts"`
	Alerts          []store.Alert                `json:"alerts"`
	Security        store.DashboardSecurityStats `json:"security"`
	DesiredState    dashboardDesiredState        `json:"desired_state"`
	Posture         dashboardPosture             `json:"posture"`
	Workspace       dashboardWorkspace           `json:"workspace"`
	RecentRuns      []store.RecentInspectionRun  `json:"recent_runs"`
	RecentIncidents []store.RecentIncident       `json:"recent_incidents"`
}

func (s *Server) handleDashboardOverview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	now := time.Now()
	hosts, err := s.db.ListHosts()
	if err != nil {
		http.Error(w, `{"error":"failed to load hosts"}`, http.StatusInternalServerError)
		return
	}
	if hosts == nil {
		hosts = []store.Host{}
	}

	alerts, err := s.db.ListActiveAlerts()
	if err != nil {
		http.Error(w, `{"error":"failed to load alerts"}`, http.StatusInternalServerError)
		return
	}
	if alerts == nil {
		alerts = []store.Alert{}
	}

	stats, err := s.db.GetDashboardDBStats(now)
	if err != nil {
		http.Error(w, `{"error":"failed to aggregate dashboard"}`, http.StatusInternalServerError)
		return
	}

	pollSec := 300
	if pollStr, err := s.db.GetSetting("poll_interval_sec"); err == nil && pollStr != "" {
		if v, err := strconv.Atoi(pollStr); err == nil {
			pollSec = v
		}
	}
	totpEnabled, _ := s.db.GetSetting("totp_enabled")
	tgToken, _ := s.db.GetSetting("telegram_token")
	tgChatID, _ := s.db.GetSetting("telegram_chat_id")
	webhookURL, _ := s.db.GetSetting("webhook_url")
	ghEnabled, _ := s.db.GetSetting("github_backup_enabled")
	lastBackupTime, _ := s.db.GetSetting("last_backup_time")
	lastBackupStatus, _ := s.db.GetSetting("last_backup_status")

	inspectInFlight := 0
	if s.inspector != nil {
		inspectInFlight = s.inspector.InFlightCount()
	}

	activeTransfers := 0
	totalTransfers := 0
	if s.transferMgr != nil {
		jobs := s.transferMgr.ListJobs()
		totalTransfers = len(jobs)
		for _, j := range jobs {
			if j.Status == "transferring" || j.Status == "queued" || j.Status == "pending" {
				activeTransfers++
			}
		}
	}

	resp := dashboardOverviewResponse{
		GeneratedAt: now,
		Hosts:       hosts,
		Alerts:      alerts,
		Security:    stats.Security,
		DesiredState: dashboardDesiredState{
			RulesTotal:   stats.DesiredRulesTotal,
			RulesEnabled: stats.DesiredRulesEnabled,
			ItemsOK:      stats.ActualItemsOK,
			ItemsDrift:   stats.ActualItemsDrift,
		},
		Posture: dashboardPosture{
			PollIntervalSec:      pollSec,
			BackgroundPaused:     pollSec == 0,
			InspectInFlight:      inspectInFlight,
			TOTPEnabled:          totpEnabled == "true",
			TelegramConfigured:   tgToken != "" && tgChatID != "",
			WebhookConfigured:    webhookURL != "",
			DesktopNotifyEnabled: s.desktop != nil && s.desktop.enabled,
			GitHubBackupEnabled:  ghEnabled == "1",
			LastBackupTime:       lastBackupTime,
			LastBackupStatus:     lastBackupStatus,
			ActiveTransfers:      activeTransfers,
			TotalTransfers:       totalTransfers,
		},
		Workspace: dashboardWorkspace{
			FilePinsCount: stats.FilePinsCount,
			PresetsCount:  stats.PresetsCount,
			PackagesCount: stats.PackagesCount,
			GlobalNotes:   stats.GlobalNotes,
		},
		RecentRuns:      stats.RecentRuns,
		RecentIncidents: stats.RecentIncidents,
	}
	writeJSON(w, http.StatusOK, resp)
}
