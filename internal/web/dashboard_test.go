package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"pantau/internal/inspector"
	"pantau/internal/store"
)

func TestDashboardOverviewAPI_AuthAndRealData(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "pantau.db")
	db, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	ins := inspector.New(db, nil, nil)
	srv := NewServer(db, ins, nil)
	srv.SetSecurityIngest("ingest-secret-token-value-1234567890", false, "http://127.0.0.1:8080")

	// 1. Unauthenticated access to API must fail with 401
	reqUnauth := httptest.NewRequest(http.MethodGet, "/api/dashboard/overview", nil)
	rrUnauth := httptest.NewRecorder()
	srv.ServeHTTP(rrUnauth, reqUnauth)
	if rrUnauth.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated /api/dashboard/overview, got %d", rrUnauth.Code)
	}

	// 2. /dashboard route serves index HTML and unknown route still returns 404
	reqPage := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	rrPage := httptest.NewRecorder()
	srv.ServeHTTP(rrPage, reqPage)
	if rrPage.Code != http.StatusOK || !strings.Contains(rrPage.Body.String(), `id="dashboardView"`) {
		t.Fatalf("expected 200 HTML containing dashboardView on /dashboard, got %d", rrPage.Code)
	}

	req404 := httptest.NewRequest(http.MethodGet, "/unknown-page-check", nil)
	rr404 := httptest.NewRecorder()
	srv.ServeHTTP(rr404, req404)
	if rr404.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown path, got %d", rr404.Code)
	}

	// 3. Seed real SQLite records across hosts, rules, actual_items, alerts, runs, incidents, pins, notes, settings, security_events
	h1 := &store.Host{Name: "app-01", Host: "10.0.0.11", Port: 22, User: "ops"}
	h1ID, err := db.CreateHost(h1)
	if err != nil {
		t.Fatalf("create h1: %v", err)
	}
	h1.ID = h1ID
	h1.Status = "healthy"
	h1.CPUCores = 4
	h1.CPULoad = "0.50, 0.40, 0.30"
	h1.RAMUsedBytes = 2 << 30
	h1.RAMTotalBytes = 8 << 30
	h1.DiskUsedBytes = 20 << 30
	h1.DiskTotalBytes = 100 << 30
	h1.LifecycleScore = 92
	if err := db.UpdateHostInspection(h1); err != nil {
		t.Fatalf("update h1: %v", err)
	}

	h2 := &store.Host{Name: "db-01", Host: "10.0.0.12", Port: 22, User: "ops"}
	h2ID, err := db.CreateHost(h2)
	if err != nil {
		t.Fatalf("create h2: %v", err)
	}
	h2.ID = h2ID
	h2.Status = "degraded"
	h2.CPUCores = 8
	h2.CPULoad = "3.20, 2.80, 2.10"
	h2.LifecycleScore = 64
	if err := db.UpdateHostInspection(h2); err != nil {
		t.Fatalf("update h2: %v", err)
	}

	if err := db.SaveDesiredRule(&store.DesiredRule{HostID: h1ID, Kind: "service", Target: "nginx", Expected: "active", Enabled: true}); err != nil {
		t.Fatalf("save rule 1: %v", err)
	}
	if err := db.SaveDesiredRule(&store.DesiredRule{HostID: h2ID, Kind: "service", Target: "postgresql", Expected: "active", Enabled: true}); err != nil {
		t.Fatalf("save rule 2: %v", err)
	}
	if err := db.UpsertActualItem(&store.ActualItem{HostID: h1ID, Kind: "service", Target: "nginx", Current: "active", Status: "ok"}); err != nil {
		t.Fatalf("upsert actual 1: %v", err)
	}
	if err := db.UpsertActualItem(&store.ActualItem{HostID: h2ID, Kind: "service", Target: "postgresql", Current: "inactive", Status: "drift"}); err != nil {
		t.Fatalf("upsert actual 2: %v", err)
	}
	if _, err := db.CreateAlert(&store.Alert{HostID: h2ID, Level: "critical", Message: "postgresql is inactive"}); err != nil {
		t.Fatalf("create alert: %v", err)
	}
	if err := db.RecordInspectionRun(&store.InspectionRun{HostID: h2ID, StartedAt: time.Now(), DurationMs: 245, Status: "drift", Summary: "1 rule drifting"}); err != nil {
		t.Fatalf("record run: %v", err)
	}
	if err := db.RecordIncident(&store.Incident{HostID: h2ID, Kind: "service", Target: "postgresql", EventType: "drift_detected", Summary: "postgresql stopped"}); err != nil {
		t.Fatalf("record incident: %v", err)
	}
	if err := db.SaveFilePin(h1ID, "/etc/nginx/nginx.conf", false, "main reverse proxy"); err != nil {
		t.Fatalf("save pin: %v", err)
	}
	if err := db.SetGlobalNotes("Shift handover: watch db-01 replication"); err != nil {
		t.Fatalf("set notes: %v", err)
	}
	_ = db.SetSetting("totp_enabled", "true")
	_ = db.SetSetting("telegram_token", "tg-super-secret-token-999")
	_ = db.SetSetting("telegram_chat_id", "-10012345")
	_ = db.SetSetting("poll_interval_sec", "120")

	now := time.Now()
	for i := 0; i < 5; i++ {
		_, _, err := db.UpsertSecurityEvent(store.SecurityEvent{
			DedupKey: "wazuh:80710:veth2",
			Source:   "wazuh",
			Category: "attack",
			Severity: "high",
			Title:    "Auditd: Device enables promiscuous mode",
			Host:     "nemesis-server",
			Ref:      "rule 80710",
		}, now)
		if err != nil {
			t.Fatalf("upsert wazuh event: %v", err)
		}
	}
	if _, _, err := db.UpsertSecurityEvent(store.SecurityEvent{
		DedupKey: "cve:CVE-2026-99999:php",
		Source:   "cve-sentinel",
		Category: "vulnerability",
		Severity: "critical",
		Title:    "CVE-2026-99999 php-cli 8.5.12",
		Host:     "localhost/inlis-php85:latest",
		Ref:      "CVE-2026-99999",
	}, now); err != nil {
		t.Fatalf("upsert cve 1: %v", err)
	}
	ackedEv, _, err := db.UpsertSecurityEvent(store.SecurityEvent{
		DedupKey: "cve:CVE-2026-00001:old",
		Source:   "cve-sentinel",
		Category: "vulnerability",
		Severity: "medium",
		Title:    "Old handled CVE",
	}, now.Add(-48*time.Hour))
	if err != nil {
		t.Fatalf("upsert cve 2: %v", err)
	}
	if _, err := db.AcknowledgeSecurityEvents(ackedEv.ID, now); err != nil {
		t.Fatalf("ack cve 2: %v", err)
	}

	// 4. Call authenticated endpoint
	token := "valid_dashboard_test_token"
	srv.sessions.Store(token, time.Now().Add(time.Hour))
	req := httptest.NewRequest(http.MethodGet, "/api/dashboard/overview", nil)
	req.AddCookie(&http.Cookie{Name: "pantau_session", Value: token})
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for authenticated /api/dashboard/overview, got %d: %s", rr.Code, rr.Body.String())
	}

	rawBody := rr.Body.String()
	for _, secret := range []string{"tg-super-secret-token-999", "ingest-secret-token-value-1234567890", "BEGIN RSA PRIVATE KEY"} {
		if strings.Contains(rawBody, secret) {
			t.Fatalf("overview response leaked sensitive value %q", secret)
		}
	}

	var resp dashboardOverviewResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode overview response: %v", err)
	}
	if len(resp.Hosts) != 2 {
		t.Errorf("hosts count = %d, want 2", len(resp.Hosts))
	}
	if len(resp.Alerts) != 1 {
		t.Errorf("alerts count = %d, want 1", len(resp.Alerts))
	}
	if resp.Security.OpenTotal != 2 || resp.Security.AckedTotal != 1 {
		t.Errorf("security open/acked = %d/%d, want 2/1", resp.Security.OpenTotal, resp.Security.AckedTotal)
	}
	if resp.Security.CountsBySeverity["critical"] != 1 || resp.Security.CountsBySeverity["high"] != 1 {
		t.Errorf("unexpected severity counts: %+v", resp.Security.CountsBySeverity)
	}
	if resp.Security.Last24hEvents != 2 {
		t.Errorf("last_24h_events = %d, want 2", resp.Security.Last24hEvents)
	}
	if len(resp.Security.TopRecurring) == 0 || resp.Security.TopRecurring[0].Count != 5 {
		t.Errorf("expected top recurring count 5, got %+v", resp.Security.TopRecurring)
	}
	if resp.DesiredState.RulesEnabled != 2 || resp.DesiredState.ItemsOK != 1 || resp.DesiredState.ItemsDrift != 1 {
		t.Errorf("unexpected desired state summary: %+v", resp.DesiredState)
	}
	if !resp.Posture.TOTPEnabled || !resp.Posture.TelegramConfigured || resp.Posture.PollIntervalSec != 120 {
		t.Errorf("unexpected posture flags: %+v", resp.Posture)
	}
	if resp.Workspace.FilePinsCount != 1 || resp.Workspace.GlobalNotes != "Shift handover: watch db-01 replication" {
		t.Errorf("unexpected workspace summary: %+v", resp.Workspace)
	}
	if len(resp.RecentRuns) != 1 || resp.RecentRuns[0].HostName != "db-01" {
		t.Errorf("unexpected recent runs: %+v", resp.RecentRuns)
	}
	if len(resp.RecentIncidents) != 1 || resp.RecentIncidents[0].Summary != "postgresql stopped" {
		t.Errorf("unexpected recent incidents: %+v", resp.RecentIncidents)
	}

	// Method not allowed check
	reqPost := httptest.NewRequest(http.MethodPost, "/api/dashboard/overview", nil)
	reqPost.AddCookie(&http.Cookie{Name: "pantau_session", Value: token})
	rrPost := httptest.NewRecorder()
	srv.ServeHTTP(rrPost, reqPost)
	if rrPost.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for POST /api/dashboard/overview, got %d", rrPost.Code)
	}
}

func TestDashboardUIInIndexHTML(t *testing.T) {
	html := string(embeddedHTML)

	required := []string{
		`id="mainContent"`,
		`id="dashboardView"`,
		`id="hostsView"`,
		`id="navDashboardBtn"`,
		`id="navHostsBtn"`,
		`id="dashHeading"`,
		`id="dashPostureGrid"`,
		`id="dashWorkspace"`,
		`id="dashBottomGrid"`,
		`function loadDashboardOverview`,
		`function renderDashboard`,
		`function setAppView`,
		`function switchDashSecTab`,
		`function openSecurityModalFiltered`,
		`"nav_dashboard":`,
		`"nav_hosts":`,
		`"dash_heading":`,
		`"dash_sec_panel_title":`,
		`"dash_readiness_title":`,
		`"dash_tools_title":`,
	}
	for _, s := range required {
		if !strings.Contains(html, s) {
			t.Errorf("expected index.html to contain %q", s)
		}
	}

	if count := strings.Count(html, `"dash_heading":`); count < 2 {
		t.Errorf("expected dash_heading i18n key in both EN and ID, found %d", count)
	}
	if count := strings.Count(html, `"dash_sec_panel_title":`); count < 2 {
		t.Errorf("expected dash_sec_panel_title i18n key in both EN and ID, found %d", count)
	}
}
