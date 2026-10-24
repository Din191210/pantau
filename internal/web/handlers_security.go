package web

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"pantau/internal/logger"
	"pantau/internal/store"
)

// Security center: CVE-Sentinel and the Wazuh integration (which also carries Suricata)
// POST findings to /api/security/ingest; the dashboard lists them and pops up on new
// critical/high events via SSE, browser notifications and the server desktop (notify-send).

type secHub struct {
	mu   sync.Mutex
	subs map[chan []byte]struct{}
}

func (h *secHub) subscribe() (chan []byte, func()) {
	ch := make(chan []byte, 32)
	h.mu.Lock()
	if h.subs == nil {
		h.subs = map[chan []byte]struct{}{}
	}
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	return ch, func() {
		h.mu.Lock()
		delete(h.subs, ch)
		h.mu.Unlock()
	}
}

// publish never blocks: a stalled browser tab just misses live updates and reloads the list.
func (h *secHub) publish(msg []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs {
		select {
		case ch <- msg:
		default:
		}
	}
}

// desktopNotifier shows popups on the server's own GNOME session. Capped so an attack
// burst cannot flood the screen; the dashboard still lists every event.
type desktopNotifier struct {
	mu      sync.Mutex
	enabled bool
	baseURL string // dashboard URL opened when a notification is clicked
	window  time.Time
	sent    int
}

const desktopPerMinute = 5

func (n *desktopNotifier) notify(e *store.SecurityEvent) {
	if n == nil || !n.enabled {
		return
	}
	n.mu.Lock()
	if time.Since(n.window) > time.Minute {
		n.window, n.sent = time.Now(), 0
	}
	n.sent++
	over := n.sent > desktopPerMinute
	n.mu.Unlock()
	if over {
		return
	}
	urgency := "normal"
	if e.Severity == "critical" {
		urgency = "critical"
	}
	title := fmt.Sprintf("Pantau: %s (%s)", strings.ToUpper(e.Severity), e.Source)
	// GNOME renders the body as markup; titles come from alert payloads, so escape it.
	esc := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	body := "<b>" + esc.Replace(e.Title) + "</b>"
	if e.Host != "" {
		body += "\n" + esc.Replace(e.Host)
	}
	if lines := strings.SplitN(e.Detail, "\n", 3); e.Detail != "" {
		body += "\n" + esc.Replace(strings.Join(lines[:min(2, len(lines))], "\n"))
	}
	detailURL := fmt.Sprintf("%s/#security-%d", n.baseURL, e.ID)
	go func() {
		// The process waits for a click (or dismissal); it is not a shell, so payload text
		// stays an argument. Clicking the body ("default") or the button opens the event.
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Hour)
		defer cancel()
		out, err := exec.CommandContext(ctx, "notify-send", "-u", urgency, "-a", "Pantau", "-i", "security-high",
			"-A", "default=Lihat detail", "-A", "open=Lihat detail", "--", title, body).Output()
		if err != nil {
			if ctx.Err() == nil {
				logger.Warn("security", "", "Desktop notification failed: "+err.Error())
			}
			return
		}
		if act := strings.TrimSpace(string(out)); act == "default" || act == "open" {
			if err := exec.Command("xdg-open", detailURL).Start(); err != nil {
				logger.Warn("security", "", "Opening dashboard failed: "+err.Error())
			}
		}
	}()
}

func newDesktopNotifier(enabled bool, baseURL string) *desktopNotifier {
	if _, err := exec.LookPath("notify-send"); err != nil {
		enabled = false
	}
	return &desktopNotifier{enabled: enabled, baseURL: baseURL}
}

// SetSecurityIngest configures the feeder token and desktop popups; baseURL is what a
// clicked desktop notification opens.
func (s *Server) SetSecurityIngest(token string, desktop bool, baseURL string) {
	s.ingestToken = token
	s.desktop = newDesktopNotifier(desktop, baseURL)
}

type ingestEvent struct {
	DedupKey string `json:"dedup_key"`
	Source   string `json:"source"`
	Category string `json:"category"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Detail   string `json:"detail"`
	Host     string `json:"host"`
	Ref      string `json:"ref"`
}

var sourceRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	// Cut on a rune boundary.
	for n > 0 && n < len(s) && (s[n]&0xC0) == 0x80 {
		n--
	}
	return s[:n] + "…"
}

func (e ingestEvent) toStore() (store.SecurityEvent, error) {
	if !sourceRe.MatchString(e.Source) {
		return store.SecurityEvent{}, fmt.Errorf("invalid source")
	}
	if !store.SecurityCategories[e.Category] {
		return store.SecurityEvent{}, fmt.Errorf("invalid category")
	}
	if !store.ValidSeverity(e.Severity) {
		return store.SecurityEvent{}, fmt.Errorf("invalid severity")
	}
	if strings.TrimSpace(e.Title) == "" {
		return store.SecurityEvent{}, fmt.Errorf("title required")
	}
	ev := store.SecurityEvent{
		Source: e.Source, Category: e.Category, Severity: e.Severity,
		Title: clip(e.Title, 300), Detail: clip(e.Detail, 4000),
		Host: clip(e.Host, 200), Ref: clip(e.Ref, 200),
	}
	key := strings.TrimSpace(e.DedupKey)
	if key == "" {
		key = strings.Join([]string{ev.Source, ev.Ref, ev.Host, ev.Title}, "|")
	}
	ev.DedupKey = clip(key, 400)
	return ev, nil
}

func isLoopback(r *http.Request) bool {
	ip := net.ParseIP(clientIP(r))
	return ip != nil && ip.IsLoopback()
}

func (s *Server) handleSecurityIngest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Feeders run on this machine; the token is a second gate, not the only one.
	if !isLoopback(r) {
		http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
		return
	}
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if s.ingestToken == "" || subtle.ConstantTimeCompare([]byte(got), []byte(s.ingestToken)) != 1 {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		http.Error(w, `{"error":"body too large"}`, http.StatusRequestEntityTooLarge)
		return
	}
	var batch struct {
		Events []ingestEvent `json:"events"`
	}
	if err := json.Unmarshal(body, &batch); err != nil || len(batch.Events) == 0 {
		var one ingestEvent
		if err := json.Unmarshal(body, &one); err != nil {
			http.Error(w, `{"error":"bad json"}`, http.StatusBadRequest)
			return
		}
		batch.Events = []ingestEvent{one}
	}
	if len(batch.Events) > 500 {
		http.Error(w, `{"error":"too many events (max 500)"}`, http.StatusBadRequest)
		return
	}

	now := time.Now()
	accepted, alerts := 0, 0
	var rejected []string
	for i, in := range batch.Events {
		ev, err := in.toStore()
		if err != nil {
			rejected = append(rejected, fmt.Sprintf("%d: %v", i, err))
			continue
		}
		stored, alert, err := s.db.UpsertSecurityEvent(ev, now)
		if err != nil {
			logger.Error("security", "", "Failed to store security event: "+err.Error())
			http.Error(w, `{"error":"store failed"}`, http.StatusInternalServerError)
			return
		}
		accepted++
		popup := alert && store.SeverityAlerts(stored.Severity)
		if popup {
			alerts++
			s.desktop.notify(stored)
		}
		if msg, err := json.Marshal(map[string]any{"type": "event", "popup": popup, "event": stored}); err == nil {
			s.secHub.publish(msg)
		}
	}
	if accepted > 0 {
		logger.Info("security", "", fmt.Sprintf("Ingested %d security event(s), %d alert(s)", accepted, alerts))
	}
	writeJSON(w, http.StatusOK, map[string]any{"accepted": accepted, "alerts": alerts, "rejected": rejected})
}

// handleSecurityRoute serves /api/security/{events,summary,ack,stream}.
func (s *Server) handleSecurityRoute(w http.ResponseWriter, r *http.Request) {
	switch rest := strings.TrimPrefix(r.URL.Path, "/api/security/"); {
	case rest == "events" && r.Method == http.MethodGet:
		events, err := s.db.ListSecurityEvents(r.URL.Query().Get("status") != "all", atoiOr(r.URL.Query().Get("limit"), 300))
		if err != nil {
			http.Error(w, `{"error":"query failed"}`, http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, events)
	case rest == "summary" && r.Method == http.MethodGet:
		counts, err := s.db.OpenSecurityCounts()
		if err != nil {
			http.Error(w, `{"error":"query failed"}`, http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, counts)
	case strings.HasPrefix(rest, "ack") && r.Method == http.MethodPost:
		id := int64(0)
		if idStr := strings.TrimPrefix(rest, "ack/"); idStr != rest {
			v, err := strconv.ParseInt(idStr, 10, 64)
			if err != nil || v <= 0 {
				http.Error(w, `{"error":"bad id"}`, http.StatusBadRequest)
				return
			}
			id = v
		} else if rest != "ack-all" {
			http.NotFound(w, r)
			return
		}
		n, err := s.db.AcknowledgeSecurityEvents(id, time.Now())
		if err != nil {
			http.Error(w, `{"error":"update failed"}`, http.StatusInternalServerError)
			return
		}
		if msg, err := json.Marshal(map[string]any{"type": "ack", "id": id}); err == nil {
			s.secHub.publish(msg)
		}
		writeJSON(w, http.StatusOK, map[string]any{"acknowledged": n})
	case rest == "stream" && r.Method == http.MethodGet:
		s.handleSecurityStream(w, r)
	default:
		http.NotFound(w, r)
	}
}

func atoiOr(s string, def int) int {
	if v, err := strconv.Atoi(s); err == nil {
		return v
	}
	return def
}

func (s *Server) handleSecurityStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, `{"error":"streaming unsupported"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	_, _ = fmt.Fprint(w, ": connected\n\n")
	flusher.Flush()

	ch, unsub := s.secHub.subscribe()
	defer unsub()
	ping := time.NewTicker(25 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case msg := <-ch:
			_, _ = fmt.Fprintf(w, "data: %s\n\n", msg)
			flusher.Flush()
		case <-ping.C:
			_, _ = fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		}
	}
}
