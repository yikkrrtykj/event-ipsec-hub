package web

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"math"
	"net"
	"net/http"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yikkrrtykj/event-ipsec-hub/internal/alert"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/failover"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/handoff"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/manifest"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/profile"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/rpc"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/storage"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/telemetry"
)

const sessionCookieName = "ipsecvpn_session"

type sessionEntry struct {
	Username  string
	Role      string
	ExpiresAt time.Time
}

// Config configures the unprivileged Go Web console server.
type Config struct {
	ListenAddr        string
	PublicIPs         []string
	CertPath          string
	KeyPath           string
	FailoverStateFile string
	StaticFS          fs.FS
	DemoMode          bool
	InsecureHTTP      bool // test-only override; production always uses TLS 1.3
}

// Server implements the non-root Web console, REST/SSE API, auth/allowlist middleware,
// and delegates privileged Hub operations to root `agent` over Unix Socket RPC.
type Server struct {
	cfg      Config
	store    *storage.Store
	agent    rpc.Client
	guard    *BruteForceGuard
	mu       sync.RWMutex
	sessions map[string]sessionEntry
}

func NewServer(cfg Config, store *storage.Store, agentClient rpc.Client) *Server {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":18443"
	}
	if cfg.FailoverStateFile == "" {
		cfg.FailoverStateFile = failover.DefaultStateFile
	}
	return &Server{
		cfg:      cfg,
		store:    store,
		agent:    agentClient,
		guard:    NewBruteForceGuard(5, 10*time.Minute, 15*time.Minute),
		sessions: make(map[string]sessionEntry),
	}
}

// BootstrapAdmin creates an initial admin user if the database has zero users, returning
// the generated password once so the installer/operator can log in.
func (s *Server) BootstrapAdmin() (string, bool, error) {
	users, err := s.store.ListUsers()
	if err != nil {
		return "", false, err
	}
	if len(users) > 0 {
		return "", false, nil
	}
	pass := GenerateRandomPassword()
	if s.cfg.DemoMode {
		pass = "Admin#2026!"
	}
	hash, err := HashPassword(pass)
	if err != nil {
		return "", false, err
	}
	err = s.store.UpsertUser(storage.User{
		Username:           "admin",
		Role:               "admin",
		PasswordHash:       hash,
		MustChangePassword: !s.cfg.DemoMode,
	})
	if err != nil {
		return "", false, err
	}
	return pass, true, nil
}

// Handler returns the complete HTTP handler chain (allowlist + expiry + API + SPA).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})

	// Auth endpoints
	mux.HandleFunc("POST /api/v1/auth/login", s.handleLogin)
	mux.HandleFunc("POST /api/v1/auth/logout", s.requireAuth(s.handleLogout))
	mux.HandleFunc("GET /api/v1/auth/me", s.requireAuth(s.handleMe))
	mux.HandleFunc("POST /api/v1/auth/password", s.requireAuth(s.handleChangePassword))
	mux.HandleFunc("POST /api/v1/auth/totp/setup", s.requireAdmin(s.handleTOTPSetup))
	mux.HandleFunc("POST /api/v1/auth/totp/enable", s.requireAdmin(s.handleTOTPEnable))

	// Overview, 4-layer synced diagnostics & searchable event log
	mux.HandleFunc("GET /api/v1/overview", s.requireAuth(s.handleOverview))
	mux.HandleFunc("GET /api/v1/diagnostics/timeline", s.requireAuth(s.handleTimeline))
	mux.HandleFunc("GET /api/v1/events", s.requireAuth(s.handleListEvents))
	mux.HandleFunc("POST /api/v1/diagnostics/seed-demo", s.requireAdmin(s.handleSeedDemo))
	mux.HandleFunc("GET /api/v1/stream", s.requireAuth(s.handleSSEStream))

	// Profiles, Dry-Run Diff, Apply/Rollback, Secrets & Multi-Format Peer Export
	mux.HandleFunc("GET /api/v1/profiles", s.requireAuth(s.handleListProfiles))
	mux.HandleFunc("POST /api/v1/profiles", s.requireAdmin(s.handleSaveProfile))
	mux.HandleFunc("POST /api/v1/profiles/validate", s.requireAuth(s.handleValidateYAML))
	mux.HandleFunc("GET /api/v1/profiles/{id}/revisions", s.requireAuth(s.handleProfileRevisions))
	mux.HandleFunc("GET /api/v1/profiles/{id}/plan", s.requireAuth(s.handleProfilePlan))
	mux.HandleFunc("GET /api/v1/profiles/{id}/render", s.requireAuth(s.handleProfileRender))
	mux.HandleFunc("POST /api/v1/profiles/{id}/apply", s.requireAdmin(s.handleProfileApply))
	mux.HandleFunc("POST /api/v1/profiles/{id}/secrets", s.requireAdmin(s.handleWriteSecret))
	mux.HandleFunc("POST /api/v1/secrets", s.requireAdmin(s.handleWriteSecret))
	mux.HandleFunc("POST /api/v1/secrets/reveal", s.requireAdmin(s.handleRevealSecret))
	mux.HandleFunc("POST /api/v1/profiles/{id}/export-peer", s.requireAuth(s.handleExportPeer))

	// Single-tunnel live operations (reconnect / rekey / live diagnostics)
	mux.HandleFunc("POST /api/v1/tunnels/{site}/reconnect", s.requireAdmin(s.handleTunnelReconnect))
	mux.HandleFunc("POST /api/v1/tunnels/{site}/rekey", s.requireAdmin(s.handleTunnelRekey))
	mux.HandleFunc("GET /api/v1/tunnels/{site}/diagnostics", s.requireAuth(s.handleTunnelDiagnostics))

	// Failover & #12 Hub Role Swap
	mux.HandleFunc("GET /api/v1/failover", s.requireAuth(s.handleFailoverStatus))
	mux.HandleFunc("POST /api/v1/failover/switch-backup", s.requireAdmin(s.handleFailoverSwitchBackup))
	mux.HandleFunc("POST /api/v1/failover/failback", s.requireAdmin(s.handleFailoverFailback))
	mux.HandleFunc("POST /api/v1/failover/set-role", s.requireAdmin(s.handleFailoverSetRole))

	// Alerts & Feishu
	mux.HandleFunc("GET /api/v1/alerts/rules", s.requireAuth(s.handleListAlertRules))
	mux.HandleFunc("PUT /api/v1/alerts/rules", s.requireAdmin(s.handleUpsertAlertRule))
	mux.HandleFunc("GET /api/v1/alerts/history", s.requireAuth(s.handleAlertHistory))
	mux.HandleFunc("GET /api/v1/alerts/channel", s.requireAuth(s.handleGetAlertChannel))
	mux.HandleFunc("PUT /api/v1/alerts/channel", s.requireAdmin(s.handleSaveAlertChannel))
	mux.HandleFunc("POST /api/v1/alerts/feishu/test", s.requireAdmin(s.handleFeishuTest))

	// Audit, Security Allowlist, Tournament Expiry & #14 Sign-off Checklist
	mux.HandleFunc("GET /api/v1/audit", s.requireAuth(s.handleAuditLogs))
	mux.HandleFunc("GET /api/v1/system/security", s.requireAuth(s.handleGetSecurity))
	mux.HandleFunc("PUT /api/v1/system/security", s.requireAdmin(s.handlePutSecurity))
	mux.HandleFunc("GET /api/v1/system/signoff", s.requireAuth(s.handleSignoffChecklist))
	mux.HandleFunc("GET /api/v1/system/host-network", s.requireAuth(s.handleHostNetwork))

	// Prometheus compatibility endpoint
	mux.HandleFunc("GET /metrics", s.handlePrometheusMetrics)

	// Embedded Vue 3 SPA fallback
	mux.Handle("/", s.spaHandler())

	return s.securityMiddleware(mux)
}

func (s *Server) Serve(ctx context.Context) error {
	httpSrv := &http.Server{
		Addr:              s.cfg.ListenAddr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutCtx)
	}()

	if s.cfg.InsecureHTTP {
		return httpSrv.ListenAndServe()
	}
	cert, err := EnsureTLSKeypair(s.cfg.CertPath, s.cfg.KeyPath, s.cfg.PublicIPs)
	if err != nil {
		return err
	}
	httpSrv.TLSConfig = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
	}
	err = httpSrv.ListenAndServeTLS("", "")
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func (s *Server) getSecuritySettings() (allowlist []string, expiresAt int64, retentionDays int) {
	retentionDays = 14
	if raw, ok, _ := s.store.GetKV("web_allowlist"); ok && raw != "" {
		_ = json.Unmarshal([]byte(raw), &allowlist)
	}
	if raw, ok, _ := s.store.GetKV("web_expires_at"); ok && raw != "" {
		expiresAt, _ = strconv.ParseInt(raw, 10, 64)
	}
	if raw, ok, _ := s.store.GetKV("retention_days"); ok && raw != "" {
		if d, err := strconv.Atoi(raw); err == nil && d >= 1 && d <= 90 {
			retentionDays = d
		}
	}
	return allowlist, expiresAt, retentionDays
}

func (s *Server) securityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")

		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		allowlist, expiresAt, _ := s.getSecuritySettings()
		if !IsIPAllowed(r.RemoteAddr, allowlist) {
			writeJSONResp(w, http.StatusForbidden, map[string]any{"error": "Client IP is not in the management allowlist."})
			return
		}
		if expiresAt > 0 && time.Now().UnixMilli() > expiresAt && !strings.HasPrefix(r.RemoteAddr, "127.0.0.1:") {
			writeJSONResp(w, http.StatusForbidden, map[string]any{"error": "Tournament Web management window has expired."})
			return
		}
		next.ServeHTTP(w, r)
	})
}

type authedHandler func(w http.ResponseWriter, r *http.Request, sess sessionEntry)

func (s *Server) currentSession(r *http.Request) (sessionEntry, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" {
		return sessionEntry{}, false
	}
	s.mu.RLock()
	sess, ok := s.sessions[cookie.Value]
	s.mu.RUnlock()
	if !ok || time.Now().After(sess.ExpiresAt) {
		return sessionEntry{}, false
	}
	return sess, true
}

func (s *Server) requireAuth(fn authedHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, ok := s.currentSession(r)
		if !ok {
			writeJSONResp(w, http.StatusUnauthorized, map[string]any{"error": "Authentication required."})
			return
		}
		fn(w, r, sess)
	}
}

func (s *Server) requireAdmin(fn authedHandler) http.HandlerFunc {
	return s.requireAuth(func(w http.ResponseWriter, r *http.Request, sess sessionEntry) {
		if sess.Role != "admin" {
			writeJSONResp(w, http.StatusForbidden, map[string]any{"error": "Admin role required."})
			return
		}
		fn(w, r, sess)
	})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	clientIP := extractClientIP(r.RemoteAddr)
	now := time.Now()
	if s.guard.IsBanned(clientIP, now) {
		writeJSONResp(w, http.StatusTooManyRequests, map[string]any{"error": "Too many failed logins. IP temporarily locked."})
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		TOTPCode string `json:"totp_code"`
	}
	if err := decodeJSONBody(r, &req); err != nil {
		writeJSONResp(w, http.StatusBadRequest, map[string]any{"error": "Invalid JSON body."})
		return
	}
	u, err := s.store.GetUser(req.Username)
	if err != nil || u == nil || !VerifyPassword(u.PasswordHash, req.Password) {
		banned := s.guard.RecordFailure(clientIP, now)
		_ = s.store.RecordAudit(req.Username, clientIP, "login", "web", "FAIL", map[string]any{"banned": banned})
		writeJSONResp(w, http.StatusUnauthorized, map[string]any{"error": "Invalid username or password."})
		return
	}
	if u.TOTPEnabled && !VerifyTOTP(u.TOTPSecret, req.TOTPCode, now) {
		s.guard.RecordFailure(clientIP, now)
		writeJSONResp(w, http.StatusUnauthorized, map[string]any{"error": "Invalid or missing TOTP 2FA code."})
		return
	}

	s.guard.Reset(clientIP)
	var tok [32]byte
	_, _ = rand.Read(tok[:])
	tokenStr := hex.EncodeToString(tok[:])
	sess := sessionEntry{
		Username:  u.Username,
		Role:      u.Role,
		ExpiresAt: now.Add(12 * time.Hour),
	}
	s.mu.Lock()
	s.sessions[tokenStr] = sess
	s.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    tokenStr,
		Path:     "/",
		HttpOnly: true,
		Secure:   !s.cfg.InsecureHTTP,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   12 * 3600,
	})
	_ = s.store.RecordAudit(u.Username, clientIP, "login", "web", "PASS", nil)
	writeJSONResp(w, http.StatusOK, map[string]any{
		"username":             u.Username,
		"role":                 u.Role,
		"must_change_password": u.MustChangePassword,
		"totp_enabled":         u.TOTPEnabled,
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request, sess sessionEntry) {
	if c, err := r.Cookie(sessionCookieName); err == nil {
		s.mu.Lock()
		delete(s.sessions, c.Value)
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true})
	_ = s.store.RecordAudit(sess.Username, extractClientIP(r.RemoteAddr), "logout", "web", "PASS", nil)
	writeJSONResp(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleMe(w http.ResponseWriter, _ *http.Request, sess sessionEntry) {
	u, _ := s.store.GetUser(sess.Username)
	mustChange := false
	totpOn := false
	if u != nil {
		mustChange = u.MustChangePassword
		totpOn = u.TOTPEnabled
	}
	writeJSONResp(w, http.StatusOK, map[string]any{
		"username":             sess.Username,
		"role":                 sess.Role,
		"must_change_password": mustChange,
		"totp_enabled":         totpOn,
		"demo_mode":            s.cfg.DemoMode,
	})
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request, sess sessionEntry) {
	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := decodeJSONBody(r, &req); err != nil {
		writeJSONResp(w, http.StatusBadRequest, map[string]any{"error": "Invalid JSON."})
		return
	}
	u, err := s.store.GetUser(sess.Username)
	if err != nil || u == nil || !VerifyPassword(u.PasswordHash, req.CurrentPassword) {
		writeJSONResp(w, http.StatusUnauthorized, map[string]any{"error": "Current password incorrect."})
		return
	}
	hash, err := HashPassword(req.NewPassword)
	if err != nil {
		writeJSONResp(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	u.PasswordHash = hash
	u.MustChangePassword = false
	if err := s.store.UpsertUser(*u); err != nil {
		writeJSONResp(w, http.StatusInternalServerError, map[string]any{"error": "Could not update password."})
		return
	}
	_ = s.store.RecordAudit(sess.Username, extractClientIP(r.RemoteAddr), "change_password", u.Username, "PASS", nil)
	writeJSONResp(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleTOTPSetup(w http.ResponseWriter, _ *http.Request, sess sessionEntry) {
	secret := GenerateTOTPSecret()
	u, err := s.store.GetUser(sess.Username)
	if err != nil || u == nil {
		writeJSONResp(w, http.StatusNotFound, map[string]any{"error": "User not found."})
		return
	}
	u.TOTPSecret = secret
	u.TOTPEnabled = false
	_ = s.store.UpsertUser(*u)
	otpauth := fmt.Sprintf("otpauth://totp/event-ipsec-hub:%s?secret=%s&issuer=event-ipsec-hub", u.Username, secret)
	writeJSONResp(w, http.StatusOK, map[string]any{"secret": secret, "otpauth_uri": otpauth})
}

func (s *Server) handleTOTPEnable(w http.ResponseWriter, r *http.Request, sess sessionEntry) {
	var req struct {
		Code string `json:"code"`
	}
	if err := decodeJSONBody(r, &req); err != nil {
		writeJSONResp(w, http.StatusBadRequest, map[string]any{"error": "Invalid JSON."})
		return
	}
	u, err := s.store.GetUser(sess.Username)
	if err != nil || u == nil || u.TOTPSecret == "" {
		writeJSONResp(w, http.StatusBadRequest, map[string]any{"error": "Run TOTP setup first."})
		return
	}
	if !VerifyTOTP(u.TOTPSecret, req.Code, time.Now()) {
		writeJSONResp(w, http.StatusBadRequest, map[string]any{"error": "Invalid TOTP verification code."})
		return
	}
	u.TOTPEnabled = true
	_ = s.store.UpsertUser(*u)
	_ = s.store.RecordAudit(sess.Username, extractClientIP(r.RemoteAddr), "totp_enable", u.Username, "PASS", nil)
	writeJSONResp(w, http.StatusOK, map[string]any{"totp_enabled": true})
}

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request, _ sessionEntry) {
	profiles, _ := s.store.ListProfiles()
	var active *storage.ProfileRecord
	for i := range profiles {
		if profiles[i].Active {
			active = &profiles[i]
			break
		}
	}
	nowMs := time.Now().UnixMilli()
	samples, _ := s.store.QueryMetricSamples("", nowMs-60*60_000, nowMs+1000, 1000)
	events, _ := s.store.QueryTimelineEvents("", nowMs-60*60_000, nowMs+1000, 50)

	latestBySite := make(map[string]storage.MetricSample)
	for _, sm := range samples {
		latestBySite[sm.SiteID] = sm
	}

	siteMeta := make(map[string]map[string]any)
	var orderedActiveSites []string
	if active != nil && strings.TrimSpace(active.YAMLContent) != "" {
		if parsed, err := profile.ParseProfile([]byte(active.YAMLContent)); err == nil && parsed != nil {
			linkBySite := make(map[string]profile.SiteLink, len(parsed.SiteLinks))
			for _, sl := range parsed.SiteLinks {
				if _, ok := linkBySite[sl.SiteID]; !ok {
					linkBySite[sl.SiteID] = sl
				}
			}
			probeBySite := make(map[string]string)
			if parsed.Monitoring != nil && parsed.Monitoring.Enabled {
				for _, pr := range parsed.Monitoring.Probes {
					if pr.Path == "" || pr.Path == "primary" {
						probeBySite[pr.SiteID] = pr.Target
					}
				}
			}
			for _, st := range parsed.Sites {
				orderedActiveSites = append(orderedActiveSites, st.ID)
				sl := linkBySite[st.ID]
				siteMeta[st.ID] = map[string]any{
					"display_name":   st.DisplayName,
					"peer_public_ip": st.PublicEndpoint,
					"lan_cidrs":      st.LANCIDRs,
					"vendor":         st.Firewall.Vendor,
					"selector_mode":  sl.SelectorMode,
					"isp_label":      sl.OuterPath.ISPLabel,
					"probe_target":   probeBySite[st.ID],
				}
			}
		}
	}

	seenSites := make(map[string]struct{}, len(latestBySite)+len(orderedActiveSites))
	siteCards := make([]map[string]any, 0, len(latestBySite)+len(orderedActiveSites))
	for _, sm := range latestBySite {
		seenSites[sm.SiteID] = struct{}{}
		diag := telemetry.Diagnose(sm, events)
		card := map[string]any{
			"sample":    sm,
			"diagnosis": diag,
		}
		if m, ok := siteMeta[sm.SiteID]; ok {
			card["meta"] = m
		}
		siteCards = append(siteCards, card)
	}
	for _, sid := range orderedActiveSites {
		if _, ok := seenSites[sid]; ok {
			continue
		}
		m := siteMeta[sid]
		ispLabel, _ := m["isp_label"].(string)
		placeholder := storage.MetricSample{
			SiteID:       sid,
			ISPLabel:     ispLabel,
			L1OuterState: telemetry.StateUnknown,
			L2IKEState:   telemetry.StateUnknown,
			L2ChildState: telemetry.StateUnknown,
			L4UDPState:   telemetry.StateUnknown,
		}
		siteCards = append(siteCards, map[string]any{
			"sample":    placeholder,
			"diagnosis": telemetry.Diagnose(placeholder, events),
			"meta":      m,
		})
	}
	sort.Slice(siteCards, func(i, j int) bool {
		return siteCards[i]["sample"].(storage.MetricSample).SiteID < siteCards[j]["sample"].(storage.MetricSample).SiteID
	})

	foState, _ := failover.LoadState(s.cfg.FailoverStateFile)
	agentOK := false
	if s.agent != nil {
		var ping map[string]any
		if err := s.agent.Call(r.Context(), rpc.MethodPing, nil, &ping); err == nil {
			agentOK = true
		}
	}
	writeJSONResp(w, http.StatusOK, map[string]any{
		"active_profile": active,
		"profile_count":  len(profiles),
		"failover":       foState,
		"agent_online":   agentOK,
		"demo_mode":      s.cfg.DemoMode,
		"sites":          siteCards,
		"recent_events":  events,
		"overall":        telemetry.SummarizeWindow(samples, events),
	})
}

func (s *Server) handleTimeline(w http.ResponseWriter, r *http.Request, _ sessionEntry) {
	site := r.URL.Query().Get("site")
	mins, _ := strconv.Atoi(r.URL.Query().Get("minutes"))
	if mins <= 0 || mins > 43200 {
		mins = 60
	}
	toMs := time.Now().UnixMilli()
	if v, err := strconv.ParseInt(r.URL.Query().Get("to"), 10, 64); err == nil && v > 0 {
		toMs = v
	}
	fromMs := toMs - int64(mins)*60_000
	if v, err := strconv.ParseInt(r.URL.Query().Get("from"), 10, 64); err == nil && v > 0 {
		fromMs = v
	}

	samples, err := s.store.QueryMetricSamples(site, fromMs, toMs, 2000)
	if err != nil {
		writeJSONResp(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	events, err := s.store.QueryTimelineEvents(site, fromMs, toMs, 500)
	if err != nil {
		writeJSONResp(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	if samples == nil {
		samples = []storage.MetricSample{}
	}
	if events == nil {
		events = []storage.TimelineEvent{}
	}
	writeJSONResp(w, http.StatusOK, telemetry.SyncedTimelineResponse{
		SiteID:    site,
		FromMs:    fromMs,
		ToMs:      toMs,
		Samples:   samples,
		Events:    events,
		Diagnosis: telemetry.SummarizeWindow(samples, events),
	})
}

func (s *Server) handleListEvents(w http.ResponseWriter, r *http.Request, _ sessionEntry) {
	q := r.URL.Query()
	var f storage.EventSearchFilter
	f.SiteID = strings.TrimSpace(q.Get("site"))
	f.Severity = strings.TrimSpace(q.Get("severity"))
	f.Layer = strings.TrimSpace(q.Get("layer"))
	f.Query = strings.TrimSpace(q.Get("q"))
	if v, err := strconv.ParseInt(q.Get("from"), 10, 64); err == nil && v > 0 {
		f.FromMs = v
	}
	if v, err := strconv.ParseInt(q.Get("to"), 10, 64); err == nil && v > 0 {
		f.ToMs = v
	}
	if v, err := strconv.Atoi(q.Get("limit")); err == nil && v > 0 {
		f.Limit = v
	} else {
		f.Limit = 50
	}
	if v, err := strconv.Atoi(q.Get("offset")); err == nil && v >= 0 {
		f.Offset = v
	}
	events, total, err := s.store.SearchTimelineEvents(f)
	if err != nil {
		writeJSONResp(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSONResp(w, http.StatusOK, map[string]any{
		"events": events,
		"total":  total,
		"limit":  f.Limit,
		"offset": f.Offset,
	})
}

func (s *Server) handleSeedDemo(w http.ResponseWriter, r *http.Request, sess sessionEntry) {
	if !s.cfg.DemoMode {
		writeJSONResp(w, http.StatusForbidden, map[string]any{"error": "Demo seed is only enabled when started with --demo."})
		return
	}
	now := time.Now().UTC()
	baseMs := now.Add(-45 * time.Minute).UnixMilli()
	sites := []struct {
		id  string
		isp string
	}{
		{"server-core", "BGP-ISP-A"},
		{"ob-venue-1", "CN-Telecom"},
		{"ob-venue-2", "JP-NTT"},
	}

	// Inject 3 realistic tournament incident windows on ob-venue-1 so the synced 4-layer ECharts
	// timeline immediately showcases ISP drop vs IPsec Rekey vs Tunnel Blackhole classification!
	for step := 0; step < 90; step++ {
		ts := baseMs + int64(step)*30_000
		for _, st := range sites {
			sm := storage.MetricSample{
				TsMs: ts, EventID: "esports-multi-ob-hillstone", HubID: "hub-vps-primary",
				SiteID: st.id, LinkID: st.id, ISPLabel: st.isp,
				L1Mode: "icmp", L1OuterState: 1, L1OuterRTTMs: 24 + 3*math.Sin(float64(step)/4), L1OuterLoss: 0,
				L2IKEState: 1, L2ChildState: 1, L2Rekeys10m: 0,
				L3RxBps: 18_500_000 + 2_000_000*math.Cos(float64(step)/3),
				L3TxBps: 19_200_000 + 1_500_000*math.Sin(float64(step)/5),
				L4UDPState: 1, L4UDPRTTMs: 27 + 3*math.Sin(float64(step)/4), L4UDPP95Ms: 31, L4UDPLoss: 0,
			}
			if st.id == "ob-venue-1" {
				switch {
				case step >= 22 && step <= 27: // Incident 1: Outer ISP jitter & loss
					sm.L1OuterRTTMs = 148
					sm.L1OuterLoss = 0.35
					sm.L4UDPRTTMs = 156
					sm.L4UDPP95Ms = 185
					sm.L4UDPLoss = 0.35
				case step >= 50 && step <= 53: // Incident 2: IPsec CHILD down + rekey
					sm.L2ChildState = 0
					sm.L2Rekeys10m = 3
					sm.L3RxBps = 0
					sm.L3TxBps = 0
					sm.L4UDPState = 0
					sm.L4UDPLoss = 1.0
				case step >= 74 && step <= 78: // Incident 3: Tunnel UP but asymmetric blackhole
					sm.L3TxBps = 14_000_000
					sm.L3RxBps = 0
					sm.L4UDPState = 0
					sm.L4UDPLoss = 1.0
				}
			}
			d := telemetry.Diagnose(sm, nil)
			sm.RootCause = d.Code
			sm.RootDetail = d.SummaryZH
			_ = s.store.InsertMetricSample(sm)
		}
	}
	_ = s.store.InsertTimelineEvent(storage.TimelineEvent{
		TsMs: baseMs + 22*30_000, Layer: "L1_OUTER", Category: "ISP_LOSS_SPIKE", Severity: "warning",
		SiteID: "ob-venue-1", Source: "self_hosted_hub", Title: "公网链路丢包率升高 (35%)", RootCause: telemetry.CauseISPOuterDegraded,
	})
	_ = s.store.InsertTimelineEvent(storage.TimelineEvent{
		TsMs: baseMs + 50*30_000, Layer: "L2_IPSEC", Category: "CHILD_DOWN", Severity: "critical",
		SiteID: "ob-venue-1", Source: "self_hosted_hub", Title: "IPsec 隧道断开 (DPD 超时)", RootCause: telemetry.CauseIPsecSAEvent,
	})
	_ = s.store.InsertTimelineEvent(storage.TimelineEvent{
		TsMs: baseMs + 54*30_000, Layer: "L2_IPSEC", Category: "CHILD_UP", Severity: "info",
		SiteID: "ob-venue-1", Source: "self_hosted_hub", Title: "IPsec 隧道已恢复",
	})
	_ = s.store.InsertTimelineEvent(storage.TimelineEvent{
		TsMs: baseMs + 74*30_000, Layer: "L4_UDP", Category: "UDP_BLACKHOLE", Severity: "critical",
		SiteID: "ob-venue-1", Source: "self_hosted_hub", Title: "隧道在线但内网探针 100% 丢包", RootCause: telemetry.CauseTunnelBlackholeAsymmetric,
	})
	_ = s.store.RecordAudit(sess.Username, extractClientIP(r.RemoteAddr), "seed_demo_telemetry", "ob-venue-1", "PASS", nil)
	writeJSONResp(w, http.StatusOK, map[string]any{"ok": true, "samples_seeded": 270})
}

func (s *Server) handleSSEStream(w http.ResponseWriter, r *http.Request, _ sessionEntry) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSONResp(w, http.StatusInternalServerError, map[string]any{"error": "Streaming unsupported."})
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	sendTick := func() {
		nowMs := time.Now().UnixMilli()
		samples, _ := s.store.QueryMetricSamples("", nowMs-60_000, nowMs+1000, 50)
		events, _ := s.store.QueryTimelineEvents("", nowMs-60_000, nowMs+1000, 20)
		payload, _ := json.Marshal(map[string]any{"ts_ms": nowMs, "samples": samples, "events": events})
		fmt.Fprintf(w, "event: tick\ndata: %s\n\n", payload)
		flusher.Flush()
	}
	sendTick()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			sendTick()
		}
	}
}

func (s *Server) handleListProfiles(w http.ResponseWriter, _ *http.Request, _ sessionEntry) {
	list, err := s.store.ListProfiles()
	if err != nil {
		writeJSONResp(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	secrets, _ := s.store.ListSecretsMeta()
	if list == nil {
		list = []storage.ProfileRecord{}
	}
	if secrets == nil {
		secrets = []storage.SecretMeta{}
	}
	writeJSONResp(w, http.StatusOK, map[string]any{"profiles": list, "secrets_meta": secrets})
}

func (s *Server) handleValidateYAML(w http.ResponseWriter, r *http.Request, _ sessionEntry) {
	var req struct {
		YAMLContent string `json:"yaml_content"`
	}
	if err := decodeJSONBody(r, &req); err != nil {
		writeJSONResp(w, http.StatusBadRequest, map[string]any{"error": "Invalid JSON."})
		return
	}
	p, err := profile.ParseProfile([]byte(req.YAMLContent))
	if err != nil {
		writeJSONResp(w, http.StatusBadRequest, map[string]any{"status": "FAIL", "detail": err.Error()})
		return
	}
	writeJSONResp(w, http.StatusOK, map[string]any{
		"status":  "PASS",
		"detail":  "Profile schema and topology validated.",
		"event":   p.Event,
		"sites":   p.Sites,
		"profile": p,
		"backup":  profile.EvaluateBackupReadiness(p),
	})
}

func (s *Server) handleSaveProfile(w http.ResponseWriter, r *http.Request, sess sessionEntry) {
	var req struct {
		YAMLContent       string `json:"yaml_content"`
		HubRole           string `json:"hub_role"`
		OuterProbeTargets string `json:"outer_probe_targets_json"`
		Note              string `json:"note"`
		Activate          bool   `json:"activate"`
	}
	if err := decodeJSONBody(r, &req); err != nil {
		writeJSONResp(w, http.StatusBadRequest, map[string]any{"error": "Invalid JSON."})
		return
	}
	p, err := profile.ParseProfile([]byte(req.YAMLContent))
	if err != nil {
		writeJSONResp(w, http.StatusBadRequest, map[string]any{"status": "FAIL", "error": err.Error()})
		return
	}
	sha := manifest.Digest([]byte(req.YAMLContent))
	rec := storage.ProfileRecord{
		ID:                p.Event.ID,
		Name:              p.Event.Name,
		YAMLContent:       req.YAMLContent,
		SHA256:            sha,
		HubRole:           req.HubRole,
		OuterProbeTargets: req.OuterProbeTargets,
	}
	if err := s.store.SaveProfile(rec, sess.Username, req.Note); err != nil {
		writeJSONResp(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	if req.Activate {
		_ = s.store.SetActiveProfile(rec.ID)
	}
	_ = s.store.RecordAudit(sess.Username, extractClientIP(r.RemoteAddr), "save_profile", rec.ID, "PASS", map[string]any{"sha256": sha, "note": req.Note})
	writeJSONResp(w, http.StatusOK, map[string]any{"status": "PASS", "id": rec.ID, "sha256": sha})
}

func (s *Server) loadStoredProfile(id string) (*storage.ProfileRecord, *profile.Profile, error) {
	rec, err := s.store.GetProfile(id)
	if err != nil {
		return nil, nil, err
	}
	if rec == nil {
		return nil, nil, fmt.Errorf("profile %q not found", id)
	}
	p, err := profile.ParseProfile([]byte(rec.YAMLContent))
	if err != nil {
		return rec, nil, err
	}
	return rec, p, nil
}

func (s *Server) handleProfileRevisions(w http.ResponseWriter, r *http.Request, _ sessionEntry) {
	id := r.PathValue("id")
	revs, err := s.store.ListRevisions(id, 30)
	if err != nil {
		writeJSONResp(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	if revs == nil {
		revs = []storage.ProfileRevision{}
	}
	writeJSONResp(w, http.StatusOK, map[string]any{"revisions": revs})
}

func (s *Server) handleProfilePlan(w http.ResponseWriter, r *http.Request, _ sessionEntry) {
	_, p, err := s.loadStoredProfile(r.PathValue("id"))
	if err != nil {
		writeJSONResp(w, http.StatusNotFound, map[string]any{"error": err.Error()})
		return
	}
	writeJSONResp(w, http.StatusOK, handoff.BuildPlan(p))
}

func (s *Server) handleProfileRender(w http.ResponseWriter, r *http.Request, _ sessionEntry) {
	_, p, err := s.loadStoredProfile(r.PathValue("id"))
	if err != nil {
		writeJSONResp(w, http.StatusNotFound, map[string]any{"error": err.Error()})
		return
	}
	out, err := manifest.Render(p)
	if err != nil {
		writeJSONResp(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeJSONResp(w, http.StatusOK, out)
}

func (s *Server) handleProfileApply(w http.ResponseWriter, r *http.Request, sess sessionEntry) {
	rec, _, err := s.loadStoredProfile(r.PathValue("id"))
	if err != nil {
		writeJSONResp(w, http.StatusNotFound, map[string]any{"error": err.Error()})
		return
	}
	var req struct {
		Confirmed   bool `json:"confirmed"`
		Maintenance bool `json:"maintenance"`
	}
	_ = decodeJSONBody(r, &req)
	if s.agent == nil {
		writeJSONResp(w, http.StatusServiceUnavailable, map[string]any{"error": "Privileged Hub Agent is not connected (offline/demo mode)."})
		return
	}
	var out map[string]any
	err = s.agent.Call(r.Context(), rpc.MethodApplyProfile, rpc.ApplyParams{
		YAMLContent: rec.YAMLContent,
		Confirmed:   req.Confirmed,
		Maintenance: req.Maintenance,
		Operator:    sess.Username,
	}, &out)
	status := "PASS"
	if err != nil {
		status = "FAIL"
	} else if req.Confirmed {
		_ = s.store.SetActiveProfile(rec.ID)
	}
	_ = s.store.RecordAudit(sess.Username, extractClientIP(r.RemoteAddr), "apply_profile", rec.ID, status, map[string]any{"confirmed": req.Confirmed, "maintenance": req.Maintenance})
	if err != nil {
		writeJSONResp(w, http.StatusBadRequest, map[string]any{"status": "FAIL", "decision": "STOP", "error": err.Error()})
		return
	}
	writeJSONResp(w, http.StatusOK, out)
}

func (s *Server) handleWriteSecret(w http.ResponseWriter, r *http.Request, sess sessionEntry) {
	var req struct {
		SiteID    string `json:"site_id"`
		SecretRef string `json:"secret_ref"`
		PSKHex    string `json:"psk_hex"`
	}
	if err := decodeJSONBody(r, &req); err != nil {
		writeJSONResp(w, http.StatusBadRequest, map[string]any{"error": "Invalid JSON."})
		return
	}
	if s.agent == nil {
		writeJSONResp(w, http.StatusServiceUnavailable, map[string]any{"error": "Privileged Hub Agent is required to write root-owned PSK files."})
		return
	}
	var out map[string]any
	if err := s.agent.Call(r.Context(), rpc.MethodWriteSecret, rpc.WriteSecretParams{
		SecretRef: req.SecretRef,
		SiteID:    req.SiteID,
		PSKHex:    req.PSKHex,
		Operator:  sess.Username,
	}, &out); err != nil {
		writeJSONResp(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	_ = s.store.RecordAudit(sess.Username, extractClientIP(r.RemoteAddr), "write_secret", req.SiteID, "PASS", map[string]any{"secret_ref": req.SecretRef})
	writeJSONResp(w, http.StatusOK, out)
}

func (s *Server) handleRevealSecret(w http.ResponseWriter, r *http.Request, sess sessionEntry) {
	var req struct {
		SiteID    string `json:"site_id"`
		SecretRef string `json:"secret_ref"`
	}
	if err := decodeJSONBody(r, &req); err != nil {
		writeJSONResp(w, http.StatusBadRequest, map[string]any{"error": "Invalid JSON."})
		return
	}
	secretRef := strings.TrimSpace(req.SecretRef)
	if secretRef == "" && strings.TrimSpace(req.SiteID) != "" {
		if metas, err := s.store.ListSecretsMeta(); err == nil {
			for _, m := range metas {
				if m.SiteID == req.SiteID && m.Ref != "" {
					secretRef = m.Ref
					break
				}
			}
		}
		if secretRef == "" {
			secretRef = fmt.Sprintf("file:/etc/ipsecvpn/secrets/%s.psk", strings.TrimSpace(req.SiteID))
		}
	}
	if secretRef == "" {
		writeJSONResp(w, http.StatusBadRequest, map[string]any{"error": "site_id or secret_ref is required."})
		return
	}
	if s.agent == nil {
		writeJSONResp(w, http.StatusServiceUnavailable, map[string]any{"error": "Privileged Hub Agent is required to read root-owned PSK files."})
		return
	}
	var res struct {
		PSK string `json:"psk"`
	}
	if err := s.agent.Call(r.Context(), rpc.MethodReadSecretAudit, rpc.ReadSecretAuditParams{
		SecretRef: secretRef,
		SiteID:    req.SiteID,
		Operator:  sess.Username,
		RemoteIP:  extractClientIP(r.RemoteAddr),
	}, &res); err != nil {
		writeJSONResp(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSONResp(w, http.StatusOK, map[string]any{
		"site_id":    req.SiteID,
		"secret_ref": secretRef,
		"psk_hex":    res.PSK,
	})
}

func (s *Server) handleExportPeer(w http.ResponseWriter, r *http.Request, sess sessionEntry) {
	_, p, err := s.loadStoredProfile(r.PathValue("id"))
	if err != nil {
		writeJSONResp(w, http.StatusNotFound, map[string]any{"error": err.Error()})
		return
	}
	var req struct {
		SiteID          string `json:"site_id"`
		Format          string `json:"format"` // tencent-json | hillstone-md | generic-md | hillstone-draft | strongswan-draft | json
		IncludePSK      bool   `json:"include_psk"`
		ConfirmPassword string `json:"confirm_password"`
	}
	if err := decodeJSONBody(r, &req); err != nil {
		writeJSONResp(w, http.StatusBadRequest, map[string]any{"error": "Invalid JSON."})
		return
	}
	plaintextPSK := ""
	if req.IncludePSK {
		if sess.Role != "admin" {
			writeJSONResp(w, http.StatusForbidden, map[string]any{"error": "Admin role required to export plaintext PSK."})
			return
		}
		u, _ := s.store.GetUser(sess.Username)
		if u == nil || !VerifyPassword(u.PasswordHash, req.ConfirmPassword) {
			writeJSONResp(w, http.StatusUnauthorized, map[string]any{"error": "Password re-confirmation failed for plaintext PSK export."})
			return
		}
		var secretRef string
		for _, sl := range p.SiteLinks {
			if sl.SiteID == req.SiteID {
				secretRef = sl.SecretRef
				break
			}
		}
		if s.agent == nil {
			writeJSONResp(w, http.StatusServiceUnavailable, map[string]any{"error": "Hub Agent offline; cannot fetch root-owned PSK."})
			return
		}
		var res struct {
			PSK string `json:"psk"`
		}
		if err := s.agent.Call(r.Context(), rpc.MethodReadSecretAudit, rpc.ReadSecretAuditParams{
			SecretRef: secretRef,
			SiteID:    req.SiteID,
			Operator:  sess.Username,
			RemoteIP:  extractClientIP(r.RemoteAddr),
		}, &res); err != nil {
			writeJSONResp(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		plaintextPSK = res.PSK
	}

	_ = s.store.RecordAudit(sess.Username, extractClientIP(r.RemoteAddr), "export_peer", req.SiteID, "PASS", map[string]any{
		"format":      req.Format,
		"include_psk": req.IncludePSK,
	})

	switch req.Format {
	case "", "tencent-json":
		tc, err := handoff.RenderTencentJSON(p, req.SiteID, plaintextPSK)
		if err != nil {
			writeJSONResp(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		_ = enc.Encode(tc)
		writeJSONResp(w, http.StatusOK, map[string]any{
			"format":   "tencent-json",
			"filename": fmt.Sprintf("%s-%s-tencent.json", p.Event.ID, req.SiteID),
			"content":  buf.String(),
			"data":     tc,
		})
	case "hillstone-md", "generic-md":
		tmpl := "hillstone"
		if req.Format == "generic-md" {
			tmpl = "generic"
		}
		params, err := handoff.PeerParameters(p, req.SiteID, tmpl)
		if err != nil {
			writeJSONResp(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		md := handoff.RenderPeerMarkdown(params)
		if plaintextPSK != "" {
			md = strings.ReplaceAll(md, handoff.PSKPlaceholder, plaintextPSK)
		}
		writeJSONResp(w, http.StatusOK, map[string]any{
			"format":   req.Format,
			"filename": fmt.Sprintf("%s-%s-%s.md", p.Event.ID, req.SiteID, tmpl),
			"content":  md,
		})
	case "hillstone-draft", "strongswan-draft":
		vendor := strings.TrimSuffix(req.Format, "-draft")
		draft, err := handoff.RenderVendorDraft(p, req.SiteID, vendor, plaintextPSK)
		if err != nil {
			writeJSONResp(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		writeJSONResp(w, http.StatusOK, map[string]any{
			"format":   req.Format,
			"filename": fmt.Sprintf("%s-%s-%s.txt", p.Event.ID, req.SiteID, vendor),
			"content":  draft,
		})
	default:
		writeJSONResp(w, http.StatusBadRequest, map[string]any{"error": "Unsupported export format."})
	}
}

func (s *Server) handleTunnelReconnect(w http.ResponseWriter, r *http.Request, sess sessionEntry) {
	site := strings.TrimSpace(r.PathValue("site"))
	if site == "" {
		writeJSONResp(w, http.StatusBadRequest, map[string]any{"error": "Site ID is required."})
		return
	}
	if s.agent == nil {
		if s.cfg.DemoMode {
			_ = s.store.InsertTimelineEvent(storage.TimelineEvent{
				TsMs: time.Now().UnixMilli(), Layer: "L2_IPSEC", Category: "TUNNEL_RECONNECT", Severity: "info",
				SiteID: site, Source: "web_console", Title: fmt.Sprintf("已触发站点 %s 隧道重连 (演示模式)", site),
			})
			_ = s.store.RecordAudit(sess.Username, extractClientIP(r.RemoteAddr), "tunnel_reconnect", site, "PASS", map[string]any{"demo": true})
			writeJSONResp(w, http.StatusOK, map[string]any{"status": "PASS", "site": site, "demo": true})
			return
		}
		writeJSONResp(w, http.StatusServiceUnavailable, map[string]any{"error": "Gateway Agent is offline."})
		return
	}
	var out map[string]any
	err := s.agent.Call(r.Context(), rpc.MethodReconnect, rpc.ReconnectParams{
		Site:     site,
		Operator: sess.Username,
	}, &out)
	status := "PASS"
	if err != nil {
		status = "FAIL"
	} else {
		_ = s.store.InsertTimelineEvent(storage.TimelineEvent{
			TsMs: time.Now().UnixMilli(), Layer: "L2_IPSEC", Category: "TUNNEL_RECONNECT", Severity: "info",
			SiteID: site, Source: "web_console", Title: fmt.Sprintf("操作人 %s 触发站点 %s 隧道重连", sess.Username, site),
		})
	}
	_ = s.store.RecordAudit(sess.Username, extractClientIP(r.RemoteAddr), "tunnel_reconnect", site, status, nil)
	if err != nil {
		writeJSONResp(w, http.StatusBadRequest, map[string]any{"status": "FAIL", "error": err.Error()})
		return
	}
	writeJSONResp(w, http.StatusOK, out)
}

func (s *Server) handleTunnelRekey(w http.ResponseWriter, r *http.Request, sess sessionEntry) {
	site := strings.TrimSpace(r.PathValue("site"))
	if site == "" {
		writeJSONResp(w, http.StatusBadRequest, map[string]any{"error": "Site ID is required."})
		return
	}
	var req struct {
		Kind string `json:"kind"` // child | ike
	}
	_ = decodeJSONBody(r, &req)
	if req.Kind == "" {
		req.Kind = "child"
	}
	if req.Kind != "child" && req.Kind != "ike" {
		writeJSONResp(w, http.StatusBadRequest, map[string]any{"error": "kind must be 'child' or 'ike'."})
		return
	}
	if s.agent == nil {
		if s.cfg.DemoMode {
			_ = s.store.InsertTimelineEvent(storage.TimelineEvent{
				TsMs: time.Now().UnixMilli(), Layer: "L2_IPSEC", Category: "TUNNEL_REKEY", Severity: "info",
				SiteID: site, Source: "web_console", Title: fmt.Sprintf("已触发站点 %s %s SA 重协商 (演示模式)", site, strings.ToUpper(req.Kind)),
			})
			_ = s.store.RecordAudit(sess.Username, extractClientIP(r.RemoteAddr), "tunnel_rekey", site, "PASS", map[string]any{"kind": req.Kind, "demo": true})
			writeJSONResp(w, http.StatusOK, map[string]any{"status": "PASS", "site": site, "kind": req.Kind, "demo": true})
			return
		}
		writeJSONResp(w, http.StatusServiceUnavailable, map[string]any{"error": "Gateway Agent is offline."})
		return
	}
	var out map[string]any
	err := s.agent.Call(r.Context(), rpc.MethodRekey, rpc.RekeyParams{
		Site:     site,
		Kind:     req.Kind,
		Operator: sess.Username,
	}, &out)
	status := "PASS"
	if err != nil {
		status = "FAIL"
	} else {
		_ = s.store.InsertTimelineEvent(storage.TimelineEvent{
			TsMs: time.Now().UnixMilli(), Layer: "L2_IPSEC", Category: "TUNNEL_REKEY", Severity: "info",
			SiteID: site, Source: "web_console", Title: fmt.Sprintf("操作人 %s 触发站点 %s %s SA 重协商", sess.Username, site, strings.ToUpper(req.Kind)),
		})
	}
	_ = s.store.RecordAudit(sess.Username, extractClientIP(r.RemoteAddr), "tunnel_rekey", site, status, map[string]any{"kind": req.Kind})
	if err != nil {
		writeJSONResp(w, http.StatusBadRequest, map[string]any{"status": "FAIL", "error": err.Error()})
		return
	}
	writeJSONResp(w, http.StatusOK, out)
}

func (s *Server) handleTunnelDiagnostics(w http.ResponseWriter, r *http.Request, _ sessionEntry) {
	site := strings.TrimSpace(r.PathValue("site"))
	if site == "" {
		writeJSONResp(w, http.StatusBadRequest, map[string]any{"error": "Site ID is required."})
		return
	}
	if s.agent == nil {
		nowMs := time.Now().UnixMilli()
		evs, _ := s.store.QueryTimelineEvents(site, nowMs-24*60*60_000, nowMs+1000, 15)
		if s.cfg.DemoMode {
			writeJSONResp(w, http.StatusOK, map[string]any{
				"site_id":         site,
				"ike_state":       1,
				"child_state":     1,
				"swanctl_sas":     fmt.Sprintf("(演示模式) 站点 %s IKEv2 / ESP SA 模拟在线", site),
				"strongswan_logs": "(演示模式) 未连接宿主机 strongSwan 进程",
				"recent_events":   evs,
				"captured_at_ms":  nowMs,
			})
			return
		}
		writeJSONResp(w, http.StatusServiceUnavailable, map[string]any{"error": "Gateway Agent is offline."})
		return
	}
	var out map[string]any
	if err := s.agent.Call(r.Context(), rpc.MethodTunnelDiagnostics, rpc.TunnelDiagnosticsParams{
		Site: site,
	}, &out); err != nil {
		writeJSONResp(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	writeJSONResp(w, http.StatusOK, out)
}

func (s *Server) handleFailoverStatus(w http.ResponseWriter, _ *http.Request, _ sessionEntry) {
	st, err := failover.LoadState(s.cfg.FailoverStateFile)
	if err != nil {
		writeJSONResp(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSONResp(w, http.StatusOK, map[string]any{"status": "PASS", "state": st})
}

func (s *Server) handleFailoverSwitchBackup(w http.ResponseWriter, r *http.Request, sess sessionEntry) {
	var req struct {
		Reason    string `json:"reason"`
		ApplyGate bool   `json:"apply_gate"`
	}
	_ = decodeJSONBody(r, &req)
	ctrl, err := failover.NewController(s.cfg.FailoverStateFile, 3, 180)
	if err != nil {
		writeJSONResp(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	out, err := ctrl.ManualSwitchToBackup(sess.Username, true, req.Reason, 0)
	if err != nil {
		writeJSONResp(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	if req.ApplyGate && s.agent != nil {
		var gate map[string]any
		if gerr := s.agent.Call(r.Context(), rpc.MethodFailoverGate, rpc.FailoverGateParams{Locked: true, Operator: sess.Username}, &gate); gerr == nil {
			out["hub_gate"] = gate
		}
	}
	_ = s.store.RecordAudit(sess.Username, extractClientIP(r.RemoteAddr), "failover_switch_backup", "hub", "PASS", req)
	writeJSONResp(w, http.StatusOK, out)
}

func (s *Server) handleFailoverFailback(w http.ResponseWriter, r *http.Request, sess sessionEntry) {
	var req struct {
		Force     bool `json:"force"`
		ApplyGate bool `json:"apply_gate"`
	}
	_ = decodeJSONBody(r, &req)
	ctrl, err := failover.NewController(s.cfg.FailoverStateFile, 3, 180)
	if err != nil {
		writeJSONResp(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	out, err := ctrl.ConfirmFailback(sess.Username, true, req.Force, 0)
	if err != nil {
		writeJSONResp(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	if out["status"] == "PASS" && req.ApplyGate && s.agent != nil {
		var gate map[string]any
		if gerr := s.agent.Call(r.Context(), rpc.MethodFailoverGate, rpc.FailoverGateParams{Locked: false, Operator: sess.Username}, &gate); gerr == nil {
			out["hub_gate"] = gate
		}
	}
	_ = s.store.RecordAudit(sess.Username, extractClientIP(r.RemoteAddr), "failover_failback", "hub", fmt.Sprint(out["status"]), req)
	code := http.StatusOK
	if out["status"] == "STOP" {
		code = http.StatusConflict
	}
	writeJSONResp(w, code, out)
}

func (s *Server) handleFailoverSetRole(w http.ResponseWriter, r *http.Request, sess sessionEntry) {
	var req struct {
		Role string `json:"role"`
	}
	if err := decodeJSONBody(r, &req); err != nil {
		writeJSONResp(w, http.StatusBadRequest, map[string]any{"error": "Invalid JSON."})
		return
	}
	ctrl, err := failover.NewController(s.cfg.FailoverStateFile, 3, 180)
	if err != nil {
		writeJSONResp(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	out, err := ctrl.SetHubRole(req.Role, sess.Username, 0)
	if err != nil {
		writeJSONResp(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	_ = s.store.RecordAudit(sess.Username, extractClientIP(r.RemoteAddr), "failover_set_role", req.Role, fmt.Sprint(out["status"]), nil)
	writeJSONResp(w, http.StatusOK, out)
}

func (s *Server) handleListAlertRules(w http.ResponseWriter, _ *http.Request, _ sessionEntry) {
	rules, err := s.store.ListAlertRules()
	if err != nil {
		writeJSONResp(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSONResp(w, http.StatusOK, map[string]any{"rules": rules})
}

func (s *Server) handleUpsertAlertRule(w http.ResponseWriter, r *http.Request, sess sessionEntry) {
	var rule storage.AlertRule
	if err := decodeJSONBody(r, &rule); err != nil || rule.ID == "" {
		writeJSONResp(w, http.StatusBadRequest, map[string]any{"error": "Invalid alert rule."})
		return
	}
	if err := s.store.UpsertAlertRule(rule); err != nil {
		writeJSONResp(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	_ = s.store.RecordAudit(sess.Username, extractClientIP(r.RemoteAddr), "update_alert_rule", rule.ID, "PASS", rule)
	writeJSONResp(w, http.StatusOK, map[string]any{"ok": true, "rule": rule})
}

func (s *Server) handleAlertHistory(w http.ResponseWriter, _ *http.Request, _ sessionEntry) {
	hist, err := s.store.QueryAlertHistory(100)
	if err != nil {
		writeJSONResp(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	if hist == nil {
		hist = []storage.AlertHistoryRecord{}
	}
	writeJSONResp(w, http.StatusOK, map[string]any{"history": hist})
}

func (s *Server) handleGetAlertChannel(w http.ResponseWriter, _ *http.Request, _ sessionEntry) {
	meta := map[string]any{
		"configured": false,
		"enabled":    false,
		"masked_url": "",
		"has_secret": false,
	}
	if raw, ok, _ := s.store.GetKV("feishu_channel_meta"); ok && raw != "" {
		_ = json.Unmarshal([]byte(raw), &meta)
	}
	writeJSONResp(w, http.StatusOK, meta)
}

func (s *Server) handleSaveAlertChannel(w http.ResponseWriter, r *http.Request, sess sessionEntry) {
	var req struct {
		Enabled    bool   `json:"enabled"`
		WebhookURL string `json:"webhook_url"`
		Secret     string `json:"secret"`
		KeepSecret bool   `json:"keep_secret"`
	}
	if err := decodeJSONBody(r, &req); err != nil {
		writeJSONResp(w, http.StatusBadRequest, map[string]any{"error": "Invalid JSON."})
		return
	}
	if req.WebhookURL != "" {
		if _, err := alert.ValidateFeishuTarget(req.WebhookURL, s.cfg.DemoMode); err != nil {
			writeJSONResp(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
	}
	meta := map[string]any{
		"configured": req.WebhookURL != "",
		"enabled":    req.Enabled,
		"masked_url": alert.MaskFeishuURL(req.WebhookURL),
		"has_secret": req.Secret != "",
		"updated_at": time.Now().UnixMilli(),
	}
	if s.agent != nil {
		var out map[string]any
		if err := s.agent.Call(r.Context(), rpc.MethodSaveAlertChannel, rpc.SaveAlertChannelParams{
			Enabled:    req.Enabled,
			WebhookURL: req.WebhookURL,
			Secret:     req.Secret,
			KeepSecret: req.KeepSecret,
			Operator:   sess.Username,
		}, &out); err != nil {
			writeJSONResp(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		meta["configured"] = out["configured"]
		meta["enabled"] = out["enabled"]
		meta["masked_url"] = out["masked_url"]
		meta["has_secret"] = out["has_secret"]
	} else if !s.cfg.DemoMode {
		writeJSONResp(w, http.StatusServiceUnavailable, map[string]any{"error": "Gateway Agent is required to persist root-protected Feishu channel credentials."})
		return
	} else {
		// In demo mode, preserve existing masked_url / has_secret if left blank
		if raw, ok, _ := s.store.GetKV("feishu_channel_meta"); ok && raw != "" {
			var prev map[string]any
			if json.Unmarshal([]byte(raw), &prev) == nil {
				if req.WebhookURL == "" && prev["masked_url"] != "" {
					meta["configured"] = prev["configured"]
					meta["masked_url"] = prev["masked_url"]
				}
				if req.KeepSecret && req.Secret == "" {
					meta["has_secret"] = prev["has_secret"]
				}
			}
		}
	}
	// Never write plaintext webhook URL or secret into SQLite — store masked metadata only.
	rawMeta, _ := json.Marshal(meta)
	_ = s.store.SetKV("feishu_channel_meta", string(rawMeta))
	_ = s.store.RecordAudit(sess.Username, extractClientIP(r.RemoteAddr), "save_feishu_channel", "feishu", "PASS", map[string]any{
		"enabled":    meta["enabled"],
		"masked_url": meta["masked_url"],
		"has_secret": meta["has_secret"],
	})
	writeJSONResp(w, http.StatusOK, meta)
}

func (s *Server) handleFeishuTest(w http.ResponseWriter, r *http.Request, sess sessionEntry) {
	var req struct {
		WebhookURL string `json:"webhook_url"`
		Secret     string `json:"secret"`
	}
	if err := decodeJSONBody(r, &req); err != nil {
		writeJSONResp(w, http.StatusBadRequest, map[string]any{"error": "Invalid JSON."})
		return
	}
	if strings.TrimSpace(req.WebhookURL) == "" {
		if s.agent == nil {
			writeJSONResp(w, http.StatusBadRequest, map[string]any{"error": "Please enter a Feishu webhook URL."})
			return
		}
		var out map[string]any
		if err := s.agent.Call(r.Context(), rpc.MethodTestAlertChannel, rpc.TestAlertChannelParams{
			Operator: sess.Username,
		}, &out); err != nil {
			writeJSONResp(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
			return
		}
		_ = s.store.RecordAudit(sess.Username, extractClientIP(r.RemoteAddr), "feishu_test", "webhook", "PASS", nil)
		writeJSONResp(w, http.StatusOK, map[string]any{"ok": true})
		return
	}
	if _, err := alert.ValidateFeishuTarget(req.WebhookURL, s.cfg.DemoMode); err != nil {
		writeJSONResp(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	hostLabel := ""
	if len(s.cfg.PublicIPs) > 0 {
		hostLabel = s.cfg.PublicIPs[0]
	}
	card := alert.BuildTestFeishuCard(sess.Username, hostLabel, "", time.Now())
	if err := alert.DeliverFeishuCard(r.Context(), nil, req.WebhookURL, []byte(req.Secret), card); err != nil {
		writeJSONResp(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	_ = s.store.RecordAudit(sess.Username, extractClientIP(r.RemoteAddr), "feishu_test", "webhook", "PASS", nil)
	writeJSONResp(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleAuditLogs(w http.ResponseWriter, _ *http.Request, _ sessionEntry) {
	logs, err := s.store.QueryAuditLogs(150)
	if err != nil {
		writeJSONResp(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	if logs == nil {
		logs = []storage.AuditLog{}
	}
	writeJSONResp(w, http.StatusOK, map[string]any{"logs": logs})
}

func (s *Server) handleGetSecurity(w http.ResponseWriter, _ *http.Request, _ sessionEntry) {
	allowlist, expiresAt, retentionDays := s.getSecuritySettings()
	if allowlist == nil {
		allowlist = []string{}
	}
	writeJSONResp(w, http.StatusOK, map[string]any{
		"allowlist":      allowlist,
		"expires_at_ms":  expiresAt,
		"retention_days": retentionDays,
	})
}

func (s *Server) handlePutSecurity(w http.ResponseWriter, r *http.Request, sess sessionEntry) {
	var req struct {
		Allowlist     []string `json:"allowlist"`
		ExpiresAtMs   int64    `json:"expires_at_ms"`
		RetentionDays int      `json:"retention_days"`
	}
	if err := decodeJSONBody(r, &req); err != nil {
		writeJSONResp(w, http.StatusBadRequest, map[string]any{"error": "Invalid JSON."})
		return
	}
	rawAL, _ := json.Marshal(req.Allowlist)
	_ = s.store.SetKV("web_allowlist", string(rawAL))
	_ = s.store.SetKV("web_expires_at", strconv.FormatInt(req.ExpiresAtMs, 10))
	if req.RetentionDays >= 1 && req.RetentionDays <= 90 {
		_ = s.store.SetKV("retention_days", strconv.Itoa(req.RetentionDays))
	}
	_ = s.store.RecordAudit(sess.Username, extractClientIP(r.RemoteAddr), "update_security_settings", "web", "PASS", req)
	writeJSONResp(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleSignoffChecklist(w http.ResponseWriter, _ *http.Request, sess sessionEntry) {
	foState, _ := failover.LoadState(s.cfg.FailoverStateFile)
	md := fmt.Sprintf(`# VPN 网关赛前上线核对单

- 生成时间 (UTC): %s
- 操作人: %s
- 网关角色: %s | 当前路由路径: %s | 切换状态: %s

## 1. 主机环境与安全基线
- [ ] 已在授权主机上配置 /etc/ipsecvpn/host-authorized
- [ ] 内核已开启 net.ipv4.ip_forward=1 且 rp_filter=2
- [ ] 各站点预共享密钥已按 0600 权限独立写入 /etc/ipsecvpn/secrets
- [ ] 控制台已配置来源 IP 白名单、强密码或两步验证，以及停用时间

## 2. 隧道连通与隔离验证
- [ ] 已核验授权站点间双向 UDP / TCP 连通性、延迟及源 IP 保留
- [ ] 已核验非授权站点间互访被本端防火墙拦截
- [ ] 已核验监控页面公网探针、隧道状态、带宽及内网探针数据正常

## 3. 主备切换与回切演练
- [ ] 已确认本端网关主备角色与对端路由优先级一致
- [ ] 已完成主路故障切备演练，确认备路锁定且飞书告警送达
- [ ] 已完成主路恢复后的观察期校验与人工确认回切演练

## 签收确认
- 网关运维 / 日期: _______________
- 场馆网络 / 日期: _______________
- 备线负责 / 日期: _______________
`, time.Now().UTC().Format(time.RFC3339), sess.Username, foState.HubRole, foState.ActivePath, foState.Mode)
	writeJSONResp(w, http.StatusOK, map[string]any{"filename": "vpn-gateway-signoff-checklist.md", "content": md})
}

type hostIfaceInfo struct {
	Name string `json:"name"`
	IP   string `json:"ip"`
}

func detectDefaultRouteIface() string {
	raw, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] == "00000000" {
			return fields[0]
		}
	}
	return ""
}

func (s *Server) handleHostNetwork(w http.ResponseWriter, _ *http.Request, _ sessionEntry) {
	defIface := detectDefaultRouteIface()
	var ifaces []hostIfaceInfo
	defIP := ""
	if list, err := net.Interfaces(); err == nil {
		for _, nic := range list {
			if nic.Flags&net.FlagUp == 0 || nic.Flags&net.FlagLoopback != 0 {
				continue
			}
			if strings.HasPrefix(nic.Name, "ivp") || strings.HasPrefix(nic.Name, "docker") || strings.HasPrefix(nic.Name, "br-") {
				continue
			}
			addrs, err := nic.Addrs()
			if err != nil {
				continue
			}
			for _, a := range addrs {
				ipn, ok := a.(*net.IPNet)
				if !ok || ipn.IP == nil {
					continue
				}
				ip4 := ipn.IP.To4()
				if ip4 == nil || ip4.IsLoopback() || ip4.IsLinkLocalUnicast() {
					continue
				}
				ipStr := ip4.String()
				ifaces = append(ifaces, hostIfaceInfo{Name: nic.Name, IP: ipStr})
				if nic.Name == defIface && defIP == "" {
					defIP = ipStr
				}
				break
			}
		}
	}
	if defIface == "" && len(ifaces) > 0 {
		defIface = ifaces[0].Name
	}
	if defIP == "" && len(ifaces) > 0 {
		defIP = ifaces[0].IP
	}
	pubIP := defIP
	for _, p := range s.cfg.PublicIPs {
		if ip := net.ParseIP(strings.TrimSpace(p)); ip != nil && ip.To4() != nil {
			pubIP = ip.To4().String()
			break
		}
	}
	if ifaces == nil {
		ifaces = []hostIfaceInfo{}
	}
	writeJSONResp(w, http.StatusOK, map[string]any{
		"public_ip":         pubIP,
		"default_interface": defIface,
		"default_ip":        defIP,
		"interfaces":        ifaces,
	})
}

func (s *Server) handlePrometheusMetrics(w http.ResponseWriter, r *http.Request) {
	// Loopback scrape is permitted without cookie; non-loopback requires authenticated session.
	if !strings.HasPrefix(r.RemoteAddr, "127.0.0.1:") && !strings.HasPrefix(r.RemoteAddr, "[::1]:") {
		if _, ok := s.currentSession(r); !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}
	now := time.Now().UnixMilli()
	samples, _ := s.store.QueryMetricSamples("", now-5*60_000, now+1000, 300)
	latest := make(map[string]storage.MetricSample)
	for _, sm := range samples {
		latest[sm.SiteID] = sm
	}
	list := make([]storage.MetricSample, 0, len(latest))
	for _, sm := range latest {
		list = append(list, sm)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].SiteID < list[j].SiteID })
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	_, _ = w.Write([]byte(telemetry.RenderPrometheusMetrics(len(list) > 0, "READY", list)))
}

func (s *Server) spaHandler() http.Handler {
	if s.cfg.StaticFS == nil {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = w.Write([]byte("event-ipsec-hub V4 Web API running (frontend dist not embedded).\n"))
		})
	}
	fileServer := http.FileServer(http.FS(s.cfg.StaticFS))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clean := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if clean == "" {
			clean = "index.html"
		}
		if f, err := s.cfg.StaticFS.Open(clean); err == nil {
			_ = f.Close()
			fileServer.ServeHTTP(w, r)
			return
		}
		// SPA fallback to index.html
		idx, err := fs.ReadFile(s.cfg.StaticFS, "index.html")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(idx)
	})
}

func decodeJSONBody(r *http.Request, dst any) error {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1024*1024))
	if err != nil {
		return err
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return nil
	}
	return json.Unmarshal(raw, dst)
}

func writeJSONResp(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(payload)
}
