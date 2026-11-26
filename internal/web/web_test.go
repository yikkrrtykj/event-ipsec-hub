package web

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yikkrrtykj/event-ipsec-hub/internal/storage"
)

type fakeAgent struct {
	psk string
}

func (f *fakeAgent) Call(_ context.Context, method string, _ any, out any) error {
	switch method {
	case "agent.ping":
		b, _ := json.Marshal(map[string]any{"status": "PASS"})
		return json.Unmarshal(b, out)
	case "secret.read_for_export":
		b, _ := json.Marshal(map[string]any{"psk": f.psk})
		return json.Unmarshal(b, out)
	default:
		b, _ := json.Marshal(map[string]any{"status": "PASS"})
		return json.Unmarshal(b, out)
	}
}

func TestSecurityPrimitivesTLSAuthTOTPAndAllowlist(t *testing.T) {
	dir := t.TempDir()
	cert, err := EnsureTLSKeypair(filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"), []string{"198.51.100.10"})
	if err != nil || len(cert.Certificate) == 0 {
		t.Fatalf("EnsureTLSKeypair failed: %v", err)
	}

	hash, err := HashPassword("StrongPass#2026")
	if err != nil || !VerifyPassword(hash, "StrongPass#2026") || VerifyPassword(hash, "wrong") {
		t.Fatalf("password hash/verify failed: err=%v", err)
	}

	sec := GenerateTOTPSecret()
	now := time.Now()
	code, err := computeTOTP(sec, uint64(now.Unix()/30))
	if err != nil || !VerifyTOTP(sec, code, now) || VerifyTOTP(sec, "000000", now) {
		t.Fatalf("TOTP failed: code=%s err=%v", code, err)
	}

	g := NewBruteForceGuard(3, time.Minute, time.Minute)
	if g.RecordFailure("203.0.113.5", now) || g.RecordFailure("203.0.113.5", now) {
		t.Fatal("should not ban before 3 failures")
	}
	if !g.RecordFailure("203.0.113.5", now) || !g.IsBanned("203.0.113.5", now) {
		t.Fatal("expected IP ban on 3rd failure")
	}

	if !IsIPAllowed("203.0.113.5:5555", []string{"203.0.113.0/24"}) {
		t.Fatal("expected CIDR match allowed")
	}
	if IsIPAllowed("198.51.100.9:5555", []string{"203.0.113.0/24"}) {
		t.Fatal("expected non-matching IP blocked")
	}
	if !IsIPAllowed("127.0.0.1:5555", []string{"203.0.113.0/24"}) {
		t.Fatal("loopback must always be allowed")
	}
}

func TestWebAPIEndToEndLoginProfileExportAndTimeline(t *testing.T) {
	dir := t.TempDir()
	st, err := storage.Open(filepath.Join(dir, "web.db"))
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	defer st.Close()

	srv := NewServer(Config{
		FailoverStateFile: filepath.Join(dir, "failover.json"),
		DemoMode:          true,
		InsecureHTTP:      true,
	}, st, &fakeAgent{psk: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"})

	adminPass, created, err := srv.BootstrapAdmin()
	if err != nil || !created || adminPass == "" {
		t.Fatalf("BootstrapAdmin: created=%v err=%v", created, err)
	}

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}

	// Unauthenticated call rejected
	resp, err := client.Get(ts.URL + "/api/v1/overview")
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 before login, got %v err=%v", resp, err)
	}

	// Login
	postJSON := func(path string, body any) *http.Response {
		b, _ := json.Marshal(body)
		r, err := client.Post(ts.URL+path, "application/json", bytes.NewReader(b))
		if err != nil {
			t.Fatalf("POST %s: %v", path, err)
		}
		return r
	}
	resp = postJSON("/api/v1/auth/login", map[string]any{"username": "admin", "password": adminPass})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login failed: %d", resp.StatusCode)
	}

	// Save real example profile
	yamlBytes, err := os.ReadFile(filepath.Join("..", "..", "config", "esports-multi-ob-hillstone.example.yaml"))
	if err != nil {
		t.Fatalf("read example yaml: %v", err)
	}
	resp = postJSON("/api/v1/profiles", map[string]any{
		"yaml_content": string(yamlBytes),
		"hub_role":     "primary",
		"activate":     true,
		"note":         "test import",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("save profile failed: %d", resp.StatusCode)
	}

	// Export Tencent JSON (redacted + audited plaintext)
	resp = postJSON("/api/v1/profiles/esports-multi-ob-hillstone/export-peer", map[string]any{
		"site_id": "ob-venue-1",
		"format":  "tencent-json",
	})
	var exp1 map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&exp1)
	if resp.StatusCode != http.StatusOK || !strings.Contains(exp1["content"].(string), "<SEND_SEPARATELY>") {
		t.Fatalf("expected redacted tencent export, got %d %+v", resp.StatusCode, exp1)
	}

	resp = postJSON("/api/v1/profiles/esports-multi-ob-hillstone/export-peer", map[string]any{
		"site_id":          "ob-venue-1",
		"format":           "tencent-json",
		"include_psk":      true,
		"confirm_password": adminPass,
	})
	var exp2 map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&exp2)
	if resp.StatusCode != http.StatusOK || !strings.Contains(exp2["content"].(string), "0123456789abcdef") {
		t.Fatalf("expected audited plaintext PSK export, got %d %+v", resp.StatusCode, exp2)
	}

	// Seed demo 4-layer telemetry & query synced timeline
	resp = postJSON("/api/v1/diagnostics/seed-demo", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("seed-demo failed: %d", resp.StatusCode)
	}
	resp, _ = client.Get(ts.URL + "/api/v1/diagnostics/timeline?site=ob-venue-1&minutes=60")
	var tl map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&tl)
	if resp.StatusCode != http.StatusOK || len(tl["samples"].([]any)) < 50 {
		t.Fatalf("expected >=50 synced timeline samples, got %d %+v", resp.StatusCode, tl)
	}

	// Searchable paginated event log endpoint
	resp, _ = client.Get(ts.URL + "/api/v1/events?site=ob-venue-1&severity=critical&q=DPD&limit=10&offset=0")
	var evRes map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&evRes)
	if resp.StatusCode != http.StatusOK || int(evRes["total"].(float64)) != 1 {
		t.Fatalf("expected 1 filtered DPD critical event, got %d %+v", resp.StatusCode, evRes)
	}

	// Signoff checklist
	resp, _ = client.Get(ts.URL + "/api/v1/system/signoff")
	var so map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&so)
	if resp.StatusCode != http.StatusOK || !strings.Contains(so["content"].(string), "VPN 网关赛前上线核对单") {
		t.Fatalf("unexpected signoff checklist: %+v", so)
	}
}
