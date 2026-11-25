package alert

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yikkrrtykj/event-ipsec-hub/internal/storage"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/telemetry"
)

func TestFeishuValidationSigningAndRetryDelivery(t *testing.T) {
	if _, err := ValidateFeishuTarget("https://open.feishu.cn/open-apis/bot/v2/hook/abcdef0123456789abcdef01", false); err != nil {
		t.Fatalf("expected valid official feishu URL: %v", err)
	}
	if _, err := ValidateFeishuTarget("https://evil.example/hook/12345678901234567890", false); err == nil {
		t.Fatal("expected non-official feishu URL rejected")
	}

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["sign"] == "" || body["msg_type"] != "text" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"code":0,"msg":"success"}`))
	}))
	defer srv.Close()

	if err := DeliverFeishu(context.Background(), srv.Client(), srv.URL, []byte("secret-signing-key-123456"), "hello alert"); err != nil {
		t.Fatalf("DeliverFeishu should succeed on retry: %v", err)
	}
	if calls.Load() != 2 {
		t.Fatalf("expected 2 attempts (1 retry), got %d", calls.Load())
	}
}

func TestAlertEngineDedupAntiFalseRecoveryAndSourceTagging(t *testing.T) {
	st, err := storage.Open(filepath.Join(t.TempDir(), "alerts.db"))
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	defer st.Close()

	var sent []storage.AlertHistoryRecord
	eng := NewEngine(st, SenderFunc(func(_ context.Context, rec storage.AlertHistoryRecord) error {
		sent = append(sent, rec)
		return nil
	}), "self_hosted_hub")

	rules := []storage.AlertRule{
		{ID: "child_down", Name: "IpsecChildDown", Enabled: true, Severity: "critical", Metric: "l2_child_state", Threshold: 1, CooldownSeconds: 60},
	}

	t0 := time.Unix(1_700_000_000, 0).UTC()
	downSample := storage.MetricSample{
		TsMs: t0.UnixMilli(), EventID: "spring-2026", HubID: "hub-hk", SiteID: "ob-venue-1",
		L1Mode: "icmp", L1OuterState: telemetry.StateUp, L2IKEState: telemetry.StateUp, L2ChildState: telemetry.StateDown, L4UDPState: telemetry.StateDown,
	}
	diagDown := telemetry.Diagnose(downSample, nil)

	// 1. First failure -> FIRING
	out1 := eng.Evaluate(context.Background(), rules, downSample, diagDown, t0)
	if len(out1) != 1 || out1[0].Status != "FIRING" || !strings.Contains(out1[0].Message, "self_hosted_hub") || out1[0].RootCause != telemetry.CauseIPsecSAEvent {
		t.Fatalf("expected FIRING with root cause and source tag, got %+v", out1)
	}

	// 2. Repeated failure -> deduplicated (no spam)
	out2 := eng.Evaluate(context.Background(), rules, downSample, diagDown, t0.Add(15*time.Second))
	if len(out2) != 0 {
		t.Fatalf("expected dedup silence, got %+v", out2)
	}

	// 3. Observation becomes UNKNOWN -> DATA_UNAVAILABLE (NEVER false RECOVERED!)
	unkSample := downSample
	unkSample.L2ChildState = telemetry.StateUnknown
	diagUnk := telemetry.Diagnose(unkSample, nil)
	out3 := eng.Evaluate(context.Background(), rules, unkSample, diagUnk, t0.Add(30*time.Second))
	if len(out3) != 1 || out3[0].Status != "DATA_UNAVAILABLE" {
		t.Fatalf("UNKNOWN must emit DATA_UNAVAILABLE, never RECOVERED: %+v", out3)
	}

	// 4. Verified healthy -> RECOVERED
	okSample := downSample
	okSample.L2ChildState = telemetry.StateUp
	okSample.L4UDPState = telemetry.StateUp
	diagOK := telemetry.Diagnose(okSample, nil)
	out4 := eng.Evaluate(context.Background(), rules, okSample, diagOK, t0.Add(90*time.Second))
	if len(out4) != 1 || out4[0].Status != "RECOVERED" {
		t.Fatalf("expected RECOVERED after verified healthy, got %+v", out4)
	}

	hist, err := st.QueryAlertHistory(10)
	if err != nil || len(hist) != 3 {
		t.Fatalf("expected 3 persisted alert records, got %d err=%v", len(hist), err)
	}
}
