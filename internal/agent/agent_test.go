package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yikkrrtykj/event-ipsec-hub/internal/host"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/manifest"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/rpc"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/storage"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/telemetry"
)

type fakeNFTHost struct {
	*host.OSHost
	drops uint64
}

func (f *fakeNFTHost) NFT() ([]map[string]any, error) {
	return []map[string]any{
		{
			"rule": map[string]any{
				"family": "ip",
				"table":  manifest.Table,
				"chain":  "forward",
				"expr": []any{
					map[string]any{"counter": map[string]any{"packets": f.drops, "bytes": f.drops * 100}},
					map[string]any{"drop": nil},
				},
			},
		},
		{
			// Foreign table drop must be ignored
			"rule": map[string]any{
				"family": "inet",
				"table":  "foreign_fw",
				"chain":  "forward",
				"expr": []any{
					map[string]any{"counter": map[string]any{"packets": uint64(999)}},
					map[string]any{"drop": nil},
				},
			},
		},
	}, nil
}

func TestAgentVICIEventNFTDeltaAndFeishuChannelPersistence(t *testing.T) {
	dir := t.TempDir()
	st, err := storage.Open(filepath.Join(dir, "agent.db"))
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	defer st.Close()

	var received atomic.Int32
	mockFeishu := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"msg":"success"}`))
	}))
	defer mockFeishu.Close()

	fh := &fakeNFTHost{OSHost: host.NewOSHost(), drops: 10}
	d := New(Config{
		AlertChannelFile: filepath.Join(dir, "feishu-channel.json"),
		AllowLoopback:    true,
	}, st, fh)

	// 1. VICI event ingestion + rekey tracking
	d.connToSite["ivp000000ca"] = "ob-venue-1"
	nowMs := time.Now().UnixMilli()
	d.OnVICIEvent(storage.TimelineEvent{
		TsMs: nowMs, Layer: "L2_IPSEC", Category: "IKE_REKEY", Severity: "warning",
		LinkID: "ivp000000ca", Source: "self_hosted_hub", Title: "IKE SA rekeyed (ivp000000ca)",
	})
	if cnt := d.countRecentRekeys("ob-venue-1", nowMs+1000); cnt != 1 {
		t.Fatalf("expected 1 recent rekey for ob-venue-1, got %d", cnt)
	}
	evs, total, err := st.SearchTimelineEvents(storage.EventSearchFilter{SiteID: "ob-venue-1"})
	if err != nil || total != 1 || evs[0].Category != "IKE_REKEY" {
		t.Fatalf("expected VICI event persisted, got total=%d err=%v evs=%+v", total, err, evs)
	}

	// 2. Owned nftables drop counter delta (baseline 0 on first read, then +7)
	if delta := d.ComputeNFTDropDelta(); delta != 0 {
		t.Fatalf("expected baseline delta 0, got %d", delta)
	}
	fh.drops = 17
	if delta := d.ComputeNFTDropDelta(); delta != 7 {
		t.Fatalf("expected delta 7, got %d", delta)
	}

	// 3. Save Feishu channel via RPC, test channel, and verify live alert delivery
	saveRaw, _ := json.Marshal(rpc.SaveAlertChannelParams{
		Enabled:    true,
		WebhookURL: mockFeishu.URL + "/hook",
		Secret:     "test-secret",
		Operator:   "admin",
	})
	res, err := d.HandleRPC(context.Background(), rpc.MethodSaveAlertChannel, saveRaw)
	if err != nil {
		t.Fatalf("MethodSaveAlertChannel failed: %v", err)
	}
	resMap := res.(map[string]any)
	if resMap["configured"] != true || resMap["has_secret"] != true {
		t.Fatalf("unexpected save channel response: %+v", resMap)
	}

	testRaw, _ := json.Marshal(rpc.TestAlertChannelParams{Operator: "admin"})
	if _, err := d.HandleRPC(context.Background(), rpc.MethodTestAlertChannel, testRaw); err != nil {
		t.Fatalf("MethodTestAlertChannel failed: %v", err)
	}
	if received.Load() != 1 {
		t.Fatalf("expected 1 test Feishu delivery, got %d", received.Load())
	}

	// Trigger a live firing alert via the daemon's reloaded alert engine
	rules, _ := st.ListAlertRules()
	sample := storage.MetricSample{
		TsMs: nowMs, EventID: "evt-1", HubID: "hub-1", SiteID: "ob-venue-1",
		L1Mode: "icmp", L1OuterState: telemetry.StateUp,
		L2IKEState: telemetry.StateDown, L2ChildState: telemetry.StateDown,
	}
	diag := telemetry.Diagnose(sample, nil)
	emitted := d.alertEng.Evaluate(context.Background(), rules, sample, diag, time.Now().UTC())
	if len(emitted) == 0 || !emitted[0].Delivered || received.Load() < 2 {
		t.Fatalf("expected live alert delivered via saved Feishu channel, emitted=%+v received=%d", emitted, received.Load())
	}
}
