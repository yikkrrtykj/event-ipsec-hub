package storage

import (
	"path/filepath"
	"testing"
)

func TestStoreLifecycleMetricsEventsAndRetention(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "gateway.db")
	st, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()

	// Seeded alert rules present
	rules, err := st.ListAlertRules()
	if err != nil || len(rules) < 5 {
		t.Fatalf("expected seeded alert rules, got len=%d err=%v", len(rules), err)
	}

	// Profile save + revision + activate
	if err := st.SaveProfile(ProfileRecord{
		ID:          "esports-spring",
		Name:        "Spring Finals",
		YAMLContent: "schema_version: '2.0'\n",
		SHA256:      "abc123",
		HubRole:     "primary",
	}, "ops-lead", "initial import"); err != nil {
		t.Fatalf("SaveProfile: %v", err)
	}
	if err := st.SetActiveProfile("esports-spring"); err != nil {
		t.Fatalf("SetActiveProfile: %v", err)
	}
	p, err := st.GetProfile("esports-spring")
	if err != nil || p == nil || !p.Active {
		t.Fatalf("expected active profile, got %+v err=%v", p, err)
	}
	revs, err := st.ListRevisions("esports-spring", 10)
	if err != nil || len(revs) != 1 || revs[0].Operator != "ops-lead" {
		t.Fatalf("unexpected revisions: %+v err=%v", revs, err)
	}

	// Synchronized metrics + timeline events + retention pruning
	if err := st.InsertMetricSample(MetricSample{
		TsMs: 1000, SiteID: "ob-venue-1", L1OuterState: 1, L1OuterRTTMs: 28.5,
		L2IKEState: 1, L2ChildState: 1, L4UDPState: 1, L4UDPRTTMs: 31.2,
		RootCause: "VPN_HEALTHY_APP_SUSPECT",
	}); err != nil {
		t.Fatalf("InsertMetricSample 1: %v", err)
	}
	if err := st.InsertMetricSample(MetricSample{
		TsMs: 5000, SiteID: "ob-venue-1", L1OuterState: 0, L1OuterLoss: 1.0,
		L2IKEState: 0, L2ChildState: 0, L4UDPState: 0, L4UDPLoss: 1.0,
		RootCause: "ISP_OUTER_DEGRADED",
	}); err != nil {
		t.Fatalf("InsertMetricSample 2: %v", err)
	}
	if err := st.InsertTimelineEvent(TimelineEvent{
		TsMs: 4950, Layer: "L2_IPSEC", Category: "IKE_DOWN", Severity: "critical",
		SiteID: "ob-venue-1", Title: "IKE SA down after DPD timeout",
	}); err != nil {
		t.Fatalf("InsertTimelineEvent: %v", err)
	}

	samples, err := st.QueryMetricSamples("ob-venue-1", 0, 10000, 100)
	if err != nil || len(samples) != 2 || samples[1].RootCause != "ISP_OUTER_DEGRADED" {
		t.Fatalf("unexpected metric samples: %+v err=%v", samples, err)
	}
	events, err := st.QueryTimelineEvents("ob-venue-1", 0, 10000, 100)
	if err != nil || len(events) != 1 || events[0].Category != "IKE_DOWN" {
		t.Fatalf("unexpected timeline events: %+v err=%v", events, err)
	}

	deleted, err := st.PruneOlderThan(2000)
	if err != nil || deleted != 1 {
		t.Fatalf("expected 1 old metric pruned, got %d err=%v", deleted, err)
	}

	// Audit + KV + User
	if err := st.RecordAudit("ops-lead", "203.0.113.5", "export_psk_plaintext", "ob-venue-1", "PASS", map[string]any{"format": "tencent-json"}); err != nil {
		t.Fatalf("RecordAudit: %v", err)
	}
	logs, err := st.QueryAuditLogs(10)
	if err != nil || len(logs) != 1 || logs[0].Action != "export_psk_plaintext" {
		t.Fatalf("unexpected audit logs: %+v err=%v", logs, err)
	}
	if err := st.SetKV("retention_days", "14"); err != nil {
		t.Fatalf("SetKV: %v", err)
	}
	if v, ok, err := st.GetKV("retention_days"); err != nil || !ok || v != "14" {
		t.Fatalf("unexpected GetKV: v=%q ok=%v err=%v", v, ok, err)
	}
}
