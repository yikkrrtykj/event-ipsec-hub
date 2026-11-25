package telemetry

import (
	"bytes"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/yikkrrtykj/event-ipsec-hub/internal/storage"
)

func TestFaultTreeDiagnosesAllSevenRootCauses(t *testing.T) {
	base := storage.MetricSample{
		TsMs:         100_000,
		SiteID:       "ob-venue-1",
		L1Mode:       "icmp",
		L1OuterState: StateUp,
		L1OuterRTTMs: 25,
		L1OuterLoss:  0,
		L2IKEState:   StateUp,
		L2ChildState: StateUp,
		L4UDPState:   StateUp,
		L4UDPRTTMs:   28,
		L4UDPP95Ms:   30,
		L4UDPLoss:    0,
	}

	// 1. All healthy
	if d := Diagnose(base, nil); d.Code != CauseVPNHealthyAppSuspect || d.Severity != "ok" {
		t.Fatalf("expected healthy, got %+v", d)
	}

	// 2. Outer ISP degradation takes priority even when tunnel drops too
	sISP := base
	sISP.L1OuterState = StateDown
	sISP.L1OuterLoss = 1.0
	sISP.L2IKEState = StateDown
	sISP.L2ChildState = StateDown
	if d := Diagnose(sISP, nil); d.Code != CauseISPOuterDegraded || d.LayerFault != "L1_OUTER" {
		t.Fatalf("expected ISP_OUTER_DEGRADED, got %+v", d)
	}

	// 3. Outer healthy, IKE/CHILD down -> IPSEC_SA_EVENT
	sSA := base
	sSA.L2ChildState = StateDown
	ev := []storage.TimelineEvent{{TsMs: 99_000, Layer: "L2_IPSEC", Category: "CHILD_DOWN", SiteID: "ob-venue-1", Title: "CHILD SA deleted by peer"}}
	if d := Diagnose(sSA, ev); d.Code != CauseIPsecSAEvent || d.LayerFault != "L2_IPSEC" {
		t.Fatalf("expected IPSEC_SA_EVENT, got %+v", d)
	}

	// 4. Kernel XFRM error spike -> XFRM_CRYPTO_OR_MTU_DROP
	sXFRM := base
	sXFRM.L3XFRMErrDelta = 12
	if d := Diagnose(sXFRM, nil); d.Code != CauseXFRMCryptoOrMTUDrop || d.LayerFault != "L3_KERNEL" {
		t.Fatalf("expected XFRM_CRYPTO_OR_MTU_DROP, got %+v", d)
	}

	// 5. nftables drop spike + UDP down -> ACL_POLICY_DROP
	sACL := base
	sACL.L3NFTDropDelta = 5
	sACL.L4UDPState = StateDown
	if d := Diagnose(sACL, nil); d.Code != CauseACLPolicyDrop || d.LayerFault != "L3_KERNEL" {
		t.Fatalf("expected ACL_POLICY_DROP, got %+v", d)
	}

	// 6. Outer & SA & XFRM clean, UDP down -> TUNNEL_BLACKHOLE_OR_ASYMMETRIC
	sBH := base
	sBH.L3TxBps = 50000
	sBH.L3RxBps = 0
	sBH.L4UDPState = StateDown
	sBH.L4UDPLoss = 1.0
	if d := Diagnose(sBH, nil); d.Code != CauseTunnelBlackholeAsymmetric || d.LayerFault != "L4_UDP" {
		t.Fatalf("expected TUNNEL_BLACKHOLE_OR_ASYMMETRIC, got %+v", d)
	}

	// 7. Unknown L2 or missing UDP probe -> OBSERVATION_UNVERIFIED (never fake UP!)
	sUnk := base
	sUnk.L4UDPState = StateUnknown
	if d := Diagnose(sUnk, nil); d.Code != CauseObservationUnverified || d.Severity != "unknown" {
		t.Fatalf("expected OBSERVATION_UNVERIFIED, got %+v", d)
	}
}

func TestUDPFrameWireFormatAndRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	now := time.Now()
	frame := BuildUDPFrame(key, "q", "0123456789abcdef", 1, now.UnixMilli())
	if len(frame) != FrameBytes {
		t.Fatalf("expected %d bytes, got %d", FrameBytes, len(frame))
	}
	parsed, ok := ParseUDPFrame(frame, key, "q", now)
	if !ok || parsed.Seq != 1 || parsed.Nonce != "0123456789abcdef" {
		t.Fatalf("ParseUDPFrame failed: ok=%v parsed=%+v", ok, parsed)
	}

	// Replay & rate limit test
	resp := NewUDPResponder(key, "127.0.0.1:41000")
	if ans := resp.Answer("127.0.0.1:41000", frame, now); ans == nil {
		t.Fatal("first valid packet should be answered")
	}
	if ans := resp.Answer("127.0.0.1:41000", frame, now); ans != nil {
		t.Fatal("replayed packet must be dropped")
	}

	// Real loopback UDP round-trip
	probeConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("alloc probe port: %v", err)
	}
	probeAddr := probeConn.LocalAddr().String()
	_ = probeConn.Close()

	respConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("alloc resp port: %v", err)
	}
	respAddr := respConn.LocalAddr().String()
	_ = respConn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan struct{})
	go func() {
		_ = ServeUDPResponder(ctx, key, respAddr, probeAddr, func() { close(ready) })
	}()
	<-ready

	receipts, err := ProbeUDP(key, probeAddr, respAddr, 2, 500*time.Millisecond)
	if err != nil || len(receipts) != 2 {
		t.Fatalf("ProbeUDP failed: receipts=%+v err=%v", receipts, err)
	}
	if receipts[0].RTT == nil || receipts[1].RTT == nil {
		t.Fatalf("expected RTTs on loopback round-trip, got %+v", receipts)
	}
}

func TestParsersAndPrometheusMetrics(t *testing.T) {
	pingOut := "3 packets transmitted, 2 received, 33.3333% packet loss, time 402ms\nrtt min/avg/max/mdev = 24.100/26.500/29.200/1.500 ms\n"
	rtt, loss, ok := ParsePingOutput(pingOut)
	if !ok || rtt < 26 || rtt > 27 || loss < 0.33 || loss > 0.34 {
		t.Fatalf("unexpected ParsePingOutput: rtt=%f loss=%f ok=%v", rtt, loss, ok)
	}

	prev := ParseXFRMStat("XfrmInError 0\nXfrmInStateSeqError 2\n")
	cur := ParseXFRMStat("XfrmInError 3\nXfrmInStateSeqError 5\n")
	if delta := XFRMErrorDelta(prev, cur); delta != 6 {
		t.Fatalf("expected XFRM error delta 6, got %d", delta)
	}

	ev := ConvertVICIEvent("ike-updown", map[string]any{"up": "no", "ivp000000c9": map[string]any{}}, map[string]string{"ivp000000c9": "ob-venue-1"}, 12345)
	if ev.Category != "IKE_DOWN" || ev.SiteID != "ob-venue-1" || ev.Severity != "critical" {
		t.Fatalf("unexpected VICI event conversion: %+v", ev)
	}

	prom := RenderPrometheusMetrics(true, "READY", []storage.MetricSample{{
		TsMs: 1_700_000_000_000, EventID: "demo", HubID: "hub-1", SiteID: "ob-venue-1",
		L1OuterState: 1, L2IKEState: 1, L2ChildState: 1, L2Rekeys10m: 2, L4UDPState: 1,
		RootCause: CauseVPNHealthyAppSuspect,
	}})
	if !strings.Contains(prom, "event_ipsec_collector_healthy 1") ||
		!strings.Contains(prom, "event_ipsec_collector_last_success_timestamp_seconds") ||
		!strings.Contains(prom, "event_ipsec_site_rekeys_in_window") ||
		!strings.Contains(prom, `root_cause="VPN_HEALTHY_APP_SUSPECT"`) {
		t.Fatalf("unexpected prometheus output:\n%s", prom)
	}
}
