package telemetry

import (
	"fmt"
	"strings"

	"github.com/yikkrrtykj/event-ipsec-hub/internal/storage"
)

const (
	StateUnknown = -1
	StateDown    = 0
	StateUp      = 1
)

// Deterministic root-cause classification codes for the 4-layer synchronized timeline.
const (
	CauseISPOuterDegraded          = "ISP_OUTER_DEGRADED"
	CauseIPsecSAEvent              = "IPSEC_SA_EVENT"
	CauseTunnelBlackholeAsymmetric = "TUNNEL_BLACKHOLE_OR_ASYMMETRIC"
	CauseXFRMCryptoOrMTUDrop       = "XFRM_CRYPTO_OR_MTU_DROP"
	CauseACLPolicyDrop             = "ACL_POLICY_DROP"
	CauseVPNHealthyAppSuspect      = "VPN_HEALTHY_APP_SUSPECT"
	CauseObservationUnverified     = "OBSERVATION_UNVERIFIED"
)

// DiagnosisResult explains why a site/tunnel degraded at a specific timestamp or window.
type DiagnosisResult struct {
	Code       string   `json:"code"`
	Severity   string   `json:"severity"` // ok | warning | critical | unknown
	SummaryZH  string   `json:"summary_zh"`
	SummaryEN  string   `json:"summary_en"`
	Evidence   []string `json:"evidence"`
	LayerFault string   `json:"layer_fault"` // L1_OUTER | L2_IPSEC | L3_KERNEL | L4_UDP | NONE | UNKNOWN
}

// SyncedTimelineResponse is the aligned payload served to the Vue 3 ECharts synced view.
type SyncedTimelineResponse struct {
	SiteID     string                  `json:"site_id"`
	FromMs     int64                   `json:"from_ms"`
	ToMs       int64                   `json:"to_ms"`
	Samples    []storage.MetricSample  `json:"samples"`
	Events     []storage.TimelineEvent `json:"events"`
	Diagnosis  DiagnosisResult         `json:"diagnosis"`
}

// Diagnose runs the deterministic fault-tree classifier on a 4-layer sample + nearby events.
func Diagnose(sample storage.MetricSample, recentEvents []storage.TimelineEvent) DiagnosisResult {
	var evidence []string

	// 0. Unverified observation check (never claim healthy when collector/L2 is unknown)
	if sample.L2IKEState == StateUnknown || sample.L2ChildState == StateUnknown {
		return DiagnosisResult{
			Code:       CauseObservationUnverified,
			Severity:   "unknown",
			SummaryZH:  "暂无完整观测数据，当前状态为未检测，请检查本地采集服务与 strongSwan 状态。",
			SummaryEN:  "Observation is incomplete (UNKNOWN); refusing to report healthy or recovered.",
			Evidence:   []string{"l2_ike_or_child_state=UNKNOWN"},
			LayerFault: "UNKNOWN",
		}
	}

	// Collect relevant L2 control-plane events near this timestamp (±60s)
	var l2FaultEvents []string
	for _, ev := range recentEvents {
		if ev.SiteID != "" && sample.SiteID != "" && ev.SiteID != sample.SiteID {
			continue
		}
		delta := sample.TsMs - ev.TsMs
		if delta < -15_000 || delta > 60_000 {
			continue
		}
		if ev.Layer == "L2_IPSEC" && isSAFaultCategory(ev.Category) {
			l2FaultEvents = append(l2FaultEvents, fmt.Sprintf("%s(%s)", ev.Category, ev.Title))
		}
	}

	outerDegraded := sample.L1Mode == "icmp" && (sample.L1OuterState == StateDown || sample.L1OuterLoss >= 0.05)
	saDown := sample.L2IKEState == StateDown || sample.L2ChildState == StateDown
	udpDegraded := sample.L4UDPState == StateDown || (sample.L4UDPState == StateUp && sample.L4UDPLoss >= 0.05)

	// 1. Layer 1: Outer WAN / ISP degradation takes root precedence when outer ICMP is failing.
	if outerDegraded {
		evidence = append(evidence, fmt.Sprintf("L1 outer state=%d loss=%.1f%% rtt=%.1fms", sample.L1OuterState, sample.L1OuterLoss*100, sample.L1OuterRTTMs))
		if saDown {
			evidence = append(evidence, "L2 IPsec SA simultaneously down")
		}
		if udpDegraded {
			evidence = append(evidence, fmt.Sprintf("L4 UDP probe loss=%.1f%%", sample.L4UDPLoss*100))
		}
		sev := "warning"
		if sample.L1OuterState == StateDown || saDown || sample.L4UDPState == StateDown {
			sev = "critical"
		}
		return DiagnosisResult{
			Code:       CauseISPOuterDegraded,
			Severity:   sev,
			SummaryZH:  "公网外层线路丢包或中断，建议优先排查本端或对端运营商线路。",
			SummaryEN:  "Outer WAN/ISP path is degraded or down; investigate ISP/public underlay first.",
			Evidence:   evidence,
			LayerFault: "L1_OUTER",
		}
	}

	// 2. Layer 2: Outer is healthy (or disabled), but IKE/CHILD SA is down or had recent SA fault/rekey storm.
	if saDown || len(l2FaultEvents) > 0 || sample.L2Rekeys10m >= 3 {
		if sample.L1Mode == "icmp" {
			evidence = append(evidence, fmt.Sprintf("L1 outer healthy (loss=%.1f%% rtt=%.1fms)", sample.L1OuterLoss*100, sample.L1OuterRTTMs))
		} else {
			evidence = append(evidence, "L1 outer probe mode="+sample.L1Mode)
		}
		if saDown {
			evidence = append(evidence, fmt.Sprintf("L2 IKE=%d CHILD=%d", sample.L2IKEState, sample.L2ChildState))
		}
		if sample.L2Rekeys10m >= 3 {
			evidence = append(evidence, fmt.Sprintf("L2 frequent rekeys=%d in 10m", sample.L2Rekeys10m))
		}
		evidence = append(evidence, l2FaultEvents...)
		sev := "warning"
		if saDown {
			sev = "critical"
		}
		return DiagnosisResult{
			Code:       CauseIPsecSAEvent,
			Severity:   sev,
			SummaryZH:  "公网线路正常，IPsec 隧道断开或频繁重协商，请检查双端协商参数与对端网关日志。",
			SummaryEN:  "Outer WAN is clean, but IPsec control plane shows SA down/rekey/negotiation fault.",
			Evidence:   evidence,
			LayerFault: "L2_IPSEC",
		}
	}

	// 3. Layer 3a: Kernel XFRM crypto/replay/MTU error spikes while SA is UP.
	if sample.L3XFRMErrDelta > 0 {
		evidence = append(evidence,
			"L2 IKE=UP CHILD=UP",
			fmt.Sprintf("L3 /proc/net/xfrm_stat error delta=+%d", sample.L3XFRMErrDelta),
		)
		if udpDegraded {
			evidence = append(evidence, fmt.Sprintf("L4 UDP probe loss=%.1f%%", sample.L4UDPLoss*100))
		}
		return DiagnosisResult{
			Code:       CauseXFRMCryptoOrMTUDrop,
			Severity:   "warning",
			SummaryZH:  "隧道在线但内核 XFRM 错误计数上升，请排查 SA 同步状态、Replay 窗口及通道 MTU。",
			SummaryEN:  "Tunnel is UP, but kernel XFRM error counters increased (crypto/replay/MTU drop).",
			Evidence:   evidence,
			LayerFault: "L3_KERNEL",
		}
	}

	// 4. Layer 3b: Project nftables forward ACL drop spike while tunnel is UP.
	if sample.L3NFTDropDelta > 0 && (udpDegraded || sample.L4UDPState == StateUnknown) {
		evidence = append(evidence,
			"L2 IKE=UP CHILD=UP",
			fmt.Sprintf("L3 nftables ipsecvpn drop delta=+%d", sample.L3NFTDropDelta),
		)
		return DiagnosisResult{
			Code:       CauseACLPolicyDrop,
			Severity:   "warning",
			SummaryZH:  "流量被转发安全策略拦截，请核对允许互通网段、站点隔离策略及源地址透传。",
			SummaryEN:  "Traffic dropped by Hub nftables authorization policy (unauthorized CIDR, OB isolation, or altered source IP).",
			Evidence:   evidence,
			LayerFault: "L3_KERNEL",
		}
	}

	// 5. Layer 4: Outer & SA & XFRM clean, yet cross-tunnel UDP probe fails/loses packets.
	if udpDegraded {
		evidence = append(evidence,
			"L2 IKE=UP CHILD=UP",
			fmt.Sprintf("L4 cross-tunnel UDP state=%d loss=%.1f%% rtt=%.1fms", sample.L4UDPState, sample.L4UDPLoss*100, sample.L4UDPRTTMs),
		)
		if sample.L3TxBps > 0 && sample.L3RxBps == 0 {
			evidence = append(evidence, fmt.Sprintf("L3 asymmetric traffic: tx=%.0fbps rx=0bps", sample.L3TxBps))
		}
		sev := "warning"
		if sample.L4UDPState == StateDown {
			sev = "critical"
		}
		return DiagnosisResult{
			Code:       CauseTunnelBlackholeAsymmetric,
			Severity:   sev,
			SummaryZH:  "公网与隧道状态正常，但内网业务探测不通，请检查对端静态路由、回程路由及 NAT 豁免。",
			SummaryEN:  "Outer WAN and IPsec SAs are UP, but end-to-end UDP failed (blackhole, asymmetric return route, or peer policy/NAT).",
			Evidence:   evidence,
			LayerFault: "L4_UDP",
		}
	}

	// 6. Tunnel UP, no errors, but L4 UDP probe is not configured/not fresh -> distinguish from fully verified business!
	if sample.L4UDPState == StateUnknown {
		evidence = append(evidence, "L2 IKE=UP CHILD=UP", "L3 no XFRM/ACL errors", "L4 UDP probe=UNKNOWN (not enabled or stale)")
		return DiagnosisResult{
			Code:       CauseObservationUnverified,
			Severity:   "unknown",
			SummaryZH:  "隧道在线，但未获取到最新内网 UDP 探测数据，业务连通性为未检测。",
			SummaryEN:  "Control plane is UP, but fresh end-to-end UDP probe evidence is unavailable (UNKNOWN).",
			Evidence:   evidence,
			LayerFault: "UNKNOWN",
		}
	}

	// 7. All 4 layers verified healthy!
	evidence = append(evidence,
		"L2 IKE=UP CHILD=UP",
		"L3 XFRM/ACL error delta=0",
		fmt.Sprintf("L4 UDP healthy rtt=%.1fms p95=%.1fms loss=%.1f%%", sample.L4UDPRTTMs, sample.L4UDPP95Ms, sample.L4UDPLoss*100),
	)
	if sample.L1Mode == "icmp" {
		evidence = append(evidence, fmt.Sprintf("L1 outer healthy rtt=%.1fms loss=%.1f%%", sample.L1OuterRTTMs, sample.L1OuterLoss*100))
	}
	return DiagnosisResult{
		Code:       CauseVPNHealthyAppSuspect,
		Severity:   "ok",
		SummaryZH:  "VPN 通道各项指标正常；如业务仍有卡顿，请排查源端/目的端主机及本地局域网。",
		SummaryEN:  "All 4 VPN layers are healthy; if application lag persists, inspect game server, OB client, or local LAN.",
		Evidence:   evidence,
		LayerFault: "NONE",
	}
}

// SummarizeWindow evaluates the most severe fault across a selected time window (for interactive chart zoom/click).
func SummarizeWindow(samples []storage.MetricSample, events []storage.TimelineEvent) DiagnosisResult {
	if len(samples) == 0 {
		return DiagnosisResult{
			Code:       CauseObservationUnverified,
			Severity:   "unknown",
			SummaryZH:  "所选时间窗口内暂无监控采样数据。",
			SummaryEN:  "No telemetry samples available in the selected window.",
			LayerFault: "UNKNOWN",
		}
	}
	rank := map[string]int{
		"critical": 4,
		"warning":  3,
		"unknown":  2,
		"ok":       1,
	}
	best := Diagnose(samples[len(samples)-1], events)
	for _, s := range samples {
		d := Diagnose(s, events)
		if rank[d.Severity] > rank[best.Severity] {
			best = d
		}
	}
	return best
}

func isSAFaultCategory(cat string) bool {
	c := strings.ToUpper(cat)
	switch c {
	case "IKE_DOWN", "CHILD_DOWN", "DPD_TIMEOUT", "AUTH_FAILED", "TS_UNACCEPTABLE", "NO_PROPOSAL_CHOSEN", "CHILD_REKEY", "IKE_REKEY":
		return true
	default:
		return strings.Contains(c, "DOWN") || strings.Contains(c, "FAIL") || strings.Contains(c, "TIMEOUT")
	}
}
