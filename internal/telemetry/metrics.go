package telemetry

import (
	"fmt"
	"strings"

	"github.com/yikkrrtykj/event-ipsec-hub/internal/storage"
)

const MetricPrefix = "event_ipsec_"

// RenderPrometheusMetrics renders backward-compatible V3 `event_ipsec_*` metrics
// plus V4 Layer 1/Layer 3/root-cause gauges for optional external Prometheus scraping.
func RenderPrometheusMetrics(collectorHealthy bool, reasonCode string, samples []storage.MetricSample) string {
	var b strings.Builder
	writeGauge := func(name, help string, rows [][2]string) {
		full := MetricPrefix + name
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s gauge\n", full, help, full)
		for _, r := range rows {
			if r[0] == "" {
				fmt.Fprintf(&b, "%s %s\n", full, r[1])
			} else {
				fmt.Fprintf(&b, "%s{%s} %s\n", full, r[0], r[1])
			}
		}
	}

	healthyInt := "0"
	if collectorHealthy {
		healthyInt = "1"
	}
	writeGauge("collector_healthy", "Whether the current ownership snapshot is valid.", [][2]string{{"", healthyInt}})
	if reasonCode == "" {
		reasonCode = "READY"
	}
	writeGauge("observation_reason", "Bounded current observation reason.", [][2]string{{fmt.Sprintf(`reason_code="%s"`, escLabel(reasonCode)), "1"}})

	var ikeRows, childRows, rekeyRows, outerStateRows, outerRTTRows, outerLossRows [][2]string
	var rxBytesRows, txBytesRows, xfrmErrRows, nftDropRows, udpStateRows, udpRTTRows, udpLossRows, causeRows [][2]string
	var lastSuccessMs int64
	for _, s := range samples {
		if s.TsMs > lastSuccessMs {
			lastSuccessMs = s.TsMs
		}
		base := fmt.Sprintf(`event_id="%s",hub_id="%s",site_id="%s"`, escLabel(s.EventID), escLabel(s.HubID), escLabel(s.SiteID))
		ikeRows = append(ikeRows, [2]string{base, fmt.Sprintf("%d", s.L2IKEState)})
		childRows = append(childRows, [2]string{base, fmt.Sprintf("%d", s.L2ChildState)})
		rekeyRows = append(rekeyRows, [2]string{base, fmt.Sprintf("%d", s.L2Rekeys10m)})
		outerStateRows = append(outerStateRows, [2]string{base, fmt.Sprintf("%d", s.L1OuterState)})
		outerRTTRows = append(outerRTTRows, [2]string{base, fmt.Sprintf("%.6f", s.L1OuterRTTMs/1000.0)})
		outerLossRows = append(outerLossRows, [2]string{base, fmt.Sprintf("%.4f", s.L1OuterLoss)})
		rxBytesRows = append(rxBytesRows, [2]string{base, fmt.Sprintf("%d", s.L3RxBytes)})
		txBytesRows = append(txBytesRows, [2]string{base, fmt.Sprintf("%d", s.L3TxBytes)})
		xfrmErrRows = append(xfrmErrRows, [2]string{base, fmt.Sprintf("%d", s.L3XFRMErrDelta)})
		nftDropRows = append(nftDropRows, [2]string{base, fmt.Sprintf("%d", s.L3NFTDropDelta)})
		udpStateRows = append(udpStateRows, [2]string{base, fmt.Sprintf("%d", s.L4UDPState)})
		udpRTTRows = append(udpRTTRows, [2]string{base, fmt.Sprintf("%.6f", s.L4UDPRTTMs/1000.0)})
		udpLossRows = append(udpLossRows, [2]string{base, fmt.Sprintf("%.4f", s.L4UDPLoss)})
		causeRows = append(causeRows, [2]string{fmt.Sprintf(`%s,root_cause="%s"`, base, escLabel(s.RootCause)), "1"})
	}

	if lastSuccessMs > 0 {
		writeGauge("collector_last_success_timestamp_seconds", "Unix timestamp of the latest valid telemetry sample.", [][2]string{{"", fmt.Sprintf("%.3f", float64(lastSuccessMs)/1000.0)}})
	}
	writeGauge("site_ike_state", "Verified IKE SA state, -1 unknown.", ikeRows)
	writeGauge("site_child_state", "Verified CHILD SA state, -1 unknown.", childRows)
	writeGauge("site_rekeys_in_window", "Observed SA generation changes in the last ten minutes.", rekeyRows)
	writeGauge("site_outer_state", "Layer 1 outer WAN reachability, -1 unknown.", outerStateRows)
	writeGauge("site_outer_rtt_seconds", "Layer 1 outer WAN RTT in seconds.", outerRTTRows)
	writeGauge("site_outer_loss_ratio", "Layer 1 outer WAN packet loss ratio.", outerLossRows)
	writeGauge("site_sa_rx_bytes", "Current CHILD SA RX bytes.", rxBytesRows)
	writeGauge("site_sa_tx_bytes", "Current CHILD SA TX bytes.", txBytesRows)
	writeGauge("site_xfrm_error_delta", "Kernel /proc/net/xfrm_stat error increment in last sample window.", xfrmErrRows)
	writeGauge("site_nft_drop_delta", "Project nftables drop increment in last sample window.", nftDropRows)
	writeGauge("path_state", "Layer 4 cross-tunnel UDP echo state, -1 unknown.", udpStateRows)
	writeGauge("path_rtt_seconds", "Layer 4 cross-tunnel UDP RTT in seconds.", udpRTTRows)
	writeGauge("path_probe_loss_ratio", "Layer 4 cross-tunnel UDP loss ratio.", udpLossRows)
	writeGauge("site_root_cause_info", "Deterministic 4-layer root cause classification.", causeRows)
	return b.String()
}

func escLabel(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, `"`, `\"`)
	return strings.ReplaceAll(v, "\n", `\n`)
}
