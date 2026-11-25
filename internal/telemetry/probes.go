package telemetry

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/strongswan/govici/vici"

	"github.com/yikkrrtykj/event-ipsec-hub/internal/host"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/sa"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/storage"
)

var (
	pingLossRE = regexp.MustCompile(`(\d+(?:\.\d+)?)%\s+packet loss`)
	pingRttRE  = regexp.MustCompile(`=\s*([\d.]+)/([\d.]+)/([\d.]+)(?:/([\d.]+))?\s*ms`)
)

// OuterProbeResult captures Layer 1 (WAN/ISP underlay) latency and loss.
type OuterProbeResult struct {
	Mode   string  `json:"mode"` // icmp | dpd_fallback | disabled
	State  int     `json:"state"`
	RTTMs  float64 `json:"rtt_ms"`
	Loss   float64 `json:"loss"`
	Target string  `json:"target,omitempty"`
}

// ParsePingOutput extracts loss ratio (0.0..1.0) and average RTT (ms) from Linux iputils ping output.
func ParsePingOutput(output string) (rttMs float64, loss float64, ok bool) {
	lm := pingLossRE.FindStringSubmatch(output)
	if lm == nil {
		return 0, 1.0, false
	}
	pct, err := strconv.ParseFloat(lm[1], 64)
	if err != nil {
		return 0, 1.0, false
	}
	loss = pct / 100.0
	if rm := pingRttRE.FindStringSubmatch(output); rm != nil {
		avg, _ := strconv.ParseFloat(rm[2], 64)
		rttMs = avg
	}
	return rttMs, loss, true
}

// ProbeOuter runs a bounded Layer 1 ICMP probe bound to sourceIP/interface.
// If disabled is true (e.g. remote firewall blocks WAN ICMP), returns dpd_fallback/UNKNOWN safely.
func ProbeOuter(ctx context.Context, target, sourceIP string, count int, disabled bool) OuterProbeResult {
	if disabled || target == "" {
		return OuterProbeResult{Mode: "dpd_fallback", State: StateUnknown, Target: target}
	}
	addr, err := netip.ParseAddr(target)
	if err != nil || !addr.Is4() {
		return OuterProbeResult{Mode: "disabled", State: StateUnknown}
	}
	if count < 1 || count > 5 {
		count = 3
	}
	if runtime.GOOS != "linux" {
		return OuterProbeResult{Mode: "disabled", State: StateUnknown, Target: addr.String()}
	}
	args := []string{"-n", "-q", "-c", strconv.Itoa(count), "-W", "1", "-i", "0.2"}
	if sourceIP != "" {
		if src, err := netip.ParseAddr(sourceIP); err == nil && src.Is4() {
			args = append(args, "-I", src.String())
		}
	}
	args = append(args, addr.String())

	cctx, cancel := context.WithTimeout(ctx, time.Duration(count+2)*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(cctx, "ping", args...).CombinedOutput()
	rttMs, loss, ok := ParsePingOutput(string(out))
	if !ok {
		return OuterProbeResult{Mode: "icmp", State: StateDown, Loss: 1.0, Target: addr.String()}
	}
	st := StateUp
	if loss >= 1.0 {
		st = StateDown
	}
	return OuterProbeResult{
		Mode:   "icmp",
		State:  st,
		RTTMs:  rttMs,
		Loss:   loss,
		Target: addr.String(),
	}
}

// ParseXFRMStat parses Linux `/proc/net/xfrm_stat` counters into a map.
func ParseXFRMStat(content string) map[string]uint64 {
	res := make(map[string]uint64)
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 {
			if v, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
				res[fields[0]] = v
			}
		}
	}
	return res
}

// ReadXFRMStat reads `/proc/net/xfrm_stat` on Linux; returns empty map on non-Linux.
func ReadXFRMStat() map[string]uint64 {
	raw, err := os.ReadFile("/proc/net/xfrm_stat")
	if err != nil {
		return map[string]uint64{}
	}
	return ParseXFRMStat(string(raw))
}

// XFRMErrorDelta sums positive increments across kernel XFRM error counters between two snapshots.
func XFRMErrorDelta(prev, cur map[string]uint64) uint64 {
	if len(prev) == 0 || len(cur) == 0 {
		return 0
	}
	var total uint64
	for k, cv := range cur {
		if !strings.HasPrefix(k, "Xfrm") {
			continue
		}
		if pv, ok := prev[k]; ok && cv > pv {
			total += cv - pv
		}
	}
	return total
}

// SumNFTDropCounters sums packet counters on drop rules inside the project's nftables JSON ruleset.
func SumNFTDropCounters(ownedNFT []map[string]any) uint64 {
	var total uint64
	for _, item := range ownedNFT {
		rule, ok := item["rule"].(map[string]any)
		if !ok {
			continue
		}
		exprs, _ := rule["expr"].([]any)
		isDrop := false
		var pkts uint64
		for _, e := range exprs {
			em, _ := e.(map[string]any)
			if _, ok := em["drop"]; ok {
				isDrop = true
			}
			if cnt, ok := em["counter"].(map[string]any); ok {
				if p, err := strconv.ParseUint(fmt.Sprint(cnt["packets"]), 10, 64); err == nil {
					pkts = p
				}
			}
		}
		if isDrop {
			total += pkts
		}
	}
	return total
}

// WatchVICIEvents subscribes to real-time strongSwan VICI events (ike-updown, child-updown,
// ike-rekey, child-rekey) and invokes onEvent with millisecond UTC TimelineEvent entries.
func WatchVICIEvents(ctx context.Context, pid int, connToSite map[string]string, onEvent func(storage.TimelineEvent)) error {
	sess, err := sa.OpenSession(pid, host.VICIPath)
	if err != nil {
		return err
	}
	defer sess.Close()

	evCh := make(chan vici.Event, 64)
	sess.NotifyEvents(evCh)
	defer sess.StopEvents(evCh)

	if err := sess.Subscribe("ike-updown", "child-updown", "ike-rekey", "child-rekey"); err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case ev, ok := <-evCh:
			if !ok {
				return nil
			}
			m := sa.MessageToMap(ev.Message)
			te := ConvertVICIEvent(ev.Name, m, connToSite, time.Now().UnixMilli())
			if onEvent != nil {
				onEvent(te)
			}
		}
	}
}

// ConvertVICIEvent normalizes a raw VICI event payload into a TimelineEvent for synced charts & alerts.
func ConvertVICIEvent(eventName string, payload map[string]any, connToSite map[string]string, tsMs int64) storage.TimelineEvent {
	up := fmt.Sprint(payload["up"]) == "yes"
	siteID := ""
	connName := ""
	for k := range payload {
		if k == "up" {
			continue
		}
		connName = k
		if mapped, ok := connToSite[k]; ok {
			siteID = mapped
		}
		break
	}
	category := strings.ToUpper(strings.ReplaceAll(eventName, "-", "_"))
	severity := "info"
	title := fmt.Sprintf("VICI %s (%s)", eventName, connName)
	switch eventName {
	case "ike-updown":
		if up {
			category = "IKE_UP"
			title = fmt.Sprintf("IKE SA established (%s)", connName)
		} else {
			category = "IKE_DOWN"
			severity = "critical"
			title = fmt.Sprintf("IKE SA down (%s)", connName)
		}
	case "child-updown":
		if up {
			category = "CHILD_UP"
			title = fmt.Sprintf("CHILD SA installed (%s)", connName)
		} else {
			category = "CHILD_DOWN"
			severity = "critical"
			title = fmt.Sprintf("CHILD SA down (%s)", connName)
		}
	case "ike-rekey":
		category = "IKE_REKEY"
		severity = "warning"
		title = fmt.Sprintf("IKE SA rekeyed (%s)", connName)
	case "child-rekey":
		category = "CHILD_REKEY"
		severity = "info"
		title = fmt.Sprintf("CHILD SA rekeyed (%s)", connName)
	}
	detailRaw, _ := json.Marshal(payload)
	return storage.TimelineEvent{
		TsMs:       tsMs,
		Layer:      "L2_IPSEC",
		Category:   category,
		Severity:   severity,
		SiteID:     siteID,
		LinkID:     connName,
		Source:     "self_hosted_hub",
		Title:      title,
		DetailJSON: string(detailRaw),
	}
}
