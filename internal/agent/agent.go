package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/yikkrrtykj/event-ipsec-hub/internal/alert"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/diagnostics"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/host"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/live"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/manifest"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/profile"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/rpc"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/secureio"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/storage"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/telemetry"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/transaction"
)

// Config controls the privileged root Hub Agent daemon.
type Config struct {
	SocketPath       string
	SocketGID        int
	DBPath           string
	AlertChannelFile string
	Interval         time.Duration
	RetentionDays    int
	AllowedUIDs      map[uint32]bool
	AllowLoopback    bool // test-only override for loopback mock Feishu server
}

// Daemon runs as root on Linux, owning strongSwan VICI, XFRM, nftables, secret files,
// 4-layer telemetry sampling, VICI event watching, built-in alerting, and the SO_PEERCRED RPC server.
type Daemon struct {
	cfg           Config
	store         *storage.Store
	host          host.Runner
	alertEng      *alert.Engine
	mu            sync.Mutex
	prevXFRM      map[string]uint64
	prevNFTDrops  uint64
	hasNFTBase    bool
	prevRxTx      map[string][3]uint64 // tsMs, rxBytes, txBytes
	rekeyTimes    map[string][]int64
	connToSite    map[string]string
	watcherPID    int
	watcherCancel context.CancelFunc
}

func New(cfg Config, store *storage.Store, h host.Runner) *Daemon {
	if cfg.SocketPath == "" {
		cfg.SocketPath = rpc.DefaultSocketPath
	}
	if cfg.AlertChannelFile == "" {
		cfg.AlertChannelFile = alert.DefaultAlertChannelFile
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 15 * time.Second
	}
	if cfg.RetentionDays <= 0 {
		cfg.RetentionDays = 14
	}
	if h == nil {
		h = host.NewOSHost()
	}
	d := &Daemon{
		cfg:        cfg,
		store:      store,
		host:       h,
		alertEng:   alert.NewEngine(store, nil, "self_hosted_hub"),
		prevXFRM:   make(map[string]uint64),
		prevRxTx:   make(map[string][3]uint64),
		rekeyTimes: make(map[string][]int64),
		connToSite: make(map[string]string),
	}
	d.reloadAlertSender()
	return d
}

func (d *Daemon) reloadAlertSender() {
	cfg, ok, err := alert.LoadFeishuChannel(d.cfg.AlertChannelFile)
	if err != nil || !ok {
		d.alertEng.SetSender(nil)
		return
	}
	d.alertEng.SetSender(alert.NewFeishuSender(cfg, nil))
}

// OnVICIEvent persists a real-time strongSwan VICI lifecycle event and tracks recent rekeys.
func (d *Daemon) OnVICIEvent(ev storage.TimelineEvent) {
	if ev.SiteID == "" && ev.LinkID != "" {
		d.mu.Lock()
		if s, ok := d.connToSite[ev.LinkID]; ok {
			ev.SiteID = s
		}
		d.mu.Unlock()
	}
	if ev.Category == "IKE_REKEY" || ev.Category == "CHILD_REKEY" {
		if ev.SiteID != "" {
			d.mu.Lock()
			d.rekeyTimes[ev.SiteID] = append(d.rekeyTimes[ev.SiteID], ev.TsMs)
			d.mu.Unlock()
		}
	}
	if d.store != nil {
		_ = d.store.InsertTimelineEvent(ev)
	}
}

func (d *Daemon) ensureVICIWatcher(ctx context.Context, pid int, m *manifest.DeploymentManifest) {
	if pid <= 0 || m == nil {
		return
	}
	mapping := make(map[string]string, len(m.Links))
	for _, l := range m.Links {
		mapping[l.Name()] = l.SiteID
	}
	d.mu.Lock()
	d.connToSite = mapping
	if d.watcherPID == pid {
		d.mu.Unlock()
		return
	}
	if d.watcherCancel != nil {
		d.watcherCancel()
	}
	watchCtx, cancel := context.WithCancel(ctx)
	d.watcherPID = pid
	d.watcherCancel = cancel
	d.mu.Unlock()

	go func(targetPID int, snapMap map[string]string) {
		_ = telemetry.WatchVICIEvents(watchCtx, targetPID, snapMap, d.OnVICIEvent)
		d.mu.Lock()
		if d.watcherPID == targetPID {
			d.watcherPID = 0
			d.watcherCancel = nil
		}
		d.mu.Unlock()
	}(pid, mapping)
}

// HandleRPC dispatches strictly typed privileged requests from the non-root Web process.
func (d *Daemon) HandleRPC(ctx context.Context, method string, raw json.RawMessage) (any, error) {
	switch method {
	case rpc.MethodPing:
		return map[string]any{"status": "PASS", "role": "hub-agent", "time_utc": time.Now().UTC().Format(time.RFC3339)}, nil

	case rpc.MethodCheckHost:
		return diagnostics.CheckHost(), nil

	case rpc.MethodStatus:
		return diagnostics.StatusReport(d.host), nil

	case rpc.MethodApplyProfile:
		var p rpc.ApplyParams
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, secureio.Stop("Invalid apply RPC parameters.")
		}
		parsed, err := profile.ParseProfile([]byte(p.YAMLContent))
		if err != nil {
			return nil, err
		}
		if err := secureio.MakeDirectory(transaction.ProfilesDir, 0o700); err != nil {
			return nil, err
		}
		cfgPath := filepath.Join(transaction.ProfilesDir, parsed.Event.ID+".yaml")
		if p.Confirmed {
			if err := secureio.AtomicWrite(cfgPath, []byte(p.YAMLContent), 0o600); err != nil {
				return nil, err
			}
		} else {
			if err := secureio.AtomicWrite(cfgPath+".dryrun.yaml", []byte(p.YAMLContent), 0o600); err != nil {
				return nil, err
			}
			cfgPath = cfgPath + ".dryrun.yaml"
			defer func() { _ = secureio.RemoveFile(cfgPath) }()
		}
		res, err := transaction.NewDeployment(d.host).Dispatch(transaction.DispatchOptions{
			Action:      "apply",
			Confirmed:   p.Confirmed,
			ConfigPath:  cfgPath,
			Maintenance: p.Maintenance,
		})
		if err == nil && p.Confirmed && d.store != nil {
			_ = d.store.InsertTimelineEvent(storage.TimelineEvent{
				TsMs:     time.Now().UnixMilli(),
				Layer:    "OPS",
				Category: "CONFIG_APPLY",
				Severity: "info",
				Source:   "web_console",
				Title:    fmt.Sprintf("Profile %s applied by %s", parsed.Event.ID, p.Operator),
			})
		}
		return res, err

	case rpc.MethodRollback:
		var p rpc.RollbackParams
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, secureio.Stop("Invalid rollback RPC parameters.")
		}
		return transaction.NewDeployment(d.host).Dispatch(transaction.DispatchOptions{
			Action:      "rollback",
			Confirmed:   p.Confirmed,
			BackupID:    p.BackupID,
			Maintenance: p.Maintenance,
		})

	case rpc.MethodReconnect:
		var p rpc.ReconnectParams
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, secureio.Stop("Invalid reconnect RPC parameters.")
		}
		return transaction.NewDeployment(d.host).Dispatch(transaction.DispatchOptions{
			Action:    "reconnect",
			Confirmed: true,
			Site:      p.Site,
		})

	case rpc.MethodRekey:
		var p rpc.RekeyParams
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, secureio.Stop("Invalid rekey RPC parameters.")
		}
		return transaction.NewDeployment(d.host).Dispatch(transaction.DispatchOptions{
			Action:    "rekey",
			Confirmed: true,
			Site:      p.Site,
			Kind:      p.Kind,
		})

	case rpc.MethodTunnelDiagnostics:
		var p rpc.TunnelDiagnosticsParams
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, secureio.Stop("Invalid tunnel diagnostics RPC parameters.")
		}
		return d.tunnelDiagnostics(ctx, strings.TrimSpace(p.Site)), nil

	case rpc.MethodWriteSecret:
		var p rpc.WriteSecretParams
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, secureio.Stop("Invalid secret write parameters.")
		}
		path, err := secureio.ValidateSecretRef(p.SecretRef)
		if err != nil {
			return nil, err
		}
		validKey, err := secureio.ValidatePSKBytes([]byte(p.PSKHex))
		if err != nil {
			return nil, err
		}
		if err := secureio.MakeDirectory(filepath.Dir(path), 0o700); err != nil {
			return nil, err
		}
		if err := secureio.AtomicWrite(path, append(validKey, '\n'), 0o600); err != nil {
			return nil, err
		}
		sha := manifest.Digest(validKey)
		if d.store != nil {
			_ = d.store.UpsertSecretMeta(storage.SecretMeta{Ref: p.SecretRef, SiteID: p.SiteID, SHA256: sha})
		}
		return map[string]any{"status": "PASS", "ref": p.SecretRef, "sha256": sha}, nil

	case rpc.MethodReadSecretAudit:
		var p rpc.ReadSecretAuditParams
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, secureio.Stop("Invalid audited secret read parameters.")
		}
		path, err := secureio.ValidateSecretRef(p.SecretRef)
		if err != nil {
			return nil, err
		}
		parentMode := uint32(0o700)
		data, err := secureio.ReadFile(path, 0o600, 65, &parentMode)
		if err != nil {
			return nil, secureio.Stop("The requested PSK file does not exist or is unsafe.")
		}
		key, err := secureio.ValidatePSKBytes(data)
		if err != nil {
			return nil, err
		}
		if d.store != nil {
			_ = d.store.RecordAudit(p.Operator, p.RemoteIP, "export_psk_plaintext", p.SiteID, "PASS", map[string]any{
				"secret_ref": p.SecretRef,
				"sha256":     manifest.Digest(key),
			})
		}
		return map[string]any{"psk": string(key)}, nil

	case rpc.MethodFailoverGate:
		var p rpc.FailoverGateParams
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, secureio.Stop("Invalid failover gate parameters.")
		}
		res, err := transaction.ApplyHubXFRMGate(p.Locked, d.host)
		if err == nil && d.store != nil {
			cat := "FAILOVER_GATE_UNLOCKED"
			if p.Locked {
				cat = "FAILOVER_GATE_LOCKED"
			}
			_ = d.store.InsertTimelineEvent(storage.TimelineEvent{
				TsMs:     time.Now().UnixMilli(),
				Layer:    "FAILOVER",
				Category: cat,
				Severity: "warning",
				Source:   "self_hosted_hub",
				Title:    fmt.Sprintf("XFRM gate %v by %s", res["gate"], p.Operator),
			})
		}
		return res, err

	case rpc.MethodSaveAlertChannel:
		var p rpc.SaveAlertChannelParams
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, secureio.Stop("Invalid alert channel parameters.")
		}
		existing, _, _ := alert.LoadFeishuChannel(d.cfg.AlertChannelFile)
		cfg := alert.FeishuChannelConfig{
			Enabled:    p.Enabled,
			WebhookURL: p.WebhookURL,
			Secret:     p.Secret,
		}
		if cfg.WebhookURL == "" && existing.WebhookURL != "" {
			cfg.WebhookURL = existing.WebhookURL
		}
		if p.KeepSecret && cfg.Secret == "" {
			cfg.Secret = existing.Secret
		}
		if err := alert.SaveFeishuChannel(d.cfg.AlertChannelFile, cfg, d.cfg.AllowLoopback); err != nil {
			return nil, err
		}
		d.reloadAlertSender()
		return map[string]any{
			"status":     "PASS",
			"configured": cfg.WebhookURL != "",
			"enabled":    cfg.Enabled,
			"masked_url": alert.MaskFeishuURL(cfg.WebhookURL),
			"has_secret": cfg.Secret != "",
		}, nil

	case rpc.MethodTestAlertChannel:
		var p rpc.TestAlertChannelParams
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, secureio.Stop("Invalid alert test parameters.")
		}
		targetURL := p.WebhookURL
		secret := p.Secret
		if targetURL == "" {
			existing, ok, err := alert.LoadFeishuChannel(d.cfg.AlertChannelFile)
			if err != nil || !ok || existing.WebhookURL == "" {
				return nil, secureio.Stop("Feishu channel is not configured.")
			}
			targetURL = existing.WebhookURL
			if secret == "" {
				secret = existing.Secret
			}
		}
		if _, err := alert.ValidateFeishuTarget(targetURL, d.cfg.AllowLoopback); err != nil {
			return nil, err
		}
		card := alert.BuildTestFeishuCard(p.Operator, "", "", time.Now())
		if err := alert.DeliverFeishuCard(ctx, nil, targetURL, []byte(secret), card); err != nil {
			return nil, err
		}
		return map[string]any{"status": "PASS", "masked_url": alert.MaskFeishuURL(targetURL)}, nil

	case rpc.MethodSyncAllowlist:
		var p rpc.SyncAllowlistParams
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, secureio.Stop("Invalid allowlist parameters.")
		}
		return map[string]any{"status": "PASS", "port": p.Port, "cidrs": p.CIDRs}, nil

	default:
		return nil, secureio.Stop("Unsupported RPC method: " + method)
	}
}

// ComputeNFTDropDelta inspects the owned nftables table and computes positive drop counter delta.
func (d *Daemon) ComputeNFTDropDelta() uint64 {
	if d.host == nil {
		return 0
	}
	items, err := d.host.NFT()
	if err != nil {
		return 0
	}
	var owned []map[string]any
	for _, it := range items {
		rule, ok := it["rule"].(map[string]any)
		if !ok {
			continue
		}
		if fmt.Sprint(rule["table"]) == manifest.Table && fmt.Sprint(rule["family"]) == "ip" {
			owned = append(owned, it)
		}
	}
	cur := telemetry.SumNFTDropCounters(owned)
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.hasNFTBase {
		d.prevNFTDrops = cur
		d.hasNFTBase = true
		return 0
	}
	var delta uint64
	if cur > d.prevNFTDrops {
		delta = cur - d.prevNFTDrops
	}
	d.prevNFTDrops = cur
	return delta
}

type activeProbeSpec struct {
	Protocol string
	Target   string
	Port     int
}

func extractPrimaryProbes(active *live.ActiveRecord) map[string]activeProbeSpec {
	out := make(map[string]activeProbeSpec)
	if active == nil || active.Profile == nil {
		return out
	}
	mon, ok := active.Profile["monitoring"].(map[string]any)
	if !ok {
		return out
	}
	if en, ok := mon["enabled"].(bool); ok && !en {
		return out
	}
	rawProbes, ok := mon["probes"].([]any)
	if !ok {
		return out
	}
	for _, item := range rawProbes {
		pm, ok := item.(map[string]any)
		if !ok {
			continue
		}
		path := fmt.Sprint(pm["path"])
		if path != "" && path != "primary" {
			continue
		}
		siteID := fmt.Sprint(pm["site_id"])
		target := fmt.Sprint(pm["target"])
		proto := fmt.Sprint(pm["protocol"])
		port := 0
		switch pv := pm["port"].(type) {
		case float64:
			port = int(pv)
		case int:
			port = pv
		case json.Number:
			if v, err := pv.Int64(); err == nil {
				port = int(v)
			}
		}
		if siteID != "" && target != "" && proto != "" {
			out[siteID] = activeProbeSpec{Protocol: proto, Target: target, Port: port}
		}
	}
	return out
}

// CollectOnce performs one 4-layer synchronized telemetry collection cycle and persists results.
func (d *Daemon) CollectOnce(ctx context.Context) error {
	if d.store == nil {
		return nil
	}
	inst, err := transaction.InstalledRecord()
	if err != nil {
		return nil // Not installed yet; skip quietly.
	}
	active, m, liveSnap, pid, err := diagnostics.InspectOwned(d.host, inst, false)
	if err != nil || m == nil || active == nil {
		return err
	}
	d.ensureVICIWatcher(ctx, pid, m)

	now := time.Now().UTC()
	nowMs := now.UnixMilli()

	curXFRM := telemetry.ReadXFRMStat()
	d.mu.Lock()
	xfrmDelta := telemetry.XFRMErrorDelta(d.prevXFRM, curXFRM)
	d.prevXFRM = curXFRM
	d.mu.Unlock()

	nftDelta := d.ComputeNFTDropDelta()
	if nftDelta > 0 {
		_ = d.store.InsertTimelineEvent(storage.TimelineEvent{
			TsMs:     nowMs,
			Layer:    "L3_XFRM",
			Category: "ACL_DROP",
			Severity: "warning",
			Source:   "self_hosted_hub",
			Title:    fmt.Sprintf("防火墙转发策略拦截增量 +%d 包", nftDelta),
		})
	}

	innerProbes := extractPrimaryProbes(active)
	rules, _ := d.store.ListAlertRules()
	recentEvents, _ := d.store.QueryTimelineEvents("", nowMs-60_000, nowMs+1000, 100)

	for _, l := range m.Links {
		ike := liveSnap.Get(l.Name())
		l2IKE := telemetry.StateDown
		l2Child := telemetry.StateDown
		var rxBytes, txBytes uint64
		if ike != nil {
			l2IKE = telemetry.StateUp
			if ike.Child != nil {
				l2Child = telemetry.StateUp
				rxBytes = ike.Child.Counts[0]
				txBytes = ike.Child.Counts[1]
			}
		}

		// Layer 1 outer WAN ICMP probe
		outer := telemetry.ProbeOuter(ctx, l.Peer, l.Source, 2, false)

		// Compute bps from previous sample
		var rxBps, txBps float64
		d.mu.Lock()
		if prev, ok := d.prevRxTx[l.Name()]; ok && nowMs > int64(prev[0]) {
			dt := float64(nowMs-int64(prev[0])) / 1000.0
			if rxBytes >= prev[1] {
				rxBps = float64(rxBytes-prev[1]) * 8.0 / dt
			}
			if txBytes >= prev[2] {
				txBps = float64(txBytes-prev[2]) * 8.0 / dt
			}
		}
		d.prevRxTx[l.Name()] = [3]uint64{uint64(nowMs), rxBytes, txBytes}
		rekeys := d.countRecentRekeys(l.SiteID, nowMs)
		d.mu.Unlock()

		// Layer 4 end-to-end inner probe (if configured for this site in active profile)
		l4Res := telemetry.InnerProbeResult{State: telemetry.StateUnknown}
		if ps, ok := innerProbes[l.SiteID]; ok {
			l4Res = telemetry.ProbeInner(ctx, ps.Protocol, ps.Target, ps.Port, "", "")
		}

		sample := storage.MetricSample{
			TsMs:           nowMs,
			EventID:        m.EventID,
			HubID:          extractHubID(active),
			SiteID:         l.SiteID,
			LinkID:         l.KeyID(),
			ISPLabel:       l.ISPLabel,
			L1OuterState:   outer.State,
			L1OuterRTTMs:   outer.RTTMs,
			L1OuterLoss:    outer.Loss,
			L1Mode:         outer.Mode,
			L2IKEState:     l2IKE,
			L2ChildState:   l2Child,
			L2Rekeys10m:    rekeys,
			L3RxBps:        rxBps,
			L3TxBps:        txBps,
			L3RxBytes:      rxBytes,
			L3TxBytes:      txBytes,
			L3XFRMErrDelta: xfrmDelta,
			L3NFTDropDelta: nftDelta,
			L4UDPState:     l4Res.State,
			L4UDPRTTMs:     l4Res.RTTMs,
			L4UDPP95Ms:     l4Res.P95Ms,
			L4UDPLoss:      l4Res.Loss,
		}
		diag := telemetry.Diagnose(sample, recentEvents)
		sample.RootCause = diag.Code
		sample.RootDetail = diag.SummaryZH
		_ = d.store.InsertMetricSample(sample)
		d.alertEng.Evaluate(ctx, rules, sample, diag, now)
	}
	return nil
}

func (d *Daemon) countRecentRekeys(siteID string, nowMs int64) int {
	cutoff := nowMs - 10*60_000
	list := d.rekeyTimes[siteID]
	keep := list[:0]
	for _, ts := range list {
		if ts >= cutoff {
			keep = append(keep, ts)
		}
	}
	d.rekeyTimes[siteID] = keep
	return len(keep)
}

func extractHubID(active *live.ActiveRecord) string {
	if active == nil || active.Profile == nil {
		return ""
	}
	if hub, ok := active.Profile["hub"].(map[string]any); ok {
		return fmt.Sprint(hub["id"])
	}
	return ""
}

var diagRedactHexRE = regexp.MustCompile(`\b[0-9a-fA-F]{64,}\b`)

func sanitizeDiagOutput(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	return diagRedactHexRE.ReplaceAllString(s, "<REDACTED>")
}

func (d *Daemon) tunnelDiagnostics(ctx context.Context, siteID string) map[string]any {
	res := map[string]any{
		"site_id":        siteID,
		"ike_state":      telemetry.StateUnknown,
		"child_state":    telemetry.StateUnknown,
		"captured_at_ms": time.Now().UnixMilli(),
	}

	linkName := ""
	if inst, err := transaction.InstalledRecord(); err == nil {
		if active, m, liveSnap, _, err := diagnostics.InspectOwned(d.host, inst, false); err == nil && m != nil && active != nil {
			for _, l := range m.Links {
				if l.SiteID == siteID {
					linkName = l.Name()
					res["link_name"] = linkName
					res["peer_ip"] = l.Peer
					res["local_id"] = l.LocalID
					res["remote_id"] = l.RemoteID
					res["selector_mode"] = l.SelectorMode
					res["ike_proposal"] = l.IKEProposal
					res["esp_proposal"] = l.ESPProposal
					res["local_ts"] = l.LocalTS
					res["remote_ts"] = l.RemoteTS

					ike := liveSnap.Get(linkName)
					if ike != nil {
						res["ike_state"] = telemetry.StateUp
						if ike.Child != nil {
							res["child_state"] = telemetry.StateUp
							res["rx_bytes"] = ike.Child.Counts[0]
							res["tx_bytes"] = ike.Child.Counts[1]
						} else {
							res["child_state"] = telemetry.StateDown
						}
					} else {
						res["ike_state"] = telemetry.StateDown
						res["child_state"] = telemetry.StateDown
					}
					break
				}
			}
		}
	}

	if runtime.GOOS == "linux" {
		sasArgs := []string{"--list-sas", "--uri", host.SocketURI}
		if linkName != "" {
			sasArgs = append(sasArgs, "--ike", linkName)
		}
		cctx, cancel := context.WithTimeout(ctx, 4*time.Second)
		out, err := exec.CommandContext(cctx, "swanctl", sasArgs...).CombinedOutput()
		cancel()
		sasText := sanitizeDiagOutput(string(out))
		if sasText == "" && linkName != "" {
			cctx2, cancel2 := context.WithTimeout(ctx, 4*time.Second)
			out2, _ := exec.CommandContext(cctx2, "swanctl", "--list-sas", "--uri", host.SocketURI).CombinedOutput()
			cancel2()
			sasText = sanitizeDiagOutput(string(out2))
		}
		if err != nil && sasText == "" {
			sasText = fmt.Sprintf("swanctl unavailable: %v", err)
		}
		if sasText == "" {
			sasText = "(当前暂无活动 SA；如果刚下发配置，请确认对端已配置并等待数秒，或查看下方 strongSwan 协商日志)"
		}
		res["swanctl_sas"] = sasText

		jctx, jcancel := context.WithTimeout(ctx, 4*time.Second)
		jout, jerr := exec.CommandContext(jctx, "journalctl", "-u", "strongswan", "-u", "strongswan-starter", "--no-pager", "-n", "45", "--output=short-iso").CombinedOutput()
		jcancel()
		logText := sanitizeDiagOutput(string(jout))
		if jerr != nil && logText == "" {
			logText = fmt.Sprintf("journalctl unavailable: %v", jerr)
		}
		res["strongswan_logs"] = logText
	} else {
		res["swanctl_sas"] = "(非 Linux 运行环境，未连接 strongSwan VICI)"
		res["strongswan_logs"] = "(非 Linux 运行环境，无 journalctl 协商日志)"
	}

	if d.store != nil {
		nowMs := time.Now().UnixMilli()
		if evs, err := d.store.QueryTimelineEvents(siteID, nowMs-24*60*60_000, nowMs+1000, 15); err == nil {
			res["recent_events"] = evs
		}
	}
	return res
}

// Serve runs the Unix Socket RPC server, periodic 4-layer collector, and retention pruner.
func (d *Daemon) Serve(ctx context.Context) error {
	srv := &rpc.Server{
		SocketPath:  d.cfg.SocketPath,
		SocketGID:   d.cfg.SocketGID,
		AllowedUIDs: d.cfg.AllowedUIDs,
		Handler:     d.HandleRPC,
	}

	go func() {
		ticker := time.NewTicker(d.cfg.Interval)
		pruneTicker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		defer pruneTicker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = d.CollectOnce(ctx)
			case <-pruneTicker.C:
				if d.store != nil {
					cutoff := time.Now().Add(-time.Duration(d.cfg.RetentionDays) * 24 * time.Hour).UnixMilli()
					_, _ = d.store.PruneOlderThan(cutoff)
				}
			}
		}
	}()

	return srv.Serve(ctx)
}
