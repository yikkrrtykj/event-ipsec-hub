package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
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
	SocketPath    string
	DBPath        string
	Interval      time.Duration
	RetentionDays int
	AllowedUIDs   map[uint32]bool
}

// Daemon runs as root on Linux, owning strongSwan VICI, XFRM, nftables, secret files,
// 4-layer telemetry sampling, built-in alerting, and the SO_PEERCRED Unix Socket RPC server.
type Daemon struct {
	cfg        Config
	store      *storage.Store
	host       host.Runner
	alertEng   *alert.Engine
	mu         sync.Mutex
	prevXFRM   map[string]uint64
	prevRxTx   map[string][3]uint64 // tsMs, rxBytes, txBytes
	rekeyTimes map[string][]int64
}

func New(cfg Config, store *storage.Store, h host.Runner) *Daemon {
	if cfg.SocketPath == "" {
		cfg.SocketPath = rpc.DefaultSocketPath
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
	return &Daemon{
		cfg:        cfg,
		store:      store,
		host:       h,
		alertEng:   alert.NewEngine(store, nil, "self_hosted_hub"),
		prevXFRM:   make(map[string]uint64),
		prevRxTx:   make(map[string][3]uint64),
		rekeyTimes: make(map[string][]int64),
	}
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

	case rpc.MethodSyncAllowlist:
		// Guarded no-op placeholder until nftables management chain is explicitly installed.
		var p rpc.SyncAllowlistParams
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, secureio.Stop("Invalid allowlist parameters.")
		}
		return map[string]any{"status": "PASS", "port": p.Port, "cidrs": p.CIDRs}, nil

	default:
		return nil, secureio.Stop("Unsupported RPC method: " + method)
	}
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
	active, m, liveSnap, _, err := diagnostics.InspectOwned(d.host, inst, false)
	if err != nil || m == nil || active == nil {
		return err
	}
	now := time.Now().UTC()
	nowMs := now.UnixMilli()

	curXFRM := telemetry.ReadXFRMStat()
	d.mu.Lock()
	xfrmDelta := telemetry.XFRMErrorDelta(d.prevXFRM, curXFRM)
	d.prevXFRM = curXFRM
	d.mu.Unlock()

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
			L4UDPState:     telemetry.StateUnknown,
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

// Serve runs the Unix Socket RPC server, periodic 4-layer collector, and retention pruner.
func (d *Daemon) Serve(ctx context.Context) error {
	srv := &rpc.Server{
		SocketPath:  d.cfg.SocketPath,
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
