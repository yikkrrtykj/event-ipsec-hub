package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/yikkrrtykj/event-ipsec-hub/internal/agent"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/alert"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/diagnostics"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/failover"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/handoff"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/manifest"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/profile"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/rpc"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/secureio"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/storage"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/telemetry"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/transaction"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/web"
	webassets "github.com/yikkrrtykj/event-ipsec-hub/web"
)

var Version = "4.0.1"

const (
	DefaultProfiles = "/etc/ipsecvpn/profiles"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stderr)
		return 2
	}
	cmd := args[0]
	rest := args[1:]

	switch cmd {
	case "version", "--version":
		fmt.Fprintf(stdout, "ipsecvpn %s\n", Version)
		return 0
	case "-h", "--help", "help":
		printUsage(stdout)
		return 0
	case "boot":
		if len(rest) != 1 || (rest[0] != "guard" && rest[0] != "restore") {
			fmt.Fprintln(stderr, "STOP: Invalid boot phase.")
			return 1
		}
		if err := transaction.Boot(rest[0]); err != nil {
			fmt.Fprintf(stderr, "STOP: %v\n", err)
			return 1
		}
		return 0
	case "profiles":
		return runProfiles(rest, stdout, stderr)
	case "validate":
		return runValidate(rest, stdout, stderr)
	case "check":
		return runCheck(rest, stdout, stderr)
	case "status", "doctor":
		return runStatus(rest, stdout, stderr)
	case "plan":
		return runPlan(rest, stdout, stderr)
	case "render":
		return runRender(rest, stdout, stderr)
	case "export-peer":
		return runExportPeer(rest, stdout, stderr)
	case "install", "apply", "backup", "rollback", "uninstall", "initiate", "rekey", "reconnect":
		return runHostAction(cmd, rest, stdout, stderr)
	case "failover":
		return runFailover(rest, stdout, stderr)
	case "probe":
		return runProbe(rest, stdout, stderr)
	case "monitor":
		return runMonitor(rest, stdout, stderr)
	case "alert":
		return runAlert(rest, stdout, stderr)
	case "agent":
		return runAgent(rest, stdout, stderr)
	case "web":
		return runWeb(rest, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown command: %s\n", cmd)
		printUsage(stderr)
		return 2
	}
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "ipsecvpn — event-ipsec-hub V4.0 Go gateway CLI & Web appliance")
	fmt.Fprintln(w, "Commands: profiles list | validate | check | status | doctor | plan | render | export-peer")
	fmt.Fprintln(w, "          install | apply | backup | rollback | uninstall | initiate | rekey | reconnect")
	fmt.Fprintln(w, "          failover status|evaluate|switch-backup|failback|set-role | probe respond|run")
	fmt.Fprintln(w, "          monitor validate|timeline|metrics | alert test-feishu | agent serve | web serve | boot guard|restore | version")
}

func writeJSON(w io.Writer, v any) {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func emitResult(res map[string]any, asJSON bool, stdout, stderr io.Writer) int {
	if asJSON {
		writeJSON(stdout, res)
	} else {
		printText(stdout, res)
	}
	st, _ := res["status"].(string)
	if st == "FAIL" || st == "STOP" {
		return 1
	}
	return 0
}

func emitError(err error, asJSON, isStop bool, stdout, stderr io.Writer) int {
	detail := err.Error()
	res := map[string]any{"status": "FAIL", "detail": detail}
	if isStop {
		res["decision"] = "STOP"
	}
	if se, ok := secureio.AsStop(err); ok {
		res["decision"] = "STOP"
		if se.Reason != "" {
			res["reason_code"] = se.Reason
		}
	}
	if asJSON {
		writeJSON(stdout, res)
		return 1
	}
	prefix := "FAIL"
	if res["decision"] == "STOP" {
		prefix = "FAIL/STOP"
	}
	fmt.Fprintf(stderr, "%s %s\n", prefix, detail)
	return 1
}

func printText(w io.Writer, res map[string]any) {
	status, _ := res["status"].(string)
	if res["decision"] == "STOP" || status == "STOP" {
		status = "FAIL/STOP"
	}
	detail, _ := res["detail"].(string)
	fmt.Fprintf(w, "%s %s\n", status, detail)
	if checks, ok := res["checks"].([]map[string]any); ok {
		for _, c := range checks {
			fmt.Fprintf(w, "%v %v — %v\n", c["status"], c["id"], c["detail"])
		}
	}
	if profiles, ok := res["profiles"].([]map[string]any); ok {
		for _, p := range profiles {
			if p["status"] == "PASS" {
				ev := p["event"].(profile.Event)
				fmt.Fprintf(w, "PASS %s — %s\n", ev.ID, ev.Name)
			} else {
				fmt.Fprintf(w, "FAIL %v\n", p["detail"])
			}
		}
	}
}

func runProfiles(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "list" {
		fmt.Fprintln(stderr, "usage: ipsecvpn profiles list [--directory DIR] [--json]")
		return 2
	}
	fs := flag.NewFlagSet("profiles list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("directory", DefaultProfiles, "profile directory")
	asJSON := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}

	entries, err := os.ReadDir(*dir)
	if err != nil && !os.IsNotExist(err) {
		return emitError(&profile.ProfileError{Detail: "Could not list the profile directory."}, *asJSON, false, stdout, stderr)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	var profiles []map[string]any
	seen := make(map[string]bool)
	failed := false
	for _, ent := range entries {
		ext := strings.ToLower(filepath.Ext(ent.Name()))
		if ext != ".yaml" && ext != ".yml" {
			continue
		}
		p, perr := profile.LoadProfile(filepath.Join(*dir, ent.Name()))
		if perr != nil {
			failed = true
			profiles = append(profiles, map[string]any{"status": "FAIL", "detail": perr.Error()})
			continue
		}
		if seen[p.Event.ID] {
			failed = true
			profiles = append(profiles, map[string]any{"status": "FAIL", "detail": "Duplicate event ID in the profile directory."})
			continue
		}
		seen[p.Event.ID] = true
		profiles = append(profiles, map[string]any{"status": "PASS", "event": p.Event})
	}
	status := "SKIP"
	if failed {
		status = "FAIL"
	} else if len(profiles) > 0 {
		status = "PASS"
	}
	return emitResult(map[string]any{
		"status":         status,
		"active_profile": map[string]any{"status": "SKIP", "detail": "Offline profile listing does not activate profiles."},
		"profiles":       profiles,
	}, *asJSON, stdout, stderr)
}

func runValidate(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfg := fs.String("c", "", "config path")
	cfgLong := fs.String("config", "", "config path")
	asJSON := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	path := firstNonEmpty(*cfg, *cfgLong)
	if path == "" {
		fmt.Fprintln(stderr, "validate requires -c/--config")
		return 2
	}
	p, err := profile.LoadProfile(path)
	if err != nil {
		return emitError(err, *asJSON, false, stdout, stderr)
	}
	return emitResult(map[string]any{
		"status": "PASS",
		"detail": "Profile schema and topology validated.",
		"backup": profile.EvaluateBackupReadiness(p),
	}, *asJSON, stdout, stderr)
}

func runCheck(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	asJSON := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	return emitResult(diagnostics.CheckHost(), *asJSON, stdout, stderr)
}

func runStatus(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	asJSON := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	return emitResult(diagnostics.StatusReport(nil), *asJSON, stdout, stderr)
}

func runPlan(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("plan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfg := fs.String("c", "", "config path")
	cfgLong := fs.String("config", "", "config path")
	_ = fs.Bool("json", true, "JSON output")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	path := firstNonEmpty(*cfg, *cfgLong)
	if path == "" {
		fmt.Fprintln(stderr, "plan requires -c/--config")
		return 2
	}
	p, err := profile.LoadProfile(path)
	if err != nil {
		return emitError(err, true, false, stdout, stderr)
	}
	return emitResult(handoff.BuildPlan(p), true, stdout, stderr)
}

func runRender(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("render", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfg := fs.String("c", "", "config path")
	cfgLong := fs.String("config", "", "config path")
	_ = fs.Bool("json", true, "JSON output")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	path := firstNonEmpty(*cfg, *cfgLong)
	if path == "" {
		fmt.Fprintln(stderr, "render requires -c/--config")
		return 2
	}
	p, err := profile.LoadProfile(path)
	if err != nil {
		return emitError(err, true, false, stdout, stderr)
	}
	res, err := manifest.Render(p)
	if err != nil {
		return emitError(err, true, false, stdout, stderr)
	}
	return emitResult(res, true, stdout, stderr)
}

func runExportPeer(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("export-peer", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfg := fs.String("c", "", "config path")
	cfgLong := fs.String("config", "", "config path")
	site := fs.String("site", "", "target site ID")
	format := fs.String("format", "md", "md|json|tencent-json|hillstone-draft|strongswan-draft")
	tmpl := fs.String("template", "auto", "auto|hillstone|generic")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *site == "" {
		fmt.Fprintln(stderr, "export-peer requires --site")
		return 2
	}
	path := firstNonEmpty(*cfg, *cfgLong, os.Getenv("IPSECVPN_CONFIG"))
	asJSON := *format == "json" || *format == "tencent-json"
	if path == "" {
		return emitError(&profile.ProfileError{Detail: "Select a profile explicitly with -c or IPSECVPN_CONFIG."}, asJSON, false, stdout, stderr)
	}
	p, err := profile.LoadProfile(path)
	if err != nil {
		return emitError(err, asJSON, false, stdout, stderr)
	}

	switch *format {
	case "md":
		params, err := handoff.PeerParameters(p, *site, *tmpl)
		if err != nil {
			return emitError(err, false, false, stdout, stderr)
		}
		fmt.Fprint(stdout, handoff.RenderPeerMarkdown(params))
		return 0
	case "json":
		params, err := handoff.PeerParameters(p, *site, *tmpl)
		if err != nil {
			return emitError(err, true, false, stdout, stderr)
		}
		return emitResult(params, true, stdout, stderr)
	case "tencent-json":
		tc, err := handoff.RenderTencentJSON(p, *site, "")
		if err != nil {
			return emitError(err, true, false, stdout, stderr)
		}
		writeJSON(stdout, tc)
		return 0
	case "hillstone-draft":
		draft, err := handoff.RenderVendorDraft(p, *site, "hillstone", "")
		if err != nil {
			return emitError(err, false, false, stdout, stderr)
		}
		fmt.Fprint(stdout, draft)
		return 0
	case "strongswan-draft":
		draft, err := handoff.RenderVendorDraft(p, *site, "strongswan", "")
		if err != nil {
			return emitError(err, false, false, stdout, stderr)
		}
		fmt.Fprint(stdout, draft)
		return 0
	default:
		fmt.Fprintf(stderr, "unsupported format %q\n", *format)
		return 2
	}
}

func runHostAction(action string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet(action, flag.ContinueOnError)
	fs.SetOutput(stderr)
	dryRun := fs.Bool("dry-run", false, "dry-run mode")
	confirm := fs.Bool("confirm", false, "confirm write")
	asJSON := fs.Bool("json", false, "JSON output")
	cfg := fs.String("c", "", "config path")
	cfgLong := fs.String("config", "", "config path")
	toID := fs.String("to", "", "backup ID")
	maint := fs.Bool("maintenance", false, "explicit maintenance window")
	site := fs.String("site", "", "site ID")
	child := fs.Bool("child", false, "rekey CHILD SA")
	ike := fs.Bool("ike", false, "rekey IKE SA")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *dryRun == *confirm {
		fmt.Fprintf(stderr, "%s requires exactly one of --dry-run or --confirm\n", action)
		return 2
	}
	cfgPath := firstNonEmpty(*cfg, *cfgLong)
	if action == "apply" && cfgPath == "" {
		fmt.Fprintln(stderr, "apply requires -c/--config")
		return 2
	}
	if action == "rollback" && *toID == "" {
		fmt.Fprintln(stderr, "rollback requires --to")
		return 2
	}
	if (action == "initiate" || action == "rekey") && *site == "" {
		fmt.Fprintf(stderr, "%s requires --site\n", action)
		return 2
	}
	kind := ""
	if action == "rekey" {
		if *child == *ike {
			fmt.Fprintln(stderr, "rekey requires exactly one of --child or --ike")
			return 2
		}
		if *child {
			kind = "child"
		} else {
			kind = "ike"
		}
	}

	res, err := transaction.NewDeployment(nil).Dispatch(transaction.DispatchOptions{
		Action:      action,
		Confirmed:   *confirm,
		ConfigPath:  cfgPath,
		BackupID:    *toID,
		Maintenance: *maint,
		Site:        *site,
		Kind:        kind,
	})
	if err != nil {
		return emitError(err, *asJSON, true, stdout, stderr)
	}
	return emitResult(res, *asJSON, stdout, stderr)
}

func runFailover(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: ipsecvpn failover status|evaluate|switch-backup|failback|set-role")
		return 2
	}
	sub := args[0]
	rest := args[1:]
	fs := flag.NewFlagSet("failover "+sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	stateFile := fs.String("state-file", "", "failover state JSON path")
	asJSON := fs.Bool("json", false, "JSON output")
	applyGate := fs.Bool("apply-gate", false, "apply Hub XFRM down/up gate")
	primaryHealthy := fs.Bool("primary-healthy", false, "primary healthy")
	primaryUnhealthy := fs.Bool("primary-unhealthy", false, "primary unhealthy")
	backupHealthy := fs.Bool("backup-healthy", false, "backup healthy")
	backupUnhealthy := fs.Bool("backup-unhealthy", false, "backup unhealthy")
	reason := fs.String("reason", "", "transition reason")
	operator := fs.String("operator", "", "operator name")
	role := fs.String("role", "", "hub role: primary|backup")
	force := fs.Bool("force", false, "emergency override")
	dryRun := fs.Bool("dry-run", false, "dry-run")
	confirm := fs.Bool("confirm", false, "confirm")
	if err := fs.Parse(rest); err != nil {
		return 2
	}

	ctrl, err := failover.NewController(*stateFile, 3, 180)
	if err != nil {
		return emitError(err, *asJSON, true, stdout, stderr)
	}

	switch sub {
	case "status":
		return emitResult(map[string]any{
			"status": "PASS",
			"detail": fmt.Sprintf("Failover mode=%s active=%s role=%s.", ctrl.State.Mode, ctrl.State.ActivePath, ctrl.State.HubRole),
			"state":  ctrl.State,
		}, *asJSON, stdout, stderr)

	case "evaluate":
		if *primaryHealthy == *primaryUnhealthy || *backupHealthy == *backupUnhealthy {
			fmt.Fprintln(stderr, "evaluate requires --primary-healthy/--primary-unhealthy and --backup-healthy/--backup-unhealthy")
			return 2
		}
		out, err := ctrl.Evaluate(*primaryHealthy, *backupHealthy, 0, *reason)
		if err != nil {
			return emitError(err, *asJSON, true, stdout, stderr)
		}
		if *applyGate && out["action"] == "SWITCH_TO_BACKUP" {
			gate, gerr := transaction.ApplyHubXFRMGate(true, nil)
			if gerr != nil {
				return emitError(gerr, *asJSON, true, stdout, stderr)
			}
			out["hub_gate"] = gate
		}
		return emitResult(out, *asJSON, stdout, stderr)

	case "switch-backup", "failback", "set-role":
		if *dryRun == *confirm {
			fmt.Fprintf(stderr, "failover %s requires exactly one of --dry-run or --confirm\n", sub)
			return 2
		}
		if *operator == "" {
			fmt.Fprintf(stderr, "failover %s requires --operator\n", sub)
			return 2
		}
		if !*confirm {
			return emitResult(map[string]any{
				"status": "PASS",
				"detail": fmt.Sprintf("Dry-run %s; failover state was not changed.", sub),
				"state":  ctrl.State,
			}, *asJSON, stdout, stderr)
		}
		var out map[string]any
		switch sub {
		case "switch-backup":
			out, err = ctrl.ManualSwitchToBackup(*operator, true, *reason, 0)
			if err == nil && *applyGate && out["action"] == "SWITCH_TO_BACKUP" {
				gate, gerr := transaction.ApplyHubXFRMGate(true, nil)
				if gerr != nil {
					return emitError(gerr, *asJSON, true, stdout, stderr)
				}
				out["hub_gate"] = gate
			}
		case "failback":
			out, err = ctrl.ConfirmFailback(*operator, true, *force, 0)
			if err == nil && *applyGate && out["action"] == "SWITCH_TO_PRIMARY" {
				gate, gerr := transaction.ApplyHubXFRMGate(false, nil)
				if gerr != nil {
					return emitError(gerr, *asJSON, true, stdout, stderr)
				}
				out["hub_gate"] = gate
			}
		case "set-role":
			if *role == "" {
				return emitError(errors.New("set-role requires --role primary|backup"), *asJSON, true, stdout, stderr)
			}
			out, err = ctrl.SetHubRole(*role, *operator, 0)
		}
		if err != nil {
			return emitError(err, *asJSON, true, stdout, stderr)
		}
		return emitResult(out, *asJSON, stdout, stderr)

	default:
		fmt.Fprintf(stderr, "unknown failover subcommand: %s\n", sub)
		return 2
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func runProbe(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || (args[0] != "respond" && args[0] != "run") {
		fmt.Fprintln(stderr, "usage: ipsecvpn probe respond|run --source IP --source-port PORT --target IP --target-port PORT [--key-file PATH] [--seconds N] [--count N] [--timeout-ms N]")
		return 2
	}
	op := args[0]
	fs := flag.NewFlagSet("probe "+op, flag.ContinueOnError)
	fs.SetOutput(stderr)
	src := fs.String("source", "", "local LAN IPv4")
	srcPort := fs.Int("source-port", 41500, "local UDP port")
	dst := fs.String("target", "", "peer LAN IPv4")
	dstPort := fs.Int("target-port", 41500, "peer UDP port")
	keyFile := fs.String("key-file", "/etc/ipsecvpn/secrets/monitor-probe", "32-byte probe key file")
	seconds := fs.Int("seconds", 30, "responder duration in seconds")
	count := fs.Int("count", 3, "probe packet count (1..4)")
	timeoutMs := fs.Int("timeout-ms", 500, "per-packet timeout ms")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	localAddr, err := telemetry.ValidateLANEndpoint(*src, *srcPort)
	if err != nil {
		return emitError(err, false, true, stdout, stderr)
	}
	peerAddr, err := telemetry.ValidateLANEndpoint(*dst, *dstPort)
	if err != nil {
		return emitError(err, false, true, stdout, stderr)
	}
	key, err := os.ReadFile(*keyFile)
	if err != nil || len(key) != 32 {
		return emitError(secureio.Stop("A dedicated 32-byte UDP test key is required."), false, true, stdout, stderr)
	}
	if op == "respond" {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*seconds)*time.Second)
		defer cancel()
		err := telemetry.ServeUDPResponder(ctx, key, localAddr, peerAddr, func() {
			fmt.Fprintln(stdout, "READY")
		})
		if err != nil {
			return emitError(err, false, true, stdout, stderr)
		}
		return 0
	}
	receipts, err := telemetry.ProbeUDP(key, localAddr, peerAddr, *count, time.Duration(*timeoutMs)*time.Millisecond)
	if err != nil {
		return emitError(err, true, true, stdout, stderr)
	}
	writeJSON(stdout, receipts)
	return 0
}

func runMonitor(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: ipsecvpn monitor validate|timeline|metrics")
		return 2
	}
	sub := args[0]
	fs := flag.NewFlagSet("monitor "+sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfg := fs.String("c", "", "config path")
	cfgLong := fs.String("config", "", "config path")
	dbPath := fs.String("db", storage.DefaultDBPath, "SQLite DB path")
	site := fs.String("site", "", "site ID filter")
	windowMin := fs.Int("window-minutes", 60, "timeline lookback minutes")
	asJSON := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}

	switch sub {
	case "validate":
		path := firstNonEmpty(*cfg, *cfgLong)
		if path == "" {
			fmt.Fprintln(stderr, "monitor validate requires -c/--config")
			return 2
		}
		p, err := profile.LoadProfile(path)
		if err != nil {
			return emitError(err, *asJSON, false, stdout, stderr)
		}
		enabled := p.Monitoring != nil && p.Monitoring.Enabled
		return emitResult(map[string]any{
			"status":  "PASS",
			"enabled": enabled,
			"detail":  "Monitoring validated.",
		}, *asJSON, stdout, stderr)

	case "timeline":
		st, err := storage.Open(*dbPath)
		if err != nil {
			return emitError(err, true, true, stdout, stderr)
		}
		defer st.Close()
		toMs := time.Now().UnixMilli()
		fromMs := toMs - int64(*windowMin)*60_000
		samples, err := st.QueryMetricSamples(*site, fromMs, toMs, 1000)
		if err != nil {
			return emitError(err, true, true, stdout, stderr)
		}
		events, err := st.QueryTimelineEvents(*site, fromMs, toMs, 500)
		if err != nil {
			return emitError(err, true, true, stdout, stderr)
		}
		resp := telemetry.SyncedTimelineResponse{
			SiteID:    *site,
			FromMs:    fromMs,
			ToMs:      toMs,
			Samples:   samples,
			Events:    events,
			Diagnosis: telemetry.SummarizeWindow(samples, events),
		}
		writeJSON(stdout, resp)
		return 0

	case "metrics":
		st, err := storage.Open(*dbPath)
		if err != nil {
			return emitError(err, false, true, stdout, stderr)
		}
		defer st.Close()
		now := time.Now().UnixMilli()
		samples, err := st.QueryMetricSamples(*site, now-5*60_000, now, 200)
		if err != nil {
			return emitError(err, false, true, stdout, stderr)
		}
		latestBySite := make(map[string]storage.MetricSample)
		for _, s := range samples {
			latestBySite[s.SiteID] = s
		}
		latest := make([]storage.MetricSample, 0, len(latestBySite))
		for _, s := range latestBySite {
			latest = append(latest, s)
		}
		sort.Slice(latest, func(i, j int) bool { return latest[i].SiteID < latest[j].SiteID })
		fmt.Fprint(stdout, telemetry.RenderPrometheusMetrics(len(latest) > 0, "READY", latest))
		return 0

	default:
		fmt.Fprintf(stderr, "unknown monitor subcommand: %s\n", sub)
		return 2
	}
}

func runAlert(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "test-feishu" {
		fmt.Fprintln(stderr, "usage: ipsecvpn alert test-feishu --webhook URL [--secret SECRET] [--message TEXT]")
		return 2
	}
	fs := flag.NewFlagSet("alert test-feishu", flag.ContinueOnError)
	fs.SetOutput(stderr)
	webhook := fs.String("webhook", "", "official Feishu bot webhook URL")
	secret := fs.String("secret", "", "optional Feishu signing secret")
	message := fs.String("message", "", "optional custom message text")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if _, err := alert.ValidateFeishuTarget(*webhook, false); err != nil {
		return emitError(err, false, true, stdout, stderr)
	}
	text := *message
	if text == "" {
		cst := time.FixedZone("Asia/Shanghai", 8*3600)
		now := time.Now()
		text = fmt.Sprintf(
			"[测试] event-ipsec-hub V4 飞书告警通道连通性验证成功\n时间: %s UTC / %s Asia/Shanghai\n来源: self_hosted_hub",
			now.UTC().Format(time.RFC3339),
			now.In(cst).Format(time.RFC3339),
		)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := alert.DeliverFeishu(ctx, nil, *webhook, []byte(*secret), text); err != nil {
		return emitError(err, false, false, stdout, stderr)
	}
	fmt.Fprintf(stdout, "PASS Feishu test alert delivered (%s)\n", alert.MaskFeishuURL(*webhook))
	return 0
}

func runAgent(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "serve" {
		fmt.Fprintln(stderr, "usage: ipsecvpn agent serve [--socket PATH] [--db PATH] [--interval 15s] [--allow-uid UID]")
		return 2
	}
	fs := flag.NewFlagSet("agent serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	sock := fs.String("socket", rpc.DefaultSocketPath, "Unix socket path")
	dbPath := fs.String("db", storage.DefaultDBPath, "SQLite database path")
	interval := fs.Duration("interval", 15*time.Second, "telemetry sample interval")
	retention := fs.Int("retention-days", 14, "metric retention days")
	allowUIDsStr := fs.String("allow-uid", "", "comma-separated UIDs allowed to call RPC besides root")
	socketGID := fs.Int("socket-gid", 0, "optional GID (>0) granted access to the agent Unix socket")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}

	allowedUIDs := map[uint32]bool{}
	for _, part := range strings.Split(*allowUIDsStr, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if v, err := strconv.ParseUint(part, 10, 32); err == nil {
			allowedUIDs[uint32(v)] = true
		}
	}
	st, err := storage.Open(*dbPath)
	if err != nil {
		return emitError(err, false, true, stdout, stderr)
	}
	defer st.Close()
	if *socketGID > 0 {
		storage.EnsureGroupWritable(*dbPath, *socketGID)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	d := agent.New(agent.Config{
		SocketPath:    *sock,
		SocketGID:     *socketGID,
		DBPath:        *dbPath,
		Interval:      *interval,
		RetentionDays: *retention,
		AllowedUIDs:   allowedUIDs,
	}, st, nil)
	fmt.Fprintf(stdout, "ipsecvpn agent listening on %s (interval=%s)\n", *sock, *interval)
	if err := d.Serve(ctx); err != nil {
		return emitError(err, false, true, stdout, stderr)
	}
	return 0
}

func runWeb(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "serve" {
		fmt.Fprintln(stderr, "usage: ipsecvpn web serve [--listen :18443] [--db PATH] [--agent-socket PATH] [--cert PATH] [--key PATH] [--public-ip IP] [--demo]")
		return 2
	}
	fs := flag.NewFlagSet("web serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	listen := fs.String("listen", ":18443", "HTTPS listen address")
	dbPath := fs.String("db", storage.DefaultDBPath, "SQLite database path")
	agentSock := fs.String("agent-socket", rpc.DefaultSocketPath, "Agent Unix socket path")
	certPath := fs.String("cert", "", "TLS certificate path")
	keyPath := fs.String("key", "", "TLS private key path")
	publicIPs := fs.String("public-ip", "", "comma-separated public IP SANs for auto-generated TLS cert")
	failoverPath := fs.String("failover-state", failover.DefaultStateFile, "failover state JSON path")
	demo := fs.Bool("demo", false, "enable local UI demo/preview mode")
	insecureHTTP := fs.Bool("insecure-http", false, "disable TLS (local dev only)")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}

	st, err := storage.Open(*dbPath)
	if err != nil {
		return emitError(err, false, true, stdout, stderr)
	}
	defer st.Close()

	var agentClient rpc.Client
	if !*demo {
		agentClient = rpc.NewUnixClient(*agentSock)
	}
	staticFS, _ := webassets.DistFS()
	var ips []string
	for _, s := range strings.Split(*publicIPs, ",") {
		if s = strings.TrimSpace(s); s != "" {
			ips = append(ips, s)
		}
	}

	srv := web.NewServer(web.Config{
		ListenAddr:        *listen,
		PublicIPs:         ips,
		CertPath:          *certPath,
		KeyPath:           *keyPath,
		FailoverStateFile: *failoverPath,
		StaticFS:          staticFS,
		DemoMode:          *demo,
		InsecureHTTP:      *insecureHTTP,
	}, st, agentClient)

	if initPass, created, err := srv.BootstrapAdmin(); err != nil {
		return emitError(err, false, true, stdout, stderr)
	} else if created {
		fmt.Fprintf(stdout, "BOOTSTRAP_ADMIN username=admin initial_password=%s (change immediately after first login)\n", initPass)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	scheme := "https"
	if *insecureHTTP {
		scheme = "http"
	}
	fmt.Fprintf(stdout, "ipsecvpn web console listening on %s://%s (demo=%v)\n", scheme, *listen, *demo)
	if err := srv.Serve(ctx); err != nil {
		return emitError(err, false, true, stdout, stderr)
	}
	return 0
}
