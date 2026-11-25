package diagnostics

import (
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/yikkrrtykj/event-ipsec-hub/internal/host"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/installer"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/live"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/manifest"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/sa"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/secureio"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/transaction"
)

func checkItem(id, status, detail string) map[string]any {
	return map[string]any{"id": id, "status": status, "detail": detail}
}

// CheckHost inspects local OS metadata and required tool discovery read-only.
func CheckHost() map[string]any {
	var checks []map[string]any
	if runtime.GOOS != "linux" {
		checks = append(checks, checkItem("host", "SKIP", "Linux host prerequisites cannot be checked here."))
	} else {
		raw, err := os.ReadFile("/etc/os-release")
		if err != nil {
			checks = append(checks, checkItem("host", "SKIP", "Could not read Linux distribution metadata."))
		} else {
			fields := make(map[string]string)
			for _, line := range strings.Split(string(raw), "\n") {
				if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
					fields[k] = strings.Trim(v, `"'`)
				}
			}
			if fields["ID"] != "ubuntu" || fields["VERSION_ID"] != "24.04" {
				checks = append(checks, checkItem("host", "FAIL", "The deployment target is Ubuntu 24.04."))
			} else {
				checks = append(checks, checkItem("host", "PASS", "OS metadata identifies Ubuntu 24.04."))
				for _, cmd := range []string{"ip", "nft", "swanctl", "systemctl"} {
					st := "FAIL"
					if _, err := exec.LookPath(cmd); err == nil {
						st = "PASS"
					}
					checks = append(checks, checkItem("command_"+cmd, st, "Local executable discovery for "+cmd+"."))
				}
			}
		}
	}
	checks = append(checks,
		checkItem("active_profile", "SKIP", "Offline host check does not activate profiles."),
		checkItem("vici_sa_xfrm", "SKIP", "Daemon, SA and XFRM state were not queried."),
		checkItem("business_udp_tcp", "SKIP", "No live business traffic was sent."),
		checkItem("firewall_handoff", "SKIP", "No remote firewall was contacted."),
	)
	status := "SKIP"
	for _, c := range checks {
		if c["status"] == "FAIL" {
			status = "FAIL"
			break
		}
	}
	return map[string]any{"status": status, "checks": checks}
}

func InspectOwned(h host.Runner, inst *installer.Record, stable bool) (*live.ActiveRecord, *manifest.DeploymentManifest, *sa.Snapshot, int, error) {
	pending, err := transaction.ReadJournalRecord()
	if err != nil {
		return nil, nil, nil, 0, err
	}
	if pending != nil {
		if ph, _ := pending["phase"].(string); !transaction.Terminal[ph] {
			return nil, nil, nil, 0, secureio.StopWithReason("UNFINISHED_TRANSACTION", "An unfinished transaction needs review.")
		}
	}
	active, err := transaction.ReadActiveRecord()
	if err != nil {
		return nil, nil, nil, 0, err
	}
	m, liveSnap, pid, err := live.OwnedResources(h, inst, active)
	if err != nil {
		return nil, nil, nil, 0, err
	}
	if stable {
		afterAct, _ := transaction.ReadActiveRecord()
		afterJrn, _ := transaction.ReadJournalRecord()
		a1, _ := manifest.CanonicalJSON(active)
		a2, _ := manifest.CanonicalJSON(afterAct)
		j1, _ := manifest.CanonicalJSON(pending)
		j2, _ := manifest.CanonicalJSON(afterJrn)
		if string(a1) != string(a2) || string(j1) != string(j2) {
			return nil, nil, nil, 0, secureio.StopWithReason("SA_TRANSITION", "The active deployment changed during observation.")
		}
	}
	return active, m, liveSnap, pid, nil
}

// StatusReport returns the layered read-only status/doctor report for an installed Hub.
func StatusReport(h host.Runner) map[string]any {
	if h == nil {
		h = host.NewOSHost()
	}
	res := map[string]any{
		"status":    "SKIP",
		"data_path": map[string]any{"status": "SKIP", "reason_code": "NO_PROBE"},
		"sites":     []map[string]any{},
		"checks":    []map[string]any{},
	}
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		res["detail"] = "Runtime inspection requires an authorized Ubuntu lab VM."
		return res
	}
	failStop := func(stage string, err error) map[string]any {
		detail := "A protected observation was unavailable."
		reason := "UNVERIFIED_RUNTIME"
		if se, ok := secureio.AsStop(err); ok {
			detail = se.Detail
			if se.Reason != "" {
				reason = se.Reason
			}
		}
		res["status"] = "FAIL"
		res["decision"] = "STOP"
		res["detail"] = detail
		res["checks"] = []map[string]any{{
			"id": stage, "status": "FAIL", "reason_code": reason, "detail": detail,
		}}
		return res
	}

	rawInst, err := secureio.ReadRecord(transaction.InstalledPath)
	if err != nil {
		return failStop("deployment", err)
	}
	if rawInst == nil {
		res["detail"] = "No project installation was found."
		return res
	}
	if _, err := h.Probe(); err != nil {
		return failStop("host", err)
	}
	inst, err := transaction.InstalledRecord()
	if err != nil {
		return failStop("host", err)
	}
	_, m, liveSnap, _, err := InspectOwned(h, inst, false)
	if err != nil {
		return failStop("daemon_and_kernel", err)
	}

	res["checks"] = []map[string]any{
		checkItem("host_and_daemon", "PASS", "Owned Ubuntu lab daemon verified."),
		checkItem("kernel_and_paths", "PASS", "VICI, XFRM, protected routes and firewall are consistent."),
		checkItem("business", "SKIP", "No network probes were sent."),
	}
	res["ownership"] = liveSnap.StateLabel()
	if m == nil {
		res["detail"] = "The daemon is owned, with no active profile."
		return res
	}

	sites := make([]map[string]any, 0, len(m.Links))
	complete := true
	for _, l := range m.Links {
		ike := liveSnap.Get(l.Name())
		var child *sa.Child
		if ike != nil {
			child = ike.Child
		}
		var counts [4]uint64
		ikeState := "DOWN"
		childState := "DOWN"
		reasonCode := "CHILD_NOT_ESTABLISHED"
		if ike != nil {
			ikeState = "ESTABLISHED"
		}
		if child != nil {
			childState = "INSTALLED"
			counts = child.Counts
			reasonCode = "NO_PROBE"
		} else {
			complete = false
		}
		sites = append(sites, map[string]any{
			"site_id":                   l.SiteID,
			"ike_state":                 ikeState,
			"child_state":               childState,
			"auth_verified":             ike != nil,
			"selector_verified":         child != nil,
			"if_id_verified":            child != nil,
			"kernel_sa_policy_verified": child != nil,
			"xfrm_interface":            l.Name(),
			"rx_bytes":                  counts[0],
			"tx_bytes":                  counts[1],
			"rx_packets":                counts[2],
			"tx_packets":                counts[3],
			"protected_route":           "PASS",
			"egress_guard":              "PASS",
			"data_path":                 res["data_path"],
			"reason_code":               reasonCode,
		})
	}
	res["sites"] = sites
	if complete {
		res["status"] = "PASS"
	}
	res["detail"] = "Local tunnel evidence only. Business probes were not run."
	return res
}
