package live

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/strongswan/govici/vici"

	"github.com/yikkrrtykj/event-ipsec-hub/internal/host"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/installer"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/manifest"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/profile"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/resources"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/sa"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/secureio"
)

const AutostartWait = 15 * time.Second

// ActiveRecord is the persisted active profile state stored in /var/lib/ipsecvpn/active.json.
type ActiveRecord struct {
	Profile      map[string]any    `json:"profile"`
	Keys         map[string]string `json:"keys"`
	NFTSHA256    string            `json:"nft_sha256,omitempty"`
	HostBaseline map[string]string `json:"host_baseline,omitempty"`
}

func AssertBaseline(active *ActiveRecord, baseline map[string]string) error {
	if active == nil || len(active.HostBaseline) == 0 {
		return nil
	}
	var changed []string
	for k, v := range active.HostBaseline {
		if baseline[k] != v {
			changed = append(changed, k)
		}
	}
	if len(changed) == 0 && len(active.HostBaseline) == len(baseline) {
		return nil
	}
	stage := "HOST_BASELINE"
	if len(changed) == 1 {
		switch changed[0] {
		case "foreign_nft":
			stage = "NFTABLES"
		case "ssh":
			stage = "SSH_BASELINE"
		case "default_routes", "foreign_routes":
			stage = "ROUTING"
		case "sysctl":
			stage = "SYSCTL_BASELINE"
		}
	}
	return secureio.ObservationStop("The recorded SSH, routing or foreign firewall baseline has changed.", stage, "")
}

func ManifestFromActive(active *ActiveRecord) (*manifest.DeploymentManifest, *profile.Profile, error) {
	if active == nil {
		return nil, nil, nil
	}
	p, err := profile.ValidateRaw(active.Profile)
	if err != nil {
		return nil, nil, secureio.Stop("The persisted active profile is invalid.")
	}
	m, err := manifest.BuildManifest(p)
	if err != nil {
		return nil, nil, err
	}
	return m, p, nil
}

func OwnedResources(h host.Runner, inst *installer.Record, active *ActiveRecord) (*manifest.DeploymentManifest, *sa.Snapshot, int, error) {
	m, _, err := ManifestFromActive(active)
	if err != nil {
		return nil, nil, 0, err
	}
	mgr := resources.NewManager(h, inst.Token, []*manifest.DeploymentManifest{m})
	permitted := make(map[string]struct{})
	if m != nil {
		for _, l := range m.Links {
			permitted[l.Name()] = struct{}{}
		}
	}
	pid, err := h.AssertDaemon(permitted)
	if err != nil {
		return nil, nil, 0, err
	}
	baseline, err := mgr.Preflight(m)
	if err != nil {
		return nil, nil, 0, err
	}
	if err := AssertBaseline(active, baseline); err != nil {
		return nil, nil, 0, err
	}
	observed, err := sa.Inventory(h, m, pid, 4, 200*time.Millisecond)
	if err != nil {
		return nil, nil, 0, err
	}
	nftSHA := ""
	if active != nil {
		nftSHA = active.NFTSHA256
	}
	if _, err := mgr.Verify(m, baseline, nftSHA, observed); err != nil {
		return nil, nil, 0, err
	}
	return m, observed, pid, nil
}

func VerifyInitiateConfig(sess *vici.Session, m *manifest.DeploymentManifest) error {
	links := make(map[string]manifest.Link)
	if m != nil {
		for _, l := range m.Links {
			links[l.Name()] = l
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	seen := make(map[string]struct{})
	for msg, err := range sess.CallStreaming(ctx, "list-conns", "list-conn", nil) {
		if err != nil {
			return secureio.StopWithReason("VICI_UNAVAILABLE", "A local VICI request did not complete.")
		}
		ev := sa.MessageToMap(msg)
		for name, rawRow := range ev {
			if _, dup := seen[name]; dup {
				return secureio.Stop("The daemon has an unowned loaded connection.")
			}
			link, ok := links[name]
			if !ok {
				return secureio.Stop("The daemon has an unowned loaded connection.")
			}
			seen[name] = struct{}{}
			row, _ := rawRow.(map[string]any)
			authKeys := make(map[string]bool)
			for k := range row {
				if strings.HasPrefix(k, "local-") || strings.HasPrefix(k, "remote-") {
					authKeys[k] = true
				}
			}
			wantVer := fmt.Sprintf("IKEv%d", link.EffectiveIKEVersion())
			if len(authKeys) != 2 || !authKeys["local-1"] || !authKeys["remote-1"] || fmt.Sprint(row["version"]) != wantVer {
				return secureio.Stop("The loaded authentication profile is not the expected " + wantVer + " PSK.")
			}
			for _, pair := range [][2]string{{"local-1", link.LocalID}, {"remote-1", link.RemoteID}} {
				sec, _ := row[pair[0]].(map[string]any)
				if fmt.Sprint(sec["class"]) != "pre-shared key" || sa.Identity(fmt.Sprint(sec["id"])) != sa.Identity(pair[1]) {
					return secureio.Stop("A loaded IKE identity differs from the active manifest.")
				}
			}
		}
	}

	sharedReply, err := sess.Call(ctx, "get-shared", nil)
	if err != nil {
		return secureio.StopWithReason("VICI_UNAVAILABLE", "A local VICI request did not complete.")
	}
	keysReply, err := sess.Call(ctx, "get-keys", nil)
	if err != nil {
		return secureio.StopWithReason("VICI_UNAVAILABLE", "A local VICI request did not complete.")
	}
	sharedList, _ := sharedReply.Get("keys").([]string)
	privList, _ := keysReply.Get("keys").([]string)
	if len(seen) != len(links) || len(privList) > 0 || len(sharedList) != len(links) {
		return secureio.Stop("The loaded credential or connection inventory is not project-exclusive.")
	}
	sharedSet := make(map[string]bool, len(sharedList))
	for _, k := range sharedList {
		sharedSet[k] = true
	}
	for name := range links {
		if !sharedSet["ike-"+name] {
			return secureio.Stop("The loaded credential or connection inventory is not project-exclusive.")
		}
	}
	return nil
}

func AwaitAutostart(h host.Runner, m *manifest.DeploymentManifest, pid int, link manifest.Link, timeout, interval time.Duration) (*sa.Ike, error) {
	deadline := time.Now().Add(timeout)
	var partial *sa.Ike
	var lastErr error
	for {
		snap, err := sa.Inventory(h, m, pid, 1, interval)
		if err == nil {
			already := snap.Get(link.Name())
			if already != nil && already.Child != nil {
				return already, nil
			}
			partial = already
			lastErr = nil
		} else {
			if se, ok := secureio.AsStop(err); ok && se.Reason == "UNOWNED_DAEMON" {
				return nil, err
			}
			lastErr = err
		}
		if !time.Now().Before(deadline) {
			return partial, lastErr
		}
		time.Sleep(interval)
	}
}

func InitiateLink(h host.Runner, m *manifest.DeploymentManifest, pid int, link manifest.Link) (*sa.Ike, error) {
	installed := make(map[string]bool)
	if link.StartAction == "start" {
		already, lastErr := AwaitAutostart(h, m, pid, link, AutostartWait, 500*time.Millisecond)
		if already != nil && already.Child != nil {
			return already, nil
		}
		if se, ok := secureio.AsStop(lastErr); ok && se.Reason == "UNOWNED_SA" {
			return nil, lastErr
		}
		if already != nil {
			for k := range already.ChildMap() {
				installed[k] = true
			}
		}
	} else if len(link.ChildSpecs()) > 1 {
		snap, err := sa.Inventory(h, m, pid, 4, 200*time.Millisecond)
		if err != nil {
			return nil, err
		}
		if existing := snap.Get(link.Name()); existing != nil {
			for k := range existing.ChildMap() {
				installed[k] = true
			}
		}
	}

	sess, err := sa.OpenSession(pid, host.VICIPath)
	if err != nil {
		return nil, err
	}
	defer sess.Close()
	if err := VerifyInitiateConfig(sess, m); err != nil {
		return nil, err
	}

	diagnostic := "IKE_NEGOTIATION_UNVERIFIED"
	for _, sp := range link.ChildSpecs() {
		if installed[sp.Name] {
			continue
		}
		in := vici.NewMessage()
		_ = in.Set("ike", link.Name())
		_ = in.Set("child", sp.Name)
		_ = in.Set("timeout", "6000")
		_ = in.Set("loglevel", "1")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		for ev, err := range sess.CallStreaming(ctx, "initiate", "control-log", in) {
			if err != nil {
				cancel()
				return nil, secureio.StopWithReason(diagnostic, "The targeted IKE/CHILD negotiation did not complete.")
			}
			msg := strings.ToLower(fmt.Sprint(ev.Get("msg")))
			switch {
			case strings.Contains(msg, "ts_unacceptable"), strings.Contains(msg, "traffic selectors unacceptable"):
				diagnostic = "CHILD_SELECTORS"
			case strings.Contains(msg, "authentication_failed"), strings.Contains(msg, "no shared key"):
				diagnostic = "IKE_AUTHENTICATION"
			case strings.Contains(msg, "no_proposal_chosen"), strings.Contains(msg, "no proposal found"):
				diagnostic = "PROPOSAL_REJECTED"
			case diagnostic == "IKE_NEGOTIATION_UNVERIFIED" && strings.Contains(msg, "retransmit"):
				diagnostic = "PEER_UNREACHABLE"
			}
		}
		cancel()
	}

	snap, err := sa.Inventory(h, m, pid, 4, 200*time.Millisecond)
	if err != nil {
		return nil, err
	}
	obs := snap.Get(link.Name())
	if obs == nil || obs.Child == nil {
		return nil, secureio.StopWithReason("CHILD_NOT_ESTABLISHED", "The target did not install a verified CHILD SA.")
	}
	return obs, nil
}

func rekeyRelation(event map[string]any, kind string, link manifest.Link, expectedOld uint64) (uint64, uint64, bool) {
	item, _ := event[link.Name()].(map[string]any)
	if kind == "child" {
		children, _ := item["child-sas"].(map[string]any)
		var matched map[string]any
		if expectedOld > 0 {
			for _, raw := range children {
				cand, _ := raw.(map[string]any)
				oldMap, _ := cand["old"].(map[string]any)
				if uid, err := strconv.ParseUint(fmt.Sprint(oldMap["uniqueid"]), 10, 64); err == nil && uid == expectedOld {
					matched = cand
					break
				}
			}
		} else if len(children) == 1 {
			for _, raw := range children {
				matched, _ = raw.(map[string]any)
			}
		}
		item = matched
	}
	if item == nil {
		return 0, 0, false
	}
	oldMap, _ := item["old"].(map[string]any)
	newMap, _ := item["new"].(map[string]any)
	oID, err1 := strconv.ParseUint(fmt.Sprint(oldMap["uniqueid"]), 10, 64)
	nID, err2 := strconv.ParseUint(fmt.Sprint(newMap["uniqueid"]), 10, 64)
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return oID, nID, true
}

func rekeySingle(pid int, link manifest.Link, kind string, previous uint64) (uint64, uint64, error) {
	watcher, err := sa.OpenSession(pid, host.VICIPath)
	if err != nil {
		return 0, 0, err
	}
	defer watcher.Close()

	evCh := make(chan vici.Event, 16)
	watcher.NotifyEvents(evCh)
	defer watcher.StopEvents(evCh)
	if err := watcher.Subscribe(kind + "-rekey"); err != nil {
		return 0, 0, secureio.StopWithReason("VICI_UNAVAILABLE", "Could not subscribe to VICI rekey events.")
	}

	client, err := sa.OpenSession(pid, host.VICIPath)
	if err != nil {
		return 0, 0, err
	}
	defer client.Close()

	req := vici.NewMessage()
	_ = req.Set(kind+"-id", strconv.FormatUint(previous, 10))
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	reply, err := client.Call(ctx, "rekey", req)
	cancel()
	if err != nil || fmt.Sprint(reply.Get("matches")) != "1" {
		return 0, 0, secureio.StopWithReason("SA_TRANSITION", "The verified rekey target changed before dispatch.")
	}

	timer := time.NewTimer(7 * time.Second)
	defer timer.Stop()
	for {
		select {
		case ev := <-evCh:
			oldFilter := uint64(0)
			if kind == "child" {
				oldFilter = previous
			}
			if oID, nID, ok := rekeyRelation(sa.MessageToMap(ev.Message), kind, link, oldFilter); ok && oID == previous && nID != previous {
				return oID, nID, nil
			}
		case <-timer.C:
			return 0, 0, secureio.StopWithReason("SA_TRANSITION", "The daemon did not confirm the old/new SA relation.")
		}
	}
}

func RekeyLink(h host.Runner, m *manifest.DeploymentManifest, pid int, link manifest.Link, old *sa.Ike, kind string) (*sa.Ike, error) {
	if kind == "child" && len(old.Children) > 1 {
		expectedNew := make(map[string]uint64, len(old.Children))
		for _, nc := range old.Children {
			_, newID, err := rekeySingle(pid, link, "child", nc.Child.UniqueID)
			if err != nil {
				return nil, err
			}
			expectedNew[nc.Name] = newID
		}
		snap, err := sa.Inventory(h, m, pid, 10, 700*time.Millisecond)
		if err != nil {
			return nil, err
		}
		cur := snap.Get(link.Name())
		if cur == nil || cur.Child == nil {
			return nil, secureio.StopWithReason("SA_TRANSITION", "No stable CHILD was observed after rekey.")
		}
		cmap := cur.ChildMap()
		for cName, newID := range expectedNew {
			if c, ok := cmap[cName]; !ok || c.UniqueID != newID {
				return nil, secureio.StopWithReason("SA_TRANSITION", "The new SA did not match the daemon's rekey event.")
			}
		}
		return cur, nil
	}

	prev := old.UniqueID
	if kind == "child" {
		prev = old.Child.UniqueID
	}
	_, newID, err := rekeySingle(pid, link, kind, prev)
	if err != nil {
		return nil, err
	}
	snap, err := sa.Inventory(h, m, pid, 10, 700*time.Millisecond)
	if err != nil {
		return nil, err
	}
	cur := snap.Get(link.Name())
	if cur == nil || cur.Child == nil {
		return nil, secureio.StopWithReason("SA_TRANSITION", "No stable CHILD was observed after rekey.")
	}
	observed := cur.UniqueID
	if kind == "child" {
		observed = cur.Child.UniqueID
	}
	if observed != newID {
		return nil, secureio.StopWithReason("SA_TRANSITION", "The new SA did not match the daemon's rekey event.")
	}
	return cur, nil
}

func DrainLinks(h host.Runner, m *manifest.DeploymentManifest, pid int, liveSnap *sa.Snapshot, maxRechecks int) ([]map[string]any, error) {
	if maxRechecks <= 0 {
		maxRechecks = 2
	}
	rechecks := 0
	var reverified []map[string]any
	current, err := sa.Inventory(h, m, pid, 4, 200*time.Millisecond)
	if err != nil {
		return nil, err
	}
	if !current.EqualIdentity(liveSnap) {
		if !sameIKENames(current, liveSnap) || rechecks >= maxRechecks {
			return nil, secureio.StopWithReason("SA_TRANSITION", "The active SAs changed after the maintenance snapshot.")
		}
		rechecks++
		reverified = append(reverified, map[string]any{"phase": "pre_drain"})
	}

	remaining := make([]string, 0, len(current.IKES))
	for _, ike := range current.IKES {
		remaining = append(remaining, ike.Name)
	}
	for len(remaining) > 0 {
		name := remaining[0]
		ike := current.Get(name)
		if ike == nil {
			return nil, secureio.StopWithReason("SA_TRANSITION", "An expected owned SA disappeared before termination.")
		}
		for {
			sess, err := sa.OpenSession(pid, host.VICIPath)
			if err != nil {
				return nil, err
			}
			req := vici.NewMessage()
			_ = req.Set("ike-id", strconv.FormatUint(ike.UniqueID, 10))
			_ = req.Set("force", "yes")
			_ = req.Set("timeout", "2500")
			_ = req.Set("loglevel", "0")
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			reply, callErr := sess.Call(ctx, "terminate", req)
			cancel()
			_ = sess.Close()
			if callErr == nil && fmt.Sprint(reply.Get("matches")) != "1" {
				refreshed, rerr := sa.Inventory(h, m, pid, 4, 200*time.Millisecond)
				if rerr != nil || !sameNamesSlice(refreshed, remaining) || rechecks >= maxRechecks {
					return nil, secureio.StopWithReason("SA_TRANSITION", "The verified termination target changed.")
				}
				rechecks++
				current = refreshed
				ike = refreshed.Get(name)
				reverified = append(reverified, map[string]any{"phase": "mid_drain_target", "connection": name})
				continue
			}
			break
		}
		remaining = remaining[1:]
		observed, err := sa.Inventory(h, m, pid, 8, 550*time.Millisecond)
		if err != nil {
			return nil, err
		}
		if !sameNamesSlice(observed, remaining) {
			return nil, secureio.StopWithReason("SA_TRANSITION", "The precise set of owned SAs did not drain.")
		}
		current = observed
	}
	return reverified, nil
}

func sameIKENames(a, b *sa.Snapshot) bool {
	if len(a.IKES) != len(b.IKES) {
		return false
	}
	for i := range a.IKES {
		if a.IKES[i].Name != b.IKES[i].Name {
			return false
		}
	}
	return true
}

func sameNamesSlice(snap *sa.Snapshot, names []string) bool {
	if len(snap.IKES) != len(names) {
		return false
	}
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	for _, ike := range snap.IKES {
		if !m[ike.Name] {
			return false
		}
	}
	return true
}

func clearConnectingSA(pid int, name string) error {
	sess, err := sa.OpenSession(pid, host.VICIPath)
	if err != nil {
		if se, ok := secureio.AsStop(err); ok && se.Reason == "UNOWNED_DAEMON" {
			return err
		}
		return nil
	}
	defer sess.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	for msg, err := range sess.CallStreaming(ctx, "list-sas", "list-sa", nil) {
		if err != nil {
			break
		}
		ev := sa.MessageToMap(msg)
		row, ok := ev[name].(map[string]any)
		if ok && fmt.Sprint(row["state"]) != "ESTABLISHED" {
			if uid, err := strconv.ParseUint(fmt.Sprint(row["uniqueid"]), 10, 64); err == nil {
				req := vici.NewMessage()
				_ = req.Set("ike-id", strconv.FormatUint(uid, 10))
				_ = req.Set("force", "yes")
				_ = req.Set("timeout", "2500")
				_, _ = sess.Call(ctx, "terminate", req)
			}
		}
	}
	return nil
}

func ReconnectOwned(h host.Runner, inst *installer.Record, active *ActiveRecord, site string, maxAttempts int, baseDelay time.Duration) (map[string]any, error) {
	if maxAttempts < 1 {
		maxAttempts = 3
	}
	if baseDelay <= 0 {
		baseDelay = 400 * time.Millisecond
	}
	m, liveSnap, pid, err := OwnedResources(h, inst, active)
	if err != nil {
		return nil, err
	}
	if m == nil {
		return map[string]any{"status": "SKIP", "detail": "No active profile is deployed.", "links": []any{}}, nil
	}
	var targets []manifest.Link
	for _, l := range m.Links {
		if site == "" || l.SiteID == site || l.KeyID() == site {
			targets = append(targets, l)
		}
	}
	if site != "" && len(targets) == 0 {
		return nil, secureio.Stop("Select a site or link in the current active profile.")
	}
	outcomes := make([]map[string]any, 0, len(targets))
	exhausted := false
	for _, link := range targets {
		if existing := liveSnap.Get(link.Name()); existing != nil && existing.Child != nil {
			outcomes = append(outcomes, map[string]any{
				"site_id":  link.SiteID,
				"link_id":  link.KeyID(),
				"action":   "NOOP_HEALTHY",
				"ike_id":   existing.UniqueID,
				"child_id": existing.Child.UniqueID,
			})
			continue
		}
		lastReason := "UNVERIFIED_SA"
		var connected *sa.Ike
		for attempt := 1; attempt <= maxAttempts; attempt++ {
			obs, ierr := InitiateLink(h, m, pid, link)
			if ierr == nil {
				connected = obs
				outcomes = append(outcomes, map[string]any{
					"site_id":  link.SiteID,
					"link_id":  link.KeyID(),
					"action":   "RECONNECTED",
					"attempts": attempt,
					"ike_id":   obs.UniqueID,
					"child_id": obs.Child.UniqueID,
				})
				break
			}
			if se, ok := secureio.AsStop(ierr); ok {
				if se.Reason != "" {
					lastReason = se.Reason
				}
				if se.Reason == "UNOWNED_SA" || se.Reason == "UNOWNED_DAEMON" {
					return nil, ierr
				}
			}
			if cerr := clearConnectingSA(pid, link.Name()); cerr != nil {
				return nil, cerr
			}
			if attempt < maxAttempts {
				time.Sleep(baseDelay * time.Duration(1<<(attempt-1)))
			}
		}
		if connected == nil {
			exhausted = true
			outcomes = append(outcomes, map[string]any{
				"site_id":     link.SiteID,
				"link_id":     link.KeyID(),
				"action":      "RECONNECT_EXHAUSTED",
				"attempts":    maxAttempts,
				"reason_code": lastReason,
			})
		}
	}
	status := "PASS"
	detail := "Owned links verified or reconnected."
	if exhausted {
		status = "FAIL"
		detail = "One or more links exhausted bounded reconnect attempts."
	}
	return map[string]any{
		"status": status,
		"detail": detail,
		"links":  outcomes,
	}, nil
}

func ConfigureScoped(h host.Runner, pid int, candidates []*manifest.DeploymentManifest, target *manifest.DeploymentManifest, keys map[string][]byte) error {
	known := make(map[string]struct{})
	for _, c := range candidates {
		if c == nil {
			continue
		}
		for _, l := range c.Links {
			known[l.Name()] = struct{}{}
		}
	}
	desired := make(map[string]manifest.Link)
	if target != nil {
		for _, l := range target.Links {
			desired[l.Name()] = l
		}
	}
	if err := h.AssertExclusiveIKE(known); err != nil {
		return err
	}
	sess, err := sa.OpenSession(pid, host.VICIPath)
	if err != nil {
		return err
	}
	defer sess.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	connsReply, err := sess.Call(ctx, "get-conns", nil)
	if err != nil {
		return secureio.StopWithReason("VICI_UNAVAILABLE", "A local VICI request did not complete.")
	}
	sharedReply, err := sess.Call(ctx, "get-shared", nil)
	if err != nil {
		return secureio.StopWithReason("VICI_UNAVAILABLE", "A local VICI request did not complete.")
	}
	keysReply, err := sess.Call(ctx, "get-keys", nil)
	if err != nil {
		return secureio.StopWithReason("VICI_UNAVAILABLE", "A local VICI request did not complete.")
	}
	conns, _ := connsReply.Get("conns").([]string)
	shared, _ := sharedReply.Get("keys").([]string)
	privKeys, _ := keysReply.Get("keys").([]string)
	if len(privKeys) > 0 {
		return secureio.Stop("The daemon has an unowned private credential.")
	}
	for _, c := range conns {
		if _, ok := known[c]; !ok {
			return secureio.Stop("A non-project connection or shared credential is loaded.")
		}
	}
	for _, s := range shared {
		if !strings.HasPrefix(s, "ike-") {
			return secureio.Stop("A non-project connection or shared credential is loaded.")
		}
		if _, ok := known[strings.TrimPrefix(s, "ike-")]; !ok {
			return secureio.Stop("A non-project connection or shared credential is loaded.")
		}
	}

	// Unload existing project conns cleanly so removed children clear and start_action=start fires uniformly.
	sort.Strings(conns)
	for _, name := range conns {
		req := vici.NewMessage()
		_ = req.Set("name", name)
		if _, err := sess.Call(ctx, "unload-conn", req); err != nil {
			return secureio.StopWithReason("VICI_REJECTED", "Failed to unload existing connection.")
		}
	}
	sort.Strings(shared)
	for _, s := range shared {
		if _, keep := desired[strings.TrimPrefix(s, "ike-")]; !keep {
			req := vici.NewMessage()
			_ = req.Set("id", s)
			if _, err := sess.Call(ctx, "unload-shared", req); err != nil {
				return secureio.StopWithReason("VICI_REJECTED", "Failed to unload stale shared key.")
			}
		}
	}

	desiredNames := make([]string, 0, len(desired))
	for n := range desired {
		desiredNames = append(desiredNames, n)
	}
	sort.Strings(desiredNames)
	for _, name := range desiredNames {
		link := desired[name]
		shMsg := vici.NewMessage()
		_ = shMsg.Set("id", "ike-"+name)
		_ = shMsg.Set("type", "IKE")
		_ = shMsg.Set("data", string(keys[link.KeyID()]))
		_ = shMsg.Set("owners", []string{link.LocalID, link.RemoteID})
		if _, err := sess.Call(ctx, "load-shared", shMsg); err != nil {
			return secureio.StopWithReason("VICI_REJECTED", "Failed to load IKE shared key.")
		}

		connMsg, err := vici.MarshalMessage(map[string]any{name: manifest.ConnectionSettings(link)})
		if err != nil {
			return secureio.Stop("Failed to marshal VICI connection settings.")
		}
		if _, err := sess.Call(ctx, "load-conn", connMsg); err != nil {
			return secureio.StopWithReason("VICI_REJECTED", "Failed to load VICI connection.")
		}
	}
	return nil
}
