package transaction

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/yikkrrtykj/event-ipsec-hub/internal/host"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/installer"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/live"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/manifest"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/profile"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/resources"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/sa"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/secureio"
)

const (
	LockPath       = "/run/ipsecvpn.lock"
	StateDir       = installer.StateDir
	ActivePath     = StateDir + "/active.json"
	InstalledPath  = StateDir + "/installed.json"
	RetainedPath   = StateDir + "/retained.json"
	JournalPath    = StateDir + "/journal.json"
	BackupsDir     = StateDir + "/backups"
	HistoryDir     = StateDir + "/journals"
	ProfilesDir    = "/etc/ipsecvpn/profiles"
	ReconnectPath  = StateDir + "/reconnect.json"
)

var (
	hex32RE  = regexp.MustCompile(`^[0-9a-f]{32}$`)
	Terminal = map[string]bool{
		"COMMITTED":              true,
		"RESTORED":               true,
		"CONFIGURATION_RESTORED": true,
	}
)

func nowISO() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}

func newID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func keyDigests(keys map[string][]byte) map[string]string {
	out := make(map[string]string, len(keys))
	for k, v := range keys {
		out[k] = manifest.Digest(v)
	}
	return out
}

func decodeRecord[T any](path string) (*T, error) {
	raw, err := secureio.ReadRecord(path)
	if err != nil || raw == nil {
		return nil, err
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return nil, secureio.Stop("A persisted state record is unreadable.")
	}
	var out T
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, secureio.Stop("A persisted state record is unreadable.")
	}
	return &out, nil
}

func ReadActiveRecord() (*live.ActiveRecord, error) {
	return decodeRecord[live.ActiveRecord](ActivePath)
}

func ReadJournalRecord() (map[string]any, error) {
	raw, err := secureio.ReadRecord(JournalPath)
	if err != nil || raw == nil {
		return nil, err
	}
	m, ok := raw.(map[string]any)
	if !ok {
		return nil, secureio.Stop("A persisted state record is unreadable.")
	}
	return m, nil
}

func InstalledRecord() (*installer.Record, error) {
	rec, err := decodeRecord[installer.Record](InstalledPath)
	if err != nil {
		return nil, err
	}
	if rec == nil {
		return nil, secureio.Stop("Run install on a clean authorized VM before applying a profile.")
	}
	if err := installer.AssertFiles(rec, false); err != nil {
		return nil, err
	}
	vp, err := installer.VendorPlugins()
	if err != nil {
		return nil, err
	}
	if !equalStrMap(rec.VendorPlugins, vp) {
		return nil, secureio.Stop("Distribution strongSwan plugin configuration changed.")
	}
	return rec, nil
}

func keysFor(active *live.ActiveRecord) (map[string][]byte, error) {
	if active == nil {
		return map[string][]byte{}, nil
	}
	p, err := profile.ValidateRaw(active.Profile)
	if err != nil {
		return nil, secureio.Stop("The persisted active profile is invalid.")
	}
	keys, err := secureio.ReadKeys(p)
	if err != nil {
		return nil, err
	}
	if !equalStrMap(active.Keys, keyDigests(keys)) {
		return nil, secureio.Stop("A referenced key no longer matches its recorded snapshot.")
	}
	return keys, nil
}

func equalStrMap(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || bv != v {
			return false
		}
	}
	return true
}

func readBackup(id string) (map[string]any, error) {
	if !hex32RE.MatchString(id) {
		return nil, secureio.Stop("The backup ID is invalid.")
	}
	raw, err := secureio.ReadRecord(filepath.Join(BackupsDir, id+".json"))
	if err != nil {
		return nil, err
	}
	rec, ok := raw.(map[string]any)
	if !ok || rec["id"] != id {
		return nil, secureio.Stop("The requested backup is missing or invalid.")
	}
	if _, hasActive := rec["active"]; !hasActive {
		return nil, secureio.Stop("The requested backup is missing or invalid.")
	}
	return rec, nil
}

func readProfileForApply(path string, confirmed bool) (*profile.Profile, error) {
	if !confirmed {
		return profile.LoadProfile(path)
	}
	ext := strings.ToLower(filepath.Ext(path))
	if filepath.Dir(path) != ProfilesDir || (ext != ".yaml" && ext != ".yml") {
		return nil, secureio.Stop("Select a root-only YAML file directly under /etc/ipsecvpn/profiles.")
	}
	parentMode := uint32(0o700)
	raw, err := secureio.ReadFile(path, 0o600, profile.MaxProfileBytes, &parentMode)
	if err != nil {
		return nil, err
	}
	return profile.ParseProfile(raw)
}

func retainedInstall() (map[string]any, *installer.Record, error) {
	cur, err := ReadJournalRecord()
	if err != nil {
		return nil, nil, err
	}
	receiptRaw, err := secureio.ReadRecord(RetainedPath)
	if err != nil {
		return nil, nil, err
	}
	var journal map[string]any
	if receiptRaw == nil {
		if cur == nil || cur["action"] != "uninstall" || cur["phase"] != "COMMITTED" {
			return nil, nil, nil
		}
		journal = cur
	} else {
		rm, _ := receiptRaw.(map[string]any)
		id, _ := rm["uninstall_id"].(string)
		if !hex32RE.MatchString(id) {
			return nil, nil, secureio.Stop("The retained-package receipt is invalid.")
		}
		if cur != nil && cur["id"] == id {
			journal = cur
		} else {
			hRaw, err := secureio.ReadRecord(filepath.Join(HistoryDir, id+".json"))
			if err != nil {
				return nil, nil, err
			}
			journal, _ = hRaw.(map[string]any)
		}
		if journal == nil || journal["id"] != id || journal["action"] != "uninstall" || journal["phase"] != "COMMITTED" {
			return nil, nil, secureio.Stop("A committed uninstall does not prove the retained-package receipt.")
		}
	}
	b, _ := json.Marshal(journal["install"])
	var inst installer.Record
	if err := json.Unmarshal(b, &inst); err != nil {
		return nil, nil, secureio.Stop("Retained install record is unreadable.")
	}
	return journal, &inst, nil
}

// Deployment coordinates exclusive durable transactions for the Hub.
type Deployment struct {
	Host   host.Runner
	record map[string]any
}

func NewDeployment(h host.Runner) *Deployment {
	if h == nil {
		h = host.NewOSHost()
	}
	return &Deployment{Host: h}
}

func (d *Deployment) setPhase(phase string) error {
	d.record["phase"] = phase
	d.record["updated_at"] = nowISO()
	if err := secureio.WriteRecord(JournalPath, d.record); err != nil {
		return err
	}
	if Terminal[phase] || phase == "STOP_FOR_MANUAL" {
		id, _ := d.record["id"].(string)
		if err := secureio.WriteRecord(filepath.Join(HistoryDir, id+".json"), d.record); err != nil {
			return err
		}
	}
	return nil
}

func (d *Deployment) addStep(label, result string) {
	steps, _ := d.record["steps"].([]map[string]any)
	steps = append(steps, map[string]any{"time": nowISO(), "label": label, "result": result})
	d.record["steps"] = steps
	_ = secureio.WriteRecord(JournalPath, d.record)
}

func (d *Deployment) begin(action string, active, target *live.ActiveRecord, inst *installer.Record, baseline map[string]string) error {
	for _, dir := range []string{StateDir, BackupsDir, HistoryDir} {
		if err := secureio.MakeDirectory(dir, 0o700); err != nil {
			return err
		}
	}
	id := newID()
	beforeBytes, _ := manifest.CanonicalJSON(active)
	targetBytes, _ := manifest.CanonicalJSON(target)
	d.record = map[string]any{
		"id":            id,
		"action":        action,
		"actor_uid":     os.Getuid(),
		"began_at":      nowISO(),
		"before":        active,
		"target":        target,
		"install":       inst,
		"baseline":      baseline,
		"before_sha256": manifest.Digest(beforeBytes),
		"target_sha256": manifest.Digest(targetBytes),
		"steps":         []map[string]any{},
	}
	if err := d.setPhase("PREFLIGHT_OK"); err != nil {
		return err
	}
	if err := secureio.WriteRecord(filepath.Join(BackupsDir, id+".json"), map[string]any{
		"id":       id,
		"active":   active,
		"baseline": baseline,
		"owner":    inst.Token,
	}); err != nil {
		return err
	}
	if err := d.setPhase("SNAPSHOTTED"); err != nil {
		return err
	}
	d.Host.SetStepHook(d.addStep)
	return nil
}

func decodeAs[T any](v any) (*T, error) {
	if v == nil {
		return nil, nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var out T
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (d *Deployment) recover(maintenance bool) error {
	_ = d.setPhase("RESTORING")
	d.Host.SetStepHook(d.addStep)
	defer d.Host.SetStepHook(nil)

	failManual := func(err error) error {
		reason := "protected recovery state operation"
		if se, ok := secureio.AsStop(err); ok {
			reason = se.Detail
		}
		d.record["recovery_failure"] = reason
		_ = d.setPhase("STOP_FOR_MANUAL")
		return secureio.Stop(fmt.Sprintf("STOP_FOR_MANUAL: recovery could not be proven for %v. %s", d.record["id"], reason))
	}

	before, _ := decodeAs[live.ActiveRecord](d.record["before"])
	target, _ := decodeAs[live.ActiveRecord](d.record["target"])
	inst, err := decodeAs[installer.Record](d.record["install"])
	if err != nil || inst == nil {
		return failManual(secureio.Stop("Install metadata missing from journal."))
	}
	baseline, _ := decodeAs[map[string]string](d.record["baseline"])
	baseMap := map[string]string{}
	if baseline != nil {
		baseMap = *baseline
	}

	action, _ := d.record["action"].(string)
	if action == "install" {
		if err := installer.Deactivate(d.Host, inst); err != nil {
			return failManual(err)
		}
		if err := d.Host.AssertIdleIKE(); err != nil {
			return failManual(err)
		}
		mgr := resources.NewManager(d.Host, inst.Token, nil)
		curBase, err := mgr.Baseline()
		if err != nil || !equalStrMap(curBase, baseMap) {
			return failManual(secureio.Stop("The install baseline differs after attempted restoration."))
		}
		d.record["protected_baseline_unchanged"] = true
		if err := secureio.WriteRecord(InstalledPath, nil); err != nil {
			return failManual(err)
		}
		pkgAfter, err := d.Host.PackageState()
		if err != nil {
			return failManual(err)
		}
		audit, err := d.Host.Command("Package audit", []string{"dpkg", "--audit"}, nil, nil, 30*time.Second, false)
		if err != nil || strings.TrimSpace(audit) != "" || !equalPkgMap(inst.BeforePackageState, pkgAfter) {
			return failManual(secureio.Stop("The original dpkg state was not restored or could not be proven."))
		}
		var ret *installer.Record
		if inst.RetainedFrom != nil {
			ret = inst
		}
		if err := installer.VerifyInstallSource(d.Host, ret, pkgAfter); err != nil {
			return failManual(err)
		}
	} else if liveMaint, _ := d.record["live_maintenance"].(bool); liveMaint {
		if !maintenance {
			return failManual(secureio.Stop("Active deployment recovery needs an explicit maintenance rollback; business recovery is unverified."))
		}
		if err := d.recoverLive(before, target, inst, baseMap); err != nil {
			return failManual(err)
		}
		return d.setPhase("CONFIGURATION_RESTORED")
	} else {
		oldM, _, err := live.ManifestFromActive(before)
		if err != nil {
			return failManual(err)
		}
		reqM, _, err := live.ManifestFromActive(target)
		if err != nil {
			return failManual(err)
		}
		mgr := resources.NewManager(d.Host, inst.Token, []*manifest.DeploymentManifest{oldM, reqM})
		if action == "uninstall" {
			if err := installer.Activate(d.Host, inst); err != nil {
				return failManual(err)
			}
		}
		if err := d.Host.AssertExclusiveIKE(mgr.LinkNames()); err != nil {
			return failManual(err)
		}
		curBase, err := mgr.Preflight(oldM)
		if err != nil || !equalStrMap(curBase, baseMap) {
			return failManual(secureio.Stop("The protected host baseline changed; keep the transition guards."))
		}
		keys, err := keysFor(before)
		if err != nil {
			return failManual(err)
		}
		if err := mgr.Replace(oldM, keys, nil, false, nil); err != nil {
			return failManual(err)
		}
		obsNFT, err := mgr.Verify(oldM, baseMap, "", nil)
		if err != nil {
			return failManual(err)
		}
		if before != nil {
			before.NFTSHA256 = obsNFT
		}
		if err := secureio.WriteRecord(ActivePath, before); err != nil {
			return failManual(err)
		}
		if err := secureio.WriteRecord(InstalledPath, inst); err != nil {
			return failManual(err)
		}
	}
	return d.setPhase("RESTORED")
}

func equalPkgMap(a, b map[string]host.PackageInfo) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || bv != v {
			return false
		}
	}
	return true
}

func (d *Deployment) install(confirmed bool) (map[string]any, error) {
	if raw, err := secureio.ReadRecord(InstalledPath); err != nil {
		return nil, err
	} else if raw != nil {
		inst, err := InstalledRecord()
		if err != nil {
			return nil, err
		}
		active, err := ReadActiveRecord()
		if err != nil {
			return nil, err
		}
		m, _, pid, err := live.OwnedResources(d.Host, inst, active)
		if err != nil {
			return nil, err
		}
		sess, err := sa.OpenSession(pid, host.VICIPath)
		if err != nil {
			return nil, err
		}
		defer sess.Close()
		if err := live.VerifyInitiateConfig(sess, m); err != nil {
			return nil, err
		}
		if _, err := keysFor(active); err != nil {
			return nil, err
		}
		return map[string]any{"status": "PASS", "detail": "NOOP: owned strongSwan installation is present."}, nil
	}
	if active, err := ReadActiveRecord(); err != nil {
		return nil, err
	} else if active != nil {
		return nil, secureio.Stop("An active profile lacks its installation record.")
	}

	retJournal, retInst, err := retainedInstall()
	if err != nil {
		return nil, err
	}
	beforePkgs, err := d.Host.PackageState()
	if err != nil {
		return nil, err
	}
	if err := installer.VerifyInstallSource(d.Host, retInst, beforePkgs); err != nil {
		return nil, err
	}
	var packages map[string]string
	if retInst != nil {
		packages = retInst.Packages
	} else {
		packages, err = d.Host.APTPlan()
		if err != nil {
			return nil, err
		}
	}
	baseline, err := resources.NewManager(d.Host, "preflight", nil).Preflight(nil)
	if err != nil {
		return nil, err
	}
	mode := "install"
	outPkgs := packages
	if retInst != nil {
		mode = "reinstall"
		outPkgs = map[string]string{}
	}
	if !confirmed {
		return map[string]any{
			"status":   "PASS",
			"detail":   fmt.Sprintf("Dry-run %s; no packages installed.", mode),
			"mode":     mode,
			"packages": outPkgs,
		}, nil
	}

	binPath, err := installer.TrustedBinary()
	if err != nil {
		return nil, err
	}
	var createdDirs []string
	for _, dir := range installer.InstallDirs {
		if _, statErr := os.Stat(dir); os.IsNotExist(statErr) {
			createdDirs = append(createdDirs, dir)
		}
	}
	var retFrom *string
	if retJournal != nil {
		if id, ok := retJournal["id"].(string); ok {
			retFrom = &id
		}
	}
	inst := &installer.Record{
		Token:              newID(),
		Binary:             binPath,
		Packages:           packages,
		BeforePackageState: beforePkgs,
		RetainedFrom:       retFrom,
		CreatedDirs:        createdDirs,
	}
	if retJournal != nil && retFrom != nil {
		arch := filepath.Join(HistoryDir, *retFrom+".json")
		if r, _ := secureio.ReadRecord(arch); r == nil {
			_ = secureio.WriteRecord(arch, retJournal)
		}
		if r, _ := secureio.ReadRecord(RetainedPath); r == nil {
			_ = secureio.WriteRecord(RetainedPath, map[string]any{"uninstall_id": *retFrom})
		}
	}
	if err := d.begin("install", nil, nil, inst, baseline); err != nil {
		return nil, err
	}
	defer d.Host.SetStepHook(nil)

	runErr := func() error {
		if err := d.setPhase("STAGED"); err != nil {
			return err
		}
		if err := d.setPhase("APPLYING"); err != nil {
			return err
		}
		if retInst == nil {
			if err := installer.InstallPackages(d.Host, inst); err != nil {
				return err
			}
		} else {
			curPkgs, err := d.Host.PackageState()
			if err != nil {
				return err
			}
			if err := installer.VerifyInstallSource(d.Host, retInst, curPkgs); err != nil {
				return err
			}
		}
		if err := installer.Activate(d.Host, inst); err != nil {
			return err
		}
		if err := installer.AssertFiles(inst, false); err != nil {
			return err
		}
		if err := d.Host.AssertExclusiveIKE(map[string]struct{}{}); err != nil {
			return err
		}
		vp, err := installer.VendorPlugins()
		if err != nil {
			return err
		}
		inst.VendorPlugins = vp
		if retInst != nil {
			curPkgs, err := d.Host.PackageState()
			if err != nil || !equalPkgMap(curPkgs, beforePkgs) {
				return secureio.Stop("Reinstallation changed the dpkg inventory.")
			}
		}
		afterBase, err := resources.NewManager(d.Host, inst.Token, nil).Baseline()
		if err != nil || !equalStrMap(afterBase, baseline) {
			return secureio.Stop("Installation changed a protected host baseline.")
		}
		if err := d.setPhase("VERIFIED"); err != nil {
			return err
		}
		if err := secureio.WriteRecord(InstalledPath, inst); err != nil {
			return err
		}
		return d.setPhase("COMMITTED")
	}()
	if runErr != nil {
		reason := "protected install state operation"
		if se, ok := secureio.AsStop(runErr); ok {
			reason = se.Detail
		}
		d.record["failure"] = reason
		_ = d.setPhase("FAILED")
		if recErr := d.recover(false); recErr != nil {
			return nil, recErr
		}
		return nil, secureio.Stop(fmt.Sprintf("Install failed and protected state was restored. %s Journal %v.", reason, d.record["id"]))
	}
	detail := "Installed the owned Ubuntu strongSwan service."
	if retInst != nil {
		detail = "Reactivated the retained Ubuntu strongSwan service."
	}
	return map[string]any{
		"status":             "PASS",
		"detail":             detail,
		"mode":               mode,
		"packages":           outPkgs,
		"journal":            d.record["id"],
		"baseline_unchanged": true,
	}, nil
}

func (d *Deployment) change(action string, prof *profile.Profile, identifier string, confirmed, maintenance bool) (map[string]any, error) {
	inst, err := InstalledRecord()
	if err != nil {
		return nil, err
	}
	active, err := ReadActiveRecord()
	if err != nil {
		return nil, err
	}
	beforeM, _, err := live.ManifestFromActive(active)
	if err != nil {
		return nil, err
	}
	var targetM *manifest.DeploymentManifest
	var requested *live.ActiveRecord
	var backupState map[string]any

	switch action {
	case "apply":
		backupState = manifest.ExternalBackup(prof)
		targetM, err = manifest.BuildManifest(prof)
		if err != nil {
			return nil, err
		}
		if beforeM != nil && targetM.EventID != beforeM.EventID {
			return nil, secureio.Stop("An existing active profile cannot be silently switched.")
		}
		requested = &live.ActiveRecord{Profile: prof.Raw}
	case "rollback":
		saved, err := readBackup(identifier)
		if err != nil {
			return nil, err
		}
		if saved["owner"] != inst.Token {
			return nil, secureio.Stop("The backup belongs to a different installation.")
		}
		requested, err = decodeAs[live.ActiveRecord](saved["active"])
		if err != nil {
			return nil, err
		}
		var reqProf *profile.Profile
		targetM, reqProf, err = live.ManifestFromActive(requested)
		if err != nil {
			return nil, err
		}
		if reqProf != nil {
			backupState = manifest.ExternalBackup(reqProf)
		}
	case "uninstall":
		requested = nil
		targetM = nil
	}

	mgr := resources.NewManager(d.Host, inst.Token, []*manifest.DeploymentManifest{beforeM, targetM})
	ownedNames := make(map[string]struct{})
	if beforeM != nil {
		for _, l := range beforeM.Links {
			ownedNames[l.Name()] = struct{}{}
		}
	}
	pid, err := d.Host.AssertDaemon(ownedNames)
	if err != nil {
		return nil, err
	}
	baseline, err := mgr.Preflight(targetM)
	if err != nil {
		return nil, err
	}
	if err := live.AssertBaseline(active, baseline); err != nil {
		return nil, err
	}
	liveSnap, err := sa.Inventory(d.Host, beforeM, pid, 4, 200*time.Millisecond)
	if err != nil {
		return nil, err
	}
	nftSHA := ""
	if active != nil {
		nftSHA = active.NFTSHA256
	}
	if _, err := mgr.Verify(beforeM, baseline, nftSHA, liveSnap); err != nil {
		return nil, err
	}

	res := map[string]any{
		"status": "PASS",
		"diff":   manifest.ResourceDiff(beforeM, targetM),
	}
	if backupState != nil {
		res["backup"] = backupState
	}
	if len(liveSnap.IKES) > 0 && beforeM != nil {
		sites := make([]string, 0, len(beforeM.Links))
		for _, l := range beforeM.Links {
			sites = append(sites, l.SiteID)
		}
		res["maintenance"] = map[string]any{
			"required_for_changes": true,
			"interruption":         "PROJECT_TUNNELS_MAY_DISCONNECT",
			"sites":                sites,
			"protected_cidrs":      resources.NetworkScope([]*manifest.DeploymentManifest{beforeM, targetM}),
		}
	}
	if !confirmed {
		res["detail"] = "Dry-run; host resources and credentials were not changed."
		return res, nil
	}

	if _, err := keysFor(active); err != nil {
		return nil, err
	}
	var keys map[string][]byte
	if action == "apply" {
		keys, err = secureio.ReadKeys(prof)
		if err != nil {
			return nil, err
		}
		requested.Keys = keyDigests(keys)
		if active != nil {
			ab, _ := manifest.CanonicalJSON(active.Profile)
			pb, _ := manifest.CanonicalJSON(prof.Raw)
			if string(ab) == string(pb) && equalStrMap(active.Keys, requested.Keys) {
				delete(res, "maintenance")
				res["detail"] = "NOOP: the active profile and live resources match."
				return res, nil
			}
		}
	} else {
		keys, err = keysFor(requested)
		if err != nil {
			return nil, err
		}
	}
	if len(liveSnap.IKES) > 0 && !maintenance {
		return nil, secureio.Stop("Active project SAs require --maintenance for a configuration change.")
	}
	if len(liveSnap.IKES) == 0 {
		if err := d.Host.AssertExclusiveIKE(ownedNames); err != nil {
			return nil, err
		}
	}

	if err := d.begin(action, active, requested, inst, baseline); err != nil {
		return nil, err
	}
	defer d.Host.SetStepHook(nil)

	runErr := func() error {
		if len(liveSnap.IKES) > 0 && beforeM != nil {
			d.record["live_maintenance"] = true
			var liveSites []string
			for _, l := range beforeM.Links {
				if ike := liveSnap.Get(l.Name()); ike != nil && ike.Child != nil {
					liveSites = append(liveSites, l.SiteID)
				}
			}
			d.record["live_sites"] = liveSites
		}
		if err := d.setPhase("STAGED"); err != nil {
			return err
		}
		if err := d.setPhase("APPLYING"); err != nil {
			return err
		}
		var obsNFT string
		if len(liveSnap.IKES) > 0 {
			obsNFT, err = d.replaceLive(mgr, beforeM, targetM, keys, pid, liveSnap, baseline)
		} else {
			if err := mgr.Replace(targetM, keys, nil, false, nil); err != nil {
				return err
			}
			obsNFT, err = mgr.Verify(targetM, baseline, "", nil)
		}
		if err != nil {
			return err
		}
		if requested != nil {
			requested.NFTSHA256 = obsNFT
			requested.HostBaseline = baseline
		}
		if action == "uninstall" {
			if err := installer.Deactivate(d.Host, inst); err != nil {
				return err
			}
			if len(liveSnap.IKES) > 0 {
				if err := mgr.Finish(nil); err != nil {
					return err
				}
			}
			afterBase, err := mgr.Baseline()
			if err != nil || !equalStrMap(afterBase, baseline) {
				return secureio.Stop("Uninstall changed a protected host baseline.")
			}
			if err := secureio.WriteRecord(RetainedPath, map[string]any{"uninstall_id": d.record["id"]}); err != nil {
				return err
			}
			if err := secureio.WriteRecord(ActivePath, nil); err != nil {
				return err
			}
			if err := secureio.WriteRecord(InstalledPath, nil); err != nil {
				return err
			}
			if len(liveSnap.IKES) > 0 {
				_ = secureio.WriteRecord(ReconnectPath, nil)
			}
		} else {
			if err := secureio.WriteRecord(ActivePath, requested); err != nil {
				return err
			}
			if len(liveSnap.IKES) > 0 && targetM != nil {
				liveSet := make(map[string]bool)
				for _, s := range stringSliceFromAny(d.record["live_sites"]) {
					liveSet[s] = true
				}
				var keep []string
				for _, l := range targetM.Links {
					if liveSet[l.SiteID] {
						keep = append(keep, l.SiteID)
					}
				}
				_ = rememberSites(inst, requested, keep)
			}
		}
		if err := d.setPhase("VERIFIED"); err != nil {
			return err
		}
		return d.setPhase("COMMITTED")
	}()
	if runErr != nil {
		reason := "protected host state operation"
		if se, ok := secureio.AsStop(runErr); ok {
			reason = se.Detail
		}
		d.record["failure"] = reason
		_ = d.setPhase("FAILED")
		if recErr := d.recover(false); recErr != nil {
			return nil, recErr
		}
		return nil, secureio.Stop(fmt.Sprintf("%s failed; pre-state restored. %s Journal %v.", action, reason, d.record["id"]))
	}
	if action == "rollback" {
		res["configuration_restored"] = true
		res["data_path_restored"] = map[string]any{"status": "SKIP", "reason_code": "NO_PROBE"}
	}
	res["detail"] = "COMMITTED: project resources verified."
	res["backup_id"] = d.record["id"]
	res["baseline_unchanged"] = true
	res["site_to_site"] = map[string]any{"status": "SKIP"}
	return res, nil
}

func (d *Deployment) replaceLive(mgr *resources.Manager, before, target *manifest.DeploymentManifest, keys map[string][]byte, pid int, liveSnap *sa.Snapshot, baseline map[string]string) (string, error) {
	if err := mgr.Guard(before); err != nil {
		return "", err
	}
	d.addStep("VICI targeted drain", "STARTED")
	reverified, err := live.DrainLinks(d.Host, before, pid, liveSnap, 2)
	if err != nil {
		return "", err
	}
	if len(reverified) > 0 {
		d.record["sa_reverified"] = reverified
	}
	d.addStep("VICI targeted drain", "DONE")

	loader := func(model *manifest.DeploymentManifest, creds map[string][]byte) error {
		d.addStep("VICI scoped load", "STARTED")
		if err := live.ConfigureScoped(d.Host, pid, mgr.Candidates, model, creds); err != nil {
			return err
		}
		d.addStep("VICI scoped load", "DONE")
		return nil
	}
	if err := mgr.Replace(target, keys, loader, true, target); err != nil {
		return "", err
	}
	if target == nil {
		return "", nil
	}
	liveSet := make(map[string]bool)
	for _, s := range stringSliceFromAny(d.record["live_sites"]) {
		liveSet[s] = true
	}
	for _, l := range target.Links {
		if liveSet[l.SiteID] {
			d.addStep("VICI targeted reconnect", "STARTED")
			if _, err := live.InitiateLink(d.Host, target, pid, l); err != nil {
				return "", err
			}
			d.addStep("VICI targeted reconnect", "DONE")
		}
	}
	snapLive, err := sa.Inventory(d.Host, target, pid, 4, 200*time.Millisecond)
	if err != nil {
		return "", err
	}
	if err := mgr.Finish(target); err != nil {
		return "", err
	}
	return mgr.Verify(target, baseline, "", snapLive)
}

func (d *Deployment) recoverLive(before, target *live.ActiveRecord, inst *installer.Record, baseline map[string]string) error {
	origM, _, err := live.ManifestFromActive(before)
	if err != nil {
		return err
	}
	reqM, _, err := live.ManifestFromActive(target)
	if err != nil {
		return err
	}
	mgr := resources.NewManager(d.Host, inst.Token, []*manifest.DeploymentManifest{origM, reqM})
	if d.record["action"] == "uninstall" {
		if err := installer.Activate(d.Host, inst); err != nil {
			return err
		}
	}
	pid, err := d.Host.AssertDaemon(mgr.LinkNames())
	if err != nil {
		return err
	}
	curBase, err := mgr.Preflight(origM)
	if err != nil || !equalStrMap(curBase, baseline) {
		return secureio.Stop("The protected baseline changed during the maintenance transaction.")
	}
	var matchedModel *manifest.DeploymentManifest
	var liveSnap *sa.Snapshot
	for _, cand := range []*manifest.DeploymentManifest{origM, reqM} {
		if snap, ierr := sa.Inventory(d.Host, cand, pid, 4, 200*time.Millisecond); ierr == nil {
			matchedModel = cand
			liveSnap = snap
			break
		}
	}
	if liveSnap == nil {
		return secureio.Stop("Current SAs cannot be attributed to either journaled manifest.")
	}
	keys, err := keysFor(before)
	if err != nil {
		return err
	}
	obsNFT, err := d.replaceLive(mgr, matchedModel, origM, keys, pid, liveSnap, baseline)
	if err != nil {
		return err
	}
	if before != nil {
		before.NFTSHA256 = obsNFT
		before.HostBaseline = baseline
	}
	if err := secureio.WriteRecord(ActivePath, before); err != nil {
		return err
	}
	if err := secureio.WriteRecord(InstalledPath, inst); err != nil {
		return err
	}
	_ = rememberSites(inst, before, stringSliceFromAny(d.record["live_sites"]))
	d.record["configuration_restored"] = true
	d.record["data_path_restored"] = map[string]any{"status": "SKIP", "reason_code": "NO_PROBE"}
	return nil
}

func stringSliceFromAny(v any) []string {
	switch tv := v.(type) {
	case []string:
		return tv
	case []any:
		out := make([]string, 0, len(tv))
		for _, item := range tv {
			out = append(out, fmt.Sprint(item))
		}
		return out
	default:
		return nil
	}
}

func (d *Deployment) backup(confirmed bool) (map[string]any, error) {
	inst, err := InstalledRecord()
	if err != nil {
		return nil, err
	}
	active, err := ReadActiveRecord()
	if err != nil {
		return nil, err
	}
	m, _, err := live.ManifestFromActive(active)
	if err != nil {
		return nil, err
	}
	mgr := resources.NewManager(d.Host, inst.Token, []*manifest.DeploymentManifest{m})
	baseline, err := mgr.Preflight(m)
	if err != nil {
		return nil, err
	}
	if _, _, _, err := live.OwnedResources(d.Host, inst, active); err != nil {
		return nil, err
	}
	if !confirmed {
		return map[string]any{"status": "PASS", "detail": "Dry-run; no snapshot written."}, nil
	}
	if _, err := keysFor(active); err != nil {
		return nil, err
	}
	id := newID()
	if err := secureio.WriteRecord(filepath.Join(BackupsDir, id+".json"), map[string]any{
		"id":       id,
		"active":   active,
		"baseline": baseline,
		"owner":    inst.Token,
	}); err != nil {
		return nil, err
	}
	return map[string]any{"status": "PASS", "detail": "Project snapshot verified.", "backup_id": id}, nil
}

func (d *Deployment) saOp(action, site, kind string, confirmed bool) (map[string]any, error) {
	inst, err := InstalledRecord()
	if err != nil {
		return nil, err
	}
	active, err := ReadActiveRecord()
	if err != nil {
		return nil, err
	}
	m, liveSnap, pid, err := live.OwnedResources(d.Host, inst, active)
	if err != nil {
		return nil, err
	}
	var link *manifest.Link
	if m != nil {
		for i := range m.Links {
			if m.Links[i].SiteID == site {
				link = &m.Links[i]
				break
			}
		}
	}
	if link == nil {
		return nil, secureio.Stop("Select a site in the current active profile.")
	}
	old := liveSnap.Get(link.Name())
	if action == "rekey" && (old == nil || old.Child == nil) {
		return nil, secureio.Stop("Rekey requires a verified established IKE and CHILD SA.")
	}
	plan := map[string]any{"status": "PASS", "site_id": site, "data_path": map[string]any{"status": "SKIP"}}
	if !confirmed {
		plan["detail"] = "Dry-run; no SA was changed."
		return plan, nil
	}
	if _, err := keysFor(active); err != nil {
		return nil, err
	}
	id := newID()
	jPath := filepath.Join(HistoryDir, id+".json")
	audit := map[string]any{
		"id":         id,
		"site_id":    site,
		"action":     action,
		"owner":      inst.Token,
		"time":       nowISO(),
		"phase":      "STARTED",
		"rekey_kind": kind,
	}
	_ = secureio.WriteRecord(jPath, audit)
	var opErr error
	if action == "rekey" {
		_, opErr = live.RekeyLink(d.Host, m, pid, *link, old, kind)
	} else {
		if old == nil || old.Child == nil {
			_, opErr = live.InitiateLink(d.Host, m, pid, *link)
		}
		if opErr == nil {
			desired := reconnectSites(inst, active)
			desired[site] = true
			sites := make([]string, 0, len(desired))
			for s := range desired {
				sites = append(sites, s)
			}
			_ = rememberSites(inst, active, sites)
		}
	}
	if opErr != nil {
		reason := "UNVERIFIED_SA"
		if se, ok := secureio.AsStop(opErr); ok && se.Reason != "" {
			reason = se.Reason
		}
		audit["phase"] = "FAILED"
		audit["reason_code"] = reason
		_ = secureio.WriteRecord(jPath, audit)
		return nil, opErr
	}
	audit["phase"] = "VERIFIED"
	_ = secureio.WriteRecord(jPath, audit)
	plan["journal"] = id
	plan["detail"] = "Verified target CHILD. Business untested."
	return plan, nil
}

type DispatchOptions struct {
	Action      string
	Confirmed   bool
	ConfigPath  string
	BackupID    string
	Maintenance bool
	Site        string
	Kind        string
}

func (d *Deployment) Dispatch(opts DispatchOptions) (map[string]any, error) {
	if _, err := d.Host.Probe(); err != nil {
		return nil, err
	}
	if !opts.Confirmed {
		return d.dispatchInner(opts)
	}
	lock, err := secureio.AcquireLock(LockPath)
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	return d.dispatchInner(opts)
}

func (d *Deployment) dispatchInner(opts DispatchOptions) (map[string]any, error) {
	pending, err := ReadJournalRecord()
	if err != nil {
		return nil, err
	}
	if pending != nil {
		phase, _ := pending["phase"].(string)
		if !Terminal[phase] {
			pid, _ := pending["id"].(string)
			if opts.Action != "rollback" || opts.BackupID != pid {
				return nil, secureio.Stop(fmt.Sprintf("Unfinished transaction; inspect and use rollback --to %s.", pid))
			}
			if phase != "PREFLIGHT_OK" {
				if _, err := readBackup(opts.BackupID); err != nil {
					return nil, err
				}
			}
			if !opts.Confirmed {
				return map[string]any{"status": "PASS", "detail": "Dry-run; pending recovery is still blocked."}, nil
			}
			if lm, _ := pending["live_maintenance"].(bool); lm && !opts.Maintenance {
				return nil, secureio.Stop("Use --maintenance to recover this interrupted live transaction.")
			}
			d.record = pending
			if err := d.recover(opts.Maintenance); err != nil {
				return nil, err
			}
			if d.record["phase"] == "CONFIGURATION_RESTORED" {
				return map[string]any{
					"status":                 "PASS",
					"detail":                 "Configuration and owned SA recovery verified; business untested.",
					"configuration_restored": true,
					"data_path_restored":     d.record["data_path_restored"],
				}, nil
			}
			return map[string]any{"status": "PASS", "detail": "RESTORED: interrupted transaction recovered."}, nil
		}
	}

	switch opts.Action {
	case "install":
		return d.install(opts.Confirmed)
	case "backup":
		return d.backup(opts.Confirmed)
	case "reconnect":
		if !opts.Confirmed {
			return map[string]any{"status": "PASS", "detail": "Dry-run reconnect; no SA was changed."}, nil
		}
		inst, err := InstalledRecord()
		if err != nil {
			return nil, err
		}
		active, err := ReadActiveRecord()
		if err != nil {
			return nil, err
		}
		if _, err := keysFor(active); err != nil {
			return nil, err
		}
		return live.ReconnectOwned(d.Host, inst, active, opts.Site, 3, 400*time.Millisecond)
	case "initiate", "rekey":
		return d.saOp(opts.Action, opts.Site, opts.Kind, opts.Confirmed)
	default:
		var prof *profile.Profile
		if opts.Action == "apply" {
			prof, err = readProfileForApply(opts.ConfigPath, opts.Confirmed)
			if err != nil {
				return nil, err
			}
		}
		return d.change(opts.Action, prof, opts.BackupID, opts.Confirmed, opts.Maintenance)
	}
}

func reconnectSites(inst *installer.Record, active *live.ActiveRecord) map[string]bool {
	out := make(map[string]bool)
	if active == nil {
		return out
	}
	raw, err := secureio.ReadRecord(ReconnectPath)
	if err != nil || raw == nil {
		return out
	}
	m, _ := raw.(map[string]any)
	b, _ := manifest.CanonicalJSON(active.Profile)
	if m["owner"] == inst.Token && m["profile_sha256"] == manifest.Digest(b) {
		for _, s := range stringSliceFromAny(m["sites"]) {
			out[s] = true
		}
	}
	return out
}

func rememberSites(inst *installer.Record, active *live.ActiveRecord, sites []string) error {
	if active == nil {
		return nil
	}
	uniq := make(map[string]struct{}, len(sites))
	for _, s := range sites {
		uniq[s] = struct{}{}
	}
	sorted := make([]string, 0, len(uniq))
	for s := range uniq {
		sorted = append(sorted, s)
	}
	sort.Strings(sorted)
	b, _ := manifest.CanonicalJSON(active.Profile)
	return secureio.WriteRecord(ReconnectPath, map[string]any{
		"owner":          inst.Token,
		"profile_sha256": manifest.Digest(b),
		"sites":          sorted,
	})
}

// Boot runs the early fail-closed guard or post-network restore boot phase.
func Boot(phase string) error {
	if phase != "guard" && phase != "restore" {
		return secureio.Stop("Invalid boot phase.")
	}
	h := host.NewOSHost()
	if _, err := h.Probe(); err != nil {
		return err
	}
	lock, err := secureio.AcquireLock(LockPath)
	if err != nil {
		return err
	}
	defer lock.Close()

	inst, _ := decodeRecord[installer.Record](InstalledPath)
	pending, err := ReadJournalRecord()
	if err != nil {
		return err
	}
	active, err := ReadActiveRecord()
	if err != nil {
		return err
	}
	interrupted := false
	if pending != nil {
		p, _ := pending["phase"].(string)
		interrupted = !Terminal[p]
	}
	activeM, _, err := live.ManifestFromActive(active)
	if err != nil {
		return err
	}
	candidates := []*manifest.DeploymentManifest{activeM}
	if interrupted {
		bAct, _ := decodeAs[live.ActiveRecord](pending["before"])
		tAct, _ := decodeAs[live.ActiveRecord](pending["target"])
		bM, _, _ := live.ManifestFromActive(bAct)
		tM, _, _ := live.ManifestFromActive(tAct)
		candidates = append(candidates, bM, tM)
		if inst == nil {
			inst, _ = decodeAs[installer.Record](pending["install"])
		}
	}
	if interrupted && phase != "guard" {
		return secureio.Stop("An unfinished journal requires explicit rollback; boot guards remain active.")
	}
	if inst == nil || len(resources.NetworkScope(candidates)) == 0 {
		return nil
	}
	mgr := resources.NewManager(h, inst.Token, candidates)
	if phase == "guard" {
		if err := h.AssertNoOtherIKE(); err != nil {
			return err
		}
		if err := mgr.Guard(nil); err != nil {
			return err
		}
		return mgr.PurgeRuntime()
	}
	if _, err := InstalledRecord(); err != nil {
		return err
	}
	if err := h.AssertExclusiveIKE(mgr.LinkNames()); err != nil {
		return err
	}
	baseline, err := mgr.Preflight(activeM)
	if err != nil {
		return err
	}
	if err := live.AssertBaseline(active, baseline); err != nil {
		return err
	}
	keys, err := keysFor(active)
	if err != nil {
		return err
	}
	if err := mgr.Replace(activeM, keys, nil, false, nil); err != nil {
		return err
	}
	nftSHA := ""
	if active != nil {
		nftSHA = active.NFTSHA256
	}
	if _, err := mgr.Verify(activeM, baseline, nftSHA, nil); err != nil {
		return err
	}
	wanted := reconnectSites(inst, active)
	if len(wanted) > 0 && activeM != nil {
		pid, err := h.AssertDaemon(mgr.LinkNames())
		if err != nil {
			return err
		}
		var failed []string
		for _, l := range activeM.Links {
			if wanted[l.SiteID] {
				if _, err := live.InitiateLink(h, activeM, pid, l); err != nil {
					failed = append(failed, l.SiteID)
				}
			}
		}
		if len(failed) > 0 {
			return secureio.Stop("An explicitly requested site did not reconnect; guards remain.")
		}
	}
	return nil
}

// ApplyHubXFRMGate sets project-owned XFRM interfaces down while backup-locked
// and restores inner routes upon unlock (preventing premature Hillstone failback).
func ApplyHubXFRMGate(locked bool, h host.Runner) (map[string]any, error) {
	if h == nil {
		h = host.NewOSHost()
	}
	if _, err := h.Probe(); err != nil {
		return nil, err
	}
	inst, err := InstalledRecord()
	if err != nil {
		return nil, err
	}
	active, err := ReadActiveRecord()
	if err != nil {
		return nil, err
	}
	if active == nil {
		return nil, secureio.Stop("No active Hub profile is deployed for XFRM gate control.")
	}
	m, _, err := live.ManifestFromActive(active)
	if err != nil {
		return nil, err
	}
	alias := "ipsecvpn:" + inst.Token
	linkRows, err := h.IP("-details", "link", "show")
	if err != nil {
		return nil, err
	}
	byName := make(map[string]map[string]any, len(linkRows))
	for _, row := range linkRows {
		if n, ok := row["ifname"].(string); ok {
			byName[n] = row
		}
	}
	state := "up"
	gateLabel := "UNLOCKED_UP"
	if locked {
		state = "down"
		gateLabel = "LOCKED_DOWN"
	}
	changed := make([]string, 0, len(m.Links))
	for _, l := range m.Links {
		row, ok := byName[l.Name()]
		if !ok || row["ifalias"] != alias {
			return nil, secureio.Stop("Refusing XFRM gate operation on an unowned interface.")
		}
		if _, err := h.Command("XFRM gate "+state, []string{"ip", "link", "set", "dev", l.Name(), state}, nil, nil, 30*time.Second, true); err != nil {
			return nil, err
		}
		if !locked {
			for _, cidr := range l.RemoteTS {
				if _, err := h.Command("XFRM gate route restore", []string{
					"ip", "-4", "route", "replace", cidr, "dev", l.Name(),
					"table", "main", "proto", manifest.RouteProtocol, "metric", strconv.Itoa(l.RoutePriority),
				}, nil, nil, 30*time.Second, true); err != nil {
					return nil, err
				}
			}
		}
		changed = append(changed, l.Name())
	}
	return map[string]any{"gate": gateLabel, "interfaces": changed}, nil
}
