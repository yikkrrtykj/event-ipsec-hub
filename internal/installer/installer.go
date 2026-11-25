package installer

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/yikkrrtykj/event-ipsec-hub/internal/host"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/manifest"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/secureio"
)

const (
	StateDir = "/var/lib/ipsecvpn"
	UnitDir  = "/etc/systemd/system"
	Guard    = "ipsecvpn-guard.service"
	Restore  = "ipsecvpn-restore.service"
)

var (
	UnitFiles = []string{
		host.PrivateConf,
		host.DropIn,
		filepath.Join(UnitDir, Guard),
		filepath.Join(UnitDir, Restore),
	}
	ConfigPaths = []string{"/etc/strongswan.conf", "/etc/strongswan.d", "/etc/swanctl"}
	InstallDirs = []string{filepath.Dir(host.DropIn), filepath.Dir(host.PrivateConf)}
	pidRE       = regexp.MustCompile(`pid=(\d+),`)
)

// Record captures the persisted owned strongSwan installation metadata.
type Record struct {
	Token              string                      `json:"token"`
	Binary             string                      `json:"binary"`
	Packages           map[string]string           `json:"packages"`
	BeforePackageState map[string]host.PackageInfo `json:"before_package_state,omitempty"`
	RetainedFrom       *string                     `json:"retained_from"`
	CreatedDirs        []string                    `json:"created_dirs"`
	VendorPlugins      map[string]string           `json:"vendor_plugins,omitempty"`
}

// InstallFiles renders the strongSwan private config, systemd drop-in, and Go boot units.
func InstallFiles(binary string) map[string][]byte {
	daemon := fmt.Sprintf(`charon-systemd {
    load_modular = yes
    install_routes = no
    routing_table = 0
    install_virtual_ip = no
    plugins {
        include /etc/strongswan.d/charon/*.conf
        kernel-netlink {
            install_routes_xfrmi = no
        }
        socket-default {
            use_ipv6 = no
        }
        vici {
            socket = %s
        }
    }
}
`, host.SocketURI)

	dropin := fmt.Sprintf("[Service]\nEnvironment=STRONGSWAN_CONF=%s\nExecStartPost=\n", host.PrivateConf)
	guard := fmt.Sprintf(`[Unit]
Description=ipsecVPN early fail-closed network guard
DefaultDependencies=no
After=local-fs.target nftables.service
Wants=network-pre.target
Before=network-pre.target shutdown.target
Conflicts=shutdown.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=%s boot guard

[Install]
WantedBy=multi-user.target
`, binary)

	restore := fmt.Sprintf(`[Unit]
Description=ipsecVPN restore committed lab configuration
Requires=%s %s
Wants=network-online.target
After=%s network-online.target %s ssh.service ssh.socket
PartOf=%s

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=%s boot restore

[Install]
WantedBy=multi-user.target
`, Guard, host.Unit, Guard, host.Unit, host.Unit, binary)

	return map[string][]byte{
		UnitFiles[0]: []byte(daemon),
		UnitFiles[1]: []byte(dropin),
		UnitFiles[2]: []byte(guard),
		UnitFiles[3]: []byte(restore),
	}
}

func AssertFiles(rec *Record, missingOK bool) error {
	files := InstallFiles(rec.Binary)
	for _, p := range UnitFiles {
		mode := uint32(0o644)
		if p == UnitFiles[0] {
			mode = 0o600
		}
		cur, err := secureio.ReadFile(p, mode, secureio.DefaultFileLimit, nil)
		if err != nil {
			if os.IsNotExist(err) && missingOK {
				continue
			}
			return secureio.Stop("An installed project service file is missing.")
		}
		if manifest.Digest(cur) != manifest.Digest(files[p]) {
			return secureio.Stop("An installed project service file has drifted.")
		}
	}
	return nil
}

func VendorPlugins() (map[string]string, error) {
	dir := "/etc/strongswan.d/charon"
	fd, err := secureio.TrustedDir(dir, nil)
	if err != nil {
		return nil, err
	}
	_ = os.NewFile(uintptr(fd), dir).Close()
	entries, err := filepath.Glob(filepath.Join(dir, "*.conf"))
	if err != nil {
		return nil, secureio.Stop("Could not inspect strongSwan charon plugins.")
	}
	sort.Strings(entries)
	out := make(map[string]string, len(entries))
	for _, p := range entries {
		data, err := secureio.ReadFile(p, 0o644, secureio.DefaultFileLimit, nil)
		if err != nil {
			return nil, err
		}
		out[filepath.Base(p)] = manifest.Digest(data)
	}
	return out, nil
}

func pathExists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

func VerifyInstallSource(h host.Runner, retained *Record, pkgState map[string]host.PackageInfo) error {
	if err := h.AssertIdleIKE(); err != nil {
		return err
	}
	extra := append([]string{}, UnitFiles...)
	extra = append(extra,
		"/etc/ipsec.conf",
		"/etc/ipsec.secrets",
		filepath.Join(UnitDir, host.Unit),
		filepath.Join("/run/systemd/system", host.Unit),
		filepath.Join("/run/systemd/system", host.Unit+".d"),
	)
	for _, p := range extra {
		if pathExists(p) {
			return secureio.Stop("An existing IKE configuration or reserved service path is unowned.")
		}
	}
	for _, u := range []string{Guard, Restore} {
		ls, err := h.Service(u, "LoadState")
		if err != nil || ls != "not-found" {
			return secureio.Stop("A reserved boot service is unowned.")
		}
	}
	audit, err := h.Command("Package audit", []string{"dpkg", "--audit"}, nil, nil, 30*time.Second, false)
	if err != nil || strings.TrimSpace(audit) != "" {
		return secureio.Stop("The VM already has an incomplete package transaction.")
	}

	related := make(map[string]struct{})
	for name := range pkgState {
		if strings.Contains(name, "strongswan") || name == "charon-systemd" || strings.HasPrefix(name, "libcharon-") {
			related[name] = struct{}{}
		}
	}
	if retained == nil {
		ls, err := h.Service(host.Unit, "LoadState")
		if err != nil {
			return err
		}
		if len(related) > 0 || ls != "not-found" || pathExists(filepath.Dir(host.DropIn)) {
			return secureio.Stop("An existing strongSwan package or configuration is unowned.")
		}
		for _, cp := range ConfigPaths {
			if pathExists(cp) {
				return secureio.Stop("An existing strongSwan package or configuration is unowned.")
			}
		}
		return nil
	}

	for _, pkg := range host.Packages {
		if _, ok := retained.Packages[pkg]; !ok {
			return secureio.Stop("Retained package versions or states differ from the committed install.")
		}
	}
	for name := range related {
		if _, ok := retained.Packages[name]; !ok {
			return secureio.Stop("Retained package versions or states differ from the committed install.")
		}
	}
	for name, ver := range retained.Packages {
		st, ok := pkgState[name]
		if !ok || st.Version != ver || st.Status != "ii " {
			return secureio.Stop("Retained package versions or states differ from the committed install.")
		}
	}
	frag, _ := h.Service(host.Unit, "FragmentPath")
	ufState, _ := h.Service(host.Unit, "UnitFileState")
	dropins, _ := h.Service(host.Unit, "DropInPaths")
	needReload, _ := h.Service(host.Unit, "NeedDaemonReload")
	if !host.VendorUnits[frag] || ufState != "disabled" || dropins != "" || needReload != "no" {
		return secureio.Stop("The retained strongSwan unit is no longer the disabled distribution unit.")
	}

	pkgNames := make([]string, 0, len(retained.Packages))
	for k := range retained.Packages {
		pkgNames = append(pkgNames, k)
	}
	sort.Strings(pkgNames)
	verifyOut, err := h.Command("Distribution file verification", append([]string{"dpkg", "--verify"}, pkgNames...), nil, nil, 30*time.Second, false)
	if err != nil || strings.TrimSpace(verifyOut) != "" {
		return secureio.Stop("Retained strongSwan distribution files have changed.")
	}
	return nil
}

func InstallPackages(h host.Runner, rec *Record) error {
	if err := AssertFiles(rec, true); err != nil {
		return err
	}
	if err := secureio.MakeDirectory(filepath.Dir(host.DropIn), 0o755); err != nil {
		return err
	}
	if err := secureio.MakeDirectory(filepath.Dir(host.PrivateConf), 0o755); err != nil {
		return err
	}
	files := InstallFiles(rec.Binary)
	if err := secureio.AtomicWrite(UnitFiles[0], files[UnitFiles[0]], 0o600); err != nil {
		return err
	}
	if err := secureio.AtomicWrite(UnitFiles[1], files[UnitFiles[1]], 0o644); err != nil {
		return err
	}
	if _, err := h.Command("Reload unit definitions", []string{"systemctl", "daemon-reload"}, nil, nil, 30*time.Second, true); err != nil {
		return err
	}
	args := []string{"apt-get", "-y", "--no-install-recommends", "--no-upgrade", "--no-remove", "install"}
	for _, pkg := range host.Packages {
		args = append(args, pkg+"="+rec.Packages[pkg])
	}
	if _, err := h.Command("APT install", args, nil, nil, 600*time.Second, true); err != nil {
		return err
	}
	after, err := h.PackageState()
	if err != nil {
		return err
	}
	expected := make(map[string]host.PackageInfo, len(rec.BeforePackageState)+len(rec.Packages))
	for k, v := range rec.BeforePackageState {
		expected[k] = v
	}
	for k, ver := range rec.Packages {
		expected[k] = host.PackageInfo{Version: ver, Status: "ii "}
	}
	audit, err := h.Command("Package audit", []string{"dpkg", "--audit"}, nil, nil, 30*time.Second, false)
	if err != nil || strings.TrimSpace(audit) != "" || !equalPkgState(after, expected) {
		return secureio.Stop("The full dpkg state differs from the preflight plan.")
	}
	return nil
}

func Activate(h host.Runner, rec *Record) error {
	if err := AssertFiles(rec, true); err != nil {
		return err
	}
	if err := secureio.MakeDirectory(filepath.Dir(host.DropIn), 0o755); err != nil {
		return err
	}
	files := InstallFiles(rec.Binary)
	for _, p := range UnitFiles {
		mode := uint32(0o644)
		if p == UnitFiles[0] {
			mode = 0o600
		}
		if err := secureio.AtomicWrite(p, files[p], mode); err != nil {
			return err
		}
	}
	for _, step := range []struct {
		label string
		args  []string
	}{
		{"Reload unit definitions", []string{"systemctl", "daemon-reload"}},
		{"Enable project boot units", []string{"systemctl", "enable", Guard, Restore}},
		{"Enable owned daemon", []string{"systemctl", "enable", host.Unit}},
		{"Start owned daemon", []string{"systemctl", "start", host.Unit}},
	} {
		if _, err := h.Command(step.label, step.args, nil, nil, 30*time.Second, true); err != nil {
			return err
		}
	}
	return nil
}

func Deactivate(h host.Runner, rec *Record) error {
	if err := AssertFiles(rec, true); err != nil {
		return err
	}
	ownedFiles := make(map[string]bool)
	for _, p := range UnitFiles {
		if pathExists(p) {
			ownedFiles[p] = true
		}
	}
	if ls, _ := h.Service(host.Unit, "LoadState"); ls == "loaded" {
		dropins, _ := h.Service(host.Unit, "DropInPaths")
		if dropins == host.DropIn && ownedFiles[host.DropIn] {
			frag, _ := h.Service(host.Unit, "FragmentPath")
			if !host.VendorUnits[frag] {
				return secureio.Stop("The strongSwan unit cannot be proven owned for cleanup.")
			}
			pidStr, _ := h.Service(host.Unit, "MainPID")
			dev, ino, hasSock, err := viciSocketIdentity()
			if err != nil {
				return err
			}
			if pidStr != "0" {
				pid, _ := strconv.Atoi(pidStr)
				if err := h.AssertPrivateDaemon(pid); err != nil {
					return err
				}
			}
			if hasSock {
				listeners, err := h.VICIListeners()
				if err != nil || pidStr == "0" || len(listeners) == 0 {
					return secureio.Stop("VICI socket ownership cannot be proven for cleanup.")
				}
				for _, line := range listeners {
					ms := pidRE.FindAllStringSubmatch(line, -1)
					if len(ms) == 0 {
						return secureio.Stop("VICI socket ownership cannot be proven for cleanup.")
					}
					for _, m := range ms {
						if m[1] != pidStr {
							return secureio.Stop("VICI socket ownership cannot be proven for cleanup.")
						}
					}
				}
			}
			if _, err := h.Command("Stop owned daemon", []string{"systemctl", "stop", host.Unit}, nil, nil, 30*time.Second, true); err != nil {
				return err
			}
			rDev, rIno, rHasSock, err := viciSocketIdentity()
			if err != nil {
				return err
			}
			if rHasSock {
				listeners, _ := h.VICIListeners()
				if rDev != dev || rIno != ino || len(listeners) > 0 {
					return secureio.Stop("The VICI socket changed or still has a listener after stop.")
				}
				if err := secureio.RemoveFile(host.VICIPath); err != nil {
					return err
				}
			}
			if _, err := h.Command("Disable owned daemon", []string{"systemctl", "disable", host.Unit}, nil, nil, 30*time.Second, true); err != nil {
				return err
			}
		} else {
			act, _ := h.Service(host.Unit, "ActiveState")
			uf, _ := h.Service(host.Unit, "UnitFileState")
			if dropins != "" || act != "inactive" || uf != "disabled" {
				return secureio.Stop("Daemon ownership cannot be proven for cleanup.")
			}
		}
	}

	for _, unit := range []string{Restore, Guard} {
		if ls, _ := h.Service(unit, "LoadState"); ls == "loaded" {
			p := filepath.Join(UnitDir, unit)
			frag, _ := h.Service(unit, "FragmentPath")
			dropins, _ := h.Service(unit, "DropInPaths")
			if !ownedFiles[p] || frag != p || dropins != "" {
				return secureio.Stop("A boot service cannot be proven owned for cleanup.")
			}
			if _, err := h.Command("Disable project boot unit", []string{"systemctl", "disable", "--now", unit}, nil, nil, 30*time.Second, true); err != nil {
				return err
			}
		}
	}
	var sortedOwned []string
	for p := range ownedFiles {
		sortedOwned = append(sortedOwned, p)
	}
	sort.Strings(sortedOwned)
	for _, p := range sortedOwned {
		if err := secureio.RemoveFile(p); err != nil {
			return err
		}
	}
	createdSet := make(map[string]bool, len(rec.CreatedDirs))
	for _, d := range rec.CreatedDirs {
		createdSet[d] = true
	}
	for _, d := range InstallDirs {
		if createdSet[d] && pathExists(d) {
			entries, _ := os.ReadDir(d)
			if len(entries) == 0 {
				_ = os.Remove(d)
				_ = secureio.SyncDir(filepath.Dir(d))
			}
		}
	}
	if len(ownedFiles) > 0 {
		if _, err := h.Command("Reload unit definitions", []string{"systemctl", "daemon-reload"}, nil, nil, 30*time.Second, true); err != nil {
			return err
		}
	}
	return nil
}

func equalPkgState(a, b map[string]host.PackageInfo) bool {
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
