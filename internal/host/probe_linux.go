//go:build linux

package host

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/yikkrrtykj/event-ipsec-hub/internal/secureio"
)

// ReadHostAuthorization checks the root-only authorization marker and returns "production" or "lab".
func ReadHostAuthorization() (string, error) {
	parentMode := uint32(0o700)
	marker, err := secureio.ReadFile(HostMarker, 0o600, 64, &parentMode)
	if err == nil {
		if string(marker) != HostMarkerValue {
			return "", secureio.Stop("The production host authorization marker is invalid.")
		}
		return "production", nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", secureio.Stop("The root-only host authorization marker is invalid or unreadable.")
	}
	lab, err := secureio.ReadFile(LabMarker, 0o600, 64, &parentMode)
	if err != nil {
		return "", secureio.Stop("Host authorization marker is missing (/etc/ipsecvpn/host-authorized or /etc/ipsecvpn/lab-authorized).")
	}
	if string(lab) != LabMarkerValue {
		return "", secureio.Stop("The isolated VM authorization marker is invalid.")
	}
	return "lab", nil
}

func (h *OSHost) Probe() (map[string]string, error) {
	if os.Geteuid() != 0 {
		return nil, secureio.Stop("Host operations require root on an isolated Ubuntu 24.04 VM.")
	}
	if os.Getuid() != 0 {
		return nil, secureio.Stop("Run the CLI as root, not as a setuid executable.")
	}
	raw, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return nil, secureio.Stop("Could not read /etc/os-release.")
	}
	fields := parseOSRelease(string(raw))
	if fields["ID"] != "ubuntu" || fields["VERSION_ID"] != "24.04" {
		return nil, secureio.Stop("Only Ubuntu 24.04 is supported.")
	}
	if st, err := os.Stat("/run/systemd/system"); err != nil || !st.IsDir() {
		return nil, secureio.Stop("A systemd-managed Ubuntu 24.04 host is required.")
	}
	mode, err := ReadHostAuthorization()
	if err != nil {
		return nil, err
	}
	virt, err := h.Command("VM detection", []string{"systemd-detect-virt", "--vm"}, nil, []int{0, 1}, 30*time.Second, false)
	if err != nil {
		return nil, err
	}
	virt = strings.TrimSpace(virt)
	if virt == "" {
		virt = "none"
	}
	if mode == "lab" && virt == "none" {
		return nil, secureio.Stop("A systemd-managed isolated VM is required for lab authorization.")
	}
	for _, tool := range HostTools {
		if _, err := lookPathIn(tool, SafePath); err != nil {
			return nil, secureio.Stop("The required Ubuntu host tools are missing.")
		}
	}
	if _, err := h.Command("XFRM interface support", []string{"modprobe", "-nq", "xfrm_interface"}, nil, nil, 30*time.Second, false); err != nil {
		return nil, err
	}
	if _, err := h.Command("IPv4 XFRM support", []string{"ip", "xfrm", "policy", "list"}, nil, nil, 30*time.Second, false); err != nil {
		return nil, err
	}
	if _, err := h.JSON("nftables support", "nft", "-j", "list", "ruleset"); err != nil {
		return nil, err
	}
	kernel := ""
	if out, err := h.Command("kernel release", []string{"uname", "-r"}, nil, nil, 5*time.Second, false); err == nil {
		kernel = strings.TrimSpace(out)
	}
	return map[string]string{
		"os":         "Ubuntu 24.04",
		"kernel":     kernel,
		"hypervisor": virt,
		"mode":       mode,
	}, nil
}

func (h *OSHost) AssertPrivateDaemon(pid int) error {
	if pid <= 0 {
		return secureio.Stop("The strongSwan service has no provable process identity.")
	}
	envBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
	if err != nil {
		if os.IsPermission(err) {
			return secureio.ObservationStop("Cannot read the daemon environment.", "DAEMON_ENV", "PERMISSION_DENIED")
		}
		return secureio.Stop("The strongSwan service has no provable process identity.")
	}
	expected := []byte("STRONGSWAN_CONF=" + PrivateConf)
	for _, item := range bytes.Split(envBytes, []byte{0}) {
		if bytes.Equal(item, expected) {
			return nil
		}
	}
	return secureio.Stop("The running strongSwan process does not use the project configuration.")
}

func parseOSRelease(text string) map[string]string {
	out := make(map[string]string)
	for _, line := range strings.Split(text, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			out[k] = strings.Trim(v, `"'`)
		}
	}
	return out
}

func lookPathIn(name, pathEnv string) (string, error) {
	for _, dir := range strings.Split(pathEnv, ":") {
		cand := dir + "/" + name
		if info, err := os.Stat(cand); err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
			return cand, nil
		}
	}
	return exec.LookPath(name)
}
