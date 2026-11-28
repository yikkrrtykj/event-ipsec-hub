package host

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/yikkrrtykj/event-ipsec-hub/internal/manifest"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/secureio"
)

const (
	SafePath        = "/usr/sbin:/usr/bin:/sbin:/bin"
	Unit            = "strongswan.service"
	DropIn          = "/etc/systemd/system/strongswan.service.d/99-ipsecvpn.conf"
	PrivateConf     = "/etc/strongswan.d/ipsecvpn-private.conf"
	VICIPath        = "/run/charon.vici"
	SocketURI       = "unix://" + VICIPath
	LabMarker       = "/etc/ipsecvpn/lab-authorized"
	HostMarker      = "/etc/ipsecvpn/host-authorized"
	LabMarkerValue  = "ipsecvpn-lab-v1\n"
	HostMarkerValue = "ipsecvpn-prod-v1\n"
)

var (
	Packages    = []string{"charon-systemd", "strongswan-swanctl", "libstrongswan-standard-plugins"}
	VendorUnits = map[string]bool{
		"/usr/lib/systemd/system/strongswan.service": true,
		"/lib/systemd/system/strongswan.service":     true,
	}
	HostTools = []string{"ip", "nft", "ss", "systemctl", "sysctl", "modprobe", "dpkg-query", "apt-get"}

	viciConnRE    = regexp.MustCompile(`^(.+?):\s+IKEv[12]\b`)
	aptInstRE     = regexp.MustCompile(`^Inst ([A-Za-z0-9+:.-]+) \(([^ )]+)`)
	ssPIDRE       = regexp.MustCompile(`pid=(\d+),`)
	ssVersionRE   = regexp.MustCompile(`\b5\.9\.\d+\b`)
)

// PackageInfo records dpkg package version and status.
type PackageInfo struct {
	Version string `json:"version"`
	Status  string `json:"status"`
}

// StepHook records transactional mutation steps.
type StepHook func(label, result string)

// Runner abstracts privileged Linux host interactions for both live execution and unit tests.
type Runner interface {
	SetStepHook(fn StepHook)
	Probe() (map[string]string, error)
	Command(label string, args []string, stdin []byte, allowed []int, timeout time.Duration, mutate bool) (string, error)
	JSON(label string, args ...string) (any, error)
	IP(args ...string) ([]map[string]any, error)
	Service(unit, prop string) (string, error)
	VICI(action string, options ...string) (string, error)
	VICIConnections() (map[string][]string, error)
	VICINames() (map[string]struct{}, error)
	PackageState() (map[string]PackageInfo, error)
	APTPlan() (map[string]string, error)
	IKEPorts() (string, error)
	VICIListeners() ([]string, error)
	AssertNoStarter() error
	AssertNoOtherIKE() error
	AssertIdleIKE() error
	AssertExclusiveIKE(permitted map[string]struct{}) error
	AssertDaemon(permitted map[string]struct{}) (int, error)
	AssertPrivateDaemon(pid int) error
	Routing(permittedRules map[RuleKey]struct{}) ([]map[string]any, []map[string]any, []map[string]any, error)
	CheckPaths(m *manifest.DeploymentManifest, routes []map[string]any, ownedRoutes map[RouteKey]struct{}, links []map[string]any, ownedLinks map[string]struct{}, ownedRules map[RuleKey]struct{}) error
	NFT() ([]map[string]any, error)
	CheckFirewall(objects []map[string]any) error
	Baseline(rules, routes, links, foreignNFT []map[string]any, ownedRoutes map[RouteKey]struct{}, ownedLinks map[string]struct{}, ownedRules map[RuleKey]struct{}) (map[string]string, error)
	RouteLookups(targets [][2]string) (map[[2]string][]map[string]any, error)
	IPv4Setting(key string) (string, error)
}

// OSHost executes constrained host commands without a shell.
type OSHost struct {
	step StepHook
}

func NewOSHost() *OSHost {
	return &OSHost{}
}

func (h *OSHost) SetStepHook(fn StepHook) {
	h.step = fn
}

func (h *OSHost) Command(label string, args []string, stdin []byte, allowed []int, timeout time.Duration, mutate bool) (string, error) {
	if len(args) == 0 {
		return "", secureio.Stop(label + " failed (empty command).")
	}
	if len(allowed) == 0 {
		allowed = []int{0}
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	if mutate && h.step != nil {
		h.step(label, "STARTED")
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Env = []string{
		"PATH=" + SafePath,
		"LC_ALL=C",
		"DEBIAN_FRONTEND=noninteractive",
		"NEEDRESTART_MODE=l",
		"NEEDRESTART_SUSPEND=1",
	}
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return "", secureio.StopWithReason("COMMAND_TIMEOUT", fmt.Sprintf("%s failed (unavailable or timed out). Command output was suppressed.", label))
	}
	exitCode := 0
	if err != nil {
		var exitErr *exec.ExitError
		if ok := errorAsExit(err, &exitErr); ok {
			exitCode = exitErr.ExitCode()
		} else if os.IsPermission(err) {
			return "", secureio.StopWithReason("PERMISSION_DENIED", fmt.Sprintf("%s failed (unavailable or timed out). Command output was suppressed.", label))
		} else {
			return "", secureio.StopWithReason("COMMAND_FAILED", fmt.Sprintf("%s failed (unavailable or timed out). Command output was suppressed.", label))
		}
	}

	okCode := false
	for _, c := range allowed {
		if c == exitCode {
			okCode = true
			break
		}
	}
	if !okCode {
		low := strings.ToLower(stderr.String())
		cat := "COMMAND_FAILED"
		if strings.Contains(low, "permission denied") || strings.Contains(low, "operation not permitted") || strings.Contains(low, "access denied") {
			cat = "PERMISSION_DENIED"
		}
		return "", secureio.StopWithReason(cat, fmt.Sprintf("%s failed (%d). Command output was suppressed.", label, exitCode))
	}

	if mutate && h.step != nil {
		h.step(label, "DONE")
	}
	return stdout.String(), nil
}

func errorAsExit(err error, target **exec.ExitError) bool {
	if ee, ok := err.(*exec.ExitError); ok {
		*target = ee
		return true
	}
	return false
}

func (h *OSHost) JSON(label string, args ...string) (any, error) {
	out, err := h.Command(label, args, nil, nil, 30*time.Second, false)
	if err != nil {
		return nil, err
	}
	var val any
	dec := json.NewDecoder(strings.NewReader(out))
	dec.UseNumber()
	if err := dec.Decode(&val); err != nil {
		return nil, secureio.Stop(label + " did not return valid JSON.")
	}
	return val, nil
}

func (h *OSHost) IP(args ...string) ([]map[string]any, error) {
	cmd := append([]string{"ip", "-j", "-N"}, args...)
	raw, err := h.JSON("ip query", cmd...)
	if err != nil {
		return nil, err
	}
	list, ok := raw.([]any)
	if !ok {
		return nil, secureio.Stop("ip query did not return a JSON array.")
	}
	out := make([]map[string]any, 0, len(list))
	for _, item := range list {
		row, ok := item.(map[string]any)
		if !ok {
			return nil, secureio.Stop("ip query returned a non-object row.")
		}
		out = append(out, row)
	}
	return out, nil
}

func (h *OSHost) Service(unit, prop string) (string, error) {
	out, err := h.Command("systemd query", []string{"systemctl", "show", unit, "-p", prop, "--value"}, nil, nil, 30*time.Second, false)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

func (h *OSHost) VICI(action string, options ...string) (string, error) {
	args := append([]string{"swanctl", action}, options...)
	args = append(args, "--uri", SocketURI)
	return h.Command("VICI query", args, nil, nil, 30*time.Second, false)
}

func ParseVICIConnections(output string) (map[string][]string, error) {
	conns := make(map[string][]string)
	current := ""
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		if line[0] != ' ' && line[0] != '\t' {
			m := viciConnRE.FindStringSubmatch(line)
			if m == nil {
				return nil, secureio.Stop("VICI returned an unrecognized connection entry.")
			}
			current = m[1]
			conns[current] = []string{}
		} else if current != "" {
			conns[current] = append(conns[current], line)
		}
	}
	return conns, nil
}

func (h *OSHost) VICIConnections() (map[string][]string, error) {
	out, err := h.VICI("--list-conns")
	if err != nil {
		return nil, err
	}
	return ParseVICIConnections(out)
}

func (h *OSHost) VICINames() (map[string]struct{}, error) {
	conns, err := h.VICIConnections()
	if err != nil {
		return nil, err
	}
	names := make(map[string]struct{}, len(conns))
	for k := range conns {
		names[k] = struct{}{}
	}
	return names, nil
}

func (h *OSHost) PackageState() (map[string]PackageInfo, error) {
	out, err := h.Command("Full dpkg inventory", []string{"dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${db:Status-Abbrev}\n"}, nil, nil, 30*time.Second, false)
	if err != nil {
		return nil, err
	}
	res := make(map[string]PackageInfo)
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) == 3 {
			res[parts[0]] = PackageInfo{Version: parts[1], Status: parts[2]}
		}
	}
	return res, nil
}

func (h *OSHost) APTPlan() (map[string]string, error) {
	audit, err := h.Command("Package audit", []string{"dpkg", "--audit"}, nil, nil, 30*time.Second, false)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(audit) != "" {
		return nil, secureio.Stop("The VM already has an incomplete package transaction.")
	}
	args := append([]string{"apt-get", "-s", "--no-install-recommends", "--no-upgrade", "--no-remove", "install"}, Packages...)
	report, err := h.Command("APT simulation", args, nil, nil, 30*time.Second, false)
	if err != nil {
		return nil, err
	}
	plan := make(map[string]string)
	for _, line := range strings.Split(report, "\n") {
		if strings.HasPrefix(line, "Remv ") {
			return nil, secureio.Stop("APT would remove an installed package.")
		}
		if strings.HasPrefix(line, "Inst ") {
			m := aptInstRE.FindStringSubmatch(line)
			if m == nil {
				return nil, secureio.Stop("APT would upgrade an installed package or returned an unknown plan.")
			}
			plan[m[1]] = m[2]
		}
	}
	for _, pkg := range Packages {
		if !strings.HasPrefix(plan[pkg], "5.9.") {
			return nil, secureio.Stop("Expected Ubuntu strongSwan 5.9.x packages are unavailable.")
		}
	}
	return plan, nil
}

func (h *OSHost) IKEPorts() (string, error) {
	out, err := h.Command("IKE socket probe", []string{"ss", "-H", "-ulnp", "( sport = :500 or sport = :4500 )"}, nil, nil, 30*time.Second, false)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

func (h *OSHost) VICIListeners() ([]string, error) {
	out, err := h.Command("VICI listener probe", []string{"ss", "-H", "-xlpn"}, nil, nil, 30*time.Second, false)
	if err != nil {
		return nil, err
	}
	var rows []string
	for _, line := range strings.Split(out, "\n") {
		for _, tok := range strings.Fields(line) {
			if tok == VICIPath {
				rows = append(rows, line)
				break
			}
		}
	}
	return rows, nil
}

func (h *OSHost) AssertNoStarter() error {
	st, err := h.Service("strongswan-starter.service", "ActiveState")
	if err != nil {
		return err
	}
	if st != "inactive" && st != "failed" {
		return secureio.Stop("A legacy strongSwan starter unit is active.")
	}
	return nil
}

func (h *OSHost) AssertNoOtherIKE() error {
	if err := h.AssertNoStarter(); err != nil {
		return err
	}
	saOut, err := h.Command("XFRM SA probe", []string{"ip", "xfrm", "state", "list", "nokeys"}, nil, nil, 30*time.Second, false)
	if err != nil {
		return err
	}
	if strings.TrimSpace(saOut) != "" {
		return secureio.Stop("An active kernel IPsec SA exists. Use a dedicated idle VM.")
	}
	spOut, err := h.Command("XFRM SPD probe", []string{"ip", "xfrm", "policy", "list", "nosock"}, nil, nil, 30*time.Second, false)
	if err != nil {
		return err
	}
	if strings.TrimSpace(spOut) != "" {
		return secureio.Stop("An unexpected global XFRM policy exists.")
	}
	return nil
}

func (h *OSHost) AssertIdleIKE() error {
	if err := h.AssertNoOtherIKE(); err != nil {
		return err
	}
	st, err := h.Service(Unit, "ActiveState")
	if err != nil {
		return err
	}
	ports, err := h.IKEPorts()
	if err != nil {
		return err
	}
	if st != "inactive" || ports != "" || pathExistsOrSymlink(VICIPath) || pathExistsOrSymlink("/run/charon.ctl") {
		return secureio.Stop("An existing IKE listener or strongSwan service is unowned.")
	}
	return nil
}

func pathExistsOrSymlink(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

func (h *OSHost) AssertExclusiveIKE(permitted map[string]struct{}) error {
	if err := h.AssertNoOtherIKE(); err != nil {
		return err
	}
	if _, err := h.AssertDaemon(permitted); err != nil {
		return err
	}
	sas, err := h.VICI("--list-sas")
	if err != nil {
		return err
	}
	if strings.TrimSpace(sas) != "" {
		return secureio.Stop("Active SAs prevent changes that require an idle daemon.")
	}
	return nil
}

func (h *OSHost) AssertDaemon(permitted map[string]struct{}) (int, error) {
	if err := h.AssertNoStarter(); err != nil {
		return 0, err
	}
	frag, err := h.Service(Unit, "FragmentPath")
	if err != nil {
		return 0, err
	}
	dropin, err := h.Service(Unit, "DropInPaths")
	if err != nil {
		return 0, err
	}
	execStart, err := h.Service(Unit, "ExecStart")
	if err != nil {
		return 0, err
	}
	activeState, err := h.Service(Unit, "ActiveState")
	if err != nil {
		return 0, err
	}
	pidStr, err := h.Service(Unit, "MainPID")
	if err != nil {
		return 0, err
	}
	if !VendorUnits[frag] {
		return 0, secureio.Stop("The strongSwan unit is not the expected Ubuntu unit.")
	}
	if dropin != DropIn {
		return 0, secureio.Stop("The strongSwan unit has unexpected overrides.")
	}
	if !strings.Contains(execStart, "charon-systemd") {
		return 0, secureio.Stop("The active unit does not use charon-systemd.")
	}
	pid, err := strconv.Atoi(pidStr)
	portsRaw, perr := h.IKEPorts()
	if perr != nil {
		return 0, perr
	}
	var ports []string
	if portsRaw != "" {
		ports = strings.Split(portsRaw, "\n")
	}
	if activeState != "active" || err != nil || pid <= 0 || len(ports) == 0 {
		return 0, secureio.Stop("The owned charon-systemd service and IKE sockets are not active.")
	}
	if err := h.AssertPrivateDaemon(pid); err != nil {
		return 0, err
	}
	vici, err := h.VICIListeners()
	if err != nil {
		return 0, err
	}
	if len(vici) == 0 {
		return 0, secureio.ObservationStop("The daemon does not exclusively own the IKE and VICI sockets.", "VICI", "UNOWNED_DAEMON")
	}
	for _, line := range append(ports, vici...) {
		matches := ssPIDRE.FindAllStringSubmatch(line, -1)
		if len(matches) == 0 {
			return 0, secureio.ObservationStop("The daemon does not exclusively own the IKE and VICI sockets.", "VICI", "UNOWNED_DAEMON")
		}
		for _, m := range matches {
			if m[1] != pidStr {
				return 0, secureio.ObservationStop("The daemon does not exclusively own the IKE and VICI sockets.", "VICI", "UNOWNED_DAEMON")
			}
		}
	}
	ver, err := h.VICI("--version", "--daemon")
	if err != nil {
		return 0, err
	}
	if !ssVersionRE.MatchString(ver) || !strings.Contains(ver, "charon-systemd") {
		return 0, secureio.Stop("VICI did not report the expected strongSwan 5.9.x version.")
	}
	names, err := h.VICINames()
	if err != nil {
		return 0, err
	}
	for name := range names {
		if _, ok := permitted[name]; !ok {
			return 0, secureio.ObservationStop("Unowned VICI connections prevent safe changes.", "VICI", "UNOWNED_SA")
		}
	}
	return pid, nil
}

// RouteKey uniquely identifies an IPv4 kernel route managed or observed by ipsecvpn.
type RouteKey struct {
	Destination string
	Kind        string
	Dev         string
	Metric      string
	Protocol    string
	Table       string
}

// RuleKey uniquely identifies an IPv4 policy routing rule.
type RuleKey struct {
	Priority int
	Source   string
	Table    string
}

func TableID(v any) string {
	s := fmt.Sprint(v)
	switch s {
	case "local":
		return "255"
	case "main":
		return "254"
	case "default":
		return "253"
	default:
		return s
	}
}

func RouteKind(row map[string]any) string {
	raw, ok := row["type"]
	if !ok || raw == nil {
		return "unicast"
	}
	s := fmt.Sprint(raw)
	switch s {
	case "1":
		return "unicast"
	case "6":
		return "blackhole"
	default:
		return s
	}
}

func ParseRouteKey(row map[string]any) RouteKey {
	dst, _ := row["dst"].(string)
	if dst != "" && dst != "default" && !strings.Contains(dst, "/") {
		dst += "/32"
	}
	dev, _ := row["dev"].(string)
	metric := "0"
	if m, ok := row["metric"]; ok && m != nil {
		metric = fmt.Sprint(m)
	}
	proto := "<nil>"
	if p, ok := row["protocol"]; ok && p != nil {
		proto = fmt.Sprint(p)
	}
	tbl := "254"
	if t, ok := row["table"]; ok && t != nil {
		tbl = TableID(t)
	}
	return RouteKey{
		Destination: dst,
		Kind:        RouteKind(row),
		Dev:         dev,
		Metric:      metric,
		Protocol:    proto,
		Table:       tbl,
	}
}

func ParseRuleKey(row map[string]any) RuleKey {
	prio := intFromAny(row["priority"])
	src := ""
	if s, ok := row["src"]; ok && s != nil {
		src = fmt.Sprint(s)
	}
	if src != "" && src != "all" && !strings.Contains(src, "/") {
		srclen := 32
		if sl, ok := row["srclen"]; ok && sl != nil {
			srclen = intFromAny(sl)
		}
		src = fmt.Sprintf("%s/%d", src, srclen)
	}
	return RuleKey{
		Priority: prio,
		Source:   src,
		Table:    TableID(row["table"]),
	}
}

func XFRMID(row map[string]any) (uint32, bool) {
	li, ok := row["linkinfo"].(map[string]any)
	if !ok || li["info_kind"] != "xfrm" {
		return 0, false
	}
	idMap, ok := li["info_data"].(map[string]any)
	if !ok {
		return 0, false
	}
	raw, ok := idMap["if_id"]
	if !ok || raw == nil {
		return 0, false
	}
	v, err := strconv.ParseUint(fmt.Sprint(raw), 0, 32)
	if err != nil {
		return 0, false
	}
	return uint32(v), true
}

func intFromAny(v any) int {
	switch tv := v.(type) {
	case int:
		return tv
	case int64:
		return int(tv)
	case float64:
		return int(tv)
	case json.Number:
		i, _ := tv.Int64()
		return int(i)
	case string:
		i, _ := strconv.Atoi(tv)
		return i
	default:
		return 0
	}
}

func VerifyRoutingRules(rules []map[string]any, permitted map[RuleKey]struct{}) error {
	systemExpected := map[RuleKey]bool{
		{Priority: 0, Source: "all", Table: "255"}:     true,
		{Priority: 32766, Source: "all", Table: "254"}: true,
		{Priority: 32767, Source: "all", Table: "253"}: true,
	}
	allowedFields := map[string]bool{
		"priority": true, "src": true, "srclen": true, "table": true, "protocol": true,
	}
	seenSystem := make(map[RuleKey]bool)
	for _, row := range rules {
		for k := range row {
			if !allowedFields[k] {
				return secureio.Stop("IPv4 policy routing differs from the default rule set.")
			}
		}
		key := ParseRuleKey(row)
		if systemExpected[key] {
			if seenSystem[key] {
				return secureio.Stop("IPv4 policy routing differs from the default rule set.")
			}
			seenSystem[key] = true
			continue
		}
		if _, ok := permitted[key]; ok {
			continue
		}
		return secureio.Stop("IPv4 policy routing differs from the default rule set.")
	}
	if len(seenSystem) != len(systemExpected) {
		return secureio.Stop("IPv4 policy routing differs from the default rule set.")
	}
	return nil
}

func (h *OSHost) Routing(permittedRules map[RuleKey]struct{}) ([]map[string]any, []map[string]any, []map[string]any, error) {
	rules, err := h.IP("-4", "rule", "show")
	if err != nil {
		return nil, nil, nil, err
	}
	if err := VerifyRoutingRules(rules, permittedRules); err != nil {
		return nil, nil, nil, err
	}
	routes, err := h.IP("-4", "route", "show", "table", "all")
	if err != nil {
		return nil, nil, nil, err
	}
	links, err := h.IP("-details", "link", "show")
	if err != nil {
		return nil, nil, nil, err
	}
	return rules, routes, links, nil
}

func (h *OSHost) NFT() ([]map[string]any, error) {
	raw, err := h.JSON("nftables inventory", "nft", "-j", "list", "ruleset")
	if err != nil {
		return nil, err
	}
	root, ok := raw.(map[string]any)
	if !ok {
		return nil, secureio.Stop("nftables inventory did not return an object.")
	}
	items, ok := root["nftables"].([]any)
	if !ok {
		return nil, secureio.Stop("nftables inventory missing nftables array.")
	}
	out := make([]map[string]any, 0, len(items))
	for _, it := range items {
		if m, ok := it.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out, nil
}

func SeparateNFT(objects []map[string]any) (owned []map[string]any, foreign []map[string]any) {
	for _, item := range objects {
		for kind, v := range item {
			if kind == "metainfo" {
				break
			}
			row, _ := v.(map[string]any)
			tableName, _ := row["table"].(string)
			if tableName == "" {
				tableName, _ = row["name"].(string)
			}
			if row["family"] == "ip" && tableName == manifest.Table {
				owned = append(owned, item)
			} else {
				foreign = append(foreign, item)
			}
			break
		}
	}
	return owned, foreign
}

func CheckFirewallObjects(objects []map[string]any) error {
	if raw, err := os.ReadFile("/proc/net/ip_tables_names"); err == nil && strings.TrimSpace(string(raw)) != "" {
		return secureio.Stop("An IPv4 legacy iptables table prevents proof of safe coexistence.")
	}
	sensitive := make(map[[3]string]bool)
	rulesByChain := make(map[[3]string][]map[string]any)
	for _, obj := range objects {
		if row, ok := obj["chain"].(map[string]any); ok {
			fam, _ := row["family"].(string)
			if fam != "ip" && fam != "inet" && fam != "netdev" && fam != "bridge" {
				continue
			}
			if row["hook"] == nil {
				continue
			}
			policy, _ := row["policy"].(string)
			tbl, _ := row["table"].(string)
			name, _ := row["name"].(string)
			if policy != "" && policy != "accept" {
				return secureio.Stop(fmt.Sprintf("A foreign firewall base chain can override the project's allow rules (%s %s %s, policy %s).", fam, tbl, name, policy))
			}
			sensitive[[3]string{fam, tbl, name}] = true
			continue
		}
		if row, ok := obj["rule"].(map[string]any); ok {
			fam, _ := row["family"].(string)
			tbl, _ := row["table"].(string)
			chn, _ := row["chain"].(string)
			key := [3]string{fam, tbl, chn}
			rulesByChain[key] = append(rulesByChain[key], row)
		}
	}
	for key := range sensitive {
		for _, row := range rulesByChain[key] {
			if err := checkForeignRuleSafe(key[0], key[1], key[2], row, rulesByChain, map[[3]string]bool{key: true}); err != nil {
				return err
			}
		}
	}
	return nil
}

func isDockerInterfaceName(name string) bool {
	return name == "docker0" || strings.HasPrefix(name, "docker") || strings.HasPrefix(name, "br-") || strings.HasPrefix(name, "veth")
}

func isDockerChainName(name string) bool {
	return name == "DOCKER" || strings.HasPrefix(name, "DOCKER-")
}

func matchTargetsDockerIface(expr map[string]any, requireEq bool) bool {
	m, ok := expr["match"].(map[string]any)
	if !ok {
		return false
	}
	op, _ := m["op"].(string)
	if requireEq && op != "==" {
		return false
	}
	if op != "==" && op != "!=" {
		return false
	}
	left, _ := m["left"].(map[string]any)
	meta, _ := left["meta"].(map[string]any)
	key, _ := meta["key"].(string)
	if key != "iifname" && key != "oifname" {
		return false
	}
	if s, ok := m["right"].(string); ok {
		return isDockerInterfaceName(s)
	}
	return false
}

func matchHasIPField(expr map[string]any, field string) bool {
	m, ok := expr["match"].(map[string]any)
	if !ok {
		return false
	}
	left, _ := m["left"].(map[string]any)
	payload, _ := left["payload"].(map[string]any)
	return payload["protocol"] == "ip" && payload["field"] == field
}

func matchTouchesIPsecPorts(expr map[string]any) bool {
	m, ok := expr["match"].(map[string]any)
	if !ok {
		return false
	}
	left, _ := m["left"].(map[string]any)
	payload, _ := left["payload"].(map[string]any)
	if payload == nil {
		return false
	}
	proto, _ := payload["protocol"].(string)
	field, _ := payload["field"].(string)
	if proto == "ip" && field == "protocol" {
		if s, ok := m["right"].(string); ok && (s == "esp" || s == "ah") {
			return true
		}
		if n, ok := m["right"].(float64); ok && (int(n) == 50 || int(n) == 51) {
			return true
		}
	}
	if proto == "udp" && field == "dport" {
		if n, ok := m["right"].(float64); ok && (int(n) == 500 || int(n) == 4500) {
			return true
		}
	}
	return false
}

func checkForeignRuleSafe(fam, tbl, chn string, row map[string]any, rulesByChain map[[3]string][]map[string]any, visited map[[3]string]bool) error {
	exprs, _ := row["expr"].([]any)
	safeExpr := map[string]bool{"match": true, "counter": true, "accept": true, "log": true}
	if isDockerChainName(chn) {
		safeExpr["return"] = true
	}

	var unsafeKeys []string
	var jumpTargets []string
	hasDockerEqIface := false
	hasDockerAnyIface := false
	hasIPSaddr := false
	hasIPDaddr := false
	hasL4Port := false
	touchesIPsec := false

	for _, e := range exprs {
		em, _ := e.(map[string]any)
		if matchTargetsDockerIface(em, true) {
			hasDockerEqIface = true
		}
		if matchTargetsDockerIface(em, false) {
			hasDockerAnyIface = true
		}
		if matchHasIPField(em, "saddr") {
			hasIPSaddr = true
		}
		if matchHasIPField(em, "daddr") {
			hasIPDaddr = true
		}
		if m, ok := em["match"].(map[string]any); ok {
			if left, ok := m["left"].(map[string]any); ok {
				if pl, ok := left["payload"].(map[string]any); ok {
					if (pl["protocol"] == "tcp" || pl["protocol"] == "udp") && pl["field"] == "dport" {
						hasL4Port = true
					}
				}
			}
		}
		if matchTouchesIPsecPorts(em) {
			touchesIPsec = true
		}
		for k, v := range em {
			if safeExpr[k] {
				continue
			}
			if k == "xt" {
				if xm, ok := v.(map[string]any); ok {
					xtype, _ := xm["type"].(string)
					xname := strings.ToUpper(fmt.Sprint(xm["name"]))
					if xtype == "match" || xtype == "watcher" {
						continue
					}
					if xtype == "target" {
						switch xname {
						case "MASQUERADE":
							unsafeKeys = append(unsafeKeys, "masquerade")
							continue
						case "DNAT":
							unsafeKeys = append(unsafeKeys, "dnat")
							continue
						case "DROP":
							unsafeKeys = append(unsafeKeys, "drop")
							continue
						case "REJECT":
							unsafeKeys = append(unsafeKeys, "reject")
							continue
						case "RETURN":
							if isDockerChainName(chn) {
								continue
							}
						case "ACCEPT":
							continue
						}
						unsafeKeys = append(unsafeKeys, "xt:"+xname)
						continue
					}
				}
			}
			if k == "jump" {
				if jm, ok := v.(map[string]any); ok {
					if tgt, ok := jm["target"].(string); ok && isDockerChainName(tgt) {
						jumpTargets = append(jumpTargets, tgt)
						continue
					}
				}
			}
			unsafeKeys = append(unsafeKeys, k)
		}
	}

	// Verify any jumped Docker sub-chains recursively.
	for _, tgt := range jumpTargets {
		subKey := [3]string{fam, tbl, tgt}
		if visited[subKey] {
			continue
		}
		nextVisited := make(map[[3]string]bool, len(visited)+1)
		for k, v := range visited {
			nextVisited[k] = v
		}
		nextVisited[subKey] = true
		for _, subRow := range rulesByChain[subKey] {
			if err := checkForeignRuleSafe(fam, tbl, tgt, subRow, rulesByChain, nextVisited); err != nil {
				return err
			}
		}
	}

	if len(unsafeKeys) == 0 {
		return nil
	}

	// Allow standard Docker-only masquerade rules in ip nat POSTROUTING:
	// 1) Bridge subnet SNAT: ip saddr <bridge_cidr> oifname != "docker0"/"br-*" masquerade
	// 2) Container hairpin SNAT: ip saddr <c> ip daddr <c> tcp/udp dport <p!=500/4500> masquerade
	if fam == "ip" && tbl == "nat" && chn == "POSTROUTING" && len(unsafeKeys) == 1 && unsafeKeys[0] == "masquerade" {
		if (hasIPSaddr && hasDockerAnyIface) || (hasIPSaddr && hasIPDaddr && hasL4Port && !touchesIPsec) {
			return nil
		}
	}

	// Allow Docker-bridge-only drop/reject inside DOCKER* filter chains (e.g. oifname == "docker0" drop).
	if fam == "ip" && tbl == "filter" && isDockerChainName(chn) && len(unsafeKeys) == 1 && (unsafeKeys[0] == "drop" || unsafeKeys[0] == "reject") {
		if hasDockerEqIface {
			return nil
		}
	}

	// Allow Docker container port-publish DNAT inside ip nat DOCKER* chains when not touching UDP 500/4500 or ESP.
	if fam == "ip" && tbl == "nat" && isDockerChainName(chn) && len(unsafeKeys) == 1 && unsafeKeys[0] == "dnat" {
		if hasL4Port && !touchesIPsec {
			return nil
		}
	}

	return secureio.Stop(fmt.Sprintf("A foreign firewall rule may drop, redirect or rewrite project traffic (%s %s %s: %s).", fam, tbl, chn, unsafeKeys[0]))
}

func (h *OSHost) CheckFirewall(objects []map[string]any) error {
	return CheckFirewallObjects(objects)
}

func (h *OSHost) IPv4Setting(key string) (string, error) {
	out, err := h.Command("sysctl snapshot", []string{"sysctl", "-n", "net.ipv4." + key}, nil, nil, 30*time.Second, false)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

func (h *OSHost) RouteLookups(targets [][2]string) (map[[2]string][]map[string]any, error) {
	out := make(map[[2]string][]map[string]any, len(targets))
	for _, t := range targets {
		args := []string{"-4", "route", "get", t[0]}
		if t[1] != "" {
			args = append(args, "from", t[1])
		}
		rows, err := h.IP(args...)
		if err != nil {
			return nil, err
		}
		out[t] = rows
	}
	return out, nil
}

func (h *OSHost) CheckPaths(
	m *manifest.DeploymentManifest,
	routes []map[string]any,
	ownedRoutes map[RouteKey]struct{},
	links []map[string]any,
	ownedLinks map[string]struct{},
	ownedRules map[RuleKey]struct{},
) error {
	if m == nil {
		return nil
	}
	ids := make(map[uint32]bool, len(m.Links))
	names := make(map[string]bool, len(m.Links))
	identities := make(map[string]bool, len(m.Links))
	for _, l := range m.Links {
		ids[l.IfID] = true
		names[l.Name()] = true
		identities[strings.ToLower(strings.TrimPrefix(l.RemoteID, "@"))] = true
	}
	if len(identities) != len(m.Links) {
		return secureio.Stop("Distinct remote IKE identities are required for per-link keys.")
	}
	for _, row := range links {
		name, _ := row["ifname"].(string)
		if _, isOwned := ownedLinks[name]; isOwned {
			continue
		}
		if id, ok := XFRMID(row); (names[name] || (ok && ids[id])) {
			return secureio.Stop("A requested XFRM name or ID is already in use.")
		}
	}

	var networks []netip.Prefix
	for _, c := range m.Networks() {
		networks = append(networks, netip.MustParsePrefix(c))
	}

	var defaults []map[string]any
	for _, row := range routes {
		rk := ParseRouteKey(row)
		if _, isOwned := ownedRoutes[rk]; isOwned {
			continue
		}
		dst, _ := row["dst"].(string)
		if dst == "default" {
			defaults = append(defaults, row)
			continue
		}
		if dst != "" {
			prefStr := dst
			if !strings.Contains(prefStr, "/") {
				prefStr += "/32"
			}
			if p, err := netip.ParsePrefix(prefStr); err == nil {
				for _, n := range networks {
					if p.Overlaps(n) {
						return secureio.Stop("An existing route overlaps an authorized remote LAN.")
					}
				}
			}
		}
	}
	if len(defaults) == 0 {
		return secureio.Stop("The existing IPv4 default path is missing or ambiguous.")
	}
	for _, row := range defaults {
		dev, _ := row["dev"].(string)
		if names[dev] || row["nexthops"] != nil {
			return secureio.Stop("The existing IPv4 default path is missing or ambiguous.")
		}
	}

	est, err := h.Command("TCP management path probe", []string{"ss", "-H", "-nt", "state", "established"}, nil, nil, 30*time.Second, false)
	if err != nil {
		return err
	}
	for _, line := range strings.Split(est, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		peerCol := fields[len(fields)-1]
		idx := strings.LastIndex(peerCol, ":")
		if idx < 0 {
			continue
		}
		ipStr := strings.TrimSuffix(strings.TrimPrefix(peerCol[:idx], "[::ffff:"), "]")
		if addr, err := netip.ParseAddr(ipStr); err == nil && addr.Is4() {
			for _, n := range networks {
				if n.Contains(addr) {
					return secureio.Stop("An established TCP management or application path overlaps a managed LAN.")
				}
			}
		}
	}

	for _, l := range m.Links {
		if l.WAN == "auto" {
			return secureio.Stop("outer_path.interface auto is an offline placeholder.")
		}
	}

	pendingPolicy := make(map[string]bool)
	var lookupTargets [][2]string
	for _, l := range m.Links {
		if l.RouteTable != nil {
			rk := RuleKey{Priority: l.PolicyPriority, Source: l.Source + "/32", Table: strconv.Itoa(*l.RouteTable)}
			if _, ok := ownedRules[rk]; !ok {
				pendingPolicy[l.Name()] = true
			}
		}
		if pendingPolicy[l.Name()] && l.Gateway != nil {
			lookupTargets = append(lookupTargets, [2]string{*l.Gateway, ""})
		} else {
			lookupTargets = append(lookupTargets, [2]string{l.Peer, l.Source})
		}
	}
	lookups, err := h.RouteLookups(lookupTargets)
	if err != nil {
		return err
	}

	for _, l := range m.Links {
		addrs, err := h.IP("-4", "addr", "show", "dev", l.WAN)
		if err != nil {
			return err
		}
		foundSrc := false
		for _, row := range addrs {
			if infos, ok := row["addr_info"].([]any); ok {
				for _, info := range infos {
					if im, ok := info.(map[string]any); ok && im["local"] == l.Source {
						foundSrc = true
						break
					}
				}
			}
		}
		if !foundSrc {
			return secureio.Stop("The IKE source address is not assigned to the specified WAN interface.")
		}
		if _, isOwned := ownedLinks[l.WAN]; names[l.WAN] || isOwned {
			return secureio.Stop("The existing peer route does not match the specified WAN path.")
		}
		if pendingPolicy[l.Name()] && l.Gateway != nil {
			gwRes := lookups[[2]string{*l.Gateway, ""}]
			if len(gwRes) != 1 || gwRes[0]["dev"] != l.WAN || RouteKind(gwRes[0]) != "unicast" {
				return secureio.Stop("The Dual-ISP gateway is not reachable on the specified WAN interface.")
			}
		} else {
			res := lookups[[2]string{l.Peer, l.Source}]
			if len(res) != 1 || res[0]["dev"] != l.WAN || (l.Gateway != nil && res[0]["gateway"] != *l.Gateway) || RouteKind(res[0]) != "unicast" {
				return secureio.Stop("The existing peer route does not match the specified WAN path.")
			}
		}
	}

	fwd, err := h.IPv4Setting("ip_forward")
	if err != nil {
		return err
	}
	if fwd != "1" {
		return secureio.Stop("Preconfigure IPv4 forwarding on the VM before apply; no sysctl was changed.")
	}
	ifaces := map[string]bool{"all": true, "default": true}
	for _, l := range m.Links {
		ifaces[l.WAN] = true
	}
	for iface := range ifaces {
		raw, err := os.ReadFile(fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/rp_filter", iface))
		if err != nil {
			return secureio.Stop("Could not inspect reverse-path filtering sysctl.")
		}
		v := strings.TrimSpace(string(raw))
		if v != "0" && v != "2" {
			return secureio.Stop("Strict reverse-path filtering must be reviewed before this deployment.")
		}
	}
	return nil
}

func (h *OSHost) Baseline(
	rules, routes, links, foreignNFT []map[string]any,
	ownedRoutes map[RouteKey]struct{},
	ownedLinks map[string]struct{},
	ownedRules map[RuleKey]struct{},
) (map[string]string, error) {
	addrs, err := h.IP("address", "show")
	if err != nil {
		return nil, err
	}
	sshSvc, err := h.Service("ssh.service", "ActiveState")
	if err != nil {
		return nil, err
	}
	sshSockState, err := h.Service("ssh.socket", "ActiveState")
	if err != nil {
		return nil, err
	}
	sshSockListen, err := h.Service("ssh.socket", "Listen")
	if err != nil {
		return nil, err
	}
	ssOut, err := h.Command("SSH listener snapshot", []string{"ss", "-H", "-ltnp"}, nil, nil, 30*time.Second, false)
	if err != nil {
		return nil, err
	}
	var sshListeners []string
	for _, line := range strings.Split(ssOut, "\n") {
		if strings.Contains(line, `("sshd",`) {
			fields := strings.Fields(line)
			if len(fields) > 3 {
				sshListeners = append(sshListeners, fields[3])
			}
		}
	}
	sort.Strings(sshListeners)

	var foreignRules, defaultRoutes, foreignRoutes, foreignLinks []map[string]any
	for _, r := range rules {
		if _, ok := ownedRules[ParseRuleKey(r)]; !ok {
			foreignRules = append(foreignRules, r)
		}
	}
	for _, r := range routes {
		rk := ParseRouteKey(r)
		if _, ok := ownedRoutes[rk]; ok {
			continue
		}
		if rk.Protocol == "kernel" && rk.Dev != "" {
			if _, ok := ownedLinks[rk.Dev]; ok {
				continue
			}
		}
		foreignRoutes = append(foreignRoutes, r)
		if r["dst"] == "default" {
			defaultRoutes = append(defaultRoutes, r)
		}
	}
	for _, l := range links {
		name, _ := l["ifname"].(string)
		if _, ok := ownedLinks[name]; ok || strings.HasPrefix(name, "veth") {
			continue
		}
		var linkKind any
		if li, ok := l["linkinfo"].(map[string]any); ok {
			lk := map[string]any{}
			if v, ok := li["info_kind"]; ok {
				lk["info_kind"] = v
			}
			if v, ok := li["info_slave_kind"]; ok {
				lk["info_slave_kind"] = v
			}
			linkKind = lk
		}
		foreignLinks = append(foreignLinks, map[string]any{
			"ifname":   l["ifname"],
			"address":  l["address"],
			"mtu":      l["mtu"],
			"linkinfo": linkKind,
		})
	}
	var addrSummary []any
	for _, row := range addrs {
		name, _ := row["ifname"].(string)
		if _, ok := ownedLinks[name]; ok || strings.HasPrefix(name, "veth") {
			continue
		}
		var tuples []string
		if infos, ok := row["addr_info"].([]any); ok {
			for _, it := range infos {
				if im, ok := it.(map[string]any); ok {
					tuples = append(tuples, fmt.Sprintf("%v|%v|%v", im["family"], im["local"], im["prefixlen"]))
				}
			}
		}
		sort.Strings(tuples)
		addrSummary = append(addrSummary, []any{name, tuples})
	}

	sysctlMap := make(map[string]string, 3)
	for _, k := range []string{"ip_forward", "conf.all.rp_filter", "conf.default.rp_filter"} {
		v, err := h.IPv4Setting(k)
		if err != nil {
			return nil, err
		}
		sysctlMap[k] = v
	}

	return map[string]string{
		"rules":          Fingerprint(foreignRules),
		"default_routes": Fingerprint(defaultRoutes),
		"foreign_routes": Fingerprint(foreignRoutes),
		"foreign_links":  Fingerprint(foreignLinks),
		"addresses":      Fingerprint(addrSummary),
		"foreign_nft":    Fingerprint(foreignNFT),
		"ssh": Fingerprint(map[string]any{
			"ssh.service": sshSvc,
			"ssh.socket":  sshSockState,
			"socket":      sshSockListen,
			"listeners":   sshListeners,
		}),
		"sysctl": Fingerprint(sysctlMap),
	}, nil
}

// Fingerprint strips volatile counters/handles/expiry fields and returns canonical SHA-256.
func Fingerprint(data any) string {
	cleaned := cleanVolatile(data)
	b, _ := manifest.CanonicalJSON(cleaned)
	return manifest.Digest(b)
}

func cleanVolatile(v any) any {
	switch tv := v.(type) {
	case []map[string]any:
		out := make([]any, len(tv))
		for i, item := range tv {
			out[i] = cleanVolatile(item)
		}
		return out
	case []any:
		out := make([]any, len(tv))
		for i, item := range tv {
			out[i] = cleanVolatile(item)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(tv))
		for k, item := range tv {
			if k == "handle" || k == "expires" || k == "used" ||
				k == "gc_timer" || k == "hello_timer" || k == "tcn_timer" || k == "topology_change_timer" ||
				k == "valid_life_time" || k == "preferred_life_time" {
				continue
			}
			if k == "counter" {
				out[k] = map[string]any{}
				continue
			}
			out[k] = cleanVolatile(item)
		}
		return out
	default:
		return v
	}
}
