package resources

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
	"github.com/yikkrrtykj/event-ipsec-hub/internal/sa"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/secureio"
)

const (
	SwanctlDir   = "/etc/swanctl"
	PolicyMetric = "100"
)

type LinkSpec struct {
	Name string
	IfID uint32
}

func RouteSpecs(manifests []*manifest.DeploymentManifest) map[host.RouteKey]struct{} {
	res := make(map[host.RouteKey]struct{})
	for _, m := range manifests {
		if m == nil {
			continue
		}
		for _, l := range m.Links {
			for _, cidr := range l.RemoteTS {
				res[host.RouteKey{
					Destination: cidr,
					Kind:        "unicast",
					Dev:         l.Name(),
					Metric:      strconv.Itoa(l.RoutePriority),
					Protocol:    manifest.RouteProtocol,
					Table:       "254",
				}] = struct{}{}
				res[host.RouteKey{
					Destination: cidr,
					Kind:        "blackhole",
					Dev:         "",
					Metric:      strconv.Itoa(manifest.BlackholeMetric),
					Protocol:    manifest.RouteProtocol,
					Table:       "254",
				}] = struct{}{}
			}
		}
	}
	return res
}

func PolicyRuleSpecs(manifests []*manifest.DeploymentManifest) map[host.RuleKey]struct{} {
	res := make(map[host.RuleKey]struct{})
	for _, m := range manifests {
		if m == nil {
			continue
		}
		for _, l := range m.Links {
			if l.RouteTable != nil {
				res[host.RuleKey{
					Priority: l.PolicyPriority,
					Source:   l.Source + "/32",
					Table:    strconv.Itoa(*l.RouteTable),
				}] = struct{}{}
			}
		}
	}
	return res
}

func TableRouteSpecs(manifests []*manifest.DeploymentManifest) map[host.RouteKey]string {
	res := make(map[host.RouteKey]string)
	for _, m := range manifests {
		if m == nil {
			continue
		}
		for _, l := range m.Links {
			if l.RouteTable != nil && l.Gateway != nil {
				k := host.RouteKey{
					Destination: "default",
					Kind:        "unicast",
					Dev:         l.WAN,
					Metric:      PolicyMetric,
					Protocol:    manifest.RouteProtocol,
					Table:       strconv.Itoa(*l.RouteTable),
				}
				res[k] = *l.Gateway
			}
		}
	}
	return res
}

func LinkSpecs(manifests []*manifest.DeploymentManifest) map[LinkSpec]struct{} {
	res := make(map[LinkSpec]struct{})
	for _, m := range manifests {
		if m == nil {
			continue
		}
		for _, l := range m.Links {
			res[LinkSpec{Name: l.Name(), IfID: l.IfID}] = struct{}{}
		}
	}
	return res
}

func NetworkScope(manifests []*manifest.DeploymentManifest) []string {
	set := make(map[string]struct{})
	for _, m := range manifests {
		if m == nil {
			continue
		}
		for _, c := range m.Networks() {
			set[c] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for c := range set {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

type NetworkView struct {
	Rules       []map[string]any
	Routes      []map[string]any
	Links       []map[string]any
	OwnedRoutes map[host.RouteKey]struct{}
	OwnedLinks  map[string]struct{}
	OwnedNFT    []map[string]any
	ForeignNFT  []map[string]any
	OwnedRules  map[host.RuleKey]struct{}
}

// Manager applies and verifies only declared project-owned network, nftables, and VICI objects.
type Manager struct {
	Host        host.Runner
	Token       string
	Alias       string
	Candidates  []*manifest.DeploymentManifest
	Routes      map[host.RouteKey]struct{}
	PolicyRules map[host.RuleKey]struct{}
	TableRoutes map[host.RouteKey]string
	Links       map[LinkSpec]struct{}
}

func NewManager(h host.Runner, token string, candidates []*manifest.DeploymentManifest) *Manager {
	return &Manager{
		Host:        h,
		Token:       token,
		Alias:       "ipsecvpn:" + token,
		Candidates:  candidates,
		Routes:      RouteSpecs(candidates),
		PolicyRules: PolicyRuleSpecs(candidates),
		TableRoutes: TableRouteSpecs(candidates),
		Links:       LinkSpecs(candidates),
	}
}

func (m *Manager) RuntimeDir() string {
	return filepath.Join(SwanctlDir, "ipsecvpn-"+m.Token)
}

func (m *Manager) PurgeRuntime() error {
	mode := uint32(0o700)
	fd, err := secureio.TrustedDir(m.RuntimeDir(), &mode)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	_ = os.NewFile(uintptr(fd), m.RuntimeDir()).Close()
	if err := secureio.RemoveFile(filepath.Join(m.RuntimeDir(), "swanctl.conf")); err != nil {
		return err
	}
	if err := os.Remove(m.RuntimeDir()); err != nil && !os.IsNotExist(err) {
		return secureio.Stop("Could not remove temporary swanctl runtime directory.")
	}
	return secureio.SyncDir(SwanctlDir)
}

func (m *Manager) LinkNames() map[string]struct{} {
	out := make(map[string]struct{}, len(m.Links))
	for ls := range m.Links {
		out[ls.Name] = struct{}{}
	}
	return out
}

func (m *Manager) Network() (*NetworkView, error) {
	rules, routes, links, err := m.Host.Routing(m.PolicyRules)
	if err != nil {
		return nil, err
	}
	ownedLinks := make(map[string]struct{})
	for _, row := range links {
		name, _ := row["ifname"].(string)
		ifID, hasID := host.XFRMID(row)
		if alias, _ := row["ifalias"].(string); alias == m.Alias {
			if !hasID {
				return nil, secureio.Stop("An unregistered interface carries the project ownership tag.")
			}
			if _, ok := m.Links[LinkSpec{Name: name, IfID: ifID}]; !ok {
				return nil, secureio.Stop("An unregistered interface carries the project ownership tag.")
			}
			ownedLinks[name] = struct{}{}
		} else {
			for ls := range m.Links {
				if name == ls.Name || (hasID && ifID == ls.IfID) {
					return nil, secureio.Stop("An XFRM name or ID belongs to an unowned interface.")
				}
			}
		}
	}

	ownedRules := make(map[host.RuleKey]struct{})
	for _, row := range rules {
		rk := host.ParseRuleKey(row)
		if _, ok := m.PolicyRules[rk]; ok {
			ownedRules[rk] = struct{}{}
		}
	}

	ownedRoutes := make(map[host.RouteKey]struct{})
	for _, row := range routes {
		rk := host.ParseRouteKey(row)
		if _, ok := m.Routes[rk]; ok {
			if row["gateway"] != nil || row["nexthops"] != nil || row["prefsrc"] != nil {
				return nil, secureio.Stop("A project-marked route has unexpected routing attributes.")
			}
			if rk.Dev != "" {
				if _, ok := ownedLinks[rk.Dev]; !ok {
					return nil, secureio.Stop("A project-marked route is attached to an unowned interface.")
				}
			}
			ownedRoutes[rk] = struct{}{}
		} else if expectedGW, ok := m.TableRoutes[rk]; ok {
			if row["gateway"] != expectedGW || row["nexthops"] != nil {
				return nil, secureio.Stop("A project policy table route has unexpected gateway attributes.")
			}
			ownedRoutes[rk] = struct{}{}
		} else if rk.Protocol == manifest.RouteProtocol {
			return nil, secureio.Stop("An unregistered route uses the project route protocol.")
		}
	}

	nftObjs, err := m.Host.NFT()
	if err != nil {
		return nil, err
	}
	ownedNFT, foreignNFT := host.SeparateNFT(nftObjs)
	if len(ownedNFT) > 0 && !hasOwnerChain(ownedNFT, m.Token) {
		return nil, secureio.ObservationStop("The private nftables table is not owned by this installation.", "NFTABLES", "")
	}
	return &NetworkView{
		Rules:       rules,
		Routes:      routes,
		Links:       links,
		OwnedRoutes: ownedRoutes,
		OwnedLinks:  ownedLinks,
		OwnedNFT:    ownedNFT,
		ForeignNFT:  foreignNFT,
		OwnedRules:  ownedRules,
	}, nil
}

func hasOwnerChain(objs []map[string]any, token string) bool {
	want := "owner_" + token
	for _, item := range objs {
		if ch, ok := item["chain"].(map[string]any); ok && ch["name"] == want {
			return true
		}
	}
	return false
}

func (m *Manager) Preflight(target *manifest.DeploymentManifest) (map[string]string, error) {
	view, err := m.Network()
	if err != nil {
		return nil, err
	}
	if err := m.Host.CheckFirewall(view.ForeignNFT); err != nil {
		return nil, err
	}
	if err := m.Host.CheckPaths(target, view.Routes, view.OwnedRoutes, view.Links, view.OwnedLinks, view.OwnedRules); err != nil {
		return nil, err
	}
	return m.Host.Baseline(view.Rules, view.Routes, view.Links, view.ForeignNFT, view.OwnedRoutes, view.OwnedLinks, view.OwnedRules)
}

func (m *Manager) Baseline() (map[string]string, error) {
	view, err := m.Network()
	if err != nil {
		return nil, err
	}
	return m.Host.Baseline(view.Rules, view.Routes, view.Links, view.ForeignNFT, view.OwnedRoutes, view.OwnedLinks, view.OwnedRules)
}

func (m *Manager) ApplyNFT(target *manifest.DeploymentManifest, transition bool) error {
	nftObjs, err := m.Host.NFT()
	if err != nil {
		return err
	}
	owned, _ := host.SeparateNFT(nftObjs)
	if len(owned) > 0 && !hasOwnerChain(owned, m.Token) {
		return secureio.Stop("The nftables table cannot be proven owned.")
	}
	var content strings.Builder
	if len(owned) > 0 {
		fmt.Fprintf(&content, "delete table ip %s\n", manifest.Table)
	}
	if transition {
		ifaces := make([]string, 0, len(m.Links))
		for ls := range m.Links {
			ifaces = append(ifaces, ls.Name)
		}
		content.WriteString(manifest.NFTConfig(nil, m.Token, NetworkScope(m.Candidates), ifaces, target))
	} else if target != nil {
		content.WriteString(manifest.NFTConfig(target, m.Token, nil, nil, nil))
	}
	if content.Len() > 0 {
		raw := []byte(content.String())
		if _, err := m.Host.Command("nft syntax check", []string{"nft", "-c", "-f", "-"}, raw, nil, 30*time.Second, false); err != nil {
			return err
		}
		if _, err := m.Host.Command("nft atomic update", []string{"nft", "-f", "-"}, raw, nil, 30*time.Second, true); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) routeOp(op string, rk host.RouteKey) error {
	args := []string{"ip", "-4", "route", op}
	if rk.Kind == "blackhole" {
		args = append(args, "blackhole", rk.Destination)
	} else {
		args = append(args, rk.Destination, "dev", rk.Dev)
	}
	args = append(args, "table", "main", "proto", rk.Protocol, "metric", rk.Metric)
	_, err := m.Host.Command(fmt.Sprintf("IPv4 %s route %s", rk.Kind, op), args, nil, nil, 30*time.Second, true)
	return err
}

func (m *Manager) tableRouteOp(op string, rk host.RouteKey, gw string) error {
	args := []string{"ip", "-4", "route", op, "default", "via", gw, "dev", rk.Dev, "table", rk.Table, "proto", rk.Protocol, "metric", rk.Metric}
	_, err := m.Host.Command("IPv4 policy table route "+op, args, nil, nil, 30*time.Second, true)
	return err
}

func (m *Manager) policyRuleOp(op string, rk host.RuleKey) error {
	args := []string{"ip", "-4", "rule", op, "from", rk.Source, "table", rk.Table, "priority", strconv.Itoa(rk.Priority)}
	_, err := m.Host.Command("IPv4 policy rule "+op, args, nil, nil, 30*time.Second, true)
	return err
}

func (m *Manager) Guard(handshake *manifest.DeploymentManifest) error {
	if err := m.ApplyNFT(handshake, true); err != nil {
		return err
	}
	view, err := m.Network()
	if err != nil {
		return err
	}
	for _, rk := range sortedRoutes(m.Routes) {
		if rk.Kind == "blackhole" {
			if _, exists := view.OwnedRoutes[rk]; !exists {
				if err := m.routeOp("add", rk); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (m *Manager) Load(target *manifest.DeploymentManifest, keys map[string][]byte) error {
	if err := m.Host.AssertExclusiveIKE(m.LinkNames()); err != nil {
		return err
	}
	if err := secureio.MakeDirectory(m.RuntimeDir(), 0o700); err != nil {
		return err
	}
	conf := filepath.Join(m.RuntimeDir(), "swanctl.conf")
	if err := secureio.AtomicWrite(conf, []byte(manifest.SwanctlConfig(target, keys)), 0o600); err != nil {
		_ = m.PurgeRuntime()
		return err
	}
	defer func() { _ = m.PurgeRuntime() }()
	_, err := m.Host.Command("VICI load", []string{"swanctl", "--load-all", "--clear", "--noprompt", "--file", conf, "--uri", host.SocketURI}, nil, nil, 30*time.Second, true)
	return err
}

type LoaderFunc func(target *manifest.DeploymentManifest, keys map[string][]byte) error

func (m *Manager) Replace(target *manifest.DeploymentManifest, keys map[string][]byte, loader LoaderFunc, hold bool, handshake *manifest.DeploymentManifest) error {
	if err := m.Guard(handshake); err != nil {
		return err
	}
	if err := m.Host.AssertExclusiveIKE(m.LinkNames()); err != nil {
		return err
	}
	view, err := m.Network()
	if err != nil {
		return err
	}
	single := []*manifest.DeploymentManifest{target}
	desiredLinks := LinkSpecs(single)
	desiredRoutes := RouteSpecs(single)
	desiredTableRoutes := TableRouteSpecs(single)
	desiredRules := PolicyRuleSpecs(single)

	for _, rk := range sortedRules(view.OwnedRules) {
		if _, keep := desiredRules[rk]; !keep {
			if err := m.policyRuleOp("del", rk); err != nil {
				return err
			}
		}
	}
	for _, tk := range sortedRoutes(view.OwnedRoutes) {
		if gw, isTbl := m.TableRoutes[tk]; isTbl {
			if _, keep := desiredTableRoutes[tk]; !keep {
				if err := m.tableRouteOp("del", tk, gw); err != nil {
					return err
				}
			}
		}
	}
	for _, rk := range sortedRoutes(view.OwnedRoutes) {
		if _, isMain := m.Routes[rk]; isMain && rk.Kind == "unicast" {
			if _, keep := desiredRoutes[rk]; !keep {
				if err := m.routeOp("del", rk); err != nil {
					return err
				}
			}
		}
	}
	for _, row := range view.Links {
		name, _ := row["ifname"].(string)
		if _, isOwned := view.OwnedLinks[name]; isOwned {
			id, _ := host.XFRMID(row)
			if _, keep := desiredLinks[LinkSpec{Name: name, IfID: id}]; !keep {
				if _, err := m.Host.Command("XFRM delete", []string{"ip", "link", "del", "dev", name}, nil, nil, 30*time.Second, true); err != nil {
					return err
				}
			}
		}
	}
	for _, ls := range sortedLinks(desiredLinks) {
		if _, exists := view.OwnedLinks[ls.Name]; !exists {
			if _, err := m.Host.Command("XFRM create", []string{"ip", "link", "add", "name", ls.Name, "type", "xfrm", "if_id", strconv.FormatUint(uint64(ls.IfID), 10)}, nil, nil, 30*time.Second, true); err != nil {
				return err
			}
			// Linux 6.8 ignores IFLA_IFALIAS on newlink; set alias and up explicitly.
			if _, err := m.Host.Command("XFRM mark and activate", []string{"ip", "link", "set", "dev", ls.Name, "alias", m.Alias, "up"}, nil, nil, 30*time.Second, true); err != nil {
				return err
			}
		} else {
			if _, err := m.Host.Command("XFRM up", []string{"ip", "link", "set", "dev", ls.Name, "up"}, nil, nil, 30*time.Second, true); err != nil {
				return err
			}
		}
	}

	cur, err := m.Network()
	if err != nil {
		return err
	}
	for _, tk := range sortedTableKeys(desiredTableRoutes) {
		if _, exists := cur.OwnedRoutes[tk]; !exists {
			if err := m.tableRouteOp("add", tk, desiredTableRoutes[tk]); err != nil {
				return err
			}
		}
	}
	for _, rk := range sortedRules(desiredRules) {
		if _, exists := cur.OwnedRules[rk]; !exists {
			if err := m.policyRuleOp("add", rk); err != nil {
				return err
			}
		}
	}
	for _, rk := range sortedRoutes(desiredRoutes) {
		if _, exists := cur.OwnedRoutes[rk]; !exists {
			if err := m.routeOp("add", rk); err != nil {
				return err
			}
		}
	}

	if loader != nil {
		if err := loader(target, keys); err != nil {
			return err
		}
	} else {
		if err := m.Load(target, keys); err != nil {
			return err
		}
	}
	if hold {
		return m.ApplyNFT(target, true)
	}
	return m.Finish(target)
}

func (m *Manager) Finish(target *manifest.DeploymentManifest) error {
	cur, err := m.Network()
	if err != nil {
		return err
	}
	single := []*manifest.DeploymentManifest{target}
	desiredRoutes := RouteSpecs(single)
	desiredTableRoutes := TableRouteSpecs(single)
	desiredRules := PolicyRuleSpecs(single)

	for _, rk := range sortedRules(cur.OwnedRules) {
		if _, keep := desiredRules[rk]; !keep {
			if err := m.policyRuleOp("del", rk); err != nil {
				return err
			}
		}
	}
	for _, tk := range sortedRoutes(cur.OwnedRoutes) {
		if gw, isTbl := m.TableRoutes[tk]; isTbl {
			if _, keep := desiredTableRoutes[tk]; !keep {
				if err := m.tableRouteOp("del", tk, gw); err != nil {
					return err
				}
			}
		}
	}
	for _, rk := range sortedRoutes(cur.OwnedRoutes) {
		if _, isMain := m.Routes[rk]; isMain {
			if _, keep := desiredRoutes[rk]; !keep {
				if err := m.routeOp("del", rk); err != nil {
					return err
				}
			}
		}
	}
	return m.ApplyNFT(target, false)
}

func (m *Manager) Verify(expected *manifest.DeploymentManifest, baseline map[string]string, nftSHA string, live *sa.Snapshot) (string, error) {
	if live != nil && live.Manifest != expected {
		return "", secureio.Stop("The live SA proof does not belong to the expected manifest.")
	}
	view, err := m.Network()
	if err != nil {
		return "", err
	}
	single := []*manifest.DeploymentManifest{expected}
	wantedLinks := make(map[string]struct{})
	for ls := range LinkSpecs(single) {
		wantedLinks[ls.Name] = struct{}{}
	}
	upLinks := make(map[string]struct{})
	for _, row := range view.Links {
		name, _ := row["ifname"].(string)
		if _, ok := view.OwnedLinks[name]; !ok {
			continue
		}
		if flags, ok := row["flags"].([]any); ok {
			for _, f := range flags {
				if f == "UP" {
					upLinks[name] = struct{}{}
					break
				}
			}
		}
	}
	expRoutes := RouteSpecs(single)
	for tk := range TableRouteSpecs(single) {
		expRoutes[tk] = struct{}{}
	}
	expRules := PolicyRuleSpecs(single)
	if !sameSet(view.OwnedLinks, wantedLinks) || !sameSet(upLinks, wantedLinks) ||
		!sameRouteSet(view.OwnedRoutes, expRoutes) || !sameRuleSet(view.OwnedRules, expRules) {
		return "", secureio.ObservationStop("Observed XFRM interfaces or exact routes differ from the manifest.", "ROUTING", "")
	}
	hasTable := len(view.OwnedNFT) > 0
	if hasTable != (expected != nil) || (nftSHA != "" && nftSHA != host.Fingerprint(view.OwnedNFT)) {
		return "", secureio.ObservationStop("Observed project nftables rules differ from the expected state.", "NFTABLES", "")
	}

	conns, err := m.Host.VICIConnections()
	if err != nil {
		return "", err
	}
	connNames := make(map[string]struct{}, len(conns))
	for k := range conns {
		connNames[k] = struct{}{}
	}
	if !sameSet(connNames, wantedLinks) {
		return "", secureio.ObservationStop("The daemon did not report exactly the intended VICI connections.", "VICI", "")
	}

	if live == nil {
		sasOut, err := m.Host.VICI("--list-sas")
		if err != nil {
			return "", err
		}
		sasOut = strings.TrimSpace(sasOut)
		autoStarted := false
		if expected != nil {
			for _, l := range expected.Links {
				if l.StartAction != "none" {
					autoStarted = true
					break
				}
			}
		}
		if sasOut != "" {
			for _, line := range strings.Split(sasOut, "\n") {
				if line != "" && line[0] != ' ' && line[0] != '\t' {
					name, _, _ := strings.Cut(line, ":")
					if _, ok := wantedLinks[name]; !autoStarted || !ok {
						return "", secureio.ObservationStop("The daemon did not report exactly the intended VICI connections.", "VICI", "")
					}
				}
			}
		}
	}

	if expected != nil {
		for _, l := range expected.Links {
			rows := conns[l.Name()]
			listing := strings.Join(rows, "\n")
			if !containsLine(rows, "  local:  "+l.Source) || !containsLine(rows, "  remote: "+l.Peer) {
				return "", secureio.Stop("The loaded VICI peer addresses or CHILD differ from the manifest.")
			}
			specs := l.ChildSpecs()
			for _, sp := range specs {
				re := regexp.MustCompile(`(?m)^  ` + regexp.QuoteMeta(sp.Name) + `: TUNNEL\b`)
				if !re.MatchString(listing) {
					return "", secureio.Stop("The loaded VICI peer addresses or CHILD differ from the manifest.")
				}
			}
			for _, dir := range []struct {
				label string
				get   func(manifest.ChildSpec) []string
			}{
				{"local", func(sp manifest.ChildSpec) []string { return sp.LocalTS }},
				{"remote", func(sp manifest.ChildSpec) []string { return sp.RemoteTS }},
			} {
				re := regexp.MustCompile(`(?m)^    ` + dir.label + `:\s+(.+)$`)
				matches := re.FindAllStringSubmatch(listing, -1)
				if len(matches) != len(specs) {
					return "", secureio.Stop("The loaded VICI selectors differ from the authorized CIDRs.")
				}
				for idx, mRow := range matches {
					if !sameStringSliceSet(strings.Fields(mRow[1]), dir.get(specs[idx])) {
						return "", secureio.Stop("The loaded VICI selectors differ from the authorized CIDRs.")
					}
				}
			}
		}
	}

	type bestRoute struct {
		metric int
		dev    string
	}
	bestByCIDR := make(map[string]bestRoute)
	for rk := range view.OwnedRoutes {
		if _, isMain := m.Routes[rk]; isMain && rk.Kind == "unicast" {
			met, _ := strconv.Atoi(rk.Metric)
			if cur, ok := bestByCIDR[rk.Destination]; !ok || met < cur.metric {
				bestByCIDR[rk.Destination] = bestRoute{metric: met, dev: rk.Dev}
			}
		}
	}
	if len(bestByCIDR) > 0 {
		var targets [][2]string
		for cidr := range bestByCIDR {
			ip, _, _ := strings.Cut(cidr, "/")
			targets = append(targets, [2]string{ip, ""})
		}
		lookups, err := m.Host.RouteLookups(targets)
		if err != nil {
			return "", err
		}
		for cidr, best := range bestByCIDR {
			ip, _, _ := strings.Cut(cidr, "/")
			res := lookups[[2]string{ip, ""}]
			if len(res) != 1 || res[0]["dev"] != best.dev {
				return "", secureio.ObservationStop("The kernel did not resolve a protected network through its XFRM.", "ROUTING", "")
			}
		}
	}

	if expected != nil {
		var policyLinks []manifest.Link
		for _, l := range expected.Links {
			if l.RouteTable != nil {
				policyLinks = append(policyLinks, l)
			}
		}
		if len(policyLinks) > 0 {
			targets := make([][2]string, 0, len(policyLinks))
			for _, l := range policyLinks {
				targets = append(targets, [2]string{l.Peer, l.Source})
			}
			lookups, err := m.Host.RouteLookups(targets)
			if err != nil {
				return "", err
			}
			for _, l := range policyLinks {
				res := lookups[[2]string{l.Peer, l.Source}]
				if len(res) != 1 || res[0]["dev"] != l.WAN || (l.Gateway != nil && res[0]["gateway"] != *l.Gateway) {
					return "", secureio.ObservationStop("Dual-ISP policy routing did not resolve peer via expected WAN gateway.", "ROUTING", "")
				}
			}
		}
	}

	curBase, err := m.Baseline()
	if err != nil {
		return "", err
	}
	if !equalStringMap(curBase, baseline) {
		var changed []string
		for k, v := range curBase {
			if baseline[k] != v {
				changed = append(changed, k)
			}
		}
		sort.Strings(changed)
		return "", secureio.Stop("A protected non-project host baseline changed (" + strings.Join(changed, ", ") + ").")
	}
	if hasTable {
		return host.Fingerprint(view.OwnedNFT), nil
	}
	return "", nil
}

func containsLine(rows []string, want string) bool {
	for _, r := range rows {
		if r == want {
			return true
		}
	}
	return false
}

func sameStringSliceSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := make(map[string]struct{}, len(a))
	for _, x := range a {
		m[x] = struct{}{}
	}
	for _, y := range b {
		if _, ok := m[y]; !ok {
			return false
		}
	}
	return len(m) == len(b)
}

func sameSet[T comparable](a, b map[T]struct{}) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if _, ok := b[k]; !ok {
			return false
		}
	}
	return true
}

func sameRouteSet(a, b map[host.RouteKey]struct{}) bool { return sameSet(a, b) }
func sameRuleSet(a, b map[host.RuleKey]struct{}) bool   { return sameSet(a, b) }

func equalStringMap(a, b map[string]string) bool {
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

func sortedRoutes(m map[host.RouteKey]struct{}) []host.RouteKey {
	out := make([]host.RouteKey, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		return fmt.Sprint(out[i]) < fmt.Sprint(out[j])
	})
	return out
}

func sortedTableKeys(m map[host.RouteKey]string) []host.RouteKey {
	out := make([]host.RouteKey, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		return fmt.Sprint(out[i]) < fmt.Sprint(out[j])
	})
	return out
}

func sortedRules(m map[host.RuleKey]struct{}) []host.RuleKey {
	out := make([]host.RuleKey, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Priority != out[j].Priority {
			return out[i].Priority < out[j].Priority
		}
		return out[i].Source < out[j].Source
	})
	return out
}

func sortedLinks(m map[LinkSpec]struct{}) []LinkSpec {
	out := make([]LinkSpec, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
