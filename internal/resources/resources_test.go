package resources

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yikkrrtykj/event-ipsec-hub/internal/host"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/manifest"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/profile"
)

type fakeHost struct {
	manifest    *manifest.DeploymentManifest
	nftObjects  []map[string]any
	returnEmpty bool
}

func (f *fakeHost) SetStepHook(host.StepHook)                                      {}
func (f *fakeHost) Probe() (map[string]string, error)                              { return nil, nil }
func (f *fakeHost) Command(string, []string, []byte, []int, time.Duration, bool) (string, error) {
	return "", nil
}
func (f *fakeHost) JSON(string, ...string) (any, error)              { return nil, nil }
func (f *fakeHost) IP(...string) ([]map[string]any, error)           { return nil, nil }
func (f *fakeHost) Service(string, string) (string, error)           { return "", nil }
func (f *fakeHost) VICINames() (map[string]struct{}, error)          { return nil, nil }
func (f *fakeHost) PackageState() (map[string]host.PackageInfo, error) { return nil, nil }
func (f *fakeHost) APTPlan() (map[string]string, error)              { return nil, nil }
func (f *fakeHost) IKEPorts() (string, error)                        { return "", nil }
func (f *fakeHost) VICIListeners() ([]string, error)                 { return nil, nil }
func (f *fakeHost) AssertNoStarter() error                           { return nil }
func (f *fakeHost) AssertNoOtherIKE() error                          { return nil }
func (f *fakeHost) AssertIdleIKE() error                             { return nil }
func (f *fakeHost) AssertExclusiveIKE(map[string]struct{}) error     { return nil }
func (f *fakeHost) AssertDaemon(map[string]struct{}) (int, error)    { return 1, nil }
func (f *fakeHost) AssertPrivateDaemon(int) error                    { return nil }
func (f *fakeHost) CheckPaths(*manifest.DeploymentManifest, []map[string]any, map[host.RouteKey]struct{}, []map[string]any, map[string]struct{}, map[host.RuleKey]struct{}) error {
	return nil
}
func (f *fakeHost) CheckFirewall([]map[string]any) error { return nil }
func (f *fakeHost) IPv4Setting(string) (string, error)   { return "1", nil }

func (f *fakeHost) Routing(permitted map[host.RuleKey]struct{}) ([]map[string]any, []map[string]any, []map[string]any, error) {
	if f.returnEmpty {
		return nil, nil, nil, nil
	}
	rules := []map[string]any{
		{"priority": 0, "src": "all", "table": "255"},
		{"priority": 1001, "src": "198.51.100.10", "table": "101"},
		{"priority": 32766, "src": "all", "table": "254"},
		{"priority": 32767, "src": "all", "table": "253"},
	}
	if err := host.VerifyRoutingRules(rules, permitted); err != nil {
		return nil, nil, nil, err
	}
	routes := []map[string]any{
		{"dst": "default", "dev": "eth0", "gateway": "198.51.100.1", "table": "254"},
		{"dst": "default", "dev": "eth0", "gateway": "198.51.100.1", "metric": 100, "protocol": manifest.RouteProtocol, "table": "101"},
	}
	var links []map[string]any
	for _, l := range f.manifest.Links {
		for _, cidr := range l.RemoteTS {
			routes = append(routes,
				map[string]any{"dst": cidr, "dev": l.Name(), "metric": l.RoutePriority, "protocol": manifest.RouteProtocol, "table": "254"},
				map[string]any{"dst": cidr, "type": "blackhole", "metric": manifest.BlackholeMetric, "protocol": manifest.RouteProtocol, "table": "254"},
			)
		}
		links = append(links, map[string]any{
			"ifname":   l.Name(),
			"ifalias":  "ipsecvpn:tok",
			"flags":    []any{"UP"},
			"linkinfo": map[string]any{"info_kind": "xfrm", "info_data": map[string]any{"if_id": l.IfID}},
		})
	}
	return rules, routes, links, nil
}

func (f *fakeHost) NFT() ([]map[string]any, error) {
	if f.nftObjects != nil {
		return f.nftObjects, nil
	}
	return []map[string]any{
		{"table": map[string]any{"family": "ip", "name": "ipsecvpn"}},
		{"chain": map[string]any{"family": "ip", "table": "ipsecvpn", "name": "owner_tok"}},
	}, nil
}

func (f *fakeHost) VICIConnections() (map[string][]string, error) {
	conns := make(map[string][]string)
	for _, l := range f.manifest.Links {
		rows := []string{"  local:  " + l.Source, "  remote: " + l.Peer}
		for _, sp := range l.ChildSpecs() {
			rows = append(rows,
				"  "+sp.Name+": TUNNEL",
				"    local:  "+strings.Join(sp.LocalTS, " "),
				"    remote: "+strings.Join(sp.RemoteTS, " "),
			)
		}
		conns[l.Name()] = rows
	}
	return conns, nil
}

func (f *fakeHost) VICI(action string, _ ...string) (string, error) {
	if action == "--list-sas" && f.manifest != nil && len(f.manifest.Links) > 0 {
		return fmt.Sprintf("%s: #1, CONNECTING\n", f.manifest.Links[0].Name()), nil
	}
	return "", nil
}

func (f *fakeHost) RouteLookups(targets [][2]string) (map[[2]string][]map[string]any, error) {
	byPrefix := make(map[string]string)
	for _, l := range f.manifest.Links {
		for _, c := range l.RemoteTS {
			ip, _, _ := strings.Cut(c, "/")
			byPrefix[ip] = l.Name()
		}
	}
	out := make(map[[2]string][]map[string]any, len(targets))
	for _, t := range targets {
		if t[1] != "" {
			out[t] = []map[string]any{{"dev": "eth0", "gateway": "198.51.100.1"}}
		} else {
			out[t] = []map[string]any{{"dev": byPrefix[t[0]]}}
		}
	}
	return out, nil
}

func (f *fakeHost) Baseline(_, _, _, _ []map[string]any, _ map[host.RouteKey]struct{}, _ map[string]struct{}, _ map[host.RuleKey]struct{}) (map[string]string, error) {
	return map[string]string{"ok": "1"}, nil
}

func TestOwnershipMarkerRejectsForeignTable(t *testing.T) {
	fh := &fakeHost{
		returnEmpty: true,
		nftObjects:  []map[string]any{{"table": map[string]any{"family": "ip", "name": "ipsecvpn"}}},
	}
	mgr := NewManager(fh, "new", nil)
	_, err := mgr.Network()
	if err == nil || !strings.Contains(err.Error(), "not owned") {
		t.Fatalf("expected foreign nftables table rejection, got %v", err)
	}
}

func TestVerifyAcceptsMultiOBRouteBasedPerPairDualISP(t *testing.T) {
	p, err := profile.LoadProfile(filepath.Join("..", "..", "config", "esports-multi-ob-hillstone.example.yaml"))
	if err != nil {
		t.Fatalf("load profile: %v", err)
	}
	m, err := manifest.BuildManifest(p)
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	fh := &fakeHost{manifest: m}
	mgr := NewManager(fh, "tok", []*manifest.DeploymentManifest{m})
	sha, err := mgr.Verify(m, map[string]string{"ok": "1"}, "", nil)
	if err != nil || sha == "" {
		t.Fatalf("expected Verify pass with nft sha, got sha=%q err=%v", sha, err)
	}
}
