package manifest

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yikkrrtykj/event-ipsec-hub/internal/profile"
)

func TestRenderDeterministicAndSecretFree(t *testing.T) {
	fixtures := []string{
		filepath.Join("..", "..", "tests", "fixtures", "arena-apac-eu.yaml"),
		filepath.Join("..", "..", "tests", "fixtures", "signal-eu-americas.yaml"),
		filepath.Join("..", "..", "tests", "fixtures", "studio-vlan.yaml"),
	}
	for _, f := range fixtures {
		p, err := profile.LoadProfile(f)
		if err != nil {
			t.Fatalf("load %s: %v", f, err)
		}
		first, err := Render(p)
		if err != nil {
			t.Fatalf("render %s: %v", f, err)
		}
		second, err := Render(p)
		if err != nil {
			t.Fatalf("render2 %s: %v", f, err)
		}
		b1, _ := json.Marshal(first)
		b2, _ := json.Marshal(second)
		if string(b1) != string(b2) {
			t.Fatalf("non-deterministic render for %s", f)
		}
		for _, sl := range p.SiteLinks {
			if strings.Contains(string(b1), sl.SecretRef) {
				t.Fatalf("secret_ref %s leaked into render output", sl.SecretRef)
			}
		}
		files := first["files"].(map[string]any)
		swan := files["swanctl.conf"].(map[string]any)["preview"].(string)
		if strings.Contains(swan, "0.0.0.0/0") {
			t.Fatalf("exact fixture %s should not contain wildcard selector", f)
		}
		if !strings.Contains(swan, "start_action = none") {
			t.Fatalf("expected start_action = none in %s", f)
		}
	}
}

func TestMultiOBIsolationAndHillstoneModes(t *testing.T) {
	p, err := profile.LoadProfile(filepath.Join("..", "..", "config", "esports-multi-ob-hillstone.example.yaml"))
	if err != nil {
		t.Fatalf("load multi-ob: %v", err)
	}
	m, err := BuildManifest(p)
	if err != nil {
		t.Fatalf("build manifest: %v", err)
	}
	if len(m.Links) != 3 {
		t.Fatalf("expected 3 links, got %d", len(m.Links))
	}
	nft := NFTConfig(m, "tok123", nil, nil, nil)
	forward := strings.Split(nft, "chain output")[0]

	bySite := map[string]Link{}
	for _, l := range m.Links {
		bySite[l.SiteID] = l
	}
	ob1, ob2, srv := bySite["ob-venue-1"], bySite["ob-venue-2"], bySite["server-core"]

	if !strings.Contains(forward, `tcp flags syn / syn,rst tcp option maxseg size set 1360`) {
		t.Fatal("expected TCP MSS 1360 clamping in forward chain")
	}
	if !strings.Contains(forward, `iifname "`+ob1.Name()+`" oifname "`+srv.Name()+`"`) {
		t.Fatal("missing OB1 -> Server allow rule")
	}
	if !strings.Contains(forward, `iifname "`+ob2.Name()+`" oifname "`+srv.Name()+`"`) {
		t.Fatal("missing OB2 -> Server allow rule")
	}
	if strings.Contains(forward, `iifname "`+ob1.Name()+`" oifname "`+ob2.Name()+`"`) {
		t.Fatal("OB1 -> OB2 must be isolated")
	}
	if strings.Contains(forward, `iifname "`+ob2.Name()+`" oifname "`+ob1.Name()+`"`) {
		t.Fatal("OB2 -> OB1 must be isolated")
	}

	swan := SwanctlConfig(m, nil)
	if !strings.Contains(swan, "local_ts = 0.0.0.0/0") {
		t.Fatal("route_based link should render 0.0.0.0/0 local_ts")
	}
	if !strings.Contains(swan, ob2.Child()+"-0 {") {
		t.Fatalf("per_pair link should split child into %s-0", ob2.Child())
	}

	diff := ResourceDiff(m, m)
	if len(diff["add"].([]string)) != 0 || len(diff["remove"].([]string)) != 0 || len(diff["update"].([]string)) != 0 {
		t.Fatalf("expected empty self-diff, got %+v", diff)
	}
}

func TestSingleSiteManifestAndNFT(t *testing.T) {
	raw := `schema_version: "2.0"
event:
  id: single-stage
  name: Single Site Staging
hub:
  id: hub-primary
  platform: ubuntu-24.04
  public_endpoint: 198.51.100.10
  provider_label: VPS
  location_label: Primary
sites:
  - id: venue-1
    display_name: Hillstone A3800
    role: venue
    public_endpoint: 203.0.113.10
    ike_identity: 203.0.113.10
    lan_cidrs:
      - 10.43.10.0/24
    firewall:
      vendor: Hillstone
site_links:
  - site_id: venue-1
    secret_ref: file:/etc/ipsecvpn/secrets/venue-1.psk
    if_id: 201
    selector_mode: route_based
    tunnel_local_cidr: 169.254.201.1/30
    outer_path:
      interface: eth0
      isp_label: ISP-A
traffic_policy:
  allowed_site_pairs: []
backup:
  enabled: false
`
	p, err := profile.ParseProfile([]byte(raw))
	if err != nil {
		t.Fatalf("parse single-site profile: %v", err)
	}
	m, err := BuildManifest(p)
	if err != nil {
		t.Fatalf("build single-site manifest: %v", err)
	}
	if len(m.Links) != 1 {
		t.Fatalf("expected 1 link, got %d", len(m.Links))
	}
	if len(m.Links[0].RemoteTS) != 1 || m.Links[0].RemoteTS[0] != "10.43.10.0/24" {
		t.Fatalf("unexpected remote_ts: %v", m.Links[0].RemoteTS)
	}
	if len(m.Links[0].LocalTS) != 1 || m.Links[0].LocalTS[0] != "169.254.201.0/30" {
		t.Fatalf("expected tunnel subnet fallback in local_ts, got %v", m.Links[0].LocalTS)
	}
	swan := SwanctlConfig(m, nil)
	if !strings.Contains(swan, "local_ts = 0.0.0.0/0") || !strings.Contains(swan, "remote_ts = 0.0.0.0/0") {
		t.Fatalf("route_based single site should use 0.0.0.0/0 selectors:\n%s", swan)
	}
	nft := NFTConfig(m, "tok1", nil, nil, nil)
	if !strings.Contains(nft, `tcp flags syn / syn,rst tcp option maxseg size set 1360`) {
		t.Fatalf("expected MSS clamp in single-site nft:\n%s", nft)
	}
	if !strings.Contains(nft, `ip saddr 169.254.201.0/30 icmp type { echo-request, echo-reply } accept`) {
		t.Fatalf("expected tunnel subnet ICMP accept in single-site nft:\n%s", nft)
	}
}

func TestIKEv1MainModeSwanctl(t *testing.T) {
	raw := `schema_version: "2.0"
event:
  id: ikev1-hillstone
  name: Hillstone IKEv1 Test
hub:
  id: hub-primary
  platform: ubuntu-24.04
  public_endpoint: 198.51.100.10
  provider_label: VPS
  location_label: Primary
sites:
  - id: venue-1
    display_name: Hillstone WebUI
    role: venue
    public_endpoint: 203.0.113.10
    ike_identity: 203.0.113.10
    lan_cidrs:
      - 10.43.10.0/24
    firewall:
      vendor: Hillstone
security:
  ike_version: 1
  ike_proposal: aes256-sha256-prfsha256-modp2048
  esp_proposal: aes256-sha256-modp2048
  ike_lifetime_seconds: 86400
  child_lifetime_seconds: 14400
  child_lifetime_kb: 4096000
site_links:
  - site_id: venue-1
    secret_ref: file:/etc/ipsecvpn/secrets/venue-1.psk
    if_id: 201
    selector_mode: route_based
    outer_path:
      interface: eth0
      isp_label: ISP-A
traffic_policy:
  allowed_site_pairs: []
backup:
  enabled: false
`
	p, err := profile.ParseProfile([]byte(raw))
	if err != nil {
		t.Fatalf("parse IKEv1 profile: %v", err)
	}
	m, err := BuildManifest(p)
	if err != nil {
		t.Fatalf("build IKEv1 manifest: %v", err)
	}
	swan := SwanctlConfig(m, nil)
	for _, want := range []string{
		"version = 1",
		"aggressive = no",
		"proposals = aes256-sha256-modp2048",
		"reauth_time = 86400s",
		"encap = no",
		"life_bytes = 4194304000",
	} {
		if !strings.Contains(swan, want) {
			t.Fatalf("expected %q in IKEv1 swanctl.conf:\n%s", want, swan)
		}
	}
}
