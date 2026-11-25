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
