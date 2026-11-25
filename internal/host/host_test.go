package host

import (
	"strings"
	"testing"
)

func TestRouteKeyAndRuleVerification(t *testing.T) {
	rk := ParseRouteKey(map[string]any{
		"dst":      "10.44.50.0/24",
		"type":     6,
		"metric":   32760,
		"protocol": "242",
	})
	if rk.Kind != "blackhole" || rk.Table != "254" || rk.Metric != "32760" {
		t.Fatalf("unexpected route key: %+v", rk)
	}

	rules := []map[string]any{
		{"priority": 0, "src": "all", "table": "255"},
		{"priority": 1001, "src": "198.51.100.10", "table": "101"},
		{"priority": 32766, "src": "all", "table": "254"},
		{"priority": 32767, "src": "all", "table": "253"},
	}
	if err := VerifyRoutingRules(rules, nil); err == nil {
		t.Fatal("expected unpermitted custom policy rule to fail")
	}
	permitted := map[RuleKey]struct{}{
		{Priority: 1001, Source: "198.51.100.10/32", Table: "101"}: {},
	}
	if err := VerifyRoutingRules(rules, permitted); err != nil {
		t.Fatalf("expected permitted Dual-ISP rule to pass, got %v", err)
	}
}

func TestParseVICIConnectionsAndNFTSeparation(t *testing.T) {
	conns, err := ParseVICIConnections("foreign: IKEv1, no reauthentication\n  local:  192.0.2.10\n")
	if err != nil {
		t.Fatalf("ParseVICIConnections: %v", err)
	}
	if _, ok := conns["foreign"]; !ok {
		t.Fatal("legacy IKEv1 connection must not be ignored")
	}

	owned, foreign := SeparateNFT([]map[string]any{
		{"metainfo": map[string]any{"version": "1.0"}},
		{"table": map[string]any{"family": "ip", "name": "ipsecvpn"}},
		{"table": map[string]any{"family": "inet", "name": "lab_existing"}},
	})
	if len(owned) != 1 || len(foreign) != 1 {
		t.Fatalf("unexpected nft split: owned=%d foreign=%d", len(owned), len(foreign))
	}

	err = CheckFirewallObjects([]map[string]any{
		{"chain": map[string]any{"family": "inet", "table": "lab", "name": "forward", "hook": "forward", "policy": "drop"}},
	})
	if err == nil || !strings.Contains(err.Error(), "base chain") {
		t.Fatalf("expected drop base chain to fail, got %v", err)
	}
}
