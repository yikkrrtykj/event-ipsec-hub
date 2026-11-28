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

func TestCheckFirewallDockerCoexistence(t *testing.T) {
	// Standard Ubuntu 24.04 Docker iptables-nft layout (FORWARD policy accept, bridge-scoped rules).
	dockerObjs := []map[string]any{
		{"chain": map[string]any{"family": "ip", "table": "nat", "name": "DOCKER"}},
		{"chain": map[string]any{"family": "ip", "table": "nat", "name": "PREROUTING", "hook": "prerouting", "policy": "accept"}},
		{"chain": map[string]any{"family": "ip", "table": "nat", "name": "OUTPUT", "hook": "output", "policy": "accept"}},
		{"chain": map[string]any{"family": "ip", "table": "nat", "name": "POSTROUTING", "hook": "postrouting", "policy": "accept"}},
		{"rule": map[string]any{
			"family": "ip", "table": "nat", "chain": "PREROUTING",
			"expr": []any{
				map[string]any{"match": map[string]any{"op": "==", "left": map[string]any{"fib": map[string]any{"result": "type"}}, "right": "local"}},
				map[string]any{"counter": map[string]any{}},
				map[string]any{"jump": map[string]any{"target": "DOCKER"}},
			},
		}},
		{"rule": map[string]any{
			"family": "ip", "table": "nat", "chain": "POSTROUTING",
			"expr": []any{
				map[string]any{"match": map[string]any{"op": "==", "left": map[string]any{"payload": map[string]any{"protocol": "ip", "field": "saddr"}}, "right": map[string]any{"prefix": map[string]any{"addr": "172.17.0.0", "len": 16}}}},
				map[string]any{"match": map[string]any{"op": "!=", "left": map[string]any{"meta": map[string]any{"key": "oifname"}}, "right": "docker0"}},
				map[string]any{"counter": map[string]any{}},
				map[string]any{"masquerade": nil},
			},
		}},
		{"rule": map[string]any{
			"family": "ip", "table": "nat", "chain": "DOCKER",
			"expr": []any{
				map[string]any{"match": map[string]any{"op": "!=", "left": map[string]any{"meta": map[string]any{"key": "iifname"}}, "right": "docker0"}},
				map[string]any{"match": map[string]any{"op": "==", "left": map[string]any{"payload": map[string]any{"protocol": "tcp", "field": "dport"}}, "right": float64(8080)}},
				map[string]any{"dnat": map[string]any{"addr": "172.17.0.2", "port": float64(80)}},
			},
		}},
		{"chain": map[string]any{"family": "ip", "table": "filter", "name": "FORWARD", "hook": "forward", "policy": "accept"}},
		{"chain": map[string]any{"family": "ip", "table": "filter", "name": "DOCKER-USER"}},
		{"chain": map[string]any{"family": "ip", "table": "filter", "name": "DOCKER-FORWARD"}},
		{"chain": map[string]any{"family": "ip", "table": "filter", "name": "DOCKER-BRIDGE"}},
		{"chain": map[string]any{"family": "ip", "table": "filter", "name": "DOCKER"}},
		{"rule": map[string]any{
			"family": "ip", "table": "filter", "chain": "FORWARD",
			"expr": []any{
				map[string]any{"counter": map[string]any{}},
				map[string]any{"jump": map[string]any{"target": "DOCKER-USER"}},
			},
		}},
		{"rule": map[string]any{
			"family": "ip", "table": "filter", "chain": "FORWARD",
			"expr": []any{
				map[string]any{"counter": map[string]any{}},
				map[string]any{"jump": map[string]any{"target": "DOCKER-FORWARD"}},
			},
		}},
		{"rule": map[string]any{
			"family": "ip", "table": "filter", "chain": "DOCKER-FORWARD",
			"expr": []any{
				map[string]any{"counter": map[string]any{}},
				map[string]any{"jump": map[string]any{"target": "DOCKER-BRIDGE"}},
			},
		}},
		{"rule": map[string]any{
			"family": "ip", "table": "filter", "chain": "DOCKER-BRIDGE",
			"expr": []any{
				map[string]any{"match": map[string]any{"op": "==", "left": map[string]any{"meta": map[string]any{"key": "oifname"}}, "right": "docker0"}},
				map[string]any{"jump": map[string]any{"target": "DOCKER"}},
			},
		}},
		{"rule": map[string]any{
			"family": "ip", "table": "filter", "chain": "DOCKER",
			"expr": []any{
				map[string]any{"match": map[string]any{"op": "!=", "left": map[string]any{"meta": map[string]any{"key": "iifname"}}, "right": "docker0"}},
				map[string]any{"match": map[string]any{"op": "==", "left": map[string]any{"meta": map[string]any{"key": "oifname"}}, "right": "docker0"}},
				map[string]any{"counter": map[string]any{}},
				map[string]any{"drop": nil},
			},
		}},
	}
	if err := CheckFirewallObjects(dockerObjs); err != nil {
		t.Fatalf("expected standard Docker bridge-scoped rules to coexist cleanly, got: %v", err)
	}

	// Blanket drop in DOCKER-USER must STILL be rejected.
	unsafeDrop := append(append([]map[string]any{}, dockerObjs...), map[string]any{
		"rule": map[string]any{
			"family": "ip", "table": "filter", "chain": "DOCKER-USER",
			"expr": []any{map[string]any{"drop": nil}},
		},
	})
	if err := CheckFirewallObjects(unsafeDrop); err == nil {
		t.Fatal("expected blanket drop in DOCKER-USER to be rejected")
	}

	// Blanket WAN masquerade must STILL be rejected.
	unsafeMasq := []map[string]any{
		{"chain": map[string]any{"family": "ip", "table": "nat", "name": "POSTROUTING", "hook": "postrouting", "policy": "accept"}},
		{"rule": map[string]any{
			"family": "ip", "table": "nat", "chain": "POSTROUTING",
			"expr": []any{
				map[string]any{"match": map[string]any{"op": "==", "left": map[string]any{"meta": map[string]any{"key": "oifname"}}, "right": "eth0"}},
				map[string]any{"masquerade": nil},
			},
		}},
	}
	if err := CheckFirewallObjects(unsafeMasq); err == nil {
		t.Fatal("expected blanket WAN masquerade to be rejected")
	}

	// Docker DNAT hijacking UDP 4500 must STILL be rejected.
	unsafeDNAT := []map[string]any{
		{"chain": map[string]any{"family": "ip", "table": "nat", "name": "PREROUTING", "hook": "prerouting", "policy": "accept"}},
		{"chain": map[string]any{"family": "ip", "table": "nat", "name": "DOCKER"}},
		{"rule": map[string]any{
			"family": "ip", "table": "nat", "chain": "PREROUTING",
			"expr": []any{map[string]any{"jump": map[string]any{"target": "DOCKER"}}},
		}},
		{"rule": map[string]any{
			"family": "ip", "table": "nat", "chain": "DOCKER",
			"expr": []any{
				map[string]any{"match": map[string]any{"op": "==", "left": map[string]any{"payload": map[string]any{"protocol": "udp", "field": "dport"}}, "right": float64(4500)}},
				map[string]any{"dnat": map[string]any{"addr": "172.17.0.2", "port": float64(4500)}},
			},
		}},
	}
	if err := CheckFirewallObjects(unsafeDNAT); err == nil {
		t.Fatal("expected Docker DNAT on UDP 4500 to be rejected")
	}

	// Real Ubuntu 24.04 iptables-nft JSON uses {"xt":{"type":"match"/"target","name":...}} expressions.
	xtDockerObjs := []map[string]any{
		{"chain": map[string]any{"family": "ip", "table": "nat", "name": "DOCKER"}},
		{"chain": map[string]any{"family": "ip", "table": "nat", "name": "PREROUTING", "hook": "prerouting", "policy": "accept"}},
		{"chain": map[string]any{"family": "ip", "table": "nat", "name": "POSTROUTING", "hook": "postrouting", "policy": "accept"}},
		{"rule": map[string]any{
			"family": "ip", "table": "nat", "chain": "PREROUTING",
			"expr": []any{
				map[string]any{"xt": map[string]any{"type": "match", "name": "addrtype"}},
				map[string]any{"counter": map[string]any{}},
				map[string]any{"jump": map[string]any{"target": "DOCKER"}},
			},
		}},
		{"rule": map[string]any{
			"family": "ip", "table": "nat", "chain": "POSTROUTING",
			"expr": []any{
				map[string]any{"match": map[string]any{"op": "==", "left": map[string]any{"payload": map[string]any{"protocol": "ip", "field": "saddr"}}, "right": map[string]any{"prefix": map[string]any{"addr": "172.17.0.0", "len": 16}}}},
				map[string]any{"match": map[string]any{"op": "!=", "left": map[string]any{"meta": map[string]any{"key": "oifname"}}, "right": "docker0"}},
				map[string]any{"counter": map[string]any{}},
				map[string]any{"xt": map[string]any{"type": "target", "name": "MASQUERADE"}},
			},
		}},
		{"chain": map[string]any{"family": "ip", "table": "filter", "name": "FORWARD", "hook": "forward", "policy": "accept"}},
		{"chain": map[string]any{"family": "ip", "table": "filter", "name": "DOCKER-CT"}},
		{"rule": map[string]any{
			"family": "ip", "table": "filter", "chain": "FORWARD",
			"expr": []any{
				map[string]any{"counter": map[string]any{}},
				map[string]any{"jump": map[string]any{"target": "DOCKER-CT"}},
			},
		}},
		{"rule": map[string]any{
			"family": "ip", "table": "filter", "chain": "DOCKER-CT",
			"expr": []any{
				map[string]any{"match": map[string]any{"op": "==", "left": map[string]any{"meta": map[string]any{"key": "oifname"}}, "right": "docker0"}},
				map[string]any{"xt": map[string]any{"type": "match", "name": "conntrack"}},
				map[string]any{"counter": map[string]any{}},
				map[string]any{"accept": nil},
			},
		}},
	}
	if err := CheckFirewallObjects(xtDockerObjs); err != nil {
		t.Fatalf("expected iptables-nft xt Docker rules to coexist cleanly, got: %v", err)
	}

	// Unsafe xt target (e.g. REDIRECT) must STILL be rejected.
	unsafeXT := []map[string]any{
		{"chain": map[string]any{"family": "ip", "table": "nat", "name": "PREROUTING", "hook": "prerouting", "policy": "accept"}},
		{"rule": map[string]any{
			"family": "ip", "table": "nat", "chain": "PREROUTING",
			"expr": []any{map[string]any{"xt": map[string]any{"type": "target", "name": "REDIRECT"}}},
		}},
	}
	if err := CheckFirewallObjects(unsafeXT); err == nil {
		t.Fatal("expected xt REDIRECT target to be rejected")
	}
}

func TestFingerprintStripsBridgeTimers(t *testing.T) {
	a := map[string]any{
		"ifname": "docker0",
		"linkinfo": map[string]any{
			"info_kind": "bridge",
			"info_data": map[string]any{"gc_timer": 28412, "hello_timer": 199, "tcn_timer": 0},
		},
	}
	b := map[string]any{
		"ifname": "docker0",
		"linkinfo": map[string]any{
			"info_kind": "bridge",
			"info_data": map[string]any{"gc_timer": 28301, "hello_timer": 42, "tcn_timer": 12},
		},
	}
	if Fingerprint(a) != Fingerprint(b) {
		t.Fatal("expected bridge ticking timers to be ignored in Fingerprint")
	}
}
