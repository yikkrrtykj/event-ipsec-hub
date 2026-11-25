"""Unit tests for Stage 2 (#7 N-site multi-OB isolation + Hillstone route-based/multi-CHILD)."""

from pathlib import Path

import pytest

from ipsecvpn.handoff import build_plan, peer_parameters, render_peer_markdown
from ipsecvpn.profile import ProfileError, authorized_remote_lans, load_profile, validate_profile
from ipsecvpn.renderer import (
    BLACKHOLE_METRIC,
    ROUTE_PROTOCOL,
    build_manifest,
    nft_config,
    swanctl_config,
)
from ipsecvpn.resources import Resources
from ipsecvpn.sa import Policy, SAError, State, correlate, parse_vici

MULTI_OB = Path("config/esports-multi-ob-hillstone.example.yaml")


def test_multi_ob_topology_isolates_ob_sites_and_scopes_selectors():
    profile = load_profile(MULTI_OB)
    assert authorized_remote_lans(profile, "ob-venue-1") == ["10.100.10.0/24", "10.100.20.0/24"]
    assert authorized_remote_lans(profile, "ob-venue-2") == ["10.100.10.0/24"]
    assert authorized_remote_lans(profile, "server-core") == ["10.101.10.0/24", "10.102.10.0/24"]

    plan = build_plan(profile)
    assert len(plan["connections"]) == 3
    # 2 authorized pairs -> 4 directional rules (OB1<->Server, OB2<->Server), zero OB1<->OB2
    pairs = {(r["source_site_id"], r["target_site_id"]) for r in plan["forward_acl"]}
    assert pairs == {
        ("ob-venue-1", "server-core"),
        ("server-core", "ob-venue-1"),
        ("ob-venue-2", "server-core"),
        ("server-core", "ob-venue-2"),
    }
    assert ("ob-venue-1", "ob-venue-2") not in pairs
    assert ("ob-venue-2", "ob-venue-1") not in pairs

    manifest = build_manifest(profile)
    nft = nft_config(manifest, "tok")
    forward = nft.split("chain output")[0]
    by_site = {link.site_id: link for link in manifest.links}
    ob1, ob2, srv = by_site["ob-venue-1"], by_site["ob-venue-2"], by_site["server-core"]

    assert f'iifname "{ob1.name}" oifname "{srv.name}"' in forward
    assert f'iifname "{ob2.name}" oifname "{srv.name}"' in forward
    assert f'iifname "{ob1.name}" oifname "{ob2.name}"' not in forward
    assert f'iifname "{ob2.name}" oifname "{ob1.name}"' not in forward
    assert f'iifname "{ob1.name}" drop' in forward
    assert f'iifname "{ob2.name}" drop' in forward


def test_hillstone_route_based_and_per_pair_swanctl_and_markdown():
    profile = load_profile(MULTI_OB)
    manifest = build_manifest(profile)
    swanctl = swanctl_config(manifest)
    by_site = {link.site_id: link for link in manifest.links}

    # route_based uses 0.0.0.0/0 selectors in swanctl while routes stay exact
    assert "local_ts = 0.0.0.0/0" in swanctl
    assert "remote_ts = 0.0.0.0/0" in swanctl
    assert {r["destination"] for r in manifest.resources()["routes"]} == {
        "10.100.10.0/24",
        "10.100.20.0/24",
        "10.101.10.0/24",
        "10.102.10.0/24",
    }

    # per_pair splits child SAs per (local, remote) pair
    ob2 = by_site["ob-venue-2"]
    assert f"{ob2.child}-0 {{" in swanctl

    # Hillstone markdown handoff reflects route_based guidance
    params = peer_parameters(profile, "ob-venue-1")
    assert params["template"] == "hillstone"
    assert params["selector_mode"] == "route_based"
    assert params["local_ts"] == ["0.0.0.0/0"]
    assert params["remote_ts"] == ["0.0.0.0/0"]
    md = render_peer_markdown(params)
    assert "route_based" in md and "0.0.0.0/0" in md


def test_sa_parse_vici_accepts_route_based_wildcard_child():
    profile = load_profile(MULTI_OB)
    manifest = build_manifest(profile)
    link = next(item for item in manifest.links if item.site_id == "ob-venue-1")
    child = {
        "name": link.child.encode(),
        "uniqueid": b"21",
        "reqid": b"9",
        "state": b"INSTALLED",
        "protocol": b"ESP",
        "mode": b"TUNNEL",
        "spi-in": b"11223344",
        "spi-out": b"55667788",
        "if-id-in": f"{link.if_id:08x}".encode(),
        "if-id-out": f"{link.if_id:08x}".encode(),
        "local-ts": [b"0.0.0.0/0"],
        "remote-ts": [b"0.0.0.0/0"],
        "encr-alg": b"AES_CBC",
        "encr-keysize": b"256",
        "integ-alg": b"HMAC_SHA2_256_128",
        **dict.fromkeys(("bytes-in", "bytes-out", "packets-in", "packets-out"), b"0"),
    }
    event = {
        link.name: {
            "version": b"2",
            "uniqueid": b"2",
            "state": b"ESTABLISHED",
            "local-host": link.source.encode(),
            "remote-host": link.peer.encode(),
            "local-id": link.local_id.encode(),
            "remote-id": link.remote_id.encode(),
            "initiator-spi": b"1122334455667788",
            "responder-spi": b"8877665544332211",
            "encr-alg": b"AES_CBC",
            "encr-keysize": b"256",
            "integ-alg": b"HMAC_SHA2_256_128",
            "prf-alg": b"PRF_HMAC_SHA2_256",
            "dh-group": b"MODP_2048",
            "child-sas": {link.child: child},
        }
    }
    snap = parse_vici([event], manifest)
    assert snap.get(link.name).child.unique_id == 21

    child["remote-ts"] = [b"10.101.10.0/24"]
    with pytest.raises(SAError, match="CHILD selector"):
        parse_vici([event], manifest)


def test_duplicate_or_unconnected_site_pairs_rejected():
    profile = load_profile(MULTI_OB)
    profile["traffic_policy"]["allowed_site_pairs"].append({"a": "server-core", "b": "ob-venue-1"})
    with pytest.raises(ProfileError, match="Duplicate allowed_site_pairs"):
        validate_profile(profile)

    profile2 = load_profile(MULTI_OB)
    profile2["traffic_policy"]["allowed_site_pairs"] = [{"a": "ob-venue-1", "b": "server-core"}]
    with pytest.raises(ProfileError, match="participate in at least one"):
        validate_profile(profile2)


def test_per_pair_multi_child_correlates_distinct_spis_and_resources_verify():
    profile = load_profile(MULTI_OB)
    # Give ob-venue-2 (per_pair) access to both server CIDRs so it spawns 2 CHILD SAs
    profile["traffic_policy"]["allowed_site_pairs"][1]["b_cidrs"] = [
        "10.100.10.0/24",
        "10.100.20.0/24",
    ]
    manifest = build_manifest(profile)
    ob2 = next(item for item in manifest.links if item.site_id == "ob-venue-2")
    specs = ob2.child_specs()
    assert len(specs) == 2

    children_vici = {}
    states = []
    policies = []
    for idx, (c_name, c_local, c_remote) in enumerate(specs):
        reqid = 30 + idx
        spi_in = 0x11000001 + idx
        spi_out = 0x22000001 + idx
        children_vici[c_name] = {
            "name": c_name.encode(),
            "uniqueid": str(50 + idx).encode(),
            "reqid": str(reqid).encode(),
            "state": b"INSTALLED",
            "protocol": b"ESP",
            "mode": b"TUNNEL",
            "spi-in": f"{spi_in:08x}".encode(),
            "spi-out": f"{spi_out:08x}".encode(),
            "if-id-in": f"{ob2.if_id:08x}".encode(),
            "if-id-out": f"{ob2.if_id:08x}".encode(),
            "local-ts": [c_local[0].encode()],
            "remote-ts": [c_remote[0].encode()],
            "encr-alg": b"AES_CBC",
            "encr-keysize": b"256",
            "integ-alg": b"HMAC_SHA2_256_128",
            **dict.fromkeys(("bytes-in", "bytes-out", "packets-in", "packets-out"), b"10"),
        }
        in_state = State(ob2.peer, ob2.source, spi_in, reqid, ob2.if_id)
        out_state = State(ob2.source, ob2.peer, spi_out, reqid, ob2.if_id)
        states.extend((in_state, out_state))
        for direction, src, dst, sa in (
            ("out", c_local[0], c_remote[0], out_state),
            ("in", c_remote[0], c_local[0], in_state),
            ("fwd", c_remote[0], c_local[0], in_state),
        ):
            policies.append(
                (Policy(src, dst, direction, sa.source, sa.destination, reqid, ob2.if_id), sa.spi)
            )

    event = {
        ob2.name: {
            "version": b"2",
            "uniqueid": b"9",
            "state": b"ESTABLISHED",
            "local-host": ob2.source.encode(),
            "remote-host": ob2.peer.encode(),
            "local-id": ob2.local_id.encode(),
            "remote-id": ob2.remote_id.encode(),
            "initiator-spi": b"1122334455667788",
            "responder-spi": b"8877665544332211",
            "encr-alg": b"AES_CBC",
            "encr-keysize": b"256",
            "integ-alg": b"HMAC_SHA2_256_128",
            "prf-alg": b"PRF_HMAC_SHA2_256",
            "dh-group": b"MODP_2048",
            "child-sas": children_vici,
        }
    }
    snap = parse_vici([event], manifest)
    assert snap.get(ob2.name).child.counts == (20, 20, 20, 20)
    correlate(snap, manifest, states, policies)

    # Also verify Resources.verify() accepts route_based, per_pair, start_action=start, and Dual-ISP
    class FakeHost:
        def routing(self, permitted_rules=()):
            rules = [
                {"priority": 0, "src": "all", "table": "255"},
                {"priority": 1001, "src": "198.51.100.10", "table": "101"},
                {"priority": 32766, "src": "all", "table": "254"},
                {"priority": 32767, "src": "all", "table": "253"},
            ]
            from ipsecvpn.host import Host

            Host.verify_routing_rules(rules, permitted_rules=permitted_rules)
            routes = [
                {"dst": "default", "dev": "eth0", "gateway": "198.51.100.1", "table": "254"},
                {
                    "dst": "default",
                    "dev": "eth0",
                    "gateway": "198.51.100.1",
                    "metric": 100,
                    "protocol": ROUTE_PROTOCOL,
                    "table": "101",
                },
            ]
            for link in manifest.links:
                for cidr_net in link.remote_ts:
                    routes.append(
                        {
                            "dst": cidr_net,
                            "dev": link.name,
                            "metric": link.route_priority,
                            "protocol": ROUTE_PROTOCOL,
                            "table": "254",
                        }
                    )
                    routes.append(
                        {
                            "dst": cidr_net,
                            "type": "blackhole",
                            "metric": int(BLACKHOLE_METRIC),
                            "protocol": ROUTE_PROTOCOL,
                            "table": "254",
                        }
                    )
            links = [
                {
                    "ifname": link.name,
                    "ifalias": "ipsecvpn:tok",
                    "flags": ["UP"],
                    "linkinfo": {"info_kind": "xfrm", "info_data": {"if_id": link.if_id}},
                }
                for link in manifest.links
            ]
            return rules, routes, links

        def nft(self):
            return [
                {"table": {"family": "ip", "name": "ipsecvpn"}},
                {"chain": {"family": "ip", "table": "ipsecvpn", "name": "owner_tok"}},
            ]

        def vici_connections(self):
            conns = {}
            for link in manifest.links:
                rows = [f"  local:  {link.source}", f"  remote: {link.peer}"]
                for c_name, c_local, c_remote in link.child_specs():
                    rows.append(f"  {c_name}: TUNNEL")
                    rows.append(f"    local:  {' '.join(c_local)}")
                    rows.append(f"    remote: {' '.join(c_remote)}")
                conns[link.name] = rows
            return conns

        def vici(self, action, *_opts):
            if action == "--list-sas":
                # Auto-initiated owned SA does not break verify() when start_action=start
                return f"{manifest.links[0].name}: #1, CONNECTING\n"
            return ""

        def route_lookups(self, targets):
            result = {}
            by_prefix = {
                cidr_net.split("/")[0]: link.name
                for link in manifest.links
                for cidr_net in link.remote_ts
            }
            for target, source in targets:
                if source:
                    result[target, source] = [{"dev": "eth0", "gateway": "198.51.100.1"}]
                else:
                    result[target, source] = [{"dev": by_prefix[target]}]
            return result

        def baseline(self, *_args):
            return {"ok": True}

    res = Resources(FakeHost(), "tok", (manifest,))
    assert res.verify(manifest, {"ok": True}) is not None
