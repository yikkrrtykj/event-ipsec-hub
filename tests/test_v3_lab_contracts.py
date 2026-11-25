"""Unit tests for V3 Dual-ISP multi-link, bounded SA recheck (#10), and isolated reconnect (#11)."""

from contextlib import contextmanager
from pathlib import Path

import pytest

from ipsecvpn import live
from ipsecvpn.monitoring import collector, exporter
from ipsecvpn.profile import ProfileError, load_profile, validate_profile
from ipsecvpn.renderer import build_manifest, nft_config, swanctl_config
from ipsecvpn.sa import SAError, parse_vici


def _dual_isp_profile():
    profile = load_profile(Path("config/esports-multi-ob-hillstone.example.yaml"))
    profile["sites"][0]["uplinks"] = [
        {
            "id": "isp1",
            "isp_label": "ISP-A",
            "public_endpoint": "203.0.113.10",
            "interface": "wan1",
        },
        {"id": "isp2", "isp_label": "ISP-B", "public_endpoint": "192.0.2.10", "interface": "wan2"},
    ]
    profile["site_links"][0]["id"] = "srv-isp1"
    profile["site_links"][0]["uplink_id"] = "isp1"
    profile["site_links"].insert(
        1,
        {
            "id": "srv-isp2",
            "site_id": "server-core",
            "uplink_id": "isp2",
            "secret_ref": "file:/etc/ipsecvpn/secrets/server-core-isp2.psk",
            "if_id": 211,
            "selector_mode": "route_based",
            "route_priority": 20,
            "outer_path": {
                "interface": "eth1",
                "isp_label": "ISP-B",
                "source_ip": "198.51.100.11",
                "gateway": "198.51.100.2",
                "route_table": 102,
                "policy_priority": 1002,
            },
        },
    )
    return profile


def test_same_site_dual_isp_links_render_distinct_metrics_and_reject_ecmp():
    profile = _dual_isp_profile()
    validate_profile(profile)
    manifest = build_manifest(profile)
    srv_links = [item for item in manifest.links if item.site_id == "server-core"]
    assert [(item.key_id, item.route_priority) for item in srv_links] == [
        ("srv-isp1", 10),
        ("srv-isp2", 20),
    ]
    keys = {
        "srv-isp1": b"1" * 32,
        "srv-isp2": b"2" * 32,
        "ob-venue-1": b"3" * 32,
        "ob-venue-2": b"4" * 32,
    }
    swanctl = swanctl_config(manifest, keys)
    assert "remote_addrs = 192.0.2.10" in swanctl
    nft = nft_config(manifest, "tok")
    for s_link in srv_links:
        assert f'oifname "{s_link.name}"' in nft

    # Equal route_priority (unauthorized ECMP) must fail validation
    bad = _dual_isp_profile()
    bad["site_links"][1]["route_priority"] = 10
    with pytest.raises(ProfileError, match="Route priorities"):
        validate_profile(bad)


def test_drain_links_bounded_reverification_handles_concurrent_rekey(monkeypatch):
    manifest = build_manifest(load_profile(Path("config/event.example.yaml")))
    link = manifest.links[0]

    def _make_event(uid):
        return {
            link.name: {
                "version": b"2",
                "uniqueid": str(uid).encode(),
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
                "child-sas": {},
            }
        }

    snap_old = parse_vici([_make_event(1)], manifest)
    snap_rekeyed = parse_vici([_make_event(2)], manifest)
    snap_empty = parse_vici([], manifest)
    seq = iter((snap_rekeyed, snap_empty))
    monkeypatch.setattr(live, "inventory", lambda *_a, **_kw: next(seq))
    terminated = []

    class FakeCtl:
        def request(self, action, data):
            terminated.append((action, data["ike-id"]))
            return {"matches": b"1"}

    @contextmanager
    def fake_session(_pid):
        yield FakeCtl()

    monkeypatch.setattr(live, "session", fake_session)
    reverified = live.drain_links(None, manifest, 99, snap_old)
    assert len(reverified) == 1 and reverified[0]["phase"] == "pre_drain"
    assert terminated == [("terminate", "2")]


def test_reconnect_owned_isolates_down_site_and_cli_dry_run(monkeypatch, capsys):
    manifest = build_manifest(load_profile(Path("config/event.example.yaml")))
    up_link, down_link = manifest.links
    child = {
        "name": up_link.child.encode(),
        "uniqueid": b"11",
        "reqid": b"7",
        "state": b"INSTALLED",
        "protocol": b"ESP",
        "mode": b"TUNNEL",
        "spi-in": b"11223344",
        "spi-out": b"55667788",
        "if-id-in": f"{up_link.if_id:08x}".encode(),
        "if-id-out": f"{up_link.if_id:08x}".encode(),
        "local-ts": [c.encode() for c in up_link.local_ts],
        "remote-ts": [c.encode() for c in up_link.remote_ts],
        "encr-alg": b"AES_CBC",
        "encr-keysize": b"256",
        "integ-alg": b"HMAC_SHA2_256_128",
        **dict.fromkeys(("bytes-in", "bytes-out", "packets-in", "packets-out"), b"0"),
    }
    snap = parse_vici(
        [
            {
                up_link.name: {
                    "version": b"2",
                    "uniqueid": b"5",
                    "state": b"ESTABLISHED",
                    "local-host": up_link.source.encode(),
                    "remote-host": up_link.peer.encode(),
                    "local-id": up_link.local_id.encode(),
                    "remote-id": up_link.remote_id.encode(),
                    "initiator-spi": b"1122334455667788",
                    "responder-spi": b"8877665544332211",
                    "encr-alg": b"AES_CBC",
                    "encr-keysize": b"256",
                    "integ-alg": b"HMAC_SHA2_256_128",
                    "prf-alg": b"PRF_HMAC_SHA2_256",
                    "dh-group": b"MODP_2048",
                    "child-sas": {up_link.child: child},
                }
            }
        ],
        manifest,
    )
    monkeypatch.setattr(live, "owned_resources", lambda *_: (manifest, snap, 42))
    initiated = []

    def fake_initiate(_h, _m, _p, link):
        initiated.append(link.site_id)
        raise SAError("PEER_UNREACHABLE", "peer unreachable")

    monkeypatch.setattr(live, "initiate_link", fake_initiate)
    cleared = []
    monkeypatch.setattr(live, "_clear_connecting_sa", lambda _p, name: cleared.append(name))
    res = live.reconnect_owned(None, {"token": "t"}, {"profile": {}}, max_attempts=2, base_delay=0)
    assert res["status"] == "FAIL"
    assert initiated == [down_link.site_id, down_link.site_id]
    assert cleared == [down_link.name, down_link.name]
    by_site = {r["site_id"]: r for r in res["links"]}
    assert by_site[up_link.site_id]["action"] == "NOOP_HEALTHY"
    assert by_site[down_link.site_id]["action"] == "RECONNECT_EXHAUSTED"

    # Also verify exporter multi-link metrics formatting
    cache = exporter.Cache(ttl=30, probe_ttl=20)
    cache.publish(
        {
            "collector_valid": True,
            "reason_code": "READY",
            "event_id": "evt",
            "hub_id": "hub",
            "collected_at": 1000.0,
            "daemon": collector.State.UP,
            "profile_active": True,
            "business": collector.State.UP,
            "sites": [
                {
                    "site_id": "server-core",
                    "ike": 1,
                    "child": 1,
                    "kernel": 1,
                    "protected_route": 1,
                    "counts": (10, 10, 1, 1),
                    "generation": [1, 2],
                }
            ],
            "links": [
                {
                    "site_id": "server-core",
                    "link_id": "srv-isp1",
                    "isp": "ISP-A",
                    "ike": 1,
                    "child": 1,
                },
                {
                    "site_id": "server-core",
                    "link_id": "srv-isp2",
                    "isp": "ISP-B",
                    "ike": 1,
                    "child": 0,
                },
            ],
            "paths": [],
        }
    )
    prom = exporter.metrics(cache.view()).decode("ascii")
    expected_series = (
        'event_ipsec_link_child_state{event_id="evt",hub_id="hub",'
        'site_id="server-core",link_id="srv-isp2",isp="ISP-B"} 0'
    )
    assert expected_series in prom


def test_connecting_ike_without_proposal_is_a_transition_not_unowned():
    manifest = build_manifest(load_profile(Path("config/event.example.yaml")))
    link = manifest.links[0]
    row = {
        "version": b"2",
        "uniqueid": b"9",
        "state": b"CONNECTING",
        "local-host": link.source.encode(),
        "remote-host": link.peer.encode(),
    }
    with pytest.raises(SAError) as exc:
        parse_vici([{link.name: row}], manifest)
    assert exc.value.reason == "SA_TRANSITION"
    with pytest.raises(SAError) as exc_any:
        parse_vici([{link.name: {**row, "local-id": b"%any"}}], manifest)
    assert exc_any.value.reason == "SA_TRANSITION"
    foreign = {**row, "remote-host": b"192.0.2.250"}
    with pytest.raises(SAError) as exc:
        parse_vici([{link.name: foreign}], manifest)
    assert exc.value.reason == "UNOWNED_SA"


def test_initiate_link_waits_for_start_action_autostart(monkeypatch):
    from dataclasses import replace as dc_replace

    manifest = build_manifest(load_profile(Path("config/event.example.yaml")))
    link = dc_replace(manifest.links[0], start_action="start")
    ready = type("Ike", (), {"child": object()})()
    calls = []

    class Snap:
        def __init__(self, item):
            self.item = item

        def get(self, _name):
            return self.item

    def fake_inventory(*_args, **_kwargs):
        calls.append(1)
        if len(calls) < 3:
            raise SAError("SA_TRANSITION", "connecting")
        return Snap(ready)

    monkeypatch.setattr(live, "inventory", fake_inventory)
    monkeypatch.setattr(live, "session", lambda _pid: pytest.fail("explicit initiate used"))
    monkeypatch.setattr(live.time, "sleep", lambda _s: None)
    assert live.initiate_link(None, manifest, 1, link) is ready
    assert len(calls) == 3


def test_live_maintenance_load_keeps_target_handshake_open(monkeypatch):
    from ipsecvpn import transaction

    seen = {}

    class FakeResources:
        candidates = ()

        def guard(self, handshake=None):
            seen["guard"] = handshake

        def replace(self, target, keys, **kwargs):
            seen["replace"] = kwargs

        def finish(self, target):
            pass

        def verify(self, *_args, **_kwargs):
            return "sha"

    dep = transaction.Deployment(host=object())
    dep.record = {"live_sites": [], "baseline": {}, "steps": []}
    monkeypatch.setattr(transaction, "drain_links", lambda *_a, **_k: [])
    monkeypatch.setattr(transaction, "inventory", lambda *_a, **_k: None)
    monkeypatch.setattr(dep, "step", lambda *_a: None)
    target = build_manifest(load_profile(Path("config/event.example.yaml")))
    before = object()
    dep.replace_live(FakeResources(), before, target, {}, 1, None)
    assert seen["guard"] is before
    assert seen["replace"]["handshake"] is target and seen["replace"]["hold"] is True


def test_configure_scoped_unloads_existing_conns_and_initiate_skips_installed_children(monkeypatch):
    from dataclasses import replace as dc_replace

    manifest = build_manifest(load_profile(Path("config/esports-multi-ob-hillstone.example.yaml")))
    ob2 = next(item for item in manifest.links if item.selector_mode == "per_pair")
    ob2 = dc_replace(ob2, start_action="start", local_ts=("10.100.10.0/24", "10.100.20.0/24"))
    partial_ike = type(
        "Ike",
        (),
        {"child": None, "child_map": lambda _s: {ob2.child_specs()[1][0]: object()}},
    )()
    full_ike = type("Ike", (), {"child": object(), "child_map": lambda _s: {}})()
    initiated = []

    class FakeClient:
        def initiate(self, params):
            initiated.append(params["child"])
            return iter(())

    @contextmanager
    def fake_session(_pid):
        yield FakeClient()

    monkeypatch.setattr(live, "await_autostart", lambda *_a, **_k: (partial_ike, None))
    monkeypatch.setattr(live, "session", fake_session)
    monkeypatch.setattr(live, "verify_initiate_config", lambda *_a: None)
    monkeypatch.setattr(
        live, "inventory", lambda *_a, **_k: type("S", (), {"get": lambda _s, _n: full_ike})()
    )
    assert live.initiate_link(None, manifest, 1, ob2) is full_ike
    assert initiated == [ob2.child_specs()[0][0]]
