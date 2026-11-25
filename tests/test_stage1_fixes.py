"""Unit tests covering Stage 1 bug fixes (rollback, nftables, routes, host authorization)."""

from contextlib import contextmanager
from pathlib import Path

import pytest

from ipsecvpn import host as host_mod
from ipsecvpn import live, transaction
from ipsecvpn.monitoring import collector
from ipsecvpn.profile import load_profile
from ipsecvpn.renderer import build_manifest, nft_config
from ipsecvpn.resources import route_specs
from ipsecvpn.sa import SAError, kernel_policies, kernel_states, proposal
from ipsecvpn.secureio import Stop

FIXTURES = Path(__file__).with_name("fixtures")


def test_renderer_emits_outer_routes_custom_priority_and_input_rules():
    profile = load_profile(FIXTURES / "studio-vlan.yaml")
    manifest = build_manifest(profile)
    resources = manifest.resources()

    priorities = {link.site_id: link.route_priority for link in manifest.links}
    assert priorities == {"control-X": 10, "intake-7": 11}
    assert {r["metric"] for r in resources["routes"]} == {10, 11}
    assert len(resources["outer_routes"]) == 2
    assert all(r["destination"].endswith("/32") for r in resources["outer_routes"])

    specs = route_specs((manifest,))
    unicast_metrics = {spec[3] for spec in specs if spec[1] == "unicast"}
    assert unicast_metrics == {"10", "11"}

    nft = nft_config(manifest, "tok")
    inbound = nft.split("chain input")[1]
    assert "ip protocol esp accept" in inbound
    assert "ct state established,related accept" in inbound
    assert inbound.index("ct state established,related accept") < inbound.index(
        f'iifname "{manifest.links[0].name}" drop'
    )


def test_transition_guard_keeps_input_established_disabled():
    manifest = build_manifest(load_profile(FIXTURES / "arena-apac-eu.yaml"))
    guard = nft_config(
        None, "tok", manifest.networks, [link.name for link in manifest.links], handshake=manifest
    )
    inbound = guard.split("chain input")[1]
    assert "ct state established,related accept" not in inbound
    assert "udp dport { 500, 4500 } accept" in inbound
    assert "ip protocol esp accept" in inbound


def test_sa_defensive_parsing_handles_blank_lines_and_missing_dh():
    assert kernel_states("\n\n") == []
    assert kernel_policies("\n\n") == []
    row = {
        "encr-alg": b"AES_CBC",
        "encr-keysize": b"256",
        "integ-alg": b"HMAC_SHA2_256_128",
        "dh-group": b"MODP_2048",
    }
    assert proposal(row, "aes256-sha256", ike=False) is False
    assert proposal(row, "aes256-sha256-invalidgroup", ike=False) is False


def test_rekey_link_raises_sa_error_when_stream_ends_without_relation(monkeypatch):
    manifest = build_manifest(load_profile(Path("config/event.example.yaml")))
    link = manifest.links[0]

    class FakeWatcher:
        def listen(self, _events, timeout=0.15):
            yield None, None  # registration tick only; stream ends immediately

    class FakeClient:
        def request(self, _action, _data):
            return {"matches": b"1"}

    sessions = iter((FakeWatcher(), FakeClient()))

    @contextmanager
    def fake_session(_pid):
        yield next(sessions)

    class DummyOld:
        unique_id = 1
        child = type("Child", (), {"unique_id": 11})()

    monkeypatch.setattr(live, "session", fake_session)
    with pytest.raises(SAError, match="did not confirm"):
        live.rekey_link(None, manifest, 42, link, DummyOld(), "child")


def test_production_host_marker_allows_bare_metal_and_vps(monkeypatch):
    def fake_read(path, **_kwargs):
        if path == host_mod.HOST_MARKER:
            return host_mod.HOST_MARKER_VALUE
        raise FileNotFoundError(path)

    monkeypatch.setattr(host_mod, "read_file", fake_read)
    assert host_mod.read_host_authorization() == "production"

    class BareMetalHost:
        def command(self, *_args, **_kwargs):
            return "none\n"

        def probe(self):
            return {
                "os": "Ubuntu 24.04",
                "kernel": "6.8",
                "hypervisor": "none",
                "mode": "production",
            }

    collector.authorized(BareMetalHost())


def test_recover_live_reactivates_daemon_on_failed_uninstall(monkeypatch):
    activated = []
    manifest = build_manifest(load_profile(Path("config/event.example.yaml")))
    dep = transaction.Deployment(host=None)
    dep.record = {
        "action": "uninstall",
        "baseline": {"ok": True},
        "live_sites": [],
    }

    class DummyHost:
        def assert_daemon(self, _names):
            assert activated == ["called"], "activate() must run before assert_daemon()"
            raise Stop("stop-after-activate")

    dep.host = DummyHost()
    monkeypatch.setattr(transaction, "snapshot", lambda x: manifest if x else None)
    monkeypatch.setattr(transaction, "activate", lambda _h, _i: activated.append("called"))
    with pytest.raises(Stop, match="stop-after-activate"):
        dep.recover_live({"profile": {}}, None, {"token": "tok"})


def test_live_maintenance_failure_enters_stop_for_manual_until_explicit_rollback(monkeypatch):
    dep = transaction.Deployment(host=type("H", (), {"step": None})())
    dep.record = {
        "id": "a" * 32,
        "action": "apply",
        "before": {"profile": {}},
        "target": {"profile": {}},
        "install": {"token": "tok"},
        "live_maintenance": True,
        "steps": [],
    }
    monkeypatch.setattr(transaction, "write_record", lambda *_a, **_kw: None)
    with pytest.raises(Stop, match="STOP_FOR_MANUAL"):
        dep.recover()  # default maintenance=False during mid-flight failure
    assert dep.record["phase"] == "STOP_FOR_MANUAL"
    assert not dep.record.get("configuration_restored")
