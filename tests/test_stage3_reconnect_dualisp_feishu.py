"""Unit tests for Stage 3 (#8 dual-ISP return, #11 auto-reconnect, #9 active probes & Feishu)."""

import time
from pathlib import Path

import pytest

from ipsecvpn.monitoring import active_probe, bridge, exporter, service
from ipsecvpn.profile import ProfileError, load_profile, validate_profile
from ipsecvpn.renderer import build_manifest, swanctl_config
from ipsecvpn.secureio import Stop

MULTI_OB = Path("config/esports-multi-ob-hillstone.example.yaml")


def test_unattended_reconnect_and_dual_isp_symmetric_return_rendering():
    profile = load_profile(MULTI_OB)
    manifest = build_manifest(profile)
    swanctl = swanctl_config(manifest)
    assert "start_action = start" in swanctl
    assert "dpd_action = restart" in swanctl
    assert "close_action = start" in swanctl

    resources = manifest.resources()
    rules = resources["symmetric_return_rules"]
    assert len(rules) == 1
    assert rules[0] == {
        "from_source": "198.51.100.10/32",
        "table": 101,
        "priority": 1001,
        "interface": "eth0",
        "gateway": "198.51.100.1",
    }

    legacy = build_manifest(load_profile(Path("config/event.example.yaml")))
    legacy_swanctl = swanctl_config(legacy)
    assert "start_action = none" in legacy_swanctl
    assert "dpd_action = clear" in legacy_swanctl
    assert legacy.resources()["symmetric_return_rules"] == []


def test_dual_isp_validation_rejects_incomplete_or_conflicting_route_table():
    profile = load_profile(MULTI_OB)
    del profile["site_links"][0]["outer_path"]["gateway"]
    with pytest.raises(ProfileError, match="symmetric return"):
        validate_profile(profile)

    profile2 = load_profile(MULTI_OB)
    profile2["site_links"][1]["outer_path"].update(
        {
            "interface": "eth1",
            "source_ip": "198.51.100.11",
            "gateway": "198.51.100.2",
            "route_table": 101,
        }
    )
    with pytest.raises(ProfileError, match="Conflicting outer_path"):
        validate_profile(profile2)


def test_exporter_emits_site_traffic_idle_metric_and_clears_on_progress():
    cache = exporter.Cache(ttl=30, probe_ttl=30, idle_seconds=0)
    obs1 = {
        "collector_valid": True,
        "reason_code": "READY",
        "event_id": "evt1",
        "hub_id": "hub1",
        "collected_at": time.time(),
        "daemon": 1,
        "profile_active": True,
        "business": 1,
        "sites": [
            {
                "site_id": "ob-1",
                "ike": 1,
                "child": 1,
                "kernel": 1,
                "protected_route": 1,
                "counts": (100, 100, 2, 2),
                "generation": [1, 10],
            }
        ],
        "paths": [],
    }
    cache.publish(obs1)
    prom1 = exporter.metrics(cache.view()).decode("ascii")
    assert 'event_ipsec_site_traffic_idle{event_id="evt1",hub_id="hub1",site_id="ob-1"} 1' in prom1

    cache2 = exporter.Cache(ttl=30, probe_ttl=30, idle_seconds=60)
    cache2.publish(dict(obs1, sites=[dict(obs1["sites"][0])]))
    obs2 = dict(obs1, sites=[dict(obs1["sites"][0], counts=(250, 250, 5, 5))])
    cache2.publish(obs2)
    prom2 = exporter.metrics(cache2.view()).decode("ascii")
    assert 'event_ipsec_site_traffic_idle{event_id="evt1",hub_id="hub1",site_id="ob-1"} 0' in prom2


def test_bridge_accepts_official_feishu_webhook_and_service_egress_flag():
    url = "https://open.feishu.cn" + "/open-apis/bot/v2/hook/" + ("a" * 24)
    target = bridge.resolve_delivery_target({"feishu_webhook": url}, port=9109, exporter_port=9108)
    assert target.netloc == "open.feishu.cn"

    with pytest.raises(Stop, match="official robot endpoint"):
        bridge.resolve_delivery_target(
            {"feishu_webhook": "https://evil.example.com/hook"}, port=9109, exporter_port=9108
        )

    lab_unit = service.unit("feishu", "/usr/bin/python3").decode("ascii")
    assert "IPAddressDeny=any" in lab_unit
    prod_unit = service.unit("feishu", "/usr/bin/python3", allow_feishu_egress=True).decode("ascii")
    assert "IPAddressDeny=any" not in prod_unit


def test_service_enables_feishu_egress_in_production_change(monkeypatch):
    monkeypatch.setattr(service, "read_host_authorization", lambda: "production")
    monkeypatch.setattr(
        service,
        "read_file",
        lambda path, **_kw: (
            b'{"enabled": true, "port": 9815, '
            b'"feishu_webhook_ref": "file:/etc/ipsecvpn/secrets/feishu"}\n'
            if path == service.BRIDGE_CONFIG
            else (_ for _ in ()).throw(FileNotFoundError(path))
        ),
    )
    assert service._feishu_egress_enabled() is True
    monkeypatch.setattr(service, "read_host_authorization", lambda: "lab")
    assert service._feishu_egress_enabled() is False


def test_active_probe_runner_writes_verified_receipt(monkeypatch):
    profile = load_profile(MULTI_OB)
    manifest = build_manifest(profile)
    written = {}

    monkeypatch.setattr(active_probe, "generation", lambda _l, _m: {"ob-venue-1": [1, 2, 3, 4]})
    monkeypatch.setattr(active_probe, "write_record", lambda path, data: written.update(data))

    receipt = active_probe.run_probe_cycle(
        install={"token": "tok123"},
        manifest=manifest,
        live=None,
        probe_specs=[
            {
                "src_site_id": "ob-venue-1",
                "dst_site_id": "server-core",
                "source": "10.101.10.2",
                "target": "10.100.10.2",
                "port": 41001,
                "count": 3,
            }
        ],
        secret=b"0" * 32,
        probe_fn=lambda *_args, **_kwargs: [0.012, 0.014, 0.013],
    )
    assert written["owner"] == "tok123"
    assert written["event_id"] == manifest.event_id
    assert len(receipt["directions"]) == 1
    assert receipt["directions"][0]["rtts"] == [0.012, 0.014, 0.013]
