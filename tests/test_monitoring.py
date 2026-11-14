import json
import time
from pathlib import Path

import pytest

from ipsecvpn import cli
from ipsecvpn.monitoring import collector, exporter
from ipsecvpn.monitoring.bridge import official_target, parse_alert, signature
from ipsecvpn.monitoring.model import Settings, State, unavailable
from ipsecvpn.monitoring.udp import FRAME_BYTES, Responder, frame, parse
from ipsecvpn.profile import ProfileError, load_profile, validate_profile
from ipsecvpn.secureio import Stop

ROOT = Path(__file__).resolve().parents[1]


def test_legacy_profiles_leave_monitoring_optional():
    for path in (ROOT / "tests/fixtures").glob("*.yaml"):
        profile = load_profile(path)
        assert Settings.from_profile(profile).enabled == profile.get("monitoring", {}).get(
            "enabled", False
        )


@pytest.mark.parametrize("bind", ["0.0.0.0", "192.0.2.7", "::", "localhost"])
def test_monitoring_rejects_noncanonical_bind(bind):
    profile = load_profile(ROOT / "config/event.example.yaml")
    profile["monitoring"] = {"enabled": True, "exporter": {"bind": bind}}
    with pytest.raises(ProfileError, match="monitoring.exporter.bind"):
        validate_profile(profile)


def test_timeout_must_fit_the_sampling_window():
    profile = load_profile(ROOT / "config/event.example.yaml")
    profile["monitoring"]["exporter"] = {"interval_seconds": 6, "timeout_seconds": 6}
    with pytest.raises(ProfileError, match="timeout < interval"):
        validate_profile(profile)


def test_monitor_validate_is_offline(monkeypatch, capsys):
    def unexpected(*_args, **_kwargs):
        pytest.fail("Offline validation tried to inspect the runtime.")

    monkeypatch.setattr(collector, "authorized", unexpected)
    args = ["monitor", "validate", "-c", str(ROOT / "config/event.example.yaml"), "--json"]
    assert cli.main(args) == 0
    assert json.loads(capsys.readouterr().out)["enabled"] is False


def test_read_only_adapter_stops_before_mutation():
    with pytest.raises(Stop, match="read operations"):
        collector.ReadOnlyHost().command("test", "unused", mutate=True)


def test_socket_activated_ssh_listeners_require_a_match(monkeypatch):
    host = collector.ReadOnlyHost()
    monkeypatch.setattr(host, "service", lambda *_: "ssh.service")
    monkeypatch.setattr(
        host, "command", lambda *_: "LISTEN 0 32 0.0.0.0:22 0.0.0.0:*\nLISTEN 0 32 *:22 *:*"
    )
    ssh = {
        "ssh.service": "active",
        "ssh.socket": "active",
        "socket": "0.0.0.0:22 (Stream)\n[::]:22 (Stream)",
    }
    assert host.ssh_listeners(ssh) == ["*:22", "0.0.0.0:22"]
    with pytest.raises(Stop, match="listener is missing"):
        host.ssh_listeners({**ssh, "socket": "0.0.0.0:2200 (Stream)"})


@pytest.mark.parametrize(
    ("label", "command", "stage"),
    [
        ("VICI query", ("swanctl", "--list-sas"), "VICI"),
        ("XFRM policy inventory", ("ip", "-o", "xfrm", "policy", "list", "nosock"), "XFRM"),
        ("ip query", ("ip", "-j", "-N", "-4", "route", "get", "192.0.2.1"), "ROUTING"),
        ("nftables support", ("nft", "-j", "list", "ruleset"), "NFTABLES"),
    ],
)
def test_safe_command_diagnostics(monkeypatch, label, command, stage):
    from ipsecvpn.host import CommandFailed, Host

    def rejected(*args, **kwargs):
        raise CommandFailed("sensitive diagnostic input", 1, "PERMISSION_DENIED")

    def inspect(host, **kwargs):
        host.command(label, *command)

    monkeypatch.setattr(Host, "command", rejected)
    monkeypatch.setattr(collector, "authorize_endpoint", inspect)
    report = collector.collect()
    assert report["stage"] == stage and report["reason_code"] == "PERMISSION_DENIED"
    assert not report["collector_valid"] and "sensitive" not in json.dumps(report)


def healthy_sample():
    return {
        **unavailable("READY", daemon=State.UP),
        "collector_valid": True,
        "event_id": "demo",
        "hub_id": "hub",
        "collected_at": time.time(),
        "profile_active": True,
        "business": State.UP,
        "sites": [
            {
                "site_id": "a",
                "ike": State.UP,
                "child": State.UP,
                "kernel": State.UP,
                "protected_route": State.UP,
                "counts": [7, 8, 1, 1],
                "generation": [1, 10],
            },
        ],
        "paths": [
            {
                "src_site_id": "a",
                "dst_site_id": "b",
                "state": State.UP,
                "reason_code": "READY",
                "at": time.time(),
                "sent": 2,
                "loss": 0,
                "rtt": 0.1,
            },
        ],
    }


def test_failed_refresh_revokes_previous_metrics():
    cache = exporter.Cache(ttl=30, probe_ttl=20)
    cache.publish(healthy_sample())
    text = exporter.metrics(cache.view()).decode()
    assert "# TYPE event_ipsec_site_sa_rx_bytes gauge" in text
    assert 'event_ipsec_site_child_state{event_id="demo",hub_id="hub",site_id="a"} 1' in text
    assert 'generation="' not in text
    cache.publish(unavailable("UNOWNED_SA"))
    snapshot = cache.view()
    assert snapshot["last_success"] is not None
    assert snapshot["reason_code"] == "UNOWNED_SA"
    text = exporter.metrics(snapshot).decode()
    assert "event_ipsec_collector_healthy 0" in text
    assert "event_ipsec_site_child_state{" not in text
    assert "event_ipsec_path_rtt_seconds{" not in text


def test_path_expiry_is_independent_of_collector_freshness(monkeypatch):
    cache = exporter.Cache(ttl=30, probe_ttl=20)
    cache.publish(healthy_sample())
    later = time.time() + 21
    monkeypatch.setattr(exporter.time, "time", lambda: later)
    result = cache.view()
    assert result["collector_valid"]
    assert result["business"] == State.UNKNOWN and "loss" not in result["paths"][0]


def test_exporter_ttl_with_no_further_worker_results(monkeypatch):
    cache = exporter.Cache(ttl=30, probe_ttl=20)
    cache.publish(healthy_sample())
    monkeypatch.setattr(exporter.time, "monotonic", lambda: cache.sample_clock + 30)
    result = cache.view()
    assert not result["collector_valid"] and result["reason_code"] == "STALE"
    assert result["business"] == State.UNKNOWN


def test_authenticated_udp_frames_bind_direction_and_reject_replay():
    key = bytes(range(32))
    now = 1_700_000_000.0
    peer = ("192.0.2.3", 30001)
    responder = Responder(key, peer)
    request = frame(key, "q", "1234567890abcdef", 0, int(now * 1000))
    assert len(request) == FRAME_BYTES
    assert responder.answer(("192.0.2.4", 30001), request, now) is None
    response = responder.answer(peer, request, now)
    assert parse(response, key, "r", now)
    assert parse(response, key, "q", now) is None
    assert responder.answer(peer, request, now) is None
    assert parse(request, key, "q", now + 6) is None


@pytest.mark.parametrize("value", ["https://open.feishu.cn.example.invalid/x", "http://127.0.0.1/"])
def test_nonofficial_target_rejected(value):
    with pytest.raises(Stop):
        official_target(value)


def test_signature_and_alert_field_validation():
    assert signature(1700000000, bytes(range(32))) == (
        "twQMnGoBdhC1yC0oyZ4yQGvwOinv5DsUPBbiJa4jDMA="
    )
    alert = {
        "labels": {"alertname": "IpsecChildDown", "site_id": "<bad>"},
        "fingerprint": "0000000000000000",
        "startsAt": "2025-01-01T00:00:00Z",
        "status": "firing",
    }
    with pytest.raises(ValueError):
        parse_alert(alert)
