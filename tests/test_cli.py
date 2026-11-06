import json
from pathlib import Path

import pytest
import yaml

from ipsecvpn import cli
from ipsecvpn.handoff import PSK_PLACEHOLDER
from ipsecvpn.profile import load_profile

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
SAMPLE = ROOT / "config" / "event.example.yaml"


@pytest.mark.parametrize("path", sorted(FIXTURES.glob("*.yaml")))
def test_plan_and_both_peer_views(path, capsys):
    profile = load_profile(path)
    pair = profile["traffic_policy"]["allowed_site_pairs"][0]
    site_lans = {site["id"]: site["lan_cidrs"] for site in profile["sites"]}
    site_a, site_b = pair["a"], pair["b"]
    a_lans = pair.get("a_cidrs", site_lans[site_a])
    b_lans = pair.get("b_cidrs", site_lans[site_b])

    assert cli.main(["plan", "-c", str(path)]) == 0
    plan = json.loads(capsys.readouterr().out)
    assert plan["status"] == "PASS"
    assert plan["source_nat"] is False
    assert plan["checks"][-1]["status"] == "SKIP"
    assert len(plan["routes"]) == len(a_lans) + len(b_lans)
    assert len(plan["outer_routes"]) == 2
    assert {
        (tuple(acl["source_cidrs"]), tuple(acl["destination_cidrs"])) for acl in plan["forward_acl"]
    } == {(tuple(a_lans), tuple(b_lans)), (tuple(b_lans), tuple(a_lans))}
    connections = {item["site_id"]: item for item in plan["connections"]}
    sites = {site["id"]: site for site in profile["sites"]}
    for local_id, remote_id, local_lans, remote_lans in (
        (site_a, site_b, a_lans, b_lans),
        (site_b, site_a, b_lans, a_lans),
    ):
        conn = connections[local_id]
        assert conn["hub_local_ts"] == remote_lans
        assert conn["hub_remote_ts"] == local_lans
        assert {
            route["destination"]
            for route in plan["routes"]
            if route["xfrm_if_id"] == conn["xfrm_if_id"]
        } == set(local_lans)
        command = ["export-peer", "-c", str(path), "--site", local_id, "--format"]
        assert cli.main([*command, "json"]) == 0
        data = json.loads(capsys.readouterr().out)
        assert data["local"]["public_endpoint"] == sites[local_id]["public_endpoint"]
        assert data["local"]["ike_identity"] == sites[local_id]["ike_identity"]
        assert data["remote"]["public_endpoint"] == profile["hub"]["public_endpoint"]
        assert data["remote"]["ike_identity"] == profile["hub"].get(
            "ike_identity", profile["hub"]["public_endpoint"]
        )
        assert data["local_ts"] == local_lans == conn["peer_local_ts"]
        assert data["remote_ts"] == remote_lans == conn["peer_remote_ts"]
        assert data["allowed_traffic"]["remote_site_id"] == remote_id
        assert data["ike"]["psk"] == PSK_PLACEHOLDER
        assert data["acceptance"]["status"] == "SKIP"
        if data["backup"]["enabled"]:
            assert {item["site_id"] for item in data["backup"]["links"]} == {local_id}
        else:
            assert data["backup"] == {"enabled": False}

        assert cli.main([*command, "md"]) == 0
        markdown = capsys.readouterr().out
        local_row, remote_row = [
            line for line in markdown.splitlines() if "Traffic Selectors" in line
        ]
        assert all(cidr in local_row and cidr not in remote_row for cidr in local_lans)
        assert all(cidr in remote_row and cidr not in local_row for cidr in remote_lans)
        assert PSK_PLACEHOLDER in markdown
        assert sites[local_id]["display_name"] in markdown
        assert ("山石 Hillstone" in markdown) == (data["template"] == "hillstone")
    if profile["event"]["id"] == "studio-mock":
        assert "10.61.3.0/24" not in json.dumps(plan)


def test_change_profile_and_explicit_template(tmp_path, capsys, monkeypatch):
    profile = load_profile(SAMPLE)
    profile["event"] = {"id": "another-event", "name": "虚构对抗赛"}
    profile["hub"].update(
        {
            "public_endpoint": "203.0.113.41",
            "provider_label": "Another VPS",
            "country": "冰岛",
        }
    )
    site = profile["sites"][0]
    site.update(
        {
            "id": "off",
            "role": "encoding",
            "country": "秘鲁",
            "public_endpoint": "192.0.2.78",
            "lan_cidrs": ["172.19.80.0/24", "172.19.81.0/24"],
        }
    )
    profile["site_links"][0]["site_id"] = "off"
    profile["traffic_policy"]["allowed_site_pairs"][0]["a"] = "off"
    profile["sites"][1].update({"public_endpoint": "198.51.100.25", "lan_cidrs": ["10.8.0.0/16"]})
    path = tmp_path / "custom.yaml"
    contents = yaml.safe_dump(profile, allow_unicode=True).replace("'off'", "off")
    path.write_text(contents, encoding="utf-8")
    monkeypatch.setenv("IPSECVPN_CONFIG", str(path))

    assert (
        cli.main(["export-peer", "--site", "off", "--format", "json", "--template", "generic"]) == 0
    )
    result = json.loads(capsys.readouterr().out)
    assert result["template"] == "generic"
    assert result["site"]["role"] == "encoding"
    assert result["site"]["country"] == "秘鲁"
    assert result["local"]["public_endpoint"] == "192.0.2.78"
    assert result["remote"]["public_endpoint"] == "203.0.113.41"
    assert result["local_ts"] == ["172.19.80.0/24", "172.19.81.0/24"]
    assert result["remote_ts"] == ["10.8.0.0/16"]
    assert path.read_text(encoding="utf-8") == contents


def test_secret_refs_are_not_read_or_emitted(capsys, monkeypatch):
    path = FIXTURES / "studio-vlan.yaml"
    original_open = Path.open

    def safe_open(self, *args, **kwargs):
        assert "secrets" not in self.parts
        return original_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", safe_open)
    commands = [
        ["plan", "-c", str(path)],
        ["validate", "-c", str(path), "--json"],
        ["export-peer", "-c", str(path), "--site", "control-X", "--format", "md"],
        ["export-peer", "-c", str(path), "--site", "control-X", "--format", "json"],
    ]
    for command in commands:
        assert cli.main(command) == 0
        output = capsys.readouterr()
        for marker in ("file:/etc/", "control-x.psk", "example-notification.ref", "secret_ref"):
            assert marker not in output.out
            assert marker not in output.err


def test_validation_errors_do_not_repeat_input(tmp_path, capsys):
    profile = load_profile(SAMPLE)
    sensitive_value = "redaction-test-value"
    profile["site_links"][0]["secret_ref"] = sensitive_value
    path = tmp_path / "invalid.yaml"
    path.write_text(yaml.safe_dump(profile), encoding="utf-8")
    assert cli.main(["validate", "-c", str(path), "--json"]) == 1
    output = capsys.readouterr()
    assert json.loads(output.out)["status"] == "FAIL"
    assert sensitive_value not in output.out + output.err

    path.write_text("unknown: [" + sensitive_value, encoding="utf-8")
    assert cli.main(["plan", "-c", str(path)]) == 1
    output = capsys.readouterr()
    assert sensitive_value not in output.out + output.err


def test_export_requires_explicit_profile_and_known_site(capsys, monkeypatch):
    monkeypatch.delenv("IPSECVPN_CONFIG", raising=False)
    command = ["export-peer", "--site", "other-site", "--format", "json"]
    assert cli.main(command) == 1
    assert "Select a profile explicitly" in capsys.readouterr().out
    assert cli.main([*command, "-c", str(SAMPLE)]) == 1
    assert "does not exist" in capsys.readouterr().out


def test_profiles_list_does_not_activate(tmp_path, capsys):
    command = ["profiles", "list", "--directory", str(tmp_path), "--json"]
    assert cli.main(command) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "SKIP"
    (tmp_path / "one.yaml").write_bytes(SAMPLE.read_bytes())
    assert cli.main(command) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["profiles"][0]["event"]["id"] == "demo-event"
    assert result["active_profile"]["status"] == "SKIP"
    (tmp_path / "duplicate.yml").write_bytes(SAMPLE.read_bytes())
    assert cli.main(command) == 1
    assert "Duplicate event ID" in capsys.readouterr().out


def test_check_reports_unmeasured_checks_as_skipped(capsys, monkeypatch):
    monkeypatch.setattr(cli.platform, "system", lambda: "Windows")
    assert cli.main(["check", "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "SKIP"
    assert all(item["status"] == "SKIP" for item in result["checks"])


def test_check_missing_linux_prerequisite_is_failure(capsys, monkeypatch):
    monkeypatch.setattr(cli.platform, "system", lambda: "Linux")
    monkeypatch.setattr(Path, "read_text", lambda *a, **kw: 'ID=ubuntu\nVERSION_ID="24.04"\n')
    monkeypatch.setattr(cli.shutil, "which", lambda name: None if name == "swanctl" else name)
    assert cli.main(["check", "--json"]) == 1
    checks = {item["id"]: item["status"] for item in json.loads(capsys.readouterr().out)["checks"]}
    assert checks["command_swanctl"] == "FAIL"
    assert checks["vici_sa_xfrm"] == "SKIP"
    assert checks["business_udp_tcp"] == "SKIP"
