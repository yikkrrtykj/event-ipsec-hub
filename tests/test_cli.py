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
            assert data["backup"]["status"] == "PASS"
            assert data["backup"]["readiness"] == "COMPLETE"
            (link,) = data["backup"]["links"]
            assert link == next(
                item for item in profile["backup"]["links"] if item["site_id"] == local_id
            )
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
        if data["backup"]["enabled"]:
            assert "PASS/COMPLETE" in markdown
            assert link["track_target"] in markdown
            assert link["tunnel_name"] in markdown
    if profile["event"]["id"] == "studio-mock":
        assert "10.61.3.0/24" not in json.dumps(plan)
        assert plan["backup"]["readiness"] == "COMPLETE"
        assert len(plan["backup"]["links"]) == 2


@pytest.mark.parametrize(
    ("case", "expected_missing"),
    [
        ("no-links-key", {"control-X": ["backup.links"], "intake-7": ["backup.links"]}),
        ("no-links", {"control-X": ["backup.links"], "intake-7": ["backup.links"]}),
        ("one-link", {"intake-7": ["backup.links"]}),
        (
            "partial-link",
            {
                "intake-7": [
                    "backup.links.public_endpoint",
                    "backup.links.tunnel_name",
                    "backup.links.remote_cidrs",
                    "backup.links.route_priority",
                    "backup.links.track_target",
                ],
            },
        ),
        ("no-primary-priority", {"intake-7": ["site_links.route_priority"]}),
    ],
)
def test_incomplete_backup_blocks_both_site_handoffs(case, expected_missing, tmp_path, capsys):
    profile = load_profile(FIXTURES / "studio-vlan.yaml")
    backup = profile["backup"]
    if case == "no-links-key":
        del backup["links"]
    elif case == "no-links":
        backup["links"] = []
    elif case == "one-link":
        backup["links"].pop()
    elif case == "partial-link":
        backup["links"][1] = {"site_id": "intake-7"}
    elif case == "no-primary-priority":
        del profile["site_links"][1]["route_priority"]
    path = tmp_path / "draft.yaml"
    path.write_text(yaml.safe_dump(profile), encoding="utf-8")
    config = ["-c", str(path)]
    expected_backup = {
        "enabled": True,
        "status": "SKIP",
        "readiness": "INCOMPLETE",
        "missing": expected_missing,
    }

    assert cli.main(["validate", *config, "--json"]) == 0
    validation = json.loads(capsys.readouterr().out)
    assert validation["status"] == "PASS"
    assert validation["backup"] == expected_backup
    assert cli.main(["validate", *config]) == 0
    assert "SKIP/INCOMPLETE" in capsys.readouterr().out

    assert cli.main(["plan", *config]) == 0
    plan = json.loads(capsys.readouterr().out)
    assert plan["status"] == "SKIP"
    assert plan["backup"] == expected_backup
    assert len(plan["connections"]) == 2
    assert plan["checks"][0]["status"] == "PASS"

    for site in profile["sites"]:
        args = ["export-peer", *config, "--site", site["id"], "--format"]
        assert cli.main([*args, "json"]) == 0
        result = json.loads(capsys.readouterr().out)
        assert result["status"] == "SKIP"
        assert result["backup"] == expected_backup
        assert result["acceptance"]["status"] == "SKIP"
        assert "local" not in result
        assert "ike" not in result
        assert cli.main([*args, "md"]) == 0
        markdown = capsys.readouterr().out
        assert "SKIP/INCOMPLETE" in markdown
        assert "对接参数单" not in markdown.splitlines()[0]
        assert "Traffic Selectors" not in markdown
        assert all(site_id in markdown for site_id in expected_missing)


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
