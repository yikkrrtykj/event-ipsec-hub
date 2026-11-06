import json
from pathlib import Path

import pytest

from ipsecvpn import cli
from ipsecvpn.handoff import build_plan
from ipsecvpn.host import Host, route_key
from ipsecvpn.profile import load_profile
from ipsecvpn.renderer import build_manifest, resource_diff
from ipsecvpn.resources import route_specs
from ipsecvpn.secureio import Stop

FIXTURES = Path(__file__).with_name("fixtures")


@pytest.mark.parametrize("path", sorted(FIXTURES.glob("*.yaml")))
def test_render_is_repeatable_and_matches_original_plan(path, capsys, monkeypatch):
    profile = load_profile(path)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("Read-only rendering touched a host operation.")

    monkeypatch.setattr(Host, "command", forbidden)
    args = ["render", "-c", str(path), "--json"]
    assert cli.main(args) == 0
    original = capsys.readouterr().out
    assert cli.main(args) == 0
    assert capsys.readouterr().out == original
    document = json.loads(original)
    assert document["status"] == "PASS"
    assert document["site_to_site"]["status"] == "SKIP"
    manifest = document["manifest"]
    links = {link["site_id"]: link for link in manifest["links"]}
    swanctl = document["files"]["swanctl.conf"]["preview"]
    acl = document["files"]["ipsecvpn.nft"]["preview"]
    assert "0.0.0.0/0" not in swanctl and "start_action = none" in swanctl
    for conn in build_plan(profile)["connections"]:
        link = links[conn["site_id"]]
        assert link["local_ts"] == conn["hub_local_ts"]
        assert link["remote_ts"] == conn["hub_remote_ts"]
        assert f"if_id_in = {conn['xfrm_if_id']}" in swanctl
        assert f"if_id_out = {conn['xfrm_if_id']}" in swanctl
        assert link["xfrm_interface"] in acl
    for link in profile["site_links"]:
        assert link["secret_ref"] not in original
        assert Path(link["secret_ref"]).name not in original
    assert len(manifest["forward_acl"]) == 2
    expected_acl = {
        (tuple(rule["source_cidrs"]), tuple(rule["destination_cidrs"]))
        for rule in build_plan(profile)["forward_acl"]
    }
    assert {
        (tuple(rule["source_cidrs"]), tuple(rule["destination_cidrs"]))
        for rule in manifest["forward_acl"]
    } == expected_acl
    assert manifest["source_nat"] is False
    assert document["backup"]["enabled"] == profile["backup"]["enabled"]


def test_incomplete_backup_leaves_primary_manifest_unchanged():
    profile = load_profile(FIXTURES / "studio-vlan.yaml")
    before = build_manifest(profile)
    profile["backup"]["links"].clear()
    after = build_manifest(profile)
    assert before == after
    assert resource_diff(before, after)["update"] == []


def test_linux_route_keys_match_declared_exact_fallback():
    key = route_key(
        {"dst": "10.44.50.0/24", "type": "blackhole", "metric": 32760, "protocol": "242"}
    )
    manifest = build_manifest(load_profile(FIXTURES / "arena-apac-eu.yaml"))
    assert key in route_specs((manifest,))


def test_auto_wan_is_not_a_live_interface():
    manifest = build_manifest(load_profile(FIXTURES / "arena-apac-eu.yaml"))

    class TestHost(Host):
        def command(self, *_args, **_kwargs):
            return ""

    with pytest.raises(Stop, match="offline placeholder"):
        TestHost().check_paths(manifest, [{"dst": "default", "dev": "wan"}], set(), [], set())


def test_unprivileged_or_non_linux_install_stops(capsys, monkeypatch):
    monkeypatch.setattr("ipsecvpn.host.platform.system", lambda: "Windows")
    assert cli.main(["install", "--confirm", "--json"]) == 1
    result = json.loads(capsys.readouterr().out)
    assert (result["status"], result["decision"]) == ("FAIL", "STOP")


def test_vici_inventory_does_not_ignore_legacy_connections():
    class TestHost(Host):
        def vici(self, *_args):
            return "foreign: IKEv1, no reauthentication\n  local:  192.0.2.10\n"

    assert TestHost().vici_names() == {"foreign"}


def test_ownership_marker_rejects_foreign_table():
    from ipsecvpn.resources import Resources

    class TestHost(Host):
        def routing(self):
            return [], [], []

        def nft(self):
            return [{"table": {"family": "ip", "name": "ipsecvpn"}}]

    with pytest.raises(Stop, match="not owned"):
        Resources(TestHost(), "new", ()).network()
