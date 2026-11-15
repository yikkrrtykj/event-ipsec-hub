"""PR #5 offline acceptance. The test names carry the contract's case IDs."""

import json
import socket
import subprocess
from pathlib import Path

import pytest

from ipsecvpn import cli
from ipsecvpn.failover import PathProof, observe
from ipsecvpn.handoff import PSK_PLACEHOLDER, build_plan, peer_parameters, render_peer_markdown
from ipsecvpn.profile import ProfileError, load_profile, validate_profile
from ipsecvpn.renderer import build_manifest, canonical, connection_settings, digest

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures"
SAMPLE = ROOT / "config/event.example.yaml"
DOCS = ROOT / "docs/pr5"


@pytest.fixture
def profile():
    return load_profile(FIXTURES / "studio-vlan.yaml")


def peer(profile):
    return peer_parameters(profile, profile["sites"][0]["id"])


def markdown(name):
    return (DOCS / f"PR5_{name}.md").read_text(encoding="utf-8")


def test_c02_old_v2_profiles_still_export():
    expected = {"arena-apac-eu": False, "signal-eu-americas": False, "studio-vlan": True}
    for fixture in FIXTURES.glob("*.yaml"):
        loaded = load_profile(fixture)
        result = peer(loaded)
        assert loaded["schema_version"] == "2.0" and result["status"] == "PASS"
        assert result["backup"]["enabled"] is expected[fixture.stem]


def test_c03_renamed_swapped_sites_derive_roles_and_directions(profile):
    renamed = {}
    for index, site in enumerate(profile["sites"]):
        renamed[site["id"]] = new = f"swapped-{index}"
        site.update(id=new, role="fabric" if index else "grading")
    for link in profile["site_links"] + profile["backup"]["links"]:
        link["site_id"] = renamed[link["site_id"]]
    for probe in profile["monitoring"]["probes"]:
        probe["site_id"] = renamed[probe["site_id"]]
    pair = profile["traffic_policy"]["allowed_site_pairs"][0]
    pair["a"], pair["b"] = renamed[pair["b"]], renamed[pair["a"]]
    pair["a_cidrs"], pair["b_cidrs"] = pair["b_cidrs"], pair["a_cidrs"]
    profile["sites"].reverse()
    validate_profile(profile)
    report = peer(profile)
    assert (report["site"]["id"], report["site"]["role"]) == ("swapped-1", "fabric")
    assert report["allowed_traffic"]["remote_site_id"] == "swapped-0"
    assert (report["local_ts"], report["remote_ts"]) == (pair["a_cidrs"], pair["b_cidrs"])


def test_c04_multi_cidr_report_mirrors_hub_subset(profile):
    report = peer(profile)
    connection = build_plan(profile)["connections"][0]
    assert report["local_ts"] == connection["hub_remote_ts"] == ["10.61.1.0/24", "10.61.2.0/24"]
    assert report["remote_ts"] == connection["hub_local_ts"] == ["10.62.8.0/24", "10.62.9.0/24"]
    assert "10.61.3.0/24" not in render_peer_markdown(report)


def test_c05_vendor_template_switch_does_not_change_data(profile):
    hillstone = peer(profile)
    generic = peer_parameters(profile, hillstone["site"]["id"], "generic")
    assert hillstone == {**generic, "template": "hillstone"}
    assert "StoneOS" in render_peer_markdown(hillstone).splitlines()[0]
    assert "厂商中立" in render_peer_markdown(generic).splitlines()[0]


def test_c06_json_and_markdown_share_exact_fields(profile):
    report = json.loads(json.dumps(peer(profile)))
    rendered = render_peer_markdown(report)
    alternate = report["backup"]["links"][0]
    values = [
        report["local"]["id_on_wire"]["value"],
        report["remote"]["id_on_wire"]["type"],
        report["outer"]["site_wan_peer_host_route"],
        report["delivery"]["profile_sha256"],
        *report["local_ts"],
        *report["remote_ts"],
        alternate["public_endpoint"],
        str(alternate["route_priority"]),
        alternate["track_target"],
        report["routing"]["nat_exemption"],
    ]
    assert all(value in rendered for value in values)
    for phase in ("ike", "child"):
        assert all(
            report[phase][field] in rendered for field in ("encryption", "integrity", "group")
        )


def test_c07_secret_files_and_references_never_enter_reports(profile, monkeypatch):
    def deny_open(*args, **kwargs):
        pytest.fail("Handoff opened a file after loading its profile.")

    monkeypatch.setattr(Path, "open", deny_open)
    report = peer(profile)
    alternate = report["backup"]["handoff"][report["site"]["id"]]
    assert report["ike"]["psk"] == alternate["psk"] == PSK_PLACEHOLDER
    text = render_peer_markdown(report) + json.dumps(build_plan(profile))
    assert all(marker not in text for marker in ("secret_ref", "webhook_ref", "file:/etc/"))


def test_c08_disabled_backup_still_exports():
    report = peer(load_profile(SAMPLE))
    assert report["status"] == "PASS" and report["backup"] == {"enabled": False}
    assert "INCOMPLETE" not in render_peer_markdown(report)


def test_c09_each_missing_site_is_listed_and_handoff_withheld(profile):
    first, second = profile["backup"]["links"]
    profile["backup"]["links"] = [{"site_id": first["site_id"]}]
    validate_profile(profile)
    assert len(build_plan(profile)["connections"]) == 2
    for link in (first, second):
        report = peer_parameters(profile, link["site_id"])
        missing = report["backup"]["missing"]
        assert report["status"] == "SKIP" and "ike" not in report
        assert set(missing) == {first["site_id"], second["site_id"]}
        assert "backup.links.track_target" in missing[first["site_id"]]
        assert "backup.links" in missing[second["site_id"]]


def test_c10_complete_backup_is_only_documentation_ready(profile):
    backup = peer(profile)["backup"]
    assert (backup["status"], backup["readiness"]) == ("PASS", "COMPLETE")
    assert backup["feasibility"]["data_path"]["status"] == "SKIP"
    assert backup["feasibility"]["cutover"]["status"] == "STOP"


@pytest.mark.parametrize("priority", [1, 10])
def test_c11_reject_preferred_or_equal_backup_priority(profile, priority):
    profile["backup"]["links"][0]["route_priority"] = priority
    with pytest.raises(ProfileError, match="less preferred"):
        validate_profile(profile)


@pytest.mark.parametrize("reason", ["cidr", "peer"])
def test_c12_reject_backup_cidr_or_duplicate_primary_peer(profile, reason):
    link = profile["backup"]["links"][0]
    if reason == "cidr":
        link["remote_cidrs"] = ["10.62.0.0/16"]
    else:
        link["public_endpoint"] = profile["hub"]["public_endpoint"]
    with pytest.raises(ProfileError, match="authorized remote|differ from primary"):
        validate_profile(profile)


def test_c13_reproducible_markdown_and_safe_labels(profile):
    profile["event"]["name"] = "A | <script> & B"
    validate_profile(profile)
    first, second = (render_peer_markdown(peer(profile)) for _ in range(2))
    assert first == second
    assert "A &#124; &lt;script&gt; &amp; B" in first and "<script>" not in first


def test_c14_offline_commands_never_reach_network_or_host_tools(profile, monkeypatch, capsys):
    def reject(*args, **kwargs):
        pytest.fail("An offline report attempted host or network access.")

    monkeypatch.setattr(subprocess, "Popen", reject)
    monkeypatch.setattr(socket, "socket", reject)
    config = ["-c", str(FIXTURES / "studio-vlan.yaml")]
    assert cli.main(["plan", *config]) == 0
    assert cli.main(["export-peer", *config, "--site", profile["sites"][0]["id"]]) == 0
    assert "SKIP" in capsys.readouterr().out


def test_h01_device_inventory_is_field_verified(profile):
    device = peer(profile)["device_validation"]
    assert device["model"] == profile["sites"][0]["firewall"]["model"]
    assert device["status"] == "SKIP"
    assert all(
        device[key] is None
        for key in ("verified_build", "masked_serial", "ha_role", "routing_domain")
    )


def test_h02_modes_separate_and_unconfirmed_mode_stops(profile):
    device = peer(profile)["device_validation"]
    assert "tunnel interface" in device["route_based"]
    assert "Proxy IDs" in device["policy_based"]
    assert device["tunnel_mode"] is None and device["unconfirmed_mode_decision"] == "STOP"


@pytest.mark.parametrize(
    ("identity", "kind", "value"),
    [
        ("198.51.100.13", "ID_IPV4_ADDR", "198.51.100.13"),
        ("@peer.example", "ID_FQDN", "peer.example"),
        ("peer@sample.example", "ID_RFC822_ADDR", "peer@sample.example"),
    ],
)
def test_h03_ike_v2_psk_and_wire_id(profile, identity, kind, value):
    profile["sites"][0]["ike_identity"] = identity
    validate_profile(profile)
    report = peer(profile)
    assert report["local"]["id_on_wire"] == {"type": kind, "value": value}
    assert (report["ike"]["version"], report["ike"]["authentication"]) == (2, "PSK")


def test_h04_reporting_algorithms_timers_dpd_match_hub_renderer(profile):
    for link in build_manifest(profile).links:
        report = peer_parameters(profile, link.site_id)
        swan = connection_settings(link)
        child = swan["children"][link.child]
        assert swan["proposals"] == [report["ike"]["proposal"]]
        assert child["esp_proposals"] == [report["child"]["proposal"]]
        assert swan["rekey_time"] == f"{report['ike']['lifetime_seconds']}s"
        assert swan["dpd_delay"] == f"{report['ike']['dpd_delay_seconds']}s"
        assert child["life_time"] == f"{report['child']['lifetime_seconds']}s"
        assert child["rekey_time"] == f"{report['child']['hub_rekey_seconds']}s"
        assert child["dpd_action"] == report["ike"]["dpd_action"] == "clear"
        assert child["start_action"] == report["ike"]["start_action"] == "none"


def test_h05_exact_reversed_selectors_at_both_sites(profile):
    first, second = [peer_parameters(profile, site["id"]) for site in profile["sites"]]
    assert first["local_ts"] == second["remote_ts"]
    assert first["remote_ts"] == second["local_ts"]
    assert first["device_validation"]["selector_support"].startswith("STOP")


def test_h06_matrix_represents_every_authorized_pair_both_directions(profile):
    data = peer(profile)
    forward, reverse = data["acceptance"]["matrix"]
    assert forward["source_cidrs"] == reverse["destination_cidrs"] == data["local_ts"]
    assert reverse["source_cidrs"] == forward["destination_cidrs"] == data["remote_ts"]
    for row in (forward, reverse):
        assert row["protocols"] == ["UDP", "TCP"]
        assert row["paths"] == ["primary", "backup"] and row["status"] == "SKIP"


def test_h07_peer_routes_separate_public_peer_and_bind_address(profile):
    profile["site_links"][0]["outer_path"]["source_ip"] = "192.168.79.3"
    validate_profile(profile)
    outer = peer(profile)["outer"]
    assert outer["hub_bind_source"] == "192.168.79.3"
    assert outer["site_wan_peer_host_route"] == profile["hub"]["public_endpoint"] + "/32"
    assert outer["hub_wan_peer_host_route"] == profile["sites"][0]["public_endpoint"] + "/32"
    assert outer["site_primary_uplinks"][0]["id"] == "fiber"


def test_h08_only_authorized_remote_traffic_routed(profile):
    report = peer(profile)
    assert report["routing"]["destination_cidrs"] == report["remote_ts"]
    document = render_peer_markdown(report)
    assert "VR、PBR、回程" in document and "保持原有默认路由" in document


def test_h09_symmetric_zones_and_nat_exemption(profile):
    report = peer(profile)
    forward, reverse = report["routing"]["zone_policy"]
    assert (forward["from_zone"], forward["to_zone"]) == ("LAN", "VPN")
    assert (reverse["from_zone"], reverse["to_zone"]) == ("VPN", "LAN")
    assert forward["source"] == reverse["destination"] == report["local_ts"]
    assert reverse["source"] == forward["destination"] == report["remote_ts"]
    assert not report["routing"]["source_nat"]
    assert "before public SNAT" in report["routing"]["nat_exemption"]


def test_h10_peer_scope_and_nat_t(profile):
    report = peer(profile)
    assert report["outer"]["ike_udp_ports"] == [500, 4500]
    assert report["outer"]["allow_native_esp_only_if_required"]
    assert report["ike"]["forced_nat_t"]
    assert "按 Hub 公网地址放行" in render_peer_markdown(report)


def test_h11_handoff_pass_does_not_certify_live(profile):
    report = peer(profile)
    assert report["status"] == "PASS"
    assert report["delivery"]["classification"] == "NOT_APPLYABLE_CONFIG"
    assert report["acceptance"]["ike_child"] == report["acceptance"]["data_path"] == "SKIP"


def test_h12_both_admin_signoffs_and_profile_provenance(profile):
    report = peer(profile)
    assert report["delivery"]["profile_sha256"] == digest(canonical(profile))
    assert report["delivery"]["revision_utc"] is None
    assert report["delivery"]["signoff"] == dict.fromkeys(
        ("site_admin", "remote_site_admin", "hub_owner", "backup_owner")
    )
    assert "PSK（经独立安全渠道交付）" in render_peer_markdown(report)


@pytest.mark.parametrize(
    ("declared", "status", "reason"),
    [
        ("unknown", "STOP", "UNKNOWN_BACKUP_TRANSIT"),
        ("unsupported", "STOP", "UNSUPPORTED_BACKUP_TRANSIT"),
        ("supported", "SKIP", "TRANSIT_DECLARED_REQUIRES_PATH_PROOF"),
    ],
)
def test_b01_transit_claims_require_scope_and_evidence(profile, declared, status, reason):
    profile["backup"]["transit_support"] = declared
    validate_profile(profile)
    feasibility = peer(profile)["backup"]["feasibility"]
    assert feasibility["transit"]["status"] == status
    assert feasibility["transit"]["reason_codes"] == [reason]
    assert "ACL and return routes" in feasibility["required_evidence"][0]
    assert feasibility["cutover"]["status"] == "STOP"


def test_b02_sa_up_cannot_replace_independent_backup_proof(profile):
    profile["backup"]["transit_support"] = "supported"
    assert peer(profile)["backup"]["feasibility"]["data_path"]["status"] == "SKIP"
    assert observe("backup", "backup")["state"] == "UNKNOWN"


def test_b03_cloud_capacity_and_cost_template_is_unfilled(profile):
    assert "bandwidth, cost" in peer(profile)["backup"]["feasibility"]["required_evidence"][-1]
    template = markdown("SITE_ACCEPTANCE_TEMPLATE")
    for field in ("地域", "路由表及隔离域", "最大隧道数与路由数", "可用带宽", "计费"):
        assert any(field in line and "SKIP" in line for line in template.splitlines())


def test_b04_backup_peer_independent_and_separate_psk(profile):
    data = peer(profile)
    (link,) = data["backup"]["links"]
    backup = data["backup"]["handoff"][link["site_id"]]
    assert backup["wan_peer_host_route"] == link["public_endpoint"] + "/32"
    assert backup["wan_peer_host_route"] != data["outer"]["site_wan_peer_host_route"]
    assert backup["local_uplink"]["id"] != data["outer"]["site_primary_uplinks"][0]["id"]
    assert backup["psk"] == PSK_PLACEHOLDER


def test_b05_track_pinning_and_target_unverified_per_path(profile):
    data = peer(profile)
    backup = data["backup"]["handoff"][data["site"]["id"]]["track"]
    primary = data["monitoring"]["primary_track"]
    assert backup["path"] == "backup" and primary["path"] == "primary"
    assert backup["target"] == data["backup"]["links"][0]["track_target"]
    assert backup["status"] == primary["status"] == "SKIP"
    assert all(backup[key] is None for key in ("source", "routing_domain", "ttl_seconds"))


def test_f01_unapproved_site_and_cidr_rejected(profile):
    with pytest.raises(ProfileError, match="does not exist"):
        peer_parameters(profile, "unknown-operator")
    profile["traffic_policy"]["allowed_site_pairs"][0]["a_cidrs"].append("172.25.112.0/24")
    with pytest.raises(ProfileError, match="matching site LAN"):
        validate_profile(profile)


def test_f02_wildcard_selectors_stop(profile):
    profile["sites"][0]["lan_cidrs"] = ["0.0.0.0/0"]
    profile["traffic_policy"]["allowed_site_pairs"][0]["a_cidrs"] = ["0.0.0.0/0"]
    with pytest.raises(ProfileError, match="wildcard|prefix"):
        validate_profile(profile)


def test_f03_conflicting_peer_and_outer_routes_rejected(profile):
    outer = profile["site_links"][0]["outer_path"]
    outer["source_ip"] = profile["backup"]["links"][0]["public_endpoint"]
    with pytest.raises(ProfileError, match="differ from primary"):
        validate_profile(profile)
    outer["source_ip"] = "10.61.2.9"
    with pytest.raises(ProfileError, match="capture an outer peer"):
        validate_profile(profile)


def test_f04_inconsistent_routes_never_become_up():
    proof = PathProof("primary", True, True, True, True)
    decision = observe("primary", "backup", proof)
    assert decision["state"] == "ASYMMETRIC_STOP" and decision["data_path"] == "SKIP"
    assert observe("primary", "unavailable")["state"] == "SINGLE_SIDE_TRANSITION"


def test_f05_changed_source_stops_and_unreplied_probe_fails():
    nat = PathProof("backup", True, True, False, True)
    decision = observe("backup", "backup", nat)
    assert decision["status"] == "STOP" and decision["reason"] == "SOURCE_CHANGED"
    loss = PathProof("backup", False, True, True, True)
    assert observe("backup", "backup", loss)["data_path"] == "FAIL"


def test_f06_wrong_track_path_rejected():
    proof = PathProof("backup", True, True, True, True)
    result = observe("primary", "primary", proof)
    unpinned = observe("backup", "backup", PathProof("backup", True, True, True, False))
    assert result["status"] == unpinned["status"] == "STOP"
    assert result["reason"] == unpinned["reason"] == "WRONG_PATH"


def test_f07_unknown_fib_or_stale_receipt_is_skipped():
    proof = PathProof("primary", True, True, True, True)
    assert observe(None, "primary", proof)["status"] == "SKIP"
    assert observe("primary", "primary")["data_path"] == "SKIP"


def test_f08_unchecked_os_does_not_generate_hillstone_config(profile):
    data = peer(profile)
    out = render_peer_markdown(data)
    assert "NOT_APPLYABLE_CONFIG" in out and "设备确认与签收（现场 SKIP）" in out
    assert data["device_validation"]["verified_build"] is None and chr(96) * 3 not in out


def test_f09_known_unsupported_transit_stops_even_with_complete_inputs(profile):
    profile["backup"]["transit_support"] = "unsupported"
    profile["backup"]["links"][0]["remote_cidrs"].pop()
    validate_profile(profile)
    backup = peer(profile)["backup"]
    assert backup["readiness"] == "COMPLETE"
    transit = backup["feasibility"]["transit"]
    assert "UNSUPPORTED_BACKUP_TRANSIT" in transit["reason_codes"]
    assert "INCOMPLETE_BACKUP_ROUTE_COVERAGE" in transit["reason_codes"]
    assert transit["missing_remote_cidrs"] == {profile["sites"][0]["id"]: ["10.62.9.0/24"]}


def test_f10_live_public_evidence_unavailable_for_both_templates(profile):
    for site in profile["sites"]:
        report = peer_parameters(profile, site["id"])
        assert report["outer"]["status"] == report["device_validation"]["status"] == "SKIP"
        assert report["monitoring"]["status"] == report["acceptance"]["status"] == "SKIP"


def test_f11_reject_output_path_option_without_creating_a_file(tmp_path, capsys):
    path = tmp_path / "shared.json"
    with pytest.raises(SystemExit) as exc:
        cli.main(
            ["export-peer", "-c", str(SAMPLE), "--site", "production-a", "--output", str(path)]
        )
    assert exc.value.code == 2 and not path.exists()
    assert "unrecognized arguments" in capsys.readouterr().err


def test_l01_template_has_owners_and_blank_signoff():
    template = markdown("SITE_ACCEPTANCE_TEMPLATE")
    for owner in ("Site A", "Site B", "Hub", "Backup"):
        assert owner in template
    assert "空白即未验收 / SKIP" in template and "双方签收" in template


def test_l02_access_snapshot_and_stop_are_admission_gates():
    runbook = markdown("FAILOVER_RUNBOOK")
    for term in ("带外管理", "配置快照", "STOP / NO_CUTOVER", "任一不可达 STOP"):
        assert term in runbook


@pytest.mark.parametrize(
    ("case", "filename", "fields"),
    [
        (
            "l04",
            "SITE_ACCEPTANCE_TEMPLATE",
            ("业务实际包大小", "最大成功 DF 长度", "PMTUD 反馈", "分片结果", "TCP MSS"),
        ),
        ("l06", "FAILOVER_RUNBOOK", ("显式", "initiate", "无人值守断线自动重连未验证")),
        ("l07", "FAILOVER_RUNBOOK", ("max_loss", "outage_s", "failback_s")),
        (
            "l08",
            "FAILOVER_RUNBOOK",
            ("MANUAL_CUTOVER_REQUIRED", "两端路由、业务、MTU", "按各自配置备份回滚"),
        ),
    ],
    ids=["L04", "L06", "L07", "L08"],
)
def test_l_template_observation_fields(case, filename, fields):
    document = markdown(filename)
    assert all(field in document for field in fields), case


def test_l03_every_path_direction_and_protocol_has_a_blank_row():
    template = markdown("SITE_ACCEPTANCE_TEMPLATE")
    for path in ("primary", "backup"):
        for direction in ("A→B", "B→A"):
            for protocol in ("UDP", "TCP"):
                key = f"| {path} | {direction} | {protocol} |"
                assert any(key in row and row.endswith("| SKIP |") for row in template.splitlines())


def test_l05_application_rehearsal_outcomes_start_as_skip():
    template = markdown("SITE_ACCEPTANCE_TEMPLATE")
    for term in ("SRT", "游戏/制作系统", "QoS/ISP"):
        assert any(term in line and "SKIP" in line for line in template.splitlines())


def test_l09_cleanup_only_owned_and_revoke_credentials():
    page = (ROOT / "docs/event-lifecycle.md").read_text(encoding="utf-8")
    for term in ("仅清理本赛事拥有的资源", "撤销本赛事访问", "轮换独立密钥", "非本赛事业务"):
        assert term in page


def test_l10_draft_contract_and_regression_workflows_present():
    task = (ROOT / "CODEX_PR5_TASK.md").read_text(encoding="utf-8")
    assert "**首提交**" in task and "PR 保持 Draft" in task
    assert "6aacc03514ee98bea91e26bbba46a72451211715" in task
    for name in ("ci.yml", "pr2-vm.yml", "pr3-lab.yml", "pr4-lab.yml", "pr5-lab.yml"):
        assert (ROOT / ".github/workflows" / name).is_file()
