from pathlib import Path

import pytest

from ipsecvpn.profile import (
    DOCUMENTATION_NETWORKS,
    IPv4Address,
    ProfileError,
    load_profile,
    validate_profile,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
SAMPLE = ROOT / "config" / "event.example.yaml"


@pytest.mark.parametrize("path", [SAMPLE, *sorted(FIXTURES.glob("*.yaml"))])
def test_shipped_profiles_use_documentation_wan_addresses(path):
    profile = load_profile(path)
    wan_nodes = [
        profile["hub"],
        *profile["sites"],
        *profile["backup"].get("links", []),
        *(uplink for site in profile["sites"] for uplink in site.get("uplinks", [])),
    ]
    for node in wan_nodes:
        address = IPv4Address(node["public_endpoint"])
        assert any(address in network for network in DOCUMENTATION_NETWORKS)


@pytest.mark.parametrize(
    ("path", "value", "message"),
    [
        (("schema_version",), "1.0", "Unsupported schema version"),
        (("sites",), [{}, {}, {}], "UNSUPPORTED"),
        (("sites",), [{}], "minItems"),
        (("event", "unknown"), "unexpected", "additionalProperties"),
        (("sites", 0, "id"), "bad/id", "pattern"),
        (("sites", 0, "id"), "stage-b", "Site IDs must be unique"),
        (("sites", 0, "ike_identity"), "%any", "pattern"),
        (("sites", 0, "public_endpoint"), "299.0.2.3", "format"),
        (("sites", 0, "public_endpoint"), "0.0.0.0", "Public endpoints"),
        (("sites", 0, "public_endpoint"), "203.0.113.10", "Primary public endpoints"),
        (("sites", 0, "lan_cidrs"), ["10.43.0.11/24"], "format"),
        (("sites", 0, "lan_cidrs"), ["10.43.10.0/24", "10.43.10.0/24"], "uniqueItems"),
        (("sites", 0, "lan_cidrs"), ["10.76.0.0/16"], "overlap"),
        (("sites", 0, "lan_cidrs"), ["0.0.0.0/0"], "Default routes"),
        (("sites", 0, "lan_cidrs"), ["224.0.0.0/24"], "non-forwardable"),
        (("sites", 0, "lan_cidrs"), ["198.51.100.0/24"], "capture an outer peer"),
        (("site_links", 0, "site_id"), "unknown-peer", "exactly one link"),
        (("site_links", 0, "if_id"), 102, "XFRM interface IDs"),
        (("site_links", 0, "if_id"), 1.0, "type"),
        (("site_links", 0, "if_id"), 4294967296, "maximum"),
        (("site_links", 0, "secret_ref"), "file:./secrets/local.psk", "pattern"),
        (
            ("site_links", 0, "secret_ref"),
            "file:/etc/ipsecvpn/secrets/stage-b.psk",
            "PSK references",
        ),
        (("site_links", 0, "esp_proposal"), "aes256-sha1-modp1024", "pattern"),
        (("site_links", 0, "ike_proposal"), "aes256-sha256-modp2048", "pattern"),
        (("site_links", 0, "outer_path", "source_ip"), "10.43.10.2", "capture an outer peer"),
        (("site_links", 0, "outer_path", "gateway"), "127.0.0.1", "unicast IPv4"),
        (("traffic_policy", "allowed_site_pairs"), [], "minItems"),
        (("traffic_policy", "allowed_site_pairs", 0, "b"), "production-a", "explicitly connect"),
        (
            ("traffic_policy", "allowed_site_pairs", 0),
            {"a": "production-a", "b": "stage-b", "a_cidrs": ["10.43.10.0/24"]},
            "dependentRequired",
        ),
        (
            ("traffic_policy", "allowed_site_pairs", 0),
            {
                "a": "production-a",
                "b": "stage-b",
                "a_cidrs": ["10.43.12.0/24"],
                "b_cidrs": ["10.76.12.0/24"],
            },
            "Authorized CIDRs",
        ),
        (("backup",), {"enabled": True}, "required"),
        (("backup",), {"enabled": True, "type": "arbitrary-cloud"}, "const"),
    ],
)
def test_invalid_profile(path, value, message):
    profile = load_profile(SAMPLE)
    parent = profile
    for key in path[:-1]:
        parent = parent[key]
    parent[path[-1]] = value
    with pytest.raises(ProfileError, match=message):
        validate_profile(profile)


@pytest.mark.parametrize(
    ("key", "value", "message"),
    [
        ("site_id", "missing-site", "unknown site"),
        ("public_endpoint", "203.0.113.125", "differ from primary"),
        ("local_uplink_id", "missing-isp", "unknown local uplink"),
        ("remote_cidrs", ["10.62.100.0/24"], "exceed the authorized"),
        ("route_priority", 10, "less preferred"),
    ],
)
def test_invalid_backup_link(key, value, message):
    profile = load_profile(FIXTURES / "studio-vlan.yaml")
    profile["backup"]["links"][0][key] = value
    with pytest.raises(ProfileError, match=message):
        validate_profile(profile)


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("schema_version: '2.0'\nschema_version: '1.0'\n", "unique strings"),
        ("a: &label test\nb: *label\n", "aliases"),
        ("schema_version: [2.0,\n", "single UTF-8 YAML profile"),
        ("---\nsite: a\n---\nsite: b\n", "single UTF-8 YAML profile"),
    ],
)
def test_yaml_load_errors(tmp_path, content, message):
    path = tmp_path / "broken.yaml"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(ProfileError, match=message):
        load_profile(path)
