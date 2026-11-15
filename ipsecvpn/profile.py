"""Parse and validate offline event profiles without dereferencing secrets."""

import json
import math
import re
from functools import lru_cache
from importlib.resources import files
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator, FormatChecker, validators

MAX_PROFILE_BYTES = 256 * 1024
DOCUMENTATION_NETWORKS = (
    IPv4Network("192.0.2.0/24"),
    IPv4Network("198.51.100.0/24"),
    IPv4Network("203.0.113.0/24"),
)
NON_UNICAST_LANS = tuple(
    IPv4Network(cidr)
    for cidr in ("0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4")
)
BACKUP_HANDOFF_FIELDS = (
    "public_endpoint",
    "tunnel_name",
    "remote_cidrs",
    "route_priority",
    "track_target",
)


class ProfileError(ValueError):
    """A profile error safe to display without its input values."""


class ProfileLoader(yaml.SafeLoader):
    yaml_implicit_resolvers = {
        initial: [rule for rule in rules if rule[0] != "tag:yaml.org,2002:bool"]
        for initial, rules in yaml.SafeLoader.yaml_implicit_resolvers.items()
    }

    def compose_node(self, parent, index):
        if self.check_event(yaml.AliasEvent):
            raise ProfileError("YAML aliases are not supported.")
        return super().compose_node(parent, index)

    def construct_mapping(self, node, deep=False):
        mapping = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key in mapping:
                raise ProfileError("YAML mapping keys must be unique strings.")
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


ProfileLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool", re.compile(r"^(true|false)$", re.IGNORECASE), list("tTfF")
)


@lru_cache(maxsize=1)
def schema_validator():
    source = Path(__file__).resolve().parent.parent / "config" / "schema.json"
    bundled = files("ipsecvpn").joinpath("schema.json")
    schema = json.loads((bundled if bundled.is_file() else source).read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    formats = FormatChecker()

    @formats.checks("ipv4-cidr", raises=ValueError)
    def canonical_cidr(value):
        return not isinstance(value, str) or str(IPv4Network(value)) == value

    types = Draft202012Validator.TYPE_CHECKER.redefine(
        "integer", lambda _checker, value: type(value) is int
    )
    validator = validators.extend(Draft202012Validator, type_checker=types)
    return validator(schema, format_checker=formats)


def load_profile(path):
    path = Path(path)
    try:
        if path.suffix.lower() not in {".yaml", ".yml"} or not path.is_file():
            raise ProfileError("Select a readable .yaml or .yml profile.")
        with path.open("rb") as stream:
            content = stream.read(MAX_PROFILE_BYTES + 1)
    except ProfileError:
        raise
    except (OSError, yaml.YAMLError, RecursionError, ValueError):
        raise ProfileError("Could not read a single UTF-8 YAML profile.") from None
    return parse_profile(content)


def parse_profile(content):
    if len(content) > MAX_PROFILE_BYTES:
        raise ProfileError("The profile exceeds the 256 KiB size limit.")
    try:
        profile = yaml.load(content.decode("utf-8-sig"), Loader=ProfileLoader)
    except ProfileError:
        raise
    except (yaml.YAMLError, RecursionError, ValueError):
        raise ProfileError("Could not read a single UTF-8 YAML profile.") from None
    validate_profile(profile)
    return profile


def validate_profile(profile):
    if isinstance(profile, dict):
        if "schema_version" in profile and profile["schema_version"] != "2.0":
            raise ProfileError("Unsupported schema version. Start from the V2 example.")
        sites = profile.get("sites")
        if isinstance(sites, list) and len(sites) > 2:
            raise ProfileError("UNSUPPORTED: PR #1 supports exactly two sites per profile.")

    error = next(schema_validator().iter_errors(profile), None)
    if error:
        path = ".".join(map(str, error.absolute_path)) or "profile"
        raise ProfileError(f"Schema violation at {path} ({error.validator}).")

    _validate_topology(profile)
    _validate_optional_paths(profile)


def _require_unique(values, label):
    values = list(values)
    if len(set(values)) != len(values):
        raise ProfileError(f"{label} must be unique.")


def _is_public_endpoint(value):
    address = IPv4Address(value)
    if address.is_multicast or address.is_reserved:
        return False
    return address.is_global or any(
        address in network and address not in {network.network_address, network.broadcast_address}
        for network in DOCUMENTATION_NETWORKS
    )


def _validate_topology(profile):
    sites = profile["sites"]
    links = profile["site_links"]
    _require_unique((site["id"] for site in sites), "Site IDs")
    _require_unique((link["site_id"] for link in links), "Site link IDs")
    _require_unique((link["if_id"] for link in links), "XFRM interface IDs")
    _require_unique((link["secret_ref"] for link in links), "PSK references")
    site_ids = {site["id"] for site in sites}
    if {link["site_id"] for link in links} != site_ids:
        raise ProfileError("Each site must have exactly one link and no unknown links.")

    pair = profile["traffic_policy"]["allowed_site_pairs"][0]
    if {pair["a"], pair["b"]} != site_ids:
        raise ProfileError("The allowed pair must explicitly connect the two distinct sites.")
    for side in ("a", "b"):
        site = next(site for site in sites if site["id"] == pair[side])
        if not set(pair.get(f"{side}_cidrs", ())).issubset(site["lan_cidrs"]):
            raise ProfileError("Authorized CIDRs must be listed in the matching site LAN.")

    networks = sorted(IPv4Network(cidr) for site in sites for cidr in site["lan_cidrs"])
    if any(network.prefixlen == 0 for network in networks):
        raise ProfileError("Default routes and wildcard traffic selectors are unsupported.")
    if any(network.overlaps(excluded) for network in networks for excluded in NON_UNICAST_LANS):
        raise ProfileError("Site LANs must not include special-use non-forwardable addresses.")
    if any(left.overlaps(right) for left, right in zip(networks, networks[1:], strict=False)):
        raise ProfileError("Site LAN CIDRs must not overlap.")

    primary_endpoints = [profile["hub"]["public_endpoint"], *(s["public_endpoint"] for s in sites)]
    _require_unique(primary_endpoints, "Primary public endpoints")
    endpoints = set(primary_endpoints)
    for site in sites:
        uplinks = site.get("uplinks", [])
        _require_unique((uplink["id"] for uplink in uplinks), "Uplink IDs within a site")
        uplink_endpoints = {uplink["public_endpoint"] for uplink in uplinks}
        if uplinks and site["public_endpoint"] not in uplink_endpoints:
            raise ProfileError("A site's primary public endpoint must be in its listed uplinks.")
        endpoints.update(uplink_endpoints)
    if profile["backup"]["enabled"]:
        endpoints.update(
            link["public_endpoint"]
            for link in profile["backup"].get("links", [])
            if "public_endpoint" in link
        )
    if any(not _is_public_endpoint(endpoint) for endpoint in endpoints):
        raise ProfileError("Public endpoints must be unicast public or RFC 5737 IPv4 addresses.")

    outer_addresses = {
        IPv4Address(link["outer_path"][key])
        for link in links
        for key in ("gateway", "source_ip")
        if key in link["outer_path"]
    }
    if any(address in excluded for address in outer_addresses for excluded in NON_UNICAST_LANS):
        raise ProfileError("Outer gateways and source IPs must be unicast IPv4 addresses.")
    outer_addresses.update(IPv4Address(endpoint) for endpoint in endpoints)
    if any(address in network for address in outer_addresses for network in networks):
        raise ProfileError("A site LAN would capture an outer peer, gateway or source address.")


def authorized_lans(profile):
    pair = profile["traffic_policy"]["allowed_site_pairs"][0]
    site_lans = {site["id"]: site["lan_cidrs"] for site in profile["sites"]}
    return {pair[side]: pair.get(f"{side}_cidrs", site_lans[pair[side]]) for side in ("a", "b")}


def backup_readiness(profile):
    """Report offline handoff completeness for an already validated profile."""
    backup = profile["backup"]
    if not backup["enabled"]:
        return {"enabled": False}

    backup_links = {link["site_id"]: link for link in backup.get("links", [])}
    missing = {}
    for primary in profile["site_links"]:
        site_id = primary["site_id"]
        link = backup_links.get(site_id)
        fields = (
            ["backup.links"]
            if link is None
            else [f"backup.links.{field}" for field in BACKUP_HANDOFF_FIELDS if field not in link]
        )
        if "route_priority" not in primary:
            fields.append("site_links.route_priority")
        if fields:
            missing[site_id] = fields

    if missing:
        return {"enabled": True, "status": "SKIP", "readiness": "INCOMPLETE", "missing": missing}
    return {"enabled": True, "status": "PASS", "readiness": "COMPLETE"}


def _validate_optional_paths(profile):
    sites = {site["id"]: site for site in profile["sites"]}
    backup = profile["backup"]
    authorized = authorized_lans(profile)
    if backup["enabled"]:
        links = backup.get("links", [])
        _require_unique((link["site_id"] for link in links), "Backup link site IDs")
        primary_priorities = {
            link["site_id"]: link.get("route_priority") for link in profile["site_links"]
        }
        primary_endpoints = {profile["hub"]["public_endpoint"]} | {
            site["public_endpoint"] for site in sites.values()
        }
        for link in links:
            site_id = link["site_id"]
            if site_id not in sites:
                raise ProfileError("A backup link references an unknown site.")
            if link.get("public_endpoint") in primary_endpoints:
                raise ProfileError("Backup endpoints must differ from primary endpoints.")
            if "track_target" in link and any(
                IPv4Address(link["track_target"]) in network for network in NON_UNICAST_LANS
            ):
                raise ProfileError("Backup Track targets must be unicast IPv4 addresses.")
            uplink_ids = {uplink["id"] for uplink in sites[site_id].get("uplinks", [])}
            if "local_uplink_id" in link and link["local_uplink_id"] not in uplink_ids:
                raise ProfileError("A backup link references an unknown local uplink.")
            remote_lans = next(lans for other, lans in authorized.items() if other != site_id)
            if not set(link.get("remote_cidrs", ())).issubset(remote_lans):
                raise ProfileError("Backup route CIDRs exceed the authorized remote LANs.")
            primary_priority = primary_priorities[site_id]
            backup_priority = link.get("route_priority")
            if (
                primary_priority is not None
                and backup_priority is not None
                and backup_priority <= primary_priority
            ):
                raise ProfileError("Backup route priority must be less preferred than primary.")

    monitoring = profile.get("monitoring", {})
    exporter = monitoring.get("exporter", {})
    interval = exporter.get("interval_seconds", 15)
    timeout = exporter.get("timeout_seconds", 5)
    if interval + timeout >= exporter.get("ttl_seconds", 30) or timeout >= interval:
        raise ProfileError("Monitoring requires timeout < interval and interval + timeout < TTL.")
    if any(
        isinstance(value, float) and not math.isfinite(value)
        for value in monitoring.get("thresholds", {}).values()
    ):
        raise ProfileError("Monitoring thresholds must be finite.")
    for probe in monitoring.get("probes", []):
        if probe["site_id"] not in sites:
            raise ProfileError("A monitoring probe references an unknown site.")
        if probe["path"] == "backup" and not backup["enabled"] and monitoring["enabled"]:
            raise ProfileError("A backup monitoring probe requires an enabled backup gateway.")
