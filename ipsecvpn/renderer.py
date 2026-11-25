"""Deterministic, secret-free deployment resources for one V2 profile."""

import hashlib
import json
from dataclasses import asdict, dataclass

from .handoff import HUB_DPD_ACTION, HUB_START_ACTION, build_plan, child_rekey_seconds
from .profile import backup_readiness, validate_profile

TABLE = "ipsecvpn"
ROUTE_PROTOCOL = "242"
XFRM_METRIC = "40"
BLACKHOLE_METRIC = "32760"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(data):
    return json.dumps(data, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode()


@dataclass(frozen=True)
class Link:
    site_id: str
    if_id: int
    wan: str
    source: str
    gateway: str | None
    peer: str
    local_id: str
    remote_id: str
    local_ts: tuple[str, ...]
    remote_ts: tuple[str, ...]
    ike_proposal: str
    esp_proposal: str
    ike_lifetime: int
    child_lifetime: int
    dpd_delay: int
    route_priority: int = int(XFRM_METRIC)
    selector_mode: str = "exact"
    start_action: str = HUB_START_ACTION
    dpd_action: str = HUB_DPD_ACTION
    close_action: str = "none"
    route_table: int | None = None
    policy_priority: int = 1000

    @property
    def name(self):
        return f"ivp{self.if_id:08x}"

    @property
    def child(self):
        return f"{self.name}-child"

    def child_specs(self):
        """Return (child_name, local_ts_tuple, remote_ts_tuple) entries for this link."""
        if self.selector_mode == "route_based":
            return ((self.child, ("0.0.0.0/0",), ("0.0.0.0/0",)),)
        if self.selector_mode == "per_pair":
            return tuple(
                (f"{self.child}-{idx}", (local_cidr,), (remote_cidr,))
                for idx, (local_cidr, remote_cidr) in enumerate(
                    (l_cidr, r_cidr) for l_cidr in self.local_ts for r_cidr in self.remote_ts
                )
            )
        return ((self.child, self.local_ts, self.remote_ts),)


@dataclass(frozen=True)
class DeploymentManifest:
    event_id: str
    links: tuple[Link, ...]
    forward_rules: tuple[tuple[str, str, tuple[str, ...], tuple[str, ...]], ...] = ()

    def resolved_forward_rules(self):
        """Return (source_link, target_link, source_cidrs, target_cidrs) tuples."""
        by_site = {link.site_id: link for link in self.links}
        if self.forward_rules:
            return tuple(
                (by_site[src_id], by_site[dst_id], src_cidrs, dst_cidrs)
                for src_id, dst_id, src_cidrs, dst_cidrs in self.forward_rules
                if src_id in by_site and dst_id in by_site
            )
        if len(self.links) == 2:
            a, b = self.links
            return (
                (a, b, a.remote_ts, b.remote_ts),
                (b, a, b.remote_ts, a.remote_ts),
            )
        return ()

    @property
    def networks(self):
        return sorted(cidr for link in self.links for cidr in link.remote_ts)

    def resources(self):
        return {
            "event_id": self.event_id,
            "links": [
                {**asdict(link), "xfrm_interface": link.name, "child": link.child}
                for link in self.links
            ],
            "routes": [
                {
                    "destination": cidr,
                    "interface": link.name,
                    "table": "main",
                    "metric": link.route_priority,
                    "fallback": {"type": "blackhole", "metric": int(BLACKHOLE_METRIC)},
                }
                for link in self.links
                for cidr in link.remote_ts
            ],
            "outer_routes": [
                {
                    "destination": f"{link.peer}/32",
                    "interface": link.wan,
                    "gateway": link.gateway,
                    "source_ip": link.source,
                    "route_table": link.route_table,
                }
                for link in self.links
            ],
            "symmetric_return_rules": [
                {
                    "from_source": f"{source}/32",
                    "table": table,
                    "priority": priority,
                    "interface": wan,
                    "gateway": gateway,
                }
                for table, (wan, source, gateway, priority) in sorted(
                    {
                        link.route_table: (
                            link.wan,
                            link.source,
                            link.gateway,
                            link.policy_priority,
                        )
                        for link in self.links
                        if link.route_table is not None
                    }.items()
                )
            ],
            "forward_acl": [
                {
                    "iif": source.name,
                    "oif": target.name,
                    "source_cidrs": source_cidrs,
                    "destination_cidrs": target_cidrs,
                }
                for source, target, source_cidrs, target_cidrs in self.resolved_forward_rules()
            ],
            "source_nat": False,
        }


def build_manifest(profile):
    validate_profile(profile)
    plan = build_plan(profile)
    links = []
    for item in plan["connections"]:
        outer = item["outer_path"]
        links.append(
            Link(
                site_id=item["site_id"],
                if_id=item["xfrm_if_id"],
                wan=outer["interface"],
                source=item["hub_source"],
                gateway=outer.get("gateway"),
                peer=item["peer"]["public_endpoint"],
                local_id=item["hub"]["ike_identity"],
                remote_id=item["peer"]["ike_identity"],
                local_ts=tuple(item["hub_local_ts"]),
                remote_ts=tuple(item["hub_remote_ts"]),
                ike_proposal=item["ike"]["proposal"],
                esp_proposal=item["child"]["proposal"],
                ike_lifetime=item["ike"]["lifetime_seconds"],
                child_lifetime=item["child"]["lifetime_seconds"],
                dpd_delay=item["ike"]["dpd_delay_seconds"],
                route_priority=(
                    item["primary_route_priority"]
                    if item.get("primary_route_priority") is not None
                    else int(XFRM_METRIC)
                ),
                selector_mode=item.get("selector_mode", "exact"),
                start_action=item["ike"].get("start_action", HUB_START_ACTION),
                dpd_action=item["ike"].get("dpd_action", HUB_DPD_ACTION),
                close_action=item["ike"].get("close_action", "none"),
                route_table=outer.get("route_table"),
                policy_priority=outer.get("policy_priority", 1000),
            )
        )
    forward_rules = tuple(
        (
            rule["source_site_id"],
            rule["target_site_id"],
            tuple(rule["source_cidrs"]),
            tuple(rule["destination_cidrs"]),
        )
        for rule in plan["forward_acl"]
    )
    return DeploymentManifest(
        profile["event"]["id"],
        tuple(sorted(links, key=lambda link: link.site_id)),
        forward_rules,
    )


def connection_settings(link):
    return {
        "version": "2",
        "local_addrs": [link.source],
        "remote_addrs": [link.peer],
        "proposals": [link.ike_proposal],
        "reauth_time": "0",
        "rekey_time": f"{link.ike_lifetime}s",
        "dpd_delay": f"{link.dpd_delay}s",
        "mobike": "no",
        "encap": "yes",
        "local": {"auth": "psk", "id": link.local_id},
        "remote": {"auth": "psk", "id": link.remote_id},
        "children": {
            child_name: {
                "mode": "tunnel",
                "local_ts": list(child_local_ts),
                "remote_ts": list(child_remote_ts),
                "esp_proposals": [link.esp_proposal],
                "if_id_in": str(link.if_id),
                "if_id_out": str(link.if_id),
                "life_time": f"{link.child_lifetime}s",
                "rekey_time": f"{child_rekey_seconds(link.child_lifetime)}s",
                "start_action": link.start_action,
                "dpd_action": link.dpd_action,
                "close_action": link.close_action,
            }
            for child_name, child_local_ts, child_remote_ts in link.child_specs()
        },
    }


def _config_lines(section, indent=""):
    for key, value in section.items():
        if isinstance(value, dict):
            yield f"{indent}{key} {{"
            yield from _config_lines(value, indent + "    ")
            yield f"{indent}}}"
        else:
            formatted = ", ".join(value) if isinstance(value, list) else value
            yield f"{indent}{key} = {formatted}"


def swanctl_config(manifest, keys=None):
    """Render the same connection settings used by the targeted VICI loader."""
    links = manifest.links if manifest else ()
    document = {
        "connections": {link.name: connection_settings(link) for link in links},
        "secrets": {
            f"ike-{link.name}": {
                "id-1": link.local_id,
                "id-2": link.remote_id,
                "secret": "0x" + keys[link.site_id].hex(),
            }
            for link in links
            if keys is not None
        },
    }
    return "\n".join((*_config_lines(document), ""))


def nft_config(manifest, token, guarded=(), interfaces=(), handshake=None):
    """A private table; transition guards block all protected traffic."""
    links = manifest.links if manifest else ()
    names = sorted(set(interfaces) | {link.name for link in links})
    networks = sorted(set(guarded) | {cidr for link in links for cidr in link.remote_ts})
    lines = [
        f"table ip {TABLE} {{",
        f"    chain owner_{token} {{",
        "    }",
        "    chain forward {",
        "        type filter hook forward priority -5; policy accept;",
    ]
    for source, target, source_cidrs, target_cidrs in (
        manifest.resolved_forward_rules() if manifest else ()
    ):
        lines.append(
            f'        iifname "{source.name}" oifname "{target.name}" '
            f"ip saddr {{ {', '.join(source_cidrs)} }} "
            f"ip daddr {{ {', '.join(target_cidrs)} }} accept"
        )
    for name in names:
        lines.extend([f'        iifname "{name}" drop', f'        oifname "{name}" drop'])
    for cidr in networks:
        lines.append(f"        ip daddr {cidr} drop")
    lines.extend(
        [
            "    }",
            "    chain output {",
            "        type filter hook output priority -5; policy accept;",
        ]
    )
    for link in links:
        lines.append(
            f'        oifname "{link.name}" ip daddr {{ {", ".join(link.remote_ts)} }} accept'
        )
    for cidr in networks:
        lines.append(f"        ip daddr {cidr} drop")
    lines.extend(
        ["    }", "    chain input {", "        type filter hook input priority -5; policy accept;"]
    )
    for link in handshake.links if handshake else links:
        lines.append(
            f'        iifname "{link.wan}" ip saddr {link.peer} ip daddr {link.source} '
            "udp dport { 500, 4500 } accept"
        )
        lines.append(
            f'        iifname "{link.wan}" ip saddr {link.peer} ip daddr {link.source} '
            "ip protocol esp accept"
        )
    for link in links:
        lines.append(
            f'        iifname "{link.name}" ip saddr {{ {", ".join(link.remote_ts)} }} '
            "ct state established,related accept"
        )
    for name in names:
        lines.append(f'        iifname "{name}" drop')
    lines.extend(
        ["        udp dport { 500, 4500 } drop", "        ip protocol esp drop", "    }", "}", ""]
    )
    return "\n".join(lines)


def external_backup(profile):
    state = backup_readiness(profile)
    if not state["enabled"]:
        return state
    return {
        **state,
        "status": "SKIP",
        "detail": "External backup is managed outside this Hub; no live readiness was evaluated.",
    }


def render(profile):
    manifest = build_manifest(profile)
    config = swanctl_config(manifest)
    nft = nft_config(manifest, "preview")
    return {
        "status": "PASS",
        "detail": "Offline rendering completed. Host and tunnel verification are SKIP.",
        "manifest": manifest.resources(),
        "files": {
            "swanctl.conf": {"sha256": digest(config.encode()), "preview": config},
            "ipsecvpn.nft": {"sha256": digest(nft.encode()), "preview": nft},
        },
        "permissions": "root and an explicitly authorized isolated Ubuntu 24.04 VM for writes",
        "startup_order": ["fail_closed_guard", "xfrm_and_routes", "vici", "verified_acl"],
        "backup": external_backup(profile),
        "site_to_site": {"status": "SKIP"},
    }


def resource_diff(before, target):
    previous = {link.name: link for link in before.links} if before else {}
    desired = {link.name: link for link in target.links} if target else {}
    return {
        "add": sorted(desired.keys() - previous.keys()),
        "remove": sorted(previous.keys() - desired.keys()),
        "update": sorted(
            name for name in previous.keys() & desired.keys() if previous[name] != desired[name]
        ),
        "previous_sha256": digest(canonical(before.resources())) if before else None,
        "target_sha256": digest(canonical(target.resources())) if target else None,
    }
