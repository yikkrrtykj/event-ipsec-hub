"""Derive plans and handoff parameters from the same authorized topology."""

import hashlib
import json
from html import escape
from ipaddress import IPv4Address

from .profile import ProfileError, authorized_lans, backup_readiness

PSK_PLACEHOLDER = "<SEND_SEPARATELY>"
HUB_START_ACTION = "none"
HUB_DPD_ACTION = "clear"


def child_rekey_seconds(lifetime):
    return max(1, lifetime * 9 // 10)


def _algorithms(proposal):
    encryption, *parameters, group = proposal.split("-")
    return {
        "proposal": proposal,
        "encryption": encryption,
        "integrity": next((name for name in parameters if name.startswith("sha")), None),
        "group": group,
    }


def _security(profile, link):
    shared = profile.get("security", {})
    ike = link.get("ike_proposal", shared.get("ike_proposal", "aes256-sha256-prfsha256-modp2048"))
    esp = link.get("esp_proposal", shared.get("esp_proposal", "aes256-sha256-modp2048"))
    return {
        "ike": {
            "version": 2,
            "authentication": "PSK",
            "psk": PSK_PLACEHOLDER,
            **_algorithms(ike),
            "prf": next(name for name in ike.split("-") if name.startswith("prf")),
            "lifetime_seconds": shared.get("ike_lifetime_seconds", 28800),
            "dpd_delay_seconds": shared.get("dpd_delay_seconds", 30),
            "start_action": HUB_START_ACTION,
            "dpd_action": HUB_DPD_ACTION,
            "initiator": "Explicit Hub initiate, or the authorized site peer.",
            "forced_nat_t": True,
        },
        "child": {
            "mode": "tunnel",
            "protocol": "ESP",
            **_algorithms(esp),
            "pfs": True,
            "lifetime_seconds": shared.get("child_lifetime_seconds", 3600),
            "hub_rekey_seconds": child_rekey_seconds(shared.get("child_lifetime_seconds", 3600)),
        },
    }


def _endpoint(node):
    return {
        "id": node["id"],
        "public_endpoint": node["public_endpoint"],
        "ike_identity": node.get("ike_identity", node["public_endpoint"]),
    }


def _identity(value):
    if value.startswith("@"):
        return {"type": "ID_FQDN", "value": value[1:]}
    if "@" in value:
        return {"type": "ID_RFC822_ADDR", "value": value}
    try:
        IPv4Address(value)
    except ValueError:
        return {"type": "ID_FQDN", "value": value}
    return {"type": "ID_IPV4_ADDR", "value": value}


def _connections(profile):
    hub = _endpoint(profile["hub"])
    sites = {site["id"]: site for site in profile["sites"]}
    authorized = authorized_lans(profile)
    for link in profile["site_links"]:
        site = sites[link["site_id"]]
        other = next(site_id for site_id in sites if site_id != site["id"])
        yield {
            "site_id": site["id"],
            "hub": hub,
            "peer": _endpoint(site),
            "xfrm_if_id": link["if_id"],
            "outer_path": link["outer_path"],
            "hub_source": link["outer_path"].get("source_ip", hub["public_endpoint"]),
            "hub_local_ts": authorized[other],
            "hub_remote_ts": authorized[site["id"]],
            "peer_local_ts": authorized[site["id"]],
            "peer_remote_ts": authorized[other],
            "primary_route_priority": link.get("route_priority"),
            **_security(profile, link),
        }


def _backup_transit(profile, links):
    authorized = authorized_lans(profile)
    support = profile["backup"].get("transit_support", "unknown")
    uncovered = {}
    for link in links:
        remote = next(lans for site, lans in authorized.items() if site != link["site_id"])
        missing = sorted(set(remote) - set(link["remote_cidrs"]))
        if missing:
            uncovered[link["site_id"]] = missing
    reasons = []
    if support == "unsupported":
        reasons.append("UNSUPPORTED_BACKUP_TRANSIT")
    elif support == "unknown":
        reasons.append("UNKNOWN_BACKUP_TRANSIT")
    if uncovered:
        reasons.append("INCOMPLETE_BACKUP_ROUTE_COVERAGE")
    return {
        "declared_transit_support": support,
        "transit": {
            "status": "STOP" if reasons else "SKIP",
            "reason_codes": reasons or ["TRANSIT_DECLARED_REQUIRES_PATH_PROOF"],
            "missing_remote_cidrs": uncovered,
        },
        "data_path": {"status": "SKIP", "reason_code": "NO_INDEPENDENT_BACKUP_PATH_PROOF"},
        "cutover": {"status": "STOP", "reason_code": "NO_CUTOVER"},
        "required_evidence": [
            "Product, region, exact service mode, supported tunnel transit, ACL and return routes.",
            "Independent backup path proof in both directions for every authorized UDP/TCP pair.",
            "Per-site primary and backup Track source, target, interface, routing domain and TTL.",
            "Capacity, tunnel and route limits, bandwidth, cost and the backup owner sign-off.",
        ],
    }


def _backup(profile, site_id=None):
    backup = profile["backup"]
    readiness = backup_readiness(profile)
    if not readiness["enabled"] or readiness["status"] == "SKIP":
        return readiness
    links = backup["links"]
    site_links = [link for link in links if site_id is None or link["site_id"] == site_id]
    uplinks = {site["id"]: site.get("uplinks", []) for site in profile["sites"]}
    return {
        **backup,
        **readiness,
        "feasibility": _backup_transit(profile, links),
        "links": site_links,
        "handoff": {
            link["site_id"]: {
                "wan_peer_host_route": f"{link['public_endpoint']}/32",
                "local_uplink": next(
                    (
                        row
                        for row in uplinks[link["site_id"]]
                        if row["id"] == link.get("local_uplink_id")
                    ),
                    None,
                ),
                "psk": PSK_PLACEHOLDER,
                "track": {
                    "status": "SKIP",
                    "path": "backup",
                    "target": link["track_target"],
                    "source": None,
                    "routing_domain": None,
                    "ttl_seconds": None,
                },
            }
            for link in site_links
        },
        "instructions": [
            "Use separate outer routes and tunnels for the primary and backup paths.",
            "Confirm the provider parameters and route priorities on both site firewalls.",
            "Preserve source IP and avoid per-packet ECMP across the paths.",
            "Pin each Track probe to its own path. Verify asymmetric failure and failback.",
            "Use a coordinated manual cutover if both sites cannot converge safely.",
        ],
    }


def _delivery(profile):
    digest = hashlib.sha256(
        json.dumps(profile, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode()
    ).hexdigest()
    return {
        "classification": "NOT_APPLYABLE_CONFIG",
        "profile_sha256": digest,
        "revision_utc": None,
        "signoff": dict.fromkeys(("site_admin", "remote_site_admin", "hub_owner", "backup_owner")),
    }


def _device(firewall):
    return {
        "status": "SKIP",
        "model": firewall.get("model"),
        "reported_os_version": firewall.get("os_version"),
        "verified_build": None,
        "masked_serial": None,
        "ha_role": None,
        "routing_domain": None,
        "tunnel_mode": None,
        "unconfirmed_mode_decision": "STOP",
        "route_based": "Bind the approved tunnel interface and route only the authorized CIDRs.",
        "policy_based": "Verify exact mirrored Proxy IDs and route selection for every pair.",
        "selector_support": "STOP if exact pairs or multiple Phase 2 selectors cannot be verified.",
    }


def build_plan(profile):
    first, second = _connections(profile)
    connections = [first, second]
    backup = _backup(profile)
    return {
        "status": backup.get("status", "PASS"),
        "schema_version": profile["schema_version"],
        "event": profile["event"],
        "hub": profile["hub"],
        "checks": [
            {"id": "profile", "status": "PASS", "detail": "Schema and topology validated."},
            {"id": "host_routes", "status": "SKIP", "detail": "Host routes were not inspected."},
            {"id": "site_to_site", "status": "SKIP", "detail": "No live traffic was tested."},
        ],
        "connections": connections,
        "routes": [
            {"destination": cidr, "xfrm_if_id": conn["xfrm_if_id"]}
            for conn in connections
            for cidr in conn["hub_remote_ts"]
        ],
        "outer_routes": [
            {"destination": conn["peer"]["public_endpoint"] + "/32", **conn["outer_path"]}
            for conn in connections
        ],
        "forward_acl": [
            {
                "from_xfrm_if_id": source["xfrm_if_id"],
                "to_xfrm_if_id": target["xfrm_if_id"],
                "source_cidrs": source["hub_remote_ts"],
                "destination_cidrs": target["hub_remote_ts"],
            }
            for source, target in ((first, second), (second, first))
        ],
        "source_nat": False,
        "backup": backup,
        "monitoring": {
            "configured": profile.get("monitoring", {}).get("enabled", False),
            "status": "SKIP",
        },
    }


def peer_parameters(profile, site_id, template="auto"):
    site = next((site for site in profile["sites"] if site["id"] == site_id), None)
    if site is None:
        raise ProfileError("The requested site ID does not exist in the selected profile.")
    backup = _backup(profile, site_id)
    if backup.get("status") == "SKIP":
        return {
            "status": "SKIP",
            "delivery": {"classification": "NOT_APPLYABLE_CONFIG"},
            "detail": "Handoff withheld until both sites have complete backup parameters.",
            "backup": backup,
            "acceptance": {"status": "SKIP"},
        }
    connection = next(conn for conn in _connections(profile) if conn["site_id"] == site_id)
    if template == "auto":
        vendor = site["firewall"]["vendor"].casefold()
        template = "hillstone" if vendor == "hillstone" else "generic"
    authorized = authorized_lans(profile)
    remote_site_id = next(other for other in authorized if other != site_id)
    local_cidrs, remote_cidrs = connection["peer_local_ts"], connection["peer_remote_ts"]
    hub_endpoint = connection["hub"]["public_endpoint"]
    return {
        "status": "PASS",
        "format_version": "2.0",
        "template": template,
        "delivery": _delivery(profile),
        "event": profile["event"],
        "site": {
            key: site[key]
            for key in ("id", "display_name", "role", "country", "location_label")
            if key in site
        },
        "firewall": site["firewall"],
        "device_validation": _device(site["firewall"]),
        "uplinks": site.get("uplinks", []),
        "local": {
            **connection["peer"],
            "id_on_wire": _identity(connection["peer"]["ike_identity"]),
        },
        "remote": {**connection["hub"], "id_on_wire": _identity(connection["hub"]["ike_identity"])},
        "outer": {
            "site_wan_peer_host_route": f"{hub_endpoint}/32",
            "site_primary_uplinks": [
                row
                for row in site.get("uplinks", [])
                if row["public_endpoint"] == site["public_endpoint"]
            ],
            "hub_egress": connection["outer_path"],
            "hub_bind_source": connection["hub_source"],
            "hub_wan_peer_host_route": f"{site['public_endpoint']}/32",
            "hub_xfrm_if_id": connection["xfrm_if_id"],
            "ike_udp_ports": [500, 4500],
            "allow_native_esp_only_if_required": True,
            "status": "SKIP",
        },
        "ike": connection["ike"],
        "child": connection["child"],
        "local_ts": local_cidrs,
        "remote_ts": remote_cidrs,
        "allowed_traffic": {
            "remote_site_id": remote_site_id,
            "local_cidrs": local_cidrs,
            "remote_cidrs": remote_cidrs,
            "direction": "bidirectional",
        },
        "routing": {
            "destination_cidrs": remote_cidrs,
            "primary_route_priority": connection["primary_route_priority"],
            "source_nat": False,
            "instructions": [
                "Route only the listed remote CIDRs into the tunnel and verify return routes.",
                "Keep the Hub public endpoint on the WAN and exempt the authorized LANs from NAT.",
                "Permit forwarding only between the authorized LANs in both directions.",
                "Permit IKE UDP 500/4500 for the Hub and ESP protocol 50 when required.",
            ],
            "zone_policy": [
                {
                    "from_zone": "LAN",
                    "to_zone": "VPN",
                    "source": local_cidrs,
                    "destination": remote_cidrs,
                },
                {
                    "from_zone": "VPN",
                    "to_zone": "LAN",
                    "source": remote_cidrs,
                    "destination": local_cidrs,
                },
            ],
            "nat_exemption": "Exempt both directions before public SNAT; verify original sources.",
        },
        "backup": backup,
        "monitoring": {
            "configured": profile.get("monitoring", {}).get("enabled", False),
            "status": "SKIP",
            "primary_track": {
                "status": "SKIP",
                "path": "primary",
                "target": None,
                "source": None,
                "routing_domain": None,
                "ttl_seconds": None,
            },
            "instructions": "Measure IKE, CHILD SA, counters and path-pinned probes separately.",
        },
        "acceptance": {
            "status": "SKIP",
            "ike_child": "SKIP",
            "data_path": "SKIP",
            "matrix": [
                {
                    "from_site_id": source,
                    "to_site_id": destination,
                    "source_cidrs": authorized[source],
                    "destination_cidrs": authorized[destination],
                    "protocols": ["UDP", "TCP"],
                    "paths": ["primary", "backup"] if backup["enabled"] else ["primary"],
                    "pairing": "every source CIDR against every destination CIDR",
                    "status": "SKIP",
                }
                for source, destination in ((site_id, remote_site_id), (remote_site_id, site_id))
            ],
            "instructions": [
                "Confirm IKE and CHILD SA establishment with the exact selectors.",
                "Test bidirectional UDP/TCP, source IP preservation and MTU for every CIDR pair.",
                "Verify rekey, return routing and rejection of unauthorized traffic.",
                "Verify any backup path separately, including failover and failback.",
            ],
        },
    }


def _value(value):
    if isinstance(value, list):
        return "、".join(_value(item) for item in value) or "未填写"
    if value is None:
        return "未填写"
    if isinstance(value, bool):
        return "是" if value else "否"
    if value == PSK_PLACEHOLDER:
        return "`<SEND_SEPARATELY>`"
    escaped = (
        escape(str(value)).replace("|", "&#124;").replace("\r", "&#13;").replace("\n", "&#10;")
    )
    return "<code>" + escaped + "</code>"


def _table(title, rows):
    return [
        f"## {title}",
        "",
        "| 参数 | 值 |",
        "| --- | --- |",
        *(f"| {label} | {_value(value)} |" for label, value in rows),
        "",
    ]


def render_peer_markdown(data):
    if data["status"] == "SKIP":
        lines = [
            "# 外部备网关交接暂停",
            "",
            "**NOT_APPLYABLE_CONFIG**",
            "",
            "**SKIP/INCOMPLETE**。补齐以下双站资料后再导出对接参数单。",
            "",
            *(
                f"- {_value(site_id)} 缺少 {_value(fields)}"
                for site_id, fields in data["backup"]["missing"].items()
            ),
            "",
        ]
        return "\n".join(lines)

    hillstone = data["template"] == "hillstone"
    name = "山石 Hillstone / StoneOS" if hillstone else "厂商中立"
    lines = [
        f"# {name} IPsec 对接参数单",
        "",
        "PASS 表示离线参数单已生成。现场验收为 SKIP。",
        "",
        "参数以接收方站点视角编制。双方应核对 IKE ID 类型与值、算法、计时器和选择器。",
        "",
    ]
    if hillstone:
        lines.extend(
            [
                "请按设备型号和 StoneOS 版本核对 IKE 对端、IPsec 提议、隧道接口、"
                "安全区域和 Track 的配置方式。需核实设备能否协商列出的多 CIDR，"
                "如需通配选择器则暂停对接并单独验收。",
                "",
            ]
        )
    site = data["site"]
    delivery = data["delivery"]
    device = data["device_validation"]
    lines += _table(
        "对接对象",
        [
            ("赛事", data["event"]["name"]),
            ("本端站点 ID", site["id"]),
            ("本端站点名称", site["display_name"]),
            ("国家 / 地区", [site.get("country"), site.get("location_label")]),
            ("远端业务站点 ID", data["allowed_traffic"]["remote_site_id"]),
            ("用途", delivery["classification"]),
            ("Profile SHA-256", delivery["profile_sha256"]),
            ("修订时间（UTC）", delivery["revision_utc"]),
            (
                "设备厂商 / 型号 / 版本",
                [data["firewall"].get(field) for field in ("vendor", "model", "os_version")],
            ),
        ],
    )
    lines += _table(
        "设备确认与签收（现场 SKIP）",
        [
            (
                "经核验的完整固件 build / 脱敏序列号",
                [device["verified_build"], device["masked_serial"]],
            ),
            (
                "HA 角色 / VR 或 VSYS / 隧道模式",
                [device["ha_role"], device["routing_domain"], device["tunnel_mode"]],
            ),
            ("未确认模式时", device["unconfirmed_mode_decision"]),
            ("Route-based", device["route_based"]),
            ("Policy-based", device["policy_based"]),
            ("精确 Proxy ID / 多 Phase 2 支持", device["selector_support"]),
            ("本站管理员 / 签收 UTC", delivery["signoff"]["site_admin"]),
            ("对站管理员 / 签收 UTC", delivery["signoff"]["remote_site_admin"]),
            ("Hub 管理员 / 签收 UTC", delivery["signoff"]["hub_owner"]),
            ("备网关管理员 / 签收 UTC", delivery["signoff"]["backup_owner"]),
        ],
    )
    if data["uplinks"]:
        lines += _table(
            "本端运营商出口",
            [
                (
                    "出口 ID / 运营商 / 公网地址 / 接口",
                    [
                        uplink["id"],
                        uplink["isp_label"],
                        uplink["public_endpoint"],
                        uplink.get("interface"),
                    ],
                )
                for uplink in data["uplinks"]
            ],
        )
    outer = data["outer"]
    egress = outer["hub_egress"]
    lines += _table(
        "外层 WAN 路径（两端 FIB 核验）",
        [
            ("本站至 Hub 的 WAN Peer /32", outer["site_wan_peer_host_route"]),
            ("本站主出口 ID", [row["id"] for row in outer["site_primary_uplinks"]]),
            ("Hub 至本站的 WAN Peer /32", outer["hub_wan_peer_host_route"]),
            (
                "Hub WAN 接口 / 运营商 / 网关",
                [egress.get(key) for key in ("interface", "isp_label", "gateway")],
            ),
            ("Hub 本地绑定源地址（存在 NAT 时核实外部映射）", outer["hub_bind_source"]),
            ("Hub XFRM ID（Linux 本地）", outer["hub_xfrm_if_id"]),
            ("IKE UDP 端口", outer["ike_udp_ports"]),
            ("原生 ESP 协议 50 按实际需要放行", outer["allow_native_esp_only_if_required"]),
        ],
    )
    ike = data["ike"]
    lines += _table(
        "IKE 网关与提议（阶段 1）",
        [
            ("本端公网地址", data["local"]["public_endpoint"]),
            ("远端 Hub 公网地址", data["remote"]["public_endpoint"]),
            ("本端 IKE ID", data["local"]["ike_identity"]),
            ("远端 IKE ID", data["remote"]["ike_identity"]),
            ("本端 IKE ID 类型 / 线上值", list(data["local"]["id_on_wire"].values())),
            ("远端 IKE ID 类型 / 线上值", list(data["remote"]["id_on_wire"].values())),
            ("版本 / 认证", [ike["version"], ike["authentication"]]),
            ("PSK（经独立安全渠道交付）", ike["psk"]),
            (
                "加密 / 完整性 / PRF / DH",
                [ike["encryption"], ike["integrity"] or "AEAD", ike["prf"], ike["group"]],
            ),
            ("IKE 生存期（秒）", ike["lifetime_seconds"]),
            ("DPD 间隔（秒）", ike["dpd_delay_seconds"]),
            ("VPN 发起方式", ike["initiator"]),
            ("Hub start_action / dpd_action", [ike["start_action"], ike["dpd_action"]]),
            ("Hub 强制 NAT-T", ike["forced_nat_t"]),
        ],
    )
    child = data["child"]
    lines += _table(
        "IPsec 隧道与提议（阶段 2）",
        [
            ("封装 / 协议", [child["mode"], child["protocol"]]),
            (
                "加密 / 完整性 / PFS 组",
                [child["encryption"], child["integrity"] or "AEAD", child["group"]],
            ),
            ("CHILD 生存期（秒）", child["lifetime_seconds"]),
            ("Hub CHILD rekey（秒，配置值）", child["hub_rekey_seconds"]),
            ("本端 Traffic Selectors", data["local_ts"]),
            ("远端 Traffic Selectors", data["remote_ts"]),
            ("主路由优先级", data["routing"]["primary_route_priority"]),
        ],
    )
    lines += [
        "## 路由、安全策略与 NAT",
        "",
        "- 只把上表远端网段指向隧道，核对回程路由。Hub 公网地址应经 WAN 到达。",
        "- 仅允许上表本端与远端业务网段双向互通，加入 NAT 豁免并保持源 IP。",
        "- 按 Hub 公网地址放行 IKE UDP 500/4500，按实际封装决定是否放行 ESP 协议 50。",
        "- 核对双端 VR、PBR、回程与 WAN /32，避免递归进入隧道。保持原有默认路由。",
        f"- {_value(data['routing']['nat_exemption'])}",
        "",
    ]
    lines += _table(
        "双向安全区域授权",
        [
            (
                f"{rule['from_zone']} → {rule['to_zone']}",
                [rule["source"], "→", rule["destination"]],
            )
            for rule in data["routing"]["zone_policy"]
        ],
    )
    backup = data["backup"]
    if backup["enabled"]:
        (link,) = backup["links"]
        alternate = backup["handoff"][link["site_id"]]
        lines += _table(
            "外部备网关（人工交接）",
            [
                ("供应商", backup.get("provider_label")),
                ("备网关公网地址", link["public_endpoint"]),
                ("备 Peer 的 WAN /32", alternate["wan_peer_host_route"]),
                ("备隧道名称", link["tunnel_name"]),
                ("本端备用运营商出口 ID", link.get("local_uplink_id")),
                (
                    "本端备出口运营商 / 公网地址",
                    [
                        (alternate["local_uplink"] or {}).get(key)
                        for key in ("isp_label", "public_endpoint")
                    ],
                ),
                ("备 PSK（独立于主路径）", alternate["psk"]),
                ("备路由网段", link["remote_cidrs"]),
                ("备路由优先级", link["route_priority"]),
                ("Track 目标", link["track_target"]),
                (
                    "Track 源 / VR / TTL（需现场证明走备路径）",
                    [
                        alternate["track"][key]
                        for key in ("source", "routing_domain", "ttl_seconds")
                    ],
                ),
            ],
        )
        lines += [
            "PASS/COMPLETE 表示两站备用交接字段齐全。现场验收为 SKIP。",
            "",
            "核对主备独立外层路由和隧道。Track 探测分别固定到各自路径。"
            "保持源 IP 并避免逐包 ECMP。验证单侧故障和恢复回切，"
            "双端无法可靠收敛时由两端协调人工切换。",
            "",
        ]
        feasibility = backup["feasibility"]
        lines += _table(
            "备路径可行性与切换准入",
            [
                ("中转能力声明", feasibility["declared_transit_support"]),
                (
                    "中转核验",
                    [feasibility["transit"]["status"], *feasibility["transit"]["reason_codes"]],
                ),
                (
                    "未覆盖的授权网段",
                    [
                        f"{site_id}: {', '.join(cidrs)}"
                        for site_id, cidrs in feasibility["transit"]["missing_remote_cidrs"].items()
                    ],
                ),
                ("业务路径", list(feasibility["data_path"].values())),
                ("切换准入", list(feasibility["cutover"].values())),
                ("所需证据", feasibility["required_evidence"]),
            ],
        )
    else:
        lines += ["## 外部备网关", "", "未启用。", ""]
    lines += [
        "## 监控和现场验收",
        "",
        "- 分别记录 IKE、CHILD SA、XFRM 计数和固定路径的端到端业务探测。",
        "- 分别填写主、备 Track 的目标、源、出接口、VR 和 TTL，验证绕路回执会被拒绝。",
        "- 验证每对授权网段的双向 UDP/TCP、源 IP、MTU、回程路由、重协商和越权阻断。",
        "- 如启用外部备网关，单独验收备路径、故障切换和回切。",
        "",
        "自动化监控与现场验收均为 SKIP。",
        "",
    ]
    lines += _table(
        "精确选择器与现场测试矩阵（逐一验证每个源网段与目的网段组合）",
        [
            (
                f"{_value(row['from_site_id'])} → {_value(row['to_site_id'])}",
                [
                    row["source_cidrs"],
                    "→",
                    row["destination_cidrs"],
                    row["protocols"],
                    row["paths"],
                    row["status"],
                ],
            )
            for row in data["acceptance"]["matrix"]
        ],
    )
    return "\n".join(lines)
