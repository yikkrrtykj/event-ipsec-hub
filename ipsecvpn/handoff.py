"""Derive plans and handoff parameters from the same authorized topology."""

from html import escape

from .profile import ProfileError, authorized_lans, backup_readiness

PSK_PLACEHOLDER = "<SEND_SEPARATELY>"


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
        },
        "child": {
            "mode": "tunnel",
            "protocol": "ESP",
            **_algorithms(esp),
            "pfs": True,
            "lifetime_seconds": shared.get("child_lifetime_seconds", 3600),
        },
    }


def _endpoint(node):
    return {
        "id": node["id"],
        "public_endpoint": node["public_endpoint"],
        "ike_identity": node.get("ike_identity", node["public_endpoint"]),
    }


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
            "hub_local_ts": authorized[other],
            "hub_remote_ts": authorized[site["id"]],
            "peer_local_ts": authorized[site["id"]],
            "peer_remote_ts": authorized[other],
            "primary_route_priority": link.get("route_priority"),
            **_security(profile, link),
        }


def _backup(profile, site_id=None):
    backup = profile["backup"]
    readiness = backup_readiness(profile)
    if not readiness["enabled"] or readiness["status"] == "SKIP":
        return readiness
    return {
        **backup,
        **readiness,
        "links": [
            link
            for link in backup.get("links", [])
            if site_id is None or link["site_id"] == site_id
        ],
        "instructions": [
            "Use separate outer routes and tunnels for the primary and backup paths.",
            "Confirm the provider parameters and route priorities on both site firewalls.",
            "Preserve source IP and avoid per-packet ECMP across the paths.",
            "Pin each Track probe to its own path. Verify asymmetric failure and failback.",
            "Use a coordinated manual cutover if both sites cannot converge safely.",
        ],
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
    return {
        "status": "PASS",
        "format_version": "2.0",
        "template": template,
        "event": profile["event"],
        "site": {
            key: site[key]
            for key in ("id", "display_name", "role", "country", "location_label")
            if key in site
        },
        "firewall": site["firewall"],
        "uplinks": site.get("uplinks", []),
        "local": connection["peer"],
        "remote": connection["hub"],
        "ike": connection["ike"],
        "child": connection["child"],
        "local_ts": connection["peer_local_ts"],
        "remote_ts": connection["peer_remote_ts"],
        "allowed_traffic": {
            "remote_site_id": remote_site_id,
            "local_cidrs": connection["peer_local_ts"],
            "remote_cidrs": connection["peer_remote_ts"],
            "direction": "bidirectional",
        },
        "routing": {
            "destination_cidrs": connection["peer_remote_ts"],
            "primary_route_priority": connection["primary_route_priority"],
            "source_nat": False,
            "instructions": [
                "Route only the listed remote CIDRs into the tunnel and verify return routes.",
                "Keep the Hub public endpoint on the WAN and exempt the authorized LANs from NAT.",
                "Permit forwarding only between the authorized LANs in both directions.",
                "Permit IKE UDP 500/4500 for the Hub and ESP protocol 50 when required.",
            ],
        },
        "backup": backup,
        "monitoring": {
            "configured": profile.get("monitoring", {}).get("enabled", False),
            "status": "SKIP",
            "instructions": "Measure IKE, CHILD SA, counters and path-pinned probes separately.",
        },
        "acceptance": {
            "status": "SKIP",
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
    return "<code>" + escape(str(value)).replace("|", "&#124;") + "</code>"


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
    lines += _table(
        "对接对象",
        [
            ("赛事", data["event"]["name"]),
            ("本端站点 ID", site["id"]),
            ("本端站点名称", site["display_name"]),
            ("国家 / 地区", [site.get("country"), site.get("location_label")]),
            ("远端业务站点 ID", data["allowed_traffic"]["remote_site_id"]),
            (
                "设备厂商 / 型号 / 版本",
                [data["firewall"].get(field) for field in ("vendor", "model", "os_version")],
            ),
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
    ike = data["ike"]
    lines += _table(
        "IKE 网关与提议（阶段 1）",
        [
            ("本端公网地址", data["local"]["public_endpoint"]),
            ("远端 Hub 公网地址", data["remote"]["public_endpoint"]),
            ("本端 IKE ID", data["local"]["ike_identity"]),
            ("远端 IKE ID", data["remote"]["ike_identity"]),
            ("版本 / 认证", [ike["version"], ike["authentication"]]),
            ("PSK（经独立安全渠道交付）", ike["psk"]),
            (
                "加密 / 完整性 / PRF / DH",
                [ike["encryption"], ike["integrity"] or "AEAD", ike["prf"], ike["group"]],
            ),
            ("IKE 生存期（秒）", ike["lifetime_seconds"]),
            ("DPD 间隔（秒）", ike["dpd_delay_seconds"]),
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
        "",
    ]
    backup = data["backup"]
    if backup["enabled"]:
        (link,) = backup["links"]
        lines += _table(
            "外部备网关（人工交接）",
            [
                ("供应商", backup.get("provider_label")),
                ("备网关公网地址", link["public_endpoint"]),
                ("备隧道名称", link["tunnel_name"]),
                ("本端备用运营商出口 ID", link.get("local_uplink_id")),
                ("备路由网段", link["remote_cidrs"]),
                ("备路由优先级", link["route_priority"]),
                ("Track 目标", link["track_target"]),
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
    else:
        lines += ["## 外部备网关", "", "未启用。", ""]
    lines += [
        "## 监控和现场验收",
        "",
        "- 分别记录 IKE、CHILD SA、XFRM 计数和固定路径的端到端业务探测。",
        "- 验证每对授权网段的双向 UDP/TCP、源 IP、MTU、回程路由、重协商和越权阻断。",
        "- 如启用外部备网关，单独验收备路径、故障切换和回切。",
        "",
        "自动化监控与现场验收均为 SKIP。",
        "",
    ]
    return "\n".join(lines)
