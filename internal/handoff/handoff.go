package handoff

import (
	"fmt"
	"html"
	"net/netip"
	"slices"
	"sort"
	"strings"

	"github.com/yikkrrtykj/event-ipsec-hub/internal/manifest"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/profile"
)

const PSKPlaceholder = "<SEND_SEPARATELY>"

type parsedAlg struct {
	Proposal   string
	Encryption string
	Integrity  string
	PRF        string
	Group      string
}

func parseProposal(prop string, isIKE bool) parsedAlg {
	parts := strings.Split(prop, "-")
	res := parsedAlg{Proposal: prop}
	if len(parts) < 2 {
		return res
	}
	res.Encryption = parts[0]
	res.Group = parts[len(parts)-1]
	for _, p := range parts[1 : len(parts)-1] {
		if strings.HasPrefix(p, "sha") {
			res.Integrity = p
		} else if isIKE && strings.HasPrefix(p, "prf") {
			res.PRF = p
		}
	}
	return res
}

type wireIdentity struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

func resolveIdentity(val string) wireIdentity {
	if strings.HasPrefix(val, "@") {
		return wireIdentity{Type: "ID_FQDN", Value: val[1:]}
	}
	if strings.Contains(val, "@") {
		return wireIdentity{Type: "ID_RFC822_ADDR", Value: val}
	}
	if addr, err := netip.ParseAddr(val); err == nil && addr.Is4() {
		return wireIdentity{Type: "ID_IPV4_ADDR", Value: val}
	}
	return wireIdentity{Type: "ID_FQDN", Value: val}
}

func buildConnections(p *profile.Profile) []map[string]any {
	m, _ := manifest.BuildManifest(p)
	siteMap := make(map[string]profile.Site, len(p.Sites))
	for _, s := range p.Sites {
		siteMap[s.ID] = s
	}
	linkMeta := make(map[string]profile.SiteLink, len(p.SiteLinks))
	for _, sl := range p.SiteLinks {
		linkMeta[sl.KeyID()] = sl
	}

	out := make([]map[string]any, 0, len(m.Links))
	for _, l := range m.Links {
		sl := linkMeta[l.KeyID()]
		ikeAlg := parseProposal(l.IKEProposal, true)
		espAlg := parseProposal(l.ESPProposal, false)
		initiator := "Explicit Hub initiate, or the authorized site peer."
		if l.StartAction != "none" || l.DPDAction == "restart" {
			initiator = "Unattended Hub auto-initiate/reconnect enabled."
		}
		var ikeInteg any
		if ikeAlg.Integrity != "" {
			ikeInteg = ikeAlg.Integrity
		}
		var espInteg any
		if espAlg.Integrity != "" {
			espInteg = espAlg.Integrity
		}
		var prio any
		if sl.RoutePriority != nil {
			prio = *sl.RoutePriority
		}
		out = append(out, map[string]any{
			"link_id": l.KeyID(),
			"site_id": l.SiteID,
			"hub": map[string]any{
				"id":              p.Hub.ID,
				"public_endpoint": p.Hub.PublicEndpoint,
				"ike_identity":    p.Hub.EffectiveIKEIdentity(),
			},
			"peer": map[string]any{
				"id":              l.SiteID,
				"public_endpoint": l.Peer,
				"ike_identity":    l.RemoteID,
			},
			"xfrm_if_id":             l.IfID,
			"outer_path":             sl.OuterPath,
			"hub_source":             l.Source,
			"hub_local_ts":           l.LocalTS,
			"hub_remote_ts":          l.RemoteTS,
			"peer_local_ts":          l.RemoteTS,
			"peer_remote_ts":         l.LocalTS,
			"selector_mode":          l.SelectorMode,
			"primary_route_priority": prio,
			"ike": map[string]any{
				"version":           2,
				"authentication":    "PSK",
				"psk":               PSKPlaceholder,
				"proposal":          ikeAlg.Proposal,
				"encryption":        ikeAlg.Encryption,
				"integrity":         ikeInteg,
				"group":             ikeAlg.Group,
				"prf":               ikeAlg.PRF,
				"lifetime_seconds":  l.IKELifetime,
				"dpd_delay_seconds": l.DPDDelay,
				"start_action":      l.StartAction,
				"dpd_action":        l.DPDAction,
				"close_action":      l.CloseAction,
				"initiator":         initiator,
				"forced_nat_t":      true,
			},
			"child": map[string]any{
				"mode":              "tunnel",
				"protocol":          "ESP",
				"proposal":          espAlg.Proposal,
				"encryption":        espAlg.Encryption,
				"integrity":         espInteg,
				"group":             espAlg.Group,
				"pfs":               true,
				"lifetime_seconds":  l.ChildLifetime,
				"hub_rekey_seconds": manifest.ChildRekeySeconds(l.ChildLifetime),
			},
		})
	}
	return out
}

func buildBackupInfo(p *profile.Profile, siteID string) map[string]any {
	readiness := profile.EvaluateBackupReadiness(p)
	if !readiness.Enabled {
		return map[string]any{"enabled": false}
	}
	if readiness.Status == "SKIP" {
		return map[string]any{
			"enabled":   true,
			"status":    "SKIP",
			"readiness": readiness.Readiness,
			"missing":   readiness.Missing,
		}
	}

	support := p.Backup.TransitSupport
	if support == "" {
		support = "unknown"
	}
	uncovered := make(map[string][]string)
	for _, bl := range p.Backup.Links {
		remote := profile.AuthorizedRemoteLANs(p, bl.SiteID)
		var missing []string
		for _, r := range remote {
			if !slices.Contains(bl.RemoteCIDRs, r) {
				missing = append(missing, r)
			}
		}
		if len(missing) > 0 {
			sort.Strings(missing)
			uncovered[bl.SiteID] = missing
		}
	}
	var reasons []string
	switch support {
	case "unsupported":
		reasons = append(reasons, "UNSUPPORTED_BACKUP_TRANSIT")
	case "unknown":
		reasons = append(reasons, "UNKNOWN_BACKUP_TRANSIT")
	}
	if len(uncovered) > 0 {
		reasons = append(reasons, "INCOMPLETE_BACKUP_ROUTE_COVERAGE")
	}
	transitStatus := "SKIP"
	reasonCodes := reasons
	if len(reasons) > 0 {
		transitStatus = "STOP"
	} else {
		reasonCodes = []string{"TRANSIT_DECLARED_REQUIRES_PATH_PROOF"}
	}

	siteUplinks := make(map[string][]profile.Uplink, len(p.Sites))
	for _, s := range p.Sites {
		siteUplinks[s.ID] = s.Uplinks
	}
	var filtered []profile.BackupLink
	handoffMap := make(map[string]any)
	for _, bl := range p.Backup.Links {
		if siteID != "" && bl.SiteID != siteID {
			continue
		}
		filtered = append(filtered, bl)
		var localUplink any
		for _, u := range siteUplinks[bl.SiteID] {
			if u.ID == bl.LocalUplinkID {
				localUplink = u
				break
			}
		}
		handoffMap[bl.SiteID] = map[string]any{
			"wan_peer_host_route": bl.PublicEndpoint + "/32",
			"local_uplink":        localUplink,
			"psk":                 PSKPlaceholder,
			"track": map[string]any{
				"status":         "SKIP",
				"path":           "backup",
				"target":         bl.TrackTarget,
				"source":         nil,
				"routing_domain": nil,
				"ttl_seconds":    nil,
			},
		}
	}

	return map[string]any{
		"enabled":        true,
		"type":           p.Backup.Type,
		"provider_label": p.Backup.ProviderLabel,
		"location_label": p.Backup.LocationLabel,
		"country":        p.Backup.Country,
		"status":         readiness.Status,
		"readiness":      readiness.Readiness,
		"links":          filtered,
		"handoff":        handoffMap,
		"feasibility": map[string]any{
			"declared_transit_support": support,
			"transit": map[string]any{
				"status":               transitStatus,
				"reason_codes":         reasonCodes,
				"missing_remote_cidrs": uncovered,
			},
			"data_path": map[string]any{"status": "SKIP", "reason_code": "NO_INDEPENDENT_BACKUP_PATH_PROOF"},
			"cutover":   map[string]any{"status": "STOP", "reason_code": "NO_CUTOVER"},
		},
		"instructions": []string{
			"Use separate outer routes and tunnels for the primary and backup paths.",
			"Confirm the provider parameters and route priorities on both site firewalls.",
			"Preserve source IP and avoid per-packet ECMP across the paths.",
			"Pin each Track probe to its own path. Verify asymmetric failure and failback.",
			"Use a coordinated manual cutover if both sites cannot converge safely.",
		},
	}
}

// BuildPlan produces the read-only JSON topology plan for `ipsecvpn plan`.
func BuildPlan(p *profile.Profile) map[string]any {
	conns := buildConnections(p)
	bySite := make(map[string][]map[string]any)
	routes := make([]map[string]any, 0)
	outerRoutes := make([]map[string]any, 0, len(conns))
	for _, c := range conns {
		sid := c["site_id"].(string)
		bySite[sid] = append(bySite[sid], c)
		for _, cidr := range c["hub_remote_ts"].([]string) {
			routes = append(routes, map[string]any{
				"destination": cidr,
				"xfrm_if_id":  c["xfrm_if_id"],
			})
		}
		peer := c["peer"].(map[string]any)
		outerRoutes = append(outerRoutes, map[string]any{
			"destination": peer["public_endpoint"].(string) + "/32",
			"outer_path":  c["outer_path"],
		})
	}
	forwardACL := make([]map[string]any, 0)
	for _, rule := range profile.AuthorizedPairs(p) {
		for _, src := range bySite[rule.SourceSiteID] {
			for _, dst := range bySite[rule.TargetSiteID] {
				forwardACL = append(forwardACL, map[string]any{
					"from_xfrm_if_id":   src["xfrm_if_id"],
					"to_xfrm_if_id":     dst["xfrm_if_id"],
					"source_site_id":    rule.SourceSiteID,
					"target_site_id":    rule.TargetSiteID,
					"source_cidrs":      rule.SourceCIDRs,
					"destination_cidrs": rule.TargetCIDRs,
				})
			}
		}
	}
	backup := buildBackupInfo(p, "")
	status := "PASS"
	if s, ok := backup["status"].(string); ok && s != "" {
		status = s
	}
	monConfigured := p.Monitoring != nil && p.Monitoring.Enabled
	return map[string]any{
		"status":         status,
		"schema_version": p.SchemaVersion,
		"event":          p.Event,
		"hub":            p.Hub,
		"checks": []map[string]any{
			{"id": "profile", "status": "PASS", "detail": "Schema and topology validated."},
			{"id": "host_routes", "status": "SKIP", "detail": "Host routes were not inspected."},
			{"id": "site_to_site", "status": "SKIP", "detail": "No live traffic was tested."},
		},
		"connections":  conns,
		"routes":       routes,
		"outer_routes": outerRoutes,
		"forward_acl":  forwardACL,
		"source_nat":   false,
		"backup":       backup,
		"monitoring": map[string]any{
			"configured": monConfigured,
			"status":     "SKIP",
		},
	}
}

func profileDigest(p *profile.Profile) string {
	b, _ := manifest.CanonicalJSON(p.Raw)
	if len(b) == 0 {
		b, _ = manifest.CanonicalJSON(p)
	}
	return manifest.Digest(b)
}

// PeerParameters generates the site-perspective handoff JSON payload.
func PeerParameters(p *profile.Profile, siteID, template string) (map[string]any, error) {
	var site *profile.Site
	for i := range p.Sites {
		if p.Sites[i].ID == siteID {
			site = &p.Sites[i]
			break
		}
	}
	if site == nil {
		return nil, &profile.ProfileError{Detail: "The requested site ID does not exist in the selected profile."}
	}

	backup := buildBackupInfo(p, siteID)
	if s, _ := backup["status"].(string); s == "SKIP" {
		return map[string]any{
			"status":     "SKIP",
			"delivery":   map[string]any{"classification": "NOT_APPLYABLE_CONFIG"},
			"detail":     "Handoff withheld until both sites have complete backup parameters.",
			"backup":     backup,
			"acceptance": map[string]any{"status": "SKIP"},
		}, nil
	}

	conns := buildConnections(p)
	var conn map[string]any
	for _, c := range conns {
		if c["site_id"].(string) == siteID {
			conn = c
			break
		}
	}
	if template == "" || template == "auto" {
		if strings.EqualFold(site.Firewall.Vendor, "hillstone") {
			template = "hillstone"
		} else {
			template = "generic"
		}
	}

	remoteSet := make(map[string]struct{})
	for _, rule := range profile.AuthorizedPairs(p) {
		if rule.SourceSiteID == siteID {
			remoteSet[rule.TargetSiteID] = struct{}{}
		}
	}
	remoteIDs := make([]string, 0, len(remoteSet))
	for id := range remoteSet {
		remoteIDs = append(remoteIDs, id)
	}
	sort.Strings(remoteIDs)

	localCIDRs := conn["peer_local_ts"].([]string)
	remoteCIDRs := conn["peer_remote_ts"].([]string)
	selectorMode := conn["selector_mode"].(string)
	localTS := localCIDRs
	remoteTS := remoteCIDRs
	if selectorMode == "route_based" {
		localTS = []string{"0.0.0.0/0"}
		remoteTS = []string{"0.0.0.0/0"}
	}

	peer := conn["peer"].(map[string]any)
	hub := conn["hub"].(map[string]any)

	var primaryUplinks []profile.Uplink
	for _, u := range site.Uplinks {
		if u.PublicEndpoint == site.PublicEndpoint {
			primaryUplinks = append(primaryUplinks, u)
		}
	}

	return map[string]any{
		"status":         "PASS",
		"format_version": "2.0",
		"template":       template,
		"delivery": map[string]any{
			"classification": "NOT_APPLYABLE_CONFIG",
			"profile_sha256": profileDigest(p),
			"revision_utc":   nil,
			"signoff": map[string]any{
				"site_admin":        nil,
				"remote_site_admin": nil,
				"hub_owner":         nil,
				"backup_owner":      nil,
			},
		},
		"event":    p.Event,
		"site":     site,
		"firewall": site.Firewall,
		"uplinks":  site.Uplinks,
		"local": map[string]any{
			"id":              peer["id"],
			"public_endpoint": peer["public_endpoint"],
			"ike_identity":    peer["ike_identity"],
			"id_on_wire":      resolveIdentity(peer["ike_identity"].(string)),
		},
		"remote": map[string]any{
			"id":              hub["id"],
			"public_endpoint": hub["public_endpoint"],
			"ike_identity":    hub["ike_identity"],
			"id_on_wire":      resolveIdentity(hub["ike_identity"].(string)),
		},
		"outer": map[string]any{
			"site_wan_peer_host_route":           p.Hub.PublicEndpoint + "/32",
			"site_primary_uplinks":               primaryUplinks,
			"hub_egress":                         conn["outer_path"],
			"hub_bind_source":                    conn["hub_source"],
			"hub_wan_peer_host_route":            site.PublicEndpoint + "/32",
			"hub_xfrm_if_id":                     conn["xfrm_if_id"],
			"ike_udp_ports":                      []int{500, 4500},
			"allow_native_esp_only_if_required": true,
			"status":                             "SKIP",
		},
		"ike":           conn["ike"],
		"child":         conn["child"],
		"selector_mode": selectorMode,
		"local_ts":      localTS,
		"remote_ts":     remoteTS,
		"allowed_traffic": map[string]any{
			"remote_site_id":  strings.Join(remoteIDs, ", "),
			"remote_site_ids": remoteIDs,
			"local_cidrs":     localCIDRs,
			"remote_cidrs":    remoteCIDRs,
			"direction":       "bidirectional",
		},
		"routing": map[string]any{
			"destination_cidrs":      remoteCIDRs,
			"primary_route_priority": conn["primary_route_priority"],
			"source_nat":             false,
			"zone_policy": []map[string]any{
				{"from_zone": "LAN", "to_zone": "VPN", "source": localCIDRs, "destination": remoteCIDRs},
				{"from_zone": "VPN", "to_zone": "LAN", "source": remoteCIDRs, "destination": localCIDRs},
			},
			"nat_exemption": "Exempt both directions before public SNAT; verify original sources.",
		},
		"backup": backup,
		"acceptance": map[string]any{
			"status":    "SKIP",
			"ike_child": "SKIP",
			"data_path": "SKIP",
		},
	}, nil
}

// RenderPeerMarkdown renders the human-readable Hillstone/generic Markdown handoff sheet.
func RenderPeerMarkdown(data map[string]any) string {
	if data["status"] == "SKIP" {
		var b strings.Builder
		b.WriteString("# 外部备网关交接暂停\n\n**NOT_APPLYABLE_CONFIG**\n\n**SKIP/INCOMPLETE**。补齐双站资料后再导出对接参数单。\n")
		return b.String()
	}
	template, _ := data["template"].(string)
	title := "厂商中立"
	if template == "hillstone" {
		title = "山石 Hillstone / StoneOS"
	}
	mode, _ := data["selector_mode"].(string)
	site := data["site"].(*profile.Site)
	local := data["local"].(map[string]any)
	remote := data["remote"].(map[string]any)
	ike := data["ike"].(map[string]any)
	child := data["child"].(map[string]any)
	delivery := data["delivery"].(map[string]any)
	localTS := data["local_ts"].([]string)
	remoteTS := data["remote_ts"].([]string)

	var b strings.Builder
	fmt.Fprintf(&b, "# %s IPsec 对接参数单\n\n", title)
	b.WriteString("PASS 表示离线参数单已生成。现场验收为 SKIP。\n\n")
	if template == "hillstone" {
		switch mode {
		case "route_based":
			b.WriteString("当前为 **山石路由型模式（route_based）**：Phase 2 代理 ID 使用 `0.0.0.0/0 <-> 0.0.0.0/0` 并绑定 `tunnel` 接口，通过精确静态路由 + 安全策略（LAN <-> VPN）+ NAT 豁免严格限制仅授权网段互通。\n\n")
		case "per_pair":
			b.WriteString("当前为 **多 CHILD 策略模式（per_pair）**：Hub 侧已按每对 `(local_cidr, remote_cidr)` 拆分为独立 CHILD SA，请在山石侧逐对配置镜像 Proxy ID。\n\n")
		default:
			b.WriteString("当前为 **精确选择器模式（exact）**：需核实设备能否在单个 CHILD SA 内协商列出的全部 CIDR；若不支持单 CHILD 多网段，请切换为 `route_based` 或 `per_pair`。\n\n")
		}
	}
	fmt.Fprintf(&b, "## 对接对象\n\n| 参数 | 值 |\n| --- | --- |\n")
	fmt.Fprintf(&b, "| 本端站点 ID | `%s` |\n", html.EscapeString(site.ID))
	fmt.Fprintf(&b, "| 本端站点名称 | `%s` |\n", html.EscapeString(site.DisplayName))
	fmt.Fprintf(&b, "| 用途 | `%s` |\n", delivery["classification"])
	fmt.Fprintf(&b, "| Profile SHA-256 | `%s` |\n\n", delivery["profile_sha256"])

	fmt.Fprintf(&b, "## IKE 网关与提议（阶段 1）\n\n| 参数 | 值 |\n| --- | --- |\n")
	fmt.Fprintf(&b, "| 本端公网地址 | `%s` |\n", local["public_endpoint"])
	fmt.Fprintf(&b, "| 远端 Hub 公网地址 | `%s` |\n", remote["public_endpoint"])
	fmt.Fprintf(&b, "| 本端 IKE ID | `%s` |\n", local["ike_identity"])
	fmt.Fprintf(&b, "| 远端 IKE ID | `%s` |\n", remote["ike_identity"])
	fmt.Fprintf(&b, "| 版本 / 认证 | `IKEv2 / PSK` |\n")
	fmt.Fprintf(&b, "| PSK | `%s` |\n", ike["psk"])
	fmt.Fprintf(&b, "| 提议 | `%s` |\n", ike["proposal"])
	fmt.Fprintf(&b, "| 生存期 / DPD | `%vs / %vs` |\n\n", ike["lifetime_seconds"], ike["dpd_delay_seconds"])

	fmt.Fprintf(&b, "## IPsec 隧道与提议（阶段 2）\n\n| 参数 | 值 |\n| --- | --- |\n")
	fmt.Fprintf(&b, "| 提议 | `%s` |\n", child["proposal"])
	fmt.Fprintf(&b, "| 生存期 | `%vs` |\n", child["lifetime_seconds"])
	fmt.Fprintf(&b, "| 本端 Traffic Selectors | `%s` |\n", strings.Join(localTS, ", "))
	fmt.Fprintf(&b, "| 远端 Traffic Selectors | `%s` |\n\n", strings.Join(remoteTS, ", "))
	return b.String()
}

func tencentEncryName(enc string) string {
	switch enc {
	case "aes256":
		return "AES-CBC-256"
	case "aes192":
		return "AES-CBC-192"
	case "aes128":
		return "AES-CBC-128"
	case "aes256gcm16":
		return "AES-GCM-256"
	case "aes192gcm16":
		return "AES-GCM-192"
	case "aes128gcm16":
		return "AES-GCM-128"
	default:
		return strings.ToUpper(enc)
	}
}

func tencentHashName(h string) string {
	switch h {
	case "":
		return "AEAD"
	case "sha256", "prfsha256":
		return "SHA256"
	case "sha384", "prfsha384":
		return "SHA384"
	case "sha512", "prfsha512":
		return "SHA512"
	default:
		return strings.ToUpper(h)
	}
}

func tencentDHGroup(g string) string {
	switch g {
	case "modp2048":
		return "GROUP14"
	case "modp3072":
		return "GROUP15"
	case "modp4096":
		return "GROUP16"
	case "modp6144":
		return "GROUP17"
	case "modp8192":
		return "GROUP18"
	case "ecp256":
		return "GROUP19"
	case "ecp384":
		return "GROUP20"
	case "ecp521":
		return "GROUP21"
	default:
		return strings.ToUpper(g)
	}
}

func tencentIdentityType(w wireIdentity) string {
	switch w.Type {
	case "ID_IPV4_ADDR":
		return "ADDRESS"
	case "ID_FQDN":
		return "FQDN"
	case "ID_RFC822_ADDR":
		return "USER_FQDN"
	default:
		return w.Type
	}
}

// RenderTencentJSON generates a concise Tencent-Cloud-VPN-Gateway-style JSON handoff
// for external firewall engineers. Pass plaintextPSK="" for the safe redacted default.
func RenderTencentJSON(p *profile.Profile, siteID string, plaintextPSK string) (map[string]any, error) {
	params, err := PeerParameters(p, siteID, "auto")
	if err != nil {
		return nil, err
	}
	if params["status"] == "SKIP" {
		return params, nil
	}

	local := params["local"].(map[string]any)
	remote := params["remote"].(map[string]any)
	ike := params["ike"].(map[string]any)
	child := params["child"].(map[string]any)
	delivery := params["delivery"].(map[string]any)
	allowed := params["allowed_traffic"].(map[string]any)
	routing := params["routing"].(map[string]any)
	localWire := local["id_on_wire"].(wireIdentity)
	remoteWire := remote["id_on_wire"].(wireIdentity)

	ikeAlg := parseProposal(ike["proposal"].(string), true)
	espAlg := parseProposal(child["proposal"].(string), false)

	localTS := params["local_ts"].([]string)
	remoteTS := params["remote_ts"].([]string)
	spd := make([]map[string]any, 0, len(localTS))
	for _, lc := range localTS {
		spd = append(spd, map[string]any{
			"LocalCidrBlock":  lc,
			"RemoteCidrBlock": slices.Clone(remoteTS),
		})
	}

	pskOut := PSKPlaceholder
	pskRedacted := true
	if plaintextPSK != "" {
		pskOut = plaintextPSK
		pskRedacted = false
	}

	return map[string]any{
		"Meta": map[string]any{
			"Classification": "PEER_HANDOFF_PARAMETERS",
			"EventId":        p.Event.ID,
			"EventName":      p.Event.Name,
			"LocalSiteId":    siteID,
			"RemoteHubId":    p.Hub.ID,
			"SelectorMode":   params["selector_mode"],
			"ProfileSha256":  delivery["profile_sha256"],
			"PskRedacted":    pskRedacted,
		},
		"IKEOptionsSpecification": map[string]any{
			"IKEVersion":           "IKEV2",
			"PropoEncryAlgorithm":  tencentEncryName(ikeAlg.Encryption),
			"PropoAuthenAlgorithm": tencentHashName(ikeAlg.Integrity),
			"PrfAlgorithm":         "PRF-HMAC-" + tencentHashName(ikeAlg.PRF),
			"DhGroupName":          tencentDHGroup(ikeAlg.Group),
			"IKESaLifetimeSeconds": ike["lifetime_seconds"],
			"DpdDelaySeconds":      ike["dpd_delay_seconds"],
			"LocalIdentityType":    tencentIdentityType(localWire),
			"LocalIdentity":        localWire.Value,
			"RemoteIdentityType":   tencentIdentityType(remoteWire),
			"RemoteIdentity":       remoteWire.Value,
			"LocalAddress":         local["public_endpoint"],
			"RemoteAddress":        remote["public_endpoint"],
		},
		"IPSECOptionsSpecification": map[string]any{
			"Mode":                   "TUNNEL",
			"Protocol":               "ESP",
			"EncryptAlgorithm":       tencentEncryName(espAlg.Encryption),
			"IntegrityAlgorithm":     tencentHashName(espAlg.Integrity),
			"PfsDhGroup":             tencentDHGroup(espAlg.Group),
			"IPSECSaLifetimeSeconds": child["lifetime_seconds"],
		},
		"SecurityPolicyDatabaseSet": spd,
		"AuthorizedTrafficAndRouting": map[string]any{
			"LocalLanCidrs":        allowed["local_cidrs"],
			"RemoteLanCidrs":       allowed["remote_cidrs"],
			"RoutePriority":        routing["primary_route_priority"],
			"NatExemptionRequired": true,
			"SourceNat":            false,
		},
		"PreShareKey": pskOut,
	}, nil
}

// RenderVendorDraft produces an annotated NOT_APPLYABLE_CONFIG reference CLI snippet
// for partner engineers (supported vendors: "hillstone", "strongswan").
func RenderVendorDraft(p *profile.Profile, siteID, vendor, plaintextPSK string) (string, error) {
	tc, err := RenderTencentJSON(p, siteID, plaintextPSK)
	if err != nil {
		return "", err
	}
	if s, _ := tc["status"].(string); s == "SKIP" {
		return "# NOT_APPLYABLE_CONFIG: SKIP/INCOMPLETE backup parameters\n", nil
	}
	meta := tc["Meta"].(map[string]any)
	ike := tc["IKEOptionsSpecification"].(map[string]any)
	ipsec := tc["IPSECOptionsSpecification"].(map[string]any)
	auth := tc["AuthorizedTrafficAndRouting"].(map[string]any)
	psk := tc["PreShareKey"].(string)
	remoteLANs := auth["RemoteLanCidrs"].([]string)
	localLANs := auth["LocalLanCidrs"].([]string)

	switch strings.ToLower(vendor) {
	case "hillstone", "stoneos":
		var b strings.Builder
		b.WriteString("! =====================================================================\n")
		b.WriteString("! NOT_APPLYABLE_CONFIG — Hillstone StoneOS Reference Draft\n")
		fmt.Fprintf(&b, "! Event: %s | Site: %s | Mode: %s\n", meta["EventId"], siteID, meta["SelectorMode"])
		b.WriteString("! Replace <WAN_IF>, <TUNNEL_IF>, <VR>, <LAN_ZONE>, <VPN_ZONE> on site.\n")
		b.WriteString("! =====================================================================\n\n")
		fmt.Fprintf(&b, "isakmp proposal prop-ike-%s\n", siteID)
		fmt.Fprintf(&b, "  encryption %s\n", strings.ToLower(strings.ReplaceAll(ike["PropoEncryAlgorithm"].(string), "AES-CBC-", "aes-")))
		fmt.Fprintf(&b, "  hash %s\n", strings.ToLower(ike["PropoAuthenAlgorithm"].(string)))
		fmt.Fprintf(&b, "  group %s\n", strings.TrimPrefix(strings.ToLower(ike["DhGroupName"].(string)), "group"))
		fmt.Fprintf(&b, "  lifetime %v\nexit\n\n", ike["IKESaLifetimeSeconds"])
		fmt.Fprintf(&b, "isakmp peer peer-%s\n", meta["RemoteHubId"])
		b.WriteString("  version 2\n")
		fmt.Fprintf(&b, "  interface <WAN_IF>\n  peer %s\n", ike["RemoteAddress"])
		fmt.Fprintf(&b, "  local-id %s %s\n", strings.ToLower(ike["LocalIdentityType"].(string)), ike["LocalIdentity"])
		fmt.Fprintf(&b, "  peer-id %s %s\n", strings.ToLower(ike["RemoteIdentityType"].(string)), ike["RemoteIdentity"])
		fmt.Fprintf(&b, "  pre-share %s\n", psk)
		fmt.Fprintf(&b, "  isakmp-proposal prop-ike-%s\n", siteID)
		fmt.Fprintf(&b, "  dpd interval %v retry 3\nexit\n\n", ike["DpdDelaySeconds"])
		fmt.Fprintf(&b, "tunnel ipsec tun-%s auto\n", meta["RemoteHubId"])
		fmt.Fprintf(&b, "  isakmp-peer peer-%s\n", meta["RemoteHubId"])
		fmt.Fprintf(&b, "  ipsec-proposal esp-%s-%s-pfs-%s\n",
			strings.ToLower(ipsec["EncryptAlgorithm"].(string)),
			strings.ToLower(ipsec["IntegrityAlgorithm"].(string)),
			strings.ToLower(ipsec["PfsDhGroup"].(string)))
		b.WriteString("exit\n\n")
		b.WriteString("! Static routes via <TUNNEL_IF> (route-based recommended):\n")
		for _, r := range remoteLANs {
			fmt.Fprintf(&b, "ip route %s interface <TUNNEL_IF> distance %v\n", r, auth["RoutePriority"])
		}
		fmt.Fprintf(&b, "\n! Ensure NO-NAT & bidirectional security policy for LAN [%s] <-> Remote [%s]\n",
			strings.Join(localLANs, ", "), strings.Join(remoteLANs, ", "))
		return b.String(), nil

	case "strongswan", "swanctl":
		var b strings.Builder
		b.WriteString("# NOT_APPLYABLE_CONFIG — strongSwan swanctl.conf Reference Draft\n")
		fmt.Fprintf(&b, "connections {\n  to-%s {\n    version = 2\n", meta["RemoteHubId"])
		fmt.Fprintf(&b, "    local_addrs = %s\n    remote_addrs = %s\n", ike["LocalAddress"], ike["RemoteAddress"])
		fmt.Fprintf(&b, "    dpd_delay = %vs\n    rekey_time = %vs\n    encap = yes\n", ike["DpdDelaySeconds"], ike["IKESaLifetimeSeconds"])
		fmt.Fprintf(&b, "    local { auth = psk; id = %s }\n    remote { auth = psk; id = %s }\n", ike["LocalIdentity"], ike["RemoteIdentity"])
		fmt.Fprintf(&b, "    children {\n      net {\n        local_ts = %s\n        remote_ts = %s\n        life_time = %vs\n        start_action = start\n      }\n    }\n  }\n}\n",
			strings.Join(localLANs, ", "), strings.Join(remoteLANs, ", "), ipsec["IPSECSaLifetimeSeconds"])
		fmt.Fprintf(&b, "secrets {\n  ike-hub {\n    id-1 = %s\n    id-2 = %s\n    secret = %q\n  }\n}\n",
			ike["LocalIdentity"], ike["RemoteIdentity"], psk)
		return b.String(), nil

	default:
		return "", fmt.Errorf("unsupported vendor draft %q (use hillstone or strongswan)", vendor)
	}
}
