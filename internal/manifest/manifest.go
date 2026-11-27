package manifest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"

	"github.com/yikkrrtykj/event-ipsec-hub/internal/profile"
)

const (
	Table           = "ipsecvpn"
	RouteProtocol   = "242"
	XFRMMetric      = 40
	BlackholeMetric = 32760
	HubStartAction  = "none"
	HubDPDAction    = "clear"
	DefaultIKEProp  = "aes256-sha256-prfsha256-modp2048"
	DefaultESPProp  = "aes256-sha256-modp2048"
)

// Digest computes lowercase hex SHA-256 of raw bytes.
func Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// CanonicalJSON serializes any JSON-compatible value deterministically with all object keys
// recursively sorted lexicographically, including nested Go structs.
func CanonicalJSON(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var generic any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&generic); err != nil {
		return nil, err
	}
	return json.Marshal(generic)
}

func ChildRekeySeconds(lifetime int) int {
	v := lifetime * 9 / 10
	if v < 1 {
		return 1
	}
	return v
}

type ChildSpec struct {
	Name     string
	LocalTS  []string
	RemoteTS []string
}

type Link struct {
	SiteID         string   `json:"site_id"`
	IfID           uint32   `json:"if_id"`
	WAN            string   `json:"wan"`
	Source         string   `json:"source"`
	Gateway        *string  `json:"gateway"`
	Peer           string   `json:"peer"`
	LocalID        string   `json:"local_id"`
	RemoteID       string   `json:"remote_id"`
	LocalTS        []string `json:"local_ts"`
	RemoteTS       []string `json:"remote_ts"`
	IKEProposal    string   `json:"ike_proposal"`
	ESPProposal    string   `json:"esp_proposal"`
	IKELifetime    int      `json:"ike_lifetime"`
	ChildLifetime  int      `json:"child_lifetime"`
	DPDDelay       int      `json:"dpd_delay"`
	RoutePriority  int      `json:"route_priority"`
	SelectorMode   string   `json:"selector_mode"`
	StartAction    string   `json:"start_action"`
	DPDAction      string   `json:"dpd_action"`
	CloseAction    string   `json:"close_action"`
	RouteTable     *int     `json:"route_table"`
	PolicyPriority  int      `json:"policy_priority"`
	LinkID          string   `json:"link_id"`
	ISPLabel        string   `json:"isp_label"`
	TunnelLocalCIDR string   `json:"tunnel_local_cidr,omitempty"`
}

func (l Link) TunnelLocalIP() string {
	if l.TunnelLocalCIDR == "" {
		return ""
	}
	if p, err := netip.ParsePrefix(l.TunnelLocalCIDR); err == nil && p.Addr().Is4() {
		return p.Addr().String()
	}
	return ""
}

func (l Link) TunnelSubnet() string {
	if l.TunnelLocalCIDR == "" {
		return ""
	}
	if p, err := netip.ParsePrefix(l.TunnelLocalCIDR); err == nil && p.Addr().Is4() {
		return p.Masked().String()
	}
	return ""
}

func (l Link) KeyID() string {
	if l.LinkID != "" {
		return l.LinkID
	}
	return l.SiteID
}

func (l Link) Name() string {
	return fmt.Sprintf("ivp%08x", l.IfID)
}

func (l Link) Child() string {
	return l.Name() + "-child"
}

func (l Link) ChildSpecs() []ChildSpec {
	switch l.SelectorMode {
	case "route_based":
		return []ChildSpec{{
			Name:     l.Child(),
			LocalTS:  []string{"0.0.0.0/0"},
			RemoteTS: []string{"0.0.0.0/0"},
		}}
	case "per_pair":
		specs := make([]ChildSpec, 0, len(l.LocalTS)*len(l.RemoteTS))
		idx := 0
		for _, lc := range l.LocalTS {
			for _, rc := range l.RemoteTS {
				specs = append(specs, ChildSpec{
					Name:     fmt.Sprintf("%s-%d", l.Child(), idx),
					LocalTS:  []string{lc},
					RemoteTS: []string{rc},
				})
				idx++
			}
		}
		return specs
	default:
		return []ChildSpec{{
			Name:     l.Child(),
			LocalTS:  slices.Clone(l.LocalTS),
			RemoteTS: slices.Clone(l.RemoteTS),
		}}
	}
}

func (l Link) Equal(other Link) bool {
	a, _ := CanonicalJSON(l)
	b, _ := CanonicalJSON(other)
	return string(a) == string(b)
}

type ForwardRule struct {
	SourceSiteID     string
	TargetSiteID     string
	SourceCIDRs      []string
	DestinationCIDRs []string
}

type ResolvedForwardRule struct {
	Source           Link
	Target           Link
	SourceCIDRs      []string
	DestinationCIDRs []string
}

type DeploymentManifest struct {
	EventID      string
	Links        []Link
	ForwardRules []ForwardRule
}

func (m *DeploymentManifest) ResolvedForwardRules() []ResolvedForwardRule {
	if m == nil {
		return nil
	}
	bySite := make(map[string][]Link)
	for _, l := range m.Links {
		bySite[l.SiteID] = append(bySite[l.SiteID], l)
	}
	if len(m.ForwardRules) > 0 {
		seen := make(map[string]struct{})
		var resolved []ResolvedForwardRule
		for _, r := range m.ForwardRules {
			key := r.SourceSiteID + "|" + r.TargetSiteID + "|" + strings.Join(r.SourceCIDRs, ",") + "|" + strings.Join(r.DestinationCIDRs, ",")
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			for _, sLink := range bySite[r.SourceSiteID] {
				for _, dLink := range bySite[r.TargetSiteID] {
					resolved = append(resolved, ResolvedForwardRule{
						Source:           sLink,
						Target:           dLink,
						SourceCIDRs:      slices.Clone(r.SourceCIDRs),
						DestinationCIDRs: slices.Clone(r.DestinationCIDRs),
					})
				}
			}
		}
		return resolved
	}
	if len(m.Links) == 2 {
		a, b := m.Links[0], m.Links[1]
		return []ResolvedForwardRule{
			{Source: a, Target: b, SourceCIDRs: slices.Clone(a.RemoteTS), DestinationCIDRs: slices.Clone(b.RemoteTS)},
			{Source: b, Target: a, SourceCIDRs: slices.Clone(b.RemoteTS), DestinationCIDRs: slices.Clone(a.RemoteTS)},
		}
	}
	return nil
}

func (m *DeploymentManifest) Networks() []string {
	if m == nil {
		return nil
	}
	var nets []string
	for _, l := range m.Links {
		nets = append(nets, l.RemoteTS...)
	}
	sort.Strings(nets)
	return nets
}

func (m *DeploymentManifest) Resources() map[string]any {
	links := make([]map[string]any, 0, len(m.Links))
	routes := make([]map[string]any, 0)
	outerRoutes := make([]map[string]any, 0, len(m.Links))

	type symRow struct {
		table    int
		wan      string
		source   string
		gateway  *string
		priority int
	}
	symByTable := make(map[int]symRow)

	for _, l := range m.Links {
		row := map[string]any{
			"site_id":         l.SiteID,
			"if_id":           l.IfID,
			"wan":             l.WAN,
			"source":          l.Source,
			"gateway":         l.Gateway,
			"peer":            l.Peer,
			"local_id":        l.LocalID,
			"remote_id":       l.RemoteID,
			"local_ts":        l.LocalTS,
			"remote_ts":       l.RemoteTS,
			"ike_proposal":    l.IKEProposal,
			"esp_proposal":    l.ESPProposal,
			"ike_lifetime":    l.IKELifetime,
			"child_lifetime":  l.ChildLifetime,
			"dpd_delay":       l.DPDDelay,
			"route_priority":  l.RoutePriority,
			"selector_mode":   l.SelectorMode,
			"start_action":    l.StartAction,
			"dpd_action":      l.DPDAction,
			"close_action":    l.CloseAction,
			"route_table":     l.RouteTable,
			"policy_priority": l.PolicyPriority,
			"link_id":         l.LinkID,
			"isp_label":       l.ISPLabel,
			"xfrm_interface":  l.Name(),
			"child":           l.Child(),
		}
		links = append(links, row)
		for _, cidr := range l.RemoteTS {
			routes = append(routes, map[string]any{
				"destination": cidr,
				"interface":   l.Name(),
				"table":       "main",
				"metric":      l.RoutePriority,
				"fallback": map[string]any{
					"type":   "blackhole",
					"metric": BlackholeMetric,
				},
			})
		}
		outerRoutes = append(outerRoutes, map[string]any{
			"destination": l.Peer + "/32",
			"interface":   l.WAN,
			"gateway":     l.Gateway,
			"source_ip":   l.Source,
			"route_table": l.RouteTable,
		})
		if l.RouteTable != nil {
			symByTable[*l.RouteTable] = symRow{
				table:    *l.RouteTable,
				wan:      l.WAN,
				source:   l.Source,
				gateway:  l.Gateway,
				priority: l.PolicyPriority,
			}
		}
	}

	tables := make([]int, 0, len(symByTable))
	for t := range symByTable {
		tables = append(tables, t)
	}
	sort.Ints(tables)
	symRules := make([]map[string]any, 0, len(tables))
	for _, t := range tables {
		s := symByTable[t]
		symRules = append(symRules, map[string]any{
			"from_source": s.source + "/32",
			"table":       s.table,
			"priority":    s.priority,
			"interface":   s.wan,
			"gateway":     s.gateway,
		})
	}

	resolvedACL := m.ResolvedForwardRules()
	forwardACL := make([]map[string]any, 0, len(resolvedACL))
	for _, r := range resolvedACL {
		forwardACL = append(forwardACL, map[string]any{
			"iif":               r.Source.Name(),
			"oif":               r.Target.Name(),
			"source_cidrs":      r.SourceCIDRs,
			"destination_cidrs": r.DestinationCIDRs,
		})
	}

	return map[string]any{
		"event_id":               m.EventID,
		"links":                  links,
		"routes":                 routes,
		"outer_routes":           outerRoutes,
		"symmetric_return_rules": symRules,
		"forward_acl":            forwardACL,
		"source_nat":             false,
	}
}

// BuildManifest derives a deterministic secret-free DeploymentManifest from a validated Profile.
func BuildManifest(p *profile.Profile) (*DeploymentManifest, error) {
	if p == nil {
		return nil, nil
	}
	sites := make(map[string]profile.Site, len(p.Sites))
	for _, s := range p.Sites {
		sites[s.ID] = s
	}
	authLANs := profile.AuthorizedLANs(p)
	hubID := p.Hub.EffectiveIKEIdentity()

	sharedIKE := DefaultIKEProp
	sharedESP := DefaultESPProp
	sharedIKELife := 28800
	sharedChildLife := 3600
	sharedDPDDelay := 30
	sharedStart := HubStartAction
	sharedDPD := HubDPDAction
	sharedClose := "none"
	if p.Security != nil {
		if p.Security.IKEProposal != "" {
			sharedIKE = p.Security.IKEProposal
		}
		if p.Security.ESPProposal != "" {
			sharedESP = p.Security.ESPProposal
		}
		if p.Security.IKELifetimeSeconds != nil {
			sharedIKELife = *p.Security.IKELifetimeSeconds
		}
		if p.Security.ChildLifetimeSeconds != nil {
			sharedChildLife = *p.Security.ChildLifetimeSeconds
		}
		if p.Security.DPDDelaySeconds != nil {
			sharedDPDDelay = *p.Security.DPDDelaySeconds
		}
		if p.Security.StartAction != "" {
			sharedStart = p.Security.StartAction
		}
		if p.Security.DPDAction != "" {
			sharedDPD = p.Security.DPDAction
		}
		if p.Security.CloseAction != "" {
			sharedClose = p.Security.CloseAction
		}
	}

	links := make([]Link, 0, len(p.SiteLinks))
	for _, sl := range p.SiteLinks {
		site := sites[sl.SiteID]
		peerAddr := site.PublicEndpoint
		peerIKEID := site.IKEIdentity
		if sl.UplinkID != "" {
			for _, u := range site.Uplinks {
				if u.ID == sl.UplinkID {
					peerAddr = u.PublicEndpoint
					if u.IKEIdentity != "" {
						peerIKEID = u.IKEIdentity
					} else {
						peerIKEID = u.PublicEndpoint
					}
					break
				}
			}
		}

		hubSource := p.Hub.PublicEndpoint
		if sl.OuterPath.SourceIP != "" {
			hubSource = sl.OuterPath.SourceIP
		}
		var gw *string
		if sl.OuterPath.Gateway != "" {
			v := sl.OuterPath.Gateway
			gw = &v
		}
		routePrio := XFRMMetric
		if sl.RoutePriority != nil {
			routePrio = *sl.RoutePriority
		}
		policyPrio := 1000
		if sl.OuterPath.PolicyPriority != nil {
			policyPrio = *sl.OuterPath.PolicyPriority
		}
		selectorMode := sl.SelectorMode
		if selectorMode == "" {
			selectorMode = "exact"
		}
		ikeProp := sl.IKEProposal
		if ikeProp == "" {
			ikeProp = sharedIKE
		}
		espProp := sl.ESPProposal
		if espProp == "" {
			espProp = sharedESP
		}
		startAction := sl.StartAction
		if startAction == "" {
			startAction = sharedStart
		}
		dpdAction := sl.DPDAction
		if dpdAction == "" {
			dpdAction = sharedDPD
		}
		closeAction := sl.CloseAction
		if closeAction == "" {
			closeAction = sharedClose
		}

		links = append(links, Link{
			SiteID:         site.ID,
			IfID:           sl.IfID,
			WAN:            sl.OuterPath.Interface,
			Source:         hubSource,
			Gateway:        gw,
			Peer:           peerAddr,
			LocalID:        hubID,
			RemoteID:       peerIKEID,
			LocalTS:        profile.AuthorizedRemoteLANs(p, site.ID),
			RemoteTS:       slices.Clone(authLANs[site.ID]),
			IKEProposal:    ikeProp,
			ESPProposal:    espProp,
			IKELifetime:    sharedIKELife,
			ChildLifetime:  sharedChildLife,
			DPDDelay:       sharedDPDDelay,
			RoutePriority:  routePrio,
			SelectorMode:   selectorMode,
			StartAction:    startAction,
			DPDAction:      dpdAction,
			CloseAction:    closeAction,
			RouteTable:     sl.OuterPath.RouteTable,
			PolicyPriority:  policyPrio,
			LinkID:          sl.KeyID(),
			ISPLabel:        sl.OuterPath.ISPLabel,
			TunnelLocalCIDR: sl.TunnelLocalCIDR,
		})
	}

	sort.Slice(links, func(i, j int) bool {
		if links[i].SiteID != links[j].SiteID {
			return links[i].SiteID < links[j].SiteID
		}
		if links[i].RoutePriority != links[j].RoutePriority {
			return links[i].RoutePriority < links[j].RoutePriority
		}
		return links[i].IfID < links[j].IfID
	})

	pairs := profile.AuthorizedPairs(p)
	rules := make([]ForwardRule, 0, len(pairs))
	seen := make(map[string]struct{}, len(pairs))
	for _, r := range pairs {
		key := r.SourceSiteID + "|" + r.TargetSiteID + "|" + strings.Join(r.SourceCIDRs, ",") + "|" + strings.Join(r.TargetCIDRs, ",")
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		rules = append(rules, ForwardRule{
			SourceSiteID:     r.SourceSiteID,
			TargetSiteID:     r.TargetSiteID,
			SourceCIDRs:      slices.Clone(r.SourceCIDRs),
			DestinationCIDRs: slices.Clone(r.TargetCIDRs),
		})
	}

	return &DeploymentManifest{
		EventID:      p.Event.ID,
		Links:        links,
		ForwardRules: rules,
	}, nil
}

// ConnectionSettings returns the strongSwan VICI / swanctl settings map for a link.
func ConnectionSettings(l Link) map[string]any {
	children := make(map[string]any)
	for _, spec := range l.ChildSpecs() {
		children[spec.Name] = map[string]any{
			"mode":          "tunnel",
			"local_ts":      spec.LocalTS,
			"remote_ts":     spec.RemoteTS,
			"esp_proposals": []string{l.ESPProposal},
			"if_id_in":      fmt.Sprintf("%d", l.IfID),
			"if_id_out":     fmt.Sprintf("%d", l.IfID),
			"life_time":     fmt.Sprintf("%ds", l.ChildLifetime),
			"rekey_time":    fmt.Sprintf("%ds", ChildRekeySeconds(l.ChildLifetime)),
			"start_action":  l.StartAction,
			"dpd_action":    l.DPDAction,
			"close_action":  l.CloseAction,
		}
	}
	return map[string]any{
		"version":      "2",
		"local_addrs":  []string{l.Source},
		"remote_addrs": []string{l.Peer},
		"proposals":    []string{l.IKEProposal},
		"reauth_time":  "0",
		"rekey_time":   fmt.Sprintf("%ds", l.IKELifetime),
		"dpd_delay":    fmt.Sprintf("%ds", l.DPDDelay),
		"mobike":       "no",
		"encap":        "yes",
		"local":        map[string]any{"auth": "psk", "id": l.LocalID},
		"remote":       map[string]any{"auth": "psk", "id": l.RemoteID},
		"children":     children,
	}
}

// SwanctlConfig renders deterministic swanctl.conf syntax matching the VICI connection settings.
func SwanctlConfig(m *DeploymentManifest, keys map[string][]byte) string {
	var b strings.Builder
	b.WriteString("connections {\n")
	if m != nil {
		for _, l := range m.Links {
			fmt.Fprintf(&b, "    %s {\n", l.Name())
			fmt.Fprintf(&b, "        version = 2\n")
			fmt.Fprintf(&b, "        local_addrs = %s\n", l.Source)
			fmt.Fprintf(&b, "        remote_addrs = %s\n", l.Peer)
			fmt.Fprintf(&b, "        proposals = %s\n", l.IKEProposal)
			fmt.Fprintf(&b, "        reauth_time = 0\n")
			fmt.Fprintf(&b, "        rekey_time = %ds\n", l.IKELifetime)
			fmt.Fprintf(&b, "        dpd_delay = %ds\n", l.DPDDelay)
			fmt.Fprintf(&b, "        mobike = no\n")
			fmt.Fprintf(&b, "        encap = yes\n")
			fmt.Fprintf(&b, "        local {\n            auth = psk\n            id = %s\n        }\n", l.LocalID)
			fmt.Fprintf(&b, "        remote {\n            auth = psk\n            id = %s\n        }\n", l.RemoteID)
			b.WriteString("        children {\n")
			for _, spec := range l.ChildSpecs() {
				fmt.Fprintf(&b, "            %s {\n", spec.Name)
				fmt.Fprintf(&b, "                mode = tunnel\n")
				fmt.Fprintf(&b, "                local_ts = %s\n", strings.Join(spec.LocalTS, ", "))
				fmt.Fprintf(&b, "                remote_ts = %s\n", strings.Join(spec.RemoteTS, ", "))
				fmt.Fprintf(&b, "                esp_proposals = %s\n", l.ESPProposal)
				fmt.Fprintf(&b, "                if_id_in = %d\n", l.IfID)
				fmt.Fprintf(&b, "                if_id_out = %d\n", l.IfID)
				fmt.Fprintf(&b, "                life_time = %ds\n", l.ChildLifetime)
				fmt.Fprintf(&b, "                rekey_time = %ds\n", ChildRekeySeconds(l.ChildLifetime))
				fmt.Fprintf(&b, "                start_action = %s\n", l.StartAction)
				fmt.Fprintf(&b, "                dpd_action = %s\n", l.DPDAction)
				fmt.Fprintf(&b, "                close_action = %s\n", l.CloseAction)
				b.WriteString("            }\n")
			}
			b.WriteString("        }\n")
			b.WriteString("    }\n")
		}
	}
	b.WriteString("}\n")
	b.WriteString("secrets {\n")
	if m != nil && keys != nil {
		for _, l := range m.Links {
			if raw, ok := keys[l.KeyID()]; ok {
				fmt.Fprintf(&b, "    ike-%s {\n", l.Name())
				fmt.Fprintf(&b, "        id-1 = %s\n", l.LocalID)
				fmt.Fprintf(&b, "        id-2 = %s\n", l.RemoteID)
				fmt.Fprintf(&b, "        secret = 0x%s\n", hex.EncodeToString(raw))
				b.WriteString("    }\n")
			}
		}
	}
	b.WriteString("}\n")
	return b.String()
}

// NFTConfig renders the project-exclusive nftables table (normal or fail-closed transition guard).
func NFTConfig(m *DeploymentManifest, token string, guarded []string, interfaces []string, handshake *DeploymentManifest) string {
	nameSet := make(map[string]struct{})
	for _, n := range interfaces {
		nameSet[n] = struct{}{}
	}
	netSet := make(map[string]struct{})
	for _, c := range guarded {
		netSet[c] = struct{}{}
	}
	var links []Link
	if m != nil {
		links = m.Links
		for _, l := range links {
			nameSet[l.Name()] = struct{}{}
			for _, c := range l.RemoteTS {
				netSet[c] = struct{}{}
			}
		}
	}
	names := make([]string, 0, len(nameSet))
	for n := range nameSet {
		names = append(names, n)
	}
	sort.Strings(names)
	networks := make([]string, 0, len(netSet))
	for c := range netSet {
		networks = append(networks, c)
	}
	sort.Strings(networks)

	var b strings.Builder
	fmt.Fprintf(&b, "table ip %s {\n", Table)
	fmt.Fprintf(&b, "    chain owner_%s {\n    }\n", token)
	b.WriteString("    chain forward {\n")
	b.WriteString("        type filter hook forward priority -5; policy accept;\n")
	if m != nil && len(links) > 0 {
		quotedNames := make([]string, 0, len(links))
		for _, l := range links {
			quotedNames = append(quotedNames, fmt.Sprintf("%q", l.Name()))
		}
		sort.Strings(quotedNames)
		ifaceSet := strings.Join(quotedNames, ", ")
		fmt.Fprintf(&b, "        iifname { %s } tcp flags syn / syn,rst tcp option maxseg size set 1360\n", ifaceSet)
		fmt.Fprintf(&b, "        oifname { %s } tcp flags syn / syn,rst tcp option maxseg size set 1360\n", ifaceSet)
	}
	if m != nil {
		for _, r := range m.ResolvedForwardRules() {
			fmt.Fprintf(&b, "        iifname %q oifname %q ip saddr { %s } ip daddr { %s } accept\n",
				r.Source.Name(), r.Target.Name(), strings.Join(r.SourceCIDRs, ", "), strings.Join(r.DestinationCIDRs, ", "))
		}
	}
	for _, name := range names {
		fmt.Fprintf(&b, "        iifname %q drop\n", name)
		fmt.Fprintf(&b, "        oifname %q drop\n", name)
	}
	for _, cidr := range networks {
		fmt.Fprintf(&b, "        ip daddr %s drop\n", cidr)
	}
	b.WriteString("    }\n")

	b.WriteString("    chain output {\n")
	b.WriteString("        type filter hook output priority -5; policy accept;\n")
	for _, l := range links {
		fmt.Fprintf(&b, "        oifname %q ip daddr { %s } accept\n", l.Name(), strings.Join(l.RemoteTS, ", "))
		if sub := l.TunnelSubnet(); sub != "" {
			fmt.Fprintf(&b, "        oifname %q ip daddr %s accept\n", l.Name(), sub)
		}
	}
	for _, cidr := range networks {
		fmt.Fprintf(&b, "        ip daddr %s drop\n", cidr)
	}
	b.WriteString("    }\n")

	b.WriteString("    chain input {\n")
	b.WriteString("        type filter hook input priority -5; policy accept;\n")
	handshakeLinks := links
	if handshake != nil {
		handshakeLinks = handshake.Links
	}
	for _, l := range handshakeLinks {
		fmt.Fprintf(&b, "        iifname %q ip saddr %s ip daddr %s udp dport { 500, 4500 } accept\n", l.WAN, l.Peer, l.Source)
		fmt.Fprintf(&b, "        iifname %q ip saddr %s ip daddr %s ip protocol esp accept\n", l.WAN, l.Peer, l.Source)
	}
	for _, l := range links {
		fmt.Fprintf(&b, "        iifname %q ip saddr { %s } ct state established,related accept\n", l.Name(), strings.Join(l.RemoteTS, ", "))
		if sub := l.TunnelSubnet(); sub != "" {
			fmt.Fprintf(&b, "        iifname %q ip saddr %s icmp type { echo-request, echo-reply } accept\n", l.Name(), sub)
		}
	}
	for _, name := range names {
		fmt.Fprintf(&b, "        iifname %q drop\n", name)
	}
	b.WriteString("        udp dport { 500, 4500 } drop\n")
	b.WriteString("        ip protocol esp drop\n")
	b.WriteString("    }\n")
	b.WriteString("}\n")
	return b.String()
}

func ExternalBackup(p *profile.Profile) map[string]any {
	state := profile.EvaluateBackupReadiness(p)
	out := map[string]any{"enabled": state.Enabled}
	if !state.Enabled {
		return out
	}
	out["status"] = "SKIP"
	out["readiness"] = state.Readiness
	if len(state.Missing) > 0 {
		out["missing"] = state.Missing
	}
	out["detail"] = "External backup is managed outside this Hub; no live readiness was evaluated."
	return out
}

// Render produces the offline manifest and secret-free configuration preview.
func Render(p *profile.Profile) (map[string]any, error) {
	m, err := BuildManifest(p)
	if err != nil {
		return nil, err
	}
	swan := SwanctlConfig(m, nil)
	nft := NFTConfig(m, "preview", nil, nil, nil)
	return map[string]any{
		"status":   "PASS",
		"detail":   "Offline rendering completed. Host and tunnel verification are SKIP.",
		"manifest": m.Resources(),
		"files": map[string]any{
			"swanctl.conf": map[string]any{"sha256": Digest([]byte(swan)), "preview": swan},
			"ipsecvpn.nft": map[string]any{"sha256": Digest([]byte(nft)), "preview": nft},
		},
		"permissions":   "root and an explicitly authorized isolated Ubuntu 24.04 VM for writes",
		"startup_order": []string{"fail_closed_guard", "xfrm_and_routes", "vici", "verified_acl"},
		"backup":        ExternalBackup(p),
		"site_to_site":  map[string]any{"status": "SKIP"},
	}, nil
}

// ResourceDiff compares two manifests and reports link additions, removals, updates, and hashes.
func ResourceDiff(before, target *DeploymentManifest) map[string]any {
	prev := make(map[string]Link)
	if before != nil {
		for _, l := range before.Links {
			prev[l.Name()] = l
		}
	}
	next := make(map[string]Link)
	if target != nil {
		for _, l := range target.Links {
			next[l.Name()] = l
		}
	}
	add := []string{}
	remove := []string{}
	update := []string{}
	for name := range next {
		if _, ok := prev[name]; !ok {
			add = append(add, name)
		}
	}
	for name, oldLink := range prev {
		newLink, ok := next[name]
		if !ok {
			remove = append(remove, name)
		} else if !oldLink.Equal(newLink) {
			update = append(update, name)
		}
	}
	sort.Strings(add)
	sort.Strings(remove)
	sort.Strings(update)

	var prevSHA any
	if before != nil {
		b, _ := CanonicalJSON(before.Resources())
		prevSHA = Digest(b)
	}
	var targetSHA any
	if target != nil {
		b, _ := CanonicalJSON(target.Resources())
		targetSHA = Digest(b)
	}
	return map[string]any{
		"add":             add,
		"remove":          remove,
		"update":          update,
		"previous_sha256": prevSHA,
		"target_sha256":   targetSHA,
	}
}
