package sa

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/strongswan/govici/vici"

	"github.com/yikkrrtykj/event-ipsec-hub/internal/host"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/manifest"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/secureio"
)

var dhGroupRE = regexp.MustCompile(`^(modp|ecp)(\d+)$`)

func unowned(detail string) error {
	return secureio.StopWithReason("UNOWNED_SA", detail)
}

func transition(detail string) error {
	return secureio.StopWithReason("SA_TRANSITION", detail)
}

// Identity normalizes strongSwan IKE identities for comparison.
func Identity(v string) string {
	return strings.ToLower(strings.TrimPrefix(v, "@"))
}

func positiveUint(text string, base int) (uint64, error) {
	v, err := strconv.ParseUint(strings.TrimSpace(text), base, 64)
	if err != nil || v == 0 {
		return 0, errors.New("expected positive identifier")
	}
	return v, nil
}

func parseCIDR(val string, allowWildcard bool) (string, error) {
	p, err := netip.ParsePrefix(val)
	if err != nil || !p.Addr().Is4() {
		return "", errors.New("invalid IPv4 CIDR")
	}
	if p.Bits() == 0 && !allowWildcard {
		return "", errors.New("unrestricted selector")
	}
	return p.Masked().String(), nil
}

// MatchProposal validates a VICI IKE or CHILD SA map against an expected strongSwan proposal string.
func MatchProposal(row map[string]any, expected string, isIKE bool) bool {
	parts := strings.Split(expected, "-")
	if len(parts) < 2 {
		return false
	}
	aes := parts[0]
	parts = parts[1:]
	gcm := strings.HasSuffix(aes, "gcm16")
	wanted := map[string]string{
		"encr-alg":     "AES_CBC",
		"encr-keysize": strings.TrimSuffix(strings.TrimPrefix(aes, "aes"), "gcm16"),
	}
	if gcm {
		wanted["encr-alg"] = "AES_GCM_16"
		if _, hasInteg := row["integ-alg"]; hasInteg {
			return false
		}
	} else {
		if len(parts) == 0 {
			return false
		}
		integBits := strings.TrimPrefix(parts[0], "sha")
		parts = parts[1:]
		n, err := strconv.Atoi(integBits)
		if err != nil {
			return false
		}
		wanted["integ-alg"] = fmt.Sprintf("HMAC_SHA2_%s_%d", integBits, n/2)
	}
	if isIKE {
		if len(parts) == 0 {
			return false
		}
		prfBits := strings.TrimPrefix(parts[0], "prfsha")
		parts = parts[1:]
		wanted["prf-alg"] = "PRF_HMAC_SHA2_" + prfBits
	}
	if _, hasDH := row["dh-group"]; isIKE || hasDH {
		if len(parts) == 0 {
			return false
		}
		m := dhGroupRE.FindStringSubmatch(parts[0])
		if m == nil {
			return false
		}
		wanted["dh-group"] = strings.ToUpper(m[1]) + "_" + m[2]
	}
	for k, want := range wanted {
		if strVal(row[k]) != want {
			return false
		}
	}
	return true
}

func strVal(v any) string {
	switch tv := v.(type) {
	case string:
		return tv
	case []byte:
		return string(tv)
	default:
		if v == nil {
			return ""
		}
		return fmt.Sprint(v)
	}
}

func strSlice(v any) []string {
	switch tv := v.(type) {
	case []string:
		return tv
	case []any:
		out := make([]string, 0, len(tv))
		for _, item := range tv {
			out = append(out, strVal(item))
		}
		return out
	default:
		return nil
	}
}

// State represents an inbound or outbound kernel/VICI ESP SA state.
type State struct {
	Source      string
	Destination string
	SPI         uint32
	ReqID       uint32
	IfID        uint32
}

// Policy represents a kernel XFRM forwarding policy entry.
type Policy struct {
	Source           string
	Destination      string
	Direction        string
	OuterSource      string
	OuterDestination string
	ReqID            uint32
	IfID             uint32
}

// PolicyEntry pairs a Policy with its optional SPI.
type PolicyEntry struct {
	Policy Policy
	SPI    *uint32
}

// Child represents a verified installed CHILD SA and its byte/packet counters.
type Child struct {
	UniqueID uint64
	Inbound  State
	Outbound State
	Counts   [4]uint64 // bytes-in, bytes-out, packets-in, packets-out
}

func (c Child) EqualIdentity(other Child) bool {
	return c.UniqueID == other.UniqueID && c.Inbound == other.Inbound && c.Outbound == other.Outbound
}

type NamedChild struct {
	Name  string
	Child Child
}

type Ike struct {
	Name     string
	UniqueID uint64
	Cookies  [2]uint64
	Child    *Child
	Children []NamedChild
}

func (i Ike) ChildMap() map[string]Child {
	m := make(map[string]Child, len(i.Children))
	for _, nc := range i.Children {
		m[nc.Name] = nc.Child
	}
	return m
}

func (i Ike) EqualIdentity(other Ike) bool {
	if i.Name != other.Name || i.UniqueID != other.UniqueID || i.Cookies != other.Cookies {
		return false
	}
	if (i.Child == nil) != (other.Child == nil) {
		return false
	}
	if i.Child != nil && !i.Child.EqualIdentity(*other.Child) {
		return false
	}
	if len(i.Children) != len(other.Children) {
		return false
	}
	for idx := range i.Children {
		if i.Children[idx].Name != other.Children[idx].Name || !i.Children[idx].Child.EqualIdentity(other.Children[idx].Child) {
			return false
		}
	}
	return true
}

type Snapshot struct {
	IKES     []Ike
	Manifest *manifest.DeploymentManifest
}

func (s *Snapshot) Get(name string) *Ike {
	if s == nil {
		return nil
	}
	for i := range s.IKES {
		if s.IKES[i].Name == name {
			return &s.IKES[i]
		}
	}
	return nil
}

func (s *Snapshot) StateLabel() string {
	if s != nil && len(s.IKES) > 0 {
		return "OWNED"
	}
	return "EMPTY"
}

func (s *Snapshot) EqualIdentity(other *Snapshot) bool {
	if len(s.IKES) != len(other.IKES) {
		return false
	}
	for i := range s.IKES {
		if !s.IKES[i].EqualIdentity(other.IKES[i]) {
			return false
		}
	}
	return true
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	am := make(map[string]struct{}, len(a))
	for _, x := range a {
		am[x] = struct{}{}
	}
	for _, y := range b {
		if _, ok := am[y]; !ok {
			return false
		}
	}
	return len(am) == len(b)
}

func parseIKE(name string, row map[string]any, link manifest.Link) (Ike, error) {
	if strVal(row["version"]) != "2" || strVal(row["local-host"]) != link.Source || strVal(row["remote-host"]) != link.Peer {
		return Ike{}, unowned("IKE identity, endpoint or proposal differs from the active manifest.")
	}
	if strVal(row["state"]) != "ESTABLISHED" {
		for _, pair := range [][2]string{{"local-id", link.LocalID}, {"remote-id", link.RemoteID}} {
			if raw, ok := row[pair[0]]; ok {
				id := Identity(strVal(raw))
				if id != "%any" && id != Identity(pair[1]) {
					return Ike{}, unowned("IKE identity, endpoint or proposal differs from the active manifest.")
				}
			}
		}
		return Ike{}, transition("An IKE SA has not reached a stable established state.")
	}
	if Identity(strVal(row["local-id"])) != Identity(link.LocalID) ||
		Identity(strVal(row["remote-id"])) != Identity(link.RemoteID) ||
		!MatchProposal(row, link.IKEProposal, true) {
		return Ike{}, unowned("IKE identity, endpoint or proposal differs from the active manifest.")
	}

	specs := link.ChildSpecs()
	expectedChildren := make(map[string]manifest.ChildSpec, len(specs))
	for _, sp := range specs {
		expectedChildren[sp.Name] = sp
	}

	childrenRaw, _ := row["child-sas"].(map[string]any)
	if len(childrenRaw) > len(expectedChildren) {
		return Ike{}, transition("Multiple CHILD generations require a stable VICI snapshot.")
	}

	parsed := make(map[string]Child, len(childrenRaw))
	for _, rawInfo := range childrenRaw {
		info, ok := rawInfo.(map[string]any)
		if !ok {
			return Ike{}, unowned("CHILD selector, interface, mode or proposal differs from the manifest.")
		}
		cName := strVal(info["name"])
		if _, dup := parsed[cName]; dup {
			return Ike{}, transition("Multiple CHILD generations require a stable VICI snapshot.")
		}
		exp, ok := expectedChildren[cName]
		if !ok || strVal(info["protocol"]) != "ESP" || strVal(info["mode"]) != "TUNNEL" {
			return Ike{}, unowned("CHILD selector, interface, mode or proposal differs from the manifest.")
		}
		ifIn, err1 := positiveUint(strVal(info["if-id-in"]), 16)
		ifOut, err2 := positiveUint(strVal(info["if-id-out"]), 16)
		if err1 != nil || err2 != nil || uint32(ifIn) != link.IfID || uint32(ifOut) != link.IfID {
			return Ike{}, unowned("CHILD selector, interface, mode or proposal differs from the manifest.")
		}
		allowWild := link.SelectorMode == "route_based"
		var localTS, remoteTS []string
		for _, s := range strSlice(info["local-ts"]) {
			c, err := parseCIDR(s, allowWild)
			if err != nil {
				return Ike{}, unowned("CHILD selector, interface, mode or proposal differs from the manifest.")
			}
			localTS = append(localTS, c)
		}
		for _, s := range strSlice(info["remote-ts"]) {
			c, err := parseCIDR(s, allowWild)
			if err != nil {
				return Ike{}, unowned("CHILD selector, interface, mode or proposal differs from the manifest.")
			}
			remoteTS = append(remoteTS, c)
		}
		if !sameStringSet(localTS, exp.LocalTS) || !sameStringSet(remoteTS, exp.RemoteTS) {
			return Ike{}, unowned("CHILD selector, interface, mode or proposal differs from the manifest.")
		}
		for k := range info {
			if strings.HasPrefix(k, "mark-") || strings.HasPrefix(k, "cpi-") {
				return Ike{}, unowned("CHILD selector, interface, mode or proposal differs from the manifest.")
			}
		}
		if !MatchProposal(info, link.ESPProposal, false) {
			return Ike{}, unowned("CHILD selector, interface, mode or proposal differs from the manifest.")
		}
		if strVal(info["state"]) != "INSTALLED" {
			return Ike{}, transition("A CHILD SA has not reached a stable installed state.")
		}

		reqID, err := positiveUint(strVal(info["reqid"]), 10)
		if err != nil {
			return Ike{}, err
		}
		uid, err := positiveUint(strVal(info["uniqueid"]), 10)
		if err != nil {
			return Ike{}, err
		}
		spiIn, err := positiveUint(strVal(info["spi-in"]), 16)
		if err != nil {
			return Ike{}, err
		}
		spiOut, err := positiveUint(strVal(info["spi-out"]), 16)
		if err != nil {
			return Ike{}, err
		}
		var counts [4]uint64
		for idx, ck := range []string{"bytes-in", "bytes-out", "packets-in", "packets-out"} {
			v, err := strconv.ParseUint(strVal(info[ck]), 10, 64)
			if err != nil {
				return Ike{}, err
			}
			counts[idx] = v
		}
		parsed[cName] = Child{
			UniqueID: uid,
			Inbound:  State{Source: link.Peer, Destination: link.Source, SPI: uint32(spiIn), ReqID: uint32(reqID), IfID: link.IfID},
			Outbound: State{Source: link.Source, Destination: link.Peer, SPI: uint32(spiOut), ReqID: uint32(reqID), IfID: link.IfID},
			Counts:   counts,
		}
	}

	var ordered []NamedChild
	for _, sp := range specs {
		if ch, ok := parsed[sp.Name]; ok {
			ordered = append(ordered, NamedChild{Name: sp.Name, Child: ch})
		}
	}
	var summary *Child
	if len(ordered) == len(specs) && len(ordered) > 0 {
		first := ordered[0].Child
		if len(ordered) == 1 {
			summary = &first
		} else {
			var totals [4]uint64
			for _, nc := range ordered {
				for idx := 0; idx < 4; idx++ {
					totals[idx] += nc.Child.Counts[idx]
				}
			}
			summary = &Child{
				UniqueID: first.UniqueID,
				Inbound:  first.Inbound,
				Outbound: first.Outbound,
				Counts:   totals,
			}
		}
	}

	ikeUID, err := positiveUint(strVal(row["uniqueid"]), 10)
	if err != nil {
		return Ike{}, err
	}
	initSPI, err := positiveUint(strVal(row["initiator-spi"]), 16)
	if err != nil {
		return Ike{}, err
	}
	respSPI, err := positiveUint(strVal(row["responder-spi"]), 16)
	if err != nil {
		return Ike{}, err
	}

	return Ike{
		Name:     name,
		UniqueID: ikeUID,
		Cookies:  [2]uint64{initSPI, respSPI},
		Child:    summary,
		Children: ordered,
	}, nil
}

// ParseVICI validates raw VICI list-sas event maps against the active manifest.
func ParseVICI(events []map[string]any, m *manifest.DeploymentManifest) (*Snapshot, error) {
	links := make(map[string]manifest.Link)
	if m != nil {
		for _, l := range m.Links {
			links[l.Name()] = l
		}
	}
	result := make(map[string]Ike)
	for _, ev := range events {
		for name, rawRow := range ev {
			link, ok := links[name]
			if !ok {
				return nil, unowned("VICI reported an IKE SA outside the active manifest.")
			}
			if _, dup := result[name]; dup {
				return nil, transition("Multiple IKE generations require a stable VICI snapshot.")
			}
			row, ok := rawRow.(map[string]any)
			if !ok {
				return nil, unowned("VICI reported an IKE SA outside the active manifest.")
			}
			ike, err := parseIKE(name, row, link)
			if err != nil {
				return nil, err
			}
			result[name] = ike
		}
	}
	ikes := make([]Ike, 0, len(result))
	for _, ike := range result {
		ikes = append(ikes, ike)
	}
	sort.Slice(ikes, func(i, j int) bool { return ikes[i].Name < ikes[j].Name })
	return &Snapshot{IKES: ikes, Manifest: m}, nil
}

// MessageToMap recursively converts a govici *vici.Message to map[string]any.
func MessageToMap(msg *vici.Message) map[string]any {
	if msg == nil {
		return nil
	}
	out := make(map[string]any)
	for _, k := range msg.Keys() {
		v := msg.Get(k)
		if sub, ok := v.(*vici.Message); ok {
			out[k] = MessageToMap(sub)
		} else {
			out[k] = v
		}
	}
	return out
}

func tokenValue(tokens []string, key string) (string, error) {
	idx := -1
	for i, tok := range tokens {
		if tok == key {
			if idx >= 0 {
				return "", errors.New("ambiguous XFRM field")
			}
			idx = i
		}
	}
	if idx < 0 || idx+1 >= len(tokens) {
		return "", errors.New("missing XFRM field")
	}
	return tokens[idx+1], nil
}

// ParseKernelStates parses `ip -o xfrm state list nokeys` output.
func ParseKernelStates(output string) ([]State, error) {
	var res []State
	for _, line := range strings.Split(output, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var segments [][]string
		for _, seg := range strings.Split(line, `\`) {
			if f := strings.Fields(seg); len(f) > 0 {
				segments = append(segments, f)
			}
		}
		if len(segments) < 2 || len(segments[0]) < 4 || segments[0][0] != "src" || segments[0][2] != "dst" {
			return nil, unowned("The kernel reported a non-project XFRM state.")
		}
		head, body := segments[0], segments[1]
		var fields []string
		for _, seg := range segments[1:] {
			fields = append(fields, seg...)
		}
		proto, err1 := tokenValue(body, "proto")
		mode, err2 := tokenValue(body, "mode")
		if err1 != nil || err2 != nil || proto != "esp" || mode != "tunnel" {
			return nil, unowned("The kernel reported a non-project XFRM state.")
		}
		for _, tok := range fields {
			if tok == "mark" || tok == "output-mark" || tok == "output_mask" {
				return nil, unowned("The kernel reported a non-project XFRM state.")
			}
		}
		srcIP, err := netip.ParseAddr(head[1])
		if err != nil || !srcIP.Is4() {
			return nil, errors.New("invalid XFRM state src")
		}
		dstIP, err := netip.ParseAddr(head[3])
		if err != nil || !dstIP.Is4() {
			return nil, errors.New("invalid XFRM state dst")
		}
		spiStr, err := tokenValue(body, "spi")
		if err != nil {
			return nil, err
		}
		reqStr, err := tokenValue(body, "reqid")
		if err != nil {
			return nil, err
		}
		ifStr, err := tokenValue(fields, "if_id")
		if err != nil {
			return nil, err
		}
		spi, err := positiveUint(spiStr, 0)
		if err != nil {
			return nil, err
		}
		reqID, err := positiveUint(reqStr, 10)
		if err != nil {
			return nil, err
		}
		ifID, err := positiveUint(ifStr, 0)
		if err != nil {
			return nil, err
		}
		res = append(res, State{
			Source:      srcIP.String(),
			Destination: dstIP.String(),
			SPI:         uint32(spi),
			ReqID:       uint32(reqID),
			IfID:        uint32(ifID),
		})
	}
	return res, nil
}

// ParseKernelPolicies parses `ip -o xfrm policy list nosock` output.
func ParseKernelPolicies(output string) ([]PolicyEntry, error) {
	var res []PolicyEntry
	for _, line := range strings.Split(output, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var segments [][]string
		for _, seg := range strings.Split(line, `\`) {
			if f := strings.Fields(seg); len(f) > 0 {
				segments = append(segments, f)
			}
		}
		if len(segments) < 2 || len(segments[0]) < 4 || segments[0][0] != "src" || segments[0][2] != "dst" {
			return nil, unowned("The kernel reported a non-project XFRM forwarding policy.")
		}
		head := segments[0]
		var fields []string
		for _, seg := range segments[1:] {
			fields = append(fields, seg...)
		}
		tmplIdx := -1
		for i, tok := range fields {
			if tok == "mark" || tok == "block" || tok == "use" || tok == "dev" || tok == "sub" || tok == "offload" {
				return nil, unowned("The kernel reported a non-project XFRM forwarding policy.")
			}
			if tok == "tmpl" {
				if tmplIdx >= 0 {
					return nil, unowned("The kernel reported a non-project XFRM forwarding policy.")
				}
				tmplIdx = i
			}
		}
		if tmplIdx < 0 {
			return nil, unowned("The kernel reported a non-project XFRM forwarding policy.")
		}
		tmpl := fields[tmplIdx+1:]
		proto, err1 := tokenValue(tmpl, "proto")
		mode, err2 := tokenValue(tmpl, "mode")
		if err1 != nil || err2 != nil || proto != "esp" || mode != "tunnel" {
			return nil, unowned("A kernel policy does not use the expected ESP tunnel template.")
		}
		var spiPtr *uint32
		if spiStr, err := tokenValue(tmpl, "spi"); err == nil {
			v, err := positiveUint(spiStr, 0)
			if err != nil {
				return nil, err
			}
			u := uint32(v)
			spiPtr = &u
		}
		srcCIDR, err := parseCIDR(head[1], true)
		if err != nil {
			return nil, err
		}
		dstCIDR, err := parseCIDR(head[3], true)
		if err != nil {
			return nil, err
		}
		dir, err := tokenValue(fields, "dir")
		if err != nil {
			return nil, err
		}
		oSrcStr, err := tokenValue(tmpl, "src")
		if err != nil {
			return nil, err
		}
		oDstStr, err := tokenValue(tmpl, "dst")
		if err != nil {
			return nil, err
		}
		oSrc, err := netip.ParseAddr(oSrcStr)
		if err != nil || !oSrc.Is4() {
			return nil, errors.New("invalid template src")
		}
		oDst, err := netip.ParseAddr(oDstStr)
		if err != nil || !oDst.Is4() {
			return nil, errors.New("invalid template dst")
		}
		reqStr, err := tokenValue(tmpl, "reqid")
		if err != nil {
			return nil, err
		}
		reqID, err := positiveUint(reqStr, 10)
		if err != nil {
			return nil, err
		}
		ifStr, err := tokenValue(fields, "if_id")
		if err != nil {
			return nil, err
		}
		ifID, err := positiveUint(ifStr, 0)
		if err != nil {
			return nil, err
		}
		res = append(res, PolicyEntry{
			Policy: Policy{
				Source:           srcCIDR,
				Destination:      dstCIDR,
				Direction:        dir,
				OuterSource:      oSrc.String(),
				OuterDestination: oDst.String(),
				ReqID:            uint32(reqID),
				IfID:             uint32(ifID),
			},
			SPI: spiPtr,
		})
	}
	return res, nil
}

// Correlate verifies exact 1:1 mapping between VICI CHILD SAs and kernel XFRM states & policies.
func Correlate(snap *Snapshot, m *manifest.DeploymentManifest, states []State, policies []PolicyEntry) error {
	expectedStates := make(map[State]struct{})
	expectedPolicies := make(map[Policy]uint32)
	if m != nil {
		for _, link := range m.Links {
			ike := snap.Get(link.Name())
			if ike == nil || (ike.Child == nil && len(ike.Children) == 0) {
				continue
			}
			cmap := ike.ChildMap()
			if len(cmap) == 0 && ike.Child != nil {
				cmap[link.Child()] = *ike.Child
			}
			for _, sp := range link.ChildSpecs() {
				cObj, ok := cmap[sp.Name]
				if !ok {
					continue
				}
				expectedStates[cObj.Inbound] = struct{}{}
				expectedStates[cObj.Outbound] = struct{}{}
				for _, lc := range sp.LocalTS {
					for _, rc := range sp.RemoteTS {
						expectedPolicies[Policy{lc, rc, "out", cObj.Outbound.Source, cObj.Outbound.Destination, cObj.Outbound.ReqID, cObj.Outbound.IfID}] = cObj.Outbound.SPI
						expectedPolicies[Policy{rc, lc, "in", cObj.Inbound.Source, cObj.Inbound.Destination, cObj.Inbound.ReqID, cObj.Inbound.IfID}] = cObj.Inbound.SPI
						expectedPolicies[Policy{rc, lc, "fwd", cObj.Inbound.Source, cObj.Inbound.Destination, cObj.Inbound.ReqID, cObj.Inbound.IfID}] = cObj.Inbound.SPI
					}
				}
			}
		}
	}

	if len(states) != len(expectedStates) {
		return unowned("The kernel XFRM state does not map exactly to VICI CHILD SPIs.")
	}
	seenStates := make(map[State]struct{}, len(states))
	for _, st := range states {
		if _, ok := expectedStates[st]; !ok {
			return unowned("The kernel XFRM state does not map exactly to VICI CHILD SPIs.")
		}
		seenStates[st] = struct{}{}
	}
	if len(seenStates) != len(expectedStates) {
		return unowned("The kernel XFRM state does not map exactly to VICI CHILD SPIs.")
	}

	if len(policies) != len(expectedPolicies) {
		return unowned("The kernel XFRM policy does not map exactly to the authorized selectors.")
	}
	seenPolicies := make(map[Policy]struct{}, len(policies))
	for _, pe := range policies {
		expSPI, ok := expectedPolicies[pe.Policy]
		if !ok || (pe.SPI != nil && *pe.SPI != expSPI) {
			return unowned("The kernel XFRM policy does not map exactly to the authorized selectors.")
		}
		seenPolicies[pe.Policy] = struct{}{}
	}
	if len(seenPolicies) != len(expectedPolicies) {
		return unowned("The kernel XFRM policy does not map exactly to the authorized selectors.")
	}
	return nil
}

// Inventory performs a bounded, atomic before/after VICI + kernel XFRM correlation snapshot.
func Inventory(h host.Runner, m *manifest.DeploymentManifest, pid int, attempts int, delay time.Duration) (*Snapshot, error) {
	if attempts < 1 {
		attempts = 4
	}
	if delay <= 0 {
		delay = 200 * time.Millisecond
	}
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		snap, err := inventoryOnce(h, m, pid)
		if err == nil {
			return snap, nil
		}
		if _, ok := secureio.AsStop(err); ok {
			lastErr = err
		} else {
			lastErr = secureio.StopWithReason("SA_UNVERIFIED", "SA or policy fields could not be verified.")
		}
		if attempt+1 < attempts {
			time.Sleep(delay)
		}
	}
	return nil, lastErr
}

func inventoryOnce(h host.Runner, m *manifest.DeploymentManifest, pid int) (*Snapshot, error) {
	sess, err := OpenSession(pid, host.VICIPath)
	if err != nil {
		return nil, err
	}
	defer sess.Close()

	listSAs := func() ([]map[string]any, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		var events []map[string]any
		for msg, err := range sess.CallStreaming(ctx, "list-sas", "list-sa", nil) {
			if err != nil {
				return nil, secureio.StopWithReason("VICI_UNAVAILABLE", "A local VICI request did not complete.")
			}
			events = append(events, MessageToMap(msg))
		}
		return events, nil
	}

	evBefore, err := listSAs()
	if err != nil {
		return nil, err
	}
	before, err := ParseVICI(evBefore, m)
	if err != nil {
		return nil, err
	}
	stateOut, err := h.Command("XFRM state inventory", []string{"ip", "-o", "xfrm", "state", "list", "nokeys"}, nil, nil, 30*time.Second, false)
	if err != nil {
		return nil, err
	}
	states, err := ParseKernelStates(stateOut)
	if err != nil {
		return nil, err
	}
	policyOut, err := h.Command("XFRM policy inventory", []string{"ip", "-o", "xfrm", "policy", "list", "nosock"}, nil, nil, 30*time.Second, false)
	if err != nil {
		return nil, err
	}
	policies, err := ParseKernelPolicies(policyOut)
	if err != nil {
		return nil, err
	}
	evAfter, err := listSAs()
	if err != nil {
		return nil, err
	}
	after, err := ParseVICI(evAfter, m)
	if err != nil {
		return nil, err
	}
	if !before.EqualIdentity(after) {
		return nil, transition("VICI changed while the kernel inventory was being read.")
	}
	if err := Correlate(after, m, states, policies); err != nil {
		return nil, err
	}
	return after, nil
}
