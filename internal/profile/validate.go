package profile

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"

	"github.com/yikkrrtykj/event-ipsec-hub/config"
)

const MaxProfileBytes = 256 * 1024

var (
	DocumentationNetworks = []netip.Prefix{
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"),
	}
	NonUnicastLANs = []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("169.254.0.0/16"),
		netip.MustParsePrefix("224.0.0.0/4"),
		netip.MustParsePrefix("240.0.0.0/4"),
	}
	nonGlobalIPv4 = []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("169.254.0.0/16"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.0.0.0/24"),
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("198.18.0.0/15"),
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("224.0.0.0/4"),
		netip.MustParsePrefix("240.0.0.0/4"),
		netip.MustParsePrefix("255.255.255.255/32"),
	}
	backupHandoffFields = []string{
		"public_endpoint",
		"tunnel_name",
		"remote_cidrs",
		"route_priority",
		"track_target",
	}
)

// ProfileError represents a safe-to-display validation or parsing error without echoing raw inputs.
type ProfileError struct {
	Detail string
}

func (e *ProfileError) Error() string {
	return e.Detail
}

func profileErr(format string, args ...any) error {
	return &ProfileError{Detail: fmt.Sprintf(format, args...)}
}

var (
	compiledSchemaOnce sync.Once
	compiledSchema     *jsonschema.Schema
	compiledSchemaErr  error
)

var ecmaUnicodeRE = regexp.MustCompile(`\\u([0-9a-fA-F]{4})`)

func ecmaRegexpEngine(pattern string) (jsonschema.Regexp, error) {
	re2Pattern := ecmaUnicodeRE.ReplaceAllString(pattern, `\x{$1}`)
	return regexp.Compile(re2Pattern)
}

func schemaValidator() (*jsonschema.Schema, error) {
	compiledSchemaOnce.Do(func() {
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(config.SchemaJSON))
		if err != nil {
			compiledSchemaErr = err
			return
		}
		compiler := jsonschema.NewCompiler()
		compiler.UseRegexpEngine(ecmaRegexpEngine)
		compiler.AssertFormat()
		compiler.RegisterFormat(&jsonschema.Format{
			Name: "ipv4",
			Validate: func(v any) error {
				s, ok := v.(string)
				if !ok {
					return nil
				}
				addr, err := netip.ParseAddr(s)
				if err != nil || !addr.Is4() || addr.String() != s {
					return errors.New("not a canonical IPv4 address")
				}
				return nil
			},
		})
		compiler.RegisterFormat(&jsonschema.Format{
			Name: "ipv4-cidr",
			Validate: func(v any) error {
				s, ok := v.(string)
				if !ok {
					return nil
				}
				p, err := netip.ParsePrefix(s)
				if err != nil || !p.Addr().Is4() || p.Masked().String() != s {
					return errors.New("not a canonical IPv4 CIDR")
				}
				return nil
			},
		})
		if err := compiler.AddResource("schema.json", doc); err != nil {
			compiledSchemaErr = err
			return
		}
		compiledSchema, compiledSchemaErr = compiler.Compile("schema.json")
	})
	return compiledSchema, compiledSchemaErr
}

// LoadProfile reads and validates a single UTF-8 YAML profile from disk.
func LoadProfile(path string) (*Profile, error) {
	ext := strings.ToLower(filepath.Ext(path))
	if ext != ".yaml" && ext != ".yml" {
		return nil, profileErr("Select a readable .yaml or .yml profile.")
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, profileErr("Select a readable .yaml or .yml profile.")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, profileErr("Could not read a single UTF-8 YAML profile.")
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxProfileBytes+1))
	if err != nil {
		return nil, profileErr("Could not read a single UTF-8 YAML profile.")
	}
	return ParseProfile(data)
}

// ParseProfile strictly parses YAML bytes (disallowing aliases, duplicate keys, multi-doc,
// non-UTF8, and YAML 1.1 implicit booleans) and validates schema + topology constraints.
func ParseProfile(content []byte) (*Profile, error) {
	if len(content) > MaxProfileBytes {
		return nil, profileErr("The profile exceeds the 256 KiB size limit.")
	}
	content = bytes.TrimPrefix(content, []byte{0xEF, 0xBB, 0xBF})
	if !utf8.Valid(content) {
		return nil, profileErr("Could not read a single UTF-8 YAML profile.")
	}

	dec := yaml.NewDecoder(bytes.NewReader(content))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		return nil, profileErr("Could not read a single UTF-8 YAML profile.")
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, profileErr("Could not read a single UTF-8 YAML profile.")
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 {
		return nil, profileErr("Could not read a single UTF-8 YAML profile.")
	}

	rawVal, err := decodeStrictNode(doc.Content[0], 0)
	if err != nil {
		return nil, err
	}
	rawMap, ok := rawVal.(map[string]any)
	if !ok {
		return nil, profileErr("Schema violation at profile (type).")
	}
	return ValidateRaw(rawMap)
}

func decodeStrictNode(node *yaml.Node, depth int) (any, error) {
	if depth > 64 {
		return nil, profileErr("Could not read a single UTF-8 YAML profile.")
	}
	switch node.Kind {
	case yaml.AliasNode:
		return nil, profileErr("YAML aliases are not supported.")
	case yaml.MappingNode:
		if len(node.Content)%2 != 0 {
			return nil, profileErr("Could not read a single UTF-8 YAML profile.")
		}
		out := make(map[string]any, len(node.Content)/2)
		for i := 0; i < len(node.Content); i += 2 {
			kNode, vNode := node.Content[i], node.Content[i+1]
			if kNode.Kind == yaml.AliasNode {
				return nil, profileErr("YAML aliases are not supported.")
			}
			kVal, err := decodeStrictNode(kNode, depth+1)
			if err != nil {
				return nil, err
			}
			key, ok := kVal.(string)
			if !ok {
				return nil, profileErr("YAML mapping keys must be unique strings.")
			}
			if _, exists := out[key]; exists {
				return nil, profileErr("YAML mapping keys must be unique strings.")
			}
			val, err := decodeStrictNode(vNode, depth+1)
			if err != nil {
				return nil, err
			}
			out[key] = val
		}
		return out, nil
	case yaml.SequenceNode:
		out := make([]any, 0, len(node.Content))
		for _, item := range node.Content {
			val, err := decodeStrictNode(item, depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, val)
		}
		return out, nil
	case yaml.ScalarNode:
		return decodeStrictScalar(node)
	default:
		return nil, profileErr("Could not read a single UTF-8 YAML profile.")
	}
}

func decodeStrictScalar(node *yaml.Node) (any, error) {
	tag := node.ShortTag()
	if node.Style != 0 {
		// Quoted or block scalar is always a string unless explicitly tagged.
		if node.Tag == "" || tag == "!!str" {
			return node.Value, nil
		}
	}
	switch tag {
	case "!!null":
		return nil, nil
	case "!!bool":
		switch strings.ToLower(node.Value) {
		case "true":
			return true, nil
		case "false":
			return false, nil
		default:
			// Reject YAML 1.1 yes/no/on/off coercion: treat as plain string to match ProfileLoader.
			return node.Value, nil
		}
	case "!!int":
		iv, err := strconv.ParseInt(node.Value, 0, 64)
		if err != nil {
			return nil, profileErr("Could not read a single UTF-8 YAML profile.")
		}
		return json.Number(strconv.FormatInt(iv, 10)), nil
	case "!!float":
		fv, err := strconv.ParseFloat(node.Value, 64)
		if err != nil {
			return nil, profileErr("Could not read a single UTF-8 YAML profile.")
		}
		if math.IsNaN(fv) || math.IsInf(fv, 0) {
			return fv, nil
		}
		// Keep explicit float distinction (e.g. 1.0) so integer fields reject floats.
		return floatValue(fv), nil
	case "!!str", "":
		return node.Value, nil
	default:
		return node.Value, nil
	}
}

// floatValue ensures non-integer float literals (like 1.0) fail integer-type checks.
type floatValue float64

func (f floatValue) MarshalJSON() ([]byte, error) {
	v := float64(f)
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return nil, errors.New("non-finite float")
	}
	return []byte(strconv.FormatFloat(v, 'f', -1, 64)), nil
}

// ValidateRaw validates a decoded map against schema_version, JSON Schema Draft 2020-12,
// and all topology/backup/monitoring invariants, returning a typed Profile.
func ValidateRaw(raw map[string]any) (*Profile, error) {
	if sv, ok := raw["schema_version"]; ok {
		if sv != "2.0" {
			return nil, profileErr("Unsupported schema version. Start from the V2 example.")
		}
	}

	if err := checkStrictTypes(raw, ""); err != nil {
		return nil, err
	}

	// Normalize for jsonschema/v6 validation (convert floatValue -> float64, check finiteness).
	normalized, err := normalizeForSchema(raw)
	if err != nil {
		return nil, err
	}
	validator, err := schemaValidator()
	if err != nil {
		return nil, profileErr("Internal schema compilation error: %v", err)
	}
	if err := validator.Validate(normalized); err != nil {
		var ve *jsonschema.ValidationError
		if errors.As(err, &ve) {
			leaf := deepestValidationError(ve)
			loc := strings.Join(leaf.InstanceLocation, ".")
			if loc == "" {
				loc = "profile"
			}
			kw := schemaKeyword(leaf)
			return nil, profileErr("Schema violation at %s (%s).", loc, kw)
		}
		return nil, profileErr("Schema violation at profile (validation).")
	}

	// Marshal normalized map into strongly typed Profile struct.
	encoded, err := json.Marshal(normalized)
	if err != nil {
		return nil, profileErr("Could not decode validated profile.")
	}
	var p Profile
	if err := json.Unmarshal(encoded, &p); err != nil {
		return nil, profileErr("Could not decode validated profile.")
	}
	p.Raw = normalized.(map[string]any)

	if err := validateTopology(&p); err != nil {
		return nil, err
	}
	if err := validateOptionalPaths(&p); err != nil {
		return nil, err
	}
	return &p, nil
}

var integerOnlyPaths = map[string]bool{
	"site_links.*.if_id":                     true,
	"site_links.*.route_priority":            true,
	"site_links.*.outer_path.route_table":    true,
	"site_links.*.outer_path.policy_priority": true,
	"security.ike_lifetime_seconds":          true,
	"security.child_lifetime_seconds":        true,
	"security.dpd_delay_seconds":             true,
	"backup.links.*.route_priority":          true,
	"monitoring.exporter.port":               true,
	"monitoring.exporter.interval_seconds":   true,
	"monitoring.exporter.timeout_seconds":    true,
	"monitoring.exporter.ttl_seconds":        true,
	"monitoring.udp_path.ttl_seconds":        true,
	"monitoring.probes.*.port":               true,
}

func checkStrictTypes(v any, path string) error {
	switch val := v.(type) {
	case map[string]any:
		for k, child := range val {
			next := k
			if path != "" {
				next = path + "." + k
			}
			if err := checkStrictTypes(child, next); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range val {
			next := "*"
			if path != "" {
				next = path + ".*"
			}
			if err := checkStrictTypes(child, next); err != nil {
				return err
			}
		}
	case floatValue:
		if math.IsNaN(float64(val)) || math.IsInf(float64(val), 0) {
			if strings.HasPrefix(path, "monitoring.thresholds.") {
				return profileErr("Monitoring thresholds must be finite.")
			}
			return profileErr("Schema violation at %s (type).", path)
		}
		if integerOnlyPaths[path] {
			return profileErr("Schema violation at %s (type).", path)
		}
	case float64:
		if math.IsNaN(val) || math.IsInf(val, 0) {
			if strings.HasPrefix(path, "monitoring.thresholds.") {
				return profileErr("Monitoring thresholds must be finite.")
			}
			return profileErr("Schema violation at %s (type).", path)
		}
		if integerOnlyPaths[path] {
			return profileErr("Schema violation at %s (type).", path)
		}
	}
	return nil
}

func normalizeForSchema(v any) (any, error) {
	switch val := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(val))
		for k, child := range val {
			n, err := normalizeForSchema(child)
			if err != nil {
				return nil, err
			}
			out[k] = n
		}
		return out, nil
	case []any:
		out := make([]any, len(val))
		for i, child := range val {
			n, err := normalizeForSchema(child)
			if err != nil {
				return nil, err
			}
			out[i] = n
		}
		return out, nil
	case floatValue:
		return float64(val), nil
	case int:
		return json.Number(strconv.Itoa(val)), nil
	case int64:
		return json.Number(strconv.FormatInt(val, 10)), nil
	case uint32:
		return json.Number(strconv.FormatUint(uint64(val), 10)), nil
	default:
		return val, nil
	}
}

func deepestValidationError(ve *jsonschema.ValidationError) *jsonschema.ValidationError {
	cur := ve
	for len(cur.Causes) > 0 {
		cur = cur.Causes[0]
	}
	return cur
}

func schemaKeyword(ve *jsonschema.ValidationError) string {
	if ve.ErrorKind == nil {
		return "validation"
	}
	loc := ve.ErrorKind.KeywordPath()
	if len(loc) == 0 {
		return "validation"
	}
	last := loc[len(loc)-1]
	// In schema locations like ["properties", "sites", "minItems"], last is the keyword.
	// If it's a nested property name under dependentRequired/properties, walk back to known keyword.
	known := map[string]bool{
		"required": true, "minItems": true, "maxItems": true, "uniqueItems": true,
		"additionalProperties": true, "pattern": true, "format": true, "type": true,
		"minimum": true, "maximum": true, "exclusiveMinimum": true, "const": true,
		"enum": true, "dependentRequired": true, "not": true, "minLength": true, "maxLength": true,
	}
	for i := len(loc) - 1; i >= 0; i-- {
		if known[loc[i]] {
			return loc[i]
		}
	}
	return last
}

func requireUnique[T comparable](values []T, label string) error {
	seen := make(map[T]struct{}, len(values))
	for _, v := range values {
		if _, dup := seen[v]; dup {
			return profileErr("%s must be unique.", label)
		}
		seen[v] = struct{}{}
	}
	return nil
}

// IsPublicEndpoint reports whether value is a unicast global IPv4 or RFC 5737 documentation host IP.
func IsPublicEndpoint(value string) bool {
	addr, err := netip.ParseAddr(value)
	if err != nil || !addr.Is4() {
		return false
	}
	if addr.IsMulticast() {
		return false
	}
	for _, doc := range DocumentationNetworks {
		if doc.Contains(addr) {
			// Exclude network and broadcast addresses of the /24.
			b := addr.As4()
			return b[3] != 0 && b[3] != 255
		}
	}
	for _, ng := range nonGlobalIPv4 {
		if ng.Contains(addr) {
			return false
		}
	}
	return true
}

func overlapsAny(p netip.Prefix, list []netip.Prefix) bool {
	for _, item := range list {
		if p.Overlaps(item) {
			return true
		}
	}
	return false
}

func addrInAny(a netip.Addr, list []netip.Prefix) bool {
	for _, item := range list {
		if item.Contains(a) {
			return true
		}
	}
	return false
}

func validateTopology(p *Profile) error {
	siteIDs := make([]string, 0, len(p.Sites))
	siteMap := make(map[string]Site, len(p.Sites))
	for _, s := range p.Sites {
		siteIDs = append(siteIDs, s.ID)
		siteMap[s.ID] = s
	}
	if err := requireUnique(siteIDs, "Site IDs"); err != nil {
		return err
	}

	linkKeyIDs := make([]string, 0, len(p.SiteLinks))
	ifIDs := make([]uint32, 0, len(p.SiteLinks))
	secretRefs := make([]string, 0, len(p.SiteLinks))
	linksBySite := make(map[string][]SiteLink, len(p.Sites))
	linkSiteSet := make(map[string]struct{}, len(p.Sites))
	for _, l := range p.SiteLinks {
		linkKeyIDs = append(linkKeyIDs, l.KeyID())
		ifIDs = append(ifIDs, l.IfID)
		secretRefs = append(secretRefs, l.SecretRef)
		linksBySite[l.SiteID] = append(linksBySite[l.SiteID], l)
		linkSiteSet[l.SiteID] = struct{}{}
	}
	if err := requireUnique(linkKeyIDs, "Site link IDs"); err != nil {
		return err
	}
	if err := requireUnique(ifIDs, "XFRM interface IDs"); err != nil {
		return err
	}
	if err := requireUnique(secretRefs, "PSK references"); err != nil {
		return err
	}

	var tunnelPrefixes []netip.Prefix
	for _, l := range p.SiteLinks {
		if l.TunnelLocalCIDR == "" {
			continue
		}
		pref, err := netip.ParsePrefix(l.TunnelLocalCIDR)
		if err != nil || !pref.Addr().Is4() || pref.Bits() < 29 || pref.Bits() > 31 {
			return profileErr("Invalid tunnel_local_cidr (expected IPv4 /29, /30, or /31 host CIDR).")
		}
		if pref.Bits() < 31 {
			// Reject network address (masked == addr) for /29 and /30.
			if pref.Addr() == pref.Masked().Addr() {
				return profileErr("tunnel_local_cidr must specify a host address, not the network address.")
			}
		}
		for _, prev := range tunnelPrefixes {
			if prev.Overlaps(pref) {
				return profileErr("tunnel_local_cidr subnets must not overlap across links.")
			}
		}
		tunnelPrefixes = append(tunnelPrefixes, pref)
	}

	if len(linkSiteSet) != len(siteMap) {
		return profileErr("Each site must have exactly one link (or Dual-ISP links) and no unknown links.")
	}
	for sid := range linkSiteSet {
		if _, ok := siteMap[sid]; !ok {
			return profileErr("Each site must have exactly one link (or Dual-ISP links) and no unknown links.")
		}
	}

	for sid, slinks := range linksBySite {
		uplinksMap := make(map[string]Uplink, len(siteMap[sid].Uplinks))
		for _, u := range siteMap[sid].Uplinks {
			uplinksMap[u.ID] = u
		}
		for _, l := range slinks {
			if l.UplinkID != "" {
				if _, ok := uplinksMap[l.UplinkID]; !ok {
					return profileErr("A site_link references an unknown site uplink_id.")
				}
			}
		}
		if len(slinks) > 1 {
			uplinkBindings := make([]string, 0, len(slinks))
			priorities := make([]int, 0, len(slinks))
			for _, l := range slinks {
				if l.ID == "" || l.UplinkID == "" {
					return profileErr("Multi-link Dual-ISP sites require explicit id and uplink_id on each site_link.")
				}
				uplinkBindings = append(uplinkBindings, l.UplinkID)
				if l.RoutePriority == nil {
					return profileErr("Multi-link Dual-ISP sites require distinct route_priority (ECMP unsupported).")
				}
				priorities = append(priorities, *l.RoutePriority)
			}
			if err := requireUnique(uplinkBindings, "Uplink bindings within a site"); err != nil {
				return err
			}
			if err := requireUnique(priorities, "Route priorities across same-site Dual-ISP links"); err != nil {
				return err
			}
		}
	}

	seenPairs := make(map[[2]string]struct{})
	connectedSites := make(map[string]struct{}, len(siteMap))
	for _, pair := range p.TrafficPolicy.AllowedSitePairs {
		_, okA := siteMap[pair.A]
		_, okB := siteMap[pair.B]
		if pair.A == pair.B || !okA || !okB {
			return profileErr("Each allowed pair must explicitly connect two distinct defined sites.")
		}
		key := [2]string{pair.A, pair.B}
		if key[0] > key[1] {
			key[0], key[1] = key[1], key[0]
		}
		if _, dup := seenPairs[key]; dup {
			return profileErr("Duplicate allowed_site_pairs entries are not allowed.")
		}
		seenPairs[key] = struct{}{}
		connectedSites[pair.A] = struct{}{}
		connectedSites[pair.B] = struct{}{}

		for _, cidr := range pair.ACIDRs {
			if !slices.Contains(siteMap[pair.A].LANCIDRs, cidr) {
				return profileErr("Authorized CIDRs must be listed in the matching site LAN.")
			}
		}
		for _, cidr := range pair.BCIDRs {
			if !slices.Contains(siteMap[pair.B].LANCIDRs, cidr) {
				return profileErr("Authorized CIDRs must be listed in the matching site LAN.")
			}
		}
	}
	if len(siteMap) >= 2 && len(connectedSites) != len(siteMap) {
		return profileErr("Every declared site must participate in at least one allowed_site_pairs rule.")
	}

	var networks []netip.Prefix
	for _, s := range p.Sites {
		for _, c := range s.LANCIDRs {
			pref, err := netip.ParsePrefix(c)
			if err != nil || !pref.Addr().Is4() {
				return profileErr("Invalid IPv4 LAN CIDR.")
			}
			if pref.Bits() == 0 {
				return profileErr("Default routes and wildcard traffic selectors are unsupported.")
			}
			if overlapsAny(pref, NonUnicastLANs) {
				return profileErr("Site LANs must not include special-use non-forwardable addresses.")
			}
			networks = append(networks, pref)
		}
	}
	sort.Slice(networks, func(i, j int) bool {
		if cmp := networks[i].Addr().Compare(networks[j].Addr()); cmp != 0 {
			return cmp < 0
		}
		return networks[i].Bits() < networks[j].Bits()
	})
	for i := 0; i+1 < len(networks); i++ {
		if networks[i].Overlaps(networks[i+1]) {
			return profileErr("Site LAN CIDRs must not overlap.")
		}
	}

	primaryEndpoints := make([]string, 0, 1+len(p.Sites))
	primaryEndpoints = append(primaryEndpoints, p.Hub.PublicEndpoint)
	for _, s := range p.Sites {
		primaryEndpoints = append(primaryEndpoints, s.PublicEndpoint)
	}
	if err := requireUnique(primaryEndpoints, "Primary public endpoints"); err != nil {
		return err
	}
	endpoints := make(map[string]struct{}, len(primaryEndpoints))
	for _, ep := range primaryEndpoints {
		endpoints[ep] = struct{}{}
	}
	for _, s := range p.Sites {
		if len(s.Uplinks) > 0 {
			uIDs := make([]string, 0, len(s.Uplinks))
			hasPrimary := false
			for _, u := range s.Uplinks {
				uIDs = append(uIDs, u.ID)
				endpoints[u.PublicEndpoint] = struct{}{}
				if u.PublicEndpoint == s.PublicEndpoint {
					hasPrimary = true
				}
			}
			if err := requireUnique(uIDs, "Uplink IDs within a site"); err != nil {
				return err
			}
			if !hasPrimary {
				return profileErr("A site's primary public endpoint must be in its listed uplinks.")
			}
		}
	}
	if p.Backup.Enabled {
		for _, bl := range p.Backup.Links {
			if bl.PublicEndpoint != "" {
				endpoints[bl.PublicEndpoint] = struct{}{}
			}
		}
	}
	for ep := range endpoints {
		if !IsPublicEndpoint(ep) {
			return profileErr("Public endpoints must be unicast public or RFC 5737 IPv4 addresses.")
		}
	}

	var outerAddresses []netip.Addr
	for _, l := range p.SiteLinks {
		for _, rawIP := range []string{l.OuterPath.Gateway, l.OuterPath.SourceIP} {
			if rawIP == "" {
				continue
			}
			addr, err := netip.ParseAddr(rawIP)
			if err != nil || !addr.Is4() || addrInAny(addr, NonUnicastLANs) {
				return profileErr("Outer gateways and source IPs must be unicast IPv4 addresses.")
			}
			outerAddresses = append(outerAddresses, addr)
		}
	}
	for ep := range endpoints {
		addr, _ := netip.ParseAddr(ep)
		outerAddresses = append(outerAddresses, addr)
	}
	for _, addr := range outerAddresses {
		if addrInAny(addr, networks) {
			return profileErr("A site LAN would capture an outer peer, gateway or source address.")
		}
	}

	type tableBinding struct {
		iface   string
		source  string
		gateway string
	}
	tableBindings := make(map[int]tableBinding)
	for _, l := range p.SiteLinks {
		if l.OuterPath.RouteTable != nil {
			if l.OuterPath.Interface == "auto" || l.OuterPath.SourceIP == "" || l.OuterPath.Gateway == "" {
				return profileErr("Dual-ISP symmetric return (outer_path.route_table) requires explicit interface, source_ip, and gateway.")
			}
			b := tableBinding{
				iface:   l.OuterPath.Interface,
				source:  l.OuterPath.SourceIP,
				gateway: l.OuterPath.Gateway,
			}
			if existing, ok := tableBindings[*l.OuterPath.RouteTable]; ok && existing != b {
				return profileErr("Conflicting outer_path bindings share the same route_table.")
			}
			tableBindings[*l.OuterPath.RouteTable] = b
		}
	}
	return nil
}

// AuthorizedPairs returns normalized bidirectional forwarding rules from allowed_site_pairs.
func AuthorizedPairs(p *Profile) []AuthorizedPair {
	siteLANs := make(map[string][]string, len(p.Sites))
	for _, s := range p.Sites {
		siteLANs[s.ID] = s.LANCIDRs
	}
	rules := make([]AuthorizedPair, 0, len(p.TrafficPolicy.AllowedSitePairs)*2)
	for _, pair := range p.TrafficPolicy.AllowedSitePairs {
		aCIDRs := pair.ACIDRs
		if len(aCIDRs) == 0 {
			aCIDRs = siteLANs[pair.A]
		}
		bCIDRs := pair.BCIDRs
		if len(bCIDRs) == 0 {
			bCIDRs = siteLANs[pair.B]
		}
		rules = append(rules,
			AuthorizedPair{
				SourceSiteID: pair.A,
				TargetSiteID: pair.B,
				SourceCIDRs:  slices.Clone(aCIDRs),
				TargetCIDRs:  slices.Clone(bCIDRs),
			},
			AuthorizedPair{
				SourceSiteID: pair.B,
				TargetSiteID: pair.A,
				SourceCIDRs:  slices.Clone(bCIDRs),
				TargetCIDRs:  slices.Clone(aCIDRs),
			},
		)
	}
	return rules
}

// AuthorizedLANs returns the union of authorized local LAN CIDRs per site.
// In single-site staging mode (1 site, 0 pairs), the site's declared LAN CIDRs are authorized
// so the tunnel and Hub-to-site routes/probes can be verified before adding a second site.
func AuthorizedLANs(p *Profile) map[string][]string {
	result := make(map[string][]string, len(p.Sites))
	for _, s := range p.Sites {
		result[s.ID] = []string{}
	}
	if len(p.Sites) == 1 && len(p.TrafficPolicy.AllowedSitePairs) == 0 {
		result[p.Sites[0].ID] = slices.Clone(p.Sites[0].LANCIDRs)
		return result
	}
	for _, rule := range AuthorizedPairs(p) {
		for _, c := range rule.SourceCIDRs {
			if !slices.Contains(result[rule.SourceSiteID], c) {
				result[rule.SourceSiteID] = append(result[rule.SourceSiteID], c)
			}
		}
	}
	return result
}

// AuthorizedRemoteLANs returns the union of remote CIDRs that siteID is authorized to reach.
func AuthorizedRemoteLANs(p *Profile, siteID string) []string {
	var result []string
	for _, rule := range AuthorizedPairs(p) {
		if rule.SourceSiteID == siteID {
			for _, c := range rule.TargetCIDRs {
				if !slices.Contains(result, c) {
					result = append(result, c)
				}
			}
		}
	}
	return result
}

// EvaluateBackupReadiness reports offline backup handoff completeness.
func EvaluateBackupReadiness(p *Profile) BackupReadiness {
	if !p.Backup.Enabled {
		return BackupReadiness{Enabled: false}
	}
	backupLinks := make(map[string]BackupLink, len(p.Backup.Links))
	for _, bl := range p.Backup.Links {
		backupLinks[bl.SiteID] = bl
	}
	missing := make(map[string][]string)
	for _, primary := range p.SiteLinks {
		sid := primary.SiteID
		bl, ok := backupLinks[sid]
		var fields []string
		if !ok {
			fields = append(fields, "backup.links")
		} else {
			if bl.PublicEndpoint == "" {
				fields = append(fields, "backup.links.public_endpoint")
			}
			if bl.TunnelName == "" {
				fields = append(fields, "backup.links.tunnel_name")
			}
			if len(bl.RemoteCIDRs) == 0 {
				fields = append(fields, "backup.links.remote_cidrs")
			}
			if bl.RoutePriority == nil {
				fields = append(fields, "backup.links.route_priority")
			}
			if bl.TrackTarget == "" {
				fields = append(fields, "backup.links.track_target")
			}
		}
		if primary.RoutePriority == nil {
			fields = append(fields, "site_links.route_priority")
		}
		if len(fields) > 0 {
			missing[sid] = fields
		}
	}
	if len(missing) > 0 {
		return BackupReadiness{
			Enabled:   true,
			Status:    "SKIP",
			Readiness: "INCOMPLETE",
			Missing:   missing,
		}
	}
	return BackupReadiness{
		Enabled:   true,
		Status:    "PASS",
		Readiness: "COMPLETE",
	}
}

func validateOptionalPaths(p *Profile) error {
	siteMap := make(map[string]Site, len(p.Sites))
	for _, s := range p.Sites {
		siteMap[s.ID] = s
	}

	if p.Backup.Enabled {
		blSiteIDs := make([]string, 0, len(p.Backup.Links))
		for _, bl := range p.Backup.Links {
			blSiteIDs = append(blSiteIDs, bl.SiteID)
		}
		if err := requireUnique(blSiteIDs, "Backup link site IDs"); err != nil {
			return err
		}

		primaryPriorities := make(map[string]*int, len(p.SiteLinks))
		primaryEndpoints := map[string]struct{}{p.Hub.PublicEndpoint: {}}
		for _, s := range p.Sites {
			primaryEndpoints[s.PublicEndpoint] = struct{}{}
			for _, u := range s.Uplinks {
				primaryEndpoints[u.PublicEndpoint] = struct{}{}
			}
		}
		for _, l := range p.SiteLinks {
			primaryPriorities[l.SiteID] = l.RoutePriority
			if l.OuterPath.SourceIP != "" {
				primaryEndpoints[l.OuterPath.SourceIP] = struct{}{}
			}
			if l.OuterPath.Gateway != "" {
				primaryEndpoints[l.OuterPath.Gateway] = struct{}{}
			}
		}

		for _, bl := range p.Backup.Links {
			site, ok := siteMap[bl.SiteID]
			if !ok {
				return profileErr("A backup link references an unknown site.")
			}
			if bl.PublicEndpoint != "" {
				if _, dup := primaryEndpoints[bl.PublicEndpoint]; dup {
					return profileErr("Backup endpoints must differ from primary endpoints.")
				}
			}
			if bl.TrackTarget != "" {
				addr, err := netip.ParseAddr(bl.TrackTarget)
				if err != nil || !addr.Is4() || addrInAny(addr, NonUnicastLANs) {
					return profileErr("Backup Track targets must be unicast IPv4 addresses.")
				}
			}
			if bl.LocalUplinkID != "" {
				found := false
				for _, u := range site.Uplinks {
					if u.ID == bl.LocalUplinkID {
						found = true
						break
					}
				}
				if !found {
					return profileErr("A backup link references an unknown local uplink.")
				}
			}
			remoteLANs := AuthorizedRemoteLANs(p, bl.SiteID)
			for _, rc := range bl.RemoteCIDRs {
				if !slices.Contains(remoteLANs, rc) {
					return profileErr("Backup route CIDRs exceed the authorized remote LANs.")
				}
			}
			if pp := primaryPriorities[bl.SiteID]; pp != nil && bl.RoutePriority != nil && *bl.RoutePriority <= *pp {
				return profileErr("Backup route priority must be less preferred than primary.")
			}
		}
	}

	if p.Monitoring != nil {
		interval := 15
		timeout := 5
		ttl := 30
		if p.Monitoring.Exporter != nil {
			if p.Monitoring.Exporter.IntervalSeconds != nil {
				interval = *p.Monitoring.Exporter.IntervalSeconds
			}
			if p.Monitoring.Exporter.TimeoutSeconds != nil {
				timeout = *p.Monitoring.Exporter.TimeoutSeconds
			}
			if p.Monitoring.Exporter.TTLSeconds != nil {
				ttl = *p.Monitoring.Exporter.TTLSeconds
			}
		}
		if interval+timeout >= ttl || timeout >= interval {
			return profileErr("Monitoring requires timeout < interval and interval + timeout < TTL.")
		}
		if p.Monitoring.Thresholds != nil {
			for _, f := range []*float64{p.Monitoring.Thresholds.RTTMs, p.Monitoring.Thresholds.JitterMs, p.Monitoring.Thresholds.LossPct} {
				if f != nil && (math.IsNaN(*f) || math.IsInf(*f, 0)) {
					return profileErr("Monitoring thresholds must be finite.")
				}
			}
		}
		for _, pr := range p.Monitoring.Probes {
			if _, ok := siteMap[pr.SiteID]; !ok {
				return profileErr("A monitoring probe references an unknown site.")
			}
			if pr.Path == "backup" && !p.Backup.Enabled && p.Monitoring.Enabled {
				return profileErr("A backup monitoring probe requires an enabled backup gateway.")
			}
		}
	}
	return nil
}
