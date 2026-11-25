package sa

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yikkrrtykj/event-ipsec-hub/internal/manifest"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/profile"
)

func TestParseVICIRouteBasedAndPerPairCorrelation(t *testing.T) {
	p, err := profile.LoadProfile(filepath.Join("..", "..", "config", "esports-multi-ob-hillstone.example.yaml"))
	if err != nil {
		t.Fatalf("load profile: %v", err)
	}
	// Give ob-venue-2 (per_pair) 2 server CIDRs so it spawns 2 CHILD SAs
	p.TrafficPolicy.AllowedSitePairs[1].BCIDRs = []string{"10.100.10.0/24", "10.100.20.0/24"}
	m, err := manifest.BuildManifest(p)
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}

	var ob1, ob2 manifest.Link
	for _, l := range m.Links {
		if l.SiteID == "ob-venue-1" {
			ob1 = l
		}
		if l.SiteID == "ob-venue-2" {
			ob2 = l
		}
	}

	// 1. route_based wildcard 0.0.0.0/0 acceptance and mismatch rejection
	rbChild := map[string]any{
		"name":         ob1.Child(),
		"uniqueid":     "21",
		"reqid":        "9",
		"state":        "INSTALLED",
		"protocol":     "ESP",
		"mode":         "TUNNEL",
		"spi-in":       "11223344",
		"spi-out":      "55667788",
		"if-id-in":     fmt.Sprintf("%08x", ob1.IfID),
		"if-id-out":    fmt.Sprintf("%08x", ob1.IfID),
		"local-ts":     []string{"0.0.0.0/0"},
		"remote-ts":    []string{"0.0.0.0/0"},
		"encr-alg":     "AES_CBC",
		"encr-keysize": "256",
		"integ-alg":    "HMAC_SHA2_256_128",
		"bytes-in":     "0",
		"bytes-out":    "0",
		"packets-in":   "0",
		"packets-out":  "0",
	}
	rbEvent := map[string]any{
		ob1.Name(): map[string]any{
			"version":       "2",
			"uniqueid":      "2",
			"state":         "ESTABLISHED",
			"local-host":    ob1.Source,
			"remote-host":   ob1.Peer,
			"local-id":      ob1.LocalID,
			"remote-id":     ob1.RemoteID,
			"initiator-spi": "1122334455667788",
			"responder-spi": "8877665544332211",
			"encr-alg":      "AES_CBC",
			"encr-keysize":  "256",
			"integ-alg":     "HMAC_SHA2_256_128",
			"prf-alg":       "PRF_HMAC_SHA2_256",
			"dh-group":      "MODP_2048",
			"child-sas":     map[string]any{ob1.Child(): rbChild},
		},
	}
	snap, err := ParseVICI([]map[string]any{rbEvent}, m)
	if err != nil {
		t.Fatalf("ParseVICI route_based: %v", err)
	}
	if snap.Get(ob1.Name()).Child.UniqueID != 21 {
		t.Fatalf("unexpected child uniqueid: %+v", snap.Get(ob1.Name()))
	}

	rbChild["remote-ts"] = []string{"10.101.10.0/24"}
	if _, err := ParseVICI([]map[string]any{rbEvent}, m); err == nil || !strings.Contains(err.Error(), "CHILD selector") {
		t.Fatalf("expected CHILD selector mismatch, got %v", err)
	}

	// 2. per_pair multi-child correlation + count aggregation
	specs := ob2.ChildSpecs()
	if len(specs) != 2 {
		t.Fatalf("expected 2 per_pair child specs, got %d", len(specs))
	}
	children := make(map[string]any)
	var states []State
	var policies []PolicyEntry
	for idx, sp := range specs {
		reqID := uint32(30 + idx)
		spiIn := uint32(0x11000001 + idx)
		spiOut := uint32(0x22000001 + idx)
		children[sp.Name] = map[string]any{
			"name":         sp.Name,
			"uniqueid":     fmt.Sprintf("%d", 50+idx),
			"reqid":        fmt.Sprintf("%d", reqID),
			"state":        "INSTALLED",
			"protocol":     "ESP",
			"mode":         "TUNNEL",
			"spi-in":       fmt.Sprintf("%08x", spiIn),
			"spi-out":      fmt.Sprintf("%08x", spiOut),
			"if-id-in":     fmt.Sprintf("%08x", ob2.IfID),
			"if-id-out":    fmt.Sprintf("%08x", ob2.IfID),
			"local-ts":     sp.LocalTS,
			"remote-ts":    sp.RemoteTS,
			"encr-alg":     "AES_CBC",
			"encr-keysize": "256",
			"integ-alg":    "HMAC_SHA2_256_128",
			"bytes-in":     "10",
			"bytes-out":    "10",
			"packets-in":   "10",
			"packets-out":  "10",
		}
		inSt := State{ob2.Peer, ob2.Source, spiIn, reqID, ob2.IfID}
		outSt := State{ob2.Source, ob2.Peer, spiOut, reqID, ob2.IfID}
		states = append(states, inSt, outSt)
		spiInCopy, spiOutCopy := spiIn, spiOut
		policies = append(policies,
			PolicyEntry{Policy{sp.LocalTS[0], sp.RemoteTS[0], "out", outSt.Source, outSt.Destination, reqID, ob2.IfID}, &spiOutCopy},
			PolicyEntry{Policy{sp.RemoteTS[0], sp.LocalTS[0], "in", inSt.Source, inSt.Destination, reqID, ob2.IfID}, &spiInCopy},
			PolicyEntry{Policy{sp.RemoteTS[0], sp.LocalTS[0], "fwd", inSt.Source, inSt.Destination, reqID, ob2.IfID}, &spiInCopy},
		)
	}
	ppEvent := map[string]any{
		ob2.Name(): map[string]any{
			"version":       "2",
			"uniqueid":      "9",
			"state":         "ESTABLISHED",
			"local-host":    ob2.Source,
			"remote-host":   ob2.Peer,
			"local-id":      ob2.LocalID,
			"remote-id":     ob2.RemoteID,
			"initiator-spi": "1122334455667788",
			"responder-spi": "8877665544332211",
			"encr-alg":      "AES_CBC",
			"encr-keysize":  "256",
			"integ-alg":     "HMAC_SHA2_256_128",
			"prf-alg":       "PRF_HMAC_SHA2_256",
			"dh-group":      "MODP_2048",
			"child-sas":     children,
		},
	}
	snap2, err := ParseVICI([]map[string]any{ppEvent}, m)
	if err != nil {
		t.Fatalf("ParseVICI per_pair: %v", err)
	}
	if snap2.Get(ob2.Name()).Child.Counts != [4]uint64{20, 20, 20, 20} {
		t.Fatalf("expected aggregated counts [20 20 20 20], got %v", snap2.Get(ob2.Name()).Child.Counts)
	}
	if err := Correlate(snap2, m, states, policies); err != nil {
		t.Fatalf("Correlate per_pair: %v", err)
	}
}
