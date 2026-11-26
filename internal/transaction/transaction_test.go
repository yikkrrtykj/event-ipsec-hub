package transaction

import (
	"path/filepath"
	"testing"

	"github.com/yikkrrtykj/event-ipsec-hub/internal/live"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/profile"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/secureio"
)

func TestActiveRecordRoundTripPreservesIntegerTypes(t *testing.T) {
	p, err := profile.LoadProfile(filepath.Join("..", "..", "config", "esports-multi-ob-hillstone.example.yaml"))
	if err != nil {
		t.Fatalf("LoadProfile: %v", err)
	}
	orig := &live.ActiveRecord{
		Profile:      p.Raw,
		Keys:         map[string]string{"server-core": "deadbeef"},
		NFTSHA256:    "abc123",
		HostBaseline: map[string]string{"ssh": "ok"},
	}
	raw, err := secureio.MarshalRecord(orig)
	if err != nil {
		t.Fatalf("MarshalRecord: %v", err)
	}
	unmarshaled, err := secureio.UnmarshalRecord(raw)
	if err != nil {
		t.Fatalf("UnmarshalRecord: %v", err)
	}
	decoded, err := decodeAs[live.ActiveRecord](unmarshaled)
	if err != nil {
		t.Fatalf("decodeAs[live.ActiveRecord]: %v", err)
	}
	m, parsed, err := live.ManifestFromActive(decoded)
	if err != nil {
		t.Fatalf("ManifestFromActive failed on round-tripped ActiveRecord: %v", err)
	}
	if m == nil || parsed == nil || len(m.Links) != 3 {
		t.Fatalf("unexpected decoded manifest: m=%v parsed=%v", m, parsed)
	}
}
