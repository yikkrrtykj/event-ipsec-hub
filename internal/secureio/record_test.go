package secureio

import (
	"bytes"
	"strings"
	"testing"
)

func TestRecordEnvelopeIntegrity(t *testing.T) {
	payload := map[string]any{"event": "demo", "count": 3}
	raw, err := MarshalRecord(payload)
	if err != nil {
		t.Fatalf("MarshalRecord: %v", err)
	}
	decoded, err := UnmarshalRecord(raw)
	if err != nil {
		t.Fatalf("UnmarshalRecord: %v", err)
	}
	m := decoded.(map[string]any)
	if m["event"] != "demo" {
		t.Fatalf("unexpected decoded payload: %+v", m)
	}

	tampered := bytes.ReplaceAll(raw, []byte("demo"), []byte("evil"))
	if _, err := UnmarshalRecord(tampered); err == nil {
		t.Fatal("expected integrity check failure for tampered record")
	}
}

func TestSecretRefAndPSKValidation(t *testing.T) {
	p, err := ValidateSecretRef("file:/etc/ipsecvpn/secrets/ob-venue-1.psk")
	if err != nil || p != "/etc/ipsecvpn/secrets/ob-venue-1.psk" {
		t.Fatalf("expected valid secret ref, got path=%q err=%v", p, err)
	}
	if _, err := ValidateSecretRef("file:/tmp/bad.psk"); err == nil {
		t.Fatal("expected rejection outside protected directory")
	}

	good := []byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n")
	if out, err := ValidatePSKBytes(good); err != nil || len(out) != 64 {
		t.Fatalf("expected valid PSK, got len=%d err=%v", len(out), err)
	}
	weak := []byte(strings.Repeat("a", 64))
	if _, err := ValidatePSKBytes(weak); err == nil {
		t.Fatal("expected rejection for low-entropy PSK")
	}
}
