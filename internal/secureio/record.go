package secureio

import (
	"bytes"
	"encoding/json"
	"regexp"

	"github.com/yikkrrtykj/event-ipsec-hub/internal/manifest"
)

var (
	secretRefRE = regexp.MustCompile(`^file:/etc/ipsecvpn/secrets/[A-Za-z0-9][A-Za-z0-9_.-]{0,95}$`)
	pskHexRE    = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Envelope wraps persisted JSON state with a canonical SHA-256 integrity hash.
type Envelope struct {
	Payload any    `json:"payload"`
	SHA256  string `json:"sha256"`
}

// MarshalRecord encodes a payload inside a SHA-256 verified JSON envelope.
func MarshalRecord(payload any) ([]byte, error) {
	canon, err := manifest.CanonicalJSON(payload)
	if err != nil {
		return nil, Stop("Could not serialize state record.")
	}
	env := Envelope{
		Payload: payload,
		SHA256:  manifest.Digest(canon),
	}
	out, err := manifest.CanonicalJSON(env)
	if err != nil {
		return nil, Stop("Could not serialize state envelope.")
	}
	return out, nil
}

// UnmarshalRecord decodes and verifies an integrity-checked JSON envelope.
func UnmarshalRecord(raw []byte) (any, error) {
	var env map[string]json.RawMessage
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, Stop("A persisted state record is unreadable.")
	}
	payloadRaw, okP := env["payload"]
	shaRaw, okS := env["sha256"]
	if !okP || !okS {
		return nil, Stop("A persisted state record failed its integrity check.")
	}
	var expectedSHA string
	if err := json.Unmarshal(shaRaw, &expectedSHA); err != nil {
		return nil, Stop("A persisted state record failed its integrity check.")
	}
	var payload any
	dec := json.NewDecoder(bytes.NewReader(payloadRaw))
	dec.UseNumber()
	if err := dec.Decode(&payload); err != nil {
		return nil, Stop("A persisted state record is unreadable.")
	}
	canon, err := manifest.CanonicalJSON(payload)
	if err != nil || manifest.Digest(canon) != expectedSHA {
		return nil, Stop("A persisted state record failed its integrity check.")
	}
	return payload, nil
}

// ValidateSecretRef checks that an IKE key reference points inside /etc/ipsecvpn/secrets/.
func ValidateSecretRef(ref string) (string, error) {
	if !secretRefRE.MatchString(ref) {
		return "", Stop("An IKE key reference is outside the protected directory.")
	}
	return ref[len("file:"):], nil
}

// ValidatePSKBytes enforces 64-character lowercase hex PSKs with >=8 distinct characters.
func ValidatePSKBytes(raw []byte) ([]byte, error) {
	trimmed := bytes.TrimSuffix(raw, []byte("\n"))
	if !pskHexRE.Match(trimmed) {
		return nil, Stop("An IKE key must be a 64-character lowercase random hexadecimal value.")
	}
	uniq := make(map[byte]struct{}, 16)
	for _, b := range trimmed {
		uniq[b] = struct{}{}
	}
	if len(uniq) < 8 {
		return nil, Stop("An IKE key must be a 64-character lowercase random hexadecimal value.")
	}
	return trimmed, nil
}
