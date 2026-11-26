package web

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	pbkdf2Iterations = 210_000
	pbkdf2KeyLen     = 32
)

// HashPassword hashes a plaintext password with random 16-byte salt + PBKDF2-HMAC-SHA256.
func HashPassword(password string) (string, error) {
	if len(password) < 8 {
		return "", errors.New("password must be at least 8 characters")
	}
	var salt [16]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return "", err
	}
	dk, err := pbkdf2.Key(sha256.New, password, salt[:], pbkdf2Iterations, pbkdf2KeyLen)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", pbkdf2Iterations, hex.EncodeToString(salt[:]), hex.EncodeToString(dk)), nil
}

// VerifyPassword validates password against a stored PBKDF2-HMAC-SHA256 hash in constant time.
func VerifyPassword(stored, password string) bool {
	parts := strings.Split(stored, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false
	}
	var iter int
	if _, err := fmt.Sscanf(parts[1], "%d", &iter); err != nil || iter < 10_000 {
		return false
	}
	salt, err := hex.DecodeString(parts[2])
	if err != nil {
		return false
	}
	want, err := hex.DecodeString(parts[3])
	if err != nil {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, password, salt, iter, len(want))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

// GenerateRandomPassword creates a high-entropy 16-character initial admin password.
func GenerateRandomPassword() string {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%"
	var b [16]byte
	_, _ = rand.Read(b[:])
	out := make([]byte, len(b))
	for i, v := range b {
		out[i] = alphabet[int(v)%len(alphabet)]
	}
	return string(out)
}

// GenerateTOTPSecret generates a 20-byte base32 TOTP secret (RFC 6238).
func GenerateTOTPSecret() string {
	var raw [20]byte
	_, _ = rand.Read(raw[:])
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw[:])
}

func computeTOTP(secret string, counter uint64) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return "", err
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(buf[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	code := (uint32(sum[off]&0x7f)<<24 |
		uint32(sum[off+1])<<16 |
		uint32(sum[off+2])<<8 |
		uint32(sum[off+3])) % 1_000_000
	return fmt.Sprintf("%06d", code), nil
}

// VerifyTOTP checks a 6-digit TOTP code allowing ±1 30s time step skew.
func VerifyTOTP(secret, code string, now time.Time) bool {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return false
	}
	step := uint64(now.Unix() / 30)
	for _, delta := range []int64{-1, 0, 1} {
		cand := uint64(int64(step) + delta)
		expected, err := computeTOTP(secret, cand)
		if err == nil && subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 {
			return true
		}
	}
	return false
}

// EnsureTLSKeypair loads an existing cert/key or auto-generates an ECDSA P-256 self-signed
// certificate with explicit IP SANs so direct `https://<VPS_IP>:<PORT>` works immediately.
func EnsureTLSKeypair(certPath, keyPath string, extraIPs []string) (tls.Certificate, error) {
	if certPath != "" && keyPath != "" {
		if _, err1 := os.Stat(certPath); err1 == nil {
			if _, err2 := os.Stat(keyPath); err2 == nil {
				return tls.LoadX509KeyPair(certPath, keyPath)
			}
		}
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, _ := rand.Int(rand.Reader, serialLimit)

	ipSet := map[string]net.IP{
		"127.0.0.1": net.ParseIP("127.0.0.1"),
		"::1":       net.ParseIP("::1"),
	}
	for _, raw := range extraIPs {
		if ip := net.ParseIP(strings.TrimSpace(raw)); ip != nil {
			ipSet[ip.String()] = ip
		}
	}
	// Auto-include local non-loopback interface IPs for zero-friction direct IP HTTPS.
	if ifaces, err := net.InterfaceAddrs(); err == nil {
		for _, a := range ifaces {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
				ipSet[ipn.IP.String()] = ipn.IP
			}
		}
	}
	var ips []net.IP
	for _, ip := range ipSet {
		ips = append(ips, ip)
	}

	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "event-ipsec-hub",
			Organization: []string{"event-ipsec-hub V4 Gateway"},
		},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if certPath != "" && keyPath != "" {
		_ = os.MkdirAll(filepath.Dir(certPath), 0o700)
		_ = os.WriteFile(certPath, certPEM, 0o644)
		_ = os.WriteFile(keyPath, keyPEM, 0o600)
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

// BruteForceGuard tracks failed login attempts per IP and temporarily bans abusive sources.
type BruteForceGuard struct {
	mu           sync.Mutex
	maxFailures  int
	window       time.Duration
	banDuration  time.Duration
	failures     map[string][]time.Time
	bannedUntil  map[string]time.Time
}

func NewBruteForceGuard(maxFailures int, window, banDuration time.Duration) *BruteForceGuard {
	return &BruteForceGuard{
		maxFailures: maxFailures,
		window:      window,
		banDuration: banDuration,
		failures:    make(map[string][]time.Time),
		bannedUntil: make(map[string]time.Time),
	}
}

func (g *BruteForceGuard) IsBanned(ip string, now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	until, ok := g.bannedUntil[ip]
	if !ok {
		return false
	}
	if now.After(until) {
		delete(g.bannedUntil, ip)
		return false
	}
	return true
}

func (g *BruteForceGuard) RecordFailure(ip string, now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	cutoff := now.Add(-g.window)
	list := g.failures[ip]
	keep := list[:0]
	for _, ts := range list {
		if ts.After(cutoff) {
			keep = append(keep, ts)
		}
	}
	keep = append(keep, now)
	g.failures[ip] = keep
	if len(keep) >= g.maxFailures {
		g.bannedUntil[ip] = now.Add(g.banDuration)
		delete(g.failures, ip)
		return true
	}
	return false
}

func (g *BruteForceGuard) Reset(ip string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.failures, ip)
	delete(g.bannedUntil, ip)
}

// IsIPAllowed checks remote IP against an allowlist of IPs/CIDRs (empty allowlist allows all; loopback always allowed).
func IsIPAllowed(remoteAddr string, allowlist []string) bool {
	ipStr := extractClientIP(remoteAddr)
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return false
	}
	if addr.IsLoopback() || len(allowlist) == 0 {
		return true
	}
	for _, entry := range allowlist {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			if pref, err := netip.ParsePrefix(entry); err == nil && pref.Contains(addr) {
				return true
			}
		} else {
			if a, err := netip.ParseAddr(entry); err == nil && a == addr {
				return true
			}
		}
	}
	return false
}

func extractClientIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil {
		return host
	}
	return remoteAddr
}
