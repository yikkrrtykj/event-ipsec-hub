package telemetry

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yikkrrtykj/event-ipsec-hub/internal/secureio"
)

// FrameBytes matches Python ipsecvpn/monitoring/udp.py wire format exactly (103 ASCII bytes).
const FrameBytes = 103

// BuildUDPFrame constructs an authenticated 103-byte echo probe or reply frame:
// "<kind>/<16-hex-nonce>/<02d-seq>/<016d-ms>/<64-hex-hmac-sha256>".
func BuildUDPFrame(key []byte, kind, nonce string, seq int, tsMs int64) []byte {
	content := fmt.Sprintf("%s/%s/%02d/%016d", kind, nonce, seq, tsMs)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(content))
	sig := hex.EncodeToString(mac.Sum(nil))
	return []byte(content + "/" + sig)
}

type ParsedFrame struct {
	Nonce string
	Seq   int
	TsMs  int64
}

// ParseUDPFrame validates length, timestamp skew (±5s), sequence bounds (0..3), and HMAC-SHA256.
func ParseUDPFrame(packet, key []byte, expectedKind string, now time.Time) (*ParsedFrame, bool) {
	if len(packet) != FrameBytes {
		return nil, false
	}
	parts := strings.Split(string(packet), "/")
	if len(parts) != 5 || parts[0] != expectedKind {
		return nil, false
	}
	nonce := parts[1]
	if rawNonce, err := hex.DecodeString(nonce); err != nil || len(rawNonce) != 8 {
		return nil, false
	}
	seq, err := strconv.Atoi(parts[2])
	if err != nil || seq < 0 || seq >= 4 {
		return nil, false
	}
	tsMs, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil {
		return nil, false
	}
	nowSec := float64(now.UnixNano()) / 1e9
	if math.Abs(nowSec-float64(tsMs)/1000.0) > 5.0 {
		return nil, false
	}
	expected := BuildUDPFrame(key, expectedKind, nonce, seq, tsMs)
	if !hmac.Equal(packet, expected) {
		return nil, false
	}
	return &ParsedFrame{Nonce: nonce, Seq: seq, TsMs: tsMs}, true
}

// ValidateLANEndpoint ensures a UDP probe endpoint is an explicit non-loopback unicast IPv4 + unprivileged port.
func ValidateLANEndpoint(address string, port int) (string, error) {
	addr, err := netip.ParseAddr(address)
	if err != nil || !addr.Is4() || addr.IsUnspecified() || addr.IsLoopback() || addr.IsMulticast() || port < 1024 || port >= 65535 {
		return "", secureio.Stop("A UDP test endpoint must be an explicit LAN IPv4 address and port.")
	}
	b := addr.As4()
	if b[0] >= 240 {
		return "", secureio.Stop("A UDP test endpoint must be an explicit LAN IPv4 address and port.")
	}
	return fmt.Sprintf("%s:%d", addr.String(), port), nil
}

// UDPResponder answers authenticated probe frames from one explicit peer with replay & rate limits.
type UDPResponder struct {
	mu   sync.Mutex
	key  []byte
	peer string
	seen map[ParsedFrame]time.Time
	sent []time.Time
}

func NewUDPResponder(key []byte, peerAddr string) *UDPResponder {
	return &UDPResponder{
		key:  key,
		peer: peerAddr,
		seen: make(map[ParsedFrame]time.Time),
	}
}

func (r *UDPResponder) Answer(source string, packet []byte, now time.Time) []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	if source != r.peer {
		return nil
	}
	req, ok := ParseUDPFrame(packet, r.key, "q", now)
	if !ok {
		return nil
	}
	cutoff := now.Add(-time.Second)
	keep := r.sent[:0]
	for _, ts := range r.sent {
		if ts.After(cutoff) {
			keep = append(keep, ts)
		}
	}
	r.sent = keep
	for k, until := range r.seen {
		if !until.After(now) {
			delete(r.seen, k)
		}
	}
	if _, dup := r.seen[*req]; dup || len(r.sent) >= 8 || len(r.seen) >= 80 {
		return nil
	}
	r.seen[*req] = now.Add(10 * time.Second)
	r.sent = append(r.sent, now)
	return BuildUDPFrame(r.key, "r", req.Nonce, req.Seq, req.TsMs)
}

// ServeUDPResponder binds localAddr and responds to peerAddr until ctx is cancelled or duration expires.
func ServeUDPResponder(ctx context.Context, key []byte, localAddr, peerAddr string, onReady func()) error {
	laddr, err := net.ResolveUDPAddr("udp4", localAddr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp4", laddr)
	if err != nil {
		return err
	}
	defer conn.Close()
	if onReady != nil {
		onReady()
	}
	responder := NewUDPResponder(key, peerAddr)
	buf := make([]byte, FrameBytes+16)
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		_ = conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return err
		}
		if ans := responder.Answer(src.String(), buf[:n], time.Now()); ans != nil {
			_, _ = conn.WriteToUDP(ans, src)
		}
	}
}

type UDPReceipt struct {
	RequestSHA256 string   `json:"request_sha256"`
	ReplySHA256   string   `json:"reply_sha256"`
	RTT           *float64 `json:"rtt"`
	SentAt        float64  `json:"sent_at"`
	CompletedAt   float64  `json:"completed_at"`
}

// ProbeUDP sends bounded (1..4) authenticated UDP echo frames from localAddr to peerAddr.
func ProbeUDP(key []byte, localAddr, peerAddr string, count int, timeout time.Duration) ([]UDPReceipt, error) {
	if count < 1 || count > 4 || timeout < 100*time.Millisecond || timeout > 2*time.Second {
		return nil, secureio.Stop("UDP test window exceeds its configured safety limits.")
	}
	laddr, err := net.ResolveUDPAddr("udp4", localAddr)
	if err != nil {
		return nil, err
	}
	raddr, err := net.ResolveUDPAddr("udp4", peerAddr)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp4", laddr, raddr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	var nonceBytes [8]byte
	_, _ = rand.Read(nonceBytes[:])
	nonce := hex.EncodeToString(nonceBytes[:])

	receipts := make([]UDPReceipt, 0, count)
	buf := make([]byte, FrameBytes+16)
	for seq := 0; seq < count; seq++ {
		tsMs := time.Now().UnixMilli()
		pkt := BuildUDPFrame(key, "q", nonce, seq, tsMs)
		exp := BuildUDPFrame(key, "r", nonce, seq, tsMs)
		start := time.Now()
		_, _ = conn.Write(pkt)
		deadline := start.Add(timeout)
		var rttPtr *float64
		for time.Now().Before(deadline) {
			_ = conn.SetReadDeadline(deadline)
			n, err := conn.Read(buf)
			if err != nil {
				break
			}
			if hmac.Equal(buf[:n], exp) {
				v := time.Since(start).Seconds()
				rttPtr = &v
				break
			}
		}
		reqHash := sha256.Sum256(pkt)
		repHash := sha256.Sum256(exp)
		receipts = append(receipts, UDPReceipt{
			RequestSHA256: hex.EncodeToString(reqHash[:]),
			ReplySHA256:   hex.EncodeToString(repHash[:]),
			RTT:           rttPtr,
			SentAt:        float64(tsMs) / 1000.0,
			CompletedAt:   float64(time.Now().UnixNano()) / 1e9,
		})
		if wait := 125*time.Millisecond - time.Since(start); wait > 0 && seq+1 < count {
			time.Sleep(wait)
		}
	}
	return receipts, nil
}
