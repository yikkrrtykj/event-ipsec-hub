package alert

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/yikkrrtykj/event-ipsec-hub/internal/secureio"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/storage"
)

const DefaultAlertChannelFile = "/etc/ipsecvpn/secrets/feishu-channel.json"

// FeishuChannelConfig stores the persisted Feishu notification channel outside SQLite (root 0600).
type FeishuChannelConfig struct {
	Enabled    bool   `json:"enabled"`
	WebhookURL string `json:"webhook_url"`
	Secret     string `json:"secret,omitempty"`
}

// MaskFeishuURL returns a safe display summary of an official Feishu webhook URL without leaking the full token.
func MaskFeishuURL(rawURL string) string {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Path == "" {
		return ""
	}
	parts := strings.Split(strings.TrimSuffix(u.Path, "/"), "/")
	token := parts[len(parts)-1]
	if len(token) > 10 {
		token = token[:4] + "****" + token[len(token)-4:]
	} else if len(token) > 0 {
		token = "****"
	}
	parts[len(parts)-1] = token
	return fmt.Sprintf("%s://%s%s", u.Scheme, u.Host, strings.Join(parts, "/"))
}

// SaveFeishuChannel atomically writes the channel config to a mode-0600 file (never inside SQLite).
func SaveFeishuChannel(path string, cfg FeishuChannelConfig, allowLoopback bool) error {
	if path == "" {
		path = DefaultAlertChannelFile
	}
	if cfg.WebhookURL != "" {
		if _, err := ValidateFeishuTarget(cfg.WebhookURL, allowLoopback); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// LoadFeishuChannel loads the persisted Feishu channel file if present.
func LoadFeishuChannel(path string) (FeishuChannelConfig, bool, error) {
	if path == "" {
		path = DefaultAlertChannelFile
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return FeishuChannelConfig{}, false, nil
		}
		return FeishuChannelConfig{}, false, err
	}
	var cfg FeishuChannelConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return FeishuChannelConfig{}, false, err
	}
	return cfg, true, nil
}

// NewFeishuSender builds a live alert.Sender backed by DeliverFeishu.
func NewFeishuSender(cfg FeishuChannelConfig, client *http.Client) Sender {
	if !cfg.Enabled || strings.TrimSpace(cfg.WebhookURL) == "" {
		return nil
	}
	urlStr := strings.TrimSpace(cfg.WebhookURL)
	sec := []byte(cfg.Secret)
	return SenderFunc(func(ctx context.Context, rec storage.AlertHistoryRecord) error {
		return DeliverFeishu(ctx, client, urlStr, sec, rec.Message)
	})
}

var (
	feishuPathRE = regexp.MustCompile(`^/open-apis/bot/v2/hook/[A-Za-z0-9-]{20,80}$`)
	loopbackRE   = regexp.MustCompile(`^127\.0\.0\.1:\d{4,5}$`)
)

// FeishuSignature computes Feishu custom bot webhook v2 signature:
// base64(HMAC-SHA256(key = "<timestamp>\n<secret>", data = "")).
func FeishuSignature(timestamp int64, secret []byte) string {
	key := append([]byte(strconv.FormatInt(timestamp, 10)+"\n"), secret...)
	mac := hmac.New(sha256.New, key)
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// ValidateFeishuTarget validates an official Feishu webhook endpoint (or explicit loopback mock in lab mode).
func ValidateFeishuTarget(rawURL string, allowLoopbackMock bool) (*url.URL, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, secureio.Stop("The Feishu target URL is invalid.")
	}
	if u.Scheme == "https" && u.Host == "open.feishu.cn" && u.RawQuery == "" && u.Fragment == "" && feishuPathRE.MatchString(u.Path) {
		return u, nil
	}
	if allowLoopbackMock && u.Scheme == "http" && loopbackRE.MatchString(u.Host) && u.RawQuery == "" && u.Fragment == "" {
		return u, nil
	}
	return nil, secureio.Stop("The Feishu target is not an official robot endpoint.")
}

// DeliverFeishu sends a signed text message to a Feishu robot webhook with bounded 3x retry on 429/5xx.
func DeliverFeishu(ctx context.Context, client *http.Client, targetURL string, secret []byte, message string) error {
	if client == nil {
		client = &http.Client{Timeout: 3 * time.Second}
	}
	ts := time.Now().Unix()
	payload := map[string]any{
		"timestamp": strconv.FormatInt(ts, 10),
		"msg_type":  "text",
		"content":   map[string]any{"text": message},
	}
	if len(secret) > 0 {
		payload["sign"] = FeishuSignature(ts, secret)
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err == nil {
			raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
			_ = resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				var reply map[string]any
				if json.Unmarshal(raw, &reply) == nil {
					if isZeroCode(reply["code"]) || isZeroCode(reply["StatusCode"]) {
						return nil
					}
				}
				return fmt.Errorf("feishu rejected message: status=%d", resp.StatusCode)
			}
			lastErr = fmt.Errorf("feishu http status %d", resp.StatusCode)
			if resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode < 500 {
				return lastErr
			}
		} else {
			lastErr = err
		}
		if attempt < 2 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(150*(1<<attempt)) * time.Millisecond):
			}
		}
	}
	return lastErr
}

func isZeroCode(v any) bool {
	switch tv := v.(type) {
	case float64:
		return tv == 0
	case int:
		return tv == 0
	case json.Number:
		n, err := tv.Int64()
		return err == nil && n == 0
	default:
		return false
	}
}

// DeliverWebhook sends a structured JSON alert payload to a generic HTTPS/HTTP webhook.
func DeliverWebhook(ctx context.Context, client *http.Client, targetURL, bearerToken string, payload any) error {
	if client == nil {
		client = &http.Client{Timeout: 3 * time.Second}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+bearerToken)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook http status %d", resp.StatusCode)
	}
	return nil
}
