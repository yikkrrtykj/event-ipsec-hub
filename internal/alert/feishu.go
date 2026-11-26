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

// NewFeishuSender builds a live alert.Sender backed by rich Feishu interactive cards.
func NewFeishuSender(cfg FeishuChannelConfig, client *http.Client) Sender {
	if !cfg.Enabled || strings.TrimSpace(cfg.WebhookURL) == "" {
		return nil
	}
	urlStr := strings.TrimSpace(cfg.WebhookURL)
	sec := []byte(cfg.Secret)
	return SenderFunc(func(ctx context.Context, rec storage.AlertHistoryRecord) error {
		return DeliverFeishuCard(ctx, client, urlStr, sec, BuildAlertFeishuCard(rec))
	})
}

var beijingTZ = time.FixedZone("Asia/Shanghai", 8*3600)

func formatBeijingTime(t time.Time) string {
	if t.IsZero() {
		t = time.Now()
	}
	return t.In(beijingTZ).Format("2006-01-02 15:04:05") + " (北京时间)"
}

func alertRuleTitleZH(name string) string {
	switch name {
	case "IpsecChildDown":
		return "IPsec 数据隧道断开"
	case "IpsecIkeDown":
		return "IKE 认证会话断开"
	case "LanProbeDown":
		return "内网端到端探针不通"
	case "OuterWanLossHigh":
		return "外层公网丢包过高"
	case "LanProbeLossHigh":
		return "内网探针丢包过高"
	case "XfrmErrorSpike":
		return "加解密 / MTU 异常突增"
	case "FrequentRekeys":
		return "隧道频繁重协商抖动"
	default:
		if name == "" {
			return "VPN 链路事件"
		}
		return name
	}
}

func causeLabelZH(code string) string {
	switch code {
	case "ISP_OUTER_DEGRADED":
		return "公网线路异常"
	case "IPSEC_SA_EVENT":
		return "隧道协商异常"
	case "TUNNEL_BLACKHOLE_OR_ASYMMETRIC":
		return "路由 / 黑洞异常"
	case "XFRM_CRYPTO_OR_MTU_DROP":
		return "加解密 / MTU 异常"
	case "ACL_POLICY_DROP":
		return "策略拦截"
	case "VPN_HEALTHY_APP_SUSPECT":
		return "VPN 链路正常"
	case "OBSERVATION_UNVERIFIED":
		return "暂未检测到有效数据"
	default:
		if code == "" {
			return "-"
		}
		return code
	}
}

func causeHintZH(code, status string) string {
	if status == "RECOVERED" {
		return "链路已恢复正常并验证通过，无需人工干预。"
	}
	if status == "DATA_UNAVAILABLE" {
		return "采集端暂时无法获取完整遥测数据，请检查 Agent 或 strongSwan 运行状态。"
	}
	switch code {
	case "ISP_OUTER_DEGRADED":
		return "外层公网延迟或丢包异常，建议排查运营商线路，必要时在控制台执行主备切换。"
	case "IPSEC_SA_EVENT":
		return "外层公网正常但隧道异常，建议检查对端防火墙状态，或在控制台「概览」点击该站点「重连」。"
	case "TUNNEL_BLACKHOLE_OR_ASYMMETRIC":
		return "隧道已建立但内网不可达，重点核查对端安全策略、静态路由及 NAT 豁免配置。"
	case "XFRM_CRYPTO_OR_MTU_DROP":
		return "检测到加解密或 MTU 异常丢包，建议检查两端加密提议一致性与 MSS/MTU 设置。"
	case "ACL_POLICY_DROP":
		return "流量被网关隔离策略拦截，请核对「VPN 通道 → 站点互通策略」放行网段。"
	default:
		return "请登录 VPN 网关控制台「链路监控」与「事件日志」查看详细波形与记录。"
	}
}

func sourceLabelZH(src string) string {
	switch src {
	case "self_hosted_hub", "":
		return "自建主网关"
	case "cloud_backup_vpn":
		return "云备网关"
	default:
		return src
	}
}

// BuildTestFeishuCard builds a rich blue interactive Feishu card for webhook connectivity tests.
func BuildTestFeishuCard(operator, hostLabel, customNote string, now time.Time) map[string]any {
	if strings.TrimSpace(operator) == "" {
		operator = "admin"
	}
	if strings.TrimSpace(hostLabel) == "" {
		if hn, err := os.Hostname(); err == nil && hn != "" {
			hostLabel = hn
		} else {
			hostLabel = "event-ipsec-hub"
		}
	}
	detail := "**告警分级说明**\n" +
		"• 🔴 **严重告警**（红卡）：IPsec / IKE 隧道中断、内网端到端探针不通\n" +
		"• 🟠 **链路告警**（橙卡）：公网 / 内网丢包过高、加解密异常、频繁重协商\n" +
		"• 🟢 **故障恢复**（绿卡）：链路恢复正常并验证通过后自动推送"
	if strings.TrimSpace(customNote) != "" {
		detail = "**附加说明**\n" + strings.TrimSpace(customNote) + "\n\n" + detail
	}
	return map[string]any{
		"config": map[string]any{
			"wide_screen_mode": true,
			"enable_forward":   true,
		},
		"header": map[string]any{
			"template": "blue",
			"title": map[string]any{
				"tag":     "plain_text",
				"content": "🔔 VPN 网关飞书告警通道测试成功",
			},
		},
		"elements": []any{
			map[string]any{
				"tag": "div",
				"fields": []any{
					map[string]any{"is_short": true, "text": map[string]any{"tag": "lark_md", "content": "**通道状态**\n✅ 正常连通"}},
					map[string]any{"is_short": true, "text": map[string]any{"tag": "lark_md", "content": fmt.Sprintf("**触发操作人**\n`%s`", operator)}},
					map[string]any{"is_short": true, "text": map[string]any{"tag": "lark_md", "content": fmt.Sprintf("**网关主机**\n`%s`", hostLabel)}},
					map[string]any{"is_short": true, "text": map[string]any{"tag": "lark_md", "content": fmt.Sprintf("**推送时间**\n%s", formatBeijingTime(now))}},
				},
			},
			map[string]any{"tag": "hr"},
			map[string]any{
				"tag":  "div",
				"text": map[string]any{"tag": "lark_md", "content": detail},
			},
			map[string]any{"tag": "hr"},
			map[string]any{
				"tag": "note",
				"elements": []any{
					map[string]any{"tag": "plain_text", "content": "event-ipsec-hub · IPsec VPN 中心网关监控引擎"},
				},
			},
		},
	}
}

// BuildAlertFeishuCard builds a color-coded interactive Feishu card for live VPN alerts and recoveries.
func BuildAlertFeishuCard(rec storage.AlertHistoryRecord) map[string]any {
	ruleZH := alertRuleTitleZH(rec.AlertName)
	template := "orange"
	title := fmt.Sprintf("⚠️ VPN 链路告警 · %s", ruleZH)
	statusText := "触发中 (FIRING)"
	sevText := "警告 (WARNING)"

	switch strings.ToLower(rec.Severity) {
	case "critical":
		sevText = "严重 (CRITICAL)"
	case "info":
		sevText = "恢复 / 通知 (INFO)"
	}

	switch rec.Status {
	case "RECOVERED":
		template = "green"
		title = fmt.Sprintf("✅ VPN 告警已恢复 · %s", ruleZH)
		statusText = "已恢复 (RECOVERED)"
	case "DATA_UNAVAILABLE":
		template = "yellow"
		title = fmt.Sprintf("📡 监控数据暂不可用 · %s", ruleZH)
		statusText = "数据暂不可用"
	default:
		if strings.EqualFold(rec.Severity, "critical") {
			template = "red"
			title = fmt.Sprintf("🚨 VPN 严重告警 · %s", ruleZH)
		}
	}

	evTime := time.Now()
	if rec.TsMs > 0 {
		evTime = time.UnixMilli(rec.TsMs)
	}
	siteText := rec.SiteID
	if siteText == "" {
		siteText = "-"
	}

	var diagSummary string
	for _, line := range strings.Split(rec.Message, "\n") {
		if strings.HasPrefix(line, "根因定界:") || strings.HasPrefix(line, "根因定界：") {
			diagSummary = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(line, "根因定界:"), "根因定界："))
			break
		}
	}
	if diagSummary == "" {
		diagSummary = causeLabelZH(rec.RootCause)
	}
	hint := causeHintZH(rec.RootCause, rec.Status)

	return map[string]any{
		"config": map[string]any{
			"wide_screen_mode": true,
			"enable_forward":   true,
		},
		"header": map[string]any{
			"template": template,
			"title": map[string]any{
				"tag":     "plain_text",
				"content": title,
			},
		},
		"elements": []any{
			map[string]any{
				"tag": "div",
				"fields": []any{
					map[string]any{"is_short": true, "text": map[string]any{"tag": "lark_md", "content": fmt.Sprintf("**告警状态**\n%s", statusText)}},
					map[string]any{"is_short": true, "text": map[string]any{"tag": "lark_md", "content": fmt.Sprintf("**告警级别**\n%s", sevText)}},
					map[string]any{"is_short": true, "text": map[string]any{"tag": "lark_md", "content": fmt.Sprintf("**关联站点**\n`%s`", siteText)}},
					map[string]any{"is_short": true, "text": map[string]any{"tag": "lark_md", "content": fmt.Sprintf("**网关来源**\n%s", sourceLabelZH(rec.Source))}},
					map[string]any{"is_short": true, "text": map[string]any{"tag": "lark_md", "content": fmt.Sprintf("**故障定界**\n%s", causeLabelZH(rec.RootCause))}},
					map[string]any{"is_short": true, "text": map[string]any{"tag": "lark_md", "content": fmt.Sprintf("**触发时间**\n%s", formatBeijingTime(evTime))}},
				},
			},
			map[string]any{"tag": "hr"},
			map[string]any{
				"tag": "div",
				"text": map[string]any{
					"tag":     "lark_md",
					"content": fmt.Sprintf("**诊断详情**\n%s\n\n**处置建议**\n%s", diagSummary, hint),
				},
			},
			map[string]any{"tag": "hr"},
			map[string]any{
				"tag": "note",
				"elements": []any{
					map[string]any{
						"tag":     "plain_text",
						"content": fmt.Sprintf("规则: %s  |  定界码: %s  |  event-ipsec-hub VPN 网关", nonEmpty(rec.AlertName, "-"), nonEmpty(rec.RootCause, "-")),
					},
				},
			},
		},
	}
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
	return postFeishuPayload(ctx, client, targetURL, secret, map[string]any{
		"msg_type": "text",
		"content":  map[string]any{"text": message},
	})
}

// DeliverFeishuCard sends a signed interactive card to a Feishu robot webhook with bounded 3x retry on 429/5xx.
func DeliverFeishuCard(ctx context.Context, client *http.Client, targetURL string, secret []byte, card map[string]any) error {
	return postFeishuPayload(ctx, client, targetURL, secret, map[string]any{
		"msg_type": "interactive",
		"card":     card,
	})
}

func postFeishuPayload(ctx context.Context, client *http.Client, targetURL string, secret []byte, payload map[string]any) error {
	if client == nil {
		client = &http.Client{Timeout: 3 * time.Second}
	}
	ts := time.Now().Unix()
	payload["timestamp"] = strconv.FormatInt(ts, 10)
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
