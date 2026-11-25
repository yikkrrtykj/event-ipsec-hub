package alert

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/yikkrrtykj/event-ipsec-hub/internal/storage"
	"github.com/yikkrrtykj/event-ipsec-hub/internal/telemetry"
)

// Sender delivers a formatted alert notification (e.g., Feishu or generic webhook).
type Sender interface {
	Send(ctx context.Context, rec storage.AlertHistoryRecord) error
}

type SenderFunc func(ctx context.Context, rec storage.AlertHistoryRecord) error

func (f SenderFunc) Send(ctx context.Context, rec storage.AlertHistoryRecord) error {
	return f(ctx, rec)
}

type firingState struct {
	Active      bool
	Unavailable bool
	StartedAt   time.Time
	LastSentAt  time.Time
}

// Engine evaluates built-in alert rules with dedup, cooldown, silence, source tagging,
// and strict anti-false-recovery semantics (UNKNOWN -> DATA_UNAVAILABLE, never RECOVERED).
type Engine struct {
	mu     sync.Mutex
	store  *storage.Store
	sender Sender
	source string // e.g. "self_hosted_hub" | "cloud_backup_vpn"
	state  map[string]*firingState
}

func NewEngine(store *storage.Store, sender Sender, source string) *Engine {
	if source == "" {
		source = "self_hosted_hub"
	}
	return &Engine{
		store:  store,
		sender: sender,
		source: source,
		state:  make(map[string]*firingState),
	}
}

func (e *Engine) SetSender(sender Sender) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.sender = sender
}

type ruleVerdict int

const (
	verdictHealthy ruleVerdict = iota
	verdictFiring
	verdictUnknown
)

func evalMetric(rule storage.AlertRule, s storage.MetricSample) ruleVerdict {
	switch rule.Metric {
	case "l2_ike_state":
		if s.L2IKEState == telemetry.StateUnknown {
			return verdictUnknown
		}
		if float64(s.L2IKEState) < rule.Threshold {
			return verdictFiring
		}
		return verdictHealthy
	case "l2_child_state":
		if s.L2ChildState == telemetry.StateUnknown {
			return verdictUnknown
		}
		if float64(s.L2ChildState) < rule.Threshold {
			return verdictFiring
		}
		return verdictHealthy
	case "l4_udp_state":
		if s.L4UDPState == telemetry.StateUnknown {
			return verdictUnknown
		}
		if float64(s.L4UDPState) < rule.Threshold {
			return verdictFiring
		}
		return verdictHealthy
	case "l1_outer_loss":
		if s.L1Mode != "icmp" || s.L1OuterState == telemetry.StateUnknown {
			return verdictUnknown
		}
		if s.L1OuterLoss >= rule.Threshold {
			return verdictFiring
		}
		return verdictHealthy
	case "l4_udp_loss":
		if s.L4UDPState == telemetry.StateUnknown {
			return verdictUnknown
		}
		if s.L4UDPLoss >= rule.Threshold {
			return verdictFiring
		}
		return verdictHealthy
	case "l3_xfrm_err_delta":
		if s.L2ChildState == telemetry.StateUnknown {
			return verdictUnknown
		}
		if float64(s.L3XFRMErrDelta) >= rule.Threshold {
			return verdictFiring
		}
		return verdictHealthy
	case "l2_rekeys_10m":
		if s.L2IKEState == telemetry.StateUnknown {
			return verdictUnknown
		}
		if float64(s.L2Rekeys10m) >= rule.Threshold {
			return verdictFiring
		}
		return verdictHealthy
	default:
		return verdictUnknown
	}
}

// Evaluate checks all enabled rules against one site sample + diagnosis and dispatches transitions.
func (e *Engine) Evaluate(ctx context.Context, rules []storage.AlertRule, sample storage.MetricSample, diag telemetry.DiagnosisResult, now time.Time) []storage.AlertHistoryRecord {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	nowMs := now.UnixMilli()
	var emitted []storage.AlertHistoryRecord
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		if rule.SilencedUntilMs > nowMs {
			continue
		}
		fp := fmt.Sprintf("%s/%s/%s", rule.Name, sample.SiteID, e.source)
		st := e.state[fp]
		verdict := evalMetric(rule, sample)

		switch verdict {
		case verdictFiring:
			if st == nil {
				st = &firingState{Active: true, StartedAt: now}
				e.state[fp] = st
			} else if st.Active && !st.Unavailable {
				cooldown := time.Duration(rule.CooldownSeconds) * time.Second
				if cooldown > 0 && now.Sub(st.LastSentAt) < cooldown {
					continue
				}
				// Already firing and still firing: avoid duplicate noise unless re-escalated.
				continue
			} else {
				st.Active = true
				st.Unavailable = false
				if st.StartedAt.IsZero() {
					st.StartedAt = now
				}
			}
			rec := e.dispatch(ctx, fp, rule.Name, "FIRING", rule.Severity, sample, diag, now, now.Sub(st.StartedAt))
			st.LastSentAt = now
			emitted = append(emitted, rec)

		case verdictUnknown:
			// Anti-false-recovery invariant: UNKNOWN must NEVER trigger RECOVERED!
			if st != nil && st.Active && !st.Unavailable {
				st.Unavailable = true
				rec := e.dispatch(ctx, fp, rule.Name, "DATA_UNAVAILABLE", "warning", sample, diag, now, now.Sub(st.StartedAt))
				st.LastSentAt = now
				emitted = append(emitted, rec)
			}

		case verdictHealthy:
			if st != nil && st.Active {
				dur := now.Sub(st.StartedAt)
				delete(e.state, fp)
				rec := e.dispatch(ctx, fp, rule.Name, "RECOVERED", "info", sample, diag, now, dur)
				emitted = append(emitted, rec)
			}
		}
	}
	return emitted
}

func (e *Engine) dispatch(ctx context.Context, fp, alertName, status, severity string, s storage.MetricSample, diag telemetry.DiagnosisResult, now time.Time, dur time.Duration) storage.AlertHistoryRecord {
	cst := time.FixedZone("Asia/Shanghai", 8*3600)
	msg := fmt.Sprintf(
		"[%s] %s %s\n来源: %s | 赛事: %s | Hub: %s | 站点: %s\n时间: %s UTC / %s Asia/Shanghai\n持续: %d 秒\n根因定界: %s — %s",
		strings.ToUpper(severity),
		status,
		alertName,
		e.source,
		nonEmpty(s.EventID, "-"),
		nonEmpty(s.HubID, "-"),
		nonEmpty(s.SiteID, "-"),
		now.UTC().Format(time.RFC3339),
		now.In(cst).Format(time.RFC3339),
		max(0, int(dur.Seconds())),
		diag.Code,
		diag.SummaryZH,
	)
	rec := storage.AlertHistoryRecord{
		TsMs:        now.UnixMilli(),
		Fingerprint: fp,
		AlertName:   alertName,
		Status:      status,
		Severity:    severity,
		Source:      e.source,
		SiteID:      s.SiteID,
		RootCause:   diag.Code,
		Message:     msg,
	}
	if e.sender != nil {
		if err := e.sender.Send(ctx, rec); err != nil {
			rec.Delivered = false
			rec.Error = err.Error()
		} else {
			rec.Delivered = true
		}
	}
	if e.store != nil {
		_ = e.store.RecordAlert(rec)
		_ = e.store.InsertTimelineEvent(storage.TimelineEvent{
			TsMs:      now.UnixMilli(),
			Layer:     "ALERT",
			Category:  status + "_" + alertName,
			Severity:  severity,
			SiteID:    s.SiteID,
			Source:    e.source,
			Title:     fmt.Sprintf("%s %s (%s)", status, alertName, diag.Code),
			RootCause: diag.Code,
		})
	}
	return rec
}

func nonEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
