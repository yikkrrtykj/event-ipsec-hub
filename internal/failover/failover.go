package failover

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const DefaultStateFile = "/var/lib/ipsecvpn/failover-state.json"

// PathProof captures fresh bidirectional data-plane receipts bound to one path.
type PathProof struct {
	Path            string // "primary" | "backup"
	UDPBoth         bool
	TCPBoth         bool
	SourcePreserved bool
	Pinned          bool
}

// Observe classifies two-site FIB observations and data receipts.
func Observe(first, second string, proof *PathProof, primaryReady *[2]bool, holdMet bool) map[string]any {
	res := map[string]any{
		"selected_paths": []any{nullableStr(first), nullableStr(second)},
		"data_path":      "SKIP",
	}
	if first == "" || second == "" {
		res["state"] = "UNKNOWN"
		res["status"] = "SKIP"
		return res
	}
	if first != second {
		if first == "unavailable" || second == "unavailable" {
			res["state"] = "SINGLE_SIDE_TRANSITION"
		} else {
			res["state"] = "ASYMMETRIC_STOP"
		}
		res["status"] = "STOP"
		return res
	}
	if first == "unavailable" {
		res["state"] = "BOTH_UNAVAILABLE"
		res["status"] = "STOP"
		return res
	}
	if proof == nil {
		res["state"] = "UNKNOWN"
		res["status"] = "SKIP"
		return res
	}
	if proof.Path != first || !proof.Pinned {
		res["state"] = "UNKNOWN"
		res["status"] = "STOP"
		res["reason"] = "WRONG_PATH"
		return res
	}
	if !proof.SourcePreserved {
		res["state"] = "UNKNOWN"
		res["status"] = "STOP"
		res["reason"] = "SOURCE_CHANGED"
		return res
	}
	if !(proof.UDPBoth && proof.TCPBoth) {
		res["state"] = "UNKNOWN"
		res["status"] = "FAIL"
		res["data_path"] = "FAIL"
		return res
	}
	res["data_path"] = "PASS"
	if first == "backup" && primaryReady != nil && (primaryReady[0] || primaryReady[1]) {
		if primaryReady[0] && primaryReady[1] && holdMet {
			res["state"] = "MANUAL_CUTOVER_REQUIRED"
		} else {
			res["state"] = "RECOVERY_PENDING"
		}
		res["status"] = "SKIP"
		return res
	}
	res["state"] = strings.ToUpper(first) + "_VERIFIED"
	res["status"] = "PASS"
	return res
}

func nullableStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// State persists the backup-lock state machine and hub role (#12 primary/backup swap).
type State struct {
	Mode                       string           `json:"mode"`
	ActivePath                 string           `json:"active_path"`
	HubRole                    string           `json:"hub_role,omitempty"` // "primary" (default) | "backup" (#12)
	ConsecutivePrimaryFailures int              `json:"consecutive_primary_failures"`
	PrimaryRecoveredSince      *float64         `json:"primary_recovered_since"`
	SwitchedAt                 *float64         `json:"switched_at"`
	LastReason                 *string          `json:"last_reason"`
	History                    []map[string]any `json:"history"`
}

func DefaultState() State {
	return State{
		Mode:       "PRIMARY_ACTIVE",
		ActivePath: "primary",
		HubRole:    "primary",
		History:    []map[string]any{},
	}
}

func LoadState(path string) (State, error) {
	if path == "" {
		path = DefaultStateFile
	}
	st := DefaultState()
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return st, nil
		}
		return st, err
	}
	if err := json.Unmarshal(raw, &st); err != nil {
		return st, err
	}
	if st.Mode == "" {
		st.Mode = "PRIMARY_ACTIVE"
	}
	if st.ActivePath == "" {
		st.ActivePath = "primary"
	}
	if st.HubRole == "" {
		st.HubRole = "primary"
	}
	if st.History == nil {
		st.History = []map[string]any{}
	}
	return st, nil
}

func SaveState(st State, path string) error {
	if path == "" {
		path = DefaultStateFile
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(st, "", "  ")
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

// Controller manages automatic failover to healthy backup with strict manual-confirm failback.
type Controller struct {
	StateFile           string
	FailureThreshold    int
	RecoveryHoldSeconds float64
	State               State
}

func NewController(stateFile string, failureThreshold int, recoveryHoldSeconds float64) (*Controller, error) {
	if stateFile == "" {
		stateFile = DefaultStateFile
	}
	if failureThreshold < 1 {
		failureThreshold = 1
	}
	if recoveryHoldSeconds < 0 {
		recoveryHoldSeconds = 0
	}
	st, err := LoadState(stateFile)
	if err != nil {
		return nil, err
	}
	return &Controller{
		StateFile:           stateFile,
		FailureThreshold:    failureThreshold,
		RecoveryHoldSeconds: recoveryHoldSeconds,
		State:               st,
	}, nil
}

func (c *Controller) recordEvent(event string, now float64, detail map[string]any) {
	if len(c.State.History) >= 50 {
		c.State.History = c.State.History[len(c.State.History)-49:]
	}
	entry := map[string]any{"at": now, "event": event}
	for k, v := range detail {
		entry[k] = v
	}
	c.State.History = append(c.State.History, entry)
}

func (c *Controller) persist() error {
	return SaveState(c.State, c.StateFile)
}

func (c *Controller) Evaluate(primaryHealthy, backupHealthy bool, now float64, reason string) (map[string]any, error) {
	if now <= 0 {
		now = float64(time.Now().UnixNano()) / 1e9
	}
	if reason == "" {
		reason = "probe_failure"
	}

	switch c.State.Mode {
	case "PRIMARY_ACTIVE":
		if primaryHealthy {
			c.State.ConsecutivePrimaryFailures = 0
			if err := c.persist(); err != nil {
				return nil, err
			}
			return map[string]any{
				"status":        "PASS",
				"action":        "KEEP_PRIMARY",
				"notify_feishu": false,
				"state":         c.State,
			}, nil
		}
		c.State.ConsecutivePrimaryFailures++
		if c.State.ConsecutivePrimaryFailures < c.FailureThreshold {
			if err := c.persist(); err != nil {
				return nil, err
			}
			return map[string]any{
				"status":        "PASS",
				"action":        "DEGRADED_OBSERVING",
				"notify_feishu": false,
				"state":         c.State,
			}, nil
		}
		if !backupHealthy {
			r := "primary_and_backup_unhealthy"
			c.State.Mode = "MANUAL_STOP"
			c.State.LastReason = &r
			c.recordEvent("MANUAL_STOP", now, map[string]any{"reason": r})
			if err := c.persist(); err != nil {
				return nil, err
			}
			return map[string]any{
				"status":        "STOP",
				"action":        "ALERT_BOTH_UNHEALTHY",
				"notify_feishu": true,
				"state":         c.State,
			}, nil
		}
		c.State.Mode = "BACKUP_LOCKED"
		c.State.ActivePath = "backup"
		c.State.SwitchedAt = &now
		c.State.PrimaryRecoveredSince = nil
		c.State.LastReason = &reason
		c.recordEvent("AUTO_FAILOVER_TO_BACKUP", now, map[string]any{"reason": reason})
		if err := c.persist(); err != nil {
			return nil, err
		}
		return map[string]any{
			"status":        "PASS",
			"action":        "SWITCH_TO_BACKUP",
			"notify_feishu": true,
			"state":         c.State,
		}, nil

	case "BACKUP_LOCKED", "PRIMARY_RECOVERY_READY":
		if !backupHealthy {
			r := "backup_failed_while_locked"
			c.State.Mode = "MANUAL_STOP"
			c.State.LastReason = &r
			c.recordEvent("MANUAL_STOP", now, map[string]any{"reason": r})
			if err := c.persist(); err != nil {
				return nil, err
			}
			return map[string]any{
				"status":        "STOP",
				"action":        "ALERT_BACKUP_DEGRADED",
				"notify_feishu": true,
				"state":         c.State,
			}, nil
		}
		if primaryHealthy {
			if c.State.PrimaryRecoveredSince == nil {
				t := now
				c.State.PrimaryRecoveredSince = &t
			}
			held := now - *c.State.PrimaryRecoveredSince
			if held >= c.RecoveryHoldSeconds {
				newlyReady := c.State.Mode != "PRIMARY_RECOVERY_READY"
				c.State.Mode = "PRIMARY_RECOVERY_READY"
				if newlyReady {
					c.recordEvent("PRIMARY_RECOVERY_READY", now, map[string]any{
						"held_seconds": math.Round(held*100) / 100,
					})
				}
				if err := c.persist(); err != nil {
					return nil, err
				}
				return map[string]any{
					"status":        "PASS",
					"action":        "WAIT_MANUAL_FAILBACK",
					"notify_feishu": newlyReady,
					"state":         c.State,
				}, nil
			}
		} else {
			c.State.PrimaryRecoveredSince = nil
			c.State.Mode = "BACKUP_LOCKED"
		}
		if err := c.persist(); err != nil {
			return nil, err
		}
		return map[string]any{
			"status":        "PASS",
			"action":        "KEEP_BACKUP_LOCKED",
			"notify_feishu": false,
			"state":         c.State,
		}, nil

	default:
		return map[string]any{
			"status":        "STOP",
			"action":        "MANUAL_INTERVENTION_REQUIRED",
			"notify_feishu": false,
			"state":         c.State,
		}, nil
	}
}

func (c *Controller) ManualSwitchToBackup(operator string, backupHealthy bool, reason string, now float64) (map[string]any, error) {
	if now <= 0 {
		now = float64(time.Now().UnixNano()) / 1e9
	}
	if reason == "" {
		reason = "manual_switch"
	}
	if !backupHealthy {
		return map[string]any{
			"status": "STOP",
			"action": "REJECT_UNHEALTHY_BACKUP",
			"detail": "Backup path is not healthy; refusing manual switch.",
			"state":  c.State,
		}, nil
	}
	c.State.Mode = "BACKUP_LOCKED"
	c.State.ActivePath = "backup"
	c.State.SwitchedAt = &now
	c.State.PrimaryRecoveredSince = nil
	c.State.LastReason = &reason
	c.recordEvent("MANUAL_SWITCH_TO_BACKUP", now, map[string]any{"operator": operator, "reason": reason})
	if err := c.persist(); err != nil {
		return nil, err
	}
	return map[string]any{
		"status": "PASS",
		"action": "SWITCH_TO_BACKUP",
		"detail": "Switched to backup and locked by " + operator + ".",
		"state":  c.State,
	}, nil
}

func (c *Controller) ConfirmFailback(operator string, primaryHealthy, force bool, now float64) (map[string]any, error) {
	if now <= 0 {
		now = float64(time.Now().UnixNano()) / 1e9
	}
	if c.State.Mode == "PRIMARY_ACTIVE" {
		return map[string]any{
			"status": "PASS",
			"action": "NOOP_ALREADY_PRIMARY",
			"detail": "Primary path is already active.",
			"state":  c.State,
		}, nil
	}
	if !primaryHealthy && !force {
		return map[string]any{
			"status": "STOP",
			"action": "REJECT_UNHEALTHY_PRIMARY",
			"detail": "Primary path is not verified healthy; pass --force only in an emergency.",
			"state":  c.State,
		}, nil
	}
	if c.State.Mode != "PRIMARY_RECOVERY_READY" && !force {
		return map[string]any{
			"status": "STOP",
			"action": "REJECT_HOLD_NOT_MET",
			"detail": "Primary recovery hold period has not completed; wait or pass --force.",
			"state":  c.State,
		}, nil
	}
	r := "manual_failback_by_" + operator
	c.State.Mode = "PRIMARY_ACTIVE"
	c.State.ActivePath = "primary"
	c.State.ConsecutivePrimaryFailures = 0
	c.State.PrimaryRecoveredSince = nil
	c.State.LastReason = &r
	c.recordEvent("MANUAL_FAILBACK_TO_PRIMARY", now, map[string]any{"operator": operator, "forced": force})
	if err := c.persist(); err != nil {
		return nil, err
	}
	return map[string]any{
		"status": "PASS",
		"action": "SWITCH_TO_PRIMARY",
		"detail": "Manual failback to primary confirmed by " + operator + ".",
		"state":  c.State,
	}, nil
}

// SetHubRole records whether this self-hosted strongSwan Hub acts as "primary" or "backup" (#12).
func (c *Controller) SetHubRole(role, operator string, now float64) (map[string]any, error) {
	if role != "primary" && role != "backup" {
		return map[string]any{
			"status": "STOP",
			"action": "INVALID_HUB_ROLE",
			"detail": "Hub role must be primary or backup.",
			"state":  c.State,
		}, nil
	}
	if now <= 0 {
		now = float64(time.Now().UnixNano()) / 1e9
	}
	prev := c.State.HubRole
	c.State.HubRole = role
	c.recordEvent("HUB_ROLE_UPDATED", now, map[string]any{
		"operator": operator,
		"from":     prev,
		"to":       role,
	})
	if err := c.persist(); err != nil {
		return nil, err
	}
	return map[string]any{
		"status": "PASS",
		"action": "HUB_ROLE_SET",
		"detail": "Hub role updated to " + role + ".",
		"state":  c.State,
	}, nil
}
