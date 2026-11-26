package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const DefaultDBPath = "/var/lib/ipsecvpn/gateway.db"

// Store provides concurrency-safe SQLite WAL persistence for V4 configs, telemetry,
// timeline events, alert rules/history, audit logs, and Web users.
type Store struct {
	db *sql.DB
}

type ProfileRecord struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	YAMLContent       string `json:"yaml_content"`
	SHA256            string `json:"sha256"`
	Active            bool   `json:"active"`
	HubRole           string `json:"hub_role"`
	OuterProbeTargets string `json:"outer_probe_targets_json"`
	UpdatedAt         int64  `json:"updated_at"`
}

type ProfileRevision struct {
	ID          int64  `json:"id"`
	ProfileID   string `json:"profile_id"`
	YAMLContent string `json:"yaml_content"`
	SHA256      string `json:"sha256"`
	Operator    string `json:"operator"`
	Note        string `json:"note"`
	CreatedAt   int64  `json:"created_at"`
}

type SecretMeta struct {
	Ref       string `json:"ref"`
	SiteID    string `json:"site_id"`
	SHA256    string `json:"sha256"`
	UpdatedAt int64  `json:"updated_at"`
}

type MetricSample struct {
	ID              int64   `json:"id,omitempty"`
	TsMs            int64   `json:"ts_ms"`
	EventID         string  `json:"event_id"`
	HubID           string  `json:"hub_id"`
	SiteID          string  `json:"site_id"`
	LinkID          string  `json:"link_id"`
	ISPLabel        string  `json:"isp_label"`
	L1OuterState    int     `json:"l1_outer_state"` // -1 unknown, 0 down, 1 up
	L1OuterRTTMs    float64 `json:"l1_outer_rtt_ms"`
	L1OuterLoss     float64 `json:"l1_outer_loss"`
	L1Mode          string  `json:"l1_mode"` // icmp | dpd_fallback | disabled
	L2IKEState      int     `json:"l2_ike_state"`
	L2ChildState    int     `json:"l2_child_state"`
	L2Rekeys10m     int     `json:"l2_rekeys_10m"`
	L3RxBps         float64 `json:"l3_rx_bps"`
	L3TxBps         float64 `json:"l3_tx_bps"`
	L3RxBytes       uint64  `json:"l3_rx_bytes"`
	L3TxBytes       uint64  `json:"l3_tx_bytes"`
	L3XFRMErrDelta  uint64  `json:"l3_xfrm_err_delta"`
	L3NFTDropDelta  uint64  `json:"l3_nft_drop_delta"`
	L4UDPState      int     `json:"l4_udp_state"`
	L4UDPRTTMs      float64 `json:"l4_udp_rtt_ms"`
	L4UDPP95Ms      float64 `json:"l4_udp_p95_ms"`
	L4UDPLoss       float64 `json:"l4_udp_loss"`
	RootCause       string  `json:"root_cause"`
	RootDetail      string  `json:"root_detail"`
}

type TimelineEvent struct {
	ID         int64  `json:"id,omitempty"`
	TsMs       int64  `json:"ts_ms"`
	Layer      string `json:"layer"`    // L1_OUTER | L2_IPSEC | L3_KERNEL | L4_UDP | OPS | FAILOVER | ALERT
	Category   string `json:"category"` // e.g. IKE_DOWN, CHILD_REKEY, CONFIG_APPLY, FAILOVER_SWITCH
	Severity   string `json:"severity"` // info | warning | critical
	SiteID     string `json:"site_id"`
	LinkID     string `json:"link_id"`
	Source     string `json:"source"` // self_hosted_hub | cloud_backup_vpn | web_console
	Title      string `json:"title"`
	DetailJSON string `json:"detail_json"`
	RootCause  string `json:"root_cause"`
}

type AlertRule struct {
	ID              string  `json:"id"`
	Name            string  `json:"name"`
	Enabled         bool    `json:"enabled"`
	Severity        string  `json:"severity"`
	Metric          string  `json:"metric"`
	Threshold       float64 `json:"threshold"`
	CooldownSeconds int     `json:"cooldown_seconds"`
	SilencedUntilMs int64   `json:"silenced_until_ms"`
	UpdatedAt       int64   `json:"updated_at"`
}

type AlertHistoryRecord struct {
	ID          int64  `json:"id,omitempty"`
	TsMs        int64  `json:"ts_ms"`
	Fingerprint string `json:"fingerprint"`
	AlertName   string `json:"alert_name"`
	Status      string `json:"status"` // FIRING | RECOVERED | DATA_UNAVAILABLE
	Severity    string `json:"severity"`
	Source      string `json:"source"`
	SiteID      string `json:"site_id"`
	RootCause   string `json:"root_cause"`
	Message     string `json:"message"`
	Delivered   bool   `json:"delivered"`
	Error       string `json:"error,omitempty"`
}

type AuditLog struct {
	ID         int64  `json:"id,omitempty"`
	TsMs       int64  `json:"ts_ms"`
	Operator   string `json:"operator"`
	RemoteIP   string `json:"remote_ip"`
	Action     string `json:"action"`
	Target     string `json:"target"`
	Status     string `json:"status"`
	DetailJSON string `json:"detail_json"`
}

type User struct {
	Username           string `json:"username"`
	Role               string `json:"role"` // admin | viewer
	PasswordHash       string `json:"-"`
	MustChangePassword bool   `json:"must_change_password"`
	TOTPSecret         string `json:"-"`
	TOTPEnabled        bool   `json:"totp_enabled"`
	CreatedAt          int64  `json:"created_at"`
	UpdatedAt          int64  `json:"updated_at"`
}

const schemaDDL = `
CREATE TABLE IF NOT EXISTS profiles (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    yaml_content TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 0,
    hub_role TEXT NOT NULL DEFAULT 'primary',
    outer_probe_targets_json TEXT NOT NULL DEFAULT '{}',
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS profile_revisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id TEXT NOT NULL,
    yaml_content TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    operator TEXT NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_profile_revisions_pid ON profile_revisions(profile_id, created_at DESC);

CREATE TABLE IF NOT EXISTS secrets_meta (
    ref TEXT PRIMARY KEY,
    site_id TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS metric_samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_ms INTEGER NOT NULL,
    event_id TEXT NOT NULL DEFAULT '',
    hub_id TEXT NOT NULL DEFAULT '',
    site_id TEXT NOT NULL,
    link_id TEXT NOT NULL DEFAULT '',
    isp_label TEXT NOT NULL DEFAULT '',
    l1_outer_state INTEGER NOT NULL DEFAULT -1,
    l1_outer_rtt_ms REAL NOT NULL DEFAULT 0,
    l1_outer_loss REAL NOT NULL DEFAULT 0,
    l1_mode TEXT NOT NULL DEFAULT 'disabled',
    l2_ike_state INTEGER NOT NULL DEFAULT -1,
    l2_child_state INTEGER NOT NULL DEFAULT -1,
    l2_rekeys_10m INTEGER NOT NULL DEFAULT 0,
    l3_rx_bps REAL NOT NULL DEFAULT 0,
    l3_tx_bps REAL NOT NULL DEFAULT 0,
    l3_rx_bytes INTEGER NOT NULL DEFAULT 0,
    l3_tx_bytes INTEGER NOT NULL DEFAULT 0,
    l3_xfrm_err_delta INTEGER NOT NULL DEFAULT 0,
    l3_nft_drop_delta INTEGER NOT NULL DEFAULT 0,
    l4_udp_state INTEGER NOT NULL DEFAULT -1,
    l4_udp_rtt_ms REAL NOT NULL DEFAULT 0,
    l4_udp_p95_ms REAL NOT NULL DEFAULT 0,
    l4_udp_loss REAL NOT NULL DEFAULT 0,
    root_cause TEXT NOT NULL DEFAULT 'OBSERVATION_UNVERIFIED',
    root_detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_metric_samples_site_ts ON metric_samples(site_id, ts_ms);
CREATE INDEX IF NOT EXISTS idx_metric_samples_ts ON metric_samples(ts_ms);

CREATE TABLE IF NOT EXISTS timeline_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_ms INTEGER NOT NULL,
    layer TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    site_id TEXT NOT NULL DEFAULT '',
    link_id TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT 'self_hosted_hub',
    title TEXT NOT NULL,
    detail_json TEXT NOT NULL DEFAULT '{}',
    root_cause TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_timeline_events_ts ON timeline_events(ts_ms);
CREATE INDEX IF NOT EXISTS idx_timeline_events_site_ts ON timeline_events(site_id, ts_ms);

CREATE TABLE IF NOT EXISTS alert_rules (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    severity TEXT NOT NULL DEFAULT 'warning',
    metric TEXT NOT NULL,
    threshold REAL NOT NULL DEFAULT 0,
    cooldown_seconds INTEGER NOT NULL DEFAULT 120,
    silenced_until_ms INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS alert_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_ms INTEGER NOT NULL,
    fingerprint TEXT NOT NULL,
    alert_name TEXT NOT NULL,
    status TEXT NOT NULL,
    severity TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'self_hosted_hub',
    site_id TEXT NOT NULL DEFAULT '',
    root_cause TEXT NOT NULL DEFAULT '',
    message TEXT NOT NULL,
    delivered INTEGER NOT NULL DEFAULT 0,
    error TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_alert_history_ts ON alert_history(ts_ms DESC);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_ms INTEGER NOT NULL,
    operator TEXT NOT NULL,
    remote_ip TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL,
    target TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    detail_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_audit_logs_ts ON audit_logs(ts_ms DESC);

CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    role TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    must_change_password INTEGER NOT NULL DEFAULT 1,
    totp_secret TEXT NOT NULL DEFAULT '',
    totp_enabled INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS kv_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);
`

func Open(path string) (*Store, error) {
	if path == "" {
		path = DefaultDBPath
	}
	if path != ":memory:" {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, fmt.Errorf("mkdir db dir: %w", err)
		}
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	// SQLite WAL works best with a single writer connection in-process.
	db.SetMaxOpenConns(1)
	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL;",
		"PRAGMA synchronous=NORMAL;",
		"PRAGMA busy_timeout=5000;",
		"PRAGMA foreign_keys=ON;",
	} {
		if _, err := db.Exec(pragma); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("apply pragma %s: %w", pragma, err)
		}
	}
	if _, err := db.Exec(schemaDDL); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}
	s := &Store{db: db}
	if err := s.seedDefaultAlertRules(); err != nil {
		_ = db.Close()
		return nil, err
	}
	if path != ":memory:" && runtime.GOOS != "windows" {
		if st, err := os.Stat(filepath.Dir(path)); err == nil && st.Mode()&os.ModeSetgid != 0 {
			EnsureGroupWritable(path, -1)
		}
	}
	return s, nil
}

// EnsureGroupWritable makes the SQLite database and its WAL/SHM sidecar files group-writable (0660)
// and optionally assigns group ownership to gid (>0) so root agent and non-root web can share WAL access.
func EnsureGroupWritable(path string, gid int) {
	if path == "" || path == ":memory:" || runtime.GOOS == "windows" {
		return
	}
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		if gid > 0 {
			_ = os.Chown(p, -1, gid)
		}
		_ = os.Chmod(p, 0o660)
	}
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *Store) seedDefaultAlertRules() error {
	now := time.Now().UnixMilli()
	defaults := []AlertRule{
		{ID: "ike_down", Name: "IpsecIkeDown", Enabled: true, Severity: "critical", Metric: "l2_ike_state", Threshold: 1, CooldownSeconds: 60},
		{ID: "child_down", Name: "IpsecChildDown", Enabled: true, Severity: "critical", Metric: "l2_child_state", Threshold: 1, CooldownSeconds: 60},
		{ID: "path_down", Name: "IpsecPathDown", Enabled: true, Severity: "critical", Metric: "l4_udp_state", Threshold: 1, CooldownSeconds: 60},
		{ID: "outer_loss", Name: "IpsecOuterIspDegraded", Enabled: true, Severity: "warning", Metric: "l1_outer_loss", Threshold: 0.05, CooldownSeconds: 120},
		{ID: "udp_loss", Name: "IpsecUdpLossHigh", Enabled: true, Severity: "warning", Metric: "l4_udp_loss", Threshold: 0.02, CooldownSeconds: 120},
		{ID: "xfrm_err", Name: "IpsecXfrmErrorSpike", Enabled: true, Severity: "warning", Metric: "l3_xfrm_err_delta", Threshold: 1, CooldownSeconds: 120},
		{ID: "frequent_rekey", Name: "IpsecFrequentRekey", Enabled: true, Severity: "warning", Metric: "l2_rekeys_10m", Threshold: 3, CooldownSeconds: 300},
	}
	for _, r := range defaults {
		_, err := s.db.Exec(
			`INSERT OR IGNORE INTO alert_rules (id, name, enabled, severity, metric, threshold, cooldown_seconds, silenced_until_ms, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)`,
			r.ID, r.Name, boolToInt(r.Enabled), r.Severity, r.Metric, r.Threshold, r.CooldownSeconds, now,
		)
		if err != nil {
			return err
		}
	}
	return nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (s *Store) SaveProfile(rec ProfileRecord, operator, note string) error {
	now := time.Now().UnixMilli()
	if rec.HubRole == "" {
		rec.HubRole = "primary"
	}
	if rec.OuterProbeTargets == "" {
		rec.OuterProbeTargets = "{}"
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	_, err = tx.Exec(
		`INSERT INTO profiles (id, name, yaml_content, sha256, active, hub_role, outer_probe_targets_json, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET
		   name=excluded.name,
		   yaml_content=excluded.yaml_content,
		   sha256=excluded.sha256,
		   hub_role=excluded.hub_role,
		   outer_probe_targets_json=excluded.outer_probe_targets_json,
		   updated_at=excluded.updated_at`,
		rec.ID, rec.Name, rec.YAMLContent, rec.SHA256, boolToInt(rec.Active), rec.HubRole, rec.OuterProbeTargets, now,
	)
	if err != nil {
		return err
	}
	if operator == "" {
		operator = "system"
	}
	_, err = tx.Exec(
		`INSERT INTO profile_revisions (profile_id, yaml_content, sha256, operator, note, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		rec.ID, rec.YAMLContent, rec.SHA256, operator, note, now,
	)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) SetActiveProfile(id string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`UPDATE profiles SET active = 0`); err != nil {
		return err
	}
	if id != "" {
		res, err := tx.Exec(`UPDATE profiles SET active = 1 WHERE id = ?`, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return sql.ErrNoRows
		}
	}
	return tx.Commit()
}

func (s *Store) GetProfile(id string) (*ProfileRecord, error) {
	row := s.db.QueryRow(`SELECT id, name, yaml_content, sha256, active, hub_role, outer_probe_targets_json, updated_at FROM profiles WHERE id = ?`, id)
	var rec ProfileRecord
	var active int
	if err := row.Scan(&rec.ID, &rec.Name, &rec.YAMLContent, &rec.SHA256, &active, &rec.HubRole, &rec.OuterProbeTargets, &rec.UpdatedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	rec.Active = active != 0
	return &rec, nil
}

func (s *Store) ListProfiles() ([]ProfileRecord, error) {
	rows, err := s.db.Query(`SELECT id, name, yaml_content, sha256, active, hub_role, outer_probe_targets_json, updated_at FROM profiles ORDER BY active DESC, updated_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ProfileRecord
	for rows.Next() {
		var rec ProfileRecord
		var active int
		if err := rows.Scan(&rec.ID, &rec.Name, &rec.YAMLContent, &rec.SHA256, &active, &rec.HubRole, &rec.OuterProbeTargets, &rec.UpdatedAt); err != nil {
			return nil, err
		}
		rec.Active = active != 0
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (s *Store) ListRevisions(profileID string, limit int) ([]ProfileRevision, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := s.db.Query(
		`SELECT id, profile_id, yaml_content, sha256, operator, note, created_at
		 FROM profile_revisions WHERE profile_id = ? ORDER BY created_at DESC, id DESC LIMIT ?`,
		profileID, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ProfileRevision
	for rows.Next() {
		var r ProfileRevision
		if err := rows.Scan(&r.ID, &r.ProfileID, &r.YAMLContent, &r.SHA256, &r.Operator, &r.Note, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) UpsertSecretMeta(meta SecretMeta) error {
	now := time.Now().UnixMilli()
	_, err := s.db.Exec(
		`INSERT INTO secrets_meta (ref, site_id, sha256, updated_at) VALUES (?, ?, ?, ?)
		 ON CONFLICT(ref) DO UPDATE SET site_id=excluded.site_id, sha256=excluded.sha256, updated_at=excluded.updated_at`,
		meta.Ref, meta.SiteID, meta.SHA256, now,
	)
	return err
}

func (s *Store) ListSecretsMeta() ([]SecretMeta, error) {
	rows, err := s.db.Query(`SELECT ref, site_id, sha256, updated_at FROM secrets_meta ORDER BY ref ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SecretMeta
	for rows.Next() {
		var m SecretMeta
		if err := rows.Scan(&m.Ref, &m.SiteID, &m.SHA256, &m.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *Store) InsertMetricSample(m MetricSample) error {
	if m.TsMs <= 0 {
		m.TsMs = time.Now().UnixMilli()
	}
	_, err := s.db.Exec(
		`INSERT INTO metric_samples (
			ts_ms, event_id, hub_id, site_id, link_id, isp_label,
			l1_outer_state, l1_outer_rtt_ms, l1_outer_loss, l1_mode,
			l2_ike_state, l2_child_state, l2_rekeys_10m,
			l3_rx_bps, l3_tx_bps, l3_rx_bytes, l3_tx_bytes, l3_xfrm_err_delta, l3_nft_drop_delta,
			l4_udp_state, l4_udp_rtt_ms, l4_udp_p95_ms, l4_udp_loss,
			root_cause, root_detail
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		m.TsMs, m.EventID, m.HubID, m.SiteID, m.LinkID, m.ISPLabel,
		m.L1OuterState, m.L1OuterRTTMs, m.L1OuterLoss, m.L1Mode,
		m.L2IKEState, m.L2ChildState, m.L2Rekeys10m,
		m.L3RxBps, m.L3TxBps, m.L3RxBytes, m.L3TxBytes, m.L3XFRMErrDelta, m.L3NFTDropDelta,
		m.L4UDPState, m.L4UDPRTTMs, m.L4UDPP95Ms, m.L4UDPLoss,
		m.RootCause, m.RootDetail,
	)
	return err
}

func (s *Store) QueryMetricSamples(siteID string, fromMs, toMs int64, limit int) ([]MetricSample, error) {
	if limit <= 0 || limit > 5000 {
		limit = 1000
	}
	if toMs <= 0 {
		toMs = time.Now().UnixMilli() + 60_000
	}
	var (
		rows *sql.Rows
		err  error
	)
	if siteID != "" {
		rows, err = s.db.Query(
			`SELECT id, ts_ms, event_id, hub_id, site_id, link_id, isp_label,
				l1_outer_state, l1_outer_rtt_ms, l1_outer_loss, l1_mode,
				l2_ike_state, l2_child_state, l2_rekeys_10m,
				l3_rx_bps, l3_tx_bps, l3_rx_bytes, l3_tx_bytes, l3_xfrm_err_delta, l3_nft_drop_delta,
				l4_udp_state, l4_udp_rtt_ms, l4_udp_p95_ms, l4_udp_loss,
				root_cause, root_detail
			 FROM metric_samples
			 WHERE site_id = ? AND ts_ms >= ? AND ts_ms <= ?
			 ORDER BY ts_ms ASC LIMIT ?`,
			siteID, fromMs, toMs, limit,
		)
	} else {
		rows, err = s.db.Query(
			`SELECT id, ts_ms, event_id, hub_id, site_id, link_id, isp_label,
				l1_outer_state, l1_outer_rtt_ms, l1_outer_loss, l1_mode,
				l2_ike_state, l2_child_state, l2_rekeys_10m,
				l3_rx_bps, l3_tx_bps, l3_rx_bytes, l3_tx_bytes, l3_xfrm_err_delta, l3_nft_drop_delta,
				l4_udp_state, l4_udp_rtt_ms, l4_udp_p95_ms, l4_udp_loss,
				root_cause, root_detail
			 FROM metric_samples
			 WHERE ts_ms >= ? AND ts_ms <= ?
			 ORDER BY ts_ms ASC LIMIT ?`,
			fromMs, toMs, limit,
		)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MetricSample
	for rows.Next() {
		var m MetricSample
		if err := rows.Scan(
			&m.ID, &m.TsMs, &m.EventID, &m.HubID, &m.SiteID, &m.LinkID, &m.ISPLabel,
			&m.L1OuterState, &m.L1OuterRTTMs, &m.L1OuterLoss, &m.L1Mode,
			&m.L2IKEState, &m.L2ChildState, &m.L2Rekeys10m,
			&m.L3RxBps, &m.L3TxBps, &m.L3RxBytes, &m.L3TxBytes, &m.L3XFRMErrDelta, &m.L3NFTDropDelta,
			&m.L4UDPState, &m.L4UDPRTTMs, &m.L4UDPP95Ms, &m.L4UDPLoss,
			&m.RootCause, &m.RootDetail,
		); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *Store) InsertTimelineEvent(ev TimelineEvent) error {
	if ev.TsMs <= 0 {
		ev.TsMs = time.Now().UnixMilli()
	}
	if ev.DetailJSON == "" {
		ev.DetailJSON = "{}"
	}
	if ev.Source == "" {
		ev.Source = "self_hosted_hub"
	}
	_, err := s.db.Exec(
		`INSERT INTO timeline_events (ts_ms, layer, category, severity, site_id, link_id, source, title, detail_json, root_cause)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ev.TsMs, ev.Layer, ev.Category, ev.Severity, ev.SiteID, ev.LinkID, ev.Source, ev.Title, ev.DetailJSON, ev.RootCause,
	)
	return err
}

func (s *Store) QueryTimelineEvents(siteID string, fromMs, toMs int64, limit int) ([]TimelineEvent, error) {
	if limit <= 0 || limit > 2000 {
		limit = 500
	}
	if toMs <= 0 {
		toMs = time.Now().UnixMilli() + 60_000
	}
	var (
		rows *sql.Rows
		err  error
	)
	if siteID != "" {
		rows, err = s.db.Query(
			`SELECT id, ts_ms, layer, category, severity, site_id, link_id, source, title, detail_json, root_cause
			 FROM timeline_events
			 WHERE (site_id = ? OR site_id = '') AND ts_ms >= ? AND ts_ms <= ?
			 ORDER BY ts_ms ASC LIMIT ?`,
			siteID, fromMs, toMs, limit,
		)
	} else {
		rows, err = s.db.Query(
			`SELECT id, ts_ms, layer, category, severity, site_id, link_id, source, title, detail_json, root_cause
			 FROM timeline_events
			 WHERE ts_ms >= ? AND ts_ms <= ?
			 ORDER BY ts_ms ASC LIMIT ?`,
			fromMs, toMs, limit,
		)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TimelineEvent
	for rows.Next() {
		var ev TimelineEvent
		if err := rows.Scan(&ev.ID, &ev.TsMs, &ev.Layer, &ev.Category, &ev.Severity, &ev.SiteID, &ev.LinkID, &ev.Source, &ev.Title, &ev.DetailJSON, &ev.RootCause); err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}

// EventSearchFilter controls paginated event log search.
type EventSearchFilter struct {
	SiteID   string
	Severity string
	Layer    string
	Query    string
	FromMs   int64
	ToMs     int64
	Limit    int
	Offset   int
}

// SearchTimelineEvents queries timeline events newest-first with time range, severity, layer,
// site, and keyword filtering plus pagination total count.
func (s *Store) SearchTimelineEvents(f EventSearchFilter) ([]TimelineEvent, int, error) {
	if f.Limit <= 0 || f.Limit > 200 {
		f.Limit = 50
	}
	if f.Offset < 0 {
		f.Offset = 0
	}
	var conds []string
	var args []any
	if f.SiteID != "" {
		conds = append(conds, "site_id = ?")
		args = append(args, f.SiteID)
	}
	if f.Severity != "" {
		conds = append(conds, "severity = ?")
		args = append(args, f.Severity)
	}
	if f.Layer != "" {
		conds = append(conds, "layer = ?")
		args = append(args, f.Layer)
	}
	if f.FromMs > 0 {
		conds = append(conds, "ts_ms >= ?")
		args = append(args, f.FromMs)
	}
	if f.ToMs > 0 {
		conds = append(conds, "ts_ms <= ?")
		args = append(args, f.ToMs)
	}
	if q := strings.TrimSpace(strings.ToLower(f.Query)); q != "" {
		like := "%" + q + "%"
		conds = append(conds, "(LOWER(title) LIKE ? OR LOWER(category) LIKE ? OR LOWER(site_id) LIKE ? OR LOWER(root_cause) LIKE ? OR LOWER(detail_json) LIKE ?)")
		args = append(args, like, like, like, like, like)
	}
	where := ""
	if len(conds) > 0 {
		where = " WHERE " + strings.Join(conds, " AND ")
	}

	var total int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM timeline_events"+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	pageArgs := append(append([]any{}, args...), f.Limit, f.Offset)
	rows, err := s.db.Query(
		`SELECT id, ts_ms, layer, category, severity, site_id, link_id, source, title, detail_json, root_cause
		 FROM timeline_events`+where+` ORDER BY ts_ms DESC, id DESC LIMIT ? OFFSET ?`,
		pageArgs...,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := make([]TimelineEvent, 0)
	for rows.Next() {
		var ev TimelineEvent
		if err := rows.Scan(&ev.ID, &ev.TsMs, &ev.Layer, &ev.Category, &ev.Severity, &ev.SiteID, &ev.LinkID, &ev.Source, &ev.Title, &ev.DetailJSON, &ev.RootCause); err != nil {
			return nil, 0, err
		}
		out = append(out, ev)
	}
	return out, total, rows.Err()
}

// PruneOlderThan deletes metric samples and timeline events older than cutoffMs (7-30d retention).
func (s *Store) PruneOlderThan(cutoffMs int64) (int64, error) {
	r1, err := s.db.Exec(`DELETE FROM metric_samples WHERE ts_ms < ?`, cutoffMs)
	if err != nil {
		return 0, err
	}
	r2, err := s.db.Exec(`DELETE FROM timeline_events WHERE ts_ms < ?`, cutoffMs)
	if err != nil {
		return 0, err
	}
	n1, _ := r1.RowsAffected()
	n2, _ := r2.RowsAffected()
	return n1 + n2, nil
}

func (s *Store) ListAlertRules() ([]AlertRule, error) {
	rows, err := s.db.Query(`SELECT id, name, enabled, severity, metric, threshold, cooldown_seconds, silenced_until_ms, updated_at FROM alert_rules ORDER BY id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AlertRule
	for rows.Next() {
		var r AlertRule
		var en int
		if err := rows.Scan(&r.ID, &r.Name, &en, &r.Severity, &r.Metric, &r.Threshold, &r.CooldownSeconds, &r.SilencedUntilMs, &r.UpdatedAt); err != nil {
			return nil, err
		}
		r.Enabled = en != 0
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) UpsertAlertRule(r AlertRule) error {
	now := time.Now().UnixMilli()
	_, err := s.db.Exec(
		`INSERT INTO alert_rules (id, name, enabled, severity, metric, threshold, cooldown_seconds, silenced_until_ms, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET
		   name=excluded.name, enabled=excluded.enabled, severity=excluded.severity,
		   metric=excluded.metric, threshold=excluded.threshold,
		   cooldown_seconds=excluded.cooldown_seconds, silenced_until_ms=excluded.silenced_until_ms,
		   updated_at=excluded.updated_at`,
		r.ID, r.Name, boolToInt(r.Enabled), r.Severity, r.Metric, r.Threshold, r.CooldownSeconds, r.SilencedUntilMs, now,
	)
	return err
}

func (s *Store) RecordAlert(rec AlertHistoryRecord) error {
	if rec.TsMs <= 0 {
		rec.TsMs = time.Now().UnixMilli()
	}
	_, err := s.db.Exec(
		`INSERT INTO alert_history (ts_ms, fingerprint, alert_name, status, severity, source, site_id, root_cause, message, delivered, error)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.TsMs, rec.Fingerprint, rec.AlertName, rec.Status, rec.Severity, rec.Source, rec.SiteID, rec.RootCause, rec.Message, boolToInt(rec.Delivered), rec.Error,
	)
	return err
}

func (s *Store) QueryAlertHistory(limit int) ([]AlertHistoryRecord, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.Query(
		`SELECT id, ts_ms, fingerprint, alert_name, status, severity, source, site_id, root_cause, message, delivered, error
		 FROM alert_history ORDER BY ts_ms DESC, id DESC LIMIT ?`, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AlertHistoryRecord
	for rows.Next() {
		var r AlertHistoryRecord
		var del int
		if err := rows.Scan(&r.ID, &r.TsMs, &r.Fingerprint, &r.AlertName, &r.Status, &r.Severity, &r.Source, &r.SiteID, &r.RootCause, &r.Message, &del, &r.Error); err != nil {
			return nil, err
		}
		r.Delivered = del != 0
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) RecordAudit(operator, remoteIP, action, target, status string, detail any) error {
	raw, _ := json.Marshal(detail)
	if len(raw) == 0 || string(raw) == "null" {
		raw = []byte("{}")
	}
	_, err := s.db.Exec(
		`INSERT INTO audit_logs (ts_ms, operator, remote_ip, action, target, status, detail_json)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		time.Now().UnixMilli(), operator, remoteIP, action, target, status, string(raw),
	)
	return err
}

func (s *Store) QueryAuditLogs(limit int) ([]AuditLog, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.Query(
		`SELECT id, ts_ms, operator, remote_ip, action, target, status, detail_json
		 FROM audit_logs ORDER BY ts_ms DESC, id DESC LIMIT ?`, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditLog
	for rows.Next() {
		var a AuditLog
		if err := rows.Scan(&a.ID, &a.TsMs, &a.Operator, &a.RemoteIP, &a.Action, &a.Target, &a.Status, &a.DetailJSON); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) UpsertUser(u User) error {
	now := time.Now().UnixMilli()
	if u.CreatedAt == 0 {
		u.CreatedAt = now
	}
	_, err := s.db.Exec(
		`INSERT INTO users (username, role, password_hash, must_change_password, totp_secret, totp_enabled, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(username) DO UPDATE SET
		   role=excluded.role, password_hash=excluded.password_hash,
		   must_change_password=excluded.must_change_password,
		   totp_secret=excluded.totp_secret, totp_enabled=excluded.totp_enabled,
		   updated_at=excluded.updated_at`,
		u.Username, u.Role, u.PasswordHash, boolToInt(u.MustChangePassword), u.TOTPSecret, boolToInt(u.TOTPEnabled), u.CreatedAt, now,
	)
	return err
}

func (s *Store) GetUser(username string) (*User, error) {
	row := s.db.QueryRow(`SELECT username, role, password_hash, must_change_password, totp_secret, totp_enabled, created_at, updated_at FROM users WHERE username = ?`, username)
	var u User
	var mustChange, totpEn int
	if err := row.Scan(&u.Username, &u.Role, &u.PasswordHash, &mustChange, &u.TOTPSecret, &totpEn, &u.CreatedAt, &u.UpdatedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	u.MustChangePassword = mustChange != 0
	u.TOTPEnabled = totpEn != 0
	return &u, nil
}

func (s *Store) ListUsers() ([]User, error) {
	rows, err := s.db.Query(`SELECT username, role, password_hash, must_change_password, totp_secret, totp_enabled, created_at, updated_at FROM users ORDER BY username ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		var mustChange, totpEn int
		if err := rows.Scan(&u.Username, &u.Role, &u.PasswordHash, &mustChange, &u.TOTPSecret, &totpEn, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, err
		}
		u.MustChangePassword = mustChange != 0
		u.TOTPEnabled = totpEn != 0
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) SetKV(key, value string) error {
	_, err := s.db.Exec(
		`INSERT INTO kv_settings (key, value, updated_at) VALUES (?, ?, ?)
		 ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`,
		key, value, time.Now().UnixMilli(),
	)
	return err
}

func (s *Store) GetKV(key string) (string, bool, error) {
	var val string
	err := s.db.QueryRow(`SELECT value FROM kv_settings WHERE key = ?`, key).Scan(&val)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return val, true, nil
}
