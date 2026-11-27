package profile

// Profile represents a validated V2/V3/V4 event IPsec Hub configuration profile.
type Profile struct {
	SchemaVersion string         `json:"schema_version"`
	Event         Event          `json:"event"`
	Hub           Hub            `json:"hub"`
	Sites         []Site         `json:"sites"`
	SiteLinks     []SiteLink     `json:"site_links"`
	Security      *Security      `json:"security,omitempty"`
	TrafficPolicy TrafficPolicy  `json:"traffic_policy"`
	Backup        Backup         `json:"backup"`
	Monitoring    *Monitoring    `json:"monitoring,omitempty"`
	Raw           map[string]any `json:"-"`
}

type Event struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Purpose string `json:"purpose,omitempty"`
}

type Hub struct {
	ID             string `json:"id"`
	Platform       string `json:"platform"`
	PublicEndpoint string `json:"public_endpoint"`
	IKEIdentity    string `json:"ike_identity,omitempty"`
	ProviderLabel  string `json:"provider_label"`
	LocationLabel  string `json:"location_label"`
	Country        string `json:"country,omitempty"`
}

func (h Hub) EffectiveIKEIdentity() string {
	if h.IKEIdentity != "" {
		return h.IKEIdentity
	}
	return h.PublicEndpoint
}

type Site struct {
	ID             string   `json:"id"`
	DisplayName    string   `json:"display_name"`
	Role           string   `json:"role,omitempty"`
	Country        string   `json:"country,omitempty"`
	LocationLabel  string   `json:"location_label,omitempty"`
	PublicEndpoint string   `json:"public_endpoint"`
	IKEIdentity    string   `json:"ike_identity"`
	LANCIDRs       []string `json:"lan_cidrs"`
	Firewall       Firewall `json:"firewall"`
	Uplinks        []Uplink `json:"uplinks,omitempty"`
}

type Firewall struct {
	Vendor    string `json:"vendor"`
	Model     string `json:"model,omitempty"`
	OSVersion string `json:"os_version,omitempty"`
}

type Uplink struct {
	ID             string `json:"id"`
	ISPLabel       string `json:"isp_label"`
	PublicEndpoint string `json:"public_endpoint"`
	IKEIdentity    string `json:"ike_identity,omitempty"`
	Interface      string `json:"interface,omitempty"`
}

type SiteLink struct {
	ID            string    `json:"id,omitempty"`
	SiteID        string    `json:"site_id"`
	UplinkID      string    `json:"uplink_id,omitempty"`
	SecretRef     string    `json:"secret_ref"`
	IfID          uint32    `json:"if_id"`
	IKEProposal   string    `json:"ike_proposal,omitempty"`
	ESPProposal   string    `json:"esp_proposal,omitempty"`
	SelectorMode  string    `json:"selector_mode,omitempty"`
	StartAction   string    `json:"start_action,omitempty"`
	DPDAction     string    `json:"dpd_action,omitempty"`
	CloseAction     string    `json:"close_action,omitempty"`
	RoutePriority   *int      `json:"route_priority,omitempty"`
	TunnelLocalCIDR string    `json:"tunnel_local_cidr,omitempty"`
	OuterPath       OuterPath `json:"outer_path"`
}

func (l SiteLink) KeyID() string {
	if l.ID != "" {
		return l.ID
	}
	return l.SiteID
}

type OuterPath struct {
	Interface      string `json:"interface"`
	ISPLabel       string `json:"isp_label"`
	SourceIP       string `json:"source_ip,omitempty"`
	Gateway        string `json:"gateway,omitempty"`
	RouteTable     *int   `json:"route_table,omitempty"`
	PolicyPriority *int   `json:"policy_priority,omitempty"`
}

type Security struct {
	IKEProposal          string `json:"ike_proposal,omitempty"`
	ESPProposal          string `json:"esp_proposal,omitempty"`
	IKELifetimeSeconds   *int   `json:"ike_lifetime_seconds,omitempty"`
	ChildLifetimeSeconds *int   `json:"child_lifetime_seconds,omitempty"`
	DPDDelaySeconds      *int   `json:"dpd_delay_seconds,omitempty"`
	StartAction          string `json:"start_action,omitempty"`
	DPDAction            string `json:"dpd_action,omitempty"`
	CloseAction          string `json:"close_action,omitempty"`
}

type TrafficPolicy struct {
	AllowedSitePairs []AllowedSitePair `json:"allowed_site_pairs"`
}

type AllowedSitePair struct {
	A      string   `json:"a"`
	B      string   `json:"b"`
	ACIDRs []string `json:"a_cidrs,omitempty"`
	BCIDRs []string `json:"b_cidrs,omitempty"`
}

type Backup struct {
	Enabled        bool         `json:"enabled"`
	Type           string       `json:"type,omitempty"`
	TransitSupport string       `json:"transit_support,omitempty"`
	PeerProfileRef string       `json:"peer_profile_ref,omitempty"`
	ProviderLabel  string       `json:"provider_label,omitempty"`
	LocationLabel  string       `json:"location_label,omitempty"`
	Country        string       `json:"country,omitempty"`
	Links          []BackupLink `json:"links,omitempty"`
}

type BackupLink struct {
	SiteID         string   `json:"site_id"`
	PublicEndpoint string   `json:"public_endpoint,omitempty"`
	LocalUplinkID  string   `json:"local_uplink_id,omitempty"`
	TunnelName     string   `json:"tunnel_name,omitempty"`
	RemoteCIDRs    []string `json:"remote_cidrs,omitempty"`
	RoutePriority  *int     `json:"route_priority,omitempty"`
	TrackTarget    string   `json:"track_target,omitempty"`
}

type Monitoring struct {
	Enabled          bool            `json:"enabled"`
	Exporter         *ExporterConfig `json:"exporter,omitempty"`
	UDPPath          *UDPPathConfig  `json:"udp_path,omitempty"`
	Probes           []ProbeConfig   `json:"probes,omitempty"`
	Thresholds       *Thresholds     `json:"thresholds,omitempty"`
	FeishuWebhookRef string          `json:"feishu_webhook_ref,omitempty"`
}

type ExporterConfig struct {
	Bind            string `json:"bind,omitempty"`
	Port            *int   `json:"port,omitempty"`
	IntervalSeconds *int   `json:"interval_seconds,omitempty"`
	TimeoutSeconds  *int   `json:"timeout_seconds,omitempty"`
	TTLSeconds      *int   `json:"ttl_seconds,omitempty"`
}

type UDPPathConfig struct {
	Enabled    bool `json:"enabled"`
	TTLSeconds *int `json:"ttl_seconds,omitempty"`
}

type ProbeConfig struct {
	SiteID   string `json:"site_id"`
	Protocol string `json:"protocol"`
	Target   string `json:"target"`
	Path     string `json:"path"`
	Port     *int   `json:"port,omitempty"`
}

type Thresholds struct {
	RTTMs    *float64 `json:"rtt_ms,omitempty"`
	JitterMs *float64 `json:"jitter_ms,omitempty"`
	LossPct  *float64 `json:"loss_pct,omitempty"`
}

// AuthorizedPair is a normalized directional forwarding authorization rule.
type AuthorizedPair struct {
	SourceSiteID string   `json:"source_site_id"`
	TargetSiteID string   `json:"target_site_id"`
	SourceCIDRs  []string `json:"source_cidrs"`
	TargetCIDRs  []string `json:"target_cidrs"`
}

// BackupReadiness reports offline backup handoff input completeness.
type BackupReadiness struct {
	Enabled   bool                `json:"enabled"`
	Status    string              `json:"status,omitempty"`
	Readiness string              `json:"readiness,omitempty"`
	Missing   map[string][]string `json:"missing,omitempty"`
}
