package handoff

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/yikkrrtykj/event-ipsec-hub/internal/profile"
)

func TestTencentJSONAndVendorDrafts(t *testing.T) {
	p, err := profile.LoadProfile(filepath.Join("..", "..", "config", "esports-multi-ob-hillstone.example.yaml"))
	if err != nil {
		t.Fatalf("load profile: %v", err)
	}

	// Default export must redact PSK and enforce IKEv2 strong crypto
	tc, err := RenderTencentJSON(p, "ob-venue-1", "")
	if err != nil {
		t.Fatalf("RenderTencentJSON: %v", err)
	}
	if tc["PreShareKey"] != PSKPlaceholder {
		t.Fatalf("expected redacted PSK placeholder, got %v", tc["PreShareKey"])
	}
	ike := tc["IKEOptionsSpecification"].(map[string]any)
	if ike["IKEVersion"] != "IKEV2" || ike["PropoEncryAlgorithm"] != "AES-CBC-256" || ike["DhGroupName"] != "GROUP14" {
		t.Fatalf("unexpected IKE spec: %+v", ike)
	}
	if ike["LocalAddress"] != "203.0.113.21" || ike["RemoteAddress"] != "198.51.100.10" {
		t.Fatalf("wrong site-perspective addresses: %+v", ike)
	}
	spd := tc["SecurityPolicyDatabaseSet"].([]map[string]any)
	if len(spd) != 1 || spd[0]["LocalCidrBlock"] != "0.0.0.0/0" {
		t.Fatalf("expected route_based 0.0.0.0/0 SPD, got %+v", spd)
	}

	// Explicit audited plaintext delivery mode
	tcPlain, err := RenderTencentJSON(p, "ob-venue-2", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("RenderTencentJSON plaintext: %v", err)
	}
	if tcPlain["PreShareKey"] != "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" {
		t.Fatal("expected explicit PSK in audited delivery mode")
	}
	if tcPlain["Meta"].(map[string]any)["PskRedacted"] != false {
		t.Fatal("expected PskRedacted=false")
	}
	spd2 := tcPlain["SecurityPolicyDatabaseSet"].([]map[string]any)
	if len(spd2) != 1 || spd2[0]["LocalCidrBlock"] != "10.102.10.0/24" {
		t.Fatalf("expected exact per_pair CIDR in SPD, got %+v", spd2)
	}

	// Vendor CLI draft
	hsDraft, err := RenderVendorDraft(p, "ob-venue-1", "hillstone", "")
	if err != nil {
		t.Fatalf("hillstone draft: %v", err)
	}
	if !strings.Contains(hsDraft, "NOT_APPLYABLE_CONFIG") || !strings.Contains(hsDraft, "pre-share <SEND_SEPARATELY>") {
		t.Fatalf("unexpected hillstone draft:\n%s", hsDraft)
	}

	// Hillstone markdown handoff
	params, err := PeerParameters(p, "ob-venue-1", "auto")
	if err != nil {
		t.Fatalf("PeerParameters: %v", err)
	}
	md := RenderPeerMarkdown(params)
	if !strings.Contains(md, "route_based") || !strings.Contains(md, "0.0.0.0/0") {
		t.Fatalf("expected route_based guidance in markdown:\n%s", md)
	}

	// Clean 4-block standard JSON export
	std, err := RenderStandardJSON(p, "ob-venue-1", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("RenderStandardJSON: %v", err)
	}
	if std.IKEOptionsSpecification.LocalAddress != "198.51.100.10" || std.IKEOptionsSpecification.RemoteAddress != "203.0.113.21" {
		t.Fatalf("unexpected standard JSON addresses: %+v", std.IKEOptionsSpecification)
	}
	if std.IPSECOptionsSpecification.IPSECSaLifetimeTraffic != 4096000 {
		t.Fatalf("expected default 4096000 KB SA traffic lifetime, got %d", std.IPSECOptionsSpecification.IPSECSaLifetimeTraffic)
	}
	if std.PreShareKey != "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" {
		t.Fatalf("unexpected PSK: %s", std.PreShareKey)
	}
}

func TestBuildPlanAndIncompleteBackupSkip(t *testing.T) {
	p, err := profile.LoadProfile(filepath.Join("..", "..", "tests", "fixtures", "studio-vlan.yaml"))
	if err != nil {
		t.Fatalf("load studio-vlan: %v", err)
	}
	plan := BuildPlan(p)
	if plan["status"] != "PASS" {
		t.Fatalf("expected PASS plan, got %v", plan["status"])
	}

	// Clearing backup links must withhold peer handoff with SKIP
	p.Backup.Links = nil
	params, err := PeerParameters(p, p.Sites[0].ID, "auto")
	if err != nil {
		t.Fatalf("PeerParameters incomplete backup: %v", err)
	}
	if params["status"] != "SKIP" {
		t.Fatalf("expected SKIP handoff for incomplete backup, got %v", params["status"])
	}
}
