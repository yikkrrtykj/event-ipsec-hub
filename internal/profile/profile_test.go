package profile

import (
	"path/filepath"
	"strings"
	"testing"
)

func repoPath(parts ...string) string {
	all := append([]string{"..", ".."}, parts...)
	return filepath.Join(all...)
}

func TestShippedProfilesAreValid(t *testing.T) {
	paths := []string{
		repoPath("config", "event.example.yaml"),
		repoPath("config", "esports-multi-ob-hillstone.example.yaml"),
		repoPath("tests", "fixtures", "arena-apac-eu.yaml"),
		repoPath("tests", "fixtures", "signal-eu-americas.yaml"),
		repoPath("tests", "fixtures", "studio-vlan.yaml"),
	}
	for _, p := range paths {
		t.Run(filepath.Base(p), func(t *testing.T) {
			prof, err := LoadProfile(p)
			if err != nil {
				t.Fatalf("expected valid profile %s, got: %v", p, err)
			}
			if prof.Event.ID == "" {
				t.Fatal("empty event id")
			}
		})
	}
}

func TestStrictYAMLRejections(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    string
	}{
		{"duplicate_keys", "schema_version: '2.0'\nschema_version: '1.0'\n", "unique strings"},
		{"yaml_alias", "a: &label test\nb: *label\n", "aliases"},
		{"malformed_yaml", "schema_version: [2.0,\n", "single UTF-8 YAML profile"},
		{"multi_document", "---\nsite: a\n---\nsite: b\n", "single UTF-8 YAML profile"},
		{"unsupported_version", "schema_version: '1.0'\n", "Unsupported schema version"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseProfile([]byte(tc.content))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}
}

func cloneRaw(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		switch tv := v.(type) {
		case map[string]any:
			out[k] = cloneRaw(tv)
		case []any:
			s := make([]any, len(tv))
			for i, item := range tv {
				if sub, ok := item.(map[string]any); ok {
					s[i] = cloneRaw(sub)
				} else {
					s[i] = item
				}
			}
			out[k] = s
		default:
			out[k] = v
		}
	}
	return out
}

func TestInvalidProfiles(t *testing.T) {
	base, err := LoadProfile(repoPath("config", "event.example.yaml"))
	if err != nil {
		t.Fatalf("load base: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(m map[string]any)
		want   string
	}{
		{
			name:   "bad_schema_version",
			mutate: func(m map[string]any) { m["schema_version"] = "1.0" },
			want:   "Unsupported schema version",
		},
		{
			name:   "unknown_event_field",
			mutate: func(m map[string]any) { m["event"].(map[string]any)["unknown"] = "x" },
			want:   "additionalProperties",
		},
		{
			name:   "bad_site_id",
			mutate: func(m map[string]any) { m["sites"].([]any)[0].(map[string]any)["id"] = "bad/id" },
			want:   "pattern",
		},
		{
			name:   "duplicate_site_id",
			mutate: func(m map[string]any) { m["sites"].([]any)[0].(map[string]any)["id"] = "stage-b" },
			want:   "Site IDs must be unique",
		},
		{
			name:   "non_canonical_cidr",
			mutate: func(m map[string]any) { m["sites"].([]any)[0].(map[string]any)["lan_cidrs"] = []any{"10.43.0.11/24"} },
			want:   "format",
		},
		{
			name:   "overlapping_lan",
			mutate: func(m map[string]any) { m["sites"].([]any)[0].(map[string]any)["lan_cidrs"] = []any{"10.76.0.0/16"} },
			want:   "overlap",
		},
		{
			name:   "wildcard_lan",
			mutate: func(m map[string]any) { m["sites"].([]any)[0].(map[string]any)["lan_cidrs"] = []any{"0.0.0.0/0"} },
			want:   "Default routes",
		},
		{
			name:   "multicast_lan",
			mutate: func(m map[string]any) { m["sites"].([]any)[0].(map[string]any)["lan_cidrs"] = []any{"224.0.0.0/24"} },
			want:   "non-forwardable",
		},
		{
			name:   "lan_captures_outer_peer",
			mutate: func(m map[string]any) { m["sites"].([]any)[0].(map[string]any)["lan_cidrs"] = []any{"198.51.100.0/24"} },
			want:   "capture an outer peer",
		},
		{
			name:   "float_if_id",
			mutate: func(m map[string]any) { m["site_links"].([]any)[0].(map[string]any)["if_id"] = float64(1.0) },
			want:   "type",
		},
		{
			name:   "weak_esp_proposal",
			mutate: func(m map[string]any) { m["site_links"].([]any)[0].(map[string]any)["esp_proposal"] = "aes256-sha1-modp1024" },
			want:   "pattern",
		},
		{
			name:   "duplicate_if_id",
			mutate: func(m map[string]any) { m["site_links"].([]any)[0].(map[string]any)["if_id"] = 102 },
			want:   "XFRM interface IDs",
		},
		{
			name:   "relative_secret_ref",
			mutate: func(m map[string]any) { m["site_links"].([]any)[0].(map[string]any)["secret_ref"] = "file:./secrets/local.psk" },
			want:   "pattern",
		},
		{
			name:   "loopback_gateway",
			mutate: func(m map[string]any) { m["site_links"].([]any)[0].(map[string]any)["outer_path"].(map[string]any)["gateway"] = "127.0.0.1" },
			want:   "unicast IPv4",
		},
		{
			name: "dependent_required_cidrs",
			mutate: func(m map[string]any) {
				m["traffic_policy"].(map[string]any)["allowed_site_pairs"] = []any{
					map[string]any{"a": "production-a", "b": "stage-b", "a_cidrs": []any{"10.43.10.0/24"}},
				}
			},
			want: "dependentRequired",
		},
		{
			name:   "backup_enabled_missing_type",
			mutate: func(m map[string]any) { m["backup"] = map[string]any{"enabled": true} },
			want:   "required",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := cloneRaw(base.Raw)
			tc.mutate(raw)
			_, err := ValidateRaw(raw)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}
}

func TestMultiOBAuthorizedLANsAndBackupReadiness(t *testing.T) {
	multi, err := LoadProfile(repoPath("config", "esports-multi-ob-hillstone.example.yaml"))
	if err != nil {
		t.Fatalf("load multi-ob: %v", err)
	}
	ob1Remote := AuthorizedRemoteLANs(multi, "ob-venue-1")
	if len(ob1Remote) != 2 || ob1Remote[0] != "10.100.10.0/24" || ob1Remote[1] != "10.100.20.0/24" {
		t.Fatalf("unexpected ob-venue-1 remote LANs: %v", ob1Remote)
	}
	ob2Remote := AuthorizedRemoteLANs(multi, "ob-venue-2")
	if len(ob2Remote) != 1 || ob2Remote[0] != "10.100.10.0/24" {
		t.Fatalf("unexpected ob-venue-2 remote LANs: %v", ob2Remote)
	}

	studio, err := LoadProfile(repoPath("tests", "fixtures", "studio-vlan.yaml"))
	if err != nil {
		t.Fatalf("load studio-vlan: %v", err)
	}
	r := EvaluateBackupReadiness(studio)
	if !r.Enabled || r.Status != "PASS" || r.Readiness != "COMPLETE" {
		t.Fatalf("expected PASS/COMPLETE backup readiness, got %+v", r)
	}
}
