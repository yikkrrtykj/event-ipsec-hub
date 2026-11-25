package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func runCLI(args ...string) (int, string, string) {
	var out, errBuf bytes.Buffer
	code := run(args, &out, &errBuf)
	return code, out.String(), errBuf.String()
}

func TestCLIOfflineCommandsAndTencentExport(t *testing.T) {
	sample := filepath.Join("..", "..", "config", "esports-multi-ob-hillstone.example.yaml")
	fixtures := filepath.Join("..", "..", "tests", "fixtures")

	// profiles list
	code, out, _ := runCLI("profiles", "list", "--directory", fixtures, "--json")
	if code != 0 {
		t.Fatalf("profiles list failed: %d %s", code, out)
	}
	var listRes map[string]any
	if err := json.Unmarshal([]byte(out), &listRes); err != nil || listRes["status"] != "PASS" {
		t.Fatalf("unexpected profiles list: %s", out)
	}

	// validate
	code, out, _ = runCLI("validate", "-c", sample, "--json")
	if code != 0 {
		t.Fatalf("validate failed: %d %s", code, out)
	}

	// plan & render
	code, out, _ = runCLI("plan", "-c", sample)
	if code != 0 || !strings.Contains(out, `"ob-venue-1"`) {
		t.Fatalf("plan failed: %d %s", code, out)
	}
	code, out, _ = runCLI("render", "-c", sample, "--json")
	if code != 0 || !strings.Contains(out, `"swanctl.conf"`) {
		t.Fatalf("render failed: %d %s", code, out)
	}

	// export-peer tencent-json
	code, out, _ = runCLI("export-peer", "-c", sample, "--site", "ob-venue-1", "--format", "tencent-json")
	if code != 0 {
		t.Fatalf("export-peer tencent-json failed: %d %s", code, out)
	}
	var tc map[string]any
	if err := json.Unmarshal([]byte(out), &tc); err != nil {
		t.Fatalf("invalid tencent-json: %v", err)
	}
	if tc["PreShareKey"] != "<SEND_SEPARATELY>" {
		t.Fatalf("expected redacted PSK, got %v", tc["PreShareKey"])
	}
	if tc["IKEOptionsSpecification"].(map[string]any)["IKEVersion"] != "IKEV2" {
		t.Fatalf("expected IKEV2, got %v", tc["IKEOptionsSpecification"])
	}

	// export-peer hillstone-draft
	code, out, _ = runCLI("export-peer", "-c", sample, "--site", "ob-venue-1", "--format", "hillstone-draft")
	if code != 0 || !strings.Contains(out, "NOT_APPLYABLE_CONFIG") {
		t.Fatalf("hillstone-draft failed: %d %s", code, out)
	}
}

func TestCLIFailoverLifecycleAndNonLinuxInstallStop(t *testing.T) {
	stateFile := filepath.Join(t.TempDir(), "cli-failover.json")

	code, out, _ := runCLI("failover", "status", "--state-file", stateFile, "--json")
	if code != 0 || !strings.Contains(out, `"PRIMARY_ACTIVE"`) {
		t.Fatalf("failover status failed: %d %s", code, out)
	}

	code, out, _ = runCLI("failover", "switch-backup", "--operator", "lead-ops", "--reason", "drill", "--confirm", "--state-file", stateFile, "--json")
	if code != 0 || !strings.Contains(out, `"BACKUP_LOCKED"`) {
		t.Fatalf("failover switch-backup failed: %d %s", code, out)
	}

	// Failback rejected before hold window without --force
	code, out, _ = runCLI("failover", "failback", "--operator", "lead-ops", "--confirm", "--state-file", stateFile, "--json")
	if code != 1 || !strings.Contains(out, `"REJECT_HOLD_NOT_MET"`) {
		t.Fatalf("expected hold rejection exit 1, got %d %s", code, out)
	}

	// Force failback succeeds
	code, out, _ = runCLI("failover", "failback", "--operator", "lead-ops", "--force", "--confirm", "--state-file", stateFile, "--json")
	if code != 0 || !strings.Contains(out, `"PRIMARY_ACTIVE"`) {
		t.Fatalf("forced failback failed: %d %s", code, out)
	}

	// Set hub role (#12)
	code, out, _ = runCLI("failover", "set-role", "--role", "backup", "--operator", "lead-ops", "--confirm", "--state-file", stateFile, "--json")
	if code != 0 || !strings.Contains(out, `"hub_role": "backup"`) {
		t.Fatalf("set-role failed: %d %s", code, out)
	}

	// Non-Linux install must return FAIL/STOP
	code, out, _ = runCLI("install", "--confirm", "--json")
	if code != 1 || !strings.Contains(out, `"STOP"`) {
		t.Fatalf("expected FAIL/STOP on non-Linux install, got %d %s", code, out)
	}
}

func TestCLIMonitorValidateTimelineAndMetrics(t *testing.T) {
	sample := filepath.Join("..", "..", "config", "event.example.yaml")
	code, out, _ := runCLI("monitor", "validate", "-c", sample, "--json")
	if code != 0 || !strings.Contains(out, `"Monitoring validated."`) {
		t.Fatalf("monitor validate failed: %d %s", code, out)
	}

	dbPath := filepath.Join(t.TempDir(), "mon.db")
	code, out, _ = runCLI("monitor", "timeline", "--db", dbPath, "--site", "ob-venue-1")
	if code != 0 || !strings.Contains(out, `"OBSERVATION_UNVERIFIED"`) {
		t.Fatalf("monitor timeline failed: %d %s", code, out)
	}

	code, out, _ = runCLI("monitor", "metrics", "--db", dbPath)
	if code != 0 || !strings.Contains(out, "event_ipsec_collector_healthy 0") {
		t.Fatalf("monitor metrics failed: %d %s", code, out)
	}
}
