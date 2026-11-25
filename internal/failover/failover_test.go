package failover

import (
	"path/filepath"
	"testing"
)

func TestAutoFailoverLocksBackupAndRequiresManualFailback(t *testing.T) {
	stateFile := filepath.Join(t.TempDir(), "failover.json")
	ctrl, err := NewController(stateFile, 3, 180)
	if err != nil {
		t.Fatalf("NewController: %v", err)
	}

	r1, err := ctrl.Evaluate(false, true, 100, "")
	if err != nil || r1["action"] != "DEGRADED_OBSERVING" {
		t.Fatalf("expected DEGRADED_OBSERVING, got %v err=%v", r1, err)
	}
	r2, err := ctrl.Evaluate(false, true, 105, "")
	if err != nil || r2["action"] != "DEGRADED_OBSERVING" {
		t.Fatalf("expected DEGRADED_OBSERVING, got %v err=%v", r2, err)
	}
	r3, err := ctrl.Evaluate(false, true, 110, "udp_loss_100pct")
	if err != nil || r3["action"] != "SWITCH_TO_BACKUP" || r3["notify_feishu"] != true {
		t.Fatalf("expected SWITCH_TO_BACKUP + notify, got %v err=%v", r3, err)
	}
	if ctrl.State.Mode != "BACKUP_LOCKED" || ctrl.State.ActivePath != "backup" {
		t.Fatalf("unexpected state: %+v", ctrl.State)
	}

	r4, _ := ctrl.Evaluate(true, true, 200, "")
	if r4["action"] != "KEEP_BACKUP_LOCKED" || ctrl.State.ActivePath != "backup" {
		t.Fatalf("should stay locked before hold window: %v", r4)
	}

	rej, _ := ctrl.ConfirmFailback("ops-a", true, false, 250)
	if rej["status"] != "STOP" || rej["action"] != "REJECT_HOLD_NOT_MET" {
		t.Fatalf("expected REJECT_HOLD_NOT_MET, got %v", rej)
	}

	r5, _ := ctrl.Evaluate(true, true, 381, "")
	if r5["action"] != "WAIT_MANUAL_FAILBACK" || r5["notify_feishu"] != true || ctrl.State.Mode != "PRIMARY_RECOVERY_READY" || ctrl.State.ActivePath != "backup" {
		t.Fatalf("expected WAIT_MANUAL_FAILBACK while remaining on backup, got %v", r5)
	}

	ok, _ := ctrl.ConfirmFailback("ops-a", true, false, 400)
	if ok["status"] != "PASS" || ok["action"] != "SWITCH_TO_PRIMARY" || ctrl.State.Mode != "PRIMARY_ACTIVE" {
		t.Fatalf("expected SWITCH_TO_PRIMARY, got %v", ok)
	}
}

func TestBothUnhealthyAndHubRoleSwap(t *testing.T) {
	stateFile := filepath.Join(t.TempDir(), "failover.json")
	ctrl, _ := NewController(stateFile, 1, 180)
	res, _ := ctrl.Evaluate(false, false, 10, "")
	if res["status"] != "STOP" || res["action"] != "ALERT_BOTH_UNHEALTHY" || ctrl.State.Mode != "MANUAL_STOP" {
		t.Fatalf("expected MANUAL_STOP, got %v", res)
	}

	sw, err := ctrl.SetHubRole("backup", "ops-lead", 20)
	if err != nil || sw["status"] != "PASS" || ctrl.State.HubRole != "backup" {
		t.Fatalf("expected hub role backup, got %v err=%v", sw, err)
	}
}

func TestObserveMatrix(t *testing.T) {
	if out := Observe("primary", "backup", nil, nil, false); out["state"] != "ASYMMETRIC_STOP" {
		t.Fatalf("expected ASYMMETRIC_STOP, got %v", out)
	}
	proof := &PathProof{Path: "backup", UDPBoth: true, TCPBoth: true, SourcePreserved: true, Pinned: true}
	ready := [2]bool{true, true}
	if out := Observe("backup", "backup", proof, &ready, true); out["state"] != "MANUAL_CUTOVER_REQUIRED" {
		t.Fatalf("expected MANUAL_CUTOVER_REQUIRED, got %v", out)
	}
}
