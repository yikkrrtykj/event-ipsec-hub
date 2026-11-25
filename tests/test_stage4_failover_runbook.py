"""Unit tests for Stage 4 (#12/#13 auto-failover + manual-confirm failback & CLI)."""

import json

from ipsecvpn import cli, failover
from ipsecvpn.failover import FailoverController


def test_auto_failover_locks_backup_and_never_auto_fails_back(tmp_path):
    state_file = tmp_path / "failover.json"
    ctrl = FailoverController(state_file, failure_threshold=3, recovery_hold_seconds=180)

    # First 2 failures only observe
    r1 = ctrl.evaluate(primary_healthy=False, backup_healthy=True, now=100)
    r2 = ctrl.evaluate(primary_healthy=False, backup_healthy=True, now=105)
    assert r1["action"] == "DEGRADED_OBSERVING"
    assert r2["action"] == "DEGRADED_OBSERVING"

    # 3rd failure triggers automatic switch to backup + Feishu alert
    r3 = ctrl.evaluate(
        primary_healthy=False, backup_healthy=True, now=110, reason="udp_loss_100pct"
    )
    assert r3["action"] == "SWITCH_TO_BACKUP"
    assert r3["notify_feishu"] is True
    assert ctrl.state["mode"] == "BACKUP_LOCKED"
    assert ctrl.state["active_path"] == "backup"

    # Primary recovers, but hold period not met -> stays BACKUP_LOCKED
    r4 = ctrl.evaluate(primary_healthy=True, backup_healthy=True, now=200)
    assert r4["action"] == "KEEP_BACKUP_LOCKED"
    assert ctrl.state["active_path"] == "backup"

    # Manual failback rejected before hold completes
    rej = ctrl.confirm_failback(operator="ops-a", primary_healthy=True, now=250)
    assert rej["status"] == "STOP"
    assert rej["action"] == "REJECT_HOLD_NOT_MET"

    # Hold period met (>= 180s) -> PRIMARY_RECOVERY_READY, STILL does NOT auto fail back
    r5 = ctrl.evaluate(primary_healthy=True, backup_healthy=True, now=381)
    assert r5["action"] == "WAIT_MANUAL_FAILBACK"
    assert r5["notify_feishu"] is True
    assert ctrl.state["mode"] == "PRIMARY_RECOVERY_READY"
    assert ctrl.state["active_path"] == "backup"

    # Explicit operator confirmation switches back to primary
    ok = ctrl.confirm_failback(operator="ops-a", primary_healthy=True, now=400)
    assert ok["status"] == "PASS"
    assert ok["action"] == "SWITCH_TO_PRIMARY"
    assert ctrl.state["mode"] == "PRIMARY_ACTIVE"
    assert ctrl.state["active_path"] == "primary"


def test_both_unhealthy_enters_manual_stop_without_blind_switch(tmp_path):
    ctrl = FailoverController(tmp_path / "failover.json", failure_threshold=1)
    res = ctrl.evaluate(primary_healthy=False, backup_healthy=False, now=10)
    assert res["status"] == "STOP"
    assert res["action"] == "ALERT_BOTH_UNHEALTHY"
    assert res["notify_feishu"] is True
    assert ctrl.state["mode"] == "MANUAL_STOP"
    assert ctrl.state["active_path"] == "primary"


def test_cli_failover_status_switch_and_manual_failback(tmp_path, capsys):
    state_file = tmp_path / "cli-failover.json"
    assert cli.main(["failover", "status", "--state-file", str(state_file), "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["state"]["mode"] == "PRIMARY_ACTIVE"

    assert (
        cli.main(
            [
                "failover",
                "switch-backup",
                "--operator",
                "lead-ops",
                "--reason",
                "pre_match_drill",
                "--confirm",
                "--state-file",
                str(state_file),
                "--json",
            ]
        )
        == 0
    )
    out2 = json.loads(capsys.readouterr().out)
    assert out2["state"]["mode"] == "BACKUP_LOCKED"

    # Without --force before hold window, CLI exits 1 on STOP
    assert (
        cli.main(
            [
                "failover",
                "failback",
                "--operator",
                "lead-ops",
                "--confirm",
                "--state-file",
                str(state_file),
                "--json",
            ]
        )
        == 1
    )
    rejected = json.loads(capsys.readouterr().out)
    assert rejected["status"] == "STOP"
    assert rejected["action"] == "REJECT_HOLD_NOT_MET"

    # Force manual failback via CLI
    assert (
        cli.main(
            [
                "failover",
                "failback",
                "--operator",
                "lead-ops",
                "--force",
                "--confirm",
                "--state-file",
                str(state_file),
                "--json",
            ]
        )
        == 0
    )
    out3 = json.loads(capsys.readouterr().out)
    assert out3["state"]["mode"] == "PRIMARY_ACTIVE"


def test_cli_failover_evaluate_with_gate_and_feishu(tmp_path, monkeypatch, capsys):
    state_file = tmp_path / "eval-failover.json"
    gates = []
    notifications = []
    monkeypatch.setattr(
        failover,
        "apply_hub_xfrm_gate",
        lambda locked: gates.append(locked) or {"gate": "LOCKED_DOWN" if locked else "UNLOCKED_UP"},
    )
    monkeypatch.setattr(
        failover,
        "notify_feishu_failover",
        lambda action, state, detail="": notifications.append(action) or True,
    )

    for _ in range(2):
        assert (
            cli.main(
                [
                    "failover",
                    "evaluate",
                    "--primary-unhealthy",
                    "--backup-healthy",
                    "--state-file",
                    str(state_file),
                    "--json",
                ]
            )
            == 0
        )
        capsys.readouterr()

    assert (
        cli.main(
            [
                "failover",
                "evaluate",
                "--primary-unhealthy",
                "--backup-healthy",
                "--apply-gate",
                "--send-feishu",
                "--state-file",
                str(state_file),
                "--json",
            ]
        )
        == 0
    )
    switched = json.loads(capsys.readouterr().out)
    assert switched["action"] == "SWITCH_TO_BACKUP"
    assert switched["hub_gate"]["gate"] == "LOCKED_DOWN"
    assert switched["feishu_delivered"] is True
    assert gates == [True]
    assert notifications == ["SWITCH_TO_BACKUP"]
