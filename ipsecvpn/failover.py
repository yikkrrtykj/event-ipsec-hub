"""Classify manual observations and manage backup-lock failover state."""

import json
import time
from dataclasses import dataclass
from pathlib import Path as _FilePath
from typing import Literal

Path = Literal["primary", "backup"]
Selection = Literal["primary", "backup", "unavailable"]
FAILOVER_STATE_FILE = _FilePath("/var/lib/ipsecvpn/failover-state.json")


@dataclass(frozen=True)
class PathProof:
    """Fresh receipts for every authorized pair, bound to one path on both sites."""

    path: Path
    udp_both: bool
    tcp_both: bool
    source_preserved: bool
    pinned: bool


def observe(
    first: Selection | None,
    second: Selection | None,
    proof: PathProof | None = None,
    *,
    primary_ready: tuple[bool, bool] | None = None,
    hold_met: bool = False,
):
    """Return a manual decision for two FIB observations and current data receipts.

    Stale or unavailable evidence must be passed as None. A verified path always
    requires matching route selections; a recovery indication never changes them.
    """
    result = {"selected_paths": [first, second], "data_path": "SKIP"}
    if first is None or second is None:
        return {**result, "state": "UNKNOWN", "status": "SKIP"}
    if first != second:
        state = "SINGLE_SIDE_TRANSITION" if "unavailable" in (first, second) else "ASYMMETRIC_STOP"
        return {**result, "state": state, "status": "STOP"}
    if first == "unavailable":
        return {**result, "state": "BOTH_UNAVAILABLE", "status": "STOP"}
    if proof is None:
        return {**result, "state": "UNKNOWN", "status": "SKIP"}
    if proof.path != first or not proof.pinned:
        return {**result, "state": "UNKNOWN", "status": "STOP", "reason": "WRONG_PATH"}
    if not proof.source_preserved:
        return {**result, "state": "UNKNOWN", "status": "STOP", "reason": "SOURCE_CHANGED"}
    if not (proof.udp_both and proof.tcp_both):
        return {**result, "state": "UNKNOWN", "status": "FAIL", "data_path": "FAIL"}
    result["data_path"] = "PASS"
    if first == "backup" and primary_ready and any(primary_ready):
        state = "MANUAL_CUTOVER_REQUIRED" if all(primary_ready) and hold_met else "RECOVERY_PENDING"
        return {**result, "state": state, "status": "SKIP"}
    return {**result, "state": f"{first.upper()}_VERIFIED", "status": "PASS"}


def _default_state():
    return {
        "mode": "PRIMARY_ACTIVE",
        "active_path": "primary",
        "consecutive_primary_failures": 0,
        "primary_recovered_since": None,
        "switched_at": None,
        "last_reason": None,
        "history": [],
    }


def load_failover_state(state_file=FAILOVER_STATE_FILE):
    path = _FilePath(state_file)
    if not path.is_file():
        return _default_state()
    data = json.loads(path.read_text(encoding="utf-8"))
    return {**_default_state(), **data}


def save_failover_state(state, state_file=FAILOVER_STATE_FILE):
    path = _FilePath(state_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    payload = json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    tmp.write_text(payload, encoding="utf-8")
    tmp.replace(path)
    return state


def apply_hub_xfrm_gate(locked: bool, *, host=None):
    """Set project-owned XFRM interfaces down while backup-locked to block premature failback."""
    from .host import Host
    from .renderer import build_manifest
    from .secureio import Stop, read_record
    from .transaction import ACTIVE, installed_record

    runner = host or Host()
    runner.probe()
    install = installed_record()
    active = read_record(ACTIVE)
    if not active:
        raise Stop("No active Hub profile is deployed for XFRM gate control.")
    manifest = build_manifest(active["profile"])
    alias = f"ipsecvpn:{install['token']}"
    links = {row["ifname"]: row for row in runner.ip("-details", "link", "show")}
    desired_state = "down" if locked else "up"
    changed = []
    for link in manifest.links:
        row = links.get(link.name)
        if not row or row.get("ifalias") != alias:
            raise Stop("Refusing XFRM gate operation on an unowned interface.")
        runner.command(
            f"XFRM gate {desired_state}",
            "ip",
            "link",
            "set",
            "dev",
            link.name,
            desired_state,
            mutate=True,
        )
        changed.append(link.name)
    return {"gate": "LOCKED_DOWN" if locked else "UNLOCKED_UP", "interfaces": changed}


def notify_feishu_failover(action: str, state: dict, detail: str = "") -> bool:
    """Deliver a failover state transition notification when Feishu bridge is configured."""
    from .monitoring.bridge import CONFIG, deliver, resolve_delivery_target
    from .monitoring.collector import runtime_settings
    from .secureio import Stop, read_file

    try:
        config = json.loads(read_file(CONFIG, limit=4096, parent_mode=0o700))
        if not config.get("enabled", False):
            return False
        settings = runtime_settings(endpoint_only=True)
        target = resolve_delivery_target(config, port=config["port"], exporter_port=settings.port)
        secret = read_file(
            _FilePath("/etc/ipsecvpn/secrets/monitor-signing"), limit=256, parent_mode=0o700
        ).strip()
    except (Stop, OSError, KeyError, ValueError):
        return False
    message = f"[FAILOVER] action={action} mode={state['mode']} active={state['active_path']}" + (
        f"\n{detail}" if detail else ""
    )
    return deliver(target, secret, message)


class FailoverController:
    """Automatic failover to healthy backup with strict manual-confirm failback.

    Once switched to backup (`BACKUP_LOCKED`), traffic NEVER fails back to primary
    automatically. Even after primary stays healthy for `recovery_hold_seconds`,
    the controller only transitions to `PRIMARY_RECOVERY_READY` and waits for an
    explicit operator `confirm_failback()` call.
    """

    def __init__(
        self,
        state_file=FAILOVER_STATE_FILE,
        *,
        failure_threshold: int = 3,
        recovery_hold_seconds: float = 180.0,
    ):
        self.state_file = _FilePath(state_file)
        self.failure_threshold = max(1, int(failure_threshold))
        self.recovery_hold_seconds = max(0.0, float(recovery_hold_seconds))
        self.state = load_failover_state(self.state_file)

    def _record_event(self, event, now, detail):
        history = list(self.state.get("history", []))[-49:]
        history.append({"at": now, "event": event, **detail})
        self.state["history"] = history

    def _persist(self):
        return save_failover_state(self.state, self.state_file)

    def evaluate(
        self,
        *,
        primary_healthy: bool,
        backup_healthy: bool,
        now: float | None = None,
        reason: str = "probe_failure",
    ):
        now = time.time() if now is None else float(now)
        mode = self.state["mode"]

        if mode == "PRIMARY_ACTIVE":
            if primary_healthy:
                self.state["consecutive_primary_failures"] = 0
                self._persist()
                return {
                    "status": "PASS",
                    "action": "KEEP_PRIMARY",
                    "notify_feishu": False,
                    "state": dict(self.state),
                }
            failures = self.state["consecutive_primary_failures"] + 1
            self.state["consecutive_primary_failures"] = failures
            if failures < self.failure_threshold:
                self._persist()
                return {
                    "status": "PASS",
                    "action": "DEGRADED_OBSERVING",
                    "notify_feishu": False,
                    "state": dict(self.state),
                }
            if not backup_healthy:
                self.state["mode"] = "MANUAL_STOP"
                self.state["last_reason"] = "primary_and_backup_unhealthy"
                self._record_event("MANUAL_STOP", now, {"reason": self.state["last_reason"]})
                self._persist()
                return {
                    "status": "STOP",
                    "action": "ALERT_BOTH_UNHEALTHY",
                    "notify_feishu": True,
                    "state": dict(self.state),
                }
            self.state["mode"] = "BACKUP_LOCKED"
            self.state["active_path"] = "backup"
            self.state["switched_at"] = now
            self.state["primary_recovered_since"] = None
            self.state["last_reason"] = reason
            self._record_event("AUTO_FAILOVER_TO_BACKUP", now, {"reason": reason})
            self._persist()
            return {
                "status": "PASS",
                "action": "SWITCH_TO_BACKUP",
                "notify_feishu": True,
                "state": dict(self.state),
            }

        if mode in {"BACKUP_LOCKED", "PRIMARY_RECOVERY_READY"}:
            if not backup_healthy:
                self.state["mode"] = "MANUAL_STOP"
                self.state["last_reason"] = "backup_failed_while_locked"
                self._record_event("MANUAL_STOP", now, {"reason": self.state["last_reason"]})
                self._persist()
                return {
                    "status": "STOP",
                    "action": "ALERT_BACKUP_DEGRADED",
                    "notify_feishu": True,
                    "state": dict(self.state),
                }
            if primary_healthy:
                since = self.state.get("primary_recovered_since")
                if since is None:
                    self.state["primary_recovered_since"] = now
                    since = now
                if now - since >= self.recovery_hold_seconds:
                    newly_ready = mode != "PRIMARY_RECOVERY_READY"
                    self.state["mode"] = "PRIMARY_RECOVERY_READY"
                    if newly_ready:
                        self._record_event(
                            "PRIMARY_RECOVERY_READY",
                            now,
                            {"held_seconds": round(now - since, 2)},
                        )
                    self._persist()
                    return {
                        "status": "PASS",
                        "action": "WAIT_MANUAL_FAILBACK",
                        "notify_feishu": newly_ready,
                        "state": dict(self.state),
                    }
            else:
                self.state["primary_recovered_since"] = None
                self.state["mode"] = "BACKUP_LOCKED"
            self._persist()
            return {
                "status": "PASS",
                "action": "KEEP_BACKUP_LOCKED",
                "notify_feishu": False,
                "state": dict(self.state),
            }

        return {
            "status": "STOP",
            "action": "MANUAL_INTERVENTION_REQUIRED",
            "notify_feishu": False,
            "state": dict(self.state),
        }

    def manual_switch_to_backup(
        self,
        *,
        operator: str,
        backup_healthy: bool = True,
        reason: str = "manual_switch",
        now: float | None = None,
    ):
        now = time.time() if now is None else float(now)
        if not backup_healthy:
            return {
                "status": "STOP",
                "action": "REJECT_UNHEALTHY_BACKUP",
                "detail": "Backup path is not healthy; refusing manual switch.",
                "state": dict(self.state),
            }
        self.state["mode"] = "BACKUP_LOCKED"
        self.state["active_path"] = "backup"
        self.state["switched_at"] = now
        self.state["primary_recovered_since"] = None
        self.state["last_reason"] = reason
        self._record_event("MANUAL_SWITCH_TO_BACKUP", now, {"operator": operator, "reason": reason})
        self._persist()
        return {
            "status": "PASS",
            "action": "SWITCH_TO_BACKUP",
            "detail": f"Switched to backup and locked by {operator}.",
            "state": dict(self.state),
        }

    def confirm_failback(
        self,
        *,
        operator: str,
        primary_healthy: bool = True,
        force: bool = False,
        now: float | None = None,
    ):
        now = time.time() if now is None else float(now)
        mode = self.state["mode"]
        if mode == "PRIMARY_ACTIVE":
            return {
                "status": "PASS",
                "action": "NOOP_ALREADY_PRIMARY",
                "detail": "Primary path is already active.",
                "state": dict(self.state),
            }
        if not primary_healthy and not force:
            return {
                "status": "STOP",
                "action": "REJECT_UNHEALTHY_PRIMARY",
                "detail": (
                    "Primary path is not verified healthy; pass --force only in an emergency."
                ),
                "state": dict(self.state),
            }
        if mode != "PRIMARY_RECOVERY_READY" and not force:
            return {
                "status": "STOP",
                "action": "REJECT_HOLD_NOT_MET",
                "detail": "Primary recovery hold period has not completed; wait or pass --force.",
                "state": dict(self.state),
            }
        self.state["mode"] = "PRIMARY_ACTIVE"
        self.state["active_path"] = "primary"
        self.state["consecutive_primary_failures"] = 0
        self.state["primary_recovered_since"] = None
        self.state["last_reason"] = f"manual_failback_by_{operator}"
        self._record_event(
            "MANUAL_FAILBACK_TO_PRIMARY",
            now,
            {"operator": operator, "forced": force},
        )
        self._persist()
        return {
            "status": "PASS",
            "action": "SWITCH_TO_PRIMARY",
            "detail": f"Manual failback to primary confirmed by {operator}.",
            "state": dict(self.state),
        }
