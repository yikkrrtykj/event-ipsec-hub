"""Monitoring settings and bounded states independent of deployment records."""

import re
from dataclasses import dataclass
from enum import IntEnum

ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,62}", re.ASCII)
PROBE_FILE = "/var/lib/event-ipsec-hub-monitor/path.json"
DIRECTORY = "/var/lib/event-ipsec-hub-monitor"
STAGES = frozenset(
    {
        "HOST_PREFLIGHT",
        "INSTALLATION",
        "SYSTEMD",
        "DAEMON",
        "DAEMON_ENV",
        "ACTIVE_PROFILE",
        "OWNERSHIP",
        "VICI",
        "XFRM",
        "ROUTING",
        "NFTABLES",
        "HOST_BASELINE",
        "WORKER",
    }
)
REASONS = frozenset(
    {
        "READY",
        "DISABLED",
        "NO_PROFILE",
        "NO_SAMPLE",
        "STALE",
        "COLLECTOR_TIMEOUT",
        "COLLECTOR_ERROR",
        "NO_PROBE",
        "PATH_UNVERIFIED",
        "PATH_DOWN",
        "VICI_UNAVAILABLE",
        "UNOWNED_SA",
        "UNOWNED_DAEMON",
        "SA_TRANSITION",
        "SA_UNVERIFIED",
        "UNFINISHED_TRANSACTION",
        "UNVERIFIED_RUNTIME",
        "HUB_DOWN",
        "KERNEL_MISMATCH",
        "PERMISSION_DENIED",
        "COMMAND_FAILED",
        "COMMAND_TIMEOUT",
        "CHECK_FAILED",
        "INVALID_DATA",
        "VICI_REJECTED",
        "VICI_TIMEOUT",
    }
)


class State(IntEnum):
    UNKNOWN = -1
    DOWN = 0
    UP = 1


@dataclass(frozen=True)
class Settings:
    enabled: bool
    port: int
    interval: int
    timeout: int
    ttl: int
    probe_enabled: bool
    probe_ttl: int

    @classmethod
    def from_profile(cls, profile):
        config = profile.get("monitoring", {})
        exporter = config.get("exporter", {})
        probe = config.get("udp_path", {})
        return cls(
            config.get("enabled", False),
            exporter.get("port", 9814),
            exporter.get("interval_seconds", 15),
            exporter.get("timeout_seconds", 5),
            exporter.get("ttl_seconds", 30),
            probe.get("enabled", False),
            probe.get("ttl_seconds", 25),
        )


def unavailable(reason, *, daemon=State.UNKNOWN, stage=None):
    return {
        "schema_version": 1,
        "collector_valid": False,
        "reason_code": reason if reason in REASONS else "UNVERIFIED_RUNTIME",
        **({"stage": stage} if stage in STAGES else {}),
        "daemon": daemon,
        "profile_active": None,
        "sites": [],
        "paths": [],
        "business": State.UNKNOWN,
    }
