"""Collect a stable, redacted snapshot without acquiring deployment write authority."""

import json
import os
import platform
import sys
import time
from pathlib import Path

from ..diagnostics import inspect_owned
from ..host import LAB_MARKER, UNIT, CommandFailed, Host
from ..secureio import ObservationStop, Stop, read_file, read_record
from ..transaction import ACTIVE, INSTALLED, installed_record
from .model import Settings, State, unavailable
from .probes import assess

COMMAND_STAGES = {
    "VM detection": "HOST_PREFLIGHT",
    "XFRM interface support": "XFRM",
    "IPv4 XFRM support": "XFRM",
    "XFRM state inventory": "XFRM",
    "XFRM policy inventory": "XFRM",
    "nftables support": "NFTABLES",
    "nftables inventory": "NFTABLES",
    "ip query": "ROUTING",
    "TCP management path probe": "ROUTING",
    "Forwarding probe": "ROUTING",
    "VICI query": "VICI",
    "VICI listener probe": "VICI",
    "IKE socket probe": "DAEMON",
    "systemd query": "SYSTEMD",
    "SSH listener snapshot": "HOST_BASELINE",
    "sysctl snapshot": "HOST_BASELINE",
}
READ_COMMANDS = {
    "VM detection": ("systemd-detect-virt", "--vm"),
    "XFRM interface support": ("modprobe", "-nq", "xfrm_interface"),
    "IPv4 XFRM support": ("ip", "xfrm", "policy", "list"),
    "XFRM state inventory": ("ip", "-o", "xfrm", "state", "list", "nokeys"),
    "XFRM policy inventory": ("ip", "-o", "xfrm", "policy", "list", "nosock"),
    "nftables support": ("nft", "-j", "list", "ruleset"),
    "nftables inventory": ("nft", "-j", "list", "ruleset"),
    "TCP management path probe": ("ss", "-H", "-nt", "state", "established"),
    "Forwarding probe": ("sysctl", "-n", "net.ipv4.ip_forward"),
    "VICI listener probe": ("ss", "-H", "-xlpn"),
    "IKE socket probe": ("ss", "-H", "-ulnp", "( sport = :500 or sport = :4500 )"),
    "SSH listener snapshot": ("ss", "-H", "-ltnp"),
}


def read_command(label, args):
    if label in READ_COMMANDS:
        return args == READ_COMMANDS[label]
    if label == "systemd query":
        return args[:2] == ("systemctl", "show")
    if label == "VICI query":
        return args[:2] in {
            ("swanctl", "--version"),
            ("swanctl", "--list-conns"),
            ("swanctl", "--list-sas"),
        }
    if label == "sysctl snapshot":
        return args[:2] == ("sysctl", "-n") and len(args) == 3 and "=" not in args[2]
    if label == "ip query":
        query = tuple(arg for arg in args[3:] if not arg.startswith("-"))
        return args[:3] == ("ip", "-j", "-N") and (
            query[:2]
            in {
                ("address", "show"),
                ("addr", "show"),
                ("link", "show"),
                ("rule", "show"),
                ("route", "show"),
                ("route", "get"),
            }
        )
    return False


class ReadOnlyHost(Host):
    def __init__(self, progress=None):
        super().__init__()
        self.progress = progress

    def command(self, label, *args, content=None, allowed=(0,), timeout=30, mutate=False):
        if mutate or content is not None or not read_command(label, args):
            raise Stop("The monitor only supports read operations.")
        stage = COMMAND_STAGES.get(label, "HOST_PREFLIGHT")
        if self.progress:
            self.progress(stage)
        try:
            return super().command(label, *args, allowed=allowed, timeout=min(timeout, 2))
        except CommandFailed as exc:
            raise ObservationStop("A monitoring command failed.", stage, exc.category) from None


def authorize_endpoint(host):
    if platform.system() != "Linux" or os.getuid() != 0 or os.geteuid() != 0:
        raise Stop("Monitoring runtime requires root on an authorized Ubuntu 24.04 VM.")
    fields = dict(
        line.split("=", 1)
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines()
        if "=" in line
    )
    if fields.get("ID") != "ubuntu" or fields.get("VERSION_ID", "").strip('"') != "24.04":
        raise Stop("Monitoring runtime requires Ubuntu 24.04.")
    if read_file(LAB_MARKER, limit=64, parent_mode=0o700) != b"ipsecvpn-lab-v1\n":
        raise Stop("The root-only isolated VM authorization marker is invalid.")
    virtual = host.command("VM detection", "systemd-detect-virt", "--vm").strip()
    if virtual != "qemu":
        raise Stop("Monitoring runtime requires an authorized Ubuntu 24.04 QEMU VM.")


def authorized(host):
    if host.probe()["hypervisor"] != "qemu":
        raise Stop("Monitoring runtime requires an authorized Ubuntu 24.04 QEMU VM.")


def collect(host=None):
    host = host or ReadOnlyHost()
    stage = "HOST_PREFLIGHT"
    try:
        authorized(host)
        stage = "INSTALLATION"
        if read_record(INSTALLED) is None:
            return unavailable("NO_PROFILE")
        install = installed_record()
        stage = "DAEMON"
        if host.service(UNIT, "ActiveState") in {"inactive", "failed"}:
            return unavailable("HUB_DOWN", daemon=State.DOWN)
        stage = "ACTIVE_PROFILE"
        active = read_record(ACTIVE)
        if active and not Settings.from_profile(active["profile"]).enabled:
            return unavailable("DISABLED")
        stage = "OWNERSHIP"
        active, manifest, live, _ = inspect_owned(host, install, stable=True)
        if not manifest:
            return {**unavailable("NO_PROFILE", daemon=State.UP), "profile_active": False}
        profile = active["profile"]
        settings = Settings.from_profile(profile)
        if not settings.enabled:
            return unavailable("DISABLED")
        sites = []
        for link in manifest.links:
            ike = live.get(link.name)
            child = ike.child if ike else None
            row = {
                "site_id": link.site_id,
                "ike": State.UP if ike else State.DOWN,
                "child": State.UP if child else State.DOWN,
                "kernel": State.UP if child else State.DOWN,
                "protected_route": State.UP,
            }
            if child:
                row["counts"] = child.counts
                row["generation"] = [ike.unique_id, child.unique_id]
            sites.append(row)
        paths, business = assess(
            [
                {
                    "src_site_id": source["site_id"],
                    "dst_site_id": target["site_id"],
                    "state": State.UNKNOWN,
                    "reason_code": "NO_PROBE",
                }
                for source, target in (sites, sites[::-1])
            ],
            settings,
            install,
            manifest,
            live,
        )
        return {
            "schema_version": 1,
            "collector_valid": True,
            "reason_code": "READY",
            "event_id": manifest.event_id,
            "hub_id": profile["hub"]["id"],
            "collected_at": time.time(),
            "daemon": State.UP,
            "profile_active": True,
            "sites": sites,
            "paths": paths,
            "business": business,
        }
    except (Stop, OSError, KeyError, TypeError, ValueError) as exc:
        reason = getattr(exc, "reason", None)
        if reason is None:
            if isinstance(exc, PermissionError):
                reason = "PERMISSION_DENIED"
            elif isinstance(exc, (KeyError, TypeError, ValueError)):
                reason = "INVALID_DATA"
            else:
                reason = "CHECK_FAILED"
        stage = getattr(
            exc,
            "stage",
            {
                "VICI_REJECTED": "VICI",
                "VICI_UNAVAILABLE": "VICI",
                "VICI_TIMEOUT": "VICI",
                "UNOWNED_DAEMON": "VICI",
                "UNOWNED_SA": "XFRM",
                "SA_UNVERIFIED": "XFRM",
            }.get(reason, stage),
        )
        return unavailable(reason, stage=stage)


def runtime_settings(*, endpoint_only=False):
    (authorize_endpoint if endpoint_only else authorized)(ReadOnlyHost())
    active = read_record(ACTIVE)
    return Settings.from_profile(active["profile"] if active else {})


if __name__ == "__main__":
    json.dump(collect(), sys.stdout, allow_nan=False, separators=(",", ":"))
