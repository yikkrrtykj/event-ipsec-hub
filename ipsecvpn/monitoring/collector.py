"""Collect a stable, redacted snapshot without acquiring deployment write authority."""

import json
import sys
import time
from pathlib import Path

from ..diagnostics import inspect_owned
from ..host import LAB_MARKER, UNIT, Host
from ..profile import ProfileError
from ..secureio import Stop, read_file, read_record
from ..transaction import ACTIVE, INSTALLED, installed_record
from .model import Settings, State, unavailable
from .probes import assess


class ReadOnlyHost(Host):
    def command(self, label, *args, content=None, allowed=(0,), timeout=30, mutate=False):
        if mutate or content is not None:
            raise Stop("The monitor only supports read operations.")
        return super().command(label, *args, allowed=allowed, timeout=min(timeout, 2))


def authorized(host, *, endpoint_only=False):
    if endpoint_only:
        import os
        import platform

        release = Path("/etc/os-release").read_text(encoding="utf-8").splitlines()
        if (
            platform.system() != "Linux"
            or os.getuid() != 0
            or os.geteuid() != 0
            or "ID=ubuntu" not in release
            or 'VERSION_ID="24.04"' not in release
            or read_file(LAB_MARKER, limit=64, parent_mode=0o700) != b"ipsecvpn-lab-v1\n"
        ):
            raise Stop("The UDP helper requires an authorized Ubuntu 24.04 VM.")
        virtual = host.command("VM detection", "systemd-detect-virt", "--vm").strip()
    else:
        virtual = host.probe()["hypervisor"]
    if virtual != "qemu":
        raise Stop("Monitoring runtime requires an authorized Ubuntu 24.04 QEMU VM.")


def collect(host=None):
    host = host or ReadOnlyHost()
    try:
        authorized(host)
        if read_record(INSTALLED) is None:
            return unavailable("NO_PROFILE")
        install = installed_record()
        if host.service(UNIT, "ActiveState") in {"inactive", "failed"}:
            return unavailable("HUB_DOWN", daemon=State.DOWN)
        active = read_record(ACTIVE)
        if active and not Settings.from_profile(active["profile"]).enabled:
            return unavailable("DISABLED")
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
    except (Stop, OSError, KeyError, TypeError, ValueError, ProfileError) as exc:
        return unavailable(getattr(exc, "reason", "UNVERIFIED_RUNTIME"))


def runtime_settings():
    authorized(ReadOnlyHost())
    active = read_record(ACTIVE)
    return Settings.from_profile(active["profile"] if active else {})


if __name__ == "__main__":
    json.dump(collect(), sys.stdout, allow_nan=False, separators=(",", ":"))
