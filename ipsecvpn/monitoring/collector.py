"""Collect a stable, redacted snapshot without acquiring deployment write authority."""

import ipaddress
import json
import os
import platform
import re
import sys
import time
from contextlib import contextmanager
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
        return self.observed_command(stage, label, args, allowed=allowed, timeout=timeout)

    @contextmanager
    def span(self, stage, kind):
        if self.progress:
            self.progress((stage, kind, True))
        try:
            yield
        finally:
            if self.progress:
                self.progress((stage, kind, False))

    def observed_command(self, stage, label, args, *, allowed=(0,), timeout=2, content=None):
        try:
            with self.span(stage, "command"):
                return super().command(
                    label, *args, content=content, allowed=allowed, timeout=min(timeout, 2)
                )
        except CommandFailed as exc:
            raise ObservationStop("A monitoring command failed.", stage, exc.category) from None

    def route_lookups(self, targets):
        keys = list(dict.fromkeys(targets))
        if len(keys) < 2:
            return super().route_lookups(keys)
        lines = []
        for target, source in keys:
            endpoint = str(ipaddress.IPv4Address(target))
            origin = " from " + str(ipaddress.IPv4Address(source)) if source else ""
            lines.append(f"route get {endpoint}{origin}\n")
        # The batch text is constructed exclusively from canonical IPv4 addresses.
        return dict(zip(keys, self.ip_batch("".join(lines), len(keys)), strict=True))

    def routing(self):
        rules, routes = self.ip_batch("rule show\nroute show table all\n", 2)
        self.verify_routing_rules(rules)
        links = self.ip("-details", "link", "show")
        return rules, routes, links

    def ip_batch(self, batch, count):
        args = ("ip", "-j", "-N", "-4", "-batch", "-")
        output = self.observed_command(
            "ROUTING", "Read-only network batch", args, content=batch.encode("ascii")
        )
        decoder = json.JSONDecoder()
        rows = []
        try:
            while output.strip():
                value, end = decoder.raw_decode(output.lstrip())
                if not isinstance(value, list):
                    raise ValueError
                rows.append(value)
                output = output.lstrip()[end:]
            if len(rows) != count:
                raise ValueError
        except ValueError:
            raise ObservationStop(
                "Invalid route lookup output.", "ROUTING", "INVALID_DATA"
            ) from None
        return rows

    @contextmanager
    def vici_inventory(self, pid):
        from ..sa import session

        with session(pid) as client:
            yield MonitoredVici(client, self)

    def ssh_observation(self):
        rows = self.command("SSH listener snapshot", "ss", "-H", "-ltnp").splitlines()
        return {
            "observed_listeners": len(rows),
            "listeners_with_process": sum("users:" in row for row in rows),
            "ssh_process_listeners": sum('("sshd",' in row for row in rows),
        }

    def service_properties(self, unit, *props):
        if len(props) == 1:
            return super().service_properties(unit, *props)
        output = self.command(
            "systemd query",
            "systemctl",
            "show",
            "--all",
            "--no-pager",
            *("--property=" + prop for prop in props),
            unit,
        )
        values = {}
        for line in output.splitlines():
            key, separator, value = line.partition("=")
            if separator and key in props:
                values[key] = values[key] + "\n" + value if key in values else value
        if set(values) != set(props):
            raise ObservationStop("Missing systemd properties.", "SYSTEMD", "INVALID_DATA")
        return values

    def ipv4_setting(self, key, *, label="sysctl snapshot"):
        if key not in {"ip_forward", "conf.all.rp_filter", "conf.default.rp_filter"}:
            raise ObservationStop("Unknown IPv4 setting.", "SYSCTL_BASELINE")
        try:
            with self.span("SYSCTL_BASELINE", "read"):
                return (
                    Path("/proc/sys/net/ipv4", *key.split(".")).read_text(encoding="ascii").strip()
                )
        except OSError as exc:
            raise ObservationStop(
                "IPv4 setting could not be read.",
                "SYSCTL_BASELINE",
                "PERMISSION_DENIED" if isinstance(exc, PermissionError) else "CHECK_FAILED",
            ) from None

    def ssh_listeners(self, ssh):
        rows = self.command("SSH listener snapshot", "ss", "-H", "-ltnp").splitlines()
        attributed = sorted(row.split()[3] for row in rows if '("sshd",' in row)
        if attributed or ssh["ssh.service"] != "active" or ssh["ssh.socket"] != "active":
            return attributed
        # Ubuntu socket activation supplies an independent listener description.
        # The full resulting baseline must still match the committed digest.
        declared = re.findall(r"(\S+) \(Stream\)", ssh["socket"])
        triggers = self.service("ssh.socket", "Triggers").split()
        if not declared or "ssh.service" not in triggers:
            raise ObservationStop("The SSH socket cannot be attributed.", "SSH_BASELINE")
        observed = [row.split()[3] for row in rows]
        listeners = []
        for address in declared:
            wildcard = "*:" + address.rsplit(":", 1)[1]
            if address in observed:
                listeners.append(address)
            elif address.startswith("[::]:") and wildcard in observed:
                listeners.append(wildcard)
            else:
                raise ObservationStop("A systemd SSH listener is missing.", "SSH_BASELINE")
        return sorted(listeners)


class MonitoredVici:
    def __init__(self, client, host):
        self.client = client
        self.host = host

    def list_sas(self):
        with self.host.span("VICI", "read"):
            return list(self.client.list_sas())


def authorize_endpoint(host, *, require_systemd=False):
    if platform.system() != "Linux" or os.getuid() != 0 or os.geteuid() != 0:
        raise Stop("Monitoring runtime requires root on an authorized Ubuntu 24.04 VM.")
    fields = dict(
        line.split("=", 1)
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines()
        if "=" in line
    )
    if fields.get("ID") != "ubuntu" or fields.get("VERSION_ID", "").strip('"') != "24.04":
        raise Stop("Monitoring runtime requires Ubuntu 24.04.")
    if require_systemd and not Path("/run/systemd/system").is_dir():
        raise Stop("Monitoring requires a systemd-managed isolated VM.")
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
        # Verify the lab identity here. The joint ownership proof below already
        # reads the actual nftables rules, SAD, SPD and XFRM links.
        authorize_endpoint(host, require_systemd=True)
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
        report = unavailable(reason, stage=stage)
        if stage == "SSH_BASELINE" and isinstance(host, ReadOnlyHost):
            try:
                report["ssh_observation"] = host.ssh_observation()
            except Stop:
                pass
        return report


def runtime_settings(*, endpoint_only=False):
    host = ReadOnlyHost()
    if endpoint_only:
        authorize_endpoint(host, require_systemd=True)
    else:
        authorized(host)
    active = read_record(ACTIVE)
    return Settings.from_profile(active["profile"] if active else {})


if __name__ == "__main__":
    json.dump(collect(), sys.stdout, allow_nan=False, separators=(",", ":"))
