"""Manage only the two optional monitoring units in the authorized lab."""

import json
import os
from contextlib import contextmanager
from pathlib import Path

from ..host import read_host_authorization
from ..installer import trusted_python
from ..secureio import Stop, atomic_write, make_directory, read_file, remove_file
from .collector import ReadOnlyHost, authorized, runtime_settings

DIRECTORY = Path("/var/lib/event-ipsec-hub-monitor")
BRIDGE_CONFIG = Path("/etc/ipsecvpn/monitor-bridge.json")
SYSTEMD = Path("/etc/systemd/system")
SERVICES = {"sampler": "sampler", "exporter": "exporter", "feishu": "bridge"}


def notify_ready():
    import socket

    address = os.environ.get("NOTIFY_SOCKET")
    if address:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.sendto(b"READY=1", "\0" + address[1:] if address.startswith("@") else address)


def unit(component, python, *, allow_feishu_egress=False):
    if component == "sampler":
        # procfs checks require a superset of charon's permitted capabilities.
        # The sampler has no IP or packet sockets and exposes no listener.
        capabilities = "CAP_DAC_OVERRIDE CAP_NET_ADMIN CAP_NET_RAW"
        families = "AF_UNIX AF_NETLINK"
        write_access = (
            "RuntimeDirectory=event-ipsec-hub-sampler\nRuntimeDirectoryMode=0700\n"
            "SocketBindDeny=any\n"
        )
    else:
        capabilities = ""
        families = "AF_UNIX AF_INET AF_INET6"
        write_access = f"ReadWritePaths={DIRECTORY}\n" if component == "feishu" else ""
    ip_policy = (
        "# Production Feishu egress enabled; destination validated by official_target()."
        if (component == "feishu" and allow_feishu_egress)
        else "IPAddressDeny=any\nIPAddressAllow=localhost"
    )
    return f"""[Unit]
Description=Event IPsec Hub monitoring ({component})
After=local-fs.target

[Service]
Type=notify
NotifyAccess=main
ExecStart={python} -I -m ipsecvpn.monitoring.{SERVICES[component]}
TimeoutStartSec=25s
TimeoutStopSec=5s
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictAddressFamilies={families}
CapabilityBoundingSet={capabilities}
SystemCallFilter=~@debug @mount @module @reboot
{ip_policy}
UMask=0077
{write_access}
[Install]
WantedBy=multi-user.target
""".encode("ascii")


@contextmanager
def monitor_lock():
    import fcntl
    import stat

    path = Path("/run/event-ipsec-hub-monitor.lock")
    with os.fdopen(os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600), "rb") as lock:
        info = os.fstat(lock.fileno())
        if (info.st_uid, info.st_nlink, stat.S_IMODE(info.st_mode), stat.S_ISREG(info.st_mode)) != (
            0,
            1,
            0o600,
            True,
        ):
            raise Stop("The monitoring lock is not project-owned.")
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Stop("Another monitor service operation is in progress.") from None
        yield


def _feishu_egress_enabled():
    try:
        if read_host_authorization() != "production":
            return False
        config = json.loads(read_file(BRIDGE_CONFIG, limit=4096, parent_mode=0o700))
    except (Stop, OSError, ValueError):
        return False
    return bool(config.get("feishu_webhook_ref") or config.get("feishu_webhook"))


def verify_unit(host, path, content, *, alternate=None):
    name = path.name
    try:
        stored = read_file(path, mode=0o644)
    except FileNotFoundError:
        stored = None
    fragment = host.service(name, "FragmentPath")
    valid_contents = {content} | ({alternate} if alternate is not None else set())
    if (
        (stored is not None and stored not in valid_contents)
        or (fragment and fragment != str(path))
        or host.service(name, "DropInPaths")
        or (stored is None and fragment)
    ):
        raise Stop("A monitoring unit or override cannot be attributed to this project.")
    if stored is None:
        return "missing"
    return "exact" if stored == content else "outdated"


def systemctl(host, *args):
    # No daemon or network names are accepted by the service lifecycle API.
    host.command("Monitor service operation", "systemctl", *args, timeout=35)


def change(action, confirmed, with_bridge=False):
    from ..host import Host

    host = ReadOnlyHost()
    authorized(host)
    if action == "serve" and not runtime_settings().enabled:
        return {"status": "SKIP", "detail": "Monitoring is disabled or no profile is active."}
    python = trusted_python()
    components = (
        ("sampler", "exporter", "feishu")
        if with_bridge or action == "stop"
        else ("sampler", "exporter")
    )
    egress = _feishu_egress_enabled() if action == "serve" else False
    units = {
        SYSTEMD / f"event-ipsec-hub-{component}.service": unit(
            component, python, allow_feishu_egress=(component == "feishu" and egress)
        )
        for component in components
    }
    alternates = {
        SYSTEMD / "event-ipsec-hub-feishu.service": unit(
            "feishu", python, allow_feishu_egress=not egress
        )
    }
    for path, content in units.items():
        verify_unit(host, path, content, alternate=alternates.get(path))
    if not confirmed:
        return {"status": "PASS", "detail": "Monitor dry-run.", "units": [p.name for p in units]}
    with monitor_lock():
        owned = {
            path: verify_unit(host, path, content, alternate=alternates.get(path))
            for path, content in units.items()
        }
        return reconcile(Host(), action, units, owned)


def reconcile(host, action, units, owned):
    if action == "stop":
        present = {path: state != "missing" for path, state in owned.items()}
        for path, exists in present.items():
            if exists:
                systemctl(host, "disable", "--now", path.name)
                remove_file(path)
        if any(present.values()):
            systemctl(host, "daemon-reload")
        for filename in ("path.json", "delivery.json"):
            path = DIRECTORY / filename
            try:
                read_file(path, parent_mode=0o700)
            except FileNotFoundError:
                continue
            remove_file(path)
        try:
            DIRECTORY.rmdir()
        except FileNotFoundError:
            pass
        return {"status": "PASS", "detail": "Owned monitoring services removed."}

    make_directory(DIRECTORY)
    created = []
    updated = False
    try:
        for path, content in units.items():
            if owned[path] != "exact":
                was_missing = owned[path] == "missing"
                atomic_write(path, content, mode=0o644)
                updated = True
                if was_missing:
                    created.append(path)
        if updated:
            systemctl(host, "daemon-reload")
        for path in units:
            systemctl(host, "enable", "--now", path.name)
    except (Stop, OSError):
        for path in reversed(created):
            systemctl(host, "disable", "--now", path.name)
            remove_file(path)
        if created:
            systemctl(host, "daemon-reload")
        raise Stop(
            "Monitoring service startup failed. Check the monitoring unit journal."
        ) from None
    return {"status": "PASS", "detail": "Owned monitoring services are running."}
