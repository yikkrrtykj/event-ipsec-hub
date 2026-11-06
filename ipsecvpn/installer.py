"""Prepare the distribution daemon on an exclusive lab host."""

import os
import re
import stat
import sys
from pathlib import Path

from .host import DROPIN, PACKAGES, SOCKET, UNIT
from .renderer import digest
from .secureio import Stop, atomic_write, make_directory, read_file, remove_file, trusted_dir

STATE = Path("/var/lib/ipsecvpn")
UNIT_DIR = Path("/etc/systemd/system")
GUARD = "ipsecvpn-guard.service"
RESTORE = "ipsecvpn-restore.service"
UNIT_FILES = (
    Path("/etc/strongswan.d/ipsecvpn-private.conf"),
    DROPIN,
    UNIT_DIR / GUARD,
    UNIT_DIR / RESTORE,
)


def install_files(python):
    daemon = f"""charon-systemd {{
    load_modular = yes
    install_routes = no
    routing_table = 0
    install_virtual_ip = no
    plugins {{
        include /etc/strongswan.d/charon/*.conf
        kernel-netlink {{
            install_routes_xfrmi = no
        }}
        socket-default {{
            use_ipv6 = no
        }}
        vici {{
            socket = {SOCKET}
        }}
    }}
}}
"""
    dropin = f"[Service]\nEnvironment=STRONGSWAN_CONF={UNIT_FILES[0]}\nExecStartPost=\n"
    guard = f"""[Unit]
Description=ipsecVPN early fail-closed network guard
DefaultDependencies=no
After=local-fs.target nftables.service
Wants=network-pre.target
Before=network-pre.target shutdown.target
Conflicts=shutdown.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart={python} -I -m ipsecvpn.boot guard

[Install]
WantedBy=multi-user.target
"""
    restore = f"""[Unit]
Description=ipsecVPN restore committed lab configuration
Requires={GUARD} {UNIT}
Wants=network-online.target
After={GUARD} network-online.target {UNIT} ssh.service ssh.socket
PartOf={UNIT}

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart={python} -I -m ipsecvpn.boot restore

[Install]
WantedBy=multi-user.target
"""
    return dict(
        zip(UNIT_FILES, (text.encode() for text in (daemon, dropin, guard, restore)), strict=True)
    )


def trusted_python():
    python = sys.executable
    if not re.fullmatch(r"/[A-Za-z0-9/._-]+", python):
        raise Stop("The installed Python path cannot safely be used by systemd.")
    module = Path(__file__).resolve()
    if not {"site-packages", "dist-packages"}.intersection(module.parts):
        raise Stop(
            "Install the wheel in a root-owned virtual environment before installing the service."
        )
    for directory in (module.parent, Path(python).parent, Path(python).resolve().parent):
        os.close(trusted_dir(directory))
    for path in (module, Path(python).resolve()):
        info = path.stat()
        if info.st_uid != 0 or info.st_mode & 0o022 or not stat.S_ISREG(info.st_mode):
            raise Stop("The systemd entry point is not safely owned.")
    return python


def assert_files(record, missing_ok=False):
    for path, content in install_files(record["python"]).items():
        try:
            current = read_file(path, mode=0o600 if path == UNIT_FILES[0] else 0o644)
        except FileNotFoundError:
            if missing_ok:
                continue
            raise Stop("An installed project service file is missing.") from None
        if digest(current) != digest(content):
            raise Stop("An installed project service file has drifted.")


def vendor_plugins():
    directory = Path("/etc/strongswan.d/charon")
    os.close(trusted_dir(directory))
    return {
        path.name: digest(read_file(path, mode=0o644)) for path in sorted(directory.glob("*.conf"))
    }


def activate(host, record):
    assert_files(record, missing_ok=True)
    make_directory(DROPIN.parent, 0o755)
    for path, content in install_files(record["python"]).items():
        atomic_write(path, content, 0o600 if path == UNIT_FILES[0] else 0o644)
    host.command("Reload unit definitions", "systemctl", "daemon-reload", mutate=True)
    host.command("Enable project boot units", "systemctl", "enable", GUARD, RESTORE, mutate=True)
    host.command("Enable owned daemon", "systemctl", "enable", UNIT, mutate=True)
    host.command("Start owned daemon", "systemctl", "start", UNIT, mutate=True)


def deactivate(host, record):
    assert_files(record, missing_ok=True)
    if host.service(UNIT, "LoadState") == "loaded":
        if host.service(UNIT, "DropInPaths") != str(DROPIN):
            raise Stop("Daemon ownership cannot be proven for cleanup.")
        host.command("Stop owned daemon", "systemctl", "stop", UNIT, mutate=True)
        host.command("Disable owned daemon", "systemctl", "disable", UNIT, mutate=True)
    for unit in (RESTORE, GUARD):
        if host.service(unit, "LoadState") == "loaded":
            host.command(
                "Disable project boot unit", "systemctl", "disable", "--now", unit, mutate=True
            )
    for path in UNIT_FILES:
        if path.exists():
            remove_file(path)
    host.command("Reload unit definitions", "systemctl", "daemon-reload", mutate=True)


def install_packages(host, record):
    # Install the private override before any distribution maintainer script starts charon.
    assert_files(record, missing_ok=True)
    make_directory(DROPIN.parent, 0o755)
    make_directory(UNIT_FILES[0].parent, 0o755)
    files = install_files(record["python"])
    atomic_write(UNIT_FILES[0], files[UNIT_FILES[0]])
    atomic_write(DROPIN, files[DROPIN], 0o644)
    host.command("Reload unit definitions", "systemctl", "daemon-reload", mutate=True)
    host.command(
        "APT install",
        "apt-get",
        "-y",
        "--no-install-recommends",
        "--no-upgrade",
        "--no-remove",
        "install",
        *(f"{name}={record['packages'][name]}" for name in PACKAGES),
        mutate=True,
        timeout=600,
    )
    actual = host.packages()
    delta = {
        name: version for name, version in actual.items() if name not in record["before_packages"]
    }
    if delta != record["packages"] or any(
        actual.get(name) != version for name, version in record["before_packages"].items()
    ):
        raise Stop("The observed package delta differs from the preflight simulation.")
    activate(host, record)
    assert_files(record)
    host.assert_exclusive_ike(True)
    record["vendor_plugins"] = vendor_plugins()
