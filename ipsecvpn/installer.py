"""Prepare the distribution daemon on an exclusive lab host."""

import os
import re
import stat
import sys
from pathlib import Path

from .host import DROPIN, PACKAGES, PRIVATE_CONF, SOCKET, UNIT, VENDOR_UNITS, VICI_PATH
from .renderer import digest
from .secureio import (
    Stop,
    atomic_write,
    make_directory,
    read_file,
    remove_file,
    sync_dir,
    trusted_dir,
)

STATE = Path("/var/lib/ipsecvpn")
UNIT_DIR = Path("/etc/systemd/system")
GUARD = "ipsecvpn-guard.service"
RESTORE = "ipsecvpn-restore.service"
UNIT_FILES = (
    PRIVATE_CONF,
    DROPIN,
    UNIT_DIR / GUARD,
    UNIT_DIR / RESTORE,
)
CONFIG_PATHS = tuple(map(Path, ("/etc/strongswan.conf", "/etc/strongswan.d", "/etc/swanctl")))
INSTALL_DIRS = (DROPIN.parent, UNIT_FILES[0].parent)


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


def verify_install_source(host, retained, package_state):
    host.assert_idle_ike()
    extra_paths = (
        *UNIT_FILES,
        Path("/etc/ipsec.conf"),
        Path("/etc/ipsec.secrets"),
        Path("/etc/systemd/system") / UNIT,
        Path("/run/systemd/system") / UNIT,
        Path("/run/systemd/system") / f"{UNIT}.d",
    )
    if any(path.exists() or path.is_symlink() for path in extra_paths):
        raise Stop("An existing IKE configuration or reserved service path is unowned.")
    if any(host.service(unit, "LoadState") != "not-found" for unit in (GUARD, RESTORE)):
        raise Stop("A reserved boot service is unowned.")
    if host.command("Package audit", "dpkg", "--audit").strip():
        raise Stop("The VM already has an incomplete package transaction.")
    related = {
        name
        for name in package_state
        if "strongswan" in name or name == "charon-systemd" or name.startswith("libcharon-")
    }
    if retained is None:
        if (
            related
            or host.service(UNIT, "LoadState") != "not-found"
            or any(path.exists() or path.is_symlink() for path in (*CONFIG_PATHS, DROPIN.parent))
        ):
            raise Stop("An existing strongSwan package or configuration is unowned.")
        return

    packages = retained["packages"]
    if (
        not set(PACKAGES).issubset(packages)
        or not related.issubset(packages)
        or any(
            package_state.get(name) != {"version": version, "status": "ii "}
            for name, version in packages.items()
        )
    ):
        raise Stop("Retained package versions or states differ from the committed install.")
    if (
        host.service(UNIT, "FragmentPath") not in VENDOR_UNITS
        or host.service(UNIT, "UnitFileState") != "disabled"
        or host.service(UNIT, "DropInPaths")
        or host.service(UNIT, "NeedDaemonReload") != "no"
    ):
        raise Stop("The retained strongSwan unit is no longer the disabled distribution unit.")
    if DROPIN.parent.exists() or DROPIN.parent.is_symlink():
        os.close(trusted_dir(DROPIN.parent, 0o755))
        if any(DROPIN.parent.iterdir()):
            raise Stop("A foreign strongSwan service override is present.")
    if host.command("Distribution file verification", "dpkg", "--verify", *packages).strip():
        raise Stop("Retained strongSwan distribution files have changed.")
    owned = set(host.command("Distribution file list", "dpkg-query", "-L", *packages).splitlines())
    for root in CONFIG_PATHS:
        for path in (root, *root.rglob("*")):
            if str(path) not in owned or path.is_symlink():
                raise Stop("A retained strongSwan configuration path is unowned.")
            if path.is_dir():
                os.close(trusted_dir(path))
            else:
                info = path.lstat()
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_uid != 0
                    or info.st_mode & 0o022
                    or info.st_nlink != 1
                ):
                    raise Stop("A retained strongSwan configuration file is unsafe.")


def activate(host, record):
    assert_files(record, missing_ok=True)
    make_directory(DROPIN.parent, 0o755)
    for path, content in install_files(record["python"]).items():
        atomic_write(path, content, 0o600 if path == UNIT_FILES[0] else 0o644)
    host.command("Reload unit definitions", "systemctl", "daemon-reload", mutate=True)
    host.command("Enable project boot units", "systemctl", "enable", GUARD, RESTORE, mutate=True)
    host.command("Enable owned daemon", "systemctl", "enable", UNIT, mutate=True)
    host.command("Start owned daemon", "systemctl", "start", UNIT, mutate=True)


def vici_socket_identity():
    try:
        info = VICI_PATH.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1:
        raise Stop("The VICI socket path has unsafe type or ownership.")
    return info.st_dev, info.st_ino


def deactivate(host, record):
    assert_files(record, missing_ok=True)
    owned_files = {path for path in UNIT_FILES if path.exists()}
    if host.service(UNIT, "LoadState") == "loaded":
        dropins = host.service(UNIT, "DropInPaths")
        if dropins == str(DROPIN) and DROPIN in owned_files:
            if host.service(UNIT, "FragmentPath") not in VENDOR_UNITS:
                raise Stop("The strongSwan unit cannot be proven owned for cleanup.")
            pid = host.service(UNIT, "MainPID")
            socket = vici_socket_identity()
            if pid != "0":
                host.assert_private_daemon(pid)
            if socket is not None:
                listeners = host.vici_listeners()
                if (
                    pid == "0"
                    or not listeners
                    or any(set(re.findall(r"pid=(\d+),", line)) != {pid} for line in listeners)
                ):
                    raise Stop("VICI socket ownership cannot be proven for cleanup.")
            host.command("Stop owned daemon", "systemctl", "stop", UNIT, mutate=True)
            remaining = vici_socket_identity()
            if remaining is not None:
                if remaining != socket or host.vici_listeners():
                    raise Stop("The VICI socket changed or still has a listener after stop.")
                remove_file(VICI_PATH)
            host.command("Disable owned daemon", "systemctl", "disable", UNIT, mutate=True)
        elif (
            dropins
            or host.service(UNIT, "ActiveState") != "inactive"
            or host.service(UNIT, "UnitFileState") != "disabled"
        ):
            raise Stop("Daemon ownership cannot be proven for cleanup.")
    for unit in (RESTORE, GUARD):
        if host.service(unit, "LoadState") == "loaded":
            path = UNIT_DIR / unit
            if (
                path not in owned_files
                or host.service(unit, "FragmentPath") != str(path)
                or host.service(unit, "DropInPaths")
            ):
                raise Stop("A boot service cannot be proven owned for cleanup.")
            host.command(
                "Disable project boot unit", "systemctl", "disable", "--now", unit, mutate=True
            )
    for path in sorted(owned_files):
        remove_file(path)
    for path in INSTALL_DIRS:
        if str(path) in record.get("created_dirs", ()) and path.exists():
            os.close(trusted_dir(path, 0o755))
            if not any(path.iterdir()):
                path.rmdir()
                sync_dir(path.parent)
    if owned_files:
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
    after = host.package_state()
    expected = {
        **record["before_package_state"],
        **{
            name: {"version": version, "status": "ii "}
            for name, version in record["packages"].items()
        },
    }
    if after != expected or host.command("Package audit", "dpkg", "--audit").strip():
        raise Stop("The full dpkg state differs from the preflight plan.")
