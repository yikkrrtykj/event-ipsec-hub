"""Disposable Ubuntu 24.04 QEMU acceptance for V3 (#7, #8, #9, #10, #11, #13)."""

import json
import os
import secrets
import subprocess
import sys
import time
from dataclasses import replace
from datetime import UTC, datetime
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, HTTPServer
from ipaddress import IPv4Network
from pathlib import Path
from threading import Thread

import yaml

from ipsecvpn.failover import PathProof, observe
from ipsecvpn.host import UNIT, Host
from ipsecvpn.installer import install_files
from ipsecvpn.monitoring import active_probe
from ipsecvpn.monitoring.bridge import CONFIG as BRIDGE_CONF
from ipsecvpn.monitoring.collector import collect
from ipsecvpn.monitoring.model import State
from ipsecvpn.profile import load_profile, validate_profile
from ipsecvpn.renderer import DeploymentManifest, build_manifest, swanctl_config
from ipsecvpn.resources import Resources
from ipsecvpn.sa import inventory, session
from ipsecvpn.secureio import Stop, atomic_write, read_keys, read_record
from ipsecvpn.transaction import INSTALLED, JOURNAL, Deployment

HERE = Path(__file__).resolve().parent
SUMMARY = Path("/var/tmp/ipsecvpn-v3-acceptance.jsonl")
BASELINE_FILE = Path("/var/lib/ipsecvpn-v3-baseline.json")
PROFILE = Path("/etc/ipsecvpn/profiles/v3-lab.yaml")
SECRETS = Path("/etc/ipsecvpn/secrets")
PEER_ROOT = Path("/run/ipsecvpn-v3")
TOPOLOGY_UNIT = "ipsecvpn-v3-topology.service"
CLI = Path(sys.executable).with_name("ipsecvpn")
HOST = Host()
PORT = 32491
METRICS_PORT, BRIDGE_PORT, MOCK_PORT = 9814, 9815, 9816
HEAD = (
    Path("/opt/ipsecvpn-lab/head-sha").read_text(encoding="ascii").strip()
    if Path("/opt/ipsecvpn-lab/head-sha").is_file()
    else "0" * 40
)

SITES = {
    "server-core": {
        "router": "peer-srv",
        "host": "lan-srv",
        "lans": ["10.100.10.0/24", "10.100.20.0/24"],
        "extra_lan": "10.100.99.0/24",
    },
    "ob-alpha": {
        "router": "peer-ob1",
        "host": "lan-ob1",
        "lans": ["10.101.10.0/24"],
    },
    "ob-beta": {
        "router": "peer-ob2",
        "host": "lan-ob2",
        "lans": ["10.102.10.0/24", "10.102.11.0/24"],
    },
}


def cmd(*args, allowed=(0,), timeout=60, input_text=None):
    proc = subprocess.run(
        args, capture_output=True, text=True, check=False, input=input_text, timeout=timeout
    )
    if proc.returncode not in allowed:
        raise RuntimeError(
            f"{Path(args[0]).name}({args[1:4]}) exited {proc.returncode}: {proc.stderr[:300]}"
        )
    return proc


def ip(*args, ns=None, allowed=(0,)):
    prefix = ("-n", ns) if ns else ()
    return cmd("ip", *prefix, *args, allowed=allowed)


def in_ns(name, *args):
    return ("ip", "netns", "exec", name, *args)


def cli(*args, expect=0):
    proc = cmd(str(CLI), *args, "--json", allowed=(0, 1))
    report = json.loads(proc.stdout)
    if expect is not None and proc.returncode != expect:
        raise RuntimeError(f"cli {args} exited {proc.returncode}: {report}")
    return report


def addr(cidr, host_num):
    return str(IPv4Network(cidr)[host_num])


def env_info():
    probe = HOST.probe()
    return {
        **probe,
        "iproute2": cmd("dpkg-query", "-W", "-f=${Version}", "iproute2").stdout.strip(),
        "nft": cmd("nft", "--version").stdout.strip(),
        "strongswan": cmd("dpkg-query", "-W", "-f=${Version}", "charon-systemd").stdout.strip(),
    }


def emit(cases, expected, observed, status="PASS"):
    env = env_info()
    for case in cases.split():
        row = {
            "case": case,
            "time_utc": datetime.now(UTC).isoformat(),
            "head_sha": HEAD,
            "environment": env,
            "action": expected,
            "expected": expected,
            "observed": observed,
            "status": status,
            "proof_refs": [SUMMARY.name],
        }
        line = json.dumps(row, sort_keys=True)
        if SECRETS.is_dir():
            for secret_path in SECRETS.iterdir():
                val = secret_path.read_bytes().strip()
                if val and (val in line.encode() or val.hex() in line):
                    raise RuntimeError("Refusing to write secret material into evidence.")
        with SUMMARY.open("a", encoding="utf-8") as handle:
            print(line, file=handle)
        print(line, flush=True)


def wait_until(predicate, timeout=60, interval=0.5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        val = predicate()
        if val:
            return val
        time.sleep(interval)
    raise AssertionError("Timed out waiting for expected lab condition.")


def write_profile_data(profile, path=PROFILE):
    validate_profile(profile)
    path.write_text(yaml.safe_dump(profile, sort_keys=False), encoding="utf-8")
    path.chmod(0o600)


def create_v3_profile():
    SECRETS.mkdir(mode=0o700, parents=True, exist_ok=True)
    for name in ("srv-isp1", "srv-isp2", "ob-alpha", "ob-beta"):
        psk = SECRETS / f"{name}.psk"
        if not psk.exists():
            psk.write_bytes(os.urandom(32).hex().encode("ascii") + b"\n")
            psk.chmod(0o600)
    profile = {
        "schema_version": "2.0",
        "event": {
            "id": "v3-esports-lab",
            "name": "V3 Multi-Site Dual-ISP Lab",
            "purpose": "Isolated QEMU acceptance for #7 #8 #9 #10 #11 #13",
        },
        "hub": {
            "id": "hub-v3",
            "platform": "ubuntu-24.04",
            "public_endpoint": "198.51.100.10",
            "ike_identity": "@hub-v3.example",
            "provider_label": "Lab-VPS",
            "location_label": "Lab-Region",
            "country": "LAB",
        },
        "sites": [
            {
                "id": "server-core",
                "display_name": "Central Match Server",
                "role": "server",
                "country": "LAB",
                "public_endpoint": "198.51.100.21",
                "ike_identity": "198.51.100.21",
                "lan_cidrs": [
                    "10.100.10.0/24",
                    "10.100.20.0/24",
                    "10.100.99.0/24",
                ],
                "uplinks": [
                    {
                        "id": "isp1",
                        "isp_label": "ISP-A",
                        "public_endpoint": "198.51.100.21",
                        "ike_identity": "198.51.100.21",
                        "interface": "wan1",
                    },
                    {
                        "id": "isp2",
                        "isp_label": "ISP-B",
                        "public_endpoint": "192.0.2.21",
                        "ike_identity": "192.0.2.21",
                        "interface": "wan2",
                    },
                ],
                "firewall": {"vendor": "Hillstone", "os_version": "StoneOS 5.5R10"},
            },
            {
                "id": "ob-alpha",
                "display_name": "OB Venue Alpha",
                "role": "ob",
                "country": "LAB",
                "public_endpoint": "198.51.100.22",
                "ike_identity": "198.51.100.22",
                "lan_cidrs": ["10.101.10.0/24"],
                "firewall": {"vendor": "Hillstone", "os_version": "StoneOS 5.5R10"},
            },
            {
                "id": "ob-beta",
                "display_name": "OB Venue Beta",
                "role": "ob",
                "country": "LAB",
                "public_endpoint": "198.51.100.23",
                "ike_identity": "198.51.100.23",
                "lan_cidrs": ["10.102.10.0/24", "10.102.11.0/24"],
                "firewall": {"vendor": "Hillstone", "os_version": "StoneOS 5.5R10"},
            },
        ],
        "security": {
            "dpd_delay_seconds": 2,
            "start_action": "start",
            "dpd_action": "restart",
            "close_action": "start",
        },
        "site_links": [
            {
                "id": "srv-isp1",
                "site_id": "server-core",
                "uplink_id": "isp1",
                "secret_ref": "file:/etc/ipsecvpn/secrets/srv-isp1.psk",
                "if_id": 201,
                "selector_mode": "exact",
                "route_priority": 10,
                "outer_path": {"interface": "wanisp1", "isp_label": "ISP-A"},
            },
            {
                "id": "srv-isp2",
                "site_id": "server-core",
                "uplink_id": "isp2",
                "secret_ref": "file:/etc/ipsecvpn/secrets/srv-isp2.psk",
                "if_id": 211,
                "selector_mode": "exact",
                "route_priority": 20,
                "outer_path": {
                    "interface": "wanisp2",
                    "isp_label": "ISP-B",
                    "source_ip": "203.0.113.10",
                    "gateway": "203.0.113.1",
                    "route_table": 101,
                    "policy_priority": 1001,
                },
            },
            {
                "site_id": "ob-alpha",
                "secret_ref": "file:/etc/ipsecvpn/secrets/ob-alpha.psk",
                "if_id": 202,
                "selector_mode": "route_based",
                "route_priority": 10,
                "outer_path": {"interface": "wanisp1", "isp_label": "ISP-A"},
            },
            {
                "site_id": "ob-beta",
                "secret_ref": "file:/etc/ipsecvpn/secrets/ob-beta.psk",
                "if_id": 203,
                "selector_mode": "per_pair",
                "route_priority": 10,
                "outer_path": {"interface": "wanisp1", "isp_label": "ISP-A"},
            },
        ],
        "traffic_policy": {
            "allowed_site_pairs": [
                {
                    "a": "ob-alpha",
                    "b": "server-core",
                    "a_cidrs": ["10.101.10.0/24"],
                    "b_cidrs": ["10.100.10.0/24", "10.100.20.0/24"],
                },
                {
                    "a": "ob-beta",
                    "b": "server-core",
                    "a_cidrs": ["10.102.10.0/24", "10.102.11.0/24"],
                    "b_cidrs": ["10.100.10.0/24"],
                },
            ]
        },
        "backup": {"enabled": False},
        "monitoring": {
            "enabled": True,
            "exporter": {"interval_seconds": 6, "timeout_seconds": 4, "ttl_seconds": 16},
            "udp_path": {"enabled": True, "ttl_seconds": 14},
        },
    }
    write_profile_data(profile)
    return profile


def peer_args(ns_name, *args):
    return in_ns(
        ns_name,
        "unshare",
        "--mount",
        "--propagation",
        "private",
        "sh",
        "-ec",
        'mount --bind "$1" /run; shift; exec "$@"',
        "v3-peer",
        str(PEER_ROOT / ns_name),
        *args,
    )


def start_peer_daemon(ns_name, peer_links, keys, event_id):
    root = PEER_ROOT / ns_name
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    conf = Path(f"/etc/strongswan.d/v3-{ns_name}.conf")
    daemon_cfg = next(iter(install_files(sys.executable).values())).decode()
    daemon_cfg = daemon_cfg.replace(
        "install_routes = no",
        "install_routes = no\n    retransmit_timeout = 1\n    retransmit_tries = 2",
    )
    conf.write_text(daemon_cfg, encoding="ascii")
    conf.chmod(0o600)
    proc = subprocess.Popen(
        peer_args(ns_name, "env", f"STRONGSWAN_CONF={conf}", "/usr/sbin/charon-systemd"),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    (root / "pid").write_text(str(proc.pid), encoding="ascii")
    for _ in range(40):
        if (root / "charon.vici").is_socket():
            break
        time.sleep(0.25)
    else:
        raise RuntimeError(f"Peer VICI did not start for {ns_name}")

    reversed_links = tuple(
        replace(
            link,
            source=link.peer,
            peer=link.source,
            local_id=link.remote_id,
            remote_id=link.local_id,
            local_ts=link.remote_ts,
            remote_ts=link.local_ts,
            start_action="none",
            dpd_action="clear",
            close_action="none",
        )
        for link in peer_links
    )
    folder = Path(f"/etc/swanctl/v3-{ns_name}")
    folder.mkdir(mode=0o700, exist_ok=True)
    cpath = folder / "swanctl.conf"
    cpath.write_text(
        swanctl_config(DeploymentManifest(event_id, reversed_links), keys), encoding="ascii"
    )
    cpath.chmod(0o600)
    try:
        cmd(
            *peer_args(
                ns_name,
                "/usr/sbin/swanctl",
                "--load-all",
                "--clear",
                "--noprompt",
                "--file",
                str(cpath),
            )
        )
    finally:
        cpath.unlink(missing_ok=True)


def bootstrap_topology():
    if cmd("hostname").stdout.strip() != "ipsecvpn-v3-lab":
        raise RuntimeError("Expected ipsecvpn-v3-lab guest.")
    HOST.probe()
    profile = load_profile(PROFILE)
    manifest = build_manifest(profile)
    keys = read_keys(profile)

    # Create WAN switches & ISP-2 router
    for ns_name in ("wan-isp1", "wan-isp2", "isp2-rtr", "v3-backup-hub"):
        ip("netns", "add", ns_name)
        ip("link", "set", "lo", "up", ns=ns_name)
    for sw in ("wan-isp1", "wan-isp2"):
        ip("link", "add", "br0", "type", "bridge", ns=sw)
        ip("link", "set", "br0", "up", ns=sw)

    # Hub wanisp1 (198.51.100.10/24) and wanisp2 (203.0.113.10/24)
    ip("link", "add", "wanisp1", "type", "veth", "peer", "name", "hub1", "netns", "wan-isp1")
    ip("link", "set", "hub1", "master", "br0", ns="wan-isp1")
    ip("link", "set", "hub1", "up", ns="wan-isp1")
    ip("link", "set", "wanisp1", "address", "02:00:00:31:00:10")
    ip("addr", "add", "198.51.100.10/24", "dev", "wanisp1")
    ip("link", "set", "wanisp1", "up")

    ip("link", "add", "wanisp2", "type", "veth", "peer", "name", "hub2", "netns", "wan-isp2")
    ip("link", "set", "hub2", "master", "br0", ns="wan-isp2")
    ip("link", "set", "hub2", "up", ns="wan-isp2")
    ip("link", "set", "wanisp2", "address", "02:00:00:32:00:10")
    ip("addr", "add", "203.0.113.10/24", "dev", "wanisp2")
    ip("link", "set", "wanisp2", "up")

    # Connect isp2-rtr (203.0.113.1/24 on wan-isp2, 192.0.2.1/24 towards peer-srv wan2)
    ip(
        "link",
        "add",
        "rtr2",
        "type",
        "veth",
        "peer",
        "name",
        "eth0",
        "netns",
        "isp2-rtr",
        ns="wan-isp2",
    )
    ip("link", "set", "rtr2", "master", "br0", ns="wan-isp2")
    ip("link", "set", "rtr2", "up", ns="wan-isp2")
    ip("addr", "add", "203.0.113.1/24", "dev", "eth0", ns="isp2-rtr")
    ip("link", "set", "eth0", "up", ns="isp2-rtr")
    cmd(
        *in_ns(
            "isp2-rtr", "sysctl", "-qw", "net.ipv4.ip_forward=1", "net.ipv4.conf.all.rp_filter=0"
        )
    )
    cmd(
        *in_ns(
            "v3-backup-hub",
            "sysctl",
            "-qw",
            "net.ipv4.ip_forward=1",
            "net.ipv4.conf.all.rp_filter=0",
        )
    )

    # Build 3 site router + LAN host namespaces
    links_by_site = {}
    for link in manifest.links:
        links_by_site.setdefault(link.site_id, []).append(link)

    for idx, (site_id, meta) in enumerate(SITES.items()):
        rtr, hst = meta["router"], meta["host"]
        for ns_name in (rtr, hst):
            ip("netns", "add", ns_name)
            ip("link", "set", "lo", "up", ns=ns_name)
        cmd(
            *in_ns(
                rtr,
                "sysctl",
                "-qw",
                "net.ipv4.ip_forward=1",
                "net.ipv4.conf.all.rp_filter=0",
                "net.ipv4.conf.default.rp_filter=0",
            )
        )
        # ISP-1 veth
        wan_dev = "wan1" if site_id == "server-core" else "wan"
        ip(
            "link",
            "add",
            f"p1_{idx}",
            "type",
            "veth",
            "peer",
            "name",
            wan_dev,
            "netns",
            rtr,
            ns="wan-isp1",
        )
        ip("link", "set", f"p1_{idx}", "master", "br0", ns="wan-isp1")
        ip("link", "set", f"p1_{idx}", "up", ns="wan-isp1")
        ep1 = f"198.51.100.{21 + idx}/24"
        ip("addr", "add", ep1, "dev", wan_dev, ns=rtr)
        ip("link", "set", wan_dev, "up", ns=rtr)

        if site_id == "server-core":
            # ISP-2 veth via isp2-rtr
            ip(
                "link",
                "add",
                "to_srv",
                "type",
                "veth",
                "peer",
                "name",
                "wan2",
                "netns",
                rtr,
                ns="isp2-rtr",
            )
            ip("addr", "add", "192.0.2.1/24", "dev", "to_srv", ns="isp2-rtr")
            ip("link", "set", "to_srv", "up", ns="isp2-rtr")
            ip("addr", "add", "192.0.2.21/24", "dev", "wan2", ns=rtr)
            ip("link", "set", "wan2", "up", ns=rtr)
            ip("route", "add", "203.0.113.0/24", "via", "192.0.2.1", "dev", "wan2", ns=rtr)

        # Backup transit link inside peer/backup namespaces (zero Hub baseline impact)
        b_ip_rtr = f"10.179.{idx + 1}.2"
        b_ip_hub = f"10.179.{idx + 1}.1"
        ip(
            "link",
            "add",
            "bkp0",
            "type",
            "veth",
            "peer",
            "name",
            f"to_{site_id[:6]}",
            "netns",
            "v3-backup-hub",
            ns=rtr,
        )
        ip("addr", "add", f"{b_ip_rtr}/30", "dev", "bkp0", ns=rtr)
        ip("link", "set", "bkp0", "up", ns=rtr)
        ip("addr", "add", f"{b_ip_hub}/30", "dev", f"to_{site_id[:6]}", ns="v3-backup-hub")
        ip("link", "set", f"to_{site_id[:6]}", "up", ns="v3-backup-hub")

        # Inside LAN veth
        ip("link", "add", "inside", "type", "veth", "peer", "name", "eth0", "netns", hst, ns=rtr)
        ip("link", "set", "inside", "up", ns=rtr)
        ip("link", "set", "eth0", "up", ns=hst)
        all_nets = meta["lans"] + ([meta["extra_lan"]] if "extra_lan" in meta else [])
        for net in all_nets:
            plen = IPv4Network(net).prefixlen
            ip("addr", "add", f"{addr(net, 1)}/{plen}", "dev", "inside", ns=rtr)
            ip("addr", "add", f"{addr(net, 11)}/{plen}", "dev", "eth0", ns=hst)
            ip("route", "add", net, "via", b_ip_rtr, "dev", f"to_{site_id[:6]}", ns="v3-backup-hub")
        ip("route", "add", "default", "via", addr(all_nets[0], 1), ns=hst)

        # XFRM interfaces and inner routes on peer router
        site_links = links_by_site[site_id]
        for l_idx, link in enumerate(site_links):
            tname = f"tunnel{l_idx + 1}" if len(site_links) > 1 else "tunnel"
            ip("link", "add", tname, "type", "xfrm", "if_id", str(link.if_id), ns=rtr)
            ip("link", "set", tname, "up", ns=rtr)
            metric = str(link.route_priority)
            # Route all other sites' LANs into tunnel so Hub ACL/XFRM is the authoritative gate
            for other_id, other_meta in SITES.items():
                if other_id == site_id:
                    continue
                other_nets = other_meta["lans"] + (
                    [other_meta["extra_lan"]] if "extra_lan" in other_meta else []
                )
                for r_cidr in other_nets:
                    ip("route", "replace", r_cidr, "dev", tname, "metric", metric, ns=rtr)
                    ip(
                        "route",
                        "replace",
                        r_cidr,
                        "via",
                        b_ip_hub,
                        "dev",
                        "bkp0",
                        "metric",
                        "60",
                        ns=rtr,
                    )
                    ip("route", "replace", "blackhole", r_cidr, "metric", "32000", ns=rtr)

        start_peer_daemon(rtr, site_links, keys, manifest.event_id)


def install_topology_unit():
    unit = Path("/etc/systemd/system") / TOPOLOGY_UNIT
    unit.write_text(
        f"""[Unit]
Description=V3 disposable multi-site Dual-ISP peer network
After=local-fs.target systemd-sysctl.service
Before=ipsecvpn-restore.service

[Service]
Type=oneshot
ExecStart={sys.executable} {__file__} topology
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
""",
        encoding="ascii",
    )
    cmd("systemctl", "daemon-reload")
    cmd("systemctl", "enable", TOPOLOGY_UNIT)
    cmd("systemctl", "start", TOPOLOGY_UNIT)
    cmd("systemctl", "is-active", TOPOLOGY_UNIT)


def reload_peer_conns(site_id, manifest, keys):
    meta = SITES[site_id]
    rtr = meta["router"]
    peer_links = [link for link in manifest.links if link.site_id == site_id]
    reversed_links = tuple(
        replace(
            link,
            source=link.peer,
            peer=link.source,
            local_id=link.remote_id,
            remote_id=link.local_id,
            local_ts=link.remote_ts,
            remote_ts=link.local_ts,
            start_action="none",
            dpd_action="clear",
            close_action="none",
        )
        for link in peer_links
    )
    folder = Path(f"/etc/swanctl/v3-{rtr}")
    cpath = folder / "swanctl.conf"
    cpath.write_text(
        swanctl_config(DeploymentManifest(manifest.event_id, reversed_links), keys),
        encoding="ascii",
    )
    cpath.chmod(0o600)
    try:
        cmd(
            *peer_args(
                rtr,
                "/usr/sbin/swanctl",
                "--load-all",
                "--clear",
                "--noprompt",
                "--file",
                str(cpath),
            )
        )
    finally:
        cpath.unlink(missing_ok=True)


def exchange(
    src_site, dst_site, src_cidr, dst_cidr, proto="udp", sport=PORT + 1, expect_fail=False
):
    traffic_py = str(HERE / "traffic.py")
    src_host = SITES[src_site]["host"]
    dst_host = SITES[dst_site]["host"]
    src_ip = addr(src_cidr, 11)
    dst_ip = addr(dst_cidr, 11)
    nonce = secrets.token_hex(8)
    server = subprocess.Popen(
        in_ns(dst_host, sys.executable, traffic_py, "server", proto, dst_ip, str(PORT), "2"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        ready = server.stdout.readline().strip()
        assert ready == "READY", f"Server failed to bind: {server.stderr.read()}"
        client = subprocess.run(
            in_ns(
                src_host,
                sys.executable,
                traffic_py,
                "client",
                proto,
                src_ip,
                str(sport),
                dst_ip,
                str(PORT),
                "2",
                "96",
                nonce,
                "default",
                "0",
            ),
            capture_output=True,
            text=True,
            check=False,
            timeout=12,
        )
        if expect_fail:
            assert client.returncode != 0, f"Expected traffic {src_ip}->{dst_ip} to be blocked!"
            server.kill()
            return {"blocked": True, "src": src_ip, "dst": dst_ip, "protocol": proto}
        if client.returncode != 0:
            raise RuntimeError(
                f"Traffic {proto} {src_ip}->{dst_ip} failed: {client.stdout} {client.stderr}"
            )
        srv_out, _ = server.communicate(timeout=6)
        srv_rows = json.loads(srv_out)
        # Verify original source IP preserved end-to-end
        assert all(row["source"][0] == src_ip for row in srv_rows), srv_rows
        return {
            "passed": True,
            "src": src_ip,
            "dst": dst_ip,
            "protocol": proto,
            "packets": len(srv_rows),
        }
    finally:
        if server.poll() is None:
            server.kill()
            server.wait()


def wait_all_links_up(manifest, timeout=60):
    pid = HOST.assert_daemon({link.name for link in manifest.links})

    def _ready():
        try:
            snap = inventory(HOST, manifest, pid, attempts=1)
        except Stop:
            return None
        if all(snap.get(link.name) and snap.get(link.name).child for link in manifest.links):
            return snap
        return None

    return wait_until(_ready, timeout=timeout, interval=0.8)


def baseline_for(manifest):
    install = read_record(INSTALLED)
    return Resources(HOST, install["token"], (manifest,) if manifest else ()).baseline()


def verify_issue7_nsite_isolation_and_multichild(manifest):
    # Ensure unattended start_action=start established all 4 links + 5 CHILD SAs automatically!
    snap = wait_all_links_up(manifest, timeout=60)
    ob2_link = next(item for item in manifest.links if item.site_id == "ob-beta")
    assert len(snap.get(ob2_link.name).children) == 2
    status = cli("status")
    assert status["status"] == "PASS"
    emit(
        "I07_N01",
        "3-site Hub auto-establishes route_based, exact and per_pair multi-CHILD SAs.",
        {"links": len(manifest.links), "ob_beta_children": len(snap.get(ob2_link.name).children)},
    )

    # Bidirectional UDP & TCP on all authorized pairs
    flows = [
        exchange("ob-alpha", "server-core", "10.101.10.0/24", "10.100.10.0/24", "udp", PORT + 10),
        exchange("server-core", "ob-alpha", "10.100.20.0/24", "10.101.10.0/24", "tcp", PORT + 11),
        exchange("ob-beta", "server-core", "10.102.10.0/24", "10.100.10.0/24", "udp", PORT + 12),
        exchange("server-core", "ob-beta", "10.100.10.0/24", "10.102.11.0/24", "tcp", PORT + 13),
    ]
    emit(
        "I07_N02",
        "Authorized multi-VLAN pairs pass bidirectional UDP/TCP with source IP preserved.",
        flows,
    )

    # Strict OB <-> OB isolation & unauthorized Server VLAN denial
    denied = [
        exchange(
            "ob-alpha",
            "ob-beta",
            "10.101.10.0/24",
            "10.102.10.0/24",
            "udp",
            PORT + 20,
            expect_fail=True,
        ),
        exchange(
            "ob-beta",
            "ob-alpha",
            "10.102.10.0/24",
            "10.101.10.0/24",
            "tcp",
            PORT + 21,
            expect_fail=True,
        ),
        exchange(
            "ob-alpha",
            "server-core",
            "10.101.10.0/24",
            "10.100.99.0/24",
            "udp",
            PORT + 22,
            expect_fail=True,
        ),
        exchange(
            "ob-beta",
            "server-core",
            "10.102.10.0/24",
            "10.100.20.0/24",
            "udp",
            PORT + 23,
            expect_fail=True,
        ),
    ]
    emit("I07_N03", "OB-to-OB traffic and unauthorized Server VLANs are strictly dropped.", denied)

    # Multi-CHILD rekey on ob-beta (rekeys both child-0 and child-1)
    before_children = dict(snap.get(ob2_link.name).children)
    cli("rekey", "--site", "ob-beta", "--child", "--confirm")
    after_snap = wait_all_links_up(manifest)
    after_children = dict(after_snap.get(ob2_link.name).children)
    assert all(after_children[k].unique_id != before_children[k].unique_id for k in before_children)
    post_rekey = exchange(
        "ob-beta", "server-core", "10.102.11.0/24", "10.100.10.0/24", "udp", PORT + 25
    )
    emit(
        "I07_N04",
        "Targeted child rekey rotates all per_pair CHILD SAs and preserves traffic.",
        {"rotated_children": list(after_children.keys()), "flow": post_rekey},
    )

    # Explicit profile grant for ob-beta -> 10.100.20.0/24, verify pass, then rollback to deny
    saved = cli("backup", "--confirm")["backup_id"]
    expanded = load_profile(PROFILE)
    expanded["traffic_policy"]["allowed_site_pairs"][1]["b_cidrs"] = [
        "10.100.10.0/24",
        "10.100.20.0/24",
    ]
    exp_path = PROFILE.with_name("v3-expanded.yaml")
    write_profile_data(expanded, exp_path)
    exp_manifest = build_manifest(expanded)
    reload_peer_conns("ob-beta", exp_manifest, read_keys(expanded))
    reload_peer_conns("server-core", exp_manifest, read_keys(expanded))
    cli("apply", "-c", str(exp_path), "--maintenance", "--confirm")
    wait_all_links_up(exp_manifest)
    granted = exchange(
        "ob-beta", "server-core", "10.102.10.0/24", "10.100.20.0/24", "udp", PORT + 26
    )
    # Still no OB1 <-> OB2!
    still_isolated = exchange(
        "ob-alpha",
        "ob-beta",
        "10.101.10.0/24",
        "10.102.10.0/24",
        "udp",
        PORT + 27,
        expect_fail=True,
    )
    reload_peer_conns("ob-beta", manifest, read_keys(load_profile(PROFILE)))
    reload_peer_conns("server-core", manifest, read_keys(load_profile(PROFILE)))
    cli("rollback", "--to", saved, "--maintenance", "--confirm")
    wait_all_links_up(manifest)
    exp_path.unlink(missing_ok=True)
    emit(
        "I07_N05",
        "Explicit matrix expansion enables only the approved VLAN and rollback revokes it.",
        {"granted": granted, "ob_still_isolated": still_isolated},
    )


def verify_issue8_dual_isp_hot_standby(manifest):
    # Verify policy rule and table 101 symmetric return lookup
    rules = json.loads(cmd("ip", "-j", "-N", "-4", "rule", "show").stdout)
    assert any(r.get("priority") == 1001 and str(r.get("table")) == "101" for r in rules), rules
    lookup = json.loads(
        cmd("ip", "-j", "-4", "route", "get", "192.0.2.21", "from", "203.0.113.10").stdout
    )
    assert lookup[0]["dev"] == "wanisp2" and lookup[0]["gateway"] == "203.0.113.1", lookup

    links_srv = [item for item in manifest.links if item.site_id == "server-core"]
    isp1_link = next(item for item in links_srv if item.route_priority == 10)
    isp2_link = next(item for item in links_srv if item.route_priority == 20)
    fib_primary = json.loads(cmd("ip", "-j", "-4", "route", "get", "10.100.10.11").stdout)
    assert fib_primary[0]["dev"] == isp1_link.name

    # Single-ISP outage: ISP-1 XFRM down -> automatic FIB switch to ISP-2 (metric 20)
    ip("link", "set", "dev", isp1_link.name, "down")
    ip("link", "set", "dev", "tunnel1", "down", ns="peer-srv")
    try:
        fib_standby = json.loads(cmd("ip", "-j", "-4", "route", "get", "10.100.10.11").stdout)
        assert fib_standby[0]["dev"] == isp2_link.name, fib_standby
        failover_udp = exchange(
            "ob-alpha", "server-core", "10.101.10.0/24", "10.100.10.0/24", "udp", PORT + 40
        )
        failover_tcp = exchange(
            "server-core", "ob-alpha", "10.100.10.0/24", "10.101.10.0/24", "tcp", PORT + 41
        )

        # Both-ISP outage: bring ISP-2 XFRM down as well -> kernel blackhole blocks private leak
        ip("link", "set", "dev", isp2_link.name, "down")
        ip("link", "set", "dev", "tunnel2", "down", ns="peer-srv")
        try:
            bh = cmd("ip", "-4", "route", "get", "10.100.10.11", allowed=(2,))
            assert bh.returncode == 2
            blocked = exchange(
                "ob-alpha",
                "server-core",
                "10.101.10.0/24",
                "10.100.10.0/24",
                "udp",
                PORT + 42,
                expect_fail=True,
            )
        finally:
            ip("link", "set", "dev", isp2_link.name, "up")
            ip("link", "set", "dev", "tunnel2", "up", ns="peer-srv")
    finally:
        ip("link", "set", "dev", isp1_link.name, "up")
        ip("link", "set", "dev", "tunnel1", "up", ns="peer-srv")

    fib_restored = json.loads(cmd("ip", "-j", "-4", "route", "get", "10.100.10.11").stdout)
    assert fib_restored[0]["dev"] == isp1_link.name
    emit(
        "I08_D01",
        "Dual-ISP policy routing, hot-standby metric failover, and both-down blackhole verified.",
        {
            "primary_dev": isp1_link.name,
            "standby_dev": isp2_link.name,
            "standby_flows": [failover_udp, failover_tcp],
            "both_down_blackhole": blocked,
        },
    )


def verify_issue10_maintenance_rekey_races(manifest):
    saved = cli("backup", "--confirm")["backup_id"]
    tweaked = load_profile(PROFILE)
    tweaked["security"]["child_lifetime_seconds"] = 2700
    tweak_path = PROFILE.with_name("v3-i10.yaml")
    write_profile_data(tweaked, tweak_path)

    # Case 1: Inject real IKE rekey AFTER maintenance live snapshot and BEFORE drain_links
    pid = HOST.assert_daemon({item.name for item in manifest.links})
    target_link = next(item for item in manifest.links if item.site_id == "ob-alpha")

    class PostSnapshotRekeyHost(Host):
        def __init__(self):
            super().__init__()
            self.injected = False

        def command(self, label, *args, **kwargs):
            res = super().command(label, *args, **kwargs)
            if not self.injected and label == "nft atomic update" and kwargs.get("mutate"):
                # Triggered right inside replace_live -> resources.guard() BEFORE drain_links!
                self.injected = True
                snap = inventory(HOST, manifest, pid)
                old_ike = snap.get(target_link.name).unique_id
                with session(pid) as ctl:
                    ctl.request("rekey", {"ike-id": str(old_ike)})
                wait_until(
                    lambda: (
                        (s := inventory(HOST, manifest, pid)).get(target_link.name)
                        and s.get(target_link.name).unique_id != old_ike
                    ),
                    timeout=15,
                )
            return res

    dep = Deployment(PostSnapshotRekeyHost())
    out = dep.dispatch("apply", True, tweak_path, maintenance=True)
    assert out["status"] == "PASS"
    journal = read_record(JOURNAL)
    assert journal["phase"] == "COMMITTED" and journal.get("sa_reverified"), journal
    tweak_manifest = build_manifest(tweaked)
    wait_all_links_up(tweak_manifest)
    flow_after_race = exchange(
        "ob-alpha", "server-core", "10.101.10.0/24", "10.100.10.0/24", "udp", PORT + 50
    )
    emit(
        "I10_R01",
        "Concurrent SA rekey after maintenance snapshot is safely re-verified and committed.",
        {
            "journal": journal["id"],
            "sa_reverified": journal["sa_reverified"],
            "flow": flow_after_race,
        },
    )

    # Case 2: Mid-maintenance fault holds STOP_FOR_MANUAL until explicit rollback
    class FaultAfterDrainHost(Host):
        def __init__(self):
            super().__init__()
            self.tripped = False

        def command(self, label, *args, **kwargs):
            if not self.tripped and label == "VICI scoped load":
                self.tripped = True
                raise Stop("Injected scoped load fault for #10")
            return super().command(label, *args, **kwargs)

    fault_dep = Deployment(FaultAfterDrainHost())
    try:
        fault_dep.dispatch("rollback", True, identifier=saved, maintenance=True)
    except Stop:
        pass
    failed_journal = read_record(JOURNAL)
    assert failed_journal["phase"] == "STOP_FOR_MANUAL"
    assert not failed_journal.get("configuration_restored")

    # Recover via explicit maintenance rollback
    rec = cli("rollback", "--to", failed_journal["id"], "--maintenance", "--confirm")
    assert rec["configuration_restored"] is True and rec["data_path_restored"]["status"] == "SKIP"
    # Now switch back to original saved profile cleanly
    cli("rollback", "--to", saved, "--maintenance", "--confirm")
    wait_all_links_up(manifest)
    tweak_path.unlink(missing_ok=True)
    flow_restored = exchange(
        "ob-alpha", "server-core", "10.101.10.0/24", "10.100.10.0/24", "tcp", PORT + 52
    )
    emit(
        "I10_R02",
        "Mid-maintenance fault holds STOP_FOR_MANUAL until explicit rollback and traffic proof.",
        {"failed_journal": failed_journal["id"], "restored_flow": flow_restored},
    )


def verify_issue9_monitoring_and_feishu(manifest):
    # Configure loopback Feishu mock receiver + bridge secrets
    received_messages = []

    class MockFeishu(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(length))
            received_messages.append(body["content"]["text"])
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            out = b'{"code": 0}'
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

    mock_srv = HTTPServer(("127.0.0.1", MOCK_PORT), MockFeishu)
    mock_thread = Thread(target=mock_srv.serve_forever, daemon=True)
    mock_thread.start()

    signing = secrets.token_urlsafe(24).encode("ascii")
    bearer = secrets.token_urlsafe(32).encode("ascii")
    atomic_write(SECRETS / "monitor-signing", signing + b"\n", mode=0o600)
    atomic_write(SECRETS / "monitor-bearer", bearer + b"\n", mode=0o600)
    atomic_write(
        BRIDGE_CONF,
        json.dumps(
            {
                "enabled": True,
                "port": BRIDGE_PORT,
                "mock_endpoint": f"http://127.0.0.1:{MOCK_PORT}/mock",
            }
        ).encode("ascii"),
        mode=0o600,
    )

    try:
        cli("monitor", "serve", "--with-bridge", "--confirm")

        def _scrape():
            conn = HTTPConnection("127.0.0.1", METRICS_PORT, timeout=5)
            try:
                conn.request("GET", "/metrics")
                resp = conn.getresponse()
                return resp.read().decode("ascii") if resp.status == 200 else ""
            finally:
                conn.close()

        prom = wait_until(
            lambda: (t := _scrape()) and "event_ipsec_collector_healthy 1" in t and t, timeout=30
        )
        cmd("promtool", "check", "metrics", input_text=prom)
        assert (
            'site_id="server-core"' in prom
            and 'site_id="ob-alpha"' in prom
            and 'site_id="ob-beta"' in prom
        )
        assert 'link_id="srv-isp1"' in prom and 'link_id="srv-isp2"' in prom

        # Run real authenticated UDP active_probe across all 4 authorized directions
        probe_key = os.urandom(32)
        responders = []
        probe_Port = 41500
        # Start lightweight UDP echo threads in namespaces via python subprocesses
        resp_script = (
            "import socket,sys,time; from ipsecvpn.monitoring.udp import Responder; "
            "s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(15); "
            "s.bind((sys.argv[3], int(sys.argv[4]))); print('RDY', flush=True);\n"
            "for _ in range(2):\n"
            "  data, addr = s.recvfrom(512)\n"
            "  ans = Responder(bytes.fromhex(sys.argv[1]), addr).answer(addr, data, time.time())\n"
            "  if ans: s.sendto(ans, addr)\n"
        )
        directions_cfg = [
            ("ob-alpha", "server-core", "10.101.10.11", "10.100.10.11", probe_Port + 1),
            ("server-core", "ob-alpha", "10.100.10.11", "10.101.10.11", probe_Port + 2),
            ("ob-beta", "server-core", "10.102.10.11", "10.100.10.11", probe_Port + 3),
            ("server-core", "ob-beta", "10.100.10.11", "10.102.10.11", probe_Port + 4),
        ]
        # Run active_probe from Hub using namespace-bound probe_fn executing real UDP over IPsec!
        for _, dst_site, src_ip, dst_ip, pport in directions_cfg:
            proc = subprocess.Popen(
                in_ns(
                    SITES[dst_site]["host"],
                    sys.executable,
                    "-c",
                    resp_script,
                    probe_key.hex(),
                    src_ip,
                    dst_ip,
                    str(pport),
                ),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            assert proc.stdout.readline().strip() == "RDY"
            responders.append(proc)

        def _ns_udp_probe(target, port, secret, *, source, count, timeout):
            client_code = (
                "import json,sys; from ipsecvpn.monitoring.udp import probe; "
                "print(json.dumps(probe(sys.argv[1], int(sys.argv[2]), bytes.fromhex(sys.argv[3]), "
                "source=sys.argv[4], count=int(sys.argv[5]), timeout=float(sys.argv[6]))))"
            )
            src_site = next(
                sid
                for sid, d in SITES.items()
                if any(source.startswith(c.rsplit(".", 1)[0]) for c in d["lans"])
            )
            out = cmd(
                *in_ns(
                    SITES[src_site]["host"],
                    sys.executable,
                    "-c",
                    client_code,
                    target,
                    str(port),
                    secret.hex(),
                    source,
                    str(count),
                    str(timeout),
                )
            )
            return json.loads(out.stdout)

        install = read_record(INSTALLED)
        pid = HOST.assert_daemon({item.name for item in manifest.links})
        live_snap = inventory(HOST, manifest, pid)
        active_probe.run_probe_cycle(
            install=install,
            manifest=manifest,
            live=live_snap,
            probe_specs=[
                {
                    "src_site_id": s_id,
                    "dst_site_id": d_id,
                    "source": s_ip,
                    "target": d_ip,
                    "port": pport,
                    "count": 2,
                }
                for s_id, d_id, s_ip, d_ip, pport in directions_cfg
            ],
            secret=probe_key,
            probe_fn=_ns_udp_probe,
        )
        for proc in responders:
            proc.wait(timeout=5)

        verified_obs = collect()
        assert verified_obs["business"] == State.UP, verified_obs

        # Post V3 Alertmanager alerts (self_hosted & cloud_managed sources) to bridge
        payload = {
            "alerts": [
                {
                    "status": "firing",
                    "fingerprint": "1111222233334444",
                    "startsAt": datetime.now(UTC).isoformat(),
                    "labels": {
                        "alertname": "IpsecFailoverManualRequired",
                        "severity": "warning",
                        "event_id": "v3-esports-lab",
                        "hub_id": "hub-v3",
                        "source": "self_hosted",
                    },
                }
            ]
        }
        conn = HTTPConnection("127.0.0.1", BRIDGE_PORT, timeout=5)
        conn.request(
            "POST",
            "/alertmanager",
            json.dumps(payload).encode(),
            {"Authorization": f"Bearer {bearer.decode()}", "Content-Type": "application/json"},
        )
        assert conn.getresponse().status == 200
        conn.close()
        assert any(
            "IpsecFailoverManualRequired" in msg and "self_hosted" in msg
            for msg in received_messages
        )

        emit(
            "I09_M01",
            "3-site Dual-ISP metrics, real encrypted UDP active_probe, and Feishu bridge verified.",
            {"sites": 3, "links": 4, "business": "UP", "feishu_messages": len(received_messages)},
        )

        # Keep bridge running momentarily for Issue #13 failover alert test, then stop in cleanup
        verify_issue13_coordinated_failover(manifest, received_messages)
    finally:
        cli("monitor", "stop", "--confirm")
        mock_srv.shutdown()
        BRIDGE_CONF.unlink(missing_ok=True)
        (SECRETS / "monitor-signing").unlink(missing_ok=True)
        (SECRETS / "monitor-bearer").unlink(missing_ok=True)


def _raw_vici_map(pid):
    out = {}
    with session(pid) as vici_ctl:
        for event in vici_ctl.list_sas():
            for conn_name, row in event.items():
                out[conn_name] = row
    return out


def verify_issue11_unattended_reconnect(manifest):
    pid = HOST.assert_daemon({item.name for item in manifest.links})
    before = inventory(HOST, manifest, pid)
    ob1_link = next(item for item in manifest.links if item.site_id == "ob-alpha")
    ob2_link = next(item for item in manifest.links if item.site_id == "ob-beta")
    ob1_ike_before = before.get(ob1_link.name).unique_id
    ob2_ike_before = before.get(ob2_link.name).unique_id

    # 1. Drop ob-alpha WAN -> DPD restarts ONLY ob-alpha -> restore WAN -> unattended reconnect!
    ip("link", "set", "wan", "down", ns="peer-ob1")
    try:

        def _dpd_triggered():
            raw = _raw_vici_map(pid)
            assert int(raw[ob2_link.name]["uniqueid"]) == ob2_ike_before
            ob1_row = raw.get(ob1_link.name)
            return (
                ob1_row is None
                or ob1_row.get("state") != b"ESTABLISHED"
                or int(ob1_row["uniqueid"]) != ob1_ike_before
            )

        wait_until(_dpd_triggered, timeout=35, interval=0.5)
    finally:
        ip("link", "set", "wan", "up", ns="peer-ob1")

    # Wait for strongSwan dpd_action=restart to auto-restore ob-alpha WITHOUT manual initiate!
    restored = wait_all_links_up(manifest, timeout=45)
    assert restored.get(ob1_link.name).unique_id != ob1_ike_before
    assert restored.get(ob2_link.name).unique_id == ob2_ike_before
    flow_auto = exchange(
        "ob-alpha", "server-core", "10.101.10.0/24", "10.100.10.0/24", "udp", PORT + 70
    )
    emit(
        "I11_R01",
        "DPD outage auto-reconnects target site unattended without disturbing sibling SAs.",
        {"ob_beta_ike_preserved": ob2_ike_before, "flow": flow_auto},
    )

    # 2. Switch ob-alpha to explicit reconnect mode to test bounded CLI exhaustion & isolation
    saved = cli("backup", "--confirm")["backup_id"]
    manual_prof = load_profile(PROFILE)
    for sl in manual_prof["site_links"]:
        if sl.get("site_id") == "ob-alpha":
            sl["start_action"] = "none"
            sl["dpd_action"] = "clear"
            sl["close_action"] = "none"
    man_path = PROFILE.with_name("v3-man-reconn.yaml")
    write_profile_data(manual_prof, man_path)
    cli("apply", "-c", str(man_path), "--maintenance", "--confirm")
    man_manifest = build_manifest(manual_prof)
    pid = HOST.assert_daemon({item.name for item in man_manifest.links})
    wait_all_links_up(man_manifest, timeout=45)
    snap_man = inventory(HOST, man_manifest, pid)
    ob2_ike_mid = snap_man.get(ob2_link.name).unique_id

    with session(pid) as hub_ctl:
        hub_ctl.request(
            "terminate",
            {
                "ike-id": str(snap_man.get(ob1_link.name).unique_id),
                "force": "yes",
                "timeout": "2500",
            },
        )
    wait_until(lambda: ob1_link.name not in _raw_vici_map(pid), timeout=15)

    cmd(
        *in_ns("peer-ob1", "nft", "-f", "-"),
        input_text=(
            "table ip v3_block {\n"
            "  chain input { type filter hook input priority -10; policy accept;\n"
            "    udp dport { 500, 4500 } drop\n"
            "  }\n}\n"
        ),
    )
    try:
        exhausted = cli("reconnect", "--site", "ob-alpha", "--confirm", expect=1)
        assert exhausted["links"][0]["action"] == "RECONNECT_EXHAUSTED"
        assert inventory(HOST, man_manifest, pid).get(ob2_link.name).unique_id == ob2_ike_mid
    finally:
        cmd(*in_ns("peer-ob1", "nft", "delete", "table", "ip", "v3_block"))

    reconn_ok = cli("reconnect", "--site", "ob-alpha", "--confirm")
    assert reconn_ok["status"] == "PASS"
    wait_all_links_up(man_manifest, timeout=30)

    # Restore unattended start_action=start profile
    cli("rollback", "--to", saved, "--maintenance", "--confirm")
    man_path.unlink(missing_ok=True)
    wait_all_links_up(manifest, timeout=45)

    # 3. Daemon restart with start_action=start auto-establishes all 3 sites unattended
    cmd("systemctl", "restart", UNIT, timeout=60)
    wait_all_links_up(manifest, timeout=45)
    flow_restart = exchange(
        "ob-beta", "server-core", "10.102.10.0/24", "10.100.10.0/24", "tcp", PORT + 72
    )
    emit(
        "I11_R02",
        "Bounded reconnect exhaustion, sibling isolation, and daemon-restart recovery verified.",
        {"exhausted_reason": exhausted["links"][0]["reason_code"], "restart_flow": flow_restart},
    )


def verify_issue13_coordinated_failover(manifest, feishu_inbox):
    state_file = Path("/var/tmp/v3-failover-state.json")
    state_file.unlink(missing_ok=True)
    msg_before = len(feishu_inbox)

    # Asymmetric FIB detection via observe()
    asym = observe("primary", "backup", PathProof("backup", True, True, True, True))
    assert asym["state"] == "ASYMMETRIC_STOP" and asym["status"] == "STOP"

    # Debounce: 2 failures keep primary
    for _ in range(2):
        r = cli(
            "failover",
            "evaluate",
            "--primary-unhealthy",
            "--backup-healthy",
            "--state-file",
            str(state_file),
        )
        assert r["action"] == "DEGRADED_OBSERVING"

    # 3rd failure triggers automatic switch to backup + Hub XFRM gate LOCKED_DOWN + Feishu delivery!
    switched = cli(
        "failover",
        "evaluate",
        "--primary-unhealthy",
        "--backup-healthy",
        "--apply-gate",
        "--send-feishu",
        "--state-file",
        str(state_file),
    )
    assert switched["action"] == "SWITCH_TO_BACKUP"
    assert switched["hub_gate"]["gate"] == "LOCKED_DOWN"
    assert len(feishu_inbox) > msg_before

    # Site routers converge onto v3-backup-hub (metric 60) while Hub XFRM gate is LOCKED_DOWN
    ip("link", "set", "dev", "tunnel", "down", ns="peer-ob1")
    ip("link", "set", "dev", "tunnel1", "down", ns="peer-srv")
    ip("link", "set", "dev", "tunnel2", "down", ns="peer-srv")
    try:
        bkp_udp = exchange(
            "ob-alpha", "server-core", "10.101.10.0/24", "10.100.10.0/24", "udp", PORT + 80
        )
        bkp_tcp = exchange(
            "server-core", "ob-alpha", "10.100.10.0/24", "10.101.10.0/24", "tcp", PORT + 81
        )

        # Premature manual failback without --force is rejected with exit code 1 (STOP)
        rej = cli(
            "failover",
            "failback",
            "--operator",
            "v3-ops",
            "--confirm",
            "--state-file",
            str(state_file),
            expect=1,
        )
        assert rej["action"] == "REJECT_HOLD_NOT_MET"

        # Explicit operator failback unlocks Hub XFRM gate UP
        ok = cli(
            "failover",
            "failback",
            "--operator",
            "v3-ops",
            "--force",
            "--apply-gate",
            "--send-feishu",
            "--confirm",
            "--state-file",
            str(state_file),
        )
        assert ok["action"] == "SWITCH_TO_PRIMARY" and ok["hub_gate"]["gate"] == "UNLOCKED_UP"
    finally:
        ip("link", "set", "dev", "tunnel", "up", ns="peer-ob1")
        ip("link", "set", "dev", "tunnel1", "up", ns="peer-srv")
        ip("link", "set", "dev", "tunnel2", "up", ns="peer-srv")
        state_file.unlink(missing_ok=True)

    pri_flow = exchange(
        "ob-alpha", "server-core", "10.101.10.0/24", "10.100.10.0/24", "udp", PORT + 82
    )
    emit(
        "I13_F01",
        "Debounced failover, XFRM gate lock, backup UDP/TCP, and manual failback verified.",
        {
            "asymmetric": asym["state"],
            "backup_flows": [bkp_udp, bkp_tcp],
            "primary_restored": pri_flow,
        },
    )


def before_reboot():
    assert cli("install", "--confirm")["status"] == "PASS"
    profile = create_v3_profile()
    install_topology_unit()
    manifest = build_manifest(profile)
    BASELINE_FILE.write_text(json.dumps(baseline_for(manifest)), encoding="utf-8")

    assert cli("apply", "-c", str(PROFILE), "--confirm")["status"] == "PASS"
    cmd("systemctl", "start", "ipsecvpn-restore.service")

    verify_issue7_nsite_isolation_and_multichild(manifest)
    verify_issue8_dual_isp_hot_standby(manifest)
    verify_issue10_maintenance_rekey_races(manifest)
    verify_issue9_monitoring_and_feishu(manifest)
    verify_issue11_unattended_reconnect(manifest)

    assert baseline_for(manifest) == json.loads(BASELINE_FILE.read_text(encoding="utf-8"))


def after_reboot():
    profile = load_profile(PROFILE)
    manifest = build_manifest(profile)
    for unit_name in ("ipsecvpn-guard.service", "ipsecvpn-restore.service", UNIT):
        wait_until(lambda u=unit_name: HOST.service(u, "ActiveState") == "active", timeout=60)

    # start_action=start brings all 4 links + 5 CHILD SAs back up automatically across VM reboot!
    wait_all_links_up(manifest, timeout=60)
    assert cli("status")["status"] == "PASS"

    flows = [
        exchange("ob-alpha", "server-core", "10.101.10.0/24", "10.100.10.0/24", "udp", PORT + 90),
        exchange("ob-beta", "server-core", "10.102.10.0/24", "10.100.10.0/24", "tcp", PORT + 91),
        exchange(
            "ob-alpha",
            "ob-beta",
            "10.101.10.0/24",
            "10.102.10.0/24",
            "udp",
            PORT + 92,
            expect_fail=True,
        ),
    ]
    baseline = json.loads(BASELINE_FILE.read_text(encoding="utf-8"))
    assert baseline_for(manifest) == baseline
    emit(
        "I07_I08_I11_BOOT",
        "Full VM reboot restores Dual-ISP policy rules, 3-site SAs, forwarding and OB isolation.",
        {"flows": flows},
    )

    # Clean uninstall removes all XFRM, policy rules, table 101 routes and restores exact baseline
    cli("uninstall", "--maintenance", "--confirm")
    assert not HOST.command("Empty SAD", "ip", "xfrm", "state", "list", "nokeys").strip()
    assert not HOST.command("Empty SPD", "ip", "xfrm", "policy", "list", "nosock").strip()
    assert Resources(HOST, "uninstalled", ()).baseline() == baseline
    emit(
        "V3_UNINSTALL",
        "Uninstall leaves zero XFRM/policy-routing residue and preserves host baseline.",
        "PASS",
    )


if __name__ == "__main__":
    action = sys.argv[1]
    if action == "topology":
        bootstrap_topology()
    elif action == "before-reboot":
        before_reboot()
    elif action == "after-reboot":
        after_reboot()
    else:
        raise ValueError(f"Unknown action: {action}")
