"""Black-box Ubuntu 24.04 QEMU kernel acceptance for V4 single-binary Go gateway.

Uses Python 3 stdlib only (zero imports from the Python ipsecvpn package) to prove
that the compiled Go binary (/usr/local/sbin/ipsecvpn) and scripts/install-v4.sh
operate completely standalone on Ubuntu 24.04.
"""

import hashlib
import http.cookiejar
import json
import os
import re
import secrets
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime
from ipaddress import IPv4Network
from pathlib import Path

HERE = Path(__file__).resolve().parent
BIN = Path("/usr/local/sbin/ipsecvpn")
SUMMARY = Path("/var/tmp/ipsecvpn-v4-acceptance.jsonl")
PROFILE = Path("/etc/ipsecvpn/profiles/v4-lab.yaml")
SECRETS = Path("/etc/ipsecvpn/secrets")
PEER_ROOT = Path("/run/ipsecvpn-v4")
TOPOLOGY_UNIT = "ipsecvpn-v4-topology.service"
PORT = 32491

HEAD = (
    Path("/opt/ipsecvpn-lab/head-sha").read_text(encoding="ascii").strip()
    if Path("/opt/ipsecvpn-lab/head-sha").is_file()
    else "0" * 40
)
PAYLOAD_SHA = (
    hashlib.sha256(Path("/opt/ipsecvpn-lab/payload.sha256").read_bytes()).hexdigest()
    if Path("/opt/ipsecvpn-lab/payload.sha256").is_file()
    else ""
)

SITES = {
    "server-core": {
        "router": "peer-srv",
        "host": "lan-srv",
        "wan_ip": "198.51.100.21",
        "if_id": 201,
        "selector_mode": "exact",
        "lans": ["10.100.10.0/24", "10.100.20.0/24"],
        "extra_lan": "10.100.99.0/24",
        "hub_local_ts": ["10.101.10.0/24", "10.102.10.0/24", "10.102.11.0/24"],
        "hub_remote_ts": ["10.100.10.0/24", "10.100.20.0/24"],
    },
    "ob-alpha": {
        "router": "peer-ob1",
        "host": "lan-ob1",
        "wan_ip": "198.51.100.22",
        "if_id": 202,
        "selector_mode": "route_based",
        "lans": ["10.101.10.0/24"],
        "hub_local_ts": ["10.100.10.0/24", "10.100.20.0/24"],
        "hub_remote_ts": ["10.101.10.0/24"],
    },
    "ob-beta": {
        "router": "peer-ob2",
        "host": "lan-ob2",
        "wan_ip": "198.51.100.23",
        "if_id": 203,
        "selector_mode": "per_pair",
        "lans": ["10.102.10.0/24", "10.102.11.0/24"],
        "hub_local_ts": ["10.100.10.0/24"],
        "hub_remote_ts": ["10.102.10.0/24", "10.102.11.0/24"],
    },
}

LAB_PROFILE_YAML = """schema_version: "2.0"
event:
  id: v4-go-esports-lab
  name: V4 Go Single-Binary Multi-Site Lab
  purpose: Black-box Ubuntu 24.04 QEMU verification for Go V4 gateway

hub:
  id: hub-v4
  platform: ubuntu-24.04
  public_endpoint: 198.51.100.10
  ike_identity: "@hub-v4.example"
  provider_label: Lab-VPS
  location_label: Lab-Region
  country: LAB

sites:
  - id: server-core
    display_name: Central Match Server
    role: server
    country: LAB
    public_endpoint: 198.51.100.21
    ike_identity: 198.51.100.21
    lan_cidrs:
      - 10.100.10.0/24
      - 10.100.20.0/24
      - 10.100.99.0/24
    firewall:
      vendor: Hillstone
      os_version: StoneOS 5.5R10

  - id: ob-alpha
    display_name: OB Venue Alpha
    role: ob
    country: LAB
    public_endpoint: 198.51.100.22
    ike_identity: 198.51.100.22
    lan_cidrs:
      - 10.101.10.0/24
    firewall:
      vendor: Hillstone
      os_version: StoneOS 5.5R10

  - id: ob-beta
    display_name: OB Venue Beta
    role: ob
    country: LAB
    public_endpoint: 198.51.100.23
    ike_identity: 198.51.100.23
    lan_cidrs:
      - 10.102.10.0/24
      - 10.102.11.0/24
    firewall:
      vendor: Hillstone
      os_version: StoneOS 5.5R10

security:
  dpd_delay_seconds: 2
  start_action: start
  dpd_action: restart
  close_action: start

site_links:
  - site_id: server-core
    secret_ref: file:/etc/ipsecvpn/secrets/server-core.psk
    if_id: 201
    selector_mode: exact
    route_priority: 10
    outer_path:
      interface: wanisp1
      isp_label: ISP-A

  - site_id: ob-alpha
    secret_ref: file:/etc/ipsecvpn/secrets/ob-alpha.psk
    if_id: 202
    selector_mode: route_based
    route_priority: 10
    outer_path:
      interface: wanisp1
      isp_label: ISP-A

  - site_id: ob-beta
    secret_ref: file:/etc/ipsecvpn/secrets/ob-beta.psk
    if_id: 203
    selector_mode: per_pair
    route_priority: 10
    outer_path:
      interface: wanisp1
      isp_label: ISP-A

traffic_policy:
  allowed_site_pairs:
    - a: ob-alpha
      b: server-core
      a_cidrs:
        - 10.101.10.0/24
      b_cidrs:
        - 10.100.10.0/24
        - 10.100.20.0/24
    - a: ob-beta
      b: server-core
      a_cidrs:
        - 10.102.10.0/24
        - 10.102.11.0/24
      b_cidrs:
        - 10.100.10.0/24

backup:
  enabled: false
"""


def cmd(*args, allowed=(0,), timeout=90, input_text=None):
    proc = subprocess.run(
        args, capture_output=True, text=True, check=False, input=input_text, timeout=timeout
    )
    if proc.returncode not in allowed:
        raise RuntimeError(
            f"{Path(args[0]).name}({args[1:5]}) exited {proc.returncode}: "
            f"stdout={proc.stdout[:300]} stderr={proc.stderr[:300]}"
        )
    return proc


def ip(*args, ns=None, allowed=(0,)):
    prefix = ("-n", ns) if ns else ()
    return cmd("ip", *prefix, *args, allowed=allowed)


def in_ns(name, *args):
    return ("ip", "netns", "exec", name, *args)


def cli(*args, expect=0, parse_json=True):
    full = [str(BIN), *args]
    if parse_json and "--json" not in args:
        full.append("--json")
    proc = cmd(*full, allowed=(0, 1))
    if expect is not None and proc.returncode != expect:
        raise RuntimeError(
            f"ipsecvpn {args} exited {proc.returncode}: stdout={proc.stdout[:500]} stderr={proc.stderr[:500]}"
        )
    if not parse_json:
        return proc.stdout
    return json.loads(proc.stdout)


def addr(cidr, host_num):
    return str(IPv4Network(cidr)[host_num])


def env_info():
    kernel = cmd("uname", "-r").stdout.strip()
    virt = cmd("systemd-detect-virt", "--vm", allowed=(0, 1)).stdout.strip()
    ver = cmd(str(BIN), "version").stdout.strip()
    ss = cmd("dpkg-query", "-W", "-f=${Version}", "charon-systemd", allowed=(0, 1)).stdout.strip()
    return {
        "os": "Ubuntu 24.04",
        "kernel": kernel,
        "hypervisor": virt,
        "binary": ver,
        "strongswan": ss or "not-installed",
    }


def emit(case_id, expected, observed, status="PASS"):
    row = {
        "case": case_id,
        "time_utc": datetime.now(UTC).isoformat(),
        "head_sha": HEAD,
        "payload_sha256": PAYLOAD_SHA,
        "environment": env_info(),
        "action": expected,
        "expected": expected,
        "observed": observed,
        "status": status,
        "proof_refs": [SUMMARY.name],
    }
    line = json.dumps(row, sort_keys=True)
    if SECRETS.is_dir():
        for secret_path in SECRETS.iterdir():
            if secret_path.is_file():
                val = secret_path.read_bytes().strip()
                if val and (val in line.encode() or val.hex() in line):
                    raise RuntimeError("Refusing to write secret material into evidence.")
    with SUMMARY.open("a", encoding="utf-8") as handle:
        print(line, file=handle)
    print(line, flush=True)


def wait_until(predicate, timeout=60, interval=0.8):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        val = predicate()
        if val:
            return val
        time.sleep(interval)
    raise AssertionError(f"Timed out waiting for expected V4 lab condition (last={last}).")


def ensure_profile_and_secrets():
    SECRETS.mkdir(mode=0o700, parents=True, exist_ok=True)
    for site_id in SITES:
        psk = SECRETS / f"{site_id}.psk"
        if not psk.exists():
            psk.write_bytes(os.urandom(32).hex().encode("ascii") + b"\n")
            psk.chmod(0o600)
    PROFILE.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    PROFILE.write_text(LAB_PROFILE_YAML, encoding="utf-8")
    PROFILE.chmod(0o600)


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
        "v4-peer",
        str(PEER_ROOT / ns_name),
        *args,
    )


def render_peer_swanctl(site_id, meta, psk_bytes):
    if_id = meta["if_id"]
    name = f"ivp{if_id:08x}"
    mode = meta["selector_mode"]
    # Reversed selectors from peer perspective (peer local_ts == hub remote_ts)
    peer_local = meta["hub_remote_ts"]
    peer_remote = meta["hub_local_ts"]
    children = []
    if mode == "route_based":
        children.append((f"{name}-child", ["0.0.0.0/0"], ["0.0.0.0/0"]))
    elif mode == "per_pair":
        idx = 0
        for r in meta["hub_local_ts"]:
            for l in meta["hub_remote_ts"]:
                children.append((f"{name}-child-{idx}", [l], [r]))
                idx += 1
    else:
        children.append((f"{name}-child", peer_local, peer_remote))

    child_blocks = []
    for cname, lts, rts in children:
        child_blocks.append(
            f"""            {cname} {{
                mode = tunnel
                local_ts = {", ".join(lts)}
                remote_ts = {", ".join(rts)}
                esp_proposals = aes256-sha256-modp2048
                if_id_in = {if_id}
                if_id_out = {if_id}
                life_time = 14400s
                rekey_time = 12960s
                start_action = none
                dpd_action = clear
                close_action = none
            }}"""
        )

    return f"""connections {{
    {name} {{
        version = 2
        local_addrs = {meta["wan_ip"]}
        remote_addrs = 198.51.100.10
        proposals = aes256-sha256-prfsha256-modp2048
        reauth_time = 0
        rekey_time = 86400s
        dpd_delay = 2s
        mobike = no
        encap = yes
        local {{
            auth = psk
            id = {meta["wan_ip"]}
        }}
        remote {{
            auth = psk
            id = @hub-v4.example
        }}
        children {{
{chr(10).join(child_blocks)}
        }}
    }}
}}
secrets {{
    ike-{name} {{
        id-1 = {meta["wan_ip"]}
        id-2 = @hub-v4.example
        secret = 0x{psk_bytes.hex()}
    }}
}}
"""


def start_peer_daemon(site_id, meta):
    ns_name = meta["router"]
    root = PEER_ROOT / ns_name
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    conf = Path(f"/etc/strongswan.d/v4-{ns_name}.conf")
    conf.write_text(
        """charon-systemd {
    load_modular = yes
    install_routes = no
    routing_table = 0
    install_virtual_ip = no
    retransmit_timeout = 1
    retransmit_tries = 2
    plugins {
        include /etc/strongswan.d/charon/*.conf
        kernel-netlink {
            install_routes_xfrmi = no
        }
        socket-default {
            use_ipv6 = no
        }
        vici {
            socket = unix:///run/charon.vici
        }
    }
}
""",
        encoding="ascii",
    )
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
        raise RuntimeError(f"Peer charon.vici did not start for {ns_name}")

    psk_bytes = (SECRETS / f"{site_id}.psk").read_bytes().strip()
    folder = Path(f"/etc/swanctl/v4-{ns_name}")
    folder.mkdir(mode=0o700, exist_ok=True)
    cpath = folder / "swanctl.conf"
    cpath.write_text(render_peer_swanctl(site_id, meta, psk_bytes), encoding="ascii")
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
    if cmd("hostname").stdout.strip() != "ipsecvpn-v4-lab":
        raise RuntimeError("Expected ipsecvpn-v4-lab disposable VM.")

    ip("netns", "add", "wan-isp1")
    ip("link", "set", "lo", "up", ns="wan-isp1")
    ip("link", "add", "br0", "type", "bridge", ns="wan-isp1")
    ip("link", "set", "br0", "up", ns="wan-isp1")

    ip("link", "add", "wanisp1", "type", "veth", "peer", "name", "hub1", "netns", "wan-isp1")
    ip("link", "set", "hub1", "master", "br0", ns="wan-isp1")
    ip("link", "set", "hub1", "up", ns="wan-isp1")
    ip("link", "set", "wanisp1", "address", "02:00:00:41:00:10")
    ip("addr", "add", "198.51.100.10/24", "dev", "wanisp1")
    ip("link", "set", "wanisp1", "up")

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
        ip("link", "add", f"p1_{idx}", "type", "veth", "peer", "name", "wan", "netns", rtr, ns="wan-isp1")
        ip("link", "set", f"p1_{idx}", "master", "br0", ns="wan-isp1")
        ip("link", "set", f"p1_{idx}", "up", ns="wan-isp1")
        ip("addr", "add", f"{meta['wan_ip']}/24", "dev", "wan", ns=rtr)
        ip("link", "set", "wan", "up", ns=rtr)

        ip("link", "add", "inside", "type", "veth", "peer", "name", "eth0", "netns", hst, ns=rtr)
        ip("link", "set", "inside", "up", ns=rtr)
        ip("link", "set", "eth0", "up", ns=hst)
        all_nets = list(meta["lans"]) + ([meta["extra_lan"]] if "extra_lan" in meta else [])
        for net in all_nets:
            plen = IPv4Network(net).prefixlen
            ip("addr", "add", f"{addr(net, 1)}/{plen}", "dev", "inside", ns=rtr)
            ip("addr", "add", f"{addr(net, 11)}/{plen}", "dev", "eth0", ns=hst)
        ip("route", "add", "default", "via", addr(all_nets[0], 1), ns=hst)

        ip("link", "add", "tunnel", "type", "xfrm", "if_id", str(meta["if_id"]), ns=rtr)
        ip("link", "set", "tunnel", "up", ns=rtr)
        for other_id, other_meta in SITES.items():
            if other_id == site_id:
                continue
            other_nets = list(other_meta["lans"]) + (
                [other_meta["extra_lan"]] if "extra_lan" in other_meta else []
            )
            for r_cidr in other_nets:
                ip("route", "replace", r_cidr, "dev", "tunnel", "metric", "10", ns=rtr)
                ip("route", "replace", "blackhole", r_cidr, "metric", "32000", ns=rtr)

        start_peer_daemon(site_id, meta)


def install_topology_unit():
    unit = Path("/etc/systemd/system") / TOPOLOGY_UNIT
    unit.write_text(
        f"""[Unit]
Description=V4 disposable multi-site peer network
After=local-fs.target systemd-sysctl.service ipsecvpn-guard.service
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


def exchange(src_site, dst_site, src_cidr, dst_cidr, proto="udp", sport=PORT + 1, expect_fail=False):
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
        assert all(row["source"][0] == src_ip for row in srv_rows), srv_rows
        return {"passed": True, "src": src_ip, "dst": dst_ip, "protocol": proto, "packets": len(srv_rows)}
    finally:
        if server.poll() is None:
            server.kill()
            server.wait()


class WebClient:
    def __init__(self, base="https://127.0.0.1:18443"):
        self.base = base
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ctx),
            urllib.request.HTTPCookieProcessor(self.jar),
        )

    def request(self, method, path, body=None):
        data = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {"Content-Type": "application/json"} if data is not None else {}
        req = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        try:
            with self.opener.open(req, timeout=15) as resp:
                raw = resp.read().decode("utf-8")
                return resp.status, raw
        except urllib.error.HTTPError as err:
            return err.code, err.read().decode("utf-8", errors="replace")


def extract_bootstrap_password():
    def _find():
        logs = cmd("journalctl", "-u", "ipsecvpn-web.service", "--no-pager", "-n", "100").stdout
        m = re.search(r"initial_password=([^\s]+)", logs)
        return m.group(1) if m else None

    return wait_until(_find, timeout=30, interval=1.0)


def wait_status_pass(timeout=60):
    def _ok():
        proc = cmd(str(BIN), "status", "--json", allowed=(0, 1))
        if proc.returncode == 0:
            data = json.loads(proc.stdout)
            if data.get("status") == "PASS":
                return data
        return None

    return wait_until(_ok, timeout=timeout, interval=1.0)


def before_reboot():
    # 1. Offline CLI verification (zero Python ipsecvpn dependency)
    example = str(HERE / "multi-ob.example.yaml")
    ver = cmd(str(BIN), "version").stdout.strip()
    val = cli("validate", "-c", example)
    assert val["status"] == "PASS"
    plan = cli("plan", "-c", example, parse_json=True)
    assert plan["status"] == "PASS"
    rend = cli("render", "-c", example, parse_json=True)
    assert rend["status"] == "PASS"
    tc = json.loads(cmd(str(BIN), "export-peer", "-c", example, "--site", "ob-venue-1", "--format", "tencent-json").stdout)
    assert tc["IKEOptionsSpecification"]["IKEVersion"] == "IKEV2"
    assert tc["PreShareKey"] == "<SEND_SEPARATELY>"
    draft = cmd(str(BIN), "export-peer", "-c", example, "--site", "ob-venue-1", "--format", "hillstone-draft").stdout
    assert "tunnel" in draft.lower()
    emit(
        "V4_CLI_01",
        "Go single binary executes offline validate/plan/render/export-peer standalone.",
        {"version": ver, "ike_version": tc["IKEOptionsSpecification"]["IKEVersion"]},
    )

    # 2. Real strongSwan installation via Go binary
    dry = cli("install", "--dry-run")
    assert dry["status"] == "PASS"
    inst = cli("install", "--confirm")
    assert inst["status"] == "PASS"
    guard_unit = Path("/etc/systemd/system/ipsecvpn-guard.service").read_text(encoding="utf-8")
    restore_unit = Path("/etc/systemd/system/ipsecvpn-restore.service").read_text(encoding="utf-8")
    assert "/usr/local/sbin/ipsecvpn boot guard" in guard_unit
    assert "/usr/local/sbin/ipsecvpn boot restore" in restore_unit
    emit(
        "V4_INST_01",
        "Go binary installs strongSwan charon-systemd and Go boot guard/restore systemd units.",
        {"strongswan_active": cmd("systemctl", "is-active", "strongswan.service").stdout.strip()},
    )

    # 3. Multi-site topology + Go apply + real ESP traffic + OB isolation
    ensure_profile_and_secrets()
    install_topology_unit()
    dry_apply = cli("apply", "-c", str(PROFILE), "--dry-run")
    assert dry_apply["status"] == "PASS"
    applied = cli("apply", "-c", str(PROFILE), "--confirm")
    assert applied["status"] == "PASS"
    status = wait_status_pass(timeout=60)

    flows = [
        exchange("ob-alpha", "server-core", "10.101.10.0/24", "10.100.10.0/24", "udp", PORT + 10),
        exchange("server-core", "ob-alpha", "10.100.20.0/24", "10.101.10.0/24", "tcp", PORT + 11),
        exchange("ob-beta", "server-core", "10.102.10.0/24", "10.100.10.0/24", "udp", PORT + 12),
        exchange("server-core", "ob-beta", "10.100.10.0/24", "10.102.11.0/24", "tcp", PORT + 13),
    ]
    denied = [
        exchange("ob-alpha", "ob-beta", "10.101.10.0/24", "10.102.10.0/24", "udp", PORT + 20, expect_fail=True),
        exchange("ob-beta", "server-core", "10.102.10.0/24", "10.100.99.0/24", "udp", PORT + 21, expect_fail=True),
    ]
    emit(
        "V4_DATA_01",
        "Go apply establishes exact/route_based/per_pair XFRM ESP tunnels with OB isolation.",
        {"status": status["status"], "passed_flows": len(flows), "blocked_flows": len(denied)},
    )

    # 4. Install privilege-separated agent (root) + web (non-root) via scripts/install-v4.sh
    cmd("bash", str(HERE / "install-v4.sh"), str(BIN))
    assert cmd("systemctl", "is-active", "ipsecvpn-agent.service").stdout.strip() == "active"
    assert cmd("systemctl", "is-active", "ipsecvpn-web.service").stdout.strip() == "active"
    agent_uid = cmd("systemctl", "show", "-p", "MainPID", "--value", "ipsecvpn-agent.service").stdout.strip()
    web_uid = cmd("ps", "-o", "user=", "-p", cmd("systemctl", "show", "-p", "MainPID", "--value", "ipsecvpn-web.service").stdout.strip()).stdout.strip()
    assert web_uid == "ipsecvpn-web", f"Expected non-root ipsecvpn-web, got {web_uid}"
    # Verify non-root web user cannot read /etc/ipsecvpn/secrets directly
    denied_sec = cmd("su", "-s", "/bin/sh", "ipsecvpn-web", "-c", "ls /etc/ipsecvpn/secrets", allowed=(1, 2))
    assert denied_sec.returncode != 0

    wc = WebClient()
    wait_until(lambda: wc.request("GET", "/healthz")[0] == 200, timeout=30, interval=0.5)
    admin_pass = extract_bootstrap_password()
    # Save password in root-only temp file for after-reboot verification
    Path("/var/lib/ipsecvpn/v4-lab-webpass").write_text(admin_pass, encoding="ascii")
    Path("/var/lib/ipsecvpn/v4-lab-webpass").chmod(0o600)

    code, _ = wc.request("POST", "/api/v1/auth/login", {"username": "admin", "password": admin_pass})
    assert code == 200, f"Web login failed: {code}"

    # Verify Unix socket SO_PEERCRED RPC connectivity between non-root web and root agent
    def _agent_ready():
        c, raw = wc.request("GET", "/api/v1/overview")
        if c == 200:
            data = json.loads(raw)
            if data.get("agent_online") is True:
                return data
        return None

    ov = wait_until(_agent_ready, timeout=20, interval=0.5)
    assert ov.get("agent_online") is True, ov

    # Save active profile via Web API & test redacted + audited plaintext PSK Tencent JSON export
    sp_code, _ = wc.request("POST", "/api/v1/profiles", {"yaml_content": LAB_PROFILE_YAML, "hub_role": "primary", "activate": True, "note": "v4 qemu lab"})
    assert sp_code == 200
    e1_code, e1_raw = wc.request("POST", "/api/v1/profiles/v4-go-esports-lab/export-peer", {"site_id": "ob-alpha", "format": "tencent-json"})
    e1 = json.loads(e1_raw)
    assert e1_code == 200 and "<SEND_SEPARATELY>" in e1["content"]

    e2_code, e2_raw = wc.request(
        "POST",
        "/api/v1/profiles/v4-go-esports-lab/export-peer",
        {"site_id": "ob-alpha", "format": "tencent-json", "include_psk": True, "confirm_password": admin_pass},
    )
    e2 = json.loads(e2_raw)
    expected_psk = (SECRETS / "ob-alpha.psk").read_text(encoding="ascii").strip()
    assert e2_code == 200 and expected_psk in e2["content"], f"Audited PSK export failed: {e2_code}"

    # Verify timeline, signoff, Prometheus /metrics, and audit trail
    tl_code, _ = wc.request("GET", "/api/v1/diagnostics/timeline?site=ob-alpha&minutes=15")
    assert tl_code == 200
    so_code, so_raw = wc.request("GET", "/api/v1/system/signoff")
    assert so_code == 200 and "VPN 网关赛前上线核对单" in json.loads(so_raw)["content"]
    mt_code, mt_raw = wc.request("GET", "/metrics")
    assert mt_code == 200 and "ipsecvpn_collector_up" in mt_raw
    au_code, au_raw = wc.request("GET", "/api/v1/audit")
    audit_actions = [row["action"] for row in json.loads(au_raw).get("logs", [])]
    assert au_code == 200 and "export_psk_plaintext" in audit_actions, audit_actions

    emit(
        "V4_WEB_01",
        "Privilege-separated agent/web services serve TLS 1.3 console with SO_PEERCRED RPC and audited PSK export.",
        {"agent_pid": agent_uid, "web_user": web_uid, "agent_online": True, "audit_count": len(audit_actions)},
    )

    # 5. Failover backup-lock + Hub XFRM gate + role swap via Web API
    sw_code, sw_raw = wc.request("POST", "/api/v1/failover/switch-backup", {"reason": "v4_lab_drill", "apply_gate": True})
    sw = json.loads(sw_raw)
    assert sw_code == 200 and sw["state"]["mode"] == "BACKUP_LOCKED", sw
    # Verify XFRM interfaces placed down while locked
    link_state = json.loads(ip("-j", "link", "show", "dev", "ivp000000ca").stdout)[0]
    assert "UP" not in link_state.get("flags", []), link_state

    # Failback without force must be blocked (409)
    fb_block, _ = wc.request("POST", "/api/v1/failover/failback", {"force": False, "apply_gate": True})
    assert fb_block == 409, f"Expected 409 hold guard, got {fb_block}"

    # Force failback unlocks gate and restores encrypted traffic
    fb_ok, fb_raw = wc.request("POST", "/api/v1/failover/failback", {"force": True, "apply_gate": True})
    assert fb_ok == 200 and json.loads(fb_raw)["state"]["mode"] == "PRIMARY_ACTIVE"
    wait_status_pass(timeout=60)
    post_fb = exchange("ob-alpha", "server-core", "10.101.10.0/24", "10.100.10.0/24", "udp", PORT + 30)
    assert post_fb["passed"]

    r1, _ = wc.request("POST", "/api/v1/failover/set-role", {"role": "backup"})
    r2, _ = wc.request("POST", "/api/v1/failover/set-role", {"role": "primary"})
    assert r1 == 200 and r2 == 200
    emit(
        "V4_FO_01",
        "Failover backup lock drops XFRM gate, enforces manual failback guard, and supports role swap.",
        {"locked_then_restored": True, "post_failback_udp": True},
    )


def after_reboot():
    # 6. Verify full unattended boot recovery (strongSwan + boot guard/restore + agent + web)
    for unit in (
        TOPOLOGY_UNIT,
        "ipsecvpn-guard.service",
        "ipsecvpn-restore.service",
        "strongswan.service",
        "ipsecvpn-agent.service",
        "ipsecvpn-web.service",
    ):
        wait_until(lambda u=unit: cmd("systemctl", "is-active", u, allowed=(0, 3)).stdout.strip() == "active", timeout=45, interval=1.0)

    status = wait_status_pass(timeout=60)
    flow = exchange("ob-alpha", "server-core", "10.101.10.0/24", "10.100.10.0/24", "udp", PORT + 40)
    denied = exchange("ob-alpha", "ob-beta", "10.101.10.0/24", "10.102.10.0/24", "udp", PORT + 41, expect_fail=True)

    wc = WebClient()
    wait_until(lambda: wc.request("GET", "/healthz")[0] == 200, timeout=30, interval=0.5)
    admin_pass = Path("/var/lib/ipsecvpn/v4-lab-webpass").read_text(encoding="ascii").strip()
    assert wc.request("POST", "/api/v1/auth/login", {"username": "admin", "password": admin_pass})[0] == 200
    ov = wait_until(
        lambda: (lambda r: json.loads(r[1]) if r[0] == 200 and json.loads(r[1]).get("agent_online") is True else None)(
            wc.request("GET", "/api/v1/overview")
        ),
        timeout=20,
        interval=0.5,
    )
    assert ov.get("agent_online") is True, ov
    emit(
        "V4_REBOOT_01",
        "After real VM reboot, Go boot restore + agent + web recover unattended with encrypted traffic and OB isolation.",
        {"status": status["status"], "udp_after_reboot": flow["passed"], "ob_blocked": denied["blocked"], "agent_online": True},
    )

    # 7. Clean uninstall & host baseline preservation
    cmd("systemctl", "disable", "--now", "ipsecvpn-web.service", "ipsecvpn-agent.service")
    Path("/var/lib/ipsecvpn/v4-lab-webpass").unlink(missing_ok=True)
    un = cli("uninstall", "--confirm")
    assert un["status"] == "PASS", un
    nft_rules = cmd("nft", "list", "ruleset").stdout
    assert "table ip ipsecvpn" not in nft_rules
    assert "table inet lab_existing" in nft_rules
    routes = cmd("ip", "route", "show", "default").stdout
    assert "labwan" in routes
    xfrms = json.loads(ip("-j", "link", "show", "type", "xfrm").stdout)
    assert not any(item.get("ifname", "").startswith("ivp") for item in xfrms), xfrms
    emit(
        "V4_CLEAN_01",
        "Go uninstall cleanly removes owned strongSwan, XFRM, and nftables while preserving host baseline.",
        {"lab_existing_preserved": True, "default_route_preserved": True, "owned_xfrm_removed": True},
    )


if __name__ == "__main__":
    phase = sys.argv[1] if len(sys.argv) > 1 else ""
    if phase == "topology":
        bootstrap_topology()
    elif phase == "before-reboot":
        before_reboot()
    elif phase == "after-reboot":
        after_reboot()
    else:
        raise SystemExit(f"Usage: {sys.argv[0]} before-reboot|after-reboot|topology")
