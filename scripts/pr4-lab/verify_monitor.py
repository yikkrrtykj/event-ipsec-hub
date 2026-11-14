"""Monitoring receipts from a disposable Ubuntu QEMU guest."""

import hashlib
import hmac
import json
import os
import secrets
import signal
import struct
import subprocess
import sys
import time
from datetime import UTC, datetime
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, HTTPServer
from ipaddress import IPv4Interface
from pathlib import Path
from threading import Thread

import verify as lab
import yaml
from topology import HERE, HOST, PROFILE, TOPO, addr, cli, command, in_ns, ip, require_lab

from ipsecvpn.host import LAB_MARKER, UNIT
from ipsecvpn.monitoring.bridge import CONFIG, signature
from ipsecvpn.monitoring.collector import collect
from ipsecvpn.monitoring.model import PROBE_FILE, State
from ipsecvpn.monitoring.probes import generation
from ipsecvpn.monitoring.udp import FRAME_BYTES, frame
from ipsecvpn.profile import load_profile
from ipsecvpn.sa import inventory, session
from ipsecvpn.secureio import atomic_write, read_record, write_record
from ipsecvpn.transaction import INSTALLED

SUMMARY = Path("/var/tmp/ipsecvpn-pr4-acceptance.jsonl")
EXPORTER = "event-ipsec-hub-exporter.service"
SAMPLER = "event-ipsec-hub-sampler.service"
BRIDGE = "event-ipsec-hub-feishu.service"
SECRETS = Path("/etc/ipsecvpn/secrets")
METRICS, BRIDGE_PORT, MOCK, ALERTMANAGER = 9814, 9815, 9816, 9817


def emit(cases, expected, observed, status="PASS"):
    for case in cases.split():
        row = {
            "case": case,
            "time_utc": datetime.now(UTC).isoformat(),
            "head_sha": lab.HEAD,
            "environment": lab.ENV,
            "action": expected,
            "expected": expected,
            "observed": observed,
            "status": status,
            "proof_refs": [SUMMARY.name],
        }
        line = json.dumps(row, sort_keys=True)
        for path in SECRETS.iterdir():
            value = path.read_bytes().strip()
            if value and (value in line.encode() or value.hex() in line):
                raise RuntimeError("Evidence contains protected fixture material.")
        with SUMMARY.open("a", encoding="utf-8") as output:
            print(line, file=output)
        print(line, flush=True)


def http(port, path="/metrics", data=None, headers=None):
    conn = HTTPConnection("127.0.0.1", port, timeout=12)
    try:
        conn.request("GET" if data is None else "POST", path, data, headers or {})
        response = conn.getresponse()
        return response.status, response.read()
    finally:
        conn.close()


def wait_for(test, limit=45):
    deadline = time.monotonic() + limit
    while time.monotonic() < deadline:
        if result := test():
            return result
        time.sleep(0.4)
    raise AssertionError("The requested runtime observation did not converge.")


def scrape():
    status, body = http(METRICS)
    assert status == 200
    return body.decode("ascii")


def line(text, metric, value):
    return any(
        row.startswith(f"event_ipsec_{metric}") and row.endswith(f" {value}")
        for row in text.splitlines()
    )


def configure():
    disabled = cli("monitor", "serve", "--confirm")
    assert disabled["status"] == "SKIP" and not HOST.service(EXPORTER, "FragmentPath")
    profile = load_profile(PROFILE)
    profile["monitoring"] = {
        "enabled": True,
        "exporter": {"interval_seconds": 5, "timeout_seconds": 4, "ttl_seconds": 12},
        "udp_path": {"enabled": True, "ttl_seconds": 15},
    }
    lab.write_profile(profile, PROFILE)
    return lab.manifest()


def start_hub():
    assert cli("install", "--confirm")["status"] == "PASS"
    lab.environment()
    assert collect()["reason_code"] == "NO_PROFILE"
    lab.create_profile()
    lab.install_topology_unit()
    model = configure()
    assert cli("apply", "-c", str(PROFILE), "--confirm")["status"] == "PASS"
    command("systemctl", "start", "ipsecvpn-restore.service")
    lab.connect(model)
    lab.verify_sas(model)
    lab.verify_traffic(model, first=True)
    return model


def exporter_tests(model):
    displaced = LAB_MARKER.with_suffix(".pr4-fixture")
    LAB_MARKER.rename(displaced)
    try:
        assert cli("monitor", "serve", "--confirm", expect=1)["decision"] == "STOP"
    finally:
        displaced.rename(LAB_MARKER)
    emit(
        "C06", "Missing root-only marker rejects monitoring service creation.", {"decision": "STOP"}
    )
    assert cli("monitor", "serve", "--dry-run")["status"] == "PASS"
    assert not HOST.service(EXPORTER, "FragmentPath")
    cli("monitor", "serve", "--confirm")
    snapshot = startup_scrape()
    assert security_status(EXPORTER) == {"CapPrm": 0, "CapEff": 0, "CapBnd": 0, "NoNewPrivs": 1}
    assert line(snapshot, "business_state", -1)
    listeners = command("ss", "-H", "-ltn", f"sport = :{METRICS}").stdout.splitlines()
    assert len(listeners) == 1 and listeners[0].split()[3] == f"127.0.0.1:{METRICS}"
    wan = str(IPv4Interface(TOPO["hub"]).ip)
    for ns in ("wan-switch", TOPO["sites"][0]["host"]):
        attempt = command(
            *in_ns(
                ns,
                "curl",
                "--noproxy",
                "*",
                "--max-time",
                "2",
                "-fsS",
                f"http://{wan}:{METRICS}/metrics",
            ),
            allowed=(0, 7, 28),
        )
        assert attempt.returncode != 0
    assert all(
        line(snapshot, metric, 1)
        for metric in (
            "site_ike_state",
            "site_child_state",
            "site_kernel_verified",
            "site_protected_route_ok",
        )
    )
    assert all(link.site_id in snapshot for link in model.links)
    assert http(METRICS, "/healthz") == (200, b"ok\n")
    assert http(METRICS, "/metrics", b"{}")[0] == 501
    (HERE / "metrics.txt").write_text(snapshot, encoding="ascii")
    command("promtool", "check", "metrics", input=snapshot)
    emit(
        "M01 M02 M03 P01",
        "Local-only scrape reports owned SAs and unknown without UDP proof.",
        {"listeners": listeners, "series": len(snapshot.splitlines()), "business": "UNKNOWN"},
    )

    generation_before = collect()
    assert (
        cli("rekey", "--site", model.links[0].site_id, "--child", "--confirm")["status"] == "PASS"
    )
    generation_after = collect()
    assert generation_before["sites"][0]["generation"] != generation_after["sites"][0]["generation"]
    assert "# TYPE event_ipsec_site_sa_rx_bytes gauge" in healthy_scrape()
    emit(
        "M09 R04",
        "Real CHILD rekey and concurrent exporter retain bidirectional business.",
        {"flows": lab.pair("udp", 510) + lab.pair("tcp", 512), "generation_changed": True},
    )

    fixture = (
        "src",
        "192.0.2.211/32",
        "dst",
        "192.0.2.212/32",
        "dir",
        "out",
        "action",
        "block",
        "priority",
        "470001",
    )
    ip("xfrm", "policy", "add", *fixture)
    try:
        before = ip("-o", "xfrm", "policy", "list", "nosock").stdout
        degraded = wait_for(lambda: "UNOWNED_SA" in scrape())
        assert degraded and line(scrape(), "collector_healthy", 0)
        assert "event_ipsec_site_child_state{" not in scrape()
        assert ip("-o", "xfrm", "policy", "list", "nosock").stdout == before
    finally:
        ip("xfrm", "policy", "delete", *fixture[:-4])
    wait_for(healthy_scrape)
    emit(
        "M07",
        "Unknown global SPD is retained, and old healthy metrics are withdrawn.",
        {"reason": "UNOWNED_SA", "preserved": True},
    )

    pid = HOST.assert_daemon({link.name for link in model.links})
    link = model.links[0]
    old = inventory(HOST, model, pid).get(link.name)
    with session(pid) as vici:
        vici.request(
            "terminate", {"child-id": str(old.child.unique_id), "force": "yes", "timeout": "2500"}
        )
    observation = wait_for(lambda: sample_child_down())
    assert observation["business"] == State.UNKNOWN
    with session(pid) as vici:
        vici.request("terminate", {"ike-id": str(old.unique_id), "force": "yes", "timeout": "2500"})
    observation = wait_for(lambda: sample_child_down(ike_down=True))
    assert observation["sites"][1]["child"] == State.UP
    emit(
        "M04 M05",
        "IKE-only and one-site outage preserve separation and the unaffected site.",
        {"ike_only_then_down": True, "other_site": "UP"},
    )
    cli("initiate", "--site", link.site_id, "--confirm")
    wait_for(healthy_scrape)


def healthy_scrape():
    snapshot = scrape()
    return snapshot if line(snapshot, "collector_healthy", 1) else None


def startup_scrape():
    try:
        return wait_for(healthy_scrape)
    except AssertionError:
        text = scrape()
        reasons = [
            row
            for row in text.splitlines()
            if row.startswith(("event_ipsec_observation_reason{", "event_ipsec_observation_stage{"))
        ]
        standalone = collect()
        emit(
            "COLLECTOR_STARTUP",
            "Initial collection becomes healthy.",
            {
                "standalone": {key: standalone.get(key) for key in ("stage", "reason_code")},
                "exporter": reasons,
                "exporter_security": security_status(EXPORTER),
                "sampler_security": security_status(SAMPLER),
                "daemon_security": security_status(UNIT),
            },
            status="FAIL",
        )
        raise


def security_status(unit):
    pid = int(HOST.service(unit, "MainPID"))
    fields = dict(row.split(":", 1) for row in Path(f"/proc/{pid}/status").read_text().splitlines())
    return {
        key: int(fields[key].strip(), 16) for key in ("CapPrm", "CapEff", "CapBnd", "NoNewPrivs")
    }


def sample_child_down(*, ike_down=False):
    snapshot = collect()
    if snapshot["collector_valid"]:
        first = snapshot["sites"][0]
        if first["ike"] == (State.DOWN if ike_down else State.UP) and first["child"] == State.DOWN:
            return snapshot
    return None


def captured_payloads(path):
    data = path.read_bytes()
    endian = "<" if data[:4] in {b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"} else ">"
    packets = []
    offset = 24
    while offset + 16 <= len(data):
        _, _, size, _ = struct.unpack_from(endian + "IIII", data, offset)
        offset += 16
        packets.append(data[offset : offset + size])
        offset += size
    return packets, hashlib.sha256(data).hexdigest()


def probe_round(model, port, *, bypass=False):
    pid = HOST.assert_daemon({link.name for link in model.links})
    before = inventory(HOST, model, pid)
    started = time.time()
    directions, evidence = [], []
    for side in range(2):
        source, target = TOPO["sites"][side], TOPO["sites"][1 - side]
        source_ip, target_ip = (addr(site["lans"][0], 11) for site in (source, target))
        send_port, recv_port = port + side * 2, port + side * 2 + 1
        route = ip("-4", "route", "get", target_ip, "from", source_ip, ns=source["host"]).stdout
        captures = lab.begin_captures(model)
        python = (sys.executable, "-I", "-m", "ipsecvpn.monitoring.udp")
        peer = lab.start_traffic(
            in_ns(
                target["host"],
                *python,
                "respond",
                target_ip,
                str(recv_port),
                source_ip,
                str(send_port),
            )
        )
        try:
            receipts = json.loads(
                command(
                    *in_ns(
                        source["host"],
                        *python,
                        "probe",
                        source_ip,
                        str(send_port),
                        target_ip,
                        str(recv_port),
                    )
                ).stdout
            )
        finally:
            lab.stop_process(peer)
            for _, _, _, proc in captures:
                lab.stop_process(proc)
        seen, hashes = {}, {}
        for node, iface, path, _ in captures:
            packets, hashes[f"{node}/{iface}"] = captured_payloads(path)
            seen[node, iface] = {
                hashlib.sha256(packet[-FRAME_BYTES:]).hexdigest()
                for packet in packets
                if len(packet) >= FRAME_BYTES
            }
            path.unlink()
        source_link, target_link = model.links[side], model.links[1 - side]
        first, second = seen["hub", source_link.name], seen["hub", target_link.name]
        wan = seen["wan-switch", "bridge"]
        request = {row["request_sha256"] for row in receipts}
        replies = {row["reply_sha256"] for row in receipts if row["rtt"] is not None}
        assert not (request | replies) & wan
        assert len(request) == len(receipts) == 3
        bound = (
            "dev eth0" in route
            and request <= first
            and (not replies or (request | replies) <= first & second)
        )
        if bypass:
            assert replies and not bound
        directions.append(
            {
                "src_site_id": source_link.site_id,
                "dst_site_id": target_link.site_id,
                "source": source_ip,
                "target": target_ip,
                "bound": bound,
                "sent": len(receipts),
                "rtts": [row["rtt"] for row in receipts if row["rtt"]],
            }
        )
        evidence.append(
            {
                "route": route.strip(),
                "sent": len(receipts),
                "receipts": receipts,
                "capture_sha256": hashes,
                "no_wan_plaintext": True,
                "bound": bound,
            }
        )
    after = inventory(HOST, model, pid)
    assert before == after
    if all(row["bound"] and row["rtts"] for row in directions):
        assert all(
            all(
                a > b
                for a, b in zip(after.get(ike.name).child.counts, ike.child.counts, strict=True)
            )
            for ike in before.ikes
        )
    write_record(
        Path(PROBE_FILE),
        {
            "owner": read_record(INSTALLED)["token"],
            "event_id": model.event_id,
            "generations": generation(after, model),
            "started": started,
            "at": time.time(),
            "directions": directions,
        },
    )
    return evidence


def path_tests(model):
    atomic_write(SECRETS / "monitor-probe", os.urandom(32))
    evidence = probe_round(model, 31900)
    snapshot = collect()
    assert snapshot["business"] == State.UP and all(row["loss"] == 0 for row in snapshot["paths"])
    wait_for(lambda: line(scrape(), "business_state", 1))
    emit(
        "P02 P03 P04 P11",
        "Independent bidirectional authenticated UDP traverses both XFRMs.",
        {"flows": evidence, "samples": snapshot["paths"]},
    )
    wait_for(lambda: line(scrape(), "business_state", -1), 25)
    assert "event_ipsec_path_probe_loss_ratio{" not in scrape()
    emit("P09", "Expired UDP proof removes previous success and numeric loss.", {"ttl_seconds": 15})
    node = TOPO["sites"][1]["host"]
    program = "table ip pr4_probe_drop { chain input { type filter hook input priority -10; "
    program += "udp dport 31911 drop; } }"
    command(*in_ns(node, "nft", "-f", "-"), input=program)
    try:
        evidence = probe_round(model, 31910)
        snapshot = collect()
        assert snapshot["business"] == State.DOWN
        assert [row["state"] for row in snapshot["paths"]] == [State.DOWN, State.UP]
        assert all(row["child"] == State.UP for row in snapshot["sites"])
        emit(
            "P05 P06",
            "A→B UDP loss with both CHILDs UP leaves B→A independently UP.",
            {"flows": evidence, "paths": snapshot["paths"]},
        )
    finally:
        command(*in_ns(node, "nft", "delete", "table", "ip", "pr4_probe_drop"))
    probe_edges(model)


def probe_edges(model):
    from ipsecvpn.monitoring.udp import Responder

    secret = (SECRETS / "monitor-probe").read_bytes()
    peer = ("10.0.0.3", 32001)
    now = time.time()
    request = frame(secret, "q", secrets.token_hex(8), 0, int(now * 1000))
    responder = Responder(secret, peer)
    assert not responder.answer(("10.0.0.4", 32001), request, now)
    assert not responder.answer(peer, request[:-1], now)
    assert not responder.answer(peer, request[:-1] + b"!", now)
    assert responder.answer(peer, request, now)
    assert not responder.answer(peer, request, now)
    emit(
        "P10 P12",
        "Signed UDP frames reject unauthorized sources, modification and replay.",
        {"frame_bytes": len(request), "nonce_exposed": False},
    )
    link = model.links[0]
    ip("link", "set", link.name, "down")
    try:
        guard = lab.capture_fail_closed(model, 560)
        snapshot = collect()
        assert snapshot["business"] == State.UNKNOWN and not snapshot["collector_valid"]
    finally:
        ip("link", "set", link.name, "up")
    emit("P07", "An unavailable XFRM path fails guarded UDP without private WAN plaintext.", guard)
    node_a, node_b = (site["host"] for site in TOPO["sites"])
    test_a, test_b = (addr(site["lans"][0], 11) for site in TOPO["sites"])
    ip(
        "link",
        "add",
        "standby",
        "type",
        "veth",
        "peer",
        "name",
        "standby",
        "netns",
        node_b,
        ns=node_a,
    )
    try:
        for node, target in ((node_a, test_b), (node_b, test_a)):
            ip("link", "set", "standby", "up", ns=node)
            ip("route", "add", f"{target}/32", "dev", "standby", ns=node)
        evidence = probe_round(model, 31920, bypass=True)
    finally:
        ip("link", "del", "standby", ns=node_a)
    snapshot = collect()
    assert snapshot["business"] == State.UNKNOWN
    assert all(row["reason_code"] == "PATH_UNVERIFIED" for row in snapshot["paths"])
    emit(
        "P08",
        "No primary path proof keeps the overall path unverified.",
        {"directions": snapshot["paths"], "alternate_receipts": evidence},
    )


def runtime_faults(model):
    exporter_pid = int(HOST.service(EXPORTER, "MainPID"))
    sampler_pid = int(HOST.service(SAMPLER, "MainPID"))
    vpn_pid = HOST.assert_daemon({link.name for link in model.links})
    baseline = lab.baseline_for(model)
    before = inventory(HOST, model, vpn_pid)
    saved = Path("/run/charon.vici").with_suffix(".pr4")
    original = Path("/run/charon.vici")
    original.rename(saved)
    try:
        wait_for(lambda: line(scrape(), "collector_healthy", 0))
        assert line(scrape(), "business_state", -1)
    finally:
        saved.rename(original)
    wait_for(healthy_scrape)
    emit("M06", "Missing VICI socket invalidates cached healthy facts.", {"collector_healthy": 0})

    def collector_pid():
        children = Path(f"/proc/{sampler_pid}/task")
        for task in children.iterdir():
            try:
                pids = (task / "children").read_text().split()
                for pid in pids:
                    cmdline = Path(f"/proc/{pid}/cmdline").read_bytes()
                    if b"ipsecvpn.monitoring.collector" in cmdline:
                        return int(pid)
            except FileNotFoundError:
                continue
        return None

    child = None
    for _ in range(600):
        child = collector_pid()
        if child:
            os.kill(child, signal.SIGSTOP)
            break
        time.sleep(0.025)
    assert child
    start = time.monotonic()
    assert http(METRICS, "/healthz")[0] == 200
    elapsed = time.monotonic() - start
    wait_for(lambda: "COLLECTOR_TIMEOUT" in scrape())
    wait_for(healthy_scrape)
    status = Path(f"/proc/{exporter_pid}/status").read_text()
    assert "VmRSS:" in status
    proc_stat = Path(f"/proc/{exporter_pid}/stat").read_text().split(") ", 1)[1].split()
    emit(
        "M08 R07",
        "A stopped worker times out, HTTP stays responsive, and sampling recovers.",
        {
            "health_seconds": elapsed,
            "rss_kib": int(status.split("VmRSS:")[1].split()[0]),
            "cpu_ticks": int(proc_stat[11]) + int(proc_stat[12]),
        },
    )

    os.kill(exporter_pid, signal.SIGKILL)
    wait_for(lambda: HOST.service(EXPORTER, "ActiveState") == "failed")
    assert HOST.assert_daemon({link.name for link in model.links}) == vpn_pid
    assert inventory(HOST, model, vpn_pid) == before and lab.baseline_for(model) == baseline
    flows = lab.pair("udp", 572) + lab.pair("tcp", 574)
    command("systemctl", "restart", EXPORTER)
    wait_for(healthy_scrape)
    assert line(scrape(), "business_state", -1)
    emit(
        "M10 M11 R05",
        "Killed exporter leaves SSH, network, VPN and UDP/TCP intact.",
        {"flows": flows, "baseline": baseline, "restarted_exporter": True},
    )


def alert_tests(model):
    key, token = secrets.token_hex(32).encode(), secrets.token_urlsafe(32).encode()
    atomic_write(SECRETS / "monitor-signing", key)
    atomic_write(SECRETS / "monitor-bearer", token)
    atomic_write(
        CONFIG,
        json.dumps(
            {
                "enabled": True,
                "port": BRIDGE_PORT,
                "mock_endpoint": f"http://127.0.0.1:{MOCK}/mock",
            }
        ).encode(),
    )
    delivery = []
    outcomes = []

    class Mock(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            timestamp = int(payload["timestamp"])
            assert hmac.compare_digest(signature(timestamp, key), payload["sign"])
            assert abs(time.time() - timestamp) < 10
            message = payload["content"]["text"]
            delivery.append(message)
            status, code = outcomes.pop(0) if outcomes else (200, 0)
            if status == 0:
                time.sleep(2)
                return
            data = json.dumps({"code": code}).encode()
            self.send_response(status)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    with HTTPServer(("127.0.0.1", MOCK), Mock) as mock:
        thread = Thread(target=mock.serve_forever, daemon=True)
        thread.start()
        try:
            assert not HOST.service(BRIDGE, "FragmentPath") and not delivery
            emit(
                "A01",
                "Exporter and live business run without an installed bridge.",
                {"deliveries": len(delivery), "flows": lab.pair("udp", 578)},
            )
            cli("monitor", "serve", "--with-bridge", "--confirm")
            security = security_status(BRIDGE)
            assert security == {"CapPrm": 0, "CapEff": 0, "CapBnd": 0, "NoNewPrivs": 1}
            listeners = command("ss", "-H", "-ltn", f"sport = :{BRIDGE_PORT}").stdout.splitlines()
            assert len(listeners) == 1 and listeners[0].split()[3] == f"127.0.0.1:{BRIDGE_PORT}"
            emit(
                "BRIDGE_BOUNDARY",
                "The bridge starts without capabilities and binds only loopback.",
                {"security": security, "listeners": listeners},
            )
            receiver = HERE / "monitoring/alertmanager/receiver.example.yml"
            command("amtool", "check-config", str(receiver))
            rules = HERE / "monitoring/prometheus"
            command("promtool", "check", "rules", str(rules / "rules.yml"))
            command("promtool", "test", "rules", str(rules / "rules.test.yml"))
            dashboard = json.loads((HERE / "monitoring/grafana/event-ipsec-hub.json").read_text())
            assert dashboard["templating"]["list"][0]["name"] == "DS_PROMETHEUS"
            assert all(
                panel["fieldConfig"]["defaults"]["noValue"] == "UNKNOWN"
                for panel in dashboard["panels"]
                if panel["type"] != "text"
            )
            emit(
                "C12 C13 A06",
                "Prometheus rule tests and Grafana import structure validate.",
                {
                    "prometheus": version("prometheus"),
                    "alertmanager": version("prometheus-alertmanager"),
                    "dashboard_panels": len(dashboard["panels"]),
                },
            )
            run_notifications(model, key, token, delivery, outcomes, receiver)
        finally:
            mock.shutdown()
            thread.join(3)


def version(program):
    result = command(program, "--version")
    return (result.stdout or result.stderr).splitlines()[0]


def run_notifications(model, key, token, delivery, outcomes, receiver):
    current = datetime.now(UTC).isoformat()
    labels = {
        "alertname": "IpsecChildDown",
        "severity": "critical",
        "event_id": model.event_id,
        "hub_id": load_profile(PROFILE)["hub"]["id"],
        "site_id": model.links[0].site_id,
    }
    row = {
        "status": "firing",
        "startsAt": current,
        "fingerprint": "0000000000000001",
        "labels": labels,
        "annotations": {"untrusted": "<payload>"},
    }
    auth = {"Authorization": "Bearer " + token.decode("ascii")}

    def send(alert):
        return http(BRIDGE_PORT, "/alertmanager", json.dumps({"alerts": [alert]}), auth)[0]

    assert http(BRIDGE_PORT, "/alertmanager", b"{}")[0] == 401
    assert http(BRIDGE_PORT, "/alertmanager", b"{}", {"Authorization": "Bearer wrong"})[0] == 401
    assert http(BRIDGE_PORT, "/alertmanager", b"x" * 32769, auth)[0] == 413
    assert http(BRIDGE_PORT, "/alertmanager", b"not-json", auth)[0] == 400
    emit(
        "A07",
        "Missing/bad bearer, oversized input and malformed JSON are rejected.",
        {"status_codes": [401, 401, 413, 400]},
    )
    assert send({**row, "status": "resolved"}) == 200 and not delivery
    assert send(row) == 200 and len(delivery) == 1
    assert all(
        item in delivery[-1] for item in ("FIRING", "Asia/Shanghai", "UTC", "IpsecChildDown")
    )
    assert "<payload>" not in delivery[-1] and key.decode() not in delivery[-1]
    emit(
        "A02 A08 C14",
        "Local mock independently checks signature and redacted firing.",
        {"messages": 1, "timezone": "Asia/Shanghai", "signed": True},
    )
    command("systemctl", "restart", BRIDGE)
    assert send(row) == 200 and len(delivery) == 1
    emit("A03", "Duplicate firing is suppressed after bridge restart.", {"messages": 1})
    command("systemctl", "stop", EXPORTER)
    resolved = {**row, "status": "resolved"}
    try:
        assert send(resolved) == 200 and "DATA_UNAVAILABLE" in delivery[-1]
        assert send(resolved) == 200 and len(delivery) == 2
    finally:
        command("systemctl", "start", EXPORTER)
    wait_for(healthy_scrape)
    assert send(resolved) == 200 and "RECOVERED" in delivery[-1] and len(delivery) == 3
    assert send(row) == 200 and len(delivery) == 4 and "FIRING" in delivery[-1]
    emit(
        "A04 A05 A11",
        "Recovery requires prior firing and fresh proof; new firing can deliver.",
        {"sequence": ["FIRING", "DATA_UNAVAILABLE", "RECOVERED", "FIRING"]},
    )
    outcomes.extend([(429, 0), (500, 0), (200, 0)])
    assert send({**row, "fingerprint": "0000000000000002"}) == 200 and len(delivery) == 7
    outcomes.extend([(0, 0), (200, 0)])
    assert send({**row, "fingerprint": "0000000000000003"}) == 200 and len(delivery) == 9
    emit(
        "A09",
        "429, 500 and timeout retry against the mock with bounded attempts.",
        {"attempt_counts": [3, 2], "flows": lab.pair("tcp", 580)},
    )
    for index, status, code in ((4, 401, 0), (5, 200, 42)):
        failed = {**row, "fingerprint": f"{index:016x}"}
        outcomes.append((status, code))
        count = len(delivery)
        assert send(failed) == send(failed) == 503 and len(delivery) == count + 1
    assert b"event_ipsec_alert_bridge_delivery_failures_total 2" in http(BRIDGE_PORT)[1]
    emit(
        "A10",
        "HTTP 401 and HTTP 200 with a failing business code fail visibly and rate-limit.",
        {"delivery_failures": 2},
    )
    alertmanager_round(receiver, delivery, labels, current)


def alertmanager_round(receiver, delivery, labels, current):
    fixture = yaml.safe_load(receiver.read_text())
    fixture["route"]["group_wait"] = "1s"
    fixture["route"]["group_interval"] = "2s"
    config = HERE / "alertmanager-lab.yml"
    config.write_text(yaml.safe_dump(fixture), encoding="utf-8")
    with subprocess.Popen(
        (
            "prometheus-alertmanager",
            f"--config.file={config}",
            "--cluster.listen-address=",
            f"--web.listen-address=127.0.0.1:{ALERTMANAGER}",
            f"--storage.path={HERE / 'am-data'}",
        ),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ) as process:
        try:

            def ready():
                try:
                    return http(ALERTMANAGER, "/-/ready")[0] == 200
                except OSError:
                    return False

            wait_for(ready, 15)
            count = len(delivery)
            request = json.dumps(
                [
                    {
                        "startsAt": current,
                        "labels": {
                            **labels,
                            "alertname": "IpsecIkeDown",
                        },
                    }
                ]
            )
            assert (
                http(ALERTMANAGER, "/api/v2/alerts", request, {"Content-Type": "application/json"})[
                    0
                ]
                == 200
            )
            wait_for(lambda: len(delivery) > count, 15)
            assert "FIRING IpsecIkeDown" in delivery[-1]
            emit(
                "ALERTMANAGER",
                "Real local Alertmanager delivers a grouped webhook to the bridge.",
                {"outbound_messages": len(delivery) - count},
            )
        finally:
            lab.stop_process(process)


def before_reboot():
    model = start_hub()
    lab.BASELINE.write_text(json.dumps(lab.baseline_for(model)), encoding="utf-8")
    exporter_tests(model)
    path_tests(model)
    runtime_faults(model)
    alert_tests(model)


def after_reboot():
    lab.environment()
    model = lab.manifest()
    wait_for(
        lambda: all(
            HOST.service(unit, "ActiveState") == "active"
            for unit in ("ipsecvpn-guard.service", "ipsecvpn-restore.service", SAMPLER, EXPORTER)
        )
    )
    wait_for(healthy_scrape)
    pid = HOST.assert_daemon({link.name for link in model.links})
    sas = inventory(HOST, model, pid)
    assert len(sas.ikes) == 2
    baseline = lab.baseline_for(model)
    assert baseline == json.loads(lab.BASELINE.read_text(encoding="utf-8"))
    cli("monitor", "stop", "--dry-run")
    cli("monitor", "stop", "--confirm")
    assert all(not HOST.service(unit, "FragmentPath") for unit in (SAMPLER, EXPORTER, BRIDGE))
    assert HOST.assert_daemon({link.name for link in model.links}) == pid
    assert inventory(HOST, model, pid) == sas and lab.baseline_for(model) == baseline
    emit(
        "M12 A12 R06 R08",
        "Actual QEMU reboot and monitor removal preserve VPN and host baseline.",
        {
            "pid": int(pid),
            "protected_baseline": baseline,
            "flows": lab.pair("udp", 550) + lab.pair("tcp", 552),
        },
    )


if __name__ == "__main__":
    require_lab()
    try:
        {"before-reboot": before_reboot, "after-reboot": after_reboot}[sys.argv[1]]()
    except Exception as exc:
        emit(
            "LAB",
            "Monitoring isolation experiment completes.",
            {"type": type(exc).__name__},
            status="FAIL",
        )
        raise
