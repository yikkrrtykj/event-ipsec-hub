"""Real three-node acceptance, executed only inside the disposable QEMU guest."""

import hashlib
import json
import os
import re
import secrets
import select
import signal
import subprocess
import sys
import time
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

from topology import (
    HERE,
    HOST,
    PEER_ROOT,
    PROFILE,
    TOPO,
    addr,
    cli,
    command,
    create_profile,
    in_ns,
    install_topology_unit,
    ip,
    peerctl,
    require_lab,
    write_profile,
)

from ipsecvpn.host import UNIT, Host
from ipsecvpn.profile import load_profile
from ipsecvpn.renderer import DeploymentManifest, build_manifest
from ipsecvpn.resources import Resources
from ipsecvpn.sa import correlate, inventory, kernel_policies, kernel_states, parse_vici, session
from ipsecvpn.secureio import Stop, read_record
from ipsecvpn.transaction import ACTIVE, INSTALLED, JOURNAL, Deployment

SUMMARY = Path("/var/tmp/ipsecvpn-pr3-acceptance.jsonl")
BASELINE = HERE / "baseline.json"
PORT = TOPO["traffic_port"]
UPDATE = PROFILE.with_name("pr3-update.yaml")
ENV = {}
HEAD = (HERE / "head-sha").read_text(encoding="ascii").strip()


def emit(cases, expected, observed, *, status="PASS", action="inspect real nodes"):
    for case in cases.split():
        receipt = {
            "case": case,
            "time_utc": datetime.now(UTC).isoformat(),
            "head_sha": HEAD,
            "environment": ENV,
            "action": action,
            "expected": expected,
            "observed": observed,
            "status": status,
            "proof_refs": [SUMMARY.name],
        }
        line = json.dumps(receipt, sort_keys=True)
        with SUMMARY.open("a", encoding="utf-8") as stream:
            stream.write(line + "\n")
        print(line, flush=True)


def environment():
    packages = HOST.packages()
    ENV.update(
        HOST.probe(),
        strongswan=packages["charon-systemd"],
        iproute2=packages["iproute2"],
        nft=command("nft", "--version").stdout.strip(),
    )


def manifest():
    return build_manifest(load_profile(PROFILE))


def baseline_for(model):
    owner = read_record(INSTALLED)["token"]
    return Resources(HOST, owner, (model,)).baseline()


def peer_pid(site):
    return int((PEER_ROOT / site["router"] / "pid").read_text(encoding="ascii"))


def prove_topology():
    pids = {
        "hub": int(HOST.service(UNIT, "MainPID")),
        **{site["router"]: peer_pid(site) for site in TOPO["sites"]},
    }
    namespaces = {node: os.readlink(f"/proc/{pid}/ns/net") for node, pid in pids.items()}
    assert len(set(pids.values())) == len(set(namespaces.values())) == 3
    for site in TOPO["sites"]:
        assert not ip("-4", "route", "show", "default", ns=site["router"]).stdout
        assert (PEER_ROOT / site["router"] / "charon.vici").is_socket()
    assert not ip("-4", "route", "show", "default", "dev", TOPO["wan"]).stdout
    emit(
        "T01",
        "Three isolated IKE nodes, two LAN stacks, no default route on the test WAN.",
        {
            "pids": pids,
            "network_namespaces": namespaces,
            "peer_vici": {s["router"]: s["router"] + "/charon.vici" for s in TOPO["sites"]},
            "lan_nodes": [s["host"] for s in TOPO["sites"]],
            "qemu": "restrict=on with loopback-only SSH management",
        },
    )


def verify_sas(model):
    pid = HOST.assert_daemon({link.name for link in model.links})
    live = inventory(HOST, model, pid)
    assert len(live.ikes) == 2 and all(ike.child for ike in live.ikes)
    for idx, (site, link) in enumerate(zip(TOPO["sites"], model.links, strict=True)):
        reverse = replace(
            link,
            source=link.peer,
            peer=link.source,
            local_id=link.remote_id,
            remote_id=link.local_id,
            local_ts=link.remote_ts,
            remote_ts=link.local_ts,
        )
        peer = DeploymentManifest(model.event_id, (reverse,))
        with session(peer_pid(site), PEER_ROOT / site["router"] / "charon.vici") as ctl:
            observed = parse_vici(ctl.list_sas(), peer)
        states = kernel_states(
            ip("-o", "xfrm", "state", "list", "nokeys", ns=site["router"]).stdout
        )
        policies = kernel_policies(
            ip("-o", "xfrm", "policy", "list", "nosock", ns=site["router"]).stdout
        )
        correlate(observed, peer, states, policies)
        hub_child = live.get(link.name).child
        peer_child = observed.get(link.name).child
        assert hub_child.outbound.spi == peer_child.inbound.spi
        assert hub_child.inbound.spi == peer_child.outbound.spi
        emit(
            f"T0{idx + 2}",
            "Both ends installed the same negotiated tunnel.",
            {
                "peer_node": site["router"],
                "hub_interface": link.name,
                "peer_interface": "tunnel",
                "ike": "ESTABLISHED",
                "child": "INSTALLED",
                "if_id": link.if_id,
                "hub_reqid": hub_child.inbound.reqid,
                "peer_reqid": peer_child.inbound.reqid,
                "local_ts": link.local_ts,
                "remote_ts": link.remote_ts,
                "peer_policy_count": len(policies),
                "opposite_spis_match": True,
            },
        )
    emit(
        "T04",
        "Every Hub CHILD maps to both SPIs and all global ESP policies.",
        {
            "interfaces": [link.name for link in model.links],
            "ikes": len(live.ikes),
            "kernel_state_count": 2 * len(live.ikes),
        },
    )
    return live


def start_traffic(args):
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    ready, _, _ = select.select([proc.stdout], [], [], 5)
    if not ready or proc.stdout.readline().strip() != "READY":
        stop_process(proc)
        raise RuntimeError("The LAN receiver did not start.")
    return proc


def stop_process(proc):
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=4)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=4)


def exchange(
    side,
    protocol,
    source_net,
    destination_net,
    *,
    sport,
    count=3,
    size=96,
    pmtu="default",
    mss=0,
    expected_failure=False,
):
    source = addr(source_net, 11)
    destination = addr(destination_net, 11)
    sender, receiver = TOPO["sites"][side]["host"], TOPO["sites"][1 - side]["host"]
    program = (sys.executable, str(HERE / "traffic.py"))
    server = start_traffic(
        in_ns(receiver, *program, "server", protocol, destination, str(PORT), str(count))
    )
    try:
        nonce = secrets.token_hex(8)
        proc = command(
            *in_ns(
                sender,
                *program,
                "client",
                protocol,
                source,
                str(sport),
                destination,
                str(PORT),
                str(count),
                str(size),
                nonce,
                pmtu,
                str(mss),
            ),
            allowed=(0, 1),
            timeout=12,
        )
        receipt = json.loads(proc.stdout)
        if proc.returncode == 1 and expected_failure is not False:
            assert isinstance(receipt, dict)
            return {
                "sender": sender,
                "receiver": receiver,
                "source": source,
                "destination": destination,
                "bytes": size,
                **receipt,
            }
        assert expected_failure is not True
        assert proc.returncode == 0, receipt
        remote = json.loads(server.communicate(timeout=8)[0])
        assert server.returncode == 0 and remote == receipt and len(remote) == count
        assert all(row["source"] == [source, sport] and row["bytes"] == size for row in remote)
        return {
            "sender": sender,
            "receiver": receiver,
            "source": source,
            "destination": destination,
            "protocol": protocol,
            "source_port": sport,
            "destination_port": PORT,
            "received": count,
            "bytes_each": size,
            "mss": mss,
            "sha256": [row["sha256"] for row in remote],
        }
    finally:
        stop_process(server)


def begin_captures(model, *, wan_only=False):
    points = [("hub", TOPO["wan"], None, "ip")]
    for link, site in zip(model.links, TOPO["sites"], strict=True) if not wan_only else ():
        points.extend(
            (
                ("hub", link.name, None, "ip"),
                (site["router"], "wan", site["router"], "ip"),
                (site["host"], "eth0", site["host"], "ip"),
            )
        )
    captures = []
    try:
        for node, interface, ns, capture_filter in points:
            path = HERE / f"{node}-{interface}.pcap"
            args = (
                "tcpdump",
                "-nn",
                "-Z",
                "root",
                "-U",
                "-i",
                interface,
                "-s",
                "96",
                "-w",
                str(path),
                capture_filter,
            )
            proc = subprocess.Popen(
                in_ns(ns, *args) if ns else args,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
            )
            captures.append((node, interface, path, proc))
            ready, _, _ = select.select([proc.stderr], [], [], 6)
            if not ready or "listening on" not in proc.stderr.readline():
                raise RuntimeError(f"Capture failed to start at {node}/{interface}.")
    except BaseException:
        for _, _, _, proc in captures:
            stop_process(proc)
        raise
    return captures


def finish_captures(captures):
    rows = {}
    for node, interface, path, proc in captures:
        stop_process(proc)
        if not path.exists():
            continue
        lines = command("tcpdump", "-nn", "-tt", "-r", str(path)).stdout.splitlines()
        path.unlink()
        rows[f"{node}/{interface}"] = [
            re.sub(r"spi=0x[0-9a-f]+", "spi=<redacted>", line) for line in lines
        ]
    return rows


def verify_traffic(model, first):
    baseline = {
        site["site_id"]: (site["rx_packets"], site["tx_packets"]) for site in cli("status")["sites"]
    }
    captures = begin_captures(model)
    all_rows = []
    try:
        for side in (0, 1):
            src, dst = TOPO["sites"][side]["lans"], TOPO["sites"][1 - side]["lans"]
            for proto in ("udp", "tcp"):
                receipt = exchange(
                    side, proto, src[0], dst[0], sport=PORT + 1 + 2 * side + (proto == "tcp")
                )
                all_rows.append(receipt)
            for index in range(1, 4):
                all_rows.append(
                    exchange(
                        side,
                        "udp",
                        src[index // 2],
                        dst[index % 2],
                        sport=PORT + 10 + 4 * side + index,
                    )
                )
        time.sleep(0.2)
    finally:
        observed = finish_captures(captures)
    current = cli("status")
    assert current["status"] == "PASS" and current["data_path"]["status"] == "SKIP", current
    for site in current["sites"]:
        before = baseline[site["site_id"]]
        assert site["rx_packets"] > before[0] and site["tx_packets"] > before[1]
    wan = observed[f"hub/{TOPO['wan']}"]
    assert all(not any(row["source"] in line for row in all_rows) for line in wan)
    for link in model.links:
        assert any(link.peer in line and "ESP" in line for line in wan), wan[:5]
    for site in TOPO["sites"]:
        edge = observed[f"{site['router']}/wan"]
        assert any("ESP" in line for line in edge)
        assert all(not any(row["source"] in line for row in all_rows) for line in edge)
    for row in all_rows:
        needle = f"{row['source']}.{row['source_port']} > {row['destination']}.{PORT}:"
        for key in [f"hub/{link.name}" for link in model.links] + [
            f"{row['sender']}/eth0",
            f"{row['receiver']}/eth0",
        ]:
            assert any(needle in line for line in observed[key]), (key, needle)
        if row["protocol"] == "tcp":
            path = observed[f"{row['sender']}/eth0"]
            assert any(needle in line and "Flags [S]" in line for line in path)
            assert any(needle in line and "Flags [F" in line for line in path)
    if first:
        for case, row in zip(
            ("T05", "T07", "T06", "T08"),
            [all_rows[0], all_rows[1], all_rows[5], all_rows[6]],
            strict=True,
        ):
            emit(case, "LAN hosts verify nonce, sequence and original source.", row)
        emit("T09", "Every pair in the multi-CIDR matrix reaches the opposite LAN host.", all_rows)
        emit(
            "T10 T11",
            "LAN and XFRM tuples match. WAN only carries encrypted test traffic.",
            {
                key: {
                    "packets": len(lines),
                    "sha256": hashlib.sha256("\n".join(lines).encode()).hexdigest(),
                    "samples": lines[:4],
                }
                for key, lines in observed.items()
            },
        )
    return all_rows


def verify_routes(model):
    paths = {}
    for site, link in zip(TOPO["sites"], model.links, strict=True):
        destination = addr(link.local_ts[0], 11)
        site_lookup = ip("-j", "route", "get", destination, ns=site["router"])
        assert json.loads(site_lookup.stdout)[0]["dev"] == "tunnel"
        inner = json.loads(ip("-j", "route", "get", addr(link.remote_ts[0], 11)).stdout)[0]
        outer = json.loads(ip("-j", "route", "get", link.peer, "from", link.source).stdout)[0]
        assert inner["dev"] == link.name and outer["dev"] == TOPO["wan"]
        paths[site["router"]] = {
            "peer_xfrm": "tunnel",
            "hub_xfrm": inner["dev"],
            "hub_peer_route": outer["dev"],
        }
    emit(
        "T12",
        "Reciprocal private routes use XFRM, while outer peers remain on the isolated WAN.",
        paths,
    )


def connect(model):
    for link in model.links:
        report = cli("initiate", "--site", link.site_id, "--confirm")
        assert report["status"] == "PASS", report


def verify_noop(model):
    pid = HOST.assert_daemon({link.name for link in model.links})
    live = inventory(HOST, model, pid)
    recorded = JOURNAL.read_bytes()
    assert cli("doctor")["data_path"]["status"] == "SKIP"
    result = cli("apply", "-c", str(PROFILE), "--confirm")
    assert "NOOP" in result["detail"] and JOURNAL.read_bytes() == recorded
    assert inventory(HOST, model, pid) == live
    row = exchange(
        0, "udp", TOPO["sites"][0]["lans"][0], TOPO["sites"][1]["lans"][0], sport=PORT + 39
    )
    emit(
        "T14",
        "Live same-profile apply preserves IKE/CHILD IDs and journal.",
        {"apply": result["detail"], "payload": row},
        action="doctor; apply --confirm; UDP probe",
    )


def pair(protocol, start, **kwargs):
    return [
        exchange(
            side,
            protocol,
            TOPO["sites"][side]["lans"][0],
            TOPO["sites"][1 - side]["lans"][0],
            sport=PORT + start + side,
            **kwargs,
        )
        for side in (0, 1)
    ]


def stable(model, predicate, seconds=12):
    end = time.monotonic() + seconds
    pid = HOST.assert_daemon({link.name for link in model.links})
    while time.monotonic() < end:
        try:
            observed = inventory(HOST, model, pid)
            if predicate(observed):
                return observed
        except Stop:
            pass
        time.sleep(0.35)
    raise RuntimeError("The isolated Hub did not reach the expected verified SA state.")


def verify_rekeys(model):
    link = model.links[0]
    node = TOPO["sites"][0]
    pid = HOST.assert_daemon({item.name for item in model.links})
    for idx, (case, kind) in enumerate((("S01", "ike"), ("S02", "child"))):
        before = inventory(HOST, model, pid).get(link.name)
        report = cli("rekey", "--site", link.site_id, f"--{kind}", "--confirm")
        after = inventory(HOST, model, pid).get(link.name)
        old = before.unique_id if kind == "ike" else before.child.unique_id
        new = after.unique_id if kind == "ike" else after.child.unique_id
        assert old != new
        emit(
            case,
            "Targeted rekey correlates VICI old/new and retains real bidirectional traffic.",
            {
                "journal": report["journal"],
                "old": old,
                "new": new,
                "flows": pair("udp", 45 + idx * 2),
            },
            action=f"rekey --{kind} --confirm",
        )
    changes = {}
    for kind in ("child", "ike"):
        before = inventory(HOST, model, pid).get(link.name)
        old = before.child.unique_id if kind == "child" else before.unique_id
        peerctl(node, "--rekey", f"--{kind}", link.child if kind == "child" else link.name)

        def changed(snap):
            current = snap.get(link.name)
            return (
                current
                and current.child
                and (current.child.unique_id if kind == "child" else current.unique_id) != old
            )

        current = stable(model, changed).get(link.name)
        changes[kind] = [old, current.child.unique_id if kind == "child" else current.unique_id]
    emit(
        "S03",
        "The real peer initiates CHILD and IKE rekey.",
        {"peer": node["router"], "hub_generations": changes, "flows": pair("udp", 50)},
        action="peer swanctl --rekey for each SA type",
    )


def capture_fail_closed(model, start):
    captures = begin_captures(model, wan_only=True)
    try:
        rows = pair("udp", start, expected_failure=True, count=1)
    finally:
        observed = finish_captures(captures)
    wan = observed[f"hub/{TOPO['wan']}"]
    assert all(not any(row["source"] in line for row in rows) for line in wan)
    return {"unreachable_flows": rows, "wan_packets": len(wan), "wan_plaintext": 0}


def verify_mtu(model):
    def stats(node):
        command_args = ("cat", "/proc/net/xfrm_stat")
        if node:
            command_args = in_ns(node, *command_args)
        return {
            name: int(value)
            for name, value in (line.split() for line in command(*command_args).stdout.splitlines())
        }

    node = TOPO["sites"][0]["router"]
    nodes = [None, node, TOPO["sites"][1]["router"]]
    before = {ns or "hub": stats(ns) for ns in nodes}
    small = pair("udp", 60, count=5, size=96, pmtu="df")
    emit(
        "N01",
        "Five small DF UDP payloads received in both directions.",
        {"flows": small, "lost": 0},
    )
    captures = begin_captures(model)
    try:
        bounds = [
            exchange(
                0,
                "udp",
                TOPO["sites"][0]["lans"][0],
                TOPO["sites"][1]["lans"][0],
                sport=PORT + 64 + i,
                count=1,
                size=size,
                pmtu="df",
                expected_failure=None,
            )
            for i, size in enumerate((1200, 1300, 1380, 1420, 1460, 1472))
        ]
        fragments = pair("udp", 72, count=2, size=2048, pmtu="fragment", expected_failure=None)
        streams = pair("tcp", 74, count=2, size=8192, mss=512) + pair(
            "tcp", 76, count=2, size=8192, mss=1024
        )
    finally:
        observed = finish_captures(captures)
    devices = {
        f"hub/{link.name}": json.loads(ip("-j", "link", "show", "dev", link.name).stdout)[0]["mtu"]
        for link in model.links
    }
    for site in TOPO["sites"]:
        for device in ("wan", "tunnel"):
            key = f"{site['router']}/{device}"
            devices[key] = json.loads(
                ip("-j", "link", "show", "dev", device, ns=site["router"]).stdout
            )[0]["mtu"]
    icmp = {
        key: [line for line in lines if "need to frag" in line.lower()]
        for key, lines in observed.items()
    }
    emit(
        "N02",
        "Real DF size sweep with measured link MTUs.",
        {"mtus": devices, "sweep": bounds, "outer": "UDP encapsulated ESP"},
    )
    has_feedback = any(icmp.values()) or any(row.get("errno") == 90 for row in bounds)
    emit(
        "N03",
        "Oversize DF receives ICMP fragmentation-needed or EMSGSIZE.",
        {"icmp": icmp, "results": bounds},
        status="PASS" if has_feedback else "FAIL",
    )
    fragment_evidence = {
        key: [line for line in lines if "ip-proto-17" in line.lower() or "frag" in line.lower()][:8]
        for key, lines in observed.items()
    }
    fragments_ok = all(row.get("received") == 2 for row in fragments) and any(
        fragment_evidence.values()
    )
    emit(
        "N04",
        "Fragmented datagrams are reassembled with verified payloads.",
        {"flows": fragments, "fragments": fragment_evidence},
        status="PASS" if fragments_ok else "FAIL",
    )
    emit("N05", "Bidirectional TCP transfers verify payloads at two bounded MSS settings.", streams)
    after = {ns or "hub": stats(ns) for ns in nodes}
    counters = {
        node: {
            key: value - before[node][key]
            for key, value in fields.items()
            if value != before[node][key]
        }
        for node, fields in after.items()
    }
    emit(
        "N06",
        "Collect actual per-node XFRM counters and XFRM traffic stats without sysctl edits.",
        {"errors": counters, "hub_links": cli("status")["sites"]},
    )


def assert_write_stop(model):
    site = model.links[0].site_id
    recorded = JOURNAL.read_bytes()
    for args in (
        ("apply", "-c", str(PROFILE), "--maintenance", "--confirm"),
        ("initiate", "--site", site, "--confirm"),
        ("rekey", "--site", site, "--child", "--confirm"),
        ("uninstall", "--maintenance", "--confirm"),
    ):
        assert cli(*args, expect=1)["decision"] == "STOP"
    assert JOURNAL.read_bytes() == recorded


def verify_foreign_policy(model):
    policy = (
        "src",
        "192.0.2.211/32",
        "dst",
        "192.0.2.212/32",
        "dir",
        "out",
        "if_id",
        str(model.links[0].if_id),
    )
    ip("xfrm", "policy", "add", *policy, "action", "block", "priority", "470000")
    try:
        before = ip("-o", "xfrm", "policy", "list", "nosock").stdout
        assert_write_stop(model)
        assert cli("status", expect=1)["decision"] == "STOP"
        assert ip("-o", "xfrm", "policy", "list", "nosock").stdout == before
    finally:
        ip("xfrm", "policy", "delete", *policy)
    emit(
        "F05 F06",
        "Unowned kernel policy using a genuine if_id blocks writes.",
        {"decision": "STOP", "original_policy_retained_until_fixture_cleanup": True},
    )


class RouteFault(Host):
    def __init__(self, kill=False):
        super().__init__()
        self.kill = kill
        self.triggered = False

    def command(self, label, *args, **kwargs):
        if label == "IPv4 unicast route del" and kwargs.get("mutate") and not self.triggered:
            self.triggered = True
            if self.kill:
                super().command(label, *args, **kwargs)
                os.kill(os.getpid(), signal.SIGKILL)
            return super().command(
                label, "setpriv", "--bounding-set=-net_admin", *args, mutate=True
            )
        return super().command(label, *args, **kwargs)


def verify_maintenance(model):
    profile = load_profile(PROFILE)
    profile["site_links"][0]["if_id"] += 256
    write_profile(profile, UPDATE)
    blocked = cli("apply", "-c", str(UPDATE), "--confirm", expect=1)
    assert "maintenance" in blocked["detail"]
    emit(
        "F13",
        "Unconfirmed active config change preserves the old business path.",
        {"decision": "STOP", "flows": pair("udp", 80)},
    )
    saved = cli("backup", "--confirm")["backup_id"]
    changed = cli("apply", "-c", str(UPDATE), "--maintenance", "--confirm")
    assert changed["maintenance"]["required_for_changes"]
    emit(
        "S07",
        "Explicit maintenance changes Hub XFRM ID, restores both CHILDs and actual LAN traffic.",
        {"journal": changed["backup_id"], "flows": pair("udp", 84) + pair("tcp", 86)},
    )
    returned = cli("rollback", "--to", saved, "--maintenance", "--confirm")
    assert returned["configuration_restored"] and returned["data_path_restored"]["status"] == "SKIP"
    assert cli("status")["status"] == "PASS"
    for kill, case in ((False, "S10"), (True, "S08")):
        if kill:
            child = subprocess.run((sys.executable, __file__, "crash"), check=False, timeout=30)
            assert child.returncode == -signal.SIGKILL
        else:
            faulty = RouteFault()
            try:
                Deployment(faulty).dispatch("apply", True, UPDATE, maintenance=True)
            except Stop:
                assert faulty.triggered
            else:
                raise AssertionError("Live maintenance unexpectedly accepted the route fault.")
        journal = read_record(JOURNAL)
        assert journal["phase"] in {"STOP_FOR_MANUAL", "APPLYING"}
        assert not journal.get("configuration_restored")
        proof = capture_fail_closed(model, 90 + 2 * kill)
        recovered = cli("rollback", "--to", journal["id"], "--maintenance", "--confirm")
        assert (
            recovered["configuration_restored"]
            and recovered["data_path_restored"]["status"] == "SKIP"
        )
        emit(
            case,
            "Fault stays guarded until explicit maintenance recovery and real traffic proof.",
            {
                "journal": journal["id"],
                "failed_phase": journal["phase"],
                "guard": proof,
                "restored_phase": read_record(JOURNAL)["phase"],
                "flows": pair("udp", 94 + 2 * kill),
            },
        )
        if kill:
            emit("F10", "Interrupted transaction has no WAN private plaintext.", proof)
    assert read_record(ACTIVE)["profile"] == load_profile(PROFILE)


def verify_isolation_failures(model):
    extra = TOPO["sites"][0]["extra_lan"]
    failures = [
        exchange(
            0,
            "udp",
            extra,
            TOPO["sites"][1]["lans"][0],
            sport=PORT + 100,
            count=1,
            expected_failure=True,
        ),
        exchange(
            1,
            "udp",
            TOPO["sites"][1]["lans"][0],
            extra,
            sport=PORT + 101,
            count=1,
            expected_failure=True,
        ),
    ]
    emit("F07", "Declared but unauthorized LAN is refused in both directions.", failures)
    link = model.links[0]
    install = read_record(INSTALLED)
    resources = Resources(HOST, install["token"], (model,))
    ip("link", "del", "dev", link.name)
    try:
        report = cli("status", expect=1)
        assert report["data_path"]["status"] == "SKIP"
        lookup = ip("-4", "route", "get", addr(link.remote_ts[0], 11), allowed=(2,))
        assert lookup.returncode == 2
        proof = capture_fail_closed(model, 102)
        emit(
            "F08 F09",
            "Missing XFRM leaves the protected route blocked and business unverified.",
            {"diagnostics": report["status"], "business": report["data_path"], **proof},
        )
    finally:
        ip("link", "add", "name", link.name, "type", "xfrm", "if_id", str(link.if_id))
        ip("link", "set", "dev", link.name, "alias", resources.alias, "up")
        for spec in sorted(resources.routes):
            if spec[2] == link.name:
                resources.route("add", spec)
    assert cli("status")["status"] == "PASS"
    command(
        "nft",
        "-f",
        "-",
        input=(
            "table ip pr3_foreign {\n"
            "    chain filter {\n"
            "        type filter hook forward priority 15; policy drop;\n"
            "    }\n"
            "}\n"
        ),
    )
    try:
        outside = command("nft", "list", "table", "ip", "pr3_foreign").stdout
        assert_write_stop(model)
        assert command("nft", "list", "table", "ip", "pr3_foreign").stdout == outside
    finally:
        command("nft", "delete", "table", "ip", "pr3_foreign")
    emit("F11", "An external nft DROP stops active writes and is preserved.", "STOP")
    ip("-4", "route", "add", "blackhole", "default", "metric", "49152")
    try:
        assert_write_stop(model)
    finally:
        ip("-4", "route", "del", "blackhole", "default", "metric", "49152")
    emit("F12", "Recorded route baseline drift stops changes.", "STOP")
    assert (
        cli("rollback", "--to", "0" * 32, "--maintenance", "--confirm", expect=1)["decision"]
        == "STOP"
    )
    profile = load_profile(PROFILE)
    key = Path(profile["site_links"][0]["secret_ref"][5:])
    original = key.read_bytes()
    try:
        key.write_bytes(os.urandom(32).hex().encode() + b"\n")
        assert cli("apply", "-c", str(PROFILE), "--confirm", expect=1)["decision"] == "STOP"
    finally:
        key.write_bytes(original)
    emit("F15", "Invalid backup and unexpected PSK drift block changes.", "STOP")


def verify_dpd(model):
    link, other = model.links
    site = TOPO["sites"][0]
    start = time.monotonic()
    ip("link", "set", "wan", "down", ns=site["router"])
    try:
        proof = capture_fail_closed(model, 108)
        remaining = stable(
            model,
            lambda snap: (
                not snap.get(link.name) and snap.get(other.name) and snap.get(other.name).child
            ),
            seconds=190,
        )
        assert remaining.get(other.name).child
    finally:
        ip("link", "set", "wan", "up", ns=site["router"])
    detected = time.monotonic() - start
    report = cli("initiate", "--site", link.site_id, "--confirm")
    emit(
        "S05 S06",
        "One peer loses WAN, DPD removes only its SA, then targeted reconnect restores traffic.",
        {
            "detection_and_isolation_seconds": round(detected, 3),
            "guard": proof,
            "reconnect_journal": report["journal"],
            "flows": pair("udp", 110),
        },
    )


def verify_daemon_restart(model):
    old_pid = HOST.service(UNIT, "MainPID")
    command("systemctl", "restart", UNIT, timeout=90)
    stable(model, lambda snap: len(snap.ikes) == 2 and all(ike.child for ike in snap.ikes))
    assert HOST.service(UNIT, "MainPID") != old_pid
    emit(
        "T13",
        "Restarting the owned daemon restores verified SAs and both business directions.",
        {"flows": pair("udp", 114)},
        action="systemctl restart strongswan",
    )


def before_reboot():
    assert cli("install", "--confirm")["status"] == "PASS"
    environment()
    create_profile()
    install_topology_unit()
    model = manifest()
    prove_topology()
    BASELINE.write_text(json.dumps(baseline_for(model)), encoding="utf-8")
    assert cli("apply", "-c", str(PROFILE), "--confirm")["status"] == "PASS"
    command("systemctl", "start", "ipsecvpn-restore.service")
    connect(model)
    verify_sas(model)
    verify_routes(model)
    verify_traffic(model, first=True)
    verify_noop(model)
    verify_rekeys(model)
    verify_foreign_policy(model)
    verify_maintenance(model)
    verify_mtu(model)
    verify_isolation_failures(model)
    verify_dpd(model)
    verify_daemon_restart(model)
    assert baseline_for(model) == json.loads(BASELINE.read_text(encoding="utf-8"))


def after_reboot():
    environment()
    model = manifest()
    command("systemctl", "is-active", "ipsecvpn-guard.service", "ipsecvpn-restore.service")
    result = cli("status")
    assert result["status"] == "PASS", result
    receipts = verify_traffic(model, first=False)
    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
    assert baseline_for(model) == baseline
    emit(
        "T13",
        "VM reboot restores guard, routes, owned SAs and real bidirectional LAN traffic.",
        {"baseline": baseline, "flows": receipts},
        action="actual VM reboot; verify new SSH session, restored services and UDP/TCP",
    )
    removed = cli("uninstall", "--maintenance", "--confirm")
    assert not HOST.command("Empty SAD", "ip", "xfrm", "state", "list", "nokeys").strip()
    assert not HOST.command("Empty SPD", "ip", "xfrm", "policy", "list", "nosock").strip()
    assert Resources(HOST, "uninstalled", ()).baseline() == baseline
    emit(
        "S09",
        "Live maintenance uninstall drains only owned SAs and restores the foreign baseline.",
        {"journal": removed["backup_id"], "empty_sad_spd": True, "baseline": baseline},
    )
    if any(json.loads(line)["status"] == "FAIL" for line in SUMMARY.read_text().splitlines()):
        raise RuntimeError("One or more executed data-plane observations failed.")


if __name__ == "__main__":
    require_lab()
    if sys.argv[1] == "crash":
        Deployment(RouteFault(kill=True)).dispatch("apply", True, UPDATE, maintenance=True)
        sys.exit(2)
    try:
        {"before-reboot": before_reboot, "after-reboot": after_reboot}[sys.argv[1]]()
    except (RuntimeError, OSError, AssertionError, ValueError, KeyError) as exc:
        emit("LAB", "Executed three-node assertions pass.", str(exc), status="FAIL")
        raise
