"""Real IPv4 route and packet simulation, confined to a disposable Ubuntu QEMU VM."""

import json
import select
import socket
import subprocess
import sys
import time
from contextlib import ExitStack
from datetime import UTC, datetime
from itertools import product
from pathlib import Path

from ipsecvpn.failover import PathProof, observe
from ipsecvpn.host import Host

ROOT = Path(__file__).resolve().parent
EVIDENCE = Path("/var/tmp/ipsecvpn-pr5-simulation.jsonl")
SITES = ("pr5-a", "pr5-b")
TRANSIT = {"primary": "pr5-primary", "backup": "pr5-backup"}
WAN = "pr5-wan"
LAN = {
    SITES[0]: ("10.175.1.9", "10.175.2.9"),
    SITES[1]: ("10.175.3.9", "10.175.4.9"),
}
REMOTE = dict(zip(SITES, SITES[::-1], strict=True))
WAN_TARGET = "192.0.2.27"
METRIC = {"primary": "20", "backup": "60"}
LINK_NUMBER = {"primary": 1, "backup": 2, "wan": 3}


def run(*args, check=True):
    return subprocess.run(args, check=check, text=True, capture_output=True, timeout=8)


def ns(node, *args):
    return ("ip", "netns", "exec", node, *args)


def ip(node, *args, check=True):
    return run("ip", "-n", node, *args, check=check)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def network(address):
    return address.rsplit(".", 1)[0] + ".0/24"


def gateway(site, path):
    return f"10.176.{3 * SITES.index(site) + LINK_NUMBER[path]}.1"


def connect(site, peer, path):
    device = "to-a" if site == SITES[0] else "to-b"
    local = gateway(site, path).removesuffix(".1") + ".2"
    ip(site, "link", "add", path, "type", "veth", "peer", "name", device, "netns", peer)
    for node, iface, address in ((site, path, local), (peer, device, gateway(site, path))):
        ip(node, "addr", "add", address + "/30", "dev", iface)
        ip(node, "link", "set", iface, "up")
    return device, local


def change_route(site, path, enabled):
    changed = 0
    for address in LAN[REMOTE[site]]:
        destination = network(address)
        scope = ("dev", path, "metric", METRIC[path])
        if enabled:
            ip(site, "route", "replace", destination, "via", gateway(site, path), *scope)
        else:
            rows = json.loads(ip(site, "-4", "-j", "route", "show", "exact", destination).stdout)
            current = [row for row in rows if row.get("metric") == int(METRIC[path])]
            if not current:
                continue
            require(
                len(current) == 1
                and current[0].get("dev") == path
                and current[0].get("gateway") == gateway(site, path),
                "An unexpected route uses the fixture path's metric.",
            )
            ip(site, "route", "del", destination, *scope)
        changed += 1
    return changed


def primary_carriers():
    return tuple(
        "LOWER_UP" in json.loads(ip(site, "-j", "link", "show", "primary").stdout)[0]["flags"]
        for site in SITES
    )


def add_counter(node, name):
    run(*ns(node, "nft", "add", "counter", "ip", "pr5", name))


def setup(stack):
    for node in (*SITES, *TRANSIT.values(), WAN):
        run("ip", "netns", "add", node)
        stack.callback(run, "ip", "netns", "del", node)
        ip(node, "link", "set", "lo", "up")
        run(*ns(node, "sysctl", "-qw", "net.ipv4.conf.all.rp_filter=0"))
        run(*ns(node, "sysctl", "-qw", "net.ipv4.conf.default.rp_filter=0"))
    for path, node in TRANSIT.items():
        run(*ns(node, "sysctl", "-qw", "net.ipv4.ip_forward=1"))
        run(*ns(node, "nft", "add", "table", "ip", "pr5"))
        run(
            *ns(
                node,
                "nft",
                "add",
                "chain",
                "ip",
                "pr5",
                "count",
                "{ type filter hook forward priority 0; policy accept; }",
            )
        )
        for site in SITES:
            iface, next_hop = connect(site, node, path)
            add_counter(node, iface)
            run(
                *ns(
                    node,
                    "nft",
                    "add",
                    "rule",
                    "ip",
                    "pr5",
                    "count",
                    "iifname",
                    f'"{iface}"',
                    "counter",
                    "name",
                    iface,
                )
            )
            for address in LAN[site]:
                ip(node, "route", "add", network(address), "via", next_hop, "dev", iface)
    ip(WAN, "addr", "add", WAN_TARGET + "/32", "dev", "lo")
    run(*ns(WAN, "nft", "add", "table", "ip", "pr5"))
    run(
        *ns(
            WAN,
            "nft",
            "add",
            "chain",
            "ip",
            "pr5",
            "count",
            "{ type filter hook prerouting priority 0; policy accept; }",
        )
    )
    add_counter(WAN, "control")
    add_counter(WAN, "leak")
    run(
        *ns(
            WAN,
            "nft",
            "add",
            "rule",
            "ip",
            "pr5",
            "count",
            "ip",
            "daddr",
            WAN_TARGET,
            "counter",
            "name",
            "control",
        )
    )
    run(
        *ns(
            WAN,
            "nft",
            "add",
            "rule",
            "ip",
            "pr5",
            "count",
            "ip",
            "daddr",
            "{ " + ", ".join(network(address) for row in LAN.values() for address in row) + " }",
            "counter",
            "name",
            "leak",
        )
    )
    for site in SITES:
        connect(site, WAN, "wan")
        ip(site, "route", "add", "default", "via", gateway(site, "wan"), "dev", "wan")
        for address in LAN[site]:
            ip(site, "addr", "add", address + "/32", "dev", "lo")
        for address in LAN[REMOTE[site]]:
            ip(site, "route", "add", "blackhole", network(address), "metric", "32000")
        change_route(site, "backup", True)


def counter(node, name):
    rows = run(*ns(node, "nft", "-j", "list", "counter", "ip", "pr5", name)).stdout
    return next(
        row["counter"]["packets"] for row in json.loads(rows)["nftables"] if "counter" in row
    )


def counters():
    return {path: [counter(node, "to-a"), counter(node, "to-b")] for path, node in TRANSIT.items()}


def paths():
    selections = []
    for site in SITES:
        selected = set()
        for source, target in product(LAN[site], LAN[REMOTE[site]]):
            row = ip(site, "-4", "-j", "route", "get", target, "from", source, check=False)
            if row.returncode == 0:
                selected.add(json.loads(row.stdout)[0]["dev"])
                continue
            exact = ip(site, "-4", "-j", "route", "show", "exact", network(target))
            require(
                [item.get("type") for item in json.loads(exact.stdout)] == ["blackhole"],
                "An unreachable lookup has no exclusive blackhole route.",
            )
            selected.add("unavailable")
        require(
            len(selected) == 1 and selected <= {"primary", "backup", "unavailable"},
            "A site's exact CIDR lookups selected mixed or non-VPN routes.",
        )
        selections.append(selected.pop())
    return tuple(selections)


def traffic(node, *args):
    return ns(node, sys.executable, str(ROOT / "traffic.py"), *args)


def exchange(protocol, site, source, target, port):
    with subprocess.Popen(
        traffic(REMOTE[site], "server", protocol, target, port, "1"),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as listener:
        try:
            ready, _, _ = select.select([listener.stdout], [], [], 6)
            require(ready and listener.stdout.readline().strip() == "READY", "Listener not ready.")
            reply = run(
                *traffic(
                    site,
                    "client",
                    protocol,
                    source,
                    "0",
                    target,
                    port,
                    "1",
                    "256",
                    f"pr5-{port}",
                    "default",
                    "0",
                )
            )
            received, _ = listener.communicate(timeout=6)
            require(listener.returncode == 0, "Traffic receiver failed.")
        finally:
            if listener.poll() is None:
                listener.kill()
                listener.wait(timeout=3)
    sent = json.loads(reply.stdout)
    require(
        sent == json.loads(received) and sent[0]["source"][0] == source,
        "Echo, exact source or payload hash changed.",
    )
    return sent[0]["sha256"]


def prove(path):
    selections = paths()
    require(selections == (path, path), "Both sides must select the tested route.")
    start = counters()
    receipts = {"udp": [], "tcp": []}
    for site, protocol in product(SITES, receipts):
        for source, target in product(LAN[site], LAN[REMOTE[site]]):
            port = str(41000 + sum(len(rows) for rows in receipts.values()))
            receipts[protocol].append(exchange(protocol, site, source, target, port))
    end = counters()
    deltas = {name: [b - a for a, b in zip(start[name], end[name], strict=True)] for name in end}
    require(
        all(count > 0 for count in deltas[path]), "Selected transit did not see both directions."
    )
    require(
        all(delta == [0, 0] for name, delta in deltas.items() if name != path),
        "Traffic escaped to the alternate transit.",
    )
    proof = PathProof(path, len(receipts["udp"]) == 8, len(receipts["tcp"]) == 8, True, True)
    return proof, {"receipt_sha256": receipts, "path_counter_deltas": deltas}


def report(case, action, expected, observed, status="PASS"):
    receipt = {
        "case": case,
        "time_utc": datetime.now(UTC).isoformat(timespec="seconds"),
        "head_sha": (ROOT / "head-sha").read_text(encoding="utf-8").strip(),
        "environment": "SIMULATED / Ubuntu 24.04 QEMU guest network namespaces",
        "action": action,
        "expected": expected,
        "observed": observed,
        "status": status,
        "proof_refs": ["pr5-lab/verify_failover.py", "pr3-lab/traffic.py"],
    }
    with EVIDENCE.open("a", encoding="utf-8") as output:
        output.write(json.dumps(receipt, sort_keys=True) + "\n")


def scenario():
    case = "B06"
    action = "Isolate a backup-only path"
    expected = "Verified source-preserving bidirectional UDP/TCP over backup only."
    try:
        backup, traffic_proof = prove("backup")
        decision = observe(*paths(), backup)
        require(decision["state"] == "BACKUP_VERIFIED", expected)
        report(case, action, expected, {**decision, **traffic_proof})

        case = "B07"
        action = "Bring up primary on both sites and then lose Site A primary"
        expected = "Site A changes to backup and Site B still selects primary."
        for site in SITES:
            change_route(site, "primary", True)
        primary, traffic_proof = prove("primary")
        require(
            observe(*paths(), primary)["state"] == "PRIMARY_VERIFIED", "Primary baseline failed."
        )
        ip(SITES[0], "link", "set", "primary", "down")
        withdrawn = change_route(SITES[0], "primary", False)
        require(paths() == ("backup", "primary"), expected)
        report(
            case,
            action,
            expected,
            {
                "selected_paths": paths(),
                "emulated_controller_withdrawals": withdrawn,
                "missing_after_link_down": len(LAN[SITES[1]]) - withdrawn,
                "before": traffic_proof,
            },
        )

        case = "B08"
        action = "Evaluate the single-side route selection before peer changes"
        expected = "Reject asymmetric traffic even if the preceding primary probe was good."
        decision = observe(*paths(), primary)
        require(
            decision["state"] == "ASYMMETRIC_STOP" and decision["data_path"] == "SKIP", expected
        )
        report(case, action, expected, decision)

        case = "B10"
        action = "Coordinate the Site B change to backup"
        expected = "Every authorized synthetic pair verifies UDP/TCP using only backup."
        ip(SITES[1], "link", "set", "primary", "down")
        change_route(SITES[1], "primary", False)
        backup, traffic_proof = prove("backup")
        decision = observe(*paths(), backup)
        require(decision["status"] == "PASS", expected)
        report(case, action, expected, {**decision, **traffic_proof})

        case = "B11"
        action = "Restore only the first site's primary interface"
        expected = "Both still select backup, with RECOVERY_PENDING."
        ip(SITES[0], "link", "set", "primary", "up")
        backup, traffic_proof = prove("backup")
        candidates = primary_carriers()
        require(candidates == (True, False), expected)
        decision = observe(*paths(), backup, primary_ready=candidates)
        require(decision["state"] == "RECOVERY_PENDING", expected)
        report(
            case, action, expected, {**decision, **traffic_proof, "primary_carriers": candidates}
        )

        case = "B13"
        action = "Flap the first primary interface and withhold the recovery hold"
        expected = "No route switch during flap or during unconfirmed convergence."
        for link_state in ("down", "up", "down", "up"):
            ip(SITES[0], "link", "set", "primary", link_state)
            require(paths() == ("backup", "backup"), expected)
        ip(SITES[1], "link", "set", "primary", "up")
        candidates = primary_carriers()
        require(candidates == (True, True), "Both synthetic candidate links must be up.")
        backup, traffic_proof = prove("backup")
        decision = observe(*paths(), backup, primary_ready=candidates, hold_met=False)
        require(decision["state"] == "RECOVERY_PENDING", expected)
        require(
            observe(*paths(), backup, primary_ready=candidates, hold_met=True)["state"]
            == "MANUAL_CUTOVER_REQUIRED",
            "A confirmed hold must still require a manual change.",
        )
        report(
            case,
            action,
            expected,
            {
                **decision,
                **traffic_proof,
                "link_transitions": 4,
                "primary_carriers": candidates,
            },
        )

        case = "B12"
        action = "Restore both sites' primary routes as an explicit lab operation"
        expected = "Consistent primary selection and fresh source-preserving UDP/TCP."
        start = time.monotonic()
        for site in SITES:
            change_route(site, "primary", True)
        primary, traffic_proof = prove("primary")
        decision = observe(*paths(), primary)
        require(decision["state"] == "PRIMARY_VERIFIED", expected)
        report(
            case,
            action,
            expected,
            {
                **decision,
                **traffic_proof,
                "seconds_until_all_receipts": round(time.monotonic() - start, 3),
            },
        )

        case = "B09"
        action = "Withdraw all protected routes, keeping the simulated WAN defaults"
        expected = "Protected flows stop at blackhole routes with zero WAN plaintext packets."
        for site in SITES:
            for path in TRANSIT:
                change_route(site, path, False)
        decision = observe(*paths())
        require(decision["state"] == "BOTH_UNAVAILABLE", expected)
        before = counter(WAN, "control")
        leak_before = counter(WAN, "leak")
        for site in SITES:
            run(
                *ns(
                    site,
                    sys.executable,
                    "-c",
                    "import socket,sys; s=socket.socket(type=socket.SOCK_DGRAM); "
                    "s.sendto(b'wan-control', (sys.argv[1], 41901))",
                    WAN_TARGET,
                )
            )
            for target in LAN[REMOTE[site]]:
                failed = run(
                    *traffic(
                        site,
                        "client",
                        "udp",
                        LAN[site][0],
                        "0",
                        target,
                        "41900",
                        "1",
                        "256",
                        "pr5-blackhole",
                        "default",
                        "0",
                    ),
                    check=False,
                )
                require(failed.returncode != 0, "A protected probe unexpectedly received an echo.")
        controls = counter(WAN, "control") - before
        leaks = counter(WAN, "leak") - leak_before
        require(controls == len(SITES) and leaks == 0, expected)
        report(
            case,
            action,
            expected,
            {**decision, "wan_control_packets": controls, "protected_wan_packets": leaks},
        )
    except (RuntimeError, subprocess.SubprocessError, OSError, ValueError) as exc:
        detail = {"error": str(exc)}
        if isinstance(exc, subprocess.CalledProcessError) and exc.stderr:
            detail["stderr"] = exc.stderr.strip()[:240]
        report(case, action, expected, detail, "FAIL")
        raise


def baseline(host):
    return host.baseline(*host.routing(), host.nft(), set(), set())


def main():
    host = Host()
    host.probe()
    require(socket.gethostname() == "ipsecvpn-pr5-lab", "STOP: unexpected disposable VM name.")
    before = baseline(host)
    try:
        with ExitStack() as stack:
            setup(stack)
            scenario()
    finally:
        after = baseline(host)
        unchanged = before == after
        report(
            "F12",
            "Compare guest baseline before and after namespace cleanup",
            "SSH, defaults, non-project routes, firewall and host sysctls are unchanged.",
            {"before": before, "after": after},
            "PASS" if unchanged else "FAIL",
        )
        require(unchanged, "Guest baseline changed.")
    report(
        "B14",
        "Exclude real vendor paths from the isolated simulation",
        "Production automatic Track is outside the authorized test environment.",
        {"vendor_devices_used": False, "automatic_vendor_cutover": "SKIP"},
        "SKIP",
    )


if __name__ == "__main__":
    main()
