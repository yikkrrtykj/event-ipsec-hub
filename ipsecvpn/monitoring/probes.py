"""Verify fresh receipts from an authorized independent LAN probe runner."""

import math
import time
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path

from ..secureio import Stop, read_record
from .model import PROBE_FILE, State


def generation(live, manifest):
    return {
        link.site_id: [
            ike.unique_id,
            ike.child.unique_id,
            ike.child.inbound.spi,
            ike.child.outbound.spi,
        ]
        for link in manifest.links
        if (ike := live.get(link.name)) and ike.child
    }


def in_network(address, cidrs):
    return any(IPv4Address(address) in IPv4Network(cidr) for cidr in cidrs)


def assess(paths, settings, install, manifest, live):
    if not settings.probe_enabled:
        return paths, State.UNKNOWN
    unknown = [{**row, "reason_code": "PATH_UNVERIFIED"} for row in paths]
    try:
        proof = read_record(Path(PROBE_FILE))
        if not proof:
            return unknown, State.UNKNOWN
        now = time.time()
        age = now - proof["at"]
        if not math.isfinite(age) or not 0 <= age < settings.probe_ttl:
            return [{**row, "reason_code": "STALE"} for row in paths], State.UNKNOWN
        links = {link.site_id: link for link in manifest.links}
        current = generation(live, manifest)
        if (
            len(current) != 2
            or proof["owner"] != install["token"]
            or proof["event_id"] != manifest.event_id
            or proof["generations"] != current
            or len(proof["directions"]) != 2
            or not 0 <= proof["at"] - proof["started"] <= 12
        ):
            return unknown, State.UNKNOWN
        directions = {(row["src_site_id"], row["dst_site_id"]): row for row in proof["directions"]}
        result = []
        for path in unknown:
            source, target = path["src_site_id"], path["dst_site_id"]
            evidence = directions[source, target]
            if not (
                in_network(evidence["source"], links[source].remote_ts)
                and in_network(evidence["target"], links[target].remote_ts)
                and evidence["bound"]
            ):
                result.append(path)
                continue
            sent, samples = evidence["sent"], sorted(evidence["rtts"])
            received = len(samples)
            if (
                not 1 <= sent <= 4
                or received > sent
                or any(not math.isfinite(rtt) or not 0 < rtt <= 2 for rtt in samples)
            ):
                return unknown, State.UNKNOWN
            state = State.UP if received else State.DOWN
            result.append(
                {
                    **path,
                    "state": state,
                    "at": proof["at"],
                    "sent": sent,
                    "loss": (sent - received) / sent,
                    "reason_code": "READY" if received else "PATH_DOWN",
                    **(
                        {
                            "rtt": evidence["rtts"][-1],
                            "p95": samples[math.ceil(0.95 * received) - 1],
                        }
                        if received
                        else {}
                    ),
                }
            )
    except (Stop, OSError, KeyError, ValueError, TypeError, OverflowError):
        return unknown, State.UNKNOWN
    states = {row["state"] for row in result}
    business = (
        State.DOWN
        if State.DOWN in states
        else (State.UP if states == {State.UP} else State.UNKNOWN)
    )
    return result, business
