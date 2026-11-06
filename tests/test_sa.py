from dataclasses import replace
from pathlib import Path

import pytest

from ipsecvpn.profile import load_profile
from ipsecvpn.renderer import build_manifest
from ipsecvpn.sa import (
    Policy,
    SAError,
    State,
    correlate,
    kernel_policies,
    kernel_states,
    parse_vici,
)


@pytest.fixture
def observed():
    manifest = build_manifest(load_profile(Path("config/event.example.yaml")))
    link = manifest.links[0]
    child = {
        "name": link.child.encode(),
        "uniqueid": b"11",
        "reqid": b"7",
        "state": b"INSTALLED",
        "protocol": b"ESP",
        "mode": b"TUNNEL",
        "spi-in": b"11223344",
        "spi-out": b"55667788",
        "if-id-in": f"{link.if_id:08x}".encode(),
        "if-id-out": f"{link.if_id:08x}".encode(),
        "local-ts": [net.encode() for net in link.local_ts],
        "remote-ts": [net.encode() for net in link.remote_ts],
        "encr-alg": b"AES_CBC",
        "encr-keysize": b"256",
        "integ-alg": b"HMAC_SHA2_256_128",
        **dict.fromkeys(("bytes-in", "bytes-out", "packets-in", "packets-out"), b"0"),
    }
    event = {
        link.name: {
            "version": b"2",
            "uniqueid": b"1",
            "state": b"ESTABLISHED",
            "local-host": link.source.encode(),
            "remote-host": link.peer.encode(),
            "local-id": link.local_id.encode(),
            "remote-id": link.remote_id.encode(),
            "initiator-spi": b"1122334455667788",
            "responder-spi": b"8877665544332211",
            "encr-alg": b"AES_CBC",
            "encr-keysize": b"256",
            "integ-alg": b"HMAC_SHA2_256_128",
            "prf-alg": b"PRF_HMAC_SHA2_256",
            "dh-group": b"MODP_2048",
            "child-sas": {link.child: child},
        }
    }
    states = [
        State(link.peer, link.source, 0x11223344, 7, link.if_id),
        State(link.source, link.peer, 0x55667788, 7, link.if_id),
    ]
    policies = [
        (Policy(source, target, direction, state.source, state.destination, 7, link.if_id), None)
        for local in link.local_ts
        for remote in link.remote_ts
        for source, target, direction, state in (
            (local, remote, "out", states[1]),
            (remote, local, "in", states[0]),
            (remote, local, "fwd", states[0]),
        )
    ]
    return manifest, link, event, child, states, policies


def test_vici_and_kernel_must_agree(observed):
    manifest, _, event, _, states, policies = observed
    snapshot = parse_vici([event], manifest)
    correlate(snapshot, manifest, states, policies)
    with pytest.raises(SAError, match="state does not map"):
        correlate(snapshot, manifest, [*states, replace(states[0], spi=8)], policies)
    with pytest.raises(SAError, match="policy does not map"):
        correlate(snapshot, manifest, states, policies[:-1])
    with pytest.raises(SAError, match="outside the active manifest"):
        parse_vici([{"foreign": next(iter(event.values()))}], manifest)


def test_matching_name_cannot_authorize_narrowed_child(observed):
    manifest, _, event, child, _, _ = observed
    child["remote-ts"] = [b"10.99.99.0/24"]
    with pytest.raises(SAError, match="CHILD selector"):
        parse_vici([event], manifest)


def test_unconfirmed_rekey_overlap_is_not_a_write_snapshot(observed):
    manifest, _, event, _, _, _ = observed
    with pytest.raises(SAError, match="Multiple IKE generations"):
        parse_vici([event, event], manifest)


def test_nokeys_oneline_iproute2_inventory(observed):
    _, _, _, _, states, policies = observed
    assert (
        kernel_states(
            "\n".join(
                f"src {row.source} dst {row.destination} \\ proto esp spi {row.spi:#x} reqid 7"
                f" mode tunnel \\ replay-window 32 \\ if_id {row.if_id:#x} \\"
                for row in states
            )
        )
        == states
    )
    assert (
        kernel_policies(
            "\n".join(
                f"src {row.source} dst {row.destination} \\ dir {row.direction} priority 380160"
                f" ptype main \\ tmpl src {row.outer_source} dst {row.outer_destination}"
                f" \\ proto esp reqid 7 mode tunnel \\ if_id {row.if_id:#x} \\"
                for row, _ in policies
            )
        )
        == policies
    )
