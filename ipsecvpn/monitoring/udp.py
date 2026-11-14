"""Authenticated, rate-limited echo helper for explicitly authorized LAN fixtures."""

import argparse
import hashlib
import hmac
import secrets
import socket
import time
from collections import deque
from ipaddress import IPv4Address
from pathlib import Path

from ..secureio import Stop, read_file
from .collector import ReadOnlyHost, authorize_endpoint

FRAME_BYTES = 103


def frame(key, kind, nonce, sequence, timestamp):
    content = f"{kind}/{nonce}/{sequence:02d}/{timestamp:016d}".encode("ascii")
    return content + b"/" + hmac.digest(key, content, "sha256").hex().encode("ascii")


def parse(packet, key, kind, now=None):
    now = time.time() if now is None else now
    if len(packet) != FRAME_BYTES:
        return None
    try:
        actual, nonce, sequence, timestamp, _ = packet.decode("ascii").split("/")
        timestamp, sequence = int(timestamp), int(sequence)
        if (
            actual != kind
            or len(bytes.fromhex(nonce)) != 8
            or not 0 <= sequence < 4
            or abs(now - timestamp / 1000) > 5
            or not hmac.compare_digest(packet, frame(key, kind, nonce, sequence, timestamp))
        ):
            return None
    except (UnicodeError, ValueError):
        return None
    return nonce, sequence, timestamp


class Responder:
    def __init__(self, key, peer):
        self.key = key
        self.peer = peer
        self.seen = {}
        self.sent = deque()

    def answer(self, source, packet, now):
        if source != self.peer:
            return None
        request = parse(packet, self.key, "q", now)
        if not request:
            return None
        while self.sent and self.sent[0] <= now - 1:
            self.sent.popleft()
        self.seen = {item: until for item, until in self.seen.items() if until > now}
        if request in self.seen or len(self.sent) >= 8 or len(self.seen) >= 80:
            return None
        self.seen[request] = now + 10
        self.sent.append(now)
        return frame(self.key, "r", *request)


def endpoint(address, port):
    parsed = IPv4Address(address)
    if (
        parsed.is_unspecified
        or parsed.is_loopback
        or parsed.is_multicast
        or parsed.is_reserved
        or not 1024 <= port < 65535
    ):
        raise Stop("A UDP test endpoint must be an explicit LAN IPv4 address and port.")
    return str(parsed), port


def respond(key, local, peer, *, seconds):
    responder = Responder(key, peer)
    deadline = time.monotonic() + seconds
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(local)
        print("READY", flush=True)
        while time.monotonic() < deadline:
            sock.settimeout(min(0.5, max(0.001, deadline - time.monotonic())))
            try:
                packet, source = sock.recvfrom(FRAME_BYTES + 1)
            except TimeoutError:
                continue
            answer = responder.answer(source, packet, time.time())
            if answer:
                sock.sendto(answer, source)


def probe(key, local, peer, *, count=3, timeout=0.5):
    if not 1 <= count <= 4 or not 0.1 <= timeout <= 2:
        raise Stop("UDP test window exceeds its configured safety limits.")
    nonce = secrets.token_hex(8)
    receipts = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(local)
        sock.connect(peer)
        for sequence in range(count):
            timestamp = int(time.time() * 1000)
            packet = frame(key, "q", nonce, sequence, timestamp)
            expected = frame(key, "r", nonce, sequence, timestamp)
            start = time.monotonic()
            sock.send(packet)
            deadline = start + timeout
            rtt = None
            while time.monotonic() < deadline:
                sock.settimeout(max(0.001, deadline - time.monotonic()))
                try:
                    response = sock.recv(FRAME_BYTES + 1)
                except (TimeoutError, ConnectionRefusedError):
                    break
                if hmac.compare_digest(response, expected):
                    rtt = time.monotonic() - start
                    break
            receipts.append(
                {
                    "request_sha256": hashlib.sha256(packet).hexdigest(),
                    "reply_sha256": hashlib.sha256(expected).hexdigest(),
                    "rtt": rtt,
                }
            )
            time.sleep(max(0, start + 0.125 - time.monotonic()))
    return receipts


def main():
    import json

    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("probe", "respond"))
    parser.add_argument("source")
    parser.add_argument("source_port", type=int)
    parser.add_argument("target")
    parser.add_argument("target_port", type=int)
    parser.add_argument("--count", type=int, default=3)
    parser.add_argument("--timeout", type=float, default=0.5)
    args = parser.parse_args()
    try:
        authorize_endpoint(ReadOnlyHost())
        key = read_file(Path("/etc/ipsecvpn/secrets/monitor-probe"), limit=32, parent_mode=0o700)
        if len(key) != 32:
            raise Stop("A dedicated 32-byte UDP test key is required.")
        local = endpoint(args.source, args.source_port)
        peer = endpoint(args.target, args.target_port)
        if args.operation == "respond":
            respond(key, local, peer, seconds=30)
        else:
            print(json.dumps(probe(key, local, peer, count=args.count, timeout=args.timeout)))
    except (Stop, OSError, ValueError):
        raise SystemExit("STOP: UDP fixture could not complete.") from None


if __name__ == "__main__":
    main()
