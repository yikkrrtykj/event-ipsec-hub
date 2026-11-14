"""A bounded scheduler and a loopback-only Prometheus HTTP endpoint."""

import sys
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Lock

from ..secureio import Stop, read_record
from .collector import runtime_settings
from .model import SNAPSHOT, STAGES, State, unavailable

PREFIX = "event_ipsec_"


class Cache:
    def __init__(self, ttl, probe_ttl):
        self.ttl = ttl
        self.probe_ttl = probe_ttl
        self.lock = Lock()
        self.result = unavailable("NO_SAMPLE")
        self.last_success = None
        self.sample_clock = None
        self.scope = {}
        self.generations = {}
        self.changes = {}

    def publish(self, result):
        with self.lock:
            if result["collector_valid"]:
                scope = {
                    "event_id": result["event_id"],
                    "hub_id": result["hub_id"],
                }
                if scope != self.scope:
                    self.generations.clear()
                    self.changes.clear()
                self.scope = scope
                self.last_success = result["collected_at"]
                self.sample_clock = time.monotonic()
                for row in result["sites"]:
                    site = row["site_id"]
                    changes = self.changes.setdefault(site, deque(maxlen=128))
                    while changes and changes[0] < self.sample_clock - 600:
                        changes.popleft()
                    generation = row.pop("generation", None)
                    previous = self.generations.pop(site, None)
                    if generation is not None:
                        self.generations[site] = generation
                        if previous and generation != previous:
                            changes.append(self.sample_clock)
                        row["rekeys"] = len(changes)
            else:
                self.generations.clear()
            self.result = result

    def record(self):
        with self.lock:
            return {
                **self.scope,
                **self.result,
                "last_success": self.last_success,
                "sample_clock": self.sample_clock,
            }

    def view(self):
        return age_snapshot(self.record(), self.ttl, self.probe_ttl)


def age_snapshot(record, ttl, probe_ttl):
    result = dict(record)
    stamp = result.pop("sample_clock", None)
    now = time.monotonic()
    age = now - stamp if stamp is not None else None
    if result["collector_valid"] and (stamp is None or age < 0 or now >= stamp + ttl):
        result.update(unavailable("STALE"))
    elif any(
        "at" in row and not 0 <= time.time() - row["at"] < probe_ttl for row in result["paths"]
    ):
        result["business"] = State.UNKNOWN
        result["paths"] = [
            {
                "src_site_id": row["src_site_id"],
                "dst_site_id": row["dst_site_id"],
                "state": State.UNKNOWN,
                "reason_code": "STALE",
            }
            for row in result["paths"]
        ]
    return {**result, "age": age}


def current_snapshot(settings):
    try:
        record = read_record(SNAPSHOT)
        if record is None:
            return {**unavailable("NO_SAMPLE"), "last_success": None, "age": None}
        return age_snapshot(record, settings.ttl, settings.probe_ttl)
    except (Stop, OSError, KeyError, TypeError, ValueError):
        return {**unavailable("COLLECTOR_ERROR", stage="WORKER"), "last_success": None, "age": None}


def metrics(snapshot):
    output = []
    dimensions = {label: snapshot[label] for label in ("event_id", "hub_id") if label in snapshot}

    def family(name, description, rows):
        name = PREFIX + name
        output.extend((f"# HELP {name} {description}", f"# TYPE {name} gauge"))
        for labels, value in rows:
            label_text = ",".join(f'{key}="{item}"' for key, item in labels.items())
            suffix = "{" + label_text + "}" if label_text else ""
            output.append(f"{name}{suffix} {value}")

    family(
        "collector_healthy",
        "Whether the current ownership snapshot is valid.",
        [({}, int(snapshot["collector_valid"]))],
    )
    family(
        "observation_reason",
        "Bounded current observation reason.",
        [({**dimensions, "reason_code": snapshot["reason_code"]}, 1)],
    )
    if snapshot.get("stage") in STAGES:
        family(
            "observation_stage",
            "Bounded stage of the failed observation.",
            [({**dimensions, "stage": snapshot["stage"]}, 1)],
        )
    for name, key in (
        ("collector_last_success_timestamp_seconds", "last_success"),
        ("snapshot_age_seconds", "age"),
        ("daemon_state", "daemon"),
        ("profile_active", "profile_active"),
        ("business_state", "business"),
    ):
        value = snapshot[key]
        if value is not None:
            if isinstance(value, int):
                value = int(value)
            family(name, "-1 is unknown for three-state observations.", [(dimensions, value)])
    for name, key in (
        ("ike_state", "ike"),
        ("child_state", "child"),
        ("kernel_verified", "kernel"),
        ("protected_route_ok", "protected_route"),
    ):
        family(
            f"site_{name}",
            "Verified site observation, -1 unknown.",
            [
                ({**dimensions, "site_id": row["site_id"]}, int(row[key]))
                for row in snapshot["sites"]
            ],
        )
    for index, name in enumerate(("rx_bytes", "tx_bytes", "rx_packets", "tx_packets")):
        family(
            f"site_sa_{name}",
            "Current CHILD SA observation. Resets with a new generation.",
            [
                ({**dimensions, "site_id": row["site_id"]}, row["counts"][index])
                for row in snapshot["sites"]
                if "counts" in row
            ],
        )
    family(
        "site_rekeys_in_window",
        "Observed generation changes in the last ten minutes.",
        [
            ({**dimensions, "site_id": row["site_id"]}, row["rekeys"])
            for row in snapshot["sites"]
            if "rekeys" in row
        ],
    )
    paths = [
        ({**dimensions, "src_site_id": row["src_site_id"], "dst_site_id": row["dst_site_id"]}, row)
        for row in snapshot["paths"]
    ]
    family(
        "path_state",
        "Verified primary UDP path, -1 unknown.",
        [(labels, int(row["state"])) for labels, row in paths],
    )
    family(
        "path_reason",
        "Bounded direction observation reason.",
        [({**labels, "reason_code": row["reason_code"]}, 1) for labels, row in paths],
    )
    for name, key in (
        ("last_probe_timestamp_seconds", "at"),
        ("rtt_seconds", "rtt"),
        ("rtt_p95_seconds", "p95"),
        ("probe_loss_ratio", "loss"),
        ("probe_sent_packets", "sent"),
    ):
        family(
            f"path_{name}",
            "Current verified UDP probe window.",
            [(labels, row[key]) for labels, row in paths if key in row],
        )
    return ("\n".join(output) + "\n").encode("ascii")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):
        if self.path == "/healthz":
            self.reply(200, b"ok\n")
        elif self.path == "/metrics":
            snapshot = current_snapshot(self.server.settings)
            self.reply(200, metrics(snapshot), "text/plain; version=0.0.4")
        else:
            self.reply(404, b"not found\n")

    def reply(self, status, content, kind="text/plain"):
        self.send_response(status)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)


class LoopbackServer(HTTPServer):
    def __init__(self, port, handler):
        super().__init__(("127.0.0.1", port), handler)

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(1.0)
        return connection, address

    def handle_error(self, _request, _address):
        pass


def serve():
    from .service import notify_ready

    settings = runtime_settings(endpoint_only=True)
    if not settings.enabled:
        return
    with LoopbackServer(settings.port, Handler) as server:
        server.settings = settings
        notify_ready()
        server.serve_forever()


if __name__ == "__main__":
    from ..secureio import Stop

    try:
        serve()
    except (Stop, OSError, KeyError, ValueError):
        sys.exit("STOP: exporter startup failed.")
