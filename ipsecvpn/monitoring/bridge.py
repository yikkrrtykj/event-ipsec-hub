"""Authenticated Alertmanager receiver and bounded Feishu delivery in the lab."""

import base64
import hmac
import http.client
import json
import re
import time
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo

from ..secureio import Stop, read_file, read_record, write_record
from .collector import runtime_settings
from .exporter import Handler, LoopbackServer
from .model import ID
from .service import DIRECTORY, notify_ready

CONFIG = Path("/etc/ipsecvpn/monitor-bridge.json")
STATE = DIRECTORY / "delivery.json"
MAX_BODY = 32 * 1024
ALERTS = {
    "HubExporterDown": ("collector_healthy", 1),
    "HubCollectorStale": ("collector_healthy", 1),
    "IpsecOwnershipUnknown": ("collector_healthy", 1),
    "IpsecIkeDown": ("site_ike_state", 1),
    "IpsecChildDown": ("site_child_state", 1),
    "IpsecKernelMismatch": ("site_kernel_verified", 1),
    "IpsecPathDown": ("path_state", 1),
    "IpsecPathUnverified": ("path_state", 1),
    "IpsecOneWay": ("business_state", 1),
    "IpsecFrequentRekey": ("site_rekeys_in_window", 0),
    "IpsecNoTraffic": ("site_traffic_idle", 0),
}
LABELS = ("event_id", "hub_id", "site_id", "src_site_id", "dst_site_id")
ALERT_LEVELS = {"critical", "warning", "info"}
RUNBOOK = "https://github.com/yikkrrtykj/event-ipsec-hub/blob/main/docs/pr4/OPERATIONS.md"


def signature(timestamp, secret):
    key = str(timestamp).encode("ascii") + b"\n" + secret
    return base64.b64encode(hmac.digest(key, b"", "sha256")).decode("ascii")


def official_target(url):
    target = urlsplit(url)
    if (
        target.scheme != "https"
        or target.netloc != "open.feishu.cn"
        or target.query
        or target.fragment
        or not re.fullmatch(r"/open-apis/bot/v2/hook/[A-Za-z0-9-]{20,80}", target.path)
    ):
        raise Stop("The Feishu target is not an official robot endpoint.")
    return target


def transport(target, payload):
    client = http.client.HTTPSConnection if target.scheme == "https" else http.client.HTTPConnection
    conn = client(target.hostname, target.port, timeout=1.5)
    try:
        conn.request(
            "POST", target.path, json.dumps(payload).encode(), {"Content-Type": "application/json"}
        )
        response = conn.getresponse()
        return response.status, response.read(8193)
    finally:
        conn.close()


def deliver(target, secret, message):
    timestamp = int(time.time())
    payload = {
        "timestamp": str(timestamp),
        "sign": signature(timestamp, secret),
        "msg_type": "text",
        "content": {"text": message},
    }
    for attempt in range(3):
        try:
            status, raw = transport(target, payload)
            if 200 <= status < 300:
                reply = json.loads(raw)
                code = reply.get("code", reply.get("StatusCode"))
                return type(code) is int and code == 0
            if status != 429 and not 500 <= status < 600:
                return False
        except (OSError, http.client.HTTPException):
            pass
        except (ValueError, AttributeError):
            return False
        if attempt < 2:
            time.sleep(0.15 * 2**attempt)
    return False


def parse_alert(row):
    labels = row["labels"]
    name = labels["alertname"]
    state = row["status"]
    fingerprint = row["fingerprint"]
    if (
        name not in ALERTS
        or state not in {"firing", "resolved"}
        or not re.fullmatch(r"[0-9a-f]{16}", fingerprint)
    ):
        raise ValueError
    scope = {key: labels[key] for key in LABELS if key in labels}
    if not all(ID.fullmatch(value) for value in scope.values()):
        raise ValueError
    started = datetime.fromisoformat(row["startsAt"])
    if started.tzinfo is None:
        raise ValueError
    severity = labels.get("severity", "warning")
    return (
        name,
        state,
        fingerprint,
        scope,
        started,
        (severity if severity in ALERT_LEVELS else "warning"),
    )


def fresh(port, name, scope):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
    try:
        conn.request("GET", "/metrics")
        response = conn.getresponse()
        text = response.read(32769).decode("ascii")
        if response.status != 200 or "event_ipsec_collector_healthy 1" not in text.splitlines():
            return False
        metric, expected = ALERTS[name]
        for line in text.splitlines():
            key, _, value = line.rpartition(" ")
            if key.split("{")[0] != "event_ipsec_" + metric:
                continue
            labels = dict(re.findall(r'(\w+)="([^"]*)"', key))
            if float(value) == expected and all(
                labels.get(label) == value for label, value in scope.items()
            ):
                return True
    except (OSError, ValueError, http.client.HTTPException):
        return False
    finally:
        conn.close()
    return False


class Delivery:
    def __init__(self, target, secret, metrics_port):
        self.target, self.secret, self.metrics_port = target, secret, metrics_port
        self.state = read_record(STATE) or {"alerts": {}, "failures": 0}

    def accept(self, rows):
        alerts = self.state["alerts"]
        now = time.time()
        for key in list(alerts):
            if now - alerts[key]["time"] > 7 * 86400:
                del alerts[key]
        success = True
        for name, status, fingerprint, scope, started, severity in rows:
            key = "/".join([name, fingerprint, *(scope.get(label, "") for label in LABELS)])
            entry = alerts.get(key, {})
            if status == "resolved" and entry.get("state") != "firing":
                continue
            if status == "firing" and entry.get("state") == "firing":
                continue
            if entry.get("retry_after", 0) > now:
                success = False
                continue
            if len(alerts) >= 256 and key not in alerts:
                success = False
                continue
            category = "FIRING"
            if status == "resolved":
                category = (
                    "RECOVERED" if fresh(self.metrics_port, name, scope) else "DATA_UNAVAILABLE"
                )
                if category == "DATA_UNAVAILABLE" and entry.get("unavailable"):
                    continue
            moment = datetime.now(UTC)
            dimensions = " / ".join(scope.get(label, "-") for label in LABELS)
            message = (
                f"[{severity.upper()}] {category} {name}\n{dimensions}\n"
                f"开始 {started.astimezone(UTC).isoformat(timespec='seconds')} UTC\n"
                f"采集 {moment.isoformat(timespec='seconds')} UTC / "
                f"{moment.astimezone(ZoneInfo('Asia/Shanghai')).isoformat(timespec='seconds')} "
                f"Asia/Shanghai\n持续 {max(0, int((moment - started).total_seconds()))} 秒\n"
                f"影响范围为上列站点或方向，前缀请查本地授权 profile。\n{RUNBOOK}"
            )
            if deliver(self.target, self.secret, message):
                alerts[key] = {
                    "time": now,
                    "state": "firing" if category == "DATA_UNAVAILABLE" else status,
                    "unavailable": category == "DATA_UNAVAILABLE",
                }
            else:
                self.state["failures"] += 1
                alerts[key] = {**entry, "time": now, "retry_after": now + 30}
                success = False
            write_record(STATE, self.state)
        return success


class BridgeHandler(Handler):
    def do_GET(self):
        if self.path == "/metrics":
            failures = self.server.delivery.state["failures"]
            self.reply(
                200,
                (
                    "# TYPE event_ipsec_alert_bridge_delivery_failures_total counter\n"
                    f"event_ipsec_alert_bridge_delivery_failures_total {failures}\n"
                ).encode("ascii"),
            )
        else:
            self.reply(404, b"not found\n")

    def do_POST(self):
        if self.path != "/alertmanager":
            return self.reply(404, b"not found\n")
        token = self.headers.get("Authorization", "").encode("utf-8")
        if not hmac.compare_digest(token, b"Bearer " + self.server.token):
            return self.reply(401, b"unauthorized\n")
        try:
            length = int(self.headers["Content-Length"])
            if not 1 <= length <= MAX_BODY or self.headers.get("Transfer-Encoding"):
                return self.reply(413, b"invalid length\n")
            rows = json.loads(self.rfile.read(length))["alerts"]
            if not isinstance(rows, list) or not 1 <= len(rows) <= 8:
                raise ValueError
            alerts = [parse_alert(row) for row in rows]
        except (AttributeError, KeyError, OSError, TypeError, UnicodeError, ValueError):
            return self.reply(400, b"invalid payload\n")
        return (
            self.reply(200, b"ok\n")
            if self.server.delivery.accept(alerts)
            else (self.reply(503, b"delivery unavailable\n"))
        )


def serve():
    settings = runtime_settings(endpoint_only=True)
    if not settings.enabled:
        return
    config = json.loads(read_file(CONFIG, limit=4096, parent_mode=0o700))
    if not config.get("enabled", False):
        return
    # The authorized PR4 lab can exercise delivery only against a local fixture.
    target = urlsplit(config["mock_endpoint"])
    port = config["port"]
    if (
        type(port) is not int
        or not 1024 <= port <= 65535
        or target.scheme != "http"
        or not re.fullmatch(r"127\.0\.0\.1:\d{4,5}", target.netloc)
        or target.path != "/mock"
        or target.query
        or target.fragment
        or not 1024 <= target.port <= 65535
        or target.port in {port, settings.port}
    ):
        raise Stop("The lab bridge requires an explicit loopback mock.")
    directory = Path("/etc/ipsecvpn/secrets")
    secret = read_file(directory / "monitor-signing", limit=256, parent_mode=0o700).strip()
    token = read_file(directory / "monitor-bearer", limit=128, parent_mode=0o700).strip()
    if len(secret) < 24 or not re.fullmatch(rb"[A-Za-z0-9_-]{32,100}", token) or secret == token:
        raise Stop("The bridge credentials are invalid.")
    with LoopbackServer(port, BridgeHandler) as server:
        server.token = token
        server.delivery = Delivery(target, secret, settings.port)
        notify_ready()
        server.serve_forever()


if __name__ == "__main__":
    try:
        serve()
    except (Stop, OSError, KeyError, TypeError, ValueError):
        raise SystemExit("STOP: bridge startup failed.") from None
