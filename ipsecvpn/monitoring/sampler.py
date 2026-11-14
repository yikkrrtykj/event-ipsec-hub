"""Scheduled read-only collection. This process has no HTTP or UDP listener."""

import json
import subprocess
import sys
import time

from ..secureio import Stop, write_record
from .collector import runtime_settings
from .exporter import Cache
from .model import SNAPSHOT, unavailable
from .service import notify_ready


def sample(timeout):
    try:
        result = subprocess.run(
            [sys.executable, "-I", "-m", "ipsecvpn.monitoring.collector"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            check=True,
        )
        return json.loads(result.stdout)
    except subprocess.TimeoutExpired:
        return unavailable("COLLECTOR_TIMEOUT", stage="WORKER")
    except (OSError, subprocess.CalledProcessError, ValueError):
        return unavailable("COLLECTOR_ERROR", stage="WORKER")


def serve():
    settings = runtime_settings(endpoint_only=True)
    if not settings.enabled:
        return
    cache = Cache(settings.ttl, settings.probe_ttl)
    notify_ready()
    while True:
        started = time.monotonic()
        cache.publish(sample(settings.timeout))
        write_record(SNAPSHOT, cache.record())
        time.sleep(max(0, settings.interval - (time.monotonic() - started)))


if __name__ == "__main__":
    try:
        serve()
    except (Stop, OSError, KeyError, TypeError, ValueError):
        sys.exit("STOP: sampler could not publish its observation.")
