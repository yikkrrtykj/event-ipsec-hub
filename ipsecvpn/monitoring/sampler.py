"""Scheduled read-only collection. This process has no HTTP or UDP listener."""

import os
import signal
import sys
import time
from multiprocessing import get_context
from multiprocessing.connection import wait

from ..secureio import Stop, write_record
from .collector import ReadOnlyHost, collect, runtime_settings
from .exporter import Cache
from .model import SNAPSHOT, STAGES, unavailable
from .service import notify_ready


def observe(sender):
    os.setsid()
    with sender:
        sender.send(collect(ReadOnlyHost(progress=sender.send)))


def sample(timeout):
    context = get_context("fork")
    reader, writer = context.Pipe(duplex=False)
    child = context.Process(target=observe, args=(writer,))
    stage = "WORKER"
    deadline = time.monotonic() + timeout
    try:
        child.start()
        writer.close()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not wait([reader], timeout=remaining):
                return unavailable("COLLECTOR_TIMEOUT", stage=stage)
            message = reader.recv()
            if isinstance(message, dict):
                return message
            if message in STAGES:
                stage = message
    except (OSError, EOFError, ValueError):
        return unavailable("COLLECTOR_ERROR", stage=stage)
    finally:
        reader.close()
        writer.close()
        if child.pid is not None:
            child.join(0.03)
            if child.is_alive():
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    child.kill()
                child.join()
        child.close()


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
