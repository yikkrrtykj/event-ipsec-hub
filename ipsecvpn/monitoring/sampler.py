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


class SampleTiming:
    def __init__(self, started, timeout):
        self.started = started
        self.timeout = timeout
        self.active = None
        self.stage = "WORKER"
        self.stages = {}

    def update(self, event, now):
        stage, kind, started = event
        if stage not in STAGES or kind not in {"command", "read"}:
            raise ValueError
        if started:
            self.stage = stage
            self.active = (stage, kind, now)
        elif self.active and self.active[:2] == (stage, kind):
            self.finish(now)
        else:
            raise ValueError

    def finish(self, now):
        if self.active:
            stage, kind, started = self.active
            counts = self.stages.setdefault(stage, {"seconds": 0.0, "commands": 0, "reads": 0})
            counts["seconds"] += now - started
            counts["commands" if kind == "command" else "reads"] += 1
            self.active = None

    def result(self, observation):
        now = time.monotonic()
        interrupted = self.active is not None
        self.finish(now)
        return {
            **observation,
            "timing": {
                "budget_seconds": self.timeout,
                "elapsed_seconds": round(now - self.started, 6),
                "commands": sum(row["commands"] for row in self.stages.values()),
                "interrupted_operation": interrupted,
                "stages": self.stages,
            },
        }


def sample(timeout):
    context = get_context("fork")
    reader, writer = context.Pipe(duplex=False)
    child = context.Process(target=observe, args=(writer,))
    started = time.monotonic()
    timing = SampleTiming(started, timeout)
    deadline = started + timeout
    try:
        child.start()
        writer.close()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not wait([reader], timeout=remaining):
                return timing.result(unavailable("COLLECTOR_TIMEOUT", stage=timing.stage))
            message = reader.recv()
            if isinstance(message, dict):
                return timing.result(message)
            timing.update(message, time.monotonic())
    except (OSError, EOFError, ValueError):
        return timing.result(unavailable("COLLECTOR_ERROR", stage=timing.stage))
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
        observation = sample(settings.timeout)
        cache.publish(observation)
        write_record(SNAPSHOT, cache.record())
        time.sleep(max(0, settings.interval - (time.monotonic() - started)))


if __name__ == "__main__":
    try:
        serve()
    except (Stop, OSError, KeyError, TypeError, ValueError):
        sys.exit("STOP: sampler could not publish its observation.")
