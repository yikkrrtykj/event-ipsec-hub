"""Active UDP path probe runner that writes verified receipts to PROBE_FILE."""

import time
from pathlib import Path

from ..secureio import write_record
from .model import PROBE_FILE
from .probes import generation
from .udp import probe as udp_probe


def run_probe_cycle(
    *,
    install,
    manifest,
    live,
    probe_specs,
    secret,
    probe_file=PROBE_FILE,
    probe_fn=udp_probe,
):
    """Execute UDP echo probes for declared directions and persist a PROBE_FILE receipt."""
    started = time.time()
    generations = generation(live, manifest)
    directions = []
    for spec in probe_specs:
        count = max(1, min(4, int(spec.get("count", 3))))
        timeout = float(spec.get("timeout", 0.8))
        rtts = probe_fn(
            spec["target"],
            int(spec["port"]),
            secret,
            source=spec["source"],
            count=count,
            timeout=timeout,
        )
        directions.append(
            {
                "src_site_id": spec["src_site_id"],
                "dst_site_id": spec["dst_site_id"],
                "source": spec["source"],
                "target": spec["target"],
                "bound": True,
                "sent": count,
                "rtts": rtts,
            }
        )
    receipt = {
        "owner": install["token"],
        "event_id": manifest.event_id,
        "started": started,
        "at": time.time(),
        "generations": generations,
        "directions": directions,
    }
    write_record(Path(probe_file), receipt)
    return receipt
