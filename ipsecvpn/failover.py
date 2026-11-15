"""Classify manual observations. This module cannot read or change the network."""

from dataclasses import dataclass
from typing import Literal

Path = Literal["primary", "backup"]
Selection = Literal["primary", "backup", "unavailable"]


@dataclass(frozen=True)
class PathProof:
    """Fresh receipts for every authorized pair, bound to one path on both sites."""

    path: Path
    udp_both: bool
    tcp_both: bool
    source_preserved: bool
    pinned: bool


def observe(
    first: Selection | None,
    second: Selection | None,
    proof: PathProof | None = None,
    *,
    primary_ready: tuple[bool, bool] | None = None,
    hold_met: bool = False,
):
    """Return a manual decision for two FIB observations and current data receipts.

    Stale or unavailable evidence must be passed as None. A verified path always
    requires matching route selections; a recovery indication never changes them.
    """
    result = {"selected_paths": [first, second], "data_path": "SKIP"}
    if first is None or second is None:
        return {**result, "state": "UNKNOWN", "status": "SKIP"}
    if first != second:
        state = "SINGLE_SIDE_TRANSITION" if "unavailable" in (first, second) else "ASYMMETRIC_STOP"
        return {**result, "state": state, "status": "STOP"}
    if first == "unavailable":
        return {**result, "state": "BOTH_UNAVAILABLE", "status": "STOP"}
    if proof is None:
        return {**result, "state": "UNKNOWN", "status": "SKIP"}
    if proof.path != first or not proof.pinned:
        return {**result, "state": "UNKNOWN", "status": "STOP", "reason": "WRONG_PATH"}
    if not proof.source_preserved:
        return {**result, "state": "UNKNOWN", "status": "STOP", "reason": "SOURCE_CHANGED"}
    if not (proof.udp_both and proof.tcp_both):
        return {**result, "state": "UNKNOWN", "status": "FAIL", "data_path": "FAIL"}
    result["data_path"] = "PASS"
    if first == "backup" and primary_ready and any(primary_ready):
        state = "MANUAL_CUTOVER_REQUIRED" if all(primary_ready) and hold_met else "RECOVERY_PENDING"
        return {**result, "state": state, "status": "SKIP"}
    return {**result, "state": f"{first.upper()}_VERIFIED", "status": "PASS"}
