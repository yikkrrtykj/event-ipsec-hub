"""Convert actual offline workflow outcomes to sanitized PR5 JSONL receipts."""

import json
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path

MATRIX = Path("docs/pr5/PR5_ACCEPTANCE.md")
STEPS = ("install", "lint", "tests", "shellcheck", "profiles", "wheel", "secrets")
QEMU_CASES = {f"B{index:02d}" for index in range(6, 15)} | {"F12"}
CASE = re.compile(r"(?:^test_|\[)([CBHFL][0-9]{2})(?:_|\])", re.IGNORECASE)


def results(junit):
    cases = defaultdict(list)
    if junit.exists():
        root = ET.parse(junit)
        for row in root.iter("testcase"):
            if row.get("classname", "").rsplit(".", 1)[-1] != "test_pr5":
                continue
            name = row.attrib["name"]
            matched = CASE.search(name)
            if matched:
                outcome = (
                    "FAIL"
                    if row.find("failure") is not None or row.find("error") is not None
                    else "SKIP"
                    if row.find("skipped") is not None
                    else "PASS"
                )
                cases[matched[1].upper()].append({"test": name, "result": outcome})
    return cases


def main(junit, output):
    stages = json.loads(os.environ["OFFLINE_OUTCOMES"])
    checks = {step: stages.get(step, {}).get("outcome", "skipped") for step in STEPS}
    groups = results(junit)
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    as_of = datetime.now(UTC).isoformat(timespec="seconds")
    rows = []
    for line in MATRIX.read_text(encoding="utf-8").splitlines():
        if not re.match(r"^\| [CBHFL]\d{2} \|", line):
            continue
        case, action, expected = (field.strip() for field in line.split("|")[1:4])
        if case in QEMU_CASES:
            continue
        if case == "C01":
            observed = checks
            values = set(checks.values())
            status = "FAIL" if "failure" in values else "PASS" if values == {"success"} else "SKIP"
            refs = [".github/workflows/ci.yml"]
        else:
            observed = groups[case]
            values = {item["result"] for item in observed}
            status = "FAIL" if "FAIL" in values else "PASS" if values == {"PASS"} else "SKIP"
            refs = ["tests/test_pr5.py"]
        rows.append(
            {
                "case": case,
                "time_utc": as_of,
                "head_sha": head,
                "environment": "offline CI",
                "action": action,
                "expected": expected,
                "observed": observed or "No executed assertion",
                "status": status,
                "proof_refs": refs,
            }
        )
    output.write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows), encoding="utf-8"
    )
    if rows[0]["status"] == "PASS" and any(row["status"] != "PASS" for row in rows):
        raise SystemExit(
            "The offline workflow passed, but at least one acceptance receipt is missing."
        )


if __name__ == "__main__":
    main(Path(sys.argv[1]), Path(sys.argv[2]))
