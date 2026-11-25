"""Keep technical acceptance IDs, local documentation links and archived evidence intact."""

import hashlib
import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path
from urllib.parse import unquote, urlsplit

import pytest

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
ARCHIVE = DOCS / "evidence/archive"
MATRICES = {
    2: {"C": 10, "V": 20, "F": 14, "L": 4},
    3: {"C": 14, "T": 14, "S": 10, "N": 6, "F": 16, "I": 3},
    4: {"C": 15, "M": 12, "P": 12, "A": 12, "R": 8},
    5: {"C": 14, "H": 12, "B": 14, "F": 12, "L": 10},
}


@pytest.mark.parametrize("number", MATRICES)
def test_historical_acceptance_case_ids(number):
    matrix = (DOCS / f"pr{number}/PR{number}_ACCEPTANCE.md").read_text(encoding="utf-8")
    actual = re.findall(r"^\|\s*([A-Z]\d{2})\s*\|", matrix, re.MULTILINE)
    expected = {
        f"{prefix}{index:02d}"
        for prefix, maximum in MATRICES[number].items()
        for index in range(1, maximum + 1)
    }
    assert len(actual) == len(expected)
    assert set(actual) == expected


def prose(path):
    return re.sub(
        r"^(`{3,}|~{3,})[^\n]*\n.*?^\1[ \t]*$",
        "",
        path.read_text(encoding="utf-8"),
        flags=re.MULTILINE | re.DOTALL,
    )


def test_repository_markdown_links():
    failed = []
    for source in (ROOT / "README.md", *sorted(DOCS.rglob("*.md"))):
        for link in re.findall(r"\]\(([^)\s]+)(?:\s+[^)]+)?\)", prose(source)):
            parts = urlsplit(link.strip("<>"))
            if parts.scheme or parts.netloc:
                continue
            target = source.parent / unquote(parts.path) if parts.path else source
            if not target.exists():
                failed.append(f"{source.relative_to(ROOT)} -> {link}")
            elif parts.fragment and target.suffix == ".md":
                headings = re.findall(r"^#{1,6}\s+(.*?)\s*$", prose(target), re.MULTILINE)
                anchors = {
                    re.sub(r"[^\w -]", "", title.lower()).replace(" ", "-") for title in headings
                }
                if unquote(parts.fragment) not in anchors:
                    failed.append(f"{source.relative_to(ROOT)} -> {link}")
    assert failed == []


def test_archived_receipts_match_checksums_and_preserve_legacy_provenance():
    entries = json.loads((ARCHIVE / "manifest.json").read_text(encoding="utf-8"))
    assert {entry["file"] for entry in entries} == {path.name for path in ARCHIVE.glob("*.jsonl")}
    assert len({entry["artifact_id"] for entry in entries}) == len(entries)
    archived = {}
    for entry in entries:
        data = (ARCHIVE / entry["file"]).read_bytes()
        assert hashlib.sha256(data).hexdigest() == entry["archive_sha256"]
        assert re.fullmatch(r"[0-9a-f]{64}", entry["source_zip_sha256"])
        assert re.fullmatch(r"[0-9a-f]{64}", entry["source_jsonl_sha256"])
        receipts = [json.loads(line) for line in data.splitlines()]
        assert len(receipts) == entry["records"]
        assert (
            Counter(row.get("status", row.get("result")) for row in receipts) == entry["verdicts"]
        )
        assert {row.get("head_sha") for row in receipts} == {entry["reported_head_sha"]}
        if entry["reported_head_sha"] is None:
            assert re.fullmatch(r"[0-9a-f]{40}", entry["workflow_associated_head_sha"])
        archived[entry["file"]] = entry, data
    failed, failed_data = archived["pr5-pr3-stop.jsonl"]
    retried, _ = archived["pr5-pr3-retry.jsonl"]
    assert b"STOP_FOR_MANUAL" in failed_data
    assert failed["attempt"] < retried["attempt"]
    assert failed["run_id"] == retried["run_id"]
    assert failed["reported_head_sha"] == retried["reported_head_sha"]
    assert failed["verdicts"]["FAIL"] and failed["verdicts"]["SKIP"]
    assert set(retried["verdicts"]) == {"PASS"}


@pytest.mark.parametrize("change", ["none", "head_sha", "payload_sha256", "empty", "bad_json"])
def test_host_receipt_verification(tmp_path, change):
    head, payload = "1" * 40, "2" * 64
    record = {"head_sha": head, "payload_sha256": payload, "case": "V01"}
    if change in record:
        record[change] = "3" * len(record[change])
    receipts = tmp_path / "receipts.jsonl"
    content = {"empty": "", "bad_json": "{"}.get(change, json.dumps(record) + "\n")
    receipts.write_text(content, encoding="utf-8")
    result = subprocess.run(
        [sys.executable, ROOT / "scripts/pr2-vm/verify_evidence.py", receipts, head, payload],
        capture_output=True,
        text=True,
        check=False,
    )
    if change == "none":
        assert result.returncode == 0 and "Verified 1" in result.stdout
    else:
        assert result.returncode != 0 and "STOP:" in result.stderr
