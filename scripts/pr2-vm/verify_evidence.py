"""Check that isolated guest receipts belong to the requested checkout."""

import json
import sys
from pathlib import Path


def verify(path, head, payload):
    records = path.read_text(encoding="utf-8").splitlines()
    if not records:
        raise ValueError("The isolated guest returned no receipts.")
    for number, line in enumerate(records, 1):
        try:
            record = json.loads(line)
        except ValueError:
            raise ValueError(f"Invalid JSON in guest receipt {number}.") from None
        if not isinstance(record, dict) or record.get("head_sha") != head:
            raise ValueError(f"Guest receipt {number} does not match the host checkout.")
        if payload and record.get("payload_sha256") != payload:
            raise ValueError(f"Guest receipt {number} does not match the verified guest payload.")
    return len(records)


if __name__ == "__main__":
    try:
        count = verify(Path(sys.argv[1]), sys.argv[2], sys.argv[3])
    except (OSError, ValueError) as error:
        raise SystemExit(f"STOP: {error}") from None
    print(f"Verified {count} guest receipts for the requested checkout.")
