#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Turn pqc-readiness ``--ndjson`` findings into ServiceNow Import Set rows.

Reads NDJSON (OCSF 1.9.0 events, #146) on stdin or from files and writes
one JSON request body per batch for the Import Set API's
``POST /api/now/import/{stagingTableName}/insertMultiple`` endpoint
(``{"records": [...]}``).  Only Compliance Finding events (class 2003) are
converted; the per-host Device Inventory event is used to fill host
columns.  The Import Set API accepts only string values, so every column
is a string.

The correlation ID is the event's ``finding_info.uid``: stable for a
host + rule (+ subject) across runs, so a transform map that coalesces on
it updates the same Vulnerable Item instead of creating a new one (#156).

Usage::

    pqc-readiness --ndjson --output findings.ndjson
    python3 ndjson_to_import_set.py findings.ndjson > batches.jsonl
    # each line of batches.jsonl is one insertMultiple request body

Stdlib only; sample code, see docs/integrations/servicenow-vr.md.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterable, Iterator
from datetime import datetime, timezone
from typing import Any

COMPLIANCE_FINDING = 2003
DEVICE_INVENTORY = 5001
# Keep request bodies well under typical REST payload limits.
DEFAULT_BATCH = 100


def _iso(ms: Any) -> str:
    """OCSF time (epoch ms) as ServiceNow's 'yyyy-MM-dd HH:mm:ss' (UTC)."""
    try:
        dt = datetime.fromtimestamp(int(ms) / 1000, tz=timezone.utc)
    except (TypeError, ValueError, OverflowError):
        return ""
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _s(value: Any) -> str:
    """Import Set columns are strings; lists/dicts are JSON-encoded."""
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, separators=(",", ":"))
    return str(value)


def row(event: dict[str, Any]) -> dict[str, str]:
    """One staging-table row for a Compliance Finding event."""
    info = event.get("finding_info") or {}
    device = event.get("device") or {}
    os_ = device.get("os") or {}
    compliance = event.get("compliance") or {}
    unmapped = (event.get("unmapped") or {}).get("pqc_readiness") or {}
    product = (event.get("metadata") or {}).get("product") or {}
    return {
        "u_correlation_id": _s(info.get("uid")),
        "u_rule_id": _s(compliance.get("control")),
        "u_title": _s(info.get("title")),
        "u_description": _s(info.get("desc")),
        "u_message": _s(event.get("message")),
        "u_rule_url": _s(info.get("src_url")),
        "u_severity": _s(event.get("severity")),
        "u_severity_id": _s(event.get("severity_id")),
        "u_status": _s(compliance.get("status")),
        "u_hostname": _s(device.get("hostname")),
        "u_os": _s(os_.get("name")),
        "u_last_found": _iso(event.get("time")),
        "u_scanner_version": _s(product.get("version")),
        "u_event_uid": _s((event.get("metadata") or {}).get("uid")),
        "u_properties": _s(unmapped.get("properties")),
    }


def events(lines: Iterable[str]) -> Iterator[dict[str, Any]]:
    for n, line in enumerate(lines, 1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as e:
            raise SystemExit(f"line {n}: not JSON: {e}") from None
        if isinstance(obj, dict):
            yield obj


def convert(
    lines: Iterable[str], batch: int = DEFAULT_BATCH
) -> Iterator[dict[str, Any]]:
    """Yield insertMultiple request bodies of at most ``batch`` records."""
    if batch < 1:
        raise ValueError("batch must be >= 1")
    records: list[dict[str, str]] = []
    for ev in events(lines):
        if ev.get("class_uid") != COMPLIANCE_FINDING:
            continue
        records.append(row(ev))
        if len(records) == batch:
            yield {"records": records}
            records = []
    if records:
        yield {"records": records}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("files", nargs="*", help="NDJSON files (default: stdin)")
    ap.add_argument(
        "--batch", type=int, default=DEFAULT_BATCH, help="records per request body"
    )
    args = ap.parse_args(argv)
    lines: Iterable[str]
    if args.files:
        lines = (ln for f in args.files for ln in open(f, encoding="utf-8"))
    else:
        lines = sys.stdin
    for body in convert(lines, args.batch):
        sys.stdout.write(json.dumps(body, separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
