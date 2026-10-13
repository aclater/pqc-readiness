#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Push pqc-readiness results into SUSE Multi-Linux Manager Custom System Info (#157).

Multi-Linux Manager (and upstream Uyuni) stores per-system key/value
"custom info", which Salt states read from pillar (custom_info:<key>) and
which shows on the system's page.  This script takes a host's --json report
(and optionally its --ndjson findings), makes sure the custom-info keys
exist, finds the system by name, and sets the values through the XML-RPC API
(https://<server>/rpc/api; methods per the Uyuni API reference:
auth.login, system.custominfo.listAllKeys / createKey, system.getId,
system.setCustomValues, auth.logout).

Stdlib only.  Credentials come from the environment and are never printed:
  MLM_URL       e.g. https://mlm.example.com/rpc/api                   required
  MLM_USER      API user                                               required
  MLM_PASSWORD  API password                                           required
  MLM_CA_FILE   CA bundle for the server certificate (default: system trust)

Usage:
  pqc-readiness --json   > host.json
  pqc-readiness --ndjson > host.ndjson
  push-custom-info.py host.json [host.ndjson] [--system-name NAME]
Exit status: 0 pushed, 1 error (details on stderr), 2 usage.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import ssl
import sys
import xmlrpc.client
from typing import Any

FAILURE_RULE = re.compile(r"^pqc-01[1-7]-")  # software that will fail at PQC (#193)

# Custom-info key label -> description.  Labels are prefixed so they're easy
# to find and don't collide with existing keys.
KEYS: dict[str, str] = {
    "pqc_verdict": "pqc-readiness verdict",
    "pqc_schema_version": "pqc-readiness report schema version",
    "pqc_generated_at": "pqc-readiness scan time",
    "pqc_gap_tls": "PQC deployment state for TLS",
    "pqc_gap_ssh": "PQC deployment state for SSH",
    "pqc_gap_ipsec": "PQC deployment state for IPsec",
    "pqc_gap_count": "Number of PQC deployment gaps",
    "pqc_failure_findings": "Findings for software that will fail at PQC",
}


def custom_values(
    report: dict[str, Any], events: list[dict[str, Any]]
) -> dict[str, str]:
    protocols = (report.get("pqc_deployment_gap") or {}).get("protocols") or {}
    gaps = (report.get("pqc_deployment_gap") or {}).get("gaps") or []
    failures = 0
    for e in events:
        uid = ((e.get("finding_info") or {}).get("analytic") or {}).get("uid") or ""
        if e.get("class_uid") == 2003 and FAILURE_RULE.match(uid):
            failures += 1
    values = {
        "pqc_verdict": str(report.get("verdict") or ""),
        "pqc_schema_version": str(report.get("schema_version") or ""),
        "pqc_generated_at": str(report.get("generated_at") or ""),
        "pqc_gap_count": str(len(gaps)),
        "pqc_failure_findings": str(failures) if events else "not collected",
    }
    for proto in ("tls", "ssh", "ipsec"):
        values[f"pqc_gap_{proto}"] = str(
            (protocols.get(proto) or {}).get("state") or "unknown"
        )
    return values


def push(
    server: Any, user: str, password: str, system_name: str, values: dict[str, str]
) -> int:
    """Log in, ensure keys, set values on the system; returns its id."""
    session = server.auth.login(user, password)
    try:
        existing = {
            k.get("label") for k in server.system.custominfo.listAllKeys(session)
        }
        for label, description in KEYS.items():
            if label not in existing:
                server.system.custominfo.createKey(session, label, description)
        matches = server.system.getId(session, system_name)
        if len(matches) != 1:
            raise LookupError(
                f"expected exactly one system named {system_name!r}, found {len(matches)}"
            )
        sid = int(matches[0]["id"])
        server.system.setCustomValues(session, sid, values)
        return sid
    finally:
        server.auth.logout(session)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("report", help="pqc-readiness --json output")
    ap.add_argument(
        "findings", nargs="?", help="pqc-readiness --ndjson output (optional)"
    )
    ap.add_argument(
        "--system-name",
        help="system name in the manager (default: the report's hostname)",
    )
    args = ap.parse_args(argv)
    url, user, password = (
        os.environ.get(k) for k in ("MLM_URL", "MLM_USER", "MLM_PASSWORD")
    )
    if not url or not user or not password:
        print(
            "push-custom-info: MLM_URL, MLM_USER and MLM_PASSWORD are required",
            file=sys.stderr,
        )
        return 2
    try:
        with open(args.report, encoding="utf-8") as fh:
            report = json.load(fh)
        events: list[dict[str, Any]] = []
        if args.findings:
            with open(args.findings, encoding="utf-8") as fh:
                events = [json.loads(line) for line in fh if line.strip()]
    except (OSError, ValueError) as e:
        print(f"push-custom-info: cannot read input: {e}", file=sys.stderr)
        return 1
    name = args.system_name or report.get("hostname")
    if not name:
        print(
            "push-custom-info: no --system-name and no hostname in the report",
            file=sys.stderr,
        )
        return 1
    ctx = None
    if url.startswith("https://"):
        ctx = ssl.create_default_context(cafile=os.environ.get("MLM_CA_FILE") or None)
    server = xmlrpc.client.ServerProxy(url, context=ctx, allow_none=False)
    try:
        sid = push(server, user, password, name, custom_values(report, events))
    except (
        xmlrpc.client.Fault,
        xmlrpc.client.ProtocolError,
        LookupError,
        OSError,
    ) as e:
        print(f"push-custom-info: {type(e).__name__}: {e}", file=sys.stderr)
        return 1
    print(
        f"push-custom-info: set {len(KEYS)} custom values on system {name} (id {sid})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
