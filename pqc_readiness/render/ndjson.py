"""SIEM-shaped findings output (--ndjson), one JSON event per line (#146).

Events follow OCSF 1.9.0 (https://schema.ocsf.io) so SIEMs that speak
OCSF ingest them as-is, and the field mapping docs translate them for
those that don't (docs/siem-ndjson.md):

* one **Device Inventory Info** event (class 5001) per host, first, with
  the readiness verdict and headline facts;
* one **Compliance Finding** event (class 2003) per matched rule, the
  same rules ``--sarif`` reports.

OCSF has no crypto-inventory class, so scanner-specific detail goes under
``unmapped.pqc_readiness``.  Only base-class requirements are filled: the
``cloud`` and ``osint`` attributes belong to optional OCSF profiles and
mean nothing for an on-host scan.

Identity: ``finding_info.uid`` is the same host + rule (+ subject, for
rules that fire per service / library / connection) fingerprint
``--sarif-anchor`` uses, so a finding keeps one ID across runs and
across formats (ticketing correlation, #156).  ``metadata.uid`` adds the
run time, identifying one emitted event.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime
from typing import Any

from .. import registry as _registry
from .. import report as _report
from . import sarif as _sarif

OCSF_VERSION = "1.9.0"
PRODUCT_URL = "https://github.com/aclater/pqc-readiness"

# OCSF enums used below (schema.ocsf.io, 1.9.0).
_COMPLIANCE_FINDING = 2003  # category 2, Findings
_INVENTORY_INFO = 5001  # category 5, Discovery
_ACTIVITY_CREATE = 1  # Compliance Finding: Create
_ACTIVITY_LOG = 1  # Device Inventory Info: Log
_COMPLIANCE_FAIL = 3
_FINDING_STATUS_NEW = 1
_ANALYTIC_RULE = 1
_DEVICE_UNKNOWN = 0
_OS_LINUX = 200
_OS_UNKNOWN = 0
_SEVERITY_CAPTION = {1: "Informational", 2: "Low", 3: "Medium", 4: "High"}


def _severity_id(score: str | None) -> int:
    """OCSF severity_id from the rule's security-severity score, on the
    same CVSS v3.1 bands code scanning uses: low < 4.0 <= medium < 7.0
    <= high.  Readiness findings are never critical."""
    if score is None:
        return 1
    value = float(score)
    if value >= 7.0:
        return 4
    if value >= 4.0:
        return 3
    return 2


def _epoch_ms(iso: str) -> int:
    """OCSF timestamp_t is milliseconds since the Unix epoch."""
    return int(datetime.fromisoformat(iso).timestamp() * 1000)


def _metadata(r: _report.Report, uid: str) -> dict[str, Any]:
    return {
        "version": OCSF_VERSION,
        "uid": uid,
        "log_name": "pqc_readiness",
        "original_time": r.generated_at,
        "product": {
            "name": "pqc-readiness",
            "vendor_name": "pqc-readiness",
            "version": _report.SCRIPT_VERSION,
            "url_string": PRODUCT_URL,
        },
    }


def _device(r: _report.Report) -> dict[str, Any]:
    # os_release is only populated from /etc/os-release, i.e. on Linux.
    linux = bool((r.os_release or {}).get("id")) or r.os.startswith("Linux")
    return {
        "hostname": r.hostname,
        "type_id": _DEVICE_UNKNOWN,
        "type": "Unknown",
        "os": {
            "name": r.os,
            "type_id": _OS_LINUX if linux else _OS_UNKNOWN,
            "type": "Linux" if linux else "Unknown",
        },
    }


def _event_uid(finding_uid: str, generated_at: str) -> str:
    return hashlib.sha256(f"{finding_uid}\0{generated_at}".encode()).hexdigest()[:32]


def host_summary_event(r: _report.Report, findings_count: int) -> dict[str, Any]:
    """Device Inventory Info (5001): the host's verdict and headline facts."""
    host_uid = _sarif.finding_fingerprint(r.hostname, "host-summary")
    tls_groups = r.openssl.get("tls_groups") or {}
    event: dict[str, Any] = {
        "class_uid": _INVENTORY_INFO,
        "class_name": "Device Inventory Info",
        "category_uid": 5,
        "category_name": "Discovery",
        "activity_id": _ACTIVITY_LOG,
        "activity_name": "Log",
        "type_uid": _INVENTORY_INFO * 100 + _ACTIVITY_LOG,
        "type_name": "Device Inventory Info: Log",
        "severity_id": 1,
        "severity": "Informational",
        "time": _epoch_ms(r.generated_at),
        "message": f"PQC readiness: {r.verdict}",
        "metadata": _metadata(r, _event_uid(host_uid, r.generated_at)),
        "device": _device(r),
        "unmapped": {
            "pqc_readiness": {
                "schema_version": r.schema_version,
                "verdict": r.verdict,
                "exit_code": r.exit_code,
                "isa_tier": r.isa_tier,
                "replace_required": r.replace_required,
                "cnsa_2_0_status": r.cnsa_2_0.get("status"),
                "openssl_version": r.openssl.get("version"),
                "openssl_pqc_native": r.openssl.get("pqc_native"),
                "tls_hybrid_groups": list(tls_groups.get("hybrid") or []),
                "tls_pure_pqc_groups": list(tls_groups.get("pure_pqc") or []),
                "findings_count": findings_count,
            }
        },
    }
    if r.scan_mode:
        # Offline --root scan (#152): the event describes a filesystem tree.
        event["unmapped"]["pqc_readiness"]["scan_mode"] = dict(r.scan_mode)
    return event


def finding_event(r: _report.Report, finding: _sarif.Finding) -> dict[str, Any]:
    """Compliance Finding (2003) for one matched rule."""
    spec = next(s for s in _sarif.RULE_SPECS if s.id == finding.rule_id)
    uid = _sarif.finding_fingerprint(r.hostname, finding.rule_id, finding.subject)
    sev = _severity_id(_sarif.SECURITY_SEVERITY.get(finding.rule_id))
    return {
        "class_uid": _COMPLIANCE_FINDING,
        "class_name": "Compliance Finding",
        "category_uid": 2,
        "category_name": "Findings",
        "activity_id": _ACTIVITY_CREATE,
        "activity_name": "Create",
        "type_uid": _COMPLIANCE_FINDING * 100 + _ACTIVITY_CREATE,
        "type_name": "Compliance Finding: Create",
        "severity_id": sev,
        "severity": _SEVERITY_CAPTION[sev],
        "status_id": _FINDING_STATUS_NEW,
        "status": "New",
        "time": _epoch_ms(r.generated_at),
        "message": finding.message,
        "metadata": _metadata(r, _event_uid(uid, r.generated_at)),
        "finding_info": {
            "uid": uid,
            "title": spec.short_description,
            "desc": spec.full_description,
            "types": ["Post-Quantum Cryptography Readiness"],
            "src_url": spec.help_uri,
            "analytic": {
                "uid": spec.id,
                "name": spec.id,
                "type_id": _ANALYTIC_RULE,
                "type": "Rule",
            },
        },
        "compliance": {
            "control": spec.id,
            "standards": ["pqc-readiness"],
            "status": "Fail",
            "status_id": _COMPLIANCE_FAIL,
        },
        "device": _device(r),
        "unmapped": {
            "pqc_readiness": {
                "rule_id": spec.id,
                "level": finding.level,
                "security_severity": _sarif.SECURITY_SEVERITY.get(spec.id),
                "properties": finding.properties,
                **({"subject": finding.subject} if finding.subject else {}),
            }
        },
    }


def events(r: _report.Report) -> list[dict[str, Any]]:
    """Host summary first, then one event per finding in rule order."""
    findings = _sarif.build_findings(r)
    return [host_summary_event(r, len(findings))] + [
        finding_event(r, f) for f in findings
    ]


def render_ndjson(r: _report.Report) -> str:
    """One compact JSON object per line (newline-delimited JSON)."""
    return "\n".join(
        json.dumps(e, separators=(",", ":"), sort_keys=True) for e in events(r)
    )


# Slot 16: output-format block, after --prometheus (15).
@_registry.register_arguments(16)
def add_arguments(ap: argparse.ArgumentParser) -> None:
    """--ndjson."""
    ap.add_argument(
        "--ndjson",
        action="store_true",
        help=(
            "emit SIEM-ready newline-delimited JSON: one OCSF Device Inventory "
            "Info event per host plus one OCSF Compliance Finding per finding"
        ),
    )


_registry.register_output(
    _registry.OutputFormat("ndjson", 37, lambda r: render_ndjson(r))
)
