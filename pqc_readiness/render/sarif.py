"""SARIF 2.1.0 findings output (--sarif)."""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from typing import Any

from .. import report as _report
from .. import registry as _registry
from ..detect import config_policy as _config_policy


# ---------------------------------------------------------------------------
# SARIF 2.1.0 finding output (--sarif)
# ---------------------------------------------------------------------------
# SARIF (Static Analysis Results Interchange Format, OASIS) is the standard
# exchange format for code-scanning and security tooling.  Emitting SARIF
# lets readiness output drop into existing security pipelines (CodeQL,
# GitHub code scanning, IDE integrations) without per-tool adapters.
#
# This is host-level analysis, not file-level — every result attaches the
# scanned host's identity (hostname, OS, arch, the values that triggered
# the rule) under `result.properties` rather than file locations.  Per
# SARIF 2.1.0 the only required result field is `message`; `locations` is
# recommended but optional.
#
# Adding a new rule means appending one entry to RULE_SPECS plus a small
# predicate in build_findings().

SARIF_VERSION = "2.1.0"


SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"


SARIF_HELP_BASE = "https://github.com/aclater/pqc-readiness/blob/main/docs/rules"


@dataclass(frozen=True)
class RuleSpec:
    """Static metadata for one SARIF rule.

    `default_level` is the SARIF severity enum value: one of
    ``error``, ``warning``, ``note``."""

    id: str
    short_description: str
    full_description: str
    default_level: str
    help_uri: str


@dataclass(frozen=True)
class Finding:
    """One detected condition projected from Report state.

    `properties` carries host-level context — the specific values that
    triggered the rule — since SARIF results have no file location for
    host-scope analysis."""

    rule_id: str
    level: str
    message: str
    properties: dict[str, Any]


RULE_SPECS: tuple[RuleSpec, ...] = (
    RuleSpec(
        id="pqc-001-openssl-pre-3.5",
        short_description="OpenSSL is older than 3.5 (no native PQC).",
        full_description=(
            "The host's OpenSSL is older than 3.5.0, which is the first "
            "release with native ML-KEM (FIPS 203) and ML-DSA (FIPS 204) "
            "support.  Pre-3.5 OpenSSL cannot expose PQC algorithms or "
            "the hybrid TLS groups standardized in RFC 10024 (e.g. "
            "X25519MLKEM768) to applications without a third-party provider."
        ),
        default_level="warning",
        help_uri=f"{SARIF_HELP_BASE}/pqc-001-openssl-pre-3.5.md",
    ),
    RuleSpec(
        id="pqc-002-fips-pqc-conflict",
        short_description=(
            "Kernel FIPS mode active but PQC exposed via non-FIPS provider."
        ),
        full_description=(
            "Kernel FIPS mode is enabled and OpenSSL is exposing PQC "
            "algorithms, but the FIPS provider does not yet include "
            "ML-KEM or ML-DSA.  The algorithms appear listed yet would "
            "not be usable in a FIPS-validated workflow."
        ),
        default_level="error",
        help_uri=f"{SARIF_HELP_BASE}/pqc-002-fips-pqc-conflict.md",
    ),
    RuleSpec(
        id="pqc-003-no-pqc-isa-support",
        short_description=("ISA tier is poor and no PQC accelerator is present."),
        full_description=(
            "The host's ISA feature score is below the threshold for "
            "software PQC, and no PQC-capable accelerator (HSM, network "
            "HSM, or dedicated silicon) was detected.  The host cannot "
            "be made PQC-ready in software alone."
        ),
        default_level="warning",
        help_uri=f"{SARIF_HELP_BASE}/pqc-003-no-pqc-isa-support.md",
    ),
    RuleSpec(
        id="pqc-004-classical-only-trust-store",
        short_description=(
            "Trust store contains zero PQC and zero hybrid certificates."
        ),
        full_description=(
            "The system trust store was scanned and every certificate "
            "uses classical signature algorithms.  Trust-store rotation "
            "to PQC roots will be required before pure-PQC chains "
            "validate against this host."
        ),
        default_level="note",
        help_uri=f"{SARIF_HELP_BASE}/pqc-004-classical-only-trust-store.md",
    ),
    RuleSpec(
        id="pqc-005-slh-dsa-in-tls-context",
        short_description=(
            "SLH-DSA exposed for TLS use; signatures are large for handshakes."
        ),
        full_description=(
            "OpenSSL is exposing SLH-DSA (SPHINCS+) signature "
            "algorithms.  SLH-DSA signatures are an order of magnitude "
            "larger than ML-DSA and substantially slow TLS handshakes; "
            "ML-DSA is the recommended TLS signature primitive in NIST "
            "PQC migration guidance."
        ),
        default_level="warning",
        help_uri=f"{SARIF_HELP_BASE}/pqc-005-slh-dsa-in-tls-context.md",
    ),
    RuleSpec(
        id="pqc-006-no-network-hsm-pqc-firmware",
        short_description=(
            "Network HSM client present but appliance is not PQC-capable."
        ),
        full_description=(
            "A network-attached HSM client integration is installed "
            "on the host, but the appliance has not been flagged as "
            "PQC-capable.  Confirm the appliance firmware version "
            "supports ML-KEM / ML-DSA before depending on the HSM "
            "for PQC operations."
        ),
        default_level="warning",
        help_uri=f"{SARIF_HELP_BASE}/pqc-006-no-network-hsm-pqc-firmware.md",
    ),
    RuleSpec(
        id="pqc-007-fips-without-algorithm-fence",
        short_description=(
            "FIPS active but the default OpenSSL provider exposes "
            "non-FIPS-validated PQC algorithms."
        ),
        full_description=(
            "The kernel reports FIPS mode active and the OpenSSL FIPS "
            "provider is loaded, but the default provider exposes "
            "algorithms that are not in the FIPS provider's set.  "
            "Operators conflating 'FIPS mode is on' with 'only "
            "FIPS-validated algorithms are reachable' will get a "
            "different answer than the system enforces.  See the "
            "FIPS algorithm-fence finding for mechanism and mitigation."
        ),
        default_level="error",
        help_uri=f"{SARIF_HELP_BASE}/pqc-007-fips-without-algorithm-fence.md",
    ),
    RuleSpec(
        id="pqc-008-crypto-policy-blocks-pqc",
        short_description=(
            "OpenSSL supports PQC TLS groups but the system crypto policy "
            "keeps them out."
        ),
        full_description=(
            "The installed OpenSSL exposes hybrid or pure ML-KEM TLS 1.3 "
            "groups, but the active system-wide crypto policy lists none in "
            "its OpenSSL back-end, so applications using the system default "
            "never negotiate PQC.  Measured on RHEL-family 9.8 hosts, whose "
            "DEFAULT policy enables no PQC; the PQ subpolicy (EL9) or "
            "TEST-PQ (EL10 / Fedora) turns it on, and NO-PQ turns it off."
        ),
        default_level="warning",
        help_uri=f"{SARIF_HELP_BASE}/pqc-008-crypto-policy-blocks-pqc.md",
    ),
)


def _sarif_host_properties(r: _report.Report) -> dict[str, Any]:
    """Run-level host-context property bag.

    SARIF 2.1.0 lets us attach an arbitrary `properties` bag at the
    `run` level so consumers (Splunk dashboards, custom scripts) can
    correlate findings to a specific host without scraping `message`."""
    return {
        "host:hostname": r.hostname,
        "host:os": r.os,
        "host:arch": r.arch,
        "tool:schema_version": r.schema_version,
        "tool:version": _report.SCRIPT_VERSION,
        "report:generated_at": r.generated_at,
    }


def build_findings(r: _report.Report) -> list[Finding]:
    """Project a Report into typed Finding records.

    Each rule is a small predicate over Report state.  Order is
    deterministic — RULE_SPECS order is preserved so SARIF result
    indexing is stable across runs on the same host."""
    findings: list[Finding] = []

    osinfo = r.openssl
    if osinfo.get("available") and not osinfo.get("pqc_native", False):
        findings.append(
            Finding(
                rule_id="pqc-001-openssl-pre-3.5",
                level="warning",
                message=(
                    f"OpenSSL {osinfo.get('version', 'unknown')} is older "
                    "than 3.5.0 — native ML-KEM / ML-DSA are not available."
                ),
                properties={
                    "openssl:version": osinfo.get("version"),
                    "openssl:upgrade_path": osinfo.get("upgrade_path"),
                },
            )
        )

    fc = r.fips_pqc_conflict
    if fc.get("in_conflict"):
        findings.append(
            Finding(
                rule_id="pqc-002-fips-pqc-conflict",
                level="error",
                message=str(fc.get("explanation") or "FIPS / PQC provider conflict."),
                properties={
                    "fips:kernel": r.fips.get("kernel"),
                    "fips:openssl_provider": r.fips.get("openssl_provider"),
                    "openssl:kem_algorithms": list(osinfo.get("kem_algorithms") or []),
                    "openssl:sig_algorithms": list(osinfo.get("sig_algorithms") or []),
                },
            )
        )

    if r.replace_required:
        findings.append(
            Finding(
                rule_id="pqc-003-no-pqc-isa-support",
                level="warning",
                message=(
                    f"ISA tier '{r.isa_tier}' and no PQC-capable accelerator "
                    "detected; software-only PQC is not viable on this host."
                ),
                properties={
                    "isa:tier": r.isa_tier,
                    "isa:score": r.isa_score,
                    "isa:reason": r.isa_reason,
                },
            )
        )

    ts = r.trust_store
    if (
        ts.get("available")
        and ts.get("total_certs", 0) > 0
        and ts.get("pqc_certs", 0) == 0
        and ts.get("hybrid_certs", 0) == 0
    ):
        findings.append(
            Finding(
                rule_id="pqc-004-classical-only-trust-store",
                level="note",
                message=(
                    f"Scanned {ts.get('total_certs', 0)} certificates across "
                    f"{len(ts.get('scanned_dirs') or [])} trust-store "
                    "directories; every cert uses classical signatures."
                    + (
                        f" Scan was capped at {ts.get('scanned_count')} of "
                        f"{ts.get('total_found')} unique certificates; the rest "
                        "were not inspected."
                        if ts.get("truncated")
                        else ""
                    )
                ),
                properties={
                    "trust_store:total_certs": ts.get("total_certs"),
                    "trust_store:pqc_certs": ts.get("pqc_certs"),
                    "trust_store:hybrid_certs": ts.get("hybrid_certs"),
                    "trust_store:scanned_dirs": list(ts.get("scanned_dirs") or []),
                    "trust_store:truncated": bool(ts.get("truncated")),
                },
            )
        )

    sigs = list(osinfo.get("sig_algorithms") or [])
    slh_dsa = sorted(s for s in sigs if isinstance(s, str) and s.startswith("SLH-DSA"))
    if slh_dsa:
        findings.append(
            Finding(
                rule_id="pqc-005-slh-dsa-in-tls-context",
                level="warning",
                message=(
                    "OpenSSL exposes SLH-DSA signature algorithms "
                    f"({', '.join(slh_dsa)}); prefer ML-DSA for TLS handshakes."
                ),
                properties={"openssl:slh_dsa_algorithms": slh_dsa},
            )
        )

    network_hsms_no_pqc = [
        a
        for a in r.accelerators
        if a.get("kind") == "network_hsm" and not a.get("pqc_capable")
    ]
    if network_hsms_no_pqc:
        names = sorted({str(a.get("name") or "unknown") for a in network_hsms_no_pqc})
        findings.append(
            Finding(
                rule_id="pqc-006-no-network-hsm-pqc-firmware",
                level="warning",
                message=(
                    f"Network HSM client present ({', '.join(names)}) but "
                    "the appliance is not flagged as PQC-capable.  Verify "
                    "appliance firmware before relying on it for PQC."
                ),
                properties={"hsm:network_hsm_names": names},
            )
        )

    if r.fips.get("fence_check_active") and not r.fips.get("algorithm_fence_engaged"):
        outside = r.fips.get("algorithms_reachable_outside_fence") or {}
        kems = outside.get("kems") or []
        sigs = outside.get("signatures") or []
        groups = outside.get("tls_groups") or []
        msg_parts: list[str] = []
        if kems:
            msg_parts.append(f"KEMs={','.join(kems)}")
        if sigs:
            msg_parts.append(f"signatures={','.join(sigs)}")
        if groups:
            msg_parts.append(f"tls_groups={','.join(groups)}")
        findings.append(
            Finding(
                rule_id="pqc-007-fips-without-algorithm-fence",
                level="error",
                message=(
                    "FIPS mode is active but the default OpenSSL provider "
                    "exposes algorithms outside the FIPS provider's set: "
                    + "; ".join(msg_parts)
                    + ".  See "
                    "docs/findings/fips-algorithm-fence.md."
                ),
                properties={
                    "fips:algorithms_reachable_outside_fence": outside,
                },
            )
        )

    cp = r.crypto_policy
    if _config_policy.policy_blocks_capable_pqc(cp, osinfo):
        tg = osinfo.get("tls_groups") or {}
        findings.append(
            Finding(
                rule_id="pqc-008-crypto-policy-blocks-pqc",
                level="warning",
                message=(
                    f"Crypto policy {cp.get('active')} allows no PQC TLS groups, "
                    "although OpenSSL supports "
                    + ", ".join((tg.get("hybrid") or []) + (tg.get("pure_pqc") or []))
                    + "."
                ),
                properties={
                    "crypto_policy:active": cp.get("active"),
                    "crypto_policy:available_subpolicies": cp.get(
                        "available_subpolicies"
                    ),
                },
            )
        )

    return findings


def _sarif_rule_descriptor(spec: RuleSpec) -> dict[str, Any]:
    return {
        "id": spec.id,
        "name": spec.id,
        "shortDescription": {"text": spec.short_description},
        "fullDescription": {"text": spec.full_description},
        "helpUri": spec.help_uri,
        "defaultConfiguration": {"level": spec.default_level},
    }


def _sarif_result(finding: Finding, rule_index: int) -> dict[str, Any]:
    return {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index,
        "level": finding.level,
        "message": {"text": finding.message},
        "properties": finding.properties,
    }


def render_sarif(r: _report.Report) -> str:
    """Render the report as a SARIF 2.1.0 log document.

    Every rule from RULE_SPECS is emitted in the run's tool-driver
    descriptor — tooling can render rule metadata even when no result
    references the rule.  Only matched rules become results."""
    rules = [_sarif_rule_descriptor(s) for s in RULE_SPECS]
    rule_index_by_id = {s.id: i for i, s in enumerate(RULE_SPECS)}
    findings = build_findings(r)
    results = [
        _sarif_result(f, rule_index_by_id[f.rule_id])
        for f in findings
        if f.rule_id in rule_index_by_id
    ]
    log: dict[str, Any] = {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "pqc-readiness",
                        "version": _report.SCRIPT_VERSION,
                        "informationUri": ("https://github.com/aclater/pqc-readiness"),
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": _sarif_host_properties(r),
            }
        ],
    }
    return json.dumps(log, indent=2)


@_registry.register_arguments(14)
def add_arguments(ap: argparse.ArgumentParser) -> None:
    """--sarif."""
    ap.add_argument(
        "--sarif",
        action="store_true",
        help="emit SARIF 2.1.0 findings (OASIS) for security pipelines",
    )


_registry.register_output(
    _registry.OutputFormat("sarif", 30, lambda r: render_sarif(r))
)
