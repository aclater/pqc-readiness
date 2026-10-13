"""SARIF 2.1.0 findings output (--sarif)."""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from typing import Any

from .. import report as _report
from .. import registry as _registry
from ..detect import config_policy as _config_policy
from ..detect import config_sshd as _config_sshd


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
    RuleSpec(
        id="pqc-009-classical-package-signing-keys",
        short_description=(
            "Every package-signing key the package manager trusts is classical."
        ),
        full_description=(
            "No trusted package-signing key (rpm gpg-pubkey, apt keyring, "
            "pacman keyring, apk key) uses a post-quantum or composite "
            "signature algorithm.  Package signing keys are long-lived "
            "trust anchors; CNSA 2.0 expects software and firmware signing "
            "to use ML-DSA-87 or LMS/XMSS by 2030, and OpenPGP defines "
            "ML-DSA and SLH-DSA keys in RFC 9980.  Informational: the fix "
            "belongs to the distribution or repository owner, but the host "
            "has to trust the new key before PQC-signed packages verify."
        ),
        default_level="note",
        help_uri=f"{SARIF_HELP_BASE}/pqc-009-classical-package-signing-keys.md",
    ),
    RuleSpec(
        id="pqc-010-sshd-pqc-kex-not-offered",
        short_description=(
            "OpenSSH supports a PQC key exchange but sshd does not offer it "
            "(or not first)."
        ),
        full_description=(
            "The installed OpenSSH supports hybrid post-quantum key exchange "
            "(mlkem768x25519-sha256 / mlkem1024nistp384-sha384, RFC 10042, "
            "or sntrup761x25519-sha512), but sshd's effective KexAlgorithms "
            "offers none of them, so SSH sessions to this host stay "
            "quantum-vulnerable to harvest-now-decrypt-later.  Measured on "
            "Rocky Linux 9.8 with the DEFAULT crypto policy.  Reported as a "
            "note when a PQC method is offered but a classical one is "
            "preferred.  Usually fixed by the system crypto policy "
            "or KexAlgorithms in sshd_config."
        ),
        default_level="warning",
        help_uri=f"{SARIF_HELP_BASE}/pqc-010-sshd-pqc-kex-not-offered.md",
    ),
    # pqc-020: the capability-vs-configuration summary (#107).  Numbered
    # apart from pqc-011.. so failure rules added in parallel (#193) can't
    # collide with it.
    RuleSpec(
        id="pqc-020-pqc-capable-not-configured",
        short_description=(
            "PQC-capable software on this host is configured to stay classical."
        ),
        full_description=(
            "The per-host deployment-gap verdict (pqc_deployment_gap) found "
            "protocols or listening services whose software can negotiate "
            "post-quantum key exchange but whose configuration keeps it "
            "classical: the TLS default groups or crypto policy, sshd's "
            "KexAlgorithms, or the configured IKE proposals.  A "
            "configuration change, not an upgrade, closes the gap.  "
            "Reported as a warning when it covers IPsec or individual "
            "services, and as a note when it only restates the TLS / SSH "
            "gaps already reported by pqc-008 and pqc-010."
        ),
        default_level="warning",
        help_uri=f"{SARIF_HELP_BASE}/pqc-020-pqc-capable-not-configured.md",
    ),
)


# ---------------------------------------------------------------------------
# Code-scanning mode (--sarif-anchor, #145)
# ---------------------------------------------------------------------------
# Code-scanning platforms need more than SARIF 2.1.0 itself requires.
# GitHub's SARIF reference lists, as required for upload:
# - result.locations[] with physicalLocation.artifactLocation.uri;
# - result.partialFingerprints, to tell new from recurring results across
#   runs;
# - optionally runAutomationDetails.id, parsed as "category/run-id"
#   (category = everything before the last "/");
# - optionally rule properties.security-severity, a string score from
#   0.0 up to 10.0.
# https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning
#
# Host findings have no source file, so --sarif-anchor names one: the
# fleet-repo pattern keeps a file per host (e.g. hosts/{hostname}.md).
# Everything in this section only applies when the flag is given, so
# default --sarif output is byte-identical to earlier releases.

# Scores follow the CVSS v3.1 qualitative bands GitHub uses to label
# security-severity (low 0.1-3.9, medium 4.0-6.9, high 7.0-8.9, critical
# 9.0-10.0;
# https://www.first.org/cvss/v3.1/specification-document#Qualitative-Severity-Rating-Scale).
# These are readiness findings, not exploitable vulnerabilities, so none
# is critical.  The table is kept apart from RULE_SPECS so score and
# rule-text changes don't edit the same lines.
SECURITY_SEVERITY: dict[str, str] = {
    # FIPS posture differs from what operators believe: high.
    "pqc-002-fips-pqc-conflict": "7.5",
    "pqc-007-fips-without-algorithm-fence": "7.5",
    # No native PQC in the TLS library: medium.
    "pqc-001-openssl-pre-3.5": "5.3",
    # PQC-capable library held back by system policy; a config change fixes
    # it, so just below pqc-001 (#104).
    "pqc-008-crypto-policy-blocks-pqc": "5.0",
    # Same shape for SSH: PQC-capable OpenSSH held back by sshd config;
    # a config change fixes it (#105).
    "pqc-010-sshd-pqc-kex-not-offered": "5.0",
    # Appliance may not support PQC; unverified dependency: medium.
    "pqc-006-no-network-hsm-pqc-firmware": "4.3",
    # Hardware cannot run PQC in software at production speed: medium.
    "pqc-003-no-pqc-isa-support": "4.0",
    # Future trust-store rotation work: low.
    "pqc-004-classical-only-trust-store": "3.1",
    # Package-signing trust anchors need rotating to PQC keys; the fix is
    # upstream's, the host only has to trust the new key: low.
    "pqc-009-classical-package-signing-keys": "3.1",
    # Performance concern, not a security weakness: low.
    "pqc-005-slh-dsa-in-tls-context": "2.0",
    # Capability-vs-configuration summary (#107): a config change fixes it;
    # below pqc-008 / pqc-010, which it partly restates.
    "pqc-020-pqc-capable-not-configured": "4.5",
}

# partialFingerprints key.  SARIF lets producers name their own
# fingerprint keys; the "/v1" suffix allows a future change of identity
# rules without colliding with old values.
FINGERPRINT_KEY = "pqcReadinessHostRule/v1"

# Set from --sarif-anchor by the flag's action; reset on every parser
# build so one main() call never leaks into the next (same pattern as
# --cbom-version in render/cbom.py).
_anchor: str | None = None


def finding_fingerprint(hostname: str, rule_id: str) -> str:
    """Stable identity for one host + rule: the same condition on the
    same host keeps one alert across runs; it closes when the condition
    clears."""
    return hashlib.sha256(f"{hostname}\0{rule_id}".encode()).hexdigest()[:32]


def anchor_path(template: str, hostname: str) -> str:
    """Expand {hostname} in the --sarif-anchor template.  Path separators
    in a hostname (never legal, but defensive) are neutralised so a host
    can't point its findings at another directory."""
    return template.replace("{hostname}", hostname.replace("/", "_"))


def automation_id(r: _report.Report) -> str:
    """category/run-id: one category per host, so results uploaded for
    different hosts never close each other's alerts."""
    host = r.hostname.replace("/", "_")
    return f"pqc-readiness/{host}/{r.generated_at}"


def _sarif_host_properties(r: _report.Report) -> dict[str, Any]:
    """Run-level host-context property bag.

    SARIF 2.1.0 lets us attach an arbitrary `properties` bag at the
    `run` level so consumers (Splunk dashboards, custom scripts) can
    correlate findings to a specific host without scraping `message`."""
    props: dict[str, Any] = {
        "host:hostname": r.hostname,
        "host:os": r.os,
        "host:arch": r.arch,
        "tool:schema_version": r.schema_version,
        "tool:version": _report.SCRIPT_VERSION,
        "report:generated_at": r.generated_at,
    }
    if r.scan_mode:
        # Offline --root scan (#152): findings describe a filesystem tree.
        props["scan:mode"] = r.scan_mode.get("mode")
        props["scan:root"] = r.scan_mode.get("root")
        props["scan:not_applicable"] = list(r.scan_mode.get("not_applicable") or [])
    return props


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

    sk = r.signing_keys
    if sk.get("available") and (sk.get("summary") or {}).get("all_classical"):
        algos = sorted({str(k.get("algorithm")) for k in sk.get("keys") or []})
        findings.append(
            Finding(
                rule_id="pqc-009-classical-package-signing-keys",
                level="note",
                message=(
                    f"All {sk['summary']['total']} trusted package-signing keys "
                    f"are classical ({', '.join(algos)}); none uses ML-DSA or "
                    "SLH-DSA (RFC 9980)."
                ),
                properties={
                    "signing_keys:total": sk["summary"]["total"],
                    "signing_keys:algorithms": algos,
                    "signing_keys:key_ids": sorted(
                        str(k.get("key_id"))
                        for k in sk.get("keys") or []
                        if k.get("key_id")
                    ),
                },
            )
        )

    sshd = r.sshd
    gap = _config_sshd.sshd_pqc_gap(sshd)
    if gap is not None:
        offered = sshd.get("kex_offered") or []
        if gap == "not_offered":
            level, msg = (
                "warning",
                "sshd offers no post-quantum key exchange although the "
                "installed OpenSSH supports one; offered: "
                + ", ".join(offered[:4])
                + (", ..." if len(offered) > 4 else "")
                + ".",
            )
        else:
            level, msg = (
                "note",
                f"sshd offers a post-quantum key exchange but prefers "
                f"{sshd.get('first_kex')} first.",
            )
        findings.append(
            Finding(
                rule_id="pqc-010-sshd-pqc-kex-not-offered",
                level=level,
                message=msg,
                properties={
                    "sshd:source": sshd.get("source"),
                    "sshd:first_kex": sshd.get("first_kex"),
                    "sshd:gap": gap,
                },
            )
        )

    gap_finding = _capable_not_configured_finding(r)
    if gap_finding is not None:
        findings.append(gap_finding)

    return findings


def _capable_not_configured_finding(r: _report.Report) -> Finding | None:
    """pqc-020 (#107): one host-level result listing every protocol and
    service in the capable_not_configured state."""
    g = r.pqc_deployment_gap or {}
    protocols = [
        name
        for name, v in (g.get("protocols") or {}).items()
        if v.get("state") == "capable_not_configured"
    ]
    services = [
        f"{s.get('process')} {s.get('protocol')}/{s.get('port')}"
        for s in (g.get("services") or {}).get("items") or []
        if s.get("state") == "capable_not_configured"
    ]
    if not protocols and not services:
        return None
    # Only TLS / SSH protocol gaps: pqc-008 / pqc-010 already report them.
    restates_only = not services and set(protocols) <= {"tls", "ssh"}
    parts = []
    if protocols:
        parts.append("protocols: " + ", ".join(protocols))
    if services:
        parts.append(
            "services: "
            + ", ".join(services[:6])
            + (", ..." if len(services) > 6 else "")
        )
    return Finding(
        rule_id="pqc-020-pqc-capable-not-configured",
        level="note" if restates_only else "warning",
        message=(
            "PQC-capable software is configured to stay classical ("
            + "; ".join(parts)
            + "); a configuration change closes the gap."
        ),
        properties={
            "gap:protocols": protocols,
            "gap:services": services,
        },
    )


def _sarif_rule_descriptor(
    spec: RuleSpec, code_scanning: bool = False
) -> dict[str, Any]:
    descriptor: dict[str, Any] = {
        "id": spec.id,
        "name": spec.id,
        "shortDescription": {"text": spec.short_description},
        "fullDescription": {"text": spec.full_description},
        "helpUri": spec.help_uri,
        "defaultConfiguration": {"level": spec.default_level},
    }
    if code_scanning and spec.id in SECURITY_SEVERITY:
        descriptor["properties"] = {
            "security-severity": SECURITY_SEVERITY[spec.id],
            "tags": ["security", "post-quantum-cryptography"],
        }
    return descriptor


def _sarif_result(
    finding: Finding,
    rule_index: int,
    hostname: str = "",
    anchor: str | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index,
        "level": finding.level,
        "message": {"text": finding.message},
        "properties": finding.properties,
    }
    if anchor is not None:
        result["locations"] = [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": anchor},
                    "region": {"startLine": 1},
                }
            }
        ]
        result["partialFingerprints"] = {
            FINGERPRINT_KEY: finding_fingerprint(hostname, finding.rule_id)
        }
    return result


def render_sarif(r: _report.Report, anchor: str | None = None) -> str:
    """Render the report as a SARIF 2.1.0 log document.

    Every rule from RULE_SPECS is emitted in the run's tool-driver
    descriptor — tooling can render rule metadata even when no result
    references the rule.  Only matched rules become results.

    With ``anchor`` (--sarif-anchor) the log is shaped for code-scanning
    upload: results get a location and fingerprint, rules a
    security-severity, and the run an automationDetails.id per host.
    Without it the output is unchanged from earlier releases."""
    code_scanning = anchor is not None
    location = anchor_path(anchor, r.hostname) if anchor is not None else None
    rules = [_sarif_rule_descriptor(s, code_scanning) for s in RULE_SPECS]
    rule_index_by_id = {s.id: i for i, s in enumerate(RULE_SPECS)}
    findings = build_findings(r)
    results = [
        _sarif_result(f, rule_index_by_id[f.rule_id], r.hostname, location)
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
    if code_scanning:
        log["runs"][0]["automationDetails"] = {"id": automation_id(r)}
    return json.dumps(log, indent=2)


@_registry.register_arguments(14)
def add_arguments(ap: argparse.ArgumentParser) -> None:
    """--sarif."""
    ap.add_argument(
        "--sarif",
        action="store_true",
        help="emit SARIF 2.1.0 findings (OASIS) for security pipelines",
    )


class _SarifAnchorAction(argparse.Action):
    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Any,
        option_string: str | None = None,
    ) -> None:
        global _anchor
        if not str(values).strip():
            parser.error("--sarif-anchor: path must not be empty")
        _anchor = str(values)
        setattr(namespace, self.dest, values)


# Slot 18: inside the output-format block, after --sarif, before
# --cbom-version (19).
@_registry.register_arguments(18)
def add_anchor_argument(ap: argparse.ArgumentParser) -> None:
    """--sarif-anchor."""
    global _anchor
    _anchor = None
    ap.add_argument(
        "--sarif-anchor",
        metavar="PATH",
        action=_SarifAnchorAction,
        help=(
            "shape --sarif for code-scanning upload: attach every result to "
            "PATH (relative to the repo root; {hostname} is substituted) and "
            "add fingerprints, per-host run category and security-severity"
        ),
    )


def _render_selected(r: _report.Report) -> str:
    return render_sarif(r, _anchor)


_registry.register_output(_registry.OutputFormat("sarif", 30, _render_selected))
