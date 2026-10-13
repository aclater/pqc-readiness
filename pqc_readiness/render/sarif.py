"""SARIF 2.1.0 findings output (--sarif)."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from .. import report as _report
from .. import registry as _registry
from ..detect import config_policy as _config_policy
from ..detect import config_sshd as _config_sshd
from ..detect import protocols_libraries as _libraries
from ..detect import runtime_services as _services
from ..detect import protocols_boot as _boot
from ..detect import protocols_kerberos as _kerberos


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
    # What the result is about when one rule fires several times per host
    # (a service, a library, an IPsec connection; #193).  Part of the
    # finding's identity; empty for host-level rules, which keeps their
    # fingerprints identical to earlier releases.
    subject: str = ""


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
    # Software that will fail at PQC (#193): one result per service,
    # library, install, connection or package, never a host-wide summary.
    RuleSpec(
        id="pqc-011-service-crypto-library-without-pqc",
        short_description=(
            "A listening service uses a crypto library that cannot do PQC."
        ),
        full_description=(
            "A process listening on this host maps a TLS / crypto library "
            "whose version has no ML-KEM hybrid key exchange (e.g. OpenSSL "
            "older than 3.5, NSS older than 3.108).  Whatever the system "
            "policy says, connections to this service stay classical and "
            "exposed to harvest-now-decrypt-later until the library or the "
            "service is upgraded.  Needs --scan-services."
        ),
        default_level="warning",
        help_uri=f"{SARIF_HELP_BASE}/pqc-011-service-crypto-library-without-pqc.md",
    ),
    RuleSpec(
        id="pqc-012-go-service-without-hybrid-mlkem",
        short_description=(
            "A statically linked Go service does not offer hybrid ML-KEM."
        ),
        full_description=(
            "A listening Go binary carries its own crypto/tls.  Go offers "
            "X25519MLKEM768 by default only from Go 1.24; older binaries "
            "offer none (Go 1.23 offers only the pre-standard Kyber draft), "
            "and GODEBUG tlsmlkem=0 switches it off.  Rebuilding with a "
            "current Go toolchain is the fix; the host's own libraries do "
            "not help a static binary.  Needs --scan-services."
        ),
        default_level="warning",
        help_uri=f"{SARIF_HELP_BASE}/pqc-012-go-service-without-hybrid-mlkem.md",
    ),
    RuleSpec(
        id="pqc-013-crypto-library-without-pqc",
        short_description="An installed crypto library or toolchain cannot do PQC.",
        full_description=(
            "An installed crypto library (GnuTLS, libgcrypt, libssh, "
            "wolfSSL, AWS-LC) or toolchain (JDK, Go) has no ML-KEM / ML-DSA "
            "support, judged from the algorithm names inside the library "
            "file or, failing that, its version against the project's "
            "release notes.  Software built on it will fail at PQC until it "
            "is upgraded.  Needs --scan-crypto-libraries."
        ),
        default_level="warning",
        help_uri=f"{SARIF_HELP_BASE}/pqc-013-crypto-library-without-pqc.md",
    ),
    RuleSpec(
        id="pqc-014-crypto-library-pre-standard-mlkem",
        short_description=(
            "An installed crypto library only has pre-standard ML-KEM (Kyber)."
        ),
        full_description=(
            "The library carries post-quantum algorithms, but its version "
            "predates the release that moved them to the final FIPS 203 / "
            "FIPS 204 standards (libgcrypt before 1.11.1, wolfSSL before "
            "5.7.4).  Draft Kyber does not interoperate with standard "
            "ML-KEM peers.  Distribution builds sometimes backport the "
            "final standard, so treat this as a check, not a verdict."
        ),
        default_level="note",
        help_uri=f"{SARIF_HELP_BASE}/pqc-014-crypto-library-pre-standard-mlkem.md",
    ),
    RuleSpec(
        id="pqc-015-ipsec-mlkem-unsupported-by-stack",
        short_description=(
            "IPsec connections configure ML-KEM that the installed stack can't do."
        ),
        full_description=(
            "IKEv2 proposals ask for ML-KEM (RFC 9370 additional key "
            "exchanges or ML-KEM as the main exchange), but the installed "
            "IPsec stack reports no ML-KEM support.  Such connections fail "
            "to load rather than falling back (measured with Libreswan "
            "5.3.2), so the tunnel breaks outright."
        ),
        default_level="warning",
        help_uri=f"{SARIF_HELP_BASE}/pqc-015-ipsec-mlkem-unsupported-by-stack.md",
    ),
    RuleSpec(
        id="pqc-016-ipsec-classical-only-ike",
        short_description="An IPsec connection's IKE proposals are classical only.",
        full_description=(
            "Every IKE proposal configured for this connection names only "
            "classical key exchanges, so its IKE SA and the keys derived "
            "from it are quantum-vulnerable.  Adding an RFC 9370 additional "
            "key exchange with ML-KEM (strongSwan ke1_mlkem768, Libreswan "
            "addke1=ml_kem_768) makes it hybrid; ML-KEM in IKEv2 is still an "
            "IETF draft in the RFC Editor queue."
        ),
        default_level="warning",
        help_uri=f"{SARIF_HELP_BASE}/pqc-016-ipsec-classical-only-ike.md",
    ),
    RuleSpec(
        id="pqc-017-bundled-crypto-without-pqc",
        short_description="A package bundling its own crypto stack cannot do PQC.",
        full_description=(
            "A package that embeds its own crypto (Go runtime, OpenJDK) is "
            "installed at a version below the release that added PQC: Go "
            "before 1.24 has no hybrid ML-KEM in crypto/tls, OpenJDK before "
            "24 has no ML-KEM / ML-DSA at all.  Only packages whose version "
            "gives a definite answer are reported.  Needs --scan-packages."
        ),
        default_level="warning",
        help_uri=f"{SARIF_HELP_BASE}/pqc-017-bundled-crypto-without-pqc.md",
    ),
    RuleSpec(
        id="pqc-018-pqc-capability-undetermined",
        short_description="PQC capability could not be determined.",
        full_description=(
            "The scanner found software whose PQC capability it cannot "
            "decide from the evidence it has: a crypto library version with "
            "no verified threshold, a build-dependent library without a "
            "readable file, an IKE proposal relying on the implementation "
            "default, or an offline tree with no OpenSSL package.  Reported "
            "so nothing is silently assumed safe; verify it by hand."
        ),
        default_level="note",
        help_uri=f"{SARIF_HELP_BASE}/pqc-018-pqc-capability-undetermined.md",
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
    # pqc-030 .. pqc-039: detect-protocols lane (#137 rule-ID blocks).
    RuleSpec(
        id="pqc-030-classical-boot-chain",
        short_description="The boot chain's signing keys are all classical.",
        full_description=(
            "The keys that authorise boot code and kernel code (UEFI Secure "
            "Boot PK / KEK / db, shim MOK, the kernel module signing key, IMA "
            "code-signing certificates) use classical algorithms only, and "
            "the TPM reports no ML-KEM / ML-DSA support.  CNSA 2.0 expects "
            "software and firmware signing to use ML-DSA-87 or LMS / XMSS by "
            "2030; Linux supports ML-DSA module signing from 7.0.  "
            "Informational: these keys belong to the firmware vendor, the "
            "distribution and the machine owner, and are the slowest to "
            "rotate, so they need planning early."
        ),
        default_level="note",
        help_uri=f"{SARIF_HELP_BASE}/pqc-030-classical-boot-chain.md",
    ),
    RuleSpec(
        id="pqc-031-kerberos-weak-enctypes",
        short_description=(
            "Kerberos allows deprecated or 128-bit encryption types, or uses "
            "classical PKINIT."
        ),
        full_description=(
            "Kerberos keys are symmetric: the quantum risk is Grover's "
            "algorithm, which leaves a 128-bit key about 64-bit security, and "
            "CNSA 2.0 requires AES-256.  A warning when deprecated enctypes "
            "(DES, 3DES, RC4; RFC 6649 / RFC 8429) are permitted by "
            "krb5.conf / kdc.conf, by MIT's default list, or present as keytab "
            "keys; a note when only 128-bit AES / Camellia enctypes are the "
            "concern, or when PKINIT (RSA / (EC)DH) is configured, for which "
            "no post-quantum standard exists yet."
        ),
        default_level="warning",
        help_uri=f"{SARIF_HELP_BASE}/pqc-031-kerberos-weak-enctypes.md",
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
    # Boot-chain trust anchors: long rotation lead time, fix is the
    # vendor's / distribution's: low, like pqc-009 (#112).
    "pqc-030-classical-boot-chain": "3.1",
    # Deprecated enctypes are a classical weakness today, not only a
    # quantum one: medium (#109).
    "pqc-031-kerberos-weak-enctypes": "4.3",
    # Performance concern, not a security weakness: low.
    "pqc-005-slh-dsa-in-tls-context": "2.0",
    # Software that will fail at PQC (#193).  A running service that can't
    # negotiate PQC is the same exposure as pqc-001, scoped to one service.
    "pqc-011-service-crypto-library-without-pqc": "5.3",
    "pqc-012-go-service-without-hybrid-mlkem": "5.3",
    # Tunnels that fail to load: an outage, not just exposure.
    "pqc-015-ipsec-mlkem-unsupported-by-stack": "6.5",
    # Config change fixes it, like pqc-008 / pqc-010.
    "pqc-016-ipsec-classical-only-ike": "5.0",
    # Installed but not necessarily in use: medium at the bottom of the band.
    "pqc-013-crypto-library-without-pqc": "4.0",
    "pqc-017-bundled-crypto-without-pqc": "4.0",
    # Draft-only PQC; distribution backports may already fix it: low.
    "pqc-014-crypto-library-pre-standard-mlkem": "3.1",
    # Nothing known to be wrong; a prompt to check by hand: lowest.
    "pqc-018-pqc-capability-undetermined": "1.0",
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


def finding_fingerprint(hostname: str, rule_id: str, subject: str = "") -> str:
    """Stable identity for one host + rule (+ subject, for rules that fire
    once per service / library / connection, #193): the same condition on
    the same host keeps one alert across runs; it closes when the
    condition clears.  An empty subject gives the same value as earlier
    releases."""
    key = f"{hostname}\0{rule_id}" + (f"\0{subject}" if subject else "")
    return hashlib.sha256(key.encode()).hexdigest()[:32]


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

    findings.extend(pqc_failure_findings(r))
    gap_finding = _capable_not_configured_finding(r)
    if gap_finding is not None:
        findings.append(gap_finding)
    boot = r.boot_chain
    layers = _boot.describe_classical_layers(boot)
    if layers:
        summary = boot.get("summary") or {}
        findings.append(
            Finding(
                rule_id="pqc-030-classical-boot-chain",
                level="note",
                message="Boot chain is classical: " + "; ".join(layers) + ".",
                properties={
                    "boot_chain:classical_layers": summary.get("classical_layers"),
                    "boot_chain:secure_boot_algorithms": summary.get(
                        "secure_boot_algorithms"
                    ),
                    "boot_chain:module_signing_pqc": summary.get("module_signing_pqc"),
                },
            )
        )

    kb = r.kerberos
    kb_level, kb_parts = _kerberos.describe_findings(kb)
    if kb_level:
        ks = kb.get("summary") or {}
        findings.append(
            Finding(
                rule_id="pqc-031-kerberos-weak-enctypes",
                level=kb_level,
                message="Kerberos: " + "; ".join(kb_parts) + ".",
                properties={
                    "kerberos:deprecated_enctypes": ks.get("deprecated_enctypes"),
                    "kerberos:aes128_enctypes": ks.get("aes128_enctypes"),
                    "kerberos:enctypes_in_keytabs": ks.get("enctypes_in_keytabs"),
                    "kerberos:pkinit_classical": ks.get("pkinit_classical"),
                },
            )
        )

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
        # Services that only follow the host default restate the TLS / SSH
        # verdict; list the ones that differ.
        if s.get("state") == "capable_not_configured"
        and not s.get("follows_host_default")
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


# ---------------------------------------------------------------------------
# Software that will fail at PQC (#193)
# ---------------------------------------------------------------------------
# Maintainer principle: if software will fail at PQC, say so.  Each
# predicate reads facts the detections already recorded and turns them
# into one finding per subject.  "Fails" is only claimed on definite
# evidence; anything the evidence can't decide becomes pqc-018
# (informational) instead of being silently treated as fine.  Version
# thresholds are the detections' own constants (cited where defined), not
# copies.

_UNDETERMINED = "pqc-018-pqc-capability-undetermined"


def _undetermined(subject: str, what: str, props: dict[str, Any]) -> Finding:
    return Finding(
        rule_id=_UNDETERMINED,
        level="note",
        message=f"Cannot tell whether {what} can do post-quantum cryptography.",
        properties=props,
        subject=subject,
    )


def _listener_subject(lst: dict[str, Any]) -> str:
    """Stable per-service identity: protocol, family, port and executable
    (PIDs and specific addresses change across restarts / DHCP)."""
    exe = lst.get("exe") or lst.get("process") or "unattributed"
    return f"service:{lst.get('protocol')}/{lst.get('family')}/{lst.get('port')}:{exe}"


def _listener_label(lst: dict[str, Any]) -> str:
    who = lst.get("systemd_unit") or lst.get("process") or "unattributed process"
    addr = str(lst.get("address") or "?")
    if ":" in addr:
        addr = f"[{addr}]"
    return f"{who} on {lst.get('protocol')} {addr}:{lst.get('port')}"


# OpenSSL sonames before 3.0: libssl.so.1.1 / .so.1.0.0 upstream,
# libssl.so.10 on RHEL 7 (1.0.2).  OpenSSL 3.x uses .so.3, so a 1.x / 10
# soname is definite evidence of a pre-3.5 library even when no version
# string could be read (measured: AlmaLinux 8.10 sshd, OpenSSL 1.1.1k).
_OPENSSL_PRE3_SONAME = re.compile(
    r"/lib(?:ssl|crypto)\.so\.(?:1(?:\.[0-9][0-9a-z.]*)?|10)$"
)

# Service-linkage families that --scan-crypto-libraries also probes from the
# library file itself (#110); its binary evidence settles libraries whose
# version has no threshold in the service probe.
_LIBRARY_PROBE_NAME = {"gnutls": "gnutls", "wolfssl": "wolfssl", "aws-lc": "aws-lc"}


def _service_lib_capable(
    lib: dict[str, Any], probes: dict[str, Any]
) -> tuple[bool | None, str]:
    """PQC capability of one library a service maps, with the evidence
    used: the service probe's own verdict, then the library probe's
    reading of the same file (or same version), then the OpenSSL soname."""
    capable = lib.get("library_pqc_capable")
    if capable is not None:
        return bool(capable), "version"
    name = _LIBRARY_PROBE_NAME.get(str(lib.get("family")))
    probe = probes.get(name) if name else None
    if probe and probe.get("installed") and probe.get("pqc_capable") is not None:
        same_file = lib.get("path") in (probe.get("files") or [])
        same_version = lib.get("version") and lib.get("version") == probe.get("version")
        if same_file or same_version:
            return bool(probe["pqc_capable"]), "crypto_libraries"
    if lib.get("family") == "openssl" and _OPENSSL_PRE3_SONAME.search(
        str(lib.get("path") or "")
    ):
        return False, "soname"
    return None, ""


def _listener_props(lst: dict[str, Any]) -> dict[str, Any]:
    return {
        "service:protocol": lst.get("protocol"),
        "service:address": lst.get("address"),
        "service:port": lst.get("port"),
        "service:process": lst.get("process"),
        "service:exe": lst.get("exe"),
        "service:systemd_unit": lst.get("systemd_unit"),
        "service:network_namespace": lst.get("network_namespace"),
    }


def _service_findings(r: _report.Report) -> list[Finding]:
    scl = r.service_crypto_linkage
    if not scl.get("available"):
        return []
    probes = (r.crypto_libraries or {}).get("libraries") or {}
    out: list[Finding] = []
    for lst in scl.get("listeners") or []:
        subject = _listener_subject(lst)
        libs = lst.get("crypto_libraries") or []
        verdicts = [(lib, *_service_lib_capable(lib, probes)) for lib in libs]
        failing = [(lib, ev) for lib, cap, ev in verdicts if cap is False]
        unknown = [lib for lib, cap, _ev in verdicts if cap is None]
        if failing:
            names = ", ".join(
                f"{lib.get('family')} "
                + (
                    lib.get("version")
                    or ("1.x (from soname)" if ev == "soname" else "(unknown version)")
                )
                for lib, ev in failing
            )
            out.append(
                Finding(
                    rule_id="pqc-011-service-crypto-library-without-pqc",
                    level="warning",
                    message=(
                        f"{_listener_label(lst)} uses {names}, which has no "
                        "ML-KEM hybrid key exchange; its connections stay classical."
                    ),
                    properties={
                        **_listener_props(lst),
                        "service:crypto_libraries": [
                            {
                                "family": lib.get("family"),
                                "version": lib.get("version"),
                                "path": lib.get("path"),
                                "evidence": ev,
                            }
                            for lib, ev in failing
                        ],
                    },
                    subject=subject,
                )
            )
        elif unknown:
            out.append(
                _undetermined(
                    subject,
                    f"{_listener_label(lst)} (crypto library "
                    + ", ".join(
                        f"{lib.get('family')} {lib.get('version') or '?'}"
                        for lib in unknown
                    )
                    + ": no verified PQC threshold for this library/version)",
                    _listener_props(lst),
                )
            )
        go = lst.get("go")
        if go:
            reverts = list(go.get("godebug_reverts") or [])
            default = go.get("default_hybrid_kex")
            if default != "X25519MLKEM768":
                major, minor = _services.GO_MLKEM_DEFAULT_VERSION
                if "tlsmlkem" in reverts:
                    # The detection drops the default when tlsmlkem=0 is set;
                    # that comes from GODEBUG in the environment or from the
                    # binary's DefaultGODEBUG, which Go derives from the
                    # module's `go` line (a go.mod declaring go 1.22 keeps
                    # 1.22 behaviour even when built with Go 1.26).
                    why = (
                        "tlsmlkem=0 turns hybrid ML-KEM off (GODEBUG in the "
                        "environment, or DefaultGODEBUG from an old `go` line in "
                        f"go.mod); built with {go.get('go_version')}"
                    )
                elif default:
                    why = (
                        f"{go.get('go_version')} offers only the pre-standard "
                        f"{default}; standard X25519MLKEM768 needs Go {major}.{minor}+"
                    )
                else:
                    why = (
                        f"{go.get('go_version') or 'a pre-1.18 Go'} offers no "
                        f"hybrid key exchange by default (Go {major}.{minor}+ does)"
                    )
                out.append(
                    Finding(
                        rule_id="pqc-012-go-service-without-hybrid-mlkem",
                        level="warning",
                        message=f"Go service {_listener_label(lst)}: {why}.",
                        properties={
                            **_listener_props(lst),
                            "go:version": go.get("go_version"),
                            "go:main_module": go.get("main_module"),
                            "go:default_hybrid_kex": default,
                            "go:godebug_reverts": reverts,
                        },
                        subject=subject,
                    )
                )
    return out


def _library_findings(r: _report.Report) -> list[Finding]:
    cl = r.crypto_libraries
    if not cl.get("available"):
        return []
    out: list[Finding] = []
    for name, lib in (cl.get("libraries") or {}).items():
        if not lib.get("installed"):
            continue
        installs = lib.get("installs")
        if installs is not None:
            # Toolchains (java, go): judge every install, since an old JDK
            # beside a new one still fails for whatever runs on it.
            key = "jca_ml_kem_ml_dsa" if name == "java" else "tls_mlkem_default"
            for inst in installs:
                subject = f"library:{name}:{inst.get('path')}"
                label = f"{name} {inst.get('version')} at {inst.get('path')}"
                props = {
                    "library:name": name,
                    "library:version": inst.get("version"),
                    "library:path": inst.get("path"),
                }
                if inst.get(key) is False:
                    if name == "java":
                        why = (
                            "has no ML-KEM / ML-DSA (JEP 496 / 497 arrived in "
                            f"JDK {_libraries.JDK_JCA_PQC_MAJOR})"
                        )
                    else:
                        major, minor = _services.GO_MLKEM_DEFAULT_VERSION
                        why = (
                            "builds programs without default hybrid ML-KEM in "
                            f"crypto/tls (Go {major}.{minor}+)"
                        )
                    out.append(
                        Finding(
                            rule_id="pqc-013-crypto-library-without-pqc",
                            level="warning",
                            message=f"{label} {why}.",
                            properties=props,
                            subject=subject,
                        )
                    )
                elif inst.get(key) is None:
                    out.append(_undetermined(subject, label, props))
            continue
        subject = f"library:{name}"
        label = f"{name} {lib.get('version') or '(unknown version)'}"
        props = {
            "library:name": name,
            "library:version": lib.get("version"),
            "library:evidence": lib.get("evidence"),
            "library:files": list(lib.get("files") or []),
        }
        capable = lib.get("pqc_capable")
        if capable is False:
            out.append(
                Finding(
                    rule_id="pqc-013-crypto-library-without-pqc",
                    level="warning",
                    message=(
                        f"{label} has no ML-KEM / ML-DSA (evidence: "
                        f"{lib.get('evidence')}); software using it fails at PQC."
                    ),
                    properties=props,
                    subject=subject,
                )
            )
        elif capable is None:
            out.append(_undetermined(subject, label, props))
        elif lib.get("caveats"):
            out.append(
                Finding(
                    rule_id="pqc-014-crypto-library-pre-standard-mlkem",
                    level="note",
                    message=f"{label}: " + " ".join(lib["caveats"]),
                    properties={**props, "library:caveats": list(lib["caveats"])},
                    subject=subject,
                )
            )
    return out


def _ipsec_findings(r: _report.Report) -> list[Finding]:
    ipsec = r.ipsec_pqc
    cfg = ipsec.get("configured") or {}
    out: list[Finding] = []
    mismatch = cfg.get("capability_mismatch")
    if mismatch:
        conns = list(mismatch.get("connections") or [])
        out.append(
            Finding(
                rule_id="pqc-015-ipsec-mlkem-unsupported-by-stack",
                level="warning",
                message=(
                    f"{len(conns)} IPsec connection(s) configure ML-KEM "
                    f"({', '.join(conns)}) but the installed "
                    f"{ipsec.get('implementation') or 'IPsec stack'} has no "
                    "ML-KEM support; they fail to load. "
                    + str(mismatch.get("reason") or "")
                ).strip(),
                properties={
                    "ipsec:implementation": ipsec.get("implementation"),
                    "ipsec:version": ipsec.get("version"),
                    "ipsec:connections": conns,
                },
            )
        )
    by_conn: dict[str, list[dict[str, Any]]] = {}
    for prop in cfg.get("proposals") or []:
        if prop.get("kind") != "ike" or not prop.get("connection"):
            continue
        by_conn.setdefault(str(prop["connection"]), []).append(prop)
    for conn, props in sorted(by_conn.items()):
        if conn == "%default":
            continue
        cats = {p.get("category") for p in props}
        subject = f"ipsec:{conn}"
        base = {
            "ipsec:connection": conn,
            "ipsec:proposals": [p.get("proposal") for p in props],
            "ipsec:sources": sorted({str(p.get("source")) for p in props}),
        }
        if cats & {"hybrid", "pure_pqc"}:
            continue
        if None in cats:
            out.append(
                _undetermined(
                    subject,
                    f"IPsec connection {conn} (an IKE proposal relies on the "
                    "implementation's default key exchanges)",
                    base,
                )
            )
        else:
            out.append(
                Finding(
                    rule_id="pqc-016-ipsec-classical-only-ike",
                    level="warning",
                    message=(
                        f"IPsec connection {conn} offers only classical IKE key "
                        "exchanges ("
                        + "; ".join(str(p.get("proposal")) for p in props)
                        + ")."
                    ),
                    properties=base,
                    subject=subject,
                )
            )
    return out


_JAVA_MAJOR_RE = re.compile(r"^(?:java-(\d+)(?:\.(\d+))?|openjdk-(\d+)|jdk(\d+))")
_GO_PACKAGE_RE = re.compile(r"^(?:golang|go)(?:-\d|\d|-bin$|$|-go$)")


def _java_major(package: str) -> int | None:
    m = _JAVA_MAJOR_RE.match(package)
    if not m:
        return None
    first = next(g for g in m.groups() if g is not None)
    major = int(first)
    if major == 1 and m.group(2):  # java-1.8.0-openjdk -> 8
        major = int(m.group(2))
    return major


def _bundled_findings(r: _report.Report) -> list[Finding]:
    pk = r.packages
    if not pk.get("available"):
        return []
    libs = (r.crypto_libraries.get("libraries") or {}) if r.crypto_libraries else {}
    out: list[Finding] = []
    for entry in pk.get("bundled_crypto") or []:
        name = str(entry.get("package"))
        version = entry.get("version")
        props = {
            "package:name": name,
            "package:version": version,
            "package:note": entry.get("note"),
        }
        subject = f"package:{name}"
        major = _java_major(name)
        if major is not None and "openjdk" in name:
            # --scan-crypto-libraries already judged each JDK install.
            if (libs.get("java") or {}).get("installed"):
                continue
            if major < _libraries.JDK_JCA_PQC_MAJOR:
                out.append(
                    Finding(
                        rule_id="pqc-017-bundled-crypto-without-pqc",
                        level="warning",
                        message=(
                            f"{name} {version} is OpenJDK {major}: no ML-KEM / "
                            "ML-DSA (JEP 496 / 497 arrived in JDK "
                            f"{_libraries.JDK_JCA_PQC_MAJOR})."
                        ),
                        properties={**props, "package:jdk_major": major},
                        subject=subject,
                    )
                )
            continue
        if _GO_PACKAGE_RE.match(name):
            if (libs.get("go") or {}).get("installed"):
                continue
            vt = _libraries._version_tuple(str(version) if version else None)
            if vt is None or len(vt) < 2:
                continue
            gmaj, gmin = _services.GO_MLKEM_DEFAULT_VERSION
            if vt[:2] < (gmaj, gmin):
                out.append(
                    Finding(
                        rule_id="pqc-017-bundled-crypto-without-pqc",
                        level="warning",
                        message=(
                            f"{name} {version}: programs built with it get no "
                            f"default hybrid ML-KEM in crypto/tls (Go {gmaj}.{gmin}+)."
                        ),
                        properties=props,
                        subject=subject,
                    )
                )
    return out


def _offline_openssl_findings(r: _report.Report) -> list[Finding]:
    """--root (#152): the live OpenSSL probe can't run, but the packaged
    version still answers pqc-001 for the tree."""
    if not r.scan_mode:
        return []
    o = r.openssl
    pkg = o.get("package") or {}
    expected = o.get("pqc_native_expected")
    if expected is False:
        return [
            Finding(
                rule_id="pqc-001-openssl-pre-3.5",
                level="warning",
                message=(
                    f"The tree's OpenSSL package {pkg.get('name')} "
                    f"{pkg.get('version')} is older than 3.5.0 — native "
                    "ML-KEM / ML-DSA are not available."
                ),
                properties={
                    "openssl:package": pkg.get("name"),
                    "openssl:package_version": pkg.get("version"),
                },
            )
        ]
    if expected is None and "pqc_native_expected" in o:
        return [
            _undetermined(
                "openssl:tree",
                "the tree's OpenSSL (no OpenSSL library package found)",
                {"openssl:package": pkg.get("name")},
            )
        ]
    return []


def pqc_failure_findings(r: _report.Report) -> list[Finding]:
    """Every finding for software that will fail at PQC (#193), in
    RULE_SPECS order (stable: subjects keep detection order within a
    rule), so SARIF ruleIndex and NDJSON event order are deterministic."""
    order = {spec.id: i for i, spec in enumerate(RULE_SPECS)}
    found = (
        _offline_openssl_findings(r)
        + _service_findings(r)
        + _library_findings(r)
        + _ipsec_findings(r)
        + _bundled_findings(r)
    )
    return sorted(found, key=lambda f: order[f.rule_id])


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
            FINGERPRINT_KEY: finding_fingerprint(
                hostname, finding.rule_id, finding.subject
            )
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
