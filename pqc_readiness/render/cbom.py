"""CycloneDX CBOM output (--cbom)."""

from __future__ import annotations

import argparse
import json
import re
import uuid
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

from .. import report as _report
from .. import registry as _registry
from . import cbom_profiles as _profiles


# Canonical cryptographic-asset model ----------------------------------------
#
# Both --cbom (CycloneDX 1.6) and --spdx (SPDX 3.0 JSON-LD) project from
# the same canonical CryptoAsset list, so detection logic lives in one
# place and the renderers are pure projections.  A single source of
# truth means a new detection rule shows up in every output format
# without a renderer-side patch.
#
# Refs:
#   https://cyclonedx.org/docs/1.7/json/  (specVersion 1.7, default; #138)
#   https://cyclonedx.org/docs/1.6/json/  (specVersion 1.6, --cbom-version 1.6)
#   https://csrc.nist.gov/pubs/ir/8547/ipd  (NIST IR 8547, initial public draft)
#   https://spdx.github.io/spdx-spec/v3.0.1/  (SPDX 3.0.1)

# Implementation platform mapping for CycloneDX algorithmProperties.
# CycloneDX enumerates a fixed set of `implementationPlatform` values;
# anything outside the set must collapse to `other` or `unknown`.
_CBOM_PLATFORM: dict[str, str] = {
    "x86_64": "x86_64",
    "amd64": "x86_64",
    "i386": "x86_32",
    "i686": "x86_32",
    "aarch64": "armv8-a",
    "arm64": "armv8-a",
    "armv7l": "armv7-a",
    "s390x": "s390x",
    "ppc64": "ppc64",
    "ppc64le": "ppc64le",
}


def _cbom_platform(arch: str) -> str:
    return _CBOM_PLATFORM.get(arch.lower(), "unknown")


# NIST PQC parameter sets — security category lookup.  Categories follow
# the NIST PQC evaluation criteria (1=AES128-equivalent, 3=AES192-equiv,
# 5=AES256-equiv); SLH-DSA `s` and `f` variants share the category of the
# underlying parameter set.  Source: FIPS 203 / 204 / 205.
_PQC_NIST_CATEGORY: dict[str, int] = {
    "ML-KEM-512": 1,
    "ML-KEM-768": 3,
    "ML-KEM-1024": 5,
    "ML-DSA-44": 2,
    "ML-DSA-65": 3,
    "ML-DSA-87": 5,
    "SLH-DSA-SHA2-128s": 1,
    "SLH-DSA-SHA2-128f": 1,
    "SLH-DSA-SHA2-192s": 3,
    "SLH-DSA-SHA2-192f": 3,
    "SLH-DSA-SHA2-256s": 5,
    "SLH-DSA-SHA2-256f": 5,
    "SLH-DSA-SHAKE-128s": 1,
    "SLH-DSA-SHAKE-128f": 1,
    "SLH-DSA-SHAKE-192s": 3,
    "SLH-DSA-SHAKE-192f": 3,
    "SLH-DSA-SHAKE-256s": 5,
    "SLH-DSA-SHAKE-256f": 5,
}


def _pqc_parameter_set(name: str) -> str:
    """Extract the parameter-set identifier from a NIST PQC algorithm name.
    For ML-KEM-768 → '768'; for SLH-DSA-SHA2-128s → 'SHA2-128s'."""
    for prefix in ("ML-KEM-", "ML-DSA-"):
        if name.startswith(prefix):
            return name[len(prefix) :]
    if name.startswith("SLH-DSA-"):
        return name[len("SLH-DSA-") :]
    return name


@dataclass(frozen=True)
class CryptoAsset:
    """Canonical cryptographic asset detected on the host.

    Both --cbom (CycloneDX 1.6 cryptographic-asset components) and
    --spdx (SPDX 3.0 software_Package elements) project from this list,
    so each detection rule appears in exactly one place.

    The `category` is the detection-source bucket (e.g. "openssl_kem",
    "ssh_kex_hybrid") — used to label per-format properties so consumers
    can correlate findings across CBOM and SPDX outputs.

    `asset_type` matches the CycloneDX 1.6 cryptographic-asset enum:
    "algorithm" | "protocol" | "related-crypto-material".  Renderers
    omit fields whose values are empty / None."""

    key: str
    name: str
    category: str
    asset_type: str
    primitive: str = ""
    execution_environment: str = ""
    implementation_platform: str = ""
    protocol_type: str = ""
    related_material_type: str = ""
    parameter_set: str = ""
    nist_category: int | None = None
    source: str = ""
    properties: tuple[tuple[str, str], ...] = ()


def _pqc_algorithm_asset(
    key: str,
    name: str,
    category: str,
    primitive: str,
    source: str,
) -> CryptoAsset:
    """A NIST PQC algorithm exposed by a library.  Carries a derived
    parameterSetIdentifier and nistQuantumSecurityLevel where the
    algorithm name is in the published FIPS lookup."""
    pset = _pqc_parameter_set(name)
    return CryptoAsset(
        key=key,
        name=name,
        category=category,
        asset_type="algorithm",
        primitive=primitive,
        execution_environment="software-plain-ram",
        parameter_set=pset if pset != name else "",
        nist_category=_PQC_NIST_CATEGORY.get(name),
        source=source,
    )


def _canonical_isa_assets(r: _report.Report) -> list[CryptoAsset]:
    """Each detected ISA feature is a hardware-execution algorithm asset.
    Primitive is `other` because an ISA feature accelerates many primitives
    (Keccak, lattice mul, AES round) rather than implementing one — the
    human-readable purpose lives in the `purpose` property."""
    platform_id = _cbom_platform(r.arch)
    out: list[CryptoAsset] = []
    for flag, info in sorted(r.isa_features.items()):
        out.append(
            CryptoAsset(
                key=f"isa/{flag}",
                name=info.get("name", flag),
                category="isa",
                asset_type="algorithm",
                primitive="other",
                execution_environment="hardware",
                implementation_platform=platform_id,
                properties=(
                    ("isa:flag", flag),
                    ("isa:purpose", info.get("purpose", "")),
                ),
            )
        )
    return out


def _canonical_accelerator_assets(r: _report.Report) -> list[CryptoAsset]:
    """HSMs, TPMs, accelerators, DPUs and network HSMs each become a
    hardware-execution algorithm asset.  The detection layer already
    classifies kind/name/detail/pqc_capable; we surface those verbatim
    in extra properties so consumers can filter on them."""
    platform_id = _cbom_platform(r.arch)
    out: list[CryptoAsset] = []
    for idx, a in enumerate(r.accelerators):
        kind = a.get("kind", "accelerator")
        name = a.get("name", "")
        props: list[tuple[str, str]] = [("accelerator:kind", str(kind))]
        detail = a.get("detail")
        if detail:
            props.append(("accelerator:detail", str(detail)))
        if a.get("pqc_capable"):
            props.append(("accelerator:pqc_capable", "true"))
        out.append(
            CryptoAsset(
                key=f"accel/{idx}/{kind}",
                name=name or kind,
                category="accelerator",
                asset_type="algorithm",
                primitive="other",
                execution_environment="hardware",
                implementation_platform=platform_id,
                properties=tuple(props),
            )
        )
    return out


def _canonical_tpm_assets(r: _report.Report) -> list[CryptoAsset]:
    tpm = r.tpm_pqc or {}
    if not tpm.get("present"):
        return []
    return [
        CryptoAsset(
            key="tpm/pqc",
            name="TPM PQC capability",
            category="tpm",
            asset_type="algorithm",
            primitive="other",
            execution_environment="hardware",
            implementation_platform=_cbom_platform(r.arch),
            properties=(
                (
                    "tpm:pqc_advertised",
                    "true" if tpm.get("pqc_advertised") else "false",
                ),
                ("tpm:note", str(tpm.get("note", ""))),
            ),
        )
    ]


def _canonical_pkcs11_assets(r: _report.Report) -> list[CryptoAsset]:
    """PKCS#11 is a cryptographic-token API; each loadable module is
    emitted as a protocol asset with the module path captured in a
    property so an aggregator can deduplicate identical modules across
    a fleet."""
    out: list[CryptoAsset] = []
    for idx, mod in enumerate(r.pkcs11_modules or []):
        out.append(
            CryptoAsset(
                key=f"pkcs11/{idx}",
                name=Path(mod).name or f"pkcs11-module-{idx}",
                category="pkcs11",
                asset_type="protocol",
                protocol_type="other",
                properties=(("pkcs11:module_path", mod),),
            )
        )
    return out


def _canonical_openssl_assets(r: _report.Report) -> list[CryptoAsset]:
    osinfo = r.openssl or {}
    if not osinfo.get("available"):
        return []
    out: list[CryptoAsset] = []
    version = osinfo.get("version") or "unknown"
    src = f"openssl@{version}"
    for kem in osinfo.get("kem_algorithms") or []:
        out.append(
            _pqc_algorithm_asset(
                f"openssl/kem/{kem}",
                kem,
                "openssl_kem",
                "kem",
                src,
            )
        )
    for sig in osinfo.get("sig_algorithms") or []:
        out.append(
            _pqc_algorithm_asset(
                f"openssl/sig/{sig}",
                sig,
                "openssl_sig",
                "signature",
                src,
            )
        )
    tls_groups = osinfo.get("tls_groups") or {}
    for grp in tls_groups.get("hybrid") or []:
        out.append(
            CryptoAsset(
                key=f"openssl/tls-hybrid/{grp}",
                name=grp,
                category="openssl_tls_hybrid",
                asset_type="algorithm",
                primitive="combiner",
                execution_environment="software-plain-ram",
                source=src,
                properties=(("tls:role", "hybrid-group"),),
            )
        )
    for grp in tls_groups.get("pure_pqc") or []:
        out.append(
            CryptoAsset(
                key=f"openssl/tls-pure-pqc/{grp}",
                name=grp,
                category="openssl_tls_pqc",
                asset_type="algorithm",
                primitive="kem",
                execution_environment="software-plain-ram",
                source=src,
                properties=(("tls:role", "pure-pqc-group"),),
            )
        )
    return out


def _canonical_ssh_assets(r: _report.Report) -> list[CryptoAsset]:
    """SSH KEX algorithms surface as key-agreement assets.  We only emit
    the PQC subset detected by `ssh -Q kex` — the classical kex set is
    out of scope for a PQC inventory."""
    ssh_info = r.ssh_pqc or {}
    if not ssh_info.get("available"):
        return []
    out: list[CryptoAsset] = []
    version = ssh_info.get("version") or "unknown"
    src = f"openssh@{version}"
    kex_groups = ssh_info.get("kex_groups") or {}
    for kex in kex_groups.get("hybrid") or []:
        out.append(
            CryptoAsset(
                key=f"ssh/kex/hybrid/{kex}",
                name=kex,
                category="ssh_kex_hybrid",
                asset_type="algorithm",
                primitive="key-agree",
                execution_environment="software-plain-ram",
                source=src,
                properties=(("ssh:role", "hybrid-kex"),),
            )
        )
    for kex in kex_groups.get("pure_pqc") or []:
        out.append(
            CryptoAsset(
                key=f"ssh/kex/pure-pqc/{kex}",
                name=kex,
                category="ssh_kex_pqc",
                asset_type="algorithm",
                primitive="kem",
                execution_environment="software-plain-ram",
                source=src,
                properties=(("ssh:role", "pure-pqc-kex"),),
            )
        )
    return out


def _canonical_ipsec_assets(r: _report.Report) -> list[CryptoAsset]:
    """IPsec stacks expose PQC support as a single boolean today; emit
    one protocol asset describing the implementation found and whether
    it advertises any PQC KE.  When a future strongSwan release ships
    per-algorithm PQC names, this can split into algorithm assets."""
    ipsec = r.ipsec_pqc or {}
    if not ipsec.get("available"):
        return []
    impl = str(ipsec.get("implementation") or "ipsec")
    props: list[tuple[str, str]] = [("ipsec:implementation", impl)]
    if ipsec.get("evidence"):
        props.append(("ipsec:evidence", str(ipsec["evidence"])))
    if ipsec.get("version"):
        props.append(("ipsec:version", str(ipsec["version"])))
    props.append(
        (
            "ipsec:pqc_advertised",
            "true" if ipsec.get("pqc") else "false",
        )
    )
    return [
        CryptoAsset(
            key=f"ipsec/{impl}",
            name=f"IPsec ({impl})",
            category="ipsec",
            asset_type="protocol",
            protocol_type="ipsec",
            properties=tuple(props),
        )
    ]


def _canonical_trust_store_assets(r: _report.Report) -> list[CryptoAsset]:
    """Trust-store scan is summary-only (counts by category) — there is
    no per-cert detail in the Report, so we emit a single related-crypto-
    material asset whose properties carry the totals.  When a richer
    per-cert scan ships, this can fan out to one certificate asset per
    file."""
    ts = r.trust_store or {}
    if not ts.get("available"):
        return []
    props: list[tuple[str, str]] = [
        ("trust_store:total_certs", str(ts.get("total_certs", 0))),
        ("trust_store:pqc_certs", str(ts.get("pqc_certs", 0))),
        ("trust_store:hybrid_certs", str(ts.get("hybrid_certs", 0))),
    ]
    cats = ts.get("cert_categories") or {}
    for cat in ("classical", "hybrid_composite", "pure_pqc"):
        props.append(
            (
                f"trust_store:cert_categories:{cat}",
                str(cats.get(cat, 0)),
            )
        )
    if "truncated" in ts:
        props.append(("trust_store:total_found", str(ts.get("total_found", 0))))
        props.append(("trust_store:scanned_count", str(ts.get("scanned_count", 0))))
        props.append(("trust_store:truncated", str(bool(ts["truncated"])).lower()))
    for d in ts.get("scanned_dirs") or []:
        props.append(("trust_store:scanned_dir", d))
    return [
        CryptoAsset(
            key="trust-store/summary",
            name="Trust store certificate inventory",
            category="trust_store",
            asset_type="related-crypto-material",
            related_material_type="other",
            properties=tuple(props),
        )
    ]


def canonical_assets(r: _report.Report) -> list[CryptoAsset]:
    """Walk the Report and return the canonical CryptoAsset list.

    Order is deterministic so that downstream diffs across runs on the
    same host stay stable: ISA → accelerators → TPM → PKCS#11 →
    OpenSSL → SSH → IPsec → trust-store summary."""
    out: list[CryptoAsset] = []
    out.extend(_canonical_isa_assets(r))
    out.extend(_canonical_accelerator_assets(r))
    out.extend(_canonical_tpm_assets(r))
    out.extend(_canonical_pkcs11_assets(r))
    out.extend(_canonical_openssl_assets(r))
    out.extend(_canonical_ssh_assets(r))
    out.extend(_canonical_ipsec_assets(r))
    out.extend(_canonical_trust_store_assets(r))
    return out


# CycloneDX 1.6 CBOM rendering ----------------------------------------------
#
# A CBOM (Cryptographic Bill of Materials) is a CycloneDX BOM whose
# `components` are populated with `cryptographic-asset` entries.  Emitting
# the standard shape lets downstream PQC-migration tooling ingest
# pqc-readiness output without a bespoke translator.  1.6 output is kept
# byte-for-byte as it was (`--cbom-version 1.6`); 1.7 adds the fields the
# 1.7 cryptographic-asset model introduced (see _cbom17_* below).


# Provenance tag stamped onto every emitted CBOM asset so downstream
# aggregators can tell which tool detected the entry.
def _cbom_provenance() -> list[dict[str, str]]:
    return [{"name": "detectedBy", "value": f"pqc-readiness@{_report.SCRIPT_VERSION}"}]


def _cbom_crypto_properties(asset: CryptoAsset) -> dict[str, Any]:
    """Project a canonical asset's crypto properties into the CycloneDX
    1.6 cryptographic-asset shape."""
    if asset.asset_type == "algorithm":
        algo: dict[str, Any] = {"primitive": asset.primitive or "other"}
        if asset.execution_environment:
            algo["executionEnvironment"] = asset.execution_environment
        if asset.implementation_platform:
            algo["implementationPlatform"] = asset.implementation_platform
        if asset.parameter_set:
            algo["parameterSetIdentifier"] = asset.parameter_set
        if asset.nist_category is not None:
            algo["nistQuantumSecurityLevel"] = asset.nist_category
        return {"assetType": "algorithm", "algorithmProperties": algo}
    if asset.asset_type == "protocol":
        return {
            "assetType": "protocol",
            "protocolProperties": {"type": asset.protocol_type or "other"},
        }
    if asset.asset_type == "related-crypto-material":
        return {
            "assetType": "related-crypto-material",
            "relatedCryptoMaterialProperties": {
                "type": asset.related_material_type or "other"
            },
        }
    raise ValueError(f"unsupported CryptoAsset.asset_type: {asset.asset_type!r}")


def _cbom_component(asset: CryptoAsset) -> dict[str, Any]:
    """Project a canonical asset into a CycloneDX 1.6 cryptographic-asset
    component.  Every emitted asset carries the `detectedBy` provenance
    tag plus any free-form (k, v) properties from the canonical record."""
    props = _cbom_provenance()
    if asset.source:
        props.append({"name": "source", "value": asset.source})
    for k, v in asset.properties:
        props.append({"name": k, "value": v})
    return {
        "type": "cryptographic-asset",
        "bom-ref": asset.key,
        "name": asset.name,
        "cryptoProperties": _cbom_crypto_properties(asset),
        "properties": props,
    }


CBOM_VERSIONS: tuple[str, ...] = ("1.7", "1.6")
CBOM_DEFAULT_VERSION = "1.7"

# CycloneDX 1.7 algorithm families (cryptography-defs.json registry,
# spec tag 1.7.2).  Name prefix -> registry family.  Families the
# registry does not define are emitted as a pqc-readiness property
# instead of `algorithmFamily`, which must be a registry value.
_CDX17_FAMILY_PREFIXES: tuple[tuple[str, str], ...] = (
    ("ML-KEM", "ML-KEM"),
    ("MLKEM", "ML-KEM"),
    ("ML-DSA", "ML-DSA"),
    ("MLDSA", "ML-DSA"),
    ("SLH-DSA", "SLH-DSA"),
    ("SLHDSA", "SLH-DSA"),
    ("LMS", "LMS"),
    ("HSS", "LMS"),
    ("XMSS", "XMSS"),
)
# Not in the 1.7.2 registry (checked 2026-10-13): HQC (selected by NIST
# 2025-03), FN-DSA (FIPS 206 draft), FrodoKEM, Classic McEliece, BIKE.
_CDX17_UNREGISTERED_PREFIXES: tuple[tuple[str, str], ...] = (
    ("HQC", "HQC"),
    ("FN-DSA", "FN-DSA"),
    ("FALCON", "FN-DSA"),
    ("FRODO", "FrodoKEM"),
    ("MCELIECE", "Classic-McEliece"),
    ("CLASSIC-MCELIECE", "Classic-McEliece"),
    ("BIKE", "BIKE"),
)


_HYBRID_CURVE_MARKERS: tuple[str, ...] = (
    "X25519",
    "X448",
    "SECP",
    "NISTP",
    "P256",
    "P384",
    "P521",
    "BRAINPOOL",
)


def _cdx17_algorithm_family(name: str) -> tuple[str, bool] | None:
    """(family, in_registry) for a PQC algorithm name, or None when the
    name is not a recognised PQC family (hybrid groups, ISA features,
    accelerators).  Hybrid names such as X25519MLKEM768 deliberately
    return None: a combiner has no single registry family."""
    upper = name.upper()
    # Hybrids carry a classical curve anywhere in the name: X25519MLKEM768,
    # SecP384r1MLKEM1024, mlkem768x25519-sha256, mlkem1024nistp384-sha384.
    if any(c in upper for c in _HYBRID_CURVE_MARKERS):
        return None
    for prefix, family in _CDX17_FAMILY_PREFIXES:
        if upper.startswith(prefix):
            return family, True
    for prefix, family in _CDX17_UNREGISTERED_PREFIXES:
        if upper.startswith(prefix):
            return family, False
    return None


def _cbom17_component(asset: CryptoAsset) -> dict[str, Any]:
    """1.7 projection: the 1.6 component plus `algorithmFamily` (registry
    families only) or, for families outside the registry, a marked
    `pqc-readiness:algorithmFamily` property."""
    comp = _cbom_component(asset)
    if asset.asset_type != "algorithm":
        return comp
    fam = _cdx17_algorithm_family(asset.name)
    if fam is None:
        return comp
    family, registered = fam
    if registered:
        comp["cryptoProperties"]["algorithmProperties"]["algorithmFamily"] = family
    else:
        comp["properties"].append(
            {"name": "pqc-readiness:algorithmFamily", "value": family}
        )
        comp["properties"].append(
            {
                "name": "pqc-readiness:algorithmFamily:registry",
                "value": "not-in-cyclonedx-1.7-registry",
            }
        )
    return comp


# Protocol components group the algorithm assets a protocol stack can
# negotiate, through 1.7's generic `relatedCryptographicAssets` link
# (which replaced the deprecated `cryptoRefArray`).  1.6 output has no
# equivalent and does not get these components.
_CDX17_PROTOCOLS: tuple[tuple[str, str, str, tuple[str, ...]], ...] = (
    (
        "protocol/tls",
        "TLS 1.3 (OpenSSL key-exchange groups)",
        "tls",
        ("openssl_tls_hybrid", "openssl_tls_pqc", "openssl_tls_classical"),
    ),
    (
        "protocol/ssh",
        "SSH (OpenSSH key exchange)",
        "ssh",
        ("ssh_kex_hybrid", "ssh_kex_pqc", "ssh_kex_classical"),
    ),
)


def _cbom17_protocol_components(assets: list[CryptoAsset]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for ref, name, ptype, categories in _CDX17_PROTOCOLS:
        members = [a for a in assets if a.category in categories]
        if not members:
            continue
        protocol: dict[str, Any] = {
            "type": ptype,
            "relatedCryptographicAssets": [
                {"type": "algorithm", "ref": a.key} for a in members
            ],
        }
        if ptype == "tls":
            protocol["version"] = "1.3"
        props = _cbom_provenance()
        if members[0].source:
            props.append({"name": "source", "value": members[0].source})
        out.append(
            {
                "type": "cryptographic-asset",
                "bom-ref": ref,
                "name": name,
                "cryptoProperties": {
                    "assetType": "protocol",
                    "protocolProperties": protocol,
                },
                "properties": props,
            }
        )
    return out


def _cdx17_certificate_state(not_before: str, not_after: str) -> str | None:
    """Lifecycle state derivable from the validity window alone.  Revocation
    cannot be known offline, so only pre-activation / active / deactivated
    (expired) are ever emitted, and nothing when the dates don't parse."""
    try:
        start = datetime.fromisoformat(not_before.replace("Z", "+00:00"))
        end = datetime.fromisoformat(not_after.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        return None
    now = datetime.now(timezone.utc)
    if start.tzinfo is None or end.tzinfo is None:
        return None
    if now < start:
        return "pre-activation"
    if now > end:
        return "deactivated"
    return "active"


_CERT_SOURCE_TRUST_STORE = "trust-store"
_CERT_SOURCE_HOST = "host-filesystem"


def _certificate_entries(
    r: _report.Report,
) -> list[tuple[str, dict[str, Any], list[str], list[str]]]:
    """Merge trust-store certificates and certificates discovered on the
    host filesystem (`--scan-crypto-material`, #108) into one list keyed by
    SHA-256 fingerprint, so a CA that is both a trust anchor and present in
    a service directory becomes one asset (#178).

    Returns (sha256, record, sources, paths) in a deterministic order:
    trust-store certificates first, in their report order, then host-only
    certificates.  The trust-store record wins when both have the
    certificate; host paths are attached either way."""
    merged: dict[str, tuple[dict[str, Any], list[str], list[str]]] = {}
    for source, section in (
        (_CERT_SOURCE_TRUST_STORE, r.trust_store),
        (_CERT_SOURCE_HOST, r.crypto_material),
    ):
        for cert in (section or {}).get("certificates") or []:
            sha = str(cert.get("sha256") or "").lower()
            if len(sha) != 64:
                continue
            if sha not in merged:
                merged[sha] = (cert, [], [])
            _rec, sources, paths = merged[sha]
            if source not in sources:
                sources.append(source)
            for path in cert.get("paths") or []:
                if path not in paths:
                    paths.append(str(path))
    return [(sha, rec, srcs, paths) for sha, (rec, srcs, paths) in merged.items()]


def _cbom17_certificate_components(r: _report.Report) -> list[dict[str, Any]]:
    """One `certificate` asset per unique certificate in
    `trust_store.certificates` and `crypto_material.certificates`.

    Contract for the per-certificate inventory (#108): each entry is a
    dict with `sha256` (hex, required — the join key) and optionally
    `serial`, `subject`, `issuer`, `not_before`, `not_after` (ISO 8601),
    `category`, `role` (`ca` / `leaf`) and, for discovered certificates,
    `paths`.  Certificates are a 1.7 projection only: the 1.6 output is
    kept byte-identical to earlier releases (#138)."""
    out: list[dict[str, Any]] = []
    for sha, cert, sources, paths in _certificate_entries(r):
        props: dict[str, Any] = {
            "certificateFormat": "X.509",
            "fingerprint": {"alg": "SHA-256", "content": sha},
        }
        for src, dst in (
            ("serial", "serialNumber"),
            ("subject", "subjectName"),
            ("issuer", "issuerName"),
            ("not_before", "notValidBefore"),
            ("not_after", "notValidAfter"),
        ):
            if cert.get(src):
                props[dst] = str(cert[src])
        state = _cdx17_certificate_state(
            str(cert.get("not_before", "")), str(cert.get("not_after", ""))
        )
        if state:
            props["certificateState"] = [{"state": state}]
        extra = _cbom_provenance()
        if cert.get("category"):
            # Trust-store certificates keep their established property name;
            # host-only ones use the section they came from.
            prefix = (
                "trust_store"
                if _CERT_SOURCE_TRUST_STORE in sources
                else "crypto_material"
            )
            extra.append({"name": f"{prefix}:category", "value": str(cert["category"])})
        if cert.get("role"):
            extra.append({"name": "certificate:role", "value": str(cert["role"])})
        extra.extend({"name": "certificate:source", "value": s} for s in sources)
        extra.extend({"name": "crypto_material:path", "value": p} for p in paths)
        out.append(
            {
                "type": "cryptographic-asset",
                "bom-ref": f"cert/sha256:{sha}",
                "name": str(cert.get("subject") or f"certificate {sha[:16]}"),
                "cryptoProperties": {
                    "assetType": "certificate",
                    "certificateProperties": props,
                },
                "properties": extra,
            }
        )
    return out


# Profiles (--cbom-profile, #144) --------------------------------------------
#
# A profile adds regime-specific annotations to the same canonical assets.
# All regime facts (functions, deadlines, sources, item lists) are data in
# cbom_profiles.py; the code below only projects them.  With the default
# profile ("none") and no --inventory-metadata, output is unchanged.


def _profile_classical_assets(r: _report.Report) -> list[CryptoAsset]:
    """Classical (quantum-vulnerable) key-exchange groups the host offers.
    The default CBOM inventories PQC capability only; a federal inventory
    is about the CRQC-vulnerable algorithms in use (M-23-02 item 4), so
    the profile adds them."""
    out: list[CryptoAsset] = []
    osinfo = r.openssl or {}
    if osinfo.get("available"):
        src = f"openssl@{osinfo.get('version') or 'unknown'}"
        for grp in (osinfo.get("tls_groups") or {}).get("classical") or []:
            out.append(
                CryptoAsset(
                    key=f"openssl/tls-classical/{grp}",
                    name=grp,
                    category="openssl_tls_classical",
                    asset_type="algorithm",
                    primitive="key-agree",
                    execution_environment="software-plain-ram",
                    source=src,
                    properties=(("tls:role", "classical-group"),),
                )
            )
    ssh_info = r.ssh_pqc or {}
    if ssh_info.get("available"):
        src = f"openssh@{ssh_info.get('version') or 'unknown'}"
        for kex in (ssh_info.get("kex_groups") or {}).get("classical") or []:
            out.append(
                CryptoAsset(
                    key=f"ssh/kex/classical/{kex}",
                    name=kex,
                    category="ssh_kex_classical",
                    asset_type="algorithm",
                    primitive="key-agree",
                    execution_environment="software-plain-ram",
                    source=src,
                    properties=(("ssh:role", "classical-kex"),),
                )
            )
    return out


def _prop(profile: dict[str, Any], name: str, value: str) -> dict[str, str]:
    return {"name": f"{profile['prefix']}{name}", "value": value}


def _vulnerability_props(
    profile: dict[str, Any], function: str, vulnerable: bool | None
) -> list[dict[str, str]]:
    props = [
        _prop(profile, "function", function),
        _prop(
            profile,
            "quantum_vulnerable",
            "unknown" if vulnerable is None else str(vulnerable).lower(),
        ),
    ]
    if vulnerable:
        date, clause = profile["deadlines"][function]
        props.append(_prop(profile, "migration_deadline", date))
        props.append(_prop(profile, "migration_deadline:source", clause))
    return props


def _asset_profile_props(
    profile: dict[str, Any], asset: CryptoAsset
) -> list[dict[str, str]]:
    """Profile annotations for one algorithm asset; [] for assets the
    profile has nothing to say about (ISA features, accelerators, …)."""
    if asset.asset_type != "algorithm":
        return []
    function = profile["function_by_primitive"].get(asset.primitive)
    if function is None:
        return []
    vulnerable = profile["quantum_vulnerable_by_category"].get(asset.category)
    props = _vulnerability_props(profile, function, vulnerable)
    props.append(
        _prop(profile, "in_use_including_fallback", profile["in_use"]["value"])
    )
    props.append(_prop(profile, "in_use_basis", profile["in_use"]["basis"]))
    return props


def _apply_profile_to_components(
    profile: dict[str, Any],
    assets: list[CryptoAsset],
    components: list[dict[str, Any]],
) -> None:
    """Append profile properties in place.  Algorithm components line up
    with `assets` by bom-ref; certificate components get the signature
    classification from their trust-store or discovered-certificate category."""
    by_ref = {a.key: a for a in assets}
    vuln_by_cat = profile["quantum_vulnerable_by_cert_category"]
    for comp in components:
        asset = by_ref.get(comp["bom-ref"])
        if asset is not None:
            comp.setdefault("properties", []).extend(
                _asset_profile_props(profile, asset)
            )
            continue
        if comp["cryptoProperties"].get("assetType") == "certificate":
            cat = next(
                (
                    p["value"]
                    for p in comp.get("properties", [])
                    if p["name"] in ("trust_store:category", "crypto_material:category")
                ),
                None,
            )
            comp.setdefault("properties", []).extend(
                _vulnerability_props(
                    profile, "digital-signature", vuln_by_cat.get(str(cat))
                )
            )


def _tls13_status(r: _report.Report) -> tuple[str, str]:
    """(status, basis) for the TLS 1.3 deadline.  Library capability only:
    OpenSSL >= 1.1.1 implements TLS 1.3.  Whether services enable it is a
    configuration question (#106) and what they negotiate is #149."""
    osinfo = r.openssl or {}
    if not osinfo.get("available"):
        return "unknown", "OpenSSL not detected"
    vt = osinfo.get("version_tuple")
    if not vt:
        return "unknown", "OpenSSL version not parsed"
    if tuple(vt[:3]) >= (1, 1, 1):
        return (
            "capable",
            "OpenSSL >= 1.1.1 implements TLS 1.3; configuration not verified",
        )
    return "not-capable", "OpenSSL < 1.1.1 has no TLS 1.3"


def _m23_02_status(r: _report.Report, source: str) -> str:
    kind, _, what = source.partition(":")
    if kind == "metadata":
        return "provided" if (r.inventory_metadata or {}).get(what) else "not-provided"
    if what == "assets":
        return "collected"
    if what == "packages":
        return "partial" if (r.packages or {}).get("available") else "not-collected"
    if what == "os":
        return "collected" if (r.os_release or r.os) else "not-collected"
    return "unknown"


def _profile_metadata_props(
    profile: dict[str, Any], r: _report.Report, components: list[dict[str, Any]]
) -> list[dict[str, str]]:
    props = [
        _prop(profile, "profile", profile["id"]),
        _prop(profile, "profile:status", profile["status"]),
    ]
    for key, url in profile["sources"].items():
        props.append(_prop(profile, f"source:{key}", url))
    tls_status, tls_basis = _tls13_status(r)
    tls_date, tls_clause = profile["tls13_deadline"]
    props += [
        _prop(profile, "tls13_deadline", tls_date),
        _prop(profile, "tls13_deadline:source", tls_clause),
        _prop(profile, "tls13_status", tls_status),
        _prop(profile, "tls13_basis", tls_basis),
    ]
    counts = {"true": 0, "false": 0}
    for comp in components:
        for p in comp.get("properties", []):
            if (
                p["name"] == f"{profile['prefix']}quantum_vulnerable"
                and p["value"] in counts
            ):
                counts[p["value"]] += 1
    props.append(_prop(profile, "quantum_vulnerable_assets", str(counts["true"])))
    props.append(_prop(profile, "quantum_resistant_assets", str(counts["false"])))
    for number, label, source in profile["m23_02_items"]:
        props.append(_prop(profile, f"m23_02:item{number}", _m23_02_status(r, source)))
        props.append(_prop(profile, f"m23_02:item{number}:label", label))
    return props


def _inventory_host_props(meta: dict[str, Any] | None) -> list[dict[str, str]]:
    """--inventory-metadata facts as host-component properties.  Emitted
    whenever the file was given, independent of the profile."""
    if not meta:
        return []
    out: list[dict[str, str]] = []
    for key in ("fisma_system_id", "fips199_categorization", "hva_id"):
        if key in meta:
            out.append({"name": f"inventory:{key}", "value": str(meta[key])})
    hosting = meta.get("hosting") or {}
    for key in ("model", "provider"):
        if key in hosting:
            out.append({"name": f"inventory:hosting:{key}", "value": hosting[key]})
    life = meta.get("data_lifecycle") or {}
    for cat in life.get("records_categories") or []:
        out.append({"name": "inventory:data_lifecycle:records_category", "value": cat})
    if "time_to_live_years" in life:
        out.append(
            {
                "name": "inventory:data_lifecycle:time_to_live_years",
                "value": str(life["time_to_live_years"]),
            }
        )
    if "notes" in meta:
        out.append({"name": "inventory:notes", "value": meta["notes"]})
    return out


# Interop with SBOM-oriented consumers (--cbom-interop, #175) ----------------
#
# Observed with real uploads (#147, docs/integrations/dependency-track.md):
# Dependency-Track 5.x stores cryptographic-asset components but drops
# their `cryptoProperties`, keeping free-form `properties`; 4.x rejects
# the whole BOM because it has no CRYPTOGRAPHIC_ASSET classifier.  These
# modes are opt-in so the default 1.6 / 1.7 output stays unchanged.

INTEROP_NONE = "none"
INTEROP_DEPENDENCY_TRACK = "dependency-track"
INTEROP_SBOM_ONLY = "sbom-only"
INTEROP_MODES: tuple[str, ...] = (
    INTEROP_NONE,
    INTEROP_DEPENDENCY_TRACK,
    INTEROP_SBOM_ONLY,
)
_MIRROR_PREFIX = "pqc-readiness:crypto:"

# cryptoProperties fields mirrored into properties: (path, property name).
_MIRRORED_FIELDS: tuple[tuple[tuple[str, ...], str], ...] = (
    (("assetType",), "assetType"),
    (("algorithmProperties", "primitive"), "primitive"),
    (("algorithmProperties", "algorithmFamily"), "algorithmFamily"),
    (("algorithmProperties", "parameterSetIdentifier"), "parameterSetIdentifier"),
    (("algorithmProperties", "nistQuantumSecurityLevel"), "nistQuantumSecurityLevel"),
    (("algorithmProperties", "executionEnvironment"), "executionEnvironment"),
    (("algorithmProperties", "implementationPlatform"), "implementationPlatform"),
    (("protocolProperties", "type"), "protocolType"),
    (("relatedCryptoMaterialProperties", "type"), "relatedCryptoMaterialType"),
    (("certificateProperties", "fingerprint", "content"), "certificateSha256"),
    (("certificateProperties", "subjectName"), "subjectName"),
    (("certificateProperties", "issuerName"), "issuerName"),
    (("certificateProperties", "notValidAfter"), "notValidAfter"),
)
# Trust-store / discovered certificate categories -> classification.
_CERT_CLASSIFICATION = {
    "classical": "classical",
    "hybrid_composite": "hybrid",
    "pure_pqc": "pure-pqc",
}


def _asset_classification(asset: CryptoAsset) -> str | None:
    """pure-pqc / hybrid / classical where the detection bucket says so;
    None for hardware and other assets with no such meaning."""
    if "hybrid" in asset.category:
        return "hybrid"
    if "classical" in asset.category:
        return "classical"
    if asset.category.endswith("_pqc") or (
        asset.asset_type == "algorithm" and asset.nist_category is not None
    ):
        return "pure-pqc"
    return None


def _mirror_crypto_facts(
    components: list[dict[str, Any]], assets: list[CryptoAsset]
) -> None:
    """Copy the key `cryptoProperties` facts into namespaced component
    `properties`, in place, so they survive consumers that keep
    properties but drop `cryptoProperties`.  `cryptoProperties` stays the
    authoritative field."""
    by_ref = {a.key: a for a in assets}
    for comp in components:
        crypto = comp.get("cryptoProperties")
        if not isinstance(crypto, dict):
            continue
        props = comp.setdefault("properties", [])
        for path, name in _MIRRORED_FIELDS:
            value: Any = crypto
            for part in path:
                value = value.get(part) if isinstance(value, dict) else None
            if value is not None and value != "":
                props.append({"name": _MIRROR_PREFIX + name, "value": str(value)})
        states = (crypto.get("certificateProperties") or {}).get("certificateState")
        if states:
            props.append(
                {
                    "name": _MIRROR_PREFIX + "certificateState",
                    "value": str(states[0]["state"]),
                }
            )
        asset = by_ref.get(comp.get("bom-ref", ""))
        classification = _asset_classification(asset) if asset else None
        if classification is None:
            for p in props:
                if p["name"] in ("trust_store:category", "crypto_material:category"):
                    classification = _CERT_CLASSIFICATION.get(p["value"])
                    break
        if classification:
            props.append(
                {"name": _MIRROR_PREFIX + "classification", "value": classification}
            )


def _mirror_provides(
    components: list[dict[str, Any]], provides: dict[str, list[str]]
) -> None:
    """Record which library provides each asset as a namespaced property,
    in place.  Dependency-Track re-exports CycloneDX 1.5, which predates
    `dependencies[].provides`, so the link would otherwise be lost (#194)."""
    by_asset: dict[str, list[str]] = {}
    for lib, refs in provides.items():
        for ref in refs:
            by_asset.setdefault(ref, []).append(lib)
    for comp in components:
        for lib in by_asset.get(comp.get("bom-ref", ""), []):
            comp.setdefault("properties", []).append(
                {"name": _MIRROR_PREFIX + "providedBy", "value": lib}
            )


# `openssl version` prints the CLI build, then "(Library: …)" when the
# loaded libcrypto differs; the library is what actually runs.
_OPENSSL_LIBRARY_VERSION = re.compile(r"Library:\s*OpenSSL\s+(\S+)")
_OPENSSL_CLI_VERSION = re.compile(r"OpenSSL\s+(\S+)")
# os-release family -> purl type (https://github.com/package-url/purl-spec).
_PURL_TYPE_BY_FAMILY = {
    "rhel": "rpm",
    "suse": "rpm",
    "debian": "deb",
    "arch": "alpm",
    "alpine": "apk",
}


def _purl_part(value: str) -> str:
    return quote(value, safe=".+-_~")


def _library_from_source(source: str) -> tuple[str, str] | None:
    """(name, version) from an asset `source` such as `openssh@10.2p1` or
    `openssl@OpenSSL 3.5.9 … (Library: OpenSSL 3.5.9 …)`."""
    name, _, rest = source.partition("@")
    if not name or not rest or rest == "unknown":
        return None
    if name == "openssl":
        m = _OPENSSL_LIBRARY_VERSION.search(rest) or _OPENSSL_CLI_VERSION.search(rest)
        if m:
            rest = m.group(1)
        elif not rest[:1].isdigit():  # a bare version such as "3.5.5" is fine
            return None
    return name, rest.strip()


def _library_components(
    r: _report.Report, assets: list[CryptoAsset]
) -> tuple[list[dict[str, Any]], dict[str, list[str]]]:
    """Library components with purls, plus which crypto-asset bom-refs each
    provides.  Stacks the scanner probed (OpenSSL, OpenSSH, …) get a
    `pkg:generic` purl with the detected version; crypto-bearing distro
    packages from `--scan-packages` get a distro purl.  Versions are
    upstream versions only (no distro release), so treat the purls as
    identification, not as input for exact-build vulnerability matching."""
    libs: dict[str, dict[str, Any]] = {}
    provides: dict[str, list[str]] = {}
    for asset in assets:
        lib = _library_from_source(asset.source) if asset.source else None
        if lib is None:
            continue
        name, version = lib
        purl = f"pkg:generic/{_purl_part(name)}@{_purl_part(version)}"
        if purl not in libs:
            libs[purl] = {
                "type": "library",
                "bom-ref": purl,
                "name": name,
                "version": version,
                "purl": purl,
                "properties": _cbom_provenance()
                + [{"name": "pqc-readiness:library:basis", "value": "probed-stack"}],
            }
        provides.setdefault(purl, []).append(asset.key)
    osr = r.os_release or {}
    ptype = _PURL_TYPE_BY_FAMILY.get(str(osr.get("family")))
    pkgs = (r.packages or {}).get("bundled_crypto") or []
    if ptype and osr.get("id"):
        namespace = _purl_part(str(osr["id"]))
        distro = f"{osr['id']}-{osr.get('version_id') or ''}".rstrip("-")
        for entry in pkgs:
            name, version = str(entry.get("package", "")), str(entry.get("version", ""))
            if not name or not version:
                continue
            purl = (
                f"pkg:{ptype}/{namespace}/{_purl_part(name)}@{_purl_part(version)}"
                f"?distro={_purl_part(distro)}"
            )
            if purl in libs:
                continue
            props = _cbom_provenance() + [
                {
                    "name": "pqc-readiness:library:basis",
                    "value": "bundled-crypto-package",
                }
            ]
            if entry.get("note"):
                props.append(
                    {"name": "pqc-readiness:library:note", "value": str(entry["note"])}
                )
            libs[purl] = {
                "type": "library",
                "bom-ref": purl,
                "name": name,
                "version": version,
                "purl": purl,
                "properties": props,
            }
    return list(libs.values()), provides


# Crypto libraries and services (#194) ---------------------------------------
#
# CycloneDX 1.7 only (1.6 output stays byte-identical, #138).  Each library
# --scan-crypto-libraries detects becomes a `library` component that
# `provides` the algorithm assets found in its binary; each listening
# process from --scan-services becomes an `application` component that
# depends on the crypto library it actually maps.  With neither flag set
# nothing here is emitted, so default output is unchanged.

# algorithms{} kind -> (bom-ref segment, category suffix, primitive).  SSH
# key exchanges split into hybrid / pure-PQC by name, like _canonical_ssh_assets.
_LIBRARY_ALGORITHM_KINDS: dict[str, tuple[str, str, str]] = {
    "kem": ("kem", "kem", "kem"),
    "signatures": ("sig", "sig", "signature"),
    "tls_hybrid_groups": ("tls-hybrid", "tls_hybrid", "combiner"),
}


def _library_crypto_assets(r: _report.Report) -> list[CryptoAsset]:
    """Algorithm assets for the PQC names found in each crypto library's
    binary (`crypto_libraries.libraries.<lib>.algorithms`).  Keys are
    namespaced per library so they never collide with OpenSSL / OpenSSH
    assets of the same algorithm name."""
    cl = r.crypto_libraries or {}
    if not cl.get("available"):
        return []
    out: list[CryptoAsset] = []
    for lib, info in sorted((cl.get("libraries") or {}).items()):
        if not info.get("installed"):
            continue
        src = f"{lib}@{info.get('version') or 'unknown'}"
        props = (("library", lib),)
        for kind, names in sorted((info.get("algorithms") or {}).items()):
            for name in names:
                if kind == "ssh_kex":
                    hybrid = any(c in name.upper() for c in _HYBRID_CURVE_MARKERS)
                    seg, cat, prim = (
                        ("ssh-kex/hybrid", "ssh_kex_hybrid", "key-agree")
                        if hybrid
                        else ("ssh-kex/pure-pqc", "ssh_kex_pqc", "kem")
                    )
                else:
                    seg, cat, prim = _LIBRARY_ALGORITHM_KINDS.get(
                        kind, (kind, kind, "other")
                    )
                key = f"library/{lib}/{seg}/{name}"
                if prim in ("kem", "signature") and kind != "ssh_kex":
                    out.append(
                        replace(
                            _pqc_algorithm_asset(
                                key, name, f"library_{cat}", prim, src
                            ),
                            properties=props,
                        )
                    )
                else:
                    out.append(
                        CryptoAsset(
                            key=key,
                            name=name,
                            category=f"library_{cat}",
                            asset_type="algorithm",
                            primitive=prim,
                            execution_environment="software-plain-ram",
                            source=src,
                            properties=props,
                        )
                    )
    return out


def _tri(value: Any) -> str:
    return "unknown" if value is None else str(bool(value)).lower()


def _package_purl(r: _report.Report, name: str, version: str) -> str | None:
    """Distro purl for a package, or None when the family has no purl type."""
    osr = r.os_release or {}
    ptype = _PURL_TYPE_BY_FAMILY.get(str(osr.get("family")))
    if not ptype or not osr.get("id") or not name or not version:
        return None
    distro = f"{osr['id']}-{osr.get('version_id') or ''}".rstrip("-")
    return (
        f"pkg:{ptype}/{_purl_part(str(osr['id']))}/{_purl_part(name)}"
        f"@{_purl_part(version)}?distro={_purl_part(distro)}"
    )


def _generic_purl(name: str, version: str) -> str:
    return f"pkg:generic/{_purl_part(name)}@{_purl_part(version)}"


def _library_component(
    ref: str,
    name: str,
    version: str | None,
    purl: str | None,
    props: list[dict[str, str]],
) -> dict[str, Any]:
    comp: dict[str, Any] = {"type": "library", "bom-ref": ref, "name": name}
    if version:
        comp["version"] = version
    if purl:
        comp["purl"] = purl
    comp["properties"] = _cbom_provenance() + props
    return comp


def _crypto_library_inventory(
    r: _report.Report, lib_assets: list[CryptoAsset]
) -> tuple[list[dict[str, Any]], dict[str, list[str]], dict[tuple[str, str], str]]:
    """(library components, provides, (family, version) -> bom-ref) for the
    libraries --scan-crypto-libraries found.  JDK and Go installs become
    one component per install."""
    cl = r.crypto_libraries or {}
    comps: list[dict[str, Any]] = []
    provides: dict[str, list[str]] = {}
    index: dict[tuple[str, str], str] = {}
    if not cl.get("available"):
        return comps, provides, index
    by_lib: dict[str, list[str]] = {}
    for a in lib_assets:
        by_lib.setdefault(dict(a.properties).get("library", ""), []).append(a.key)
    for lib, info in sorted((cl.get("libraries") or {}).items()):
        if not info.get("installed"):
            continue
        base = [
            {"name": "pqc-readiness:library:basis", "value": "crypto-library-probe"},
            {
                "name": "pqc-readiness:library:pqc_capable",
                "value": _tri(info.get("pqc_capable")),
            },
            {
                "name": "pqc-readiness:library:evidence",
                "value": str(info.get("evidence")),
            },
        ]
        base += [
            {"name": "pqc-readiness:library:caveat", "value": str(c)}
            for c in info.get("caveats") or []
        ]
        if info.get("reference"):
            base.append(
                {
                    "name": "pqc-readiness:library:reference",
                    "value": str(info["reference"]),
                }
            )
        installs = info.get("installs")
        if installs:  # JDKs, Go toolchains
            for inst in installs:
                version = str(inst.get("version") or "") or None
                ref = (
                    _generic_purl(lib, version)
                    if version
                    else f"crypto-library/{lib}/{_purl_part(str(inst.get('path')))}"
                )
                props = list(base)
                props.append(
                    {
                        "name": "pqc-readiness:library:path",
                        "value": str(inst.get("path")),
                    }
                )
                for k, v in sorted(inst.items()):
                    if k not in ("path", "version", "implementor") and (
                        v is None or isinstance(v, bool)
                    ):
                        props.append(
                            {"name": f"pqc-readiness:library:{k}", "value": _tri(v)}
                        )
                comps.append(
                    _library_component(
                        ref, lib, version, ref if version else None, props
                    )
                )
                if version:
                    index.setdefault((lib, version), ref)
            continue
        version = str(info.get("version") or "") or None
        pkg = next(iter(info.get("packages") or []), None) or {}
        purl = _package_purl(r, str(pkg.get("name", "")), str(pkg.get("version", "")))
        if purl is None and version:
            purl = _generic_purl(lib, version)
        ref = purl or f"crypto-library/{lib}"
        props = list(base)
        props += [
            {"name": "pqc-readiness:library:file", "value": str(f)}
            for f in info.get("files") or []
        ]
        comps.append(_library_component(ref, lib, version, purl, props))
        if by_lib.get(lib):
            provides[ref] = by_lib[lib]
        if version:
            index.setdefault((lib, version), ref)
    return comps, provides, index


def _service_inventory(
    r: _report.Report, index: dict[tuple[str, str], str]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, list[str]]]:
    """(application components, extra library components, service -> library
    refs) from --scan-services.  Listeners of one process collapse into one
    component; unattributed listeners are skipped (they have no process to
    name).  Libraries a service maps but --scan-crypto-libraries did not
    report (OpenSSL, NSS, Go runtimes) get their own `pkg:generic` component."""
    sv = r.service_crypto_linkage or {}
    services: dict[str, dict[str, Any]] = {}
    extra: dict[str, dict[str, Any]] = {}
    uses: dict[str, list[str]] = {}
    if not sv.get("available"):
        return [], [], uses
    for lst in sv.get("listeners") or []:
        if lst.get("pid") is None and not lst.get("exe"):
            continue
        # Name by systemd .service unit when there is one; transient scopes
        # (app-…-NNNN.scope, terminal spawns) differ per session, so fall
        # back to the executable path, which is stable across runs.
        unit = str(lst.get("systemd_unit") or "")
        ident = (
            unit
            if unit.endswith(".service")
            else str(lst.get("exe") or lst.get("process") or unit)
        )
        ref = f"service/{ident}"
        comp = services.get(ref)
        if comp is None:
            props: list[dict[str, str]] = []
            for key, prop in (
                ("exe", "exe"),
                ("systemd_unit", "systemd_unit"),
                ("process", "process"),
            ):
                if lst.get(key):
                    props.append({"name": f"service:{prop}", "value": str(lst[key])})
            if lst.get("static_binary") is not None:
                props.append(
                    {
                        "name": "service:static_binary",
                        "value": _tri(lst["static_binary"]),
                    }
                )
            comp = {
                "type": "application",
                "bom-ref": ref,
                "name": unit
                if unit.endswith(".service")
                else str(lst.get("process") or ident),
                "properties": _cbom_provenance() + props,
            }
            services[ref] = comp
            uses[ref] = []
        addr = str(lst.get("address"))
        if lst.get("family") == "ipv6":
            addr = f"[{addr}]"
        comp["properties"].append(
            {
                "name": "service:endpoint",
                "value": f"{lst.get('protocol')}/{addr}:{lst.get('port')}",
            }
        )
        links: list[tuple[str, str | None, dict[str, str]]] = []
        for link in lst.get("crypto_libraries") or []:
            links.append(
                (
                    str(link.get("family")),
                    str(link.get("version") or "") or None,
                    {"pqc_capable": _tri(link.get("library_pqc_capable"))},
                )
            )
        go = lst.get("go") or {}
        if go.get("go_version"):
            gv = str(go["go_version"])
            links.append(
                (
                    "go",
                    gv[2:] if gv.startswith("go") else gv,
                    {"default_hybrid_kex": str(go.get("default_hybrid_kex"))},
                )
            )
        for family, version, extra_props in links:
            lib_ref = index.get((family, version or "")) if version else None
            if lib_ref is None:
                lib_ref = (
                    _generic_purl(family, version)
                    if version
                    else f"crypto-library/{family}"
                )
                if lib_ref not in extra:
                    props = [
                        {
                            "name": "pqc-readiness:library:basis",
                            "value": "service-linkage",
                        }
                    ]
                    props += [
                        {"name": f"pqc-readiness:library:{k}", "value": v}
                        for k, v in extra_props.items()
                    ]
                    extra[lib_ref] = _library_component(
                        lib_ref, family, version, lib_ref if version else None, props
                    )
            if lib_ref not in uses[ref]:
                uses[ref].append(lib_ref)
    return list(services.values()), list(extra.values()), uses


def _merge_inventory(
    r: _report.Report,
    lib_assets: list[CryptoAsset],
    libraries: list[dict[str, Any]],
    provides: dict[str, list[str]],
) -> tuple[
    list[dict[str, Any]],
    dict[str, list[str]],
    list[dict[str, Any]],
    dict[str, list[str]],
]:
    """Union of the interop library components (#175) with the crypto
    library probe (#110) and service-linkage (#111) components, keyed by
    bom-ref.  When two sources describe the same bom-ref, properties are
    combined (no duplicates) and `provides` lists are merged in order."""
    by_ref: dict[str, dict[str, Any]] = {c["bom-ref"]: c for c in libraries}
    merged = {k: list(v) for k, v in provides.items()}

    def add(comp: dict[str, Any]) -> None:
        cur = by_ref.get(comp["bom-ref"])
        if cur is None:
            by_ref[comp["bom-ref"]] = comp
            return
        have = {(p["name"], p["value"]) for p in cur.get("properties", [])}
        for p in comp.get("properties", []):
            if (p["name"], p["value"]) not in have:
                cur.setdefault("properties", []).append(p)

    lib_comps, lib_provides, index = _crypto_library_inventory(r, lib_assets)
    for c in lib_comps:
        add(c)
    for ref, keys in lib_provides.items():
        bucket = merged.setdefault(ref, [])
        bucket += [k for k in keys if k not in bucket]
    services, extra, uses = _service_inventory(r, index)
    for c in extra:
        add(c)
    return list(by_ref.values()), merged, services, uses


def render_cbom(
    r: _report.Report,
    spec_version: str = CBOM_DEFAULT_VERSION,
    profile: str = _profiles.PROFILE_NONE,
    interop: str = INTEROP_NONE,
) -> str:
    """Render the report as a CycloneDX CBOM (JSON), specVersion 1.7 by
    default or 1.6.  Both are schema-conformant — see tests/test_cbom.py.
    The 1.6 projection is unchanged from earlier releases; 1.7 enriches
    the same assets and adds protocol / certificate components.
    `profile` (see cbom_profiles.PROFILES) adds regime annotations.
    `interop` (see INTEROP_MODES) shapes the BOM for SBOM-oriented
    consumers (#175); the default leaves output unchanged."""
    if interop not in INTEROP_MODES:
        raise ValueError(f"unsupported CBOM interop mode {interop!r}")
    if spec_version not in CBOM_VERSIONS:
        raise ValueError(f"unsupported CycloneDX version {spec_version!r}")
    if profile not in _profiles.PROFILES:
        raise ValueError(f"unsupported CBOM profile {profile!r}")
    prof = _profiles.PROFILES[profile]
    assets = canonical_assets(r)
    if prof is not None:
        assets += _profile_classical_assets(r)
    if spec_version == "1.6":
        components = [_cbom_component(a) for a in assets]
    else:
        components = [_cbom17_component(a) for a in assets]
        components += _cbom17_protocol_components(assets)
        components += _cbom17_certificate_components(r)
    lib_assets = _library_crypto_assets(r) if spec_version == "1.7" else []
    for a in lib_assets:
        comp = _cbom17_component(a)
        # `group` namespaces the algorithm by the library that provides it,
        # so consumers that key components on name (Dependency-Track merges
        # same-named components) keep GnuTLS's ML-KEM-768 apart from
        # OpenSSL's.
        comp["group"] = dict(a.properties)["library"]
        components.append(comp)
    all_assets = assets + lib_assets
    if prof is not None:
        _apply_profile_to_components(prof, all_assets, components)
    libraries: list[dict[str, Any]] = []
    provides: dict[str, list[str]] = {}
    services: list[dict[str, Any]] = []
    uses: dict[str, list[str]] = {}
    if interop != INTEROP_NONE:
        libraries, provides = _library_components(r, assets)
    if spec_version == "1.7":
        libraries, provides, services, uses = _merge_inventory(
            r, lib_assets, libraries, provides
        )
    if interop == INTEROP_DEPENDENCY_TRACK:
        _mirror_crypto_facts(components, all_assets)
        _mirror_provides(components, provides)
        components += libraries + services
    elif interop == INTEROP_SBOM_ONLY:
        # Consumers without a cryptographic-asset classifier reject the
        # whole BOM, so only the library / service components are emitted.
        components = libraries + services
        provides = {}
    else:
        components += libraries + services

    timestamp = r.generated_at or datetime.now(timezone.utc).isoformat(
        timespec="seconds"
    )
    # CycloneDX metadata.timestamp must be RFC 3339 / ISO-8601 with a
    # timezone designator.  Report.generated_at already has +00:00; if a
    # caller stamped a naive value we leave it alone — the schema accepts
    # bare date-time but downstream consumers should treat it as UTC.
    host_bom_ref = f"host/{r.hostname or 'unknown'}"
    host_props: list[dict[str, str]] = []
    if r.os:
        host_props.append({"name": "host:os", "value": r.os})
    if r.arch:
        host_props.append({"name": "host:arch", "value": r.arch})
    if r.cpu_model:
        host_props.append({"name": "host:cpu_model", "value": r.cpu_model})
    host_props += _inventory_host_props(r.inventory_metadata)
    if r.scan_mode:
        # Offline --root scan (#152): the subject is a filesystem tree.
        host_props.append({"name": "scan:mode", "value": str(r.scan_mode.get("mode"))})
        host_props.append({"name": "scan:root", "value": str(r.scan_mode.get("root"))})
    host_component: dict[str, Any] = {
        "type": "operating-system" if r.scan_mode else "device",
        "bom-ref": host_bom_ref,
        "name": r.hostname or "unknown-host",
    }
    if host_props:
        host_component["properties"] = host_props

    bom: dict[str, Any] = {
        "$schema": f"http://cyclonedx.org/schema/bom-{spec_version}.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": spec_version,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "bom-ref": f"tool/pqc-readiness@{_report.SCRIPT_VERSION}",
                        "name": "pqc-readiness",
                        "version": _report.SCRIPT_VERSION,
                    }
                ],
            },
            "component": host_component,
        },
        "components": components,
    }
    if interop != INTEROP_NONE or libraries or services:
        deps: list[dict[str, Any]] = [
            {
                "ref": host_bom_ref,
                "dependsOn": [c["bom-ref"] for c in libraries + services],
            }
        ]
        for svc in services:
            deps.append(
                {"ref": svc["bom-ref"], "dependsOn": uses.get(svc["bom-ref"], [])}
            )
        for lib in libraries:
            entry: dict[str, Any] = {"ref": lib["bom-ref"]}
            if provides.get(lib["bom-ref"]):
                entry["provides"] = provides[lib["bom-ref"]]
            deps.append(entry)
        bom["dependencies"] = deps
    if prof is not None:
        bom["metadata"]["properties"] = _profile_metadata_props(prof, r, components)
    return json.dumps(bom, indent=2)


# The output registry hands renderers only the Report, so the chosen
# --cbom-version is recorded here by the flag's action.  add_arguments()
# runs on every parser build (each main() call) and resets it, so a
# previous invocation in the same process never leaks into the next.
_selected_version = CBOM_DEFAULT_VERSION
_selected_profile = _profiles.PROFILE_NONE
_selected_interop = INTEROP_NONE


class _CbomProfileAction(argparse.Action):
    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Any,
        option_string: str | None = None,
    ) -> None:
        global _selected_profile
        _selected_profile = str(values)
        setattr(namespace, self.dest, values)


class _CbomInteropAction(argparse.Action):
    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Any,
        option_string: str | None = None,
    ) -> None:
        global _selected_interop
        _selected_interop = str(values)
        setattr(namespace, self.dest, values)


class _CbomVersionAction(argparse.Action):
    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Any,
        option_string: str | None = None,
    ) -> None:
        global _selected_version
        _selected_version = str(values)
        setattr(namespace, self.dest, values)


@_registry.register_arguments(12)
def add_arguments(ap: argparse.ArgumentParser) -> None:
    """--cbom."""
    ap.add_argument(
        "--cbom",
        action="store_true",
        help="emit a CycloneDX CBOM (cryptographic bill of materials) as JSON",
    )


# Slot 19: the end of the output-format block, so the five format flags
# stay together at the top of --help.
@_registry.register_arguments(19)
def add_version_argument(ap: argparse.ArgumentParser) -> None:
    """--cbom-version, --cbom-profile and --cbom-interop."""
    global _selected_version, _selected_profile, _selected_interop
    _selected_version = CBOM_DEFAULT_VERSION
    _selected_profile = _profiles.PROFILE_NONE
    _selected_interop = INTEROP_NONE
    ap.add_argument(
        "--cbom-version",
        choices=list(CBOM_VERSIONS),
        default=CBOM_DEFAULT_VERSION,
        action=_CbomVersionAction,
        help=f"CycloneDX specVersion for --cbom (default {CBOM_DEFAULT_VERSION})",
    )
    ap.add_argument(
        "--cbom-profile",
        choices=list(_profiles.PROFILES),
        default=_profiles.PROFILE_NONE,
        action=_CbomProfileAction,
        help=(
            "annotations for a reporting regime; federal-draft adds OMB "
            "M-23-02 / M-26-15 / EO 14412 fields (draft until CISA/NIST "
            "publish the minimum CBOM elements)"
        ),
    )
    ap.add_argument(
        "--cbom-interop",
        choices=list(INTEROP_MODES),
        default=INTEROP_NONE,
        action=_CbomInteropAction,
        help=(
            "shape --cbom for SBOM-oriented tools: dependency-track mirrors "
            "crypto details into properties and adds library components "
            "with purls; sbom-only emits just the library components (for "
            "consumers that reject cryptographic assets)"
        ),
    )


def _render_selected(r: _report.Report) -> str:
    return render_cbom(r, _selected_version, _selected_profile, _selected_interop)


_registry.register_output(_registry.OutputFormat("cbom", 10, _render_selected))
