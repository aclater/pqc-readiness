"""CycloneDX CBOM output (--cbom)."""

from __future__ import annotations

import argparse
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

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


def _cbom17_certificate_components(r: _report.Report) -> list[dict[str, Any]]:
    """One `certificate` asset per entry in `trust_store.certificates`.

    Contract for the per-certificate inventory (#108): each entry is a
    dict with `sha256` (hex, required — the join key) and optionally
    `serial`, `subject`, `issuer`, `not_before`, `not_after` (ISO 8601)
    and `category`.  Today's trust-store scan is summary-only, so this
    emits nothing until #108 populates the list."""
    ts = r.trust_store or {}
    out: list[dict[str, Any]] = []
    for cert in ts.get("certificates") or []:
        sha = str(cert.get("sha256") or "").lower()
        if len(sha) != 64:
            continue
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
            extra.append(
                {"name": "trust_store:category", "value": str(cert["category"])}
            )
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
    classification from their trust-store category."""
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
                    if p["name"] == "trust_store:category"
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


def render_cbom(
    r: _report.Report,
    spec_version: str = CBOM_DEFAULT_VERSION,
    profile: str = _profiles.PROFILE_NONE,
) -> str:
    """Render the report as a CycloneDX CBOM (JSON), specVersion 1.7 by
    default or 1.6.  Both are schema-conformant — see tests/test_cbom.py.
    The 1.6 projection is unchanged from earlier releases; 1.7 enriches
    the same assets and adds protocol / certificate components.
    `profile` (see cbom_profiles.PROFILES) adds regime annotations."""
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
    if prof is not None:
        _apply_profile_to_components(prof, assets, components)

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
    if prof is not None:
        bom["metadata"]["properties"] = _profile_metadata_props(prof, r, components)
    return json.dumps(bom, indent=2)


# The output registry hands renderers only the Report, so the chosen
# --cbom-version is recorded here by the flag's action.  add_arguments()
# runs on every parser build (each main() call) and resets it, so a
# previous invocation in the same process never leaks into the next.
_selected_version = CBOM_DEFAULT_VERSION
_selected_profile = _profiles.PROFILE_NONE


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
    """--cbom-version and --cbom-profile."""
    global _selected_version, _selected_profile
    _selected_version = CBOM_DEFAULT_VERSION
    _selected_profile = _profiles.PROFILE_NONE
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


def _render_selected(r: _report.Report) -> str:
    return render_cbom(r, _selected_version, _selected_profile)


_registry.register_output(_registry.OutputFormat("cbom", 10, _render_selected))
