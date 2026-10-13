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


# Canonical cryptographic-asset model ----------------------------------------
#
# Both --cbom (CycloneDX 1.6) and --spdx (SPDX 3.0 JSON-LD) project from
# the same canonical CryptoAsset list, so detection logic lives in one
# place and the renderers are pure projections.  A single source of
# truth means a new detection rule shows up in every output format
# without a renderer-side patch.
#
# Refs:
#   https://cyclonedx.org/docs/1.6/json/  (specVersion 1.6)
#   https://csrc.nist.gov/pubs/ir/8547/final  (NIST IR 8547)
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
# `components` are populated with `cryptographic-asset` entries.  NIST IR
# 8547 references CycloneDX 1.6 as the standard for cryptographic inventory
# exchange, so emitting this shape lets downstream PQC-migration tooling
# ingest pqc-readiness output without writing a bespoke translator.


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


def render_cbom(r: _report.Report) -> str:
    """Render the report as a CycloneDX 1.6 CBOM (JSON).  The output is
    schema-conformant — see tests/test_cbom.py for the schema check."""
    components = [_cbom_component(a) for a in canonical_assets(r)]

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
    host_component: dict[str, Any] = {
        "type": "device",
        "bom-ref": host_bom_ref,
        "name": r.hostname or "unknown-host",
    }
    if host_props:
        host_component["properties"] = host_props

    bom: dict[str, Any] = {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
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
    return json.dumps(bom, indent=2)


@_registry.register_arguments(12)
def add_arguments(ap: argparse.ArgumentParser) -> None:
    """--cbom."""
    ap.add_argument(
        "--cbom",
        action="store_true",
        help="emit CycloneDX 1.6 CBOM JSON (NIST IR 8547)",
    )


_registry.register_output(_registry.OutputFormat("cbom", 10, lambda r: render_cbom(r)))
