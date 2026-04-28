# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the CycloneDX 1.6 CBOM renderer.

The renderer is a pure function over the Report dataclass, so we build
a synthetic Report with one of every detection source populated, render
the CBOM, parse the JSON, and validate the result against the official
CycloneDX 1.6 schema bundled under tests/fixtures/cyclonedx/.

We keep the schema files in-tree (not fetched at test time) so CI is
hermetic — no network calls during pytest."""

from __future__ import annotations

import json
from typing import Any

import pytest

import pqc_readiness as pr
from conftest import FIXTURES

SCHEMA_DIR = FIXTURES / "cyclonedx"
BOM_SCHEMA_PATH = SCHEMA_DIR / "bom-1.6.schema.json"
SPDX_SCHEMA_PATH = SCHEMA_DIR / "spdx.schema.json"


def _make_report() -> pr.Report:
    """A synthetic Report covering every input source the CBOM renderer
    consumes.  Values are intentionally minimal — we test the mapping,
    not the detection layer."""
    r = pr.Report(
        generated_at="2026-04-28T12:00:00+00:00",
        hostname="testhost.example",
        os="Fedora Linux 44 (Workstation Edition)",
        arch="x86_64",
        cpu_model="Test CPU",
        cores_logical=8,
        cores_physical=8,
        mem_total_gb=32.0,
        mem_avail_gb=24.0,
        isa_features={
            "avx512ifma": {
                "name": "AVX-512 IFMA",
                "purpose": "52-bit FMA; lattice multiplication",
                "weight": "3",
            },
            "avx512vbmi": {
                "name": "AVX-512 VBMI",
                "purpose": "Permute-bytes; major Keccak speedup",
                "weight": "3",
            },
        },
        accelerators=[
            {
                "kind": "hsm",
                "name": "Test HSM",
                "detail": "PCI vendor:device",
                "pqc_capable": False,
            },
            {
                "kind": "tpm",
                "name": "TPM 2.0",
                "detail": "/dev/tpm0",
                "pqc_capable": False,
            },
        ],
        pkcs11_modules=["/usr/lib64/pkcs11/libfoo.so"],
        tpm_pqc={
            "present": True,
            "pqc_advertised": False,
            "note": "TPM 2.0 PQC algorithms not advertised",
        },
        openssl={
            "available": True,
            "version": "3.5.5",
            "pqc_native": True,
            "kem_algorithms": ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"],
            "sig_algorithms": ["ML-DSA-65", "ML-DSA-87", "SLH-DSA-SHA2-128s"],
            "tls_groups": {
                "hybrid": ["X25519MLKEM768"],
                "pure_pqc": ["MLKEM768"],
                "classical": ["X25519", "P-256"],
            },
        },
        ssh_pqc={
            "available": True,
            "version": "9.9p1",
            "kex_count": 12,
            "pqc_kex": ["mlkem768x25519-sha256", "sntrup761x25519-sha512"],
            "kex_groups": {
                "hybrid": ["mlkem768x25519-sha256", "sntrup761x25519-sha512"],
                "pure_pqc": [],
            },
        },
        ipsec_pqc={
            "available": True,
            "implementation": "strongswan",
            "pqc": True,
            "evidence": "ML-KEM",
        },
        trust_store={
            "available": True,
            "scanned_dirs": ["/etc/pki/ca-trust/extracted/pem"],
            "total_certs": 142,
            "pqc_certs": 0,
            "hybrid_certs": 0,
        },
    )
    return r


def _load_schema() -> dict[str, Any]:
    return json.loads(BOM_SCHEMA_PATH.read_text())


def _validate_with_jsonschema(instance: dict[str, Any]) -> None:
    """Validate `instance` against bundled CycloneDX 1.6 schema.  The
    schema $refs `spdx.schema.json`, which lives next to the BOM schema
    file; we wire a referencing.Registry so the resolver finds it
    without going to the network.

    Different jsonschema versions resolve `$ref` against different bases
    (some keep the relative URL verbatim, some resolve it against the
    BOM schema's `$id`).  We register the SPDX schema under both keys
    so either resolver path finds it."""
    from urllib.parse import urljoin

    jsonschema = pytest.importorskip("jsonschema")
    bom_schema = _load_schema()
    spdx_schema = json.loads(SPDX_SCHEMA_PATH.read_text())
    spdx_keys: list[str] = ["spdx.schema.json"]
    bom_id = bom_schema.get("$id", "")
    if bom_id:
        spdx_keys.append(urljoin(bom_id, "spdx.schema.json"))
    try:
        from referencing import Registry, Resource
        from referencing.jsonschema import DRAFT7
    except ImportError:
        # jsonschema < 4.18 still supports RefResolver with a store map.
        from jsonschema import RefResolver  # type: ignore[attr-defined]

        resolver = RefResolver.from_schema(
            bom_schema,
            store={**{k: spdx_schema for k in spdx_keys}, bom_id: bom_schema},
        )
        jsonschema.validate(
            instance=instance,
            schema=bom_schema,
            resolver=resolver,
        )
        return
    spdx_resource = Resource.from_contents(
        spdx_schema,
        default_specification=DRAFT7,
    )
    registry = Registry().with_resources([(k, spdx_resource) for k in spdx_keys])
    validator_cls = jsonschema.validators.validator_for(bom_schema)
    validator_cls(bom_schema, registry=registry).validate(instance)


def test_render_cbom_validates_against_schema() -> None:
    r = _make_report()
    bom = json.loads(pr.render_cbom(r))
    _validate_with_jsonschema(bom)


def test_render_cbom_top_level_shape() -> None:
    r = _make_report()
    bom = json.loads(pr.render_cbom(r))
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.6"
    assert bom["serialNumber"].startswith("urn:uuid:")
    assert bom["version"] == 1
    assert bom["metadata"]["timestamp"] == "2026-04-28T12:00:00+00:00"
    tool_names = [c["name"] for c in bom["metadata"]["tools"]["components"]]
    assert "pqc-readiness" in tool_names
    assert bom["metadata"]["component"]["name"] == "testhost.example"
    assert bom["metadata"]["component"]["type"] == "device"


def _components_by_ref(bom: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {c["bom-ref"]: c for c in bom["components"]}


def _has_property(component: dict[str, Any], name: str, value: str) -> bool:
    return any(
        p.get("name") == name and p.get("value") == value
        for p in component.get("properties", [])
    )


def test_render_cbom_provenance_on_every_asset() -> None:
    r = _make_report()
    bom = json.loads(pr.render_cbom(r))
    assert bom["components"], "expected at least one cryptographic-asset"
    expected = f"pqc-readiness@{pr.SCRIPT_VERSION}"
    for c in bom["components"]:
        assert c["type"] == "cryptographic-asset"
        assert _has_property(c, "detectedBy", expected), (
            f"component {c.get('bom-ref')} missing detectedBy provenance"
        )


def test_render_cbom_isa_features_emitted() -> None:
    r = _make_report()
    bom = json.loads(pr.render_cbom(r))
    refs = _components_by_ref(bom)
    for flag in ("avx512ifma", "avx512vbmi"):
        c = refs[f"isa/{flag}"]
        algo = c["cryptoProperties"]["algorithmProperties"]
        assert algo["executionEnvironment"] == "hardware"
        assert algo["implementationPlatform"] == "x86_64"


def test_render_cbom_accelerator_pkcs11_tpm_emitted() -> None:
    r = _make_report()
    bom = json.loads(pr.render_cbom(r))
    refs = _components_by_ref(bom)
    accel_refs = [k for k in refs if k.startswith("accel/")]
    assert len(accel_refs) == 2
    pkcs_refs = [k for k in refs if k.startswith("pkcs11/")]
    assert len(pkcs_refs) == 1
    assert refs[pkcs_refs[0]]["cryptoProperties"]["assetType"] == "protocol"
    tpm = refs["tpm/pqc"]
    assert tpm["cryptoProperties"]["assetType"] == "algorithm"


def test_render_cbom_openssl_pqc_algorithms_emitted() -> None:
    r = _make_report()
    bom = json.loads(pr.render_cbom(r))
    refs = _components_by_ref(bom)
    kem = refs["openssl/kem/ML-KEM-768"]
    algo = kem["cryptoProperties"]["algorithmProperties"]
    assert algo["primitive"] == "kem"
    assert algo["parameterSetIdentifier"] == "768"
    # NIST PQC categories: 512=1, 768=3, 1024=5
    assert algo["nistQuantumSecurityLevel"] == 3
    sig = refs["openssl/sig/ML-DSA-87"]
    sig_algo = sig["cryptoProperties"]["algorithmProperties"]
    assert sig_algo["primitive"] == "signature"
    assert sig_algo["nistQuantumSecurityLevel"] == 5
    hybrid = refs["openssl/tls-hybrid/X25519MLKEM768"]
    assert hybrid["cryptoProperties"]["algorithmProperties"]["primitive"] == "combiner"


def test_render_cbom_ssh_kex_emitted() -> None:
    r = _make_report()
    bom = json.loads(pr.render_cbom(r))
    refs = _components_by_ref(bom)
    hybrid_kex = refs["ssh/kex/hybrid/mlkem768x25519-sha256"]
    algo = hybrid_kex["cryptoProperties"]["algorithmProperties"]
    assert algo["primitive"] == "key-agree"


def test_render_cbom_ipsec_emitted_as_protocol() -> None:
    r = _make_report()
    bom = json.loads(pr.render_cbom(r))
    refs = _components_by_ref(bom)
    ipsec = refs["ipsec/strongswan"]
    assert ipsec["cryptoProperties"]["assetType"] == "protocol"
    assert _has_property(ipsec, "ipsec:pqc_advertised", "true")


def test_render_cbom_trust_store_summary_emitted() -> None:
    r = _make_report()
    bom = json.loads(pr.render_cbom(r))
    refs = _components_by_ref(bom)
    ts = refs["trust-store/summary"]
    assert ts["cryptoProperties"]["assetType"] == "related-crypto-material"
    assert _has_property(ts, "trust_store:total_certs", "142")


def test_render_cbom_empty_report_still_validates() -> None:
    """An empty Report must still produce a schema-valid CBOM (a BOM
    with zero components is legal in 1.6) — guards against regressions
    where the renderer crashes on missing optional fields."""
    r = pr.Report(
        generated_at="2026-04-28T12:00:00+00:00",
        hostname="bare",
        arch="aarch64",
    )
    bom = json.loads(pr.render_cbom(r))
    assert bom["specVersion"] == "1.6"
    assert bom["components"] == []
    _validate_with_jsonschema(bom)


def test_render_cbom_arch_mapping_to_implementation_platform() -> None:
    """CycloneDX has a fixed enum for implementationPlatform; pqc-
    readiness uses different arch strings (e.g. `aarch64`) — verify the
    mapping table collapses each known arch into the schema enum."""
    cases = {
        "x86_64": "x86_64",
        "amd64": "x86_64",
        "aarch64": "armv8-a",
        "arm64": "armv8-a",
        "s390x": "s390x",
        "weird-future-arch": "unknown",
    }
    for arch, expected in cases.items():
        r = pr.Report(
            generated_at="2026-04-28T12:00:00+00:00",
            hostname="h",
            arch=arch,
            isa_features={"x": {"name": "X", "purpose": "p", "weight": "1"}},
        )
        bom = json.loads(pr.render_cbom(r))
        plat = bom["components"][0]["cryptoProperties"]["algorithmProperties"][
            "implementationPlatform"
        ]
        assert plat == expected, f"{arch} → {plat} (expected {expected})"
