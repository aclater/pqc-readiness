# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the CycloneDX CBOM renderer (1.7 default, 1.6 kept).

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


# Companion schemas each BOM schema $refs, per specVersion.  1.7 adds the
# cryptography-defs registry and ships its own copy of the SPDX license
# schema, so each version validates against the exact set it was
# published with (tests/fixtures/cyclonedx/1.7/README.md).
_SCHEMA_SETS: dict[str, tuple[Any, tuple[str, ...]]] = {
    "1.6": (SCHEMA_DIR, ("spdx.schema.json",)),
    "1.7": (
        SCHEMA_DIR / "1.7",
        ("spdx.schema.json", "cryptography-defs.schema.json", "jsf-0.82.schema.json"),
    ),
}


def _load_schema(version: str = "1.6") -> dict[str, Any]:
    base, _ = _SCHEMA_SETS[version]
    return json.loads((base / f"bom-{version}.schema.json").read_text())


def _validate_with_jsonschema(instance: dict[str, Any], version: str = "1.6") -> None:
    """Validate `instance` against the bundled CycloneDX schema for
    `version`.  The BOM schema $refs companion schemas that live next to
    it; we wire a referencing.Registry so the resolver finds them
    without going to the network.

    Different jsonschema versions resolve `$ref` against different bases
    (some keep the relative URL verbatim, some resolve it against the
    BOM schema's `$id`).  We register each companion under both keys
    so either resolver path finds it."""
    from urllib.parse import urljoin

    jsonschema = pytest.importorskip("jsonschema")
    base, companions = _SCHEMA_SETS[version]
    bom_schema = _load_schema(version)
    bom_id = bom_schema.get("$id", "")
    store: dict[str, Any] = {}
    for name in companions:
        schema = json.loads((base / name).read_text())
        store[name] = schema
        if bom_id:
            store[urljoin(bom_id, name)] = schema
    try:
        from referencing import Registry, Resource
        from referencing.jsonschema import DRAFT7
    except ImportError:
        # jsonschema < 4.18 still supports RefResolver with a store map.
        from jsonschema import RefResolver  # type: ignore[attr-defined]

        resolver = RefResolver.from_schema(
            bom_schema, store={**store, bom_id: bom_schema}
        )
        jsonschema.validate(instance=instance, schema=bom_schema, resolver=resolver)
        return
    registry = Registry().with_resources(
        [
            (k, Resource.from_contents(v, default_specification=DRAFT7))
            for k, v in store.items()
        ]
    )
    validator_cls = jsonschema.validators.validator_for(bom_schema)
    validator_cls(bom_schema, registry=registry).validate(instance)


@pytest.mark.parametrize("version", ["1.6", "1.7"])
def test_render_cbom_validates_against_schema(version: str) -> None:
    r = _make_report()
    bom = json.loads(pr.render_cbom(r, version))
    _validate_with_jsonschema(bom, version)


@pytest.mark.parametrize("version", ["1.6", "1.7"])
def test_render_cbom_top_level_shape(version: str) -> None:
    r = _make_report()
    bom = json.loads(pr.render_cbom(r, version))
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == version
    assert bom["$schema"] == f"http://cyclonedx.org/schema/bom-{version}.schema.json"
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


@pytest.mark.parametrize("version", ["1.6", "1.7"])
def test_render_cbom_empty_report_still_validates(version: str) -> None:
    """An empty Report must still produce a schema-valid CBOM (a BOM
    with zero components is legal) — guards against regressions where
    the renderer crashes on missing optional fields."""
    r = pr.Report(
        generated_at="2026-04-28T12:00:00+00:00",
        hostname="bare",
        arch="aarch64",
    )
    bom = json.loads(pr.render_cbom(r, version))
    assert bom["specVersion"] == version
    assert bom["components"] == []
    _validate_with_jsonschema(bom, version)


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


# ---------------------------------------------------------------------------
# CycloneDX 1.7 (#138)
# ---------------------------------------------------------------------------

_ZERO_SERIAL = "urn:uuid:00000000-0000-0000-0000-000000000000"
_CDX17 = SCHEMA_DIR / "1.7"


def _bom(version: str, r: pr.Report | None = None) -> dict[str, Any]:
    bom: dict[str, Any] = json.loads(pr.render_cbom(r or _make_report(), version))
    return bom


def _by_ref(bom: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {c["bom-ref"]: c for c in bom["components"]}


def test_cbom_1_6_output_is_byte_identical_to_pre_1_7_release() -> None:
    """--cbom-version 1.6 must not change: the golden file was rendered
    from main before #138 with the same synthetic report."""
    bom = _bom("1.6")
    bom["serialNumber"] = _ZERO_SERIAL
    golden = (SCHEMA_DIR / "cbom-1.6-golden.json").read_text()
    assert json.dumps(bom, indent=2) + "\n" == golden


def test_cbom_default_spec_version_is_1_7() -> None:
    r = _make_report()
    assert json.loads(pr.render_cbom(r))["specVersion"] == "1.7"


def test_cbom_rejects_unknown_spec_version() -> None:
    with pytest.raises(ValueError, match="unsupported CycloneDX version"):
        pr.render_cbom(_make_report(), "1.5")


def test_cbom_1_7_algorithm_families_come_from_the_registry() -> None:
    families = set(
        json.loads((_CDX17 / "cryptography-defs.schema.json").read_text())[
            "definitions"
        ]["algorithmFamiliesEnum"]["enum"]
    )
    comps = _by_ref(_bom("1.7"))
    got = {
        ref: c["cryptoProperties"]["algorithmProperties"].get("algorithmFamily")
        for ref, c in comps.items()
        if c["cryptoProperties"]["assetType"] == "algorithm"
    }
    assert got["openssl/kem/ML-KEM-768"] == "ML-KEM"
    assert got["openssl/sig/ML-DSA-87"] == "ML-DSA"
    assert got["openssl/sig/SLH-DSA-SHA2-128s"] == "SLH-DSA"
    assert got["openssl/tls-pure-pqc/MLKEM768"] == "ML-KEM"
    # Hybrids, ISA features and accelerators have no single family.
    assert got["openssl/tls-hybrid/X25519MLKEM768"] is None
    assert got["ssh/kex/hybrid/mlkem768x25519-sha256"] is None
    assert got["isa/avx512ifma"] is None
    assert {f for f in got.values() if f} <= families


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("ML-KEM-1024", ("ML-KEM", True)),
        ("MLKEM1024", ("ML-KEM", True)),
        ("ML-DSA-44", ("ML-DSA", True)),
        ("SLH-DSA-SHAKE-256f", ("SLH-DSA", True)),
        ("LMS", ("LMS", True)),
        ("XMSS", ("XMSS", True)),
        ("hqc128", ("HQC", False)),
        ("FN-DSA-512", ("FN-DSA", False)),
        ("falcon512", ("FN-DSA", False)),
        ("frodo640aes", ("FrodoKEM", False)),
        ("mceliece348864", ("Classic-McEliece", False)),
        ("X25519MLKEM768", None),
        ("SecP384r1MLKEM1024", None),
        ("mlkem1024nistp384-sha384", None),
        ("sntrup761x25519-sha512", None),
        ("AVX-512 IFMA", None),
    ],
)
def test_cdx17_algorithm_family_mapping(name: str, expected: Any) -> None:
    from pqc_readiness.render import cbom

    assert cbom._cdx17_algorithm_family(name) == expected


def test_cbom_1_7_marks_families_missing_from_the_registry() -> None:
    r = _make_report()
    r.openssl["kem_algorithms"] = ["ML-KEM-768", "hqc128", "frodo640aes"]
    bom = _bom("1.7", r)
    _validate_with_jsonschema(bom, "1.7")
    comp = _by_ref(bom)["openssl/kem/hqc128"]
    assert "algorithmFamily" not in comp["cryptoProperties"]["algorithmProperties"]
    props = {p["name"]: p["value"] for p in comp["properties"]}
    assert props["pqc-readiness:algorithmFamily"] == "HQC"
    assert (
        props["pqc-readiness:algorithmFamily:registry"]
        == "not-in-cyclonedx-1.7-registry"
    )


def test_cbom_1_7_protocol_components_link_their_algorithms() -> None:
    bom = _bom("1.7")
    comps = _by_ref(bom)
    tls = comps["protocol/tls"]["cryptoProperties"]["protocolProperties"]
    assert tls["type"] == "tls" and tls["version"] == "1.3"
    assert {a["ref"] for a in tls["relatedCryptographicAssets"]} == {
        "openssl/tls-hybrid/X25519MLKEM768",
        "openssl/tls-pure-pqc/MLKEM768",
    }
    ssh = comps["protocol/ssh"]["cryptoProperties"]["protocolProperties"]
    assert ssh["type"] == "ssh"
    # Every link resolves to a component in the same BOM.
    for proto in (tls, ssh):
        for link in proto["relatedCryptographicAssets"]:
            assert link["ref"] in comps and link["type"] == "algorithm"
    # 1.6 has no protocol grouping components.
    assert "protocol/tls" not in _by_ref(_bom("1.6"))


def test_cbom_1_7_bom_refs_are_unique() -> None:
    refs = [c["bom-ref"] for c in _bom("1.7")["components"]]
    assert len(refs) == len(set(refs))


def test_cbom_1_7_certificate_contract_for_per_cert_inventory() -> None:
    """Contract for #108: trust_store.certificates entries become 1.7
    certificate assets keyed by SHA-256 fingerprint."""
    r = _make_report()
    sha = "ab" * 32
    r.trust_store["certificates"] = [
        {
            "sha256": sha.upper(),
            "serial": "0a1b2c",
            "subject": "CN=Example Root",
            "issuer": "CN=Example Root",
            "not_before": "2020-01-01T00:00:00+00:00",
            "not_after": "2099-01-01T00:00:00+00:00",
            "category": "classical",
        },
        {"sha256": "not-a-fingerprint"},  # skipped: no valid join key
    ]
    bom = _bom("1.7", r)
    _validate_with_jsonschema(bom, "1.7")
    certs = [
        c
        for c in bom["components"]
        if c["cryptoProperties"]["assetType"] == "certificate"
    ]
    assert len(certs) == 1
    cert = certs[0]
    assert cert["bom-ref"] == f"cert/sha256:{sha}"
    props = cert["cryptoProperties"]["certificateProperties"]
    assert props["fingerprint"] == {"alg": "SHA-256", "content": sha}
    assert props["serialNumber"] == "0a1b2c"
    assert props["certificateState"] == [{"state": "active"}]
    # 1.6 output ignores the list.
    assert all(
        c["cryptoProperties"]["assetType"] != "certificate"
        for c in _bom("1.6", r)["components"]
    )


@pytest.mark.parametrize(
    ("not_before", "not_after", "state"),
    [
        ("2099-01-01T00:00:00+00:00", "2100-01-01T00:00:00+00:00", "pre-activation"),
        ("2000-01-01T00:00:00Z", "2001-01-01T00:00:00Z", "deactivated"),
        ("2000-01-01T00:00:00+00:00", "2999-01-01T00:00:00+00:00", "active"),
        ("garbage", "2001-01-01T00:00:00Z", None),
        ("2000-01-01T00:00:00", "2001-01-01T00:00:00", None),  # naive: unknown zone
    ],
)
def test_cdx17_certificate_state(not_before: str, not_after: str, state: Any) -> None:
    from pqc_readiness.render import cbom

    assert cbom._cdx17_certificate_state(not_before, not_after) == state


def test_cli_cbom_version_selection_does_not_leak_between_runs(
    monkeypatch, capsys
) -> None:
    """--cbom-version is recorded by an argparse action; a later main()
    without the flag must fall back to the 1.7 default."""
    from pqc_readiness import cli

    monkeypatch.setattr(cli, "collect_report", lambda args: _make_report())
    cli.main(["--cbom", "--cbom-version", "1.6"])
    assert json.loads(capsys.readouterr().out)["specVersion"] == "1.6"
    cli.main(["--cbom"])
    assert json.loads(capsys.readouterr().out)["specVersion"] == "1.7"
