# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the SPDX 3.0 JSON-LD renderer.

The renderer is a pure function over the Report dataclass.  We build a
synthetic Report with one of every detection source populated, render
the SPDX document, and validate against the bundled SPDX 3.0.1 JSON-LD
context.  SPDX 3.0.1 does not publish a JSON Schema (validation is via
OWL/SHACL), so the structural validator implements the minimum invariants
the spec requires for a JSON-LD-serialised SPDX document:

  - top-level @context resolves to the canonical 3.0.1 context URL
  - top-level @graph is an array of SPDX objects
  - every object's `type` is a class defined in the bundled context
  - every property used on an object is a term in the bundled context
  - every Element (anything with `spdxId`) carries a CreationInfo with
    specVersion, created, createdBy
  - every reference (CreationInfo.createdBy, Sbom.element, etc.) resolves
    to an spdxId or @id within the same document

We bundle the official context file under tests/fixtures/spdx/ so CI is
hermetic — no network calls during pytest."""

from __future__ import annotations

import json
import re
from typing import Any

import pqc_readiness as pr
from conftest import FIXTURES

SPDX_CONTEXT_PATH = FIXTURES / "spdx" / "spdx-3.0.1-context.jsonld"

# Property keys that are JSON-LD reserved or expected aliases that the
# context does not need to map (the spec normatively defines them).
JSONLD_BUILTINS = frozenset({"@context", "@graph", "@id", "@type"})

# Keys used universally on Elements.  `type` and `spdxId` are aliased
# via the SPDX 3.0.1 context to @type and @id respectively, so they
# already appear as terms; this set is for keys that some validators
# treat as core JSON-LD scaffolding.
ELEMENT_REQUIRED_KEYS = ("type", "spdxId", "creationInfo", "name")


def _load_context() -> dict[str, Any]:
    return json.loads(SPDX_CONTEXT_PATH.read_text())["@context"]


def _make_report() -> pr.Report:
    """A synthetic Report covering every input source the SPDX renderer
    consumes.  Mirrors tests/test_cbom.py::_make_report so that both
    renderers are tested against the same input shape."""
    return pr.Report(
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
            "kem_algorithms": ["ML-KEM-768"],
            "sig_algorithms": ["ML-DSA-65", "SLH-DSA-SHA2-128s"],
            "tls_groups": {
                "hybrid": ["X25519MLKEM768"],
                "pure_pqc": ["MLKEM768"],
                "classical": ["X25519"],
            },
        },
        ssh_pqc={
            "available": True,
            "version": "9.9p1",
            "kex_groups": {
                "hybrid": ["mlkem768x25519-sha256"],
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
        # Findings: trigger the SLH-DSA-in-TLS rule plus the
        # classical-only-trust-store rule via the inputs above.
        replace_required=False,
        fips={"kernel": False},
    )


def _validate_against_context(doc: dict[str, Any]) -> None:
    """Structural validator for SPDX 3.0.1 JSON-LD output.

    Mirrors the constraints in the SPDX 3.0.1 spec's JSON-LD
    serialization section without requiring a SHACL/OWL toolchain in CI:

      - @context references the canonical 3.0.1 URL
      - every @graph entry's `type` is a class in the bundled context
      - every property key on an entry is a term in the bundled context
      - every Element has the CreationInfo invariants
    """
    assert doc.get("@context") == pr.SPDX_CONTEXT_URL, (
        f"@context must be {pr.SPDX_CONTEXT_URL}, got {doc.get('@context')!r}"
    )
    graph = doc.get("@graph")
    assert isinstance(graph, list) and graph, "@graph must be a non-empty array"

    ctx = _load_context()

    for elem in graph:
        assert isinstance(elem, dict), "every graph entry must be an object"
        type_name = elem.get("type")
        assert isinstance(type_name, str), "every entry must have a `type`"
        assert type_name in ctx, (
            f"unknown SPDX type {type_name!r} (not a term in 3.0.1 context)"
        )
        for key in elem.keys():
            if key in JSONLD_BUILTINS:
                continue
            assert key in ctx, (
                f"property {key!r} on type {type_name!r} is not a term in "
                "the SPDX 3.0.1 context"
            )

    # Every Element (anything with spdxId) must carry a valid CreationInfo
    # with the spec-required fields and a 3.0.x specVersion.
    for elem in graph:
        if "spdxId" not in elem:
            continue
        ci = elem.get("creationInfo")
        assert isinstance(ci, dict), (
            f"Element {elem.get('spdxId')!r} missing creationInfo"
        )
        assert ci.get("type") == "CreationInfo"
        assert isinstance(ci.get("specVersion"), str)
        assert ci["specVersion"].startswith("3.0."), (
            f"specVersion {ci.get('specVersion')!r} not a 3.0.x value"
        )
        assert isinstance(ci.get("created"), str) and ci["created"]
        created_by = ci.get("createdBy")
        assert isinstance(created_by, list) and created_by, (
            "CreationInfo.createdBy must be a non-empty list"
        )

    # All references (createdBy, element, rootElement, from, to,
    # security_assessedElement) must resolve within the document.
    spdx_ids = {e["spdxId"] for e in graph if "spdxId" in e}
    for elem in graph:
        ci = elem.get("creationInfo") or {}
        for ref in ci.get("createdBy") or []:
            assert ref in spdx_ids, f"dangling createdBy reference {ref!r}"
        for prop in ("rootElement", "element", "to"):
            for ref in elem.get(prop) or []:
                assert ref in spdx_ids, (
                    f"dangling {prop} reference {ref!r} on {elem.get('type')}"
                )
        for prop in ("from", "security_assessedElement"):
            ref = elem.get(prop)
            if isinstance(ref, str):
                assert ref in spdx_ids, f"dangling {prop} reference {ref!r}"


def test_render_spdx_validates_against_context() -> None:
    r = _make_report()
    doc = json.loads(pr.render_spdx(r))
    _validate_against_context(doc)


def test_render_spdx_top_level_shape() -> None:
    r = _make_report()
    doc = json.loads(pr.render_spdx(r))
    assert doc["@context"] == "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"
    assert isinstance(doc["@graph"], list)
    types = [e.get("type") for e in doc["@graph"]]
    assert "SpdxDocument" in types
    assert "software_Sbom" in types
    # The host package and at least one asset package
    assert types.count("software_Package") >= 2


def test_render_spdx_profile_conformance_includes_security() -> None:
    r = _make_report()
    doc = json.loads(pr.render_spdx(r))
    sbom = next(e for e in doc["@graph"] if e["type"] == "software_Sbom")
    assert "security" in sbom["profileConformance"]
    assert "software" in sbom["profileConformance"]
    assert "core" in sbom["profileConformance"]


def test_render_spdx_data_license_is_cc0() -> None:
    """SPDX 3.0 documents shipped publicly conventionally use CC0 for
    the data licence so consumers can redistribute the document text."""
    r = _make_report()
    doc = json.loads(pr.render_spdx(r))
    sd = next(e for e in doc["@graph"] if e["type"] == "SpdxDocument")
    assert sd["dataLicense"] == "https://spdx.org/licenses/CC0-1.0"


def _by_id(graph: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {e["spdxId"]: e for e in graph if "spdxId" in e}


def test_render_spdx_canonical_assets_become_packages() -> None:
    r = _make_report()
    doc = json.loads(pr.render_spdx(r))
    by_id = _by_id(doc["@graph"])

    expected_keys = {a.key for a in pr.canonical_assets(r)}
    assert expected_keys, "test setup should produce canonical assets"

    asset_ids = [
        spdx_id
        for spdx_id in by_id
        if ":asset:" in spdx_id and by_id[spdx_id]["type"] == "software_Package"
    ]
    assert len(asset_ids) == len(expected_keys), (
        "every canonical asset must be projected to one software_Package"
    )

    # Every emitted package's description carries the canonical
    # category=… line so consumers can correlate with --cbom output.
    for spdx_id in asset_ids:
        desc = by_id[spdx_id].get("description", "")
        assert re.search(r"^category=", desc, re.MULTILINE), (
            f"asset package {spdx_id!r} missing category= in description"
        )


def test_render_spdx_pqc_algorithm_metadata_is_preserved() -> None:
    r = _make_report()
    doc = json.loads(pr.render_spdx(r))
    by_id = _by_id(doc["@graph"])

    ml_kem = next(
        e
        for e in by_id.values()
        if e["type"] == "software_Package" and e.get("name") == "ML-KEM-768"
    )
    # ML-KEM-768 is NIST PQC category 3 with parameter set "768"
    assert ml_kem["software_packageVersion"] == "768"
    ext_ids = ml_kem.get("externalIdentifier") or []
    assert any(
        ei.get("identifier") == "nist-pqc-category-3" for ei in ext_ids
    ), "expected NIST category 3 externalIdentifier on ML-KEM-768"


def test_render_spdx_findings_become_security_vulnerabilities() -> None:
    """The SARIF rule predicates fire the same way for SPDX — each
    finding becomes a security_Vulnerability + a VEX `affects`
    relationship to the host."""
    r = _make_report()
    doc = json.loads(pr.render_spdx(r))
    findings = pr.build_findings(r)
    assert findings, "test fixture should produce at least one finding"

    vulns = [e for e in doc["@graph"] if e["type"] == "security_Vulnerability"]
    vex = [
        e
        for e in doc["@graph"]
        if e["type"] == "security_VexAffectedVulnAssessmentRelationship"
    ]
    assert len(vulns) == len(findings)
    assert len(vex) == len(findings)

    finding_ids = {f.rule_id for f in findings}
    vuln_rule_ids = {
        ext.get("identifier")
        for v in vulns
        for ext in v.get("externalIdentifier") or []
    }
    assert finding_ids <= vuln_rule_ids


def test_render_spdx_vex_relationships_reference_host() -> None:
    r = _make_report()
    doc = json.loads(pr.render_spdx(r))
    by_id = _by_id(doc["@graph"])
    host_id = next(
        spdx_id
        for spdx_id, e in by_id.items()
        if e["type"] == "software_Package" and spdx_id.endswith(":host")
    )
    vex = [
        e
        for e in doc["@graph"]
        if e["type"] == "security_VexAffectedVulnAssessmentRelationship"
    ]
    for rel in vex:
        assert rel["relationshipType"] == "affects"
        assert rel["from"] in by_id
        assert by_id[rel["from"]]["type"] == "security_Vulnerability"
        assert host_id in rel["to"]
        assert rel["security_assessedElement"] == host_id


def test_render_spdx_creator_agent_is_self_referencing() -> None:
    """Every Element's CreationInfo.createdBy must resolve in-document.
    The pqc-readiness SoftwareAgent is the bootstrap creator and is its
    own createdBy — that self-reference is permitted by the spec and
    keeps the document closed (no external Agent registry required)."""
    r = _make_report()
    doc = json.loads(pr.render_spdx(r))
    by_id = _by_id(doc["@graph"])
    agent = next(e for e in by_id.values() if e["type"] == "SoftwareAgent")
    self_id = agent["spdxId"]
    assert agent["creationInfo"]["createdBy"] == [self_id]
    # Every other element should also reference this same creator.
    for spdx_id, e in by_id.items():
        if spdx_id == self_id:
            continue
        assert e["creationInfo"]["createdBy"] == [self_id]


def test_render_spdx_empty_report_still_validates() -> None:
    """An empty Report must still produce a structurally-valid SPDX 3.0
    document — SpdxDocument + Sbom + host package + creator, no
    cryptographic asset packages, no findings."""
    r = pr.Report(
        generated_at="2026-04-28T12:00:00+00:00",
        hostname="bare",
        arch="aarch64",
    )
    doc = json.loads(pr.render_spdx(r))
    _validate_against_context(doc)
    types = [e["type"] for e in doc["@graph"]]
    assert "SpdxDocument" in types
    assert "software_Sbom" in types
    # exactly one software_Package: the host (no canonical assets).
    assert types.count("software_Package") == 1
    assert "security_Vulnerability" not in types


def test_render_spdx_same_canonical_inputs_as_cbom() -> None:
    """The acceptance criterion: --cbom and --spdx project from the same
    canonical asset list, no detection-logic duplication."""
    r = _make_report()
    canonical = pr.canonical_assets(r)
    cbom = json.loads(pr.render_cbom(r))
    spdx = json.loads(pr.render_spdx(r))

    cbom_names = sorted(c["name"] for c in cbom["components"])
    spdx_asset_names = sorted(
        e.get("name", "")
        for e in spdx["@graph"]
        if e.get("type") == "software_Package" and ":asset:" in e.get("spdxId", "")
    )
    expected_names = sorted(a.name for a in canonical)
    assert cbom_names == expected_names
    assert spdx_asset_names == expected_names


def test_render_spdx_arch_appears_in_host_package() -> None:
    """Host context (OS / arch) is surfaced on the host software_Package
    so SPDX consumers can filter by platform without parsing CBOM."""
    cases = ["x86_64", "aarch64", "s390x"]
    for arch in cases:
        r = pr.Report(
            generated_at="2026-04-28T12:00:00+00:00",
            hostname="h",
            arch=arch,
            os="Some OS",
        )
        doc = json.loads(pr.render_spdx(r))
        host = next(
            e
            for e in doc["@graph"]
            if e.get("type") == "software_Package"
            and e.get("spdxId", "").endswith(":host")
        )
        assert arch in host.get("summary", "")


def test_cli_spdx_flag_routes_to_render_spdx(monkeypatch, capsys) -> None:
    """The --spdx CLI flag must produce the same output as
    render_spdx() so contract tests can hit either path."""
    fake_report = pr.Report(
        generated_at="2026-04-28T12:00:00+00:00",
        hostname="cliprobe",
        arch="x86_64",
    )
    monkeypatch.setattr(pr, "render_spdx", lambda r: '{"@context":"x"}')
    # Bypass the long detection pipeline by patching the heavy probes.
    monkeypatch.setattr(pr, "cpu_flags", lambda arch: set())
    monkeypatch.setattr(pr, "memory_info", lambda: (1.0, 1.0))
    monkeypatch.setattr(pr, "core_counts", lambda: (1, 1))
    monkeypatch.setattr(pr, "detect_isa", lambda *_a, **_k: ({}, 0))
    monkeypatch.setattr(pr, "isa_tier", lambda *_a, **_k: ("poor", "no SIMD"))
    monkeypatch.setattr(pr, "memory_tier", lambda *_a, **_k: ("poor", "low RAM"))
    monkeypatch.setattr(pr, "detect_runtime_environment", lambda: {})
    monkeypatch.setattr(pr, "detect_accelerators", lambda: [])
    monkeypatch.setattr(pr, "detect_network_hsms", lambda: [])
    monkeypatch.setattr(pr, "detect_os", lambda: {"family": "fedora"})
    monkeypatch.setattr(pr, "detect_pkcs11_modules", lambda *_a, **_k: [])
    monkeypatch.setattr(pr, "detect_kernel_crypto_hw", lambda: [])
    monkeypatch.setattr(pr, "detect_ktls", lambda: None)
    monkeypatch.setattr(pr, "detect_fips_mode", lambda: {})
    monkeypatch.setattr(pr, "detect_tpm_pqc", lambda: {})
    monkeypatch.setattr(
        pr,
        "openssl_capability",
        lambda *_a, **_k: {"available": False},
    )
    monkeypatch.setattr(pr, "detect_ssh_pqc", lambda *_a, **_k: {})
    monkeypatch.setattr(pr, "detect_ipsec_pqc", lambda *_a, **_k: {})
    monkeypatch.setattr(pr, "detect_nss", lambda: {})
    monkeypatch.setattr(pr, "detect_kernel_info", lambda *_a, **_k: {})
    monkeypatch.setattr(pr, "interpret_fips", lambda *_a, **_k: {"kernel": False})
    monkeypatch.setattr(pr, "fips_pqc_conflict_check", lambda *_a, **_k: {})
    monkeypatch.setattr(pr, "evaluate_cnsa_2_0", lambda *_a, **_k: {})
    monkeypatch.setattr(pr, "has_dedicated_pqc_silicon", lambda *_a, **_k: False)
    monkeypatch.setattr(
        pr, "overall_verdict", lambda *_a, **_k: ("poor", "low", 3, "")
    )

    monkeypatch.setattr("sys.argv", ["pqc-readiness", "--spdx", "--no-color"])
    rc = pr.main()
    out = capsys.readouterr().out
    assert rc == 3  # poor verdict exit code, unchanged
    assert out.strip() == '{"@context":"x"}'
    _ = fake_report  # silence unused-warning if linters don't see monkeypatching
