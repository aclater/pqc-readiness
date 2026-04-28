# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the SARIF 2.1.0 finding renderer.

The renderer is a pure function over the Report dataclass.  We build
synthetic Reports that selectively trigger each rule, render SARIF,
parse the JSON, and validate it against the bundled SARIF 2.1.0 schema.

The schema lives in tests/fixtures/sarif/ so CI is hermetic — no
network calls during pytest."""

from __future__ import annotations

import json
from typing import Any

import pytest

import pqc_readiness as pr
from conftest import FIXTURES

SCHEMA_PATH = FIXTURES / "sarif" / "sarif-2.1.0.schema.json"


def _load_schema() -> dict[str, Any]:
    return json.loads(SCHEMA_PATH.read_text())


def _validate(instance: dict[str, Any]) -> None:
    """Validate a SARIF log against the bundled 2.1.0 schema.

    The schema is self-contained Draft-07; no external $ref resolution
    is required, so a plain Draft7Validator is enough."""
    jsonschema = pytest.importorskip("jsonschema")
    schema = _load_schema()
    jsonschema.Draft7Validator(schema).validate(instance)


def _empty_report() -> pr.Report:
    """A Report with no triggering conditions — every rule should be
    silent.  Used as the base for selectively enabling one rule at a
    time."""
    return pr.Report(
        generated_at="2026-04-28T12:00:00+00:00",
        hostname="testhost.example",
        os="Fedora Linux 44",
        arch="x86_64",
    )


def _full_trigger_report() -> pr.Report:
    """A Report that trips every rule at once — used for the all-rules-
    fire test and for the schema-validation smoke test."""
    return pr.Report(
        generated_at="2026-04-28T12:00:00+00:00",
        hostname="testhost.example",
        os="Fedora Linux 44",
        arch="x86_64",
        openssl={
            "available": True,
            "version": "OpenSSL 3.0.0",
            "pqc_native": False,
            "kem_algorithms": ["ML-KEM-768"],
            "sig_algorithms": ["ML-DSA-65", "SLH-DSA-SHA2-128s"],
            "upgrade_path": {"recommendation": "upgrade to OpenSSL 3.5"},
        },
        fips={"kernel": True, "openssl_provider": None},
        fips_pqc_conflict={"in_conflict": True, "explanation": "FIPS conflict"},
        isa_tier="poor",
        isa_score=0,
        isa_reason="no PQC-relevant SIMD detected",
        replace_required=True,
        trust_store={
            "available": True,
            "scanned_dirs": ["/etc/pki/ca-trust/extracted/pem"],
            "total_certs": 142,
            "pqc_certs": 0,
            "hybrid_certs": 0,
        },
        accelerators=[
            {
                "kind": "network_hsm",
                "name": "Test Network HSM",
                "detail": "client config present",
                "pqc_capable": False,
            },
        ],
    )


def test_render_sarif_top_level_shape() -> None:
    log = json.loads(pr.render_sarif(_empty_report()))
    assert log["version"] == "2.1.0"
    assert log["$schema"].endswith("sarif-2.1.0.json")
    runs = log["runs"]
    assert len(runs) == 1
    driver = runs[0]["tool"]["driver"]
    assert driver["name"] == "pqc-readiness"
    assert driver["version"] == pr.SCRIPT_VERSION
    # Every rule from RULE_SPECS must be advertised in the driver
    # descriptor regardless of whether any result references it.
    rule_ids = [r["id"] for r in driver["rules"]]
    assert rule_ids == [s.id for s in pr.RULE_SPECS]


def test_render_sarif_empty_report_has_no_results() -> None:
    log = json.loads(pr.render_sarif(_empty_report()))
    assert log["runs"][0]["results"] == []
    _validate(log)


def test_render_sarif_rules_have_required_metadata() -> None:
    log = json.loads(pr.render_sarif(_empty_report()))
    rules = log["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) == 6
    expected_ids = {
        "pqc-001-openssl-pre-3.5",
        "pqc-002-fips-pqc-conflict",
        "pqc-003-no-pqc-isa-support",
        "pqc-004-classical-only-trust-store",
        "pqc-005-slh-dsa-in-tls-context",
        "pqc-006-no-network-hsm-pqc-firmware",
    }
    assert {r["id"] for r in rules} == expected_ids
    for r in rules:
        assert r["shortDescription"]["text"]
        assert r["fullDescription"]["text"]
        assert r["helpUri"].startswith("https://")
        assert r["defaultConfiguration"]["level"] in {"error", "warning", "note"}


def test_render_sarif_full_trigger_report_validates_against_schema() -> None:
    log = json.loads(pr.render_sarif(_full_trigger_report()))
    _validate(log)
    results = log["runs"][0]["results"]
    rule_ids = {r["ruleId"] for r in results}
    assert rule_ids == {s.id for s in pr.RULE_SPECS}


def test_render_sarif_run_properties_carry_host_context() -> None:
    log = json.loads(pr.render_sarif(_empty_report()))
    props = log["runs"][0]["properties"]
    assert props["host:hostname"] == "testhost.example"
    assert props["host:os"] == "Fedora Linux 44"
    assert props["host:arch"] == "x86_64"
    assert props["tool:version"] == pr.SCRIPT_VERSION


# ----- per-rule firing tests ------------------------------------------------


def test_pqc_001_fires_when_openssl_below_3_5() -> None:
    r = _empty_report()
    r.openssl = {
        "available": True,
        "version": "OpenSSL 3.0.0",
        "pqc_native": False,
    }
    findings = pr.build_findings(r)
    ids = [f.rule_id for f in findings]
    assert "pqc-001-openssl-pre-3.5" in ids


def test_pqc_001_silent_when_openssl_native_pqc() -> None:
    r = _empty_report()
    r.openssl = {
        "available": True,
        "version": "OpenSSL 3.5.5",
        "pqc_native": True,
    }
    findings = pr.build_findings(r)
    assert all(f.rule_id != "pqc-001-openssl-pre-3.5" for f in findings)


def test_pqc_001_silent_when_openssl_unavailable() -> None:
    r = _empty_report()
    r.openssl = {"available": False, "reason": "openssl not on PATH"}
    findings = pr.build_findings(r)
    assert all(f.rule_id != "pqc-001-openssl-pre-3.5" for f in findings)


def test_pqc_002_fires_on_fips_pqc_conflict() -> None:
    r = _empty_report()
    r.fips_pqc_conflict = {
        "in_conflict": True,
        "explanation": "kernel FIPS + non-FIPS PQC provider",
    }
    findings = pr.build_findings(r)
    fc = [f for f in findings if f.rule_id == "pqc-002-fips-pqc-conflict"]
    assert len(fc) == 1
    assert fc[0].level == "error"
    assert "non-FIPS" in fc[0].message


def test_pqc_002_silent_when_no_conflict() -> None:
    r = _empty_report()
    r.fips_pqc_conflict = {"in_conflict": False, "explanation": "ok"}
    findings = pr.build_findings(r)
    assert all(f.rule_id != "pqc-002-fips-pqc-conflict" for f in findings)


def test_pqc_003_fires_when_replace_required() -> None:
    r = _empty_report()
    r.isa_tier = "poor"
    r.replace_required = True
    findings = pr.build_findings(r)
    isa = [f for f in findings if f.rule_id == "pqc-003-no-pqc-isa-support"]
    assert len(isa) == 1
    assert isa[0].properties["isa:tier"] == "poor"


def test_pqc_003_silent_when_isa_acceptable() -> None:
    r = _empty_report()
    r.isa_tier = "good"
    r.replace_required = False
    findings = pr.build_findings(r)
    assert all(f.rule_id != "pqc-003-no-pqc-isa-support" for f in findings)


def test_pqc_004_fires_on_classical_only_trust_store() -> None:
    r = _empty_report()
    r.trust_store = {
        "available": True,
        "scanned_dirs": ["/etc/pki"],
        "total_certs": 100,
        "pqc_certs": 0,
        "hybrid_certs": 0,
    }
    findings = pr.build_findings(r)
    ts = [f for f in findings if f.rule_id == "pqc-004-classical-only-trust-store"]
    assert len(ts) == 1
    assert ts[0].level == "note"
    assert ts[0].properties["trust_store:total_certs"] == 100


def test_pqc_004_silent_when_trust_store_has_pqc() -> None:
    r = _empty_report()
    r.trust_store = {
        "available": True,
        "scanned_dirs": ["/etc/pki"],
        "total_certs": 100,
        "pqc_certs": 1,
        "hybrid_certs": 0,
    }
    findings = pr.build_findings(r)
    assert all(
        f.rule_id != "pqc-004-classical-only-trust-store" for f in findings
    )


def test_pqc_004_silent_when_trust_store_not_scanned() -> None:
    """If --scan-trust-store was not requested, the trust_store dict is
    empty and the rule must NOT fire — the absence of evidence is not
    evidence of a classical-only store."""
    r = _empty_report()
    r.trust_store = {}
    findings = pr.build_findings(r)
    assert all(
        f.rule_id != "pqc-004-classical-only-trust-store" for f in findings
    )


def test_pqc_004_silent_when_trust_store_empty() -> None:
    """A scanned trust store with zero readable certs should not fire
    the rule — there is nothing to characterise as classical-only."""
    r = _empty_report()
    r.trust_store = {
        "available": True,
        "scanned_dirs": [],
        "total_certs": 0,
        "pqc_certs": 0,
        "hybrid_certs": 0,
    }
    findings = pr.build_findings(r)
    assert all(
        f.rule_id != "pqc-004-classical-only-trust-store" for f in findings
    )


def test_pqc_005_fires_when_slh_dsa_exposed() -> None:
    r = _empty_report()
    r.openssl = {
        "available": True,
        "version": "OpenSSL 3.5.5",
        "pqc_native": True,
        "sig_algorithms": ["ML-DSA-65", "SLH-DSA-SHA2-128s", "SLH-DSA-SHAKE-128f"],
    }
    findings = pr.build_findings(r)
    slh = [f for f in findings if f.rule_id == "pqc-005-slh-dsa-in-tls-context"]
    assert len(slh) == 1
    algos = slh[0].properties["openssl:slh_dsa_algorithms"]
    assert algos == sorted(algos)
    assert all(a.startswith("SLH-DSA") for a in algos)


def test_pqc_005_silent_when_only_ml_dsa_exposed() -> None:
    r = _empty_report()
    r.openssl = {
        "available": True,
        "version": "OpenSSL 3.5.5",
        "pqc_native": True,
        "sig_algorithms": ["ML-DSA-65", "ML-DSA-87"],
    }
    findings = pr.build_findings(r)
    assert all(f.rule_id != "pqc-005-slh-dsa-in-tls-context" for f in findings)


def test_pqc_006_fires_for_non_pqc_network_hsm() -> None:
    r = _empty_report()
    r.accelerators = [
        {
            "kind": "network_hsm",
            "name": "Acme NetworkHSM",
            "pqc_capable": False,
        },
    ]
    findings = pr.build_findings(r)
    hsm = [f for f in findings if f.rule_id == "pqc-006-no-network-hsm-pqc-firmware"]
    assert len(hsm) == 1
    assert "Acme NetworkHSM" in hsm[0].properties["hsm:network_hsm_names"]


def test_pqc_006_silent_when_network_hsm_is_pqc_capable() -> None:
    r = _empty_report()
    r.accelerators = [
        {
            "kind": "network_hsm",
            "name": "PQC Network HSM",
            "pqc_capable": True,
        },
    ]
    findings = pr.build_findings(r)
    assert all(
        f.rule_id != "pqc-006-no-network-hsm-pqc-firmware" for f in findings
    )


def test_pqc_006_silent_when_local_hsm_only() -> None:
    """Local PCI HSMs are scoped under pqc-003 (replace_required) and
    must not trigger the network-HSM rule."""
    r = _empty_report()
    r.accelerators = [
        {"kind": "hsm", "name": "Local HSM", "pqc_capable": False},
    ]
    findings = pr.build_findings(r)
    assert all(
        f.rule_id != "pqc-006-no-network-hsm-pqc-firmware" for f in findings
    )


def test_findings_are_deterministic() -> None:
    """The order of findings must match RULE_SPECS so SARIF
    `ruleIndex` values are stable across runs on the same host."""
    r = _full_trigger_report()
    a = [f.rule_id for f in pr.build_findings(r)]
    b = [f.rule_id for f in pr.build_findings(r)]
    assert a == b
    assert a == [s.id for s in pr.RULE_SPECS]


def test_sarif_result_rule_index_matches_driver_rules() -> None:
    """SARIF 2.1.0 §3.27.5: a result's `ruleIndex` is an index into
    `tool.driver.rules`.  Mismatched indices break every consumer that
    looks up rule metadata via the index path."""
    log = json.loads(pr.render_sarif(_full_trigger_report()))
    rules = log["runs"][0]["tool"]["driver"]["rules"]
    for result in log["runs"][0]["results"]:
        idx = result["ruleIndex"]
        assert rules[idx]["id"] == result["ruleId"]
