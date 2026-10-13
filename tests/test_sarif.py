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
        fips={
            "kernel": True,
            "openssl_provider": True,
            "fence_check_active": True,
            "algorithm_fence_engaged": False,
            "algorithms_reachable_outside_fence": {
                "kems": ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"],
                "signatures": ["ML-DSA-87", "SLH-DSA-SHAKE-256f"],
                "tls_groups": ["X25519MLKEM768"],
            },
        },
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
        signing_keys={
            "available": True,
            "family": "rhel",
            "keys": [
                {"algorithm": "RSA", "key_id": "199E2F91FD431D51"},
                {"algorithm": "RSA", "key_id": "5054E4A45A6340B3"},
            ],
            "summary": {
                "total": 2,
                "classical": 2,
                "hybrid": 0,
                "pure_pqc": 0,
                "all_classical": True,
            },
        },
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
    assert len(rules) == 8
    expected_ids = {
        "pqc-001-openssl-pre-3.5",
        "pqc-002-fips-pqc-conflict",
        "pqc-003-no-pqc-isa-support",
        "pqc-004-classical-only-trust-store",
        "pqc-005-slh-dsa-in-tls-context",
        "pqc-006-no-network-hsm-pqc-firmware",
        "pqc-007-fips-without-algorithm-fence",
        "pqc-008-classical-package-signing-keys",
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
    assert all(f.rule_id != "pqc-004-classical-only-trust-store" for f in findings)


def test_pqc_004_silent_when_trust_store_not_scanned() -> None:
    """If --scan-trust-store was not requested, the trust_store dict is
    empty and the rule must NOT fire — the absence of evidence is not
    evidence of a classical-only store."""
    r = _empty_report()
    r.trust_store = {}
    findings = pr.build_findings(r)
    assert all(f.rule_id != "pqc-004-classical-only-trust-store" for f in findings)


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
    assert all(f.rule_id != "pqc-004-classical-only-trust-store" for f in findings)


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
    assert all(f.rule_id != "pqc-006-no-network-hsm-pqc-firmware" for f in findings)


def test_pqc_006_silent_when_local_hsm_only() -> None:
    """Local PCI HSMs are scoped under pqc-003 (replace_required) and
    must not trigger the network-HSM rule."""
    r = _empty_report()
    r.accelerators = [
        {"kind": "hsm", "name": "Local HSM", "pqc_capable": False},
    ]
    findings = pr.build_findings(r)
    assert all(f.rule_id != "pqc-006-no-network-hsm-pqc-firmware" for f in findings)


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


# ---------------------------------------------------------------------------
# Code-scanning mode: --sarif-anchor (#145)
# ---------------------------------------------------------------------------

_ANCHOR = "hosts/{hostname}.md"


def _anchored(r: pr.Report, anchor: str = _ANCHOR) -> dict[str, Any]:
    return json.loads(pr.render.sarif.render_sarif(r, anchor))


def test_default_sarif_has_no_code_scanning_fields() -> None:
    # The flag is opt-in: without it, earlier releases' output is unchanged.
    log = json.loads(pr.render_sarif(_full_trigger_report()))
    run = log["runs"][0]
    assert "automationDetails" not in run
    assert all("properties" not in rule for rule in run["tool"]["driver"]["rules"])
    for res in run["results"]:
        assert "locations" not in res
        assert "partialFingerprints" not in res


def test_anchored_sarif_validates_and_locates_every_result() -> None:
    r = _full_trigger_report()
    log = _anchored(r)
    _validate(log)
    results = log["runs"][0]["results"]
    assert results
    for res in results:
        (loc,) = res["locations"]
        assert loc["physicalLocation"]["artifactLocation"]["uri"] == (
            f"hosts/{r.hostname}.md"
        )
        assert loc["physicalLocation"]["region"]["startLine"] == 1


def test_fingerprints_are_stable_and_distinguish_host_and_rule() -> None:
    sarif = pr.render.sarif
    key = sarif.FINGERPRINT_KEY
    r = _full_trigger_report()
    first = {
        x["ruleId"]: x["partialFingerprints"][key]
        for x in _anchored(r)["runs"][0]["results"]
    }
    second = {
        x["ruleId"]: x["partialFingerprints"][key]
        for x in _anchored(r)["runs"][0]["results"]
    }
    assert first == second  # same host + rule -> same identity across runs
    assert len(set(first.values())) == len(first)  # unique per rule
    other = sarif.finding_fingerprint("another-host", next(iter(first)))
    assert other not in first.values()  # unique per host


def test_automation_id_gives_each_host_its_own_category() -> None:
    r = _full_trigger_report()
    run_id = _anchored(r)["runs"][0]["automationDetails"]["id"]
    # GitHub reads id as category/run-id; category is everything up to the
    # last "/", so it must be per host and must not contain the timestamp.
    category, _, run = run_id.rpartition("/")
    assert category == f"pqc-readiness/{r.hostname}"
    assert run == r.generated_at


def test_every_rule_has_a_security_severity_in_range() -> None:
    sarif = pr.render.sarif
    assert set(sarif.SECURITY_SEVERITY) == {s.id for s in pr.RULE_SPECS}
    rules = _anchored(_full_trigger_report())["runs"][0]["tool"]["driver"]["rules"]
    for rule in rules:
        score = float(rule["properties"]["security-severity"])
        assert 0.0 < score <= 10.0, rule["id"]
        assert score < 9.0, "readiness findings are never critical"
        assert "security" in rule["properties"]["tags"]


def test_hostname_with_separator_cannot_escape_the_anchor_directory() -> None:
    sarif = pr.render.sarif
    assert sarif.anchor_path("hosts/{hostname}.md", "../../etc") == "hosts/.._.._etc.md"


def test_cli_sarif_anchor_reaches_renderer_and_does_not_leak(
    monkeypatch, capsys
) -> None:
    from pqc_readiness import cli

    monkeypatch.setattr(cli, "collect_report", lambda args: _full_trigger_report())
    cli.main(["--sarif", "--sarif-anchor", _ANCHOR])
    anchored = json.loads(capsys.readouterr().out)
    assert "automationDetails" in anchored["runs"][0]
    cli.main(["--sarif"])  # a later run without the flag is plain again
    plain = json.loads(capsys.readouterr().out)
    assert "automationDetails" not in plain["runs"][0]


def test_cli_rejects_empty_sarif_anchor(capsys) -> None:
    from pqc_readiness import cli

    with pytest.raises(SystemExit) as exc:
        cli.main(["--sarif", "--sarif-anchor", " "])
    assert exc.value.code == 2
    assert "must not be empty" in capsys.readouterr().err
