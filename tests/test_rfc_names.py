"""Registered PQC key-exchange names, codepoints and standards status (#139).

Expected values were checked against the IANA TLS Supported Groups and
SSH Key Exchange Method Names registries, rfc-editor.org and NIST CSRC on
2026-10-13; a change here should come with a new primary-source check."""

from __future__ import annotations

from pathlib import Path

import pytest

import pqc_readiness as pr
from pqc_readiness import algorithms as alg
from pqc_readiness import recommendation as rec_mod
from pqc_readiness.render import sarif

REPO = Path(__file__).resolve().parent.parent


@pytest.mark.parametrize(
    ("name", "codepoint", "reference", "status"),
    [
        ("X25519MLKEM768", "0x11EC", "RFC 10024", "final"),
        ("SecP256r1MLKEM768", "0x11EB", "RFC 10024", "final"),
        ("SecP384r1MLKEM1024", "0x11ED", "RFC 10024", "final"),
        ("MLKEM512", "0x0200", "draft-ietf-tls-mlkem", "draft"),
        ("MLKEM768", "0x0201", "draft-ietf-tls-mlkem", "draft"),
        ("MLKEM1024", "0x0202", "draft-ietf-tls-mlkem", "draft"),
    ],
)
def test_tls_group_codepoints_and_status(name, codepoint, reference, status) -> None:
    ref = alg.tls_group_references([name])[name]
    assert ref["codepoint"] == codepoint
    assert ref["reference"] == reference
    assert ref["status"] == status


def test_only_x25519mlkem768_is_iana_recommended() -> None:
    refs = alg.tls_group_references(list(alg.TLS_PQC_GROUPS))
    assert [n for n, r in refs.items() if r["recommended"]] == ["X25519MLKEM768"]


def test_cnsa_eligible_groups_are_exactly_the_ml_kem_1024_ones() -> None:
    refs = alg.tls_group_references(list(alg.TLS_PQC_GROUPS))
    assert sorted(n for n, r in refs.items() if r["cnsa_2_0"]) == [
        "MLKEM1024",
        "SecP384r1MLKEM1024",
    ]


def test_unknown_and_obsolete_groups() -> None:
    refs = alg.tls_group_references(
        ["X25519Kyber768Draft00", "BogusMLKEM9000", "x25519"]
    )
    assert list(refs) == ["X25519Kyber768Draft00"]
    assert refs["X25519Kyber768Draft00"]["obsolete"] is True
    assert refs["X25519Kyber768Draft00"]["codepoint"] == "0x6399"


@pytest.mark.parametrize(
    ("name", "reference", "cnsa"),
    [
        ("mlkem768x25519-sha256", "RFC 10042", False),
        ("mlkem768nistp256-sha256", "RFC 10042", False),
        ("mlkem1024nistp384-sha384", "RFC 10042", True),
        ("sntrup761x25519-sha512", "RFC 9941", False),
    ],
)
def test_ssh_kex_references(name, reference, cnsa) -> None:
    ref = alg.ssh_kex_references([name])[name]
    assert (ref["reference"], ref["status"], ref["cnsa_2_0"]) == (
        reference,
        "final",
        cnsa,
    )


def test_openssh_sntrup_alias_points_at_rfc_name() -> None:
    ref = alg.ssh_kex_references(["sntrup761x25519-sha512@openssh.com"])
    assert (
        ref["sntrup761x25519-sha512@openssh.com"]["alias_of"]
        == "sntrup761x25519-sha512"
    )


def test_standards_status_labels() -> None:
    assert alg.STANDARDS["NIST IR 8547"]["status"] == "draft"
    assert alg.STANDARDS["NIST IR 8547"]["url"].endswith("/ipd")
    assert alg.STANDARDS["draft-ietf-lamps-pq-composite-sigs"]["status"] == "draft"
    for rfc in ("RFC 10024", "RFC 10042", "RFC 9954", "RFC 9941", "FIPS 203"):
        assert alg.STANDARDS[rfc]["status"] == "final"


def test_annotation_adds_sibling_keys_and_leaves_buckets_alone() -> None:
    groups = {
        "pure_pqc": ["MLKEM1024"],
        "hybrid": ["X25519MLKEM768"],
        "classical": ["x25519"],
    }
    openssl = {"available": True, "tls_groups": {k: list(v) for k, v in groups.items()}}
    ssh = {
        "available": True,
        "kex_groups": {"pure_pqc": [], "hybrid": ["mlkem768x25519-sha256"]},
    }
    alg.annotate_key_exchange(openssl, ssh)
    assert openssl["tls_groups"] == groups
    assert sorted(openssl["tls_group_references"]) == ["MLKEM1024", "X25519MLKEM768"]
    assert list(ssh["kex_references"]) == ["mlkem768x25519-sha256"]


def test_annotation_skips_probes_that_did_not_run() -> None:
    openssl: dict[str, object] = {"available": False}
    ssh: dict[str, object] = {"available": False, "reason": "ssh not on PATH"}
    alg.annotate_key_exchange(openssl, ssh)
    assert "tls_group_references" not in openssl
    assert "kex_references" not in ssh


def _openssl(pure: list[str], hybrid: list[str]) -> dict[str, object]:
    return {
        "available": True,
        "kem_algorithms": ["ML-KEM-768", "ML-KEM-1024"],
        "sig_algorithms": ["ML-DSA-87"],
        "tls_groups": {"pure_pqc": pure, "hybrid": hybrid, "classical": ["x25519"]},
    }


def test_cnsa_flags_x25519mlkem768_only_hosts() -> None:
    out = pr.evaluate_cnsa_2_0(_openssl([], ["X25519MLKEM768"]), None)
    assert out["tls_key_exchange"] == {
        "compliant_groups": [],
        "non_compliant_pqc_groups": ["X25519MLKEM768"],
    }
    assert any("X25519MLKEM768" in n and "ML-KEM-1024" in n for n in out["notes"])


def test_cnsa_accepts_p384_hybrid_and_does_not_change_status() -> None:
    compliant = pr.evaluate_cnsa_2_0(
        _openssl([], ["SecP384r1MLKEM1024", "X25519MLKEM768"]), None
    )
    weak = pr.evaluate_cnsa_2_0(_openssl([], ["X25519MLKEM768"]), None)
    assert compliant["tls_key_exchange"]["compliant_groups"] == ["SecP384r1MLKEM1024"]
    assert not any("do not meet CNSA 2.0" in n for n in compliant["notes"])
    # Informational only: --check cnsa-2.0 exit codes must not shift.
    assert compliant["status"] == weak["status"]


def _report(pure: list[str], hybrid: list[str]) -> pr.Report:
    return pr.Report(
        hostname="t",
        generated_at="2026-10-13T00:00:00+00:00",
        os="Test",
        arch="x86_64",
        isa_tier="excellent",
        fips={"kernel": True, "openssl_provider": True},
        openssl={
            "available": True,
            "version": "3.5.5",
            "tls_groups": {"pure_pqc": pure, "hybrid": hybrid},
        },
        kernel_info={"release": "6.12"},
    )


@pytest.mark.parametrize("role", ["tls-server", "tls-client"])
def test_cnsa_recommendation_needs_a_group_carrying_ml_kem_1024(role) -> None:
    rec = pr.recommend(
        _report(["MLKEM768"], ["X25519MLKEM768"]), policy="cnsa-2.0", role=role
    )
    record = rec["recommendations"]["cnsa-2.0"]
    kem, caveats = record["kem"], record["caveats"]
    assert kem["algorithm"] == "ML-KEM-1024"
    assert kem["tls_groups"] == []
    assert any("do not carry ML-KEM-1024" in c for c in caveats)


def test_recommendation_lists_matching_groups() -> None:
    groups = rec_mod._tls_groups_for(
        {
            "tls_groups": {
                "pure_pqc": ["MLKEM768", "MLKEM1024"],
                "hybrid": ["X25519MLKEM768"],
            }
        },
        "ML-KEM-1024",
        "pure",
    )
    assert groups == ["MLKEM1024"]


def test_ir_8547_is_never_presented_as_final() -> None:
    # The --cbom help and README CBOM text are owned by the render-cbom
    # lane (#138 / PR #163); this covers the data-policy lane's strings.
    nist = rec_mod.POLICY_PREFERENCES["nist-civilian"]["source"]
    assert "NIST IR 8547 (initial public draft)" in nist
    doc = REPO / "docs" / "recommendation-policies.md"
    if doc.exists():  # docs are absent in the slim container test images
        text = doc.read_text()
        assert "ir/8547/final" not in text
        assert "ir/8547/ipd" in text


def test_sarif_openssl_rule_cites_standards() -> None:
    spec = next(s for s in sarif.RULE_SPECS if s.id == "pqc-001-openssl-pre-3.5")
    assert "RFC 10024" in spec.full_description
    assert "FIPS 203" in spec.full_description
