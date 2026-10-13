# SPDX-License-Identifier: Apache-2.0
"""Tests for the algorithm recommendation engine.

`recommend()` is a pure function over (Report, policy, role).  We
construct synthetic Report values for three host capability profiles —
excellent ISA, good ISA, poor ISA without an accelerator — and confirm
that the recommendation differs across the four policies in the
expected ways.

Acceptance criteria source: issue #13 (algorithm recommendation engine)
and `docs/recommendation-policies.md`.
"""
from __future__ import annotations

import json
from typing import Any

import pytest

import pqc_readiness as pr

ALL_POLICIES = ("cnsa-2.0", "nist-civilian", "eu-anssi-bsi", "commercial")


def _make_report(
    isa_tier: str = "excellent",
    accelerators: list[dict[str, Any]] | None = None,
    fips_kernel: bool = True,
    openssl_available: bool = True,
    hybrid_groups: list[str] | None = None,
    pure_groups: list[str] | None = None,
) -> pr.Report:
    """Build a synthetic Report with only the fields the recommendation
    engine consumes.  Detection-layer fields outside the engine's input
    set are left at their dataclass defaults."""
    return pr.Report(
        hostname="test.example",
        generated_at="2026-04-28T12:00:00+00:00",
        os="Test OS",
        arch="x86_64",
        isa_tier=isa_tier,
        accelerators=accelerators or [],
        fips={"kernel": fips_kernel, "openssl_provider": fips_kernel},
        openssl={
            "available": openssl_available,
            "version": "3.5.5",
            "tls_groups": {
                "hybrid": hybrid_groups
                if hybrid_groups is not None
                else ["X25519MLKEM768"],
                "pure_pqc": pure_groups
                if pure_groups is not None
                else ["MLKEM768", "MLKEM1024"],
            },
        },
        kernel_info={"release": "6.12.0-test"},
    )


# ---------------------------------------------------------------------------
# Three host capability profiles × four policies — primary algorithm choice
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "isa_tier",
    ["excellent", "good", "poor"],
    ids=["excellent-isa", "good-isa", "poor-isa-no-accel"],
)
def test_cnsa_2_0_picks_ml_kem_1024_and_ml_dsa_87(isa_tier: str) -> None:
    """CNSA 2.0 mandates ML-KEM-1024 and ML-DSA-87 regardless of host
    capability; weaker hosts get a caveat instead of a downgrade."""
    r = _make_report(isa_tier=isa_tier)
    rec = pr.recommend(r, policy="cnsa-2.0", role="tls-server")
    sub = rec["recommendations"]["cnsa-2.0"]
    assert sub["kem"]["algorithm"] == "ML-KEM-1024"
    assert sub["kem"]["mode"] == "pure"
    assert sub["signature"]["algorithm"] == "ML-DSA-87"
    assert sub["hash"]["algorithm"] == "SHA-384"
    if isa_tier in ("good", "poor"):
        assert any("ML-KEM-1024" in c for c in sub["caveats"])
        assert any("ML-DSA-87" in c for c in sub["caveats"])
    else:
        assert all("mandates" not in c for c in sub["caveats"])


@pytest.mark.parametrize("isa_tier", ["excellent", "good", "poor"])
def test_nist_civilian_picks_ml_kem_768_pure(isa_tier: str) -> None:
    r = _make_report(isa_tier=isa_tier)
    rec = pr.recommend(r, policy="nist-civilian", role="tls-server")
    sub = rec["recommendations"]["nist-civilian"]
    assert sub["kem"]["algorithm"] == "ML-KEM-768"
    assert sub["kem"]["mode"] == "pure"
    assert sub["signature"]["algorithm"] == "ML-DSA-65"
    assert sub["hash"]["algorithm"] == "SHA-256"


@pytest.mark.parametrize("isa_tier", ["excellent", "good", "poor"])
def test_eu_anssi_bsi_picks_hybrid(isa_tier: str) -> None:
    r = _make_report(isa_tier=isa_tier)
    rec = pr.recommend(r, policy="eu-anssi-bsi", role="tls-server")
    sub = rec["recommendations"]["eu-anssi-bsi"]
    assert sub["kem"]["algorithm"] == "ML-KEM-768"
    assert sub["kem"]["mode"] == "hybrid"
    assert sub["signature"]["algorithm"] == "ML-DSA-65"
    assert sub["hash"]["algorithm"] == "SHA-256"


@pytest.mark.parametrize("isa_tier", ["excellent", "good", "poor"])
def test_commercial_picks_pure_ml_kem_768(isa_tier: str) -> None:
    r = _make_report(isa_tier=isa_tier)
    rec = pr.recommend(r, policy="commercial", role="tls-server")
    sub = rec["recommendations"]["commercial"]
    assert sub["kem"]["algorithm"] == "ML-KEM-768"
    assert sub["kem"]["mode"] == "pure"
    assert sub["signature"]["algorithm"] == "ML-DSA-65"
    assert sub["hash"]["algorithm"] == "SHA-256"


# ---------------------------------------------------------------------------
# Cross-policy contrasts — recommendations must differ as expected
# ---------------------------------------------------------------------------


def test_recommendations_differ_across_policies_for_same_host() -> None:
    """The same host must produce different recommendations under each
    policy: this is the central premise of the recommendation engine."""
    r = _make_report(isa_tier="excellent")
    rec = pr.recommend(r, policy="auto", role="tls-server")
    by_policy = rec["recommendations"]
    cnsa = by_policy["cnsa-2.0"]
    nist = by_policy["nist-civilian"]
    anssi = by_policy["eu-anssi-bsi"]
    comm = by_policy["commercial"]

    # CNSA 2.0 vs. NIST civilian: parameter set differs (1024 vs. 768),
    # signature differs (ML-DSA-87 vs. ML-DSA-65).
    assert cnsa["kem"]["algorithm"] != nist["kem"]["algorithm"]
    assert cnsa["signature"]["algorithm"] != nist["signature"]["algorithm"]

    # ANSSI/BSI vs. NIST civilian: same algorithm, different mode.
    assert anssi["kem"]["algorithm"] == nist["kem"]["algorithm"]
    assert anssi["kem"]["mode"] == "hybrid"
    assert nist["kem"]["mode"] == "pure"

    # Commercial vs. NIST civilian: same KEM, but FIPS-required differs
    # (commercial does not flag a FIPS caveat when FIPS is off).
    r2 = _make_report(isa_tier="excellent", fips_kernel=False)
    rec2 = pr.recommend(r2, policy="auto", role="tls-server")
    assert any(
        "FIPS" in c
        for c in rec2["recommendations"]["nist-civilian"]["caveats"]
    )
    assert all(
        "FIPS" not in c
        for c in rec2["recommendations"]["commercial"]["caveats"]
    )
    assert all(
        "FIPS" not in c
        for c in rec2["recommendations"]["eu-anssi-bsi"]["caveats"]
    )

    # Commercial mode on the original host should be pure.
    assert comm["kem"]["mode"] == "pure"


# ---------------------------------------------------------------------------
# Caveats: ISA tier conflicts with policy preference, FIPS missing, etc.
# ---------------------------------------------------------------------------


def test_cnsa_2_0_excellent_isa_no_isa_caveat() -> None:
    r = _make_report(isa_tier="excellent")
    sub = pr.recommend(r, "cnsa-2.0", "tls-server")["recommendations"]["cnsa-2.0"]
    # No ISA-tier caveat when host can support the larger params.
    assert all("host ISA tier" not in c for c in sub["caveats"])


def test_cnsa_2_0_poor_isa_emits_isa_caveat() -> None:
    r = _make_report(isa_tier="poor")
    sub = pr.recommend(r, "cnsa-2.0", "tls-server")["recommendations"]["cnsa-2.0"]
    assert any("host ISA tier is 'poor'" in c for c in sub["caveats"])


def test_pqc_accelerator_softens_isa_caveat() -> None:
    """A PQC-capable accelerator removes the ISA-tier caveat under
    CNSA 2.0 even when ISA tier is poor."""
    r = _make_report(
        isa_tier="poor",
        accelerators=[
            {"kind": "hsm", "name": "test", "detail": "x", "pqc_capable": True}
        ],
    )
    sub = pr.recommend(r, "cnsa-2.0", "tls-server")["recommendations"]["cnsa-2.0"]
    assert all("host ISA tier" not in c for c in sub["caveats"])
    assert sub["host_capability_inputs"]["pqc_accelerator_present"] is True


def test_fips_off_emits_caveat_for_cnsa_and_nist() -> None:
    r = _make_report(isa_tier="excellent", fips_kernel=False)
    cnsa_caveats = pr.recommend(r, "cnsa-2.0", "tls-server")[
        "recommendations"
    ]["cnsa-2.0"]["caveats"]
    nist_caveats = pr.recommend(r, "nist-civilian", "tls-server")[
        "recommendations"
    ]["nist-civilian"]["caveats"]
    assert any("FIPS" in c for c in cnsa_caveats)
    assert any("FIPS" in c for c in nist_caveats)


def test_missing_hybrid_groups_caveat_under_anssi_bsi() -> None:
    r = _make_report(isa_tier="excellent", hybrid_groups=[])
    sub = pr.recommend(r, "eu-anssi-bsi", "tls-server")[
        "recommendations"
    ]["eu-anssi-bsi"]
    assert any("hybrid groups" in c for c in sub["caveats"])


def test_missing_pure_groups_caveat_under_cnsa() -> None:
    r = _make_report(isa_tier="excellent", pure_groups=[])
    sub = pr.recommend(r, "cnsa-2.0", "tls-server")["recommendations"]["cnsa-2.0"]
    assert any("pure-PQC groups" in c for c in sub["caveats"])


def test_openssl_unavailable_emits_caveat() -> None:
    r = _make_report(isa_tier="excellent", openssl_available=False)
    sub = pr.recommend(r, "commercial", "tls-server")[
        "recommendations"
    ]["commercial"]
    assert any("OpenSSL was not detected" in c for c in sub["caveats"])


# ---------------------------------------------------------------------------
# Auto mode and role handling
# ---------------------------------------------------------------------------


def test_auto_mode_emits_all_four_policies() -> None:
    r = _make_report()
    rec = pr.recommend(r, policy="auto", role="tls-server")
    assert rec["mode"] == "auto"
    assert set(rec["recommendations"].keys()) == set(ALL_POLICIES)
    for sub in rec["recommendations"].values():
        assert sub["implemented"] is True


def test_unknown_policy_raises() -> None:
    r = _make_report()
    with pytest.raises(ValueError, match="unknown policy"):
        pr.recommend(r, policy="not-a-policy", role="tls-server")


def test_unknown_role_raises() -> None:
    r = _make_report()
    with pytest.raises(ValueError, match="unknown role"):
        pr.recommend(r, policy="commercial", role="not-a-role")


# ---------------------------------------------------------------------------
# tls-client role (#90)
# ---------------------------------------------------------------------------

_EXPECTED_TLS = {
    "cnsa-2.0": ("ML-KEM-1024", "pure", "ML-DSA-87", "SHA-384"),
    "nist-civilian": ("ML-KEM-768", "pure", "ML-DSA-65", "SHA-256"),
    "eu-anssi-bsi": ("ML-KEM-768", "hybrid", "ML-DSA-65", "SHA-256"),
    "commercial": ("ML-KEM-768", "pure", "ML-DSA-65", "SHA-256"),
}


@pytest.mark.parametrize("isa_tier", ["excellent", "good", "poor"])
@pytest.mark.parametrize("policy", ALL_POLICIES)
def test_tls_client_algorithms_per_policy(policy: str, isa_tier: str) -> None:
    r = _make_report(isa_tier=isa_tier)
    sub = pr.recommend(r, policy=policy, role="tls-client")["recommendations"][policy]
    kem, mode, sig, hash_ = _EXPECTED_TLS[policy]
    assert sub["implemented"] is True
    assert sub["role"] == "tls-client"
    assert sub["kem"]["algorithm"] == kem
    assert sub["kem"]["mode"] == mode
    assert sub["signature"]["algorithm"] == sig
    assert sub["hash"]["algorithm"] == hash_
    # A client verifies the server chain; it does not sign.
    assert "verify" in sub["signature"]["reason"]
    assert "sign p99" not in sub["signature"]["reason"]
    assert all("sign p99" not in c for c in sub["caveats"])


@pytest.mark.parametrize("policy", ALL_POLICIES)
def test_tls_client_reasons_differ_from_tls_server(policy: str) -> None:
    r = _make_report(isa_tier="good")
    client = pr.recommend(r, policy, "tls-client")["recommendations"][policy]
    server = pr.recommend(r, policy, "tls-server")["recommendations"][policy]
    assert client["signature"]["algorithm"] == server["signature"]["algorithm"]
    assert client["signature"]["reason"] != server["signature"]["reason"]


def test_tls_client_cnsa_poor_isa_caveat_references_verify() -> None:
    r = _make_report(isa_tier="poor")
    sub = pr.recommend(r, "cnsa-2.0", "tls-client")["recommendations"]["cnsa-2.0"]
    assert any("ML-DSA-87 verify p99" in c for c in sub["caveats"])


def test_tls_client_middlebox_caveat_for_ml_kem_1024() -> None:
    r = _make_report(isa_tier="excellent")
    sub = pr.recommend(r, "cnsa-2.0", "tls-client")["recommendations"]["cnsa-2.0"]
    caveat = [c for c in sub["caveats"] if "middlebox" in c]
    assert len(caveat) == 1
    # FIPS 203: ML-KEM-1024 encapsulation key = 384*4 + 32 bytes.
    assert "1568 bytes" in caveat[0]


def test_tls_client_no_middlebox_caveat_for_pure_ml_kem_768() -> None:
    """A pure ML-KEM-768 share (1184 bytes) stays under the threshold."""
    r = _make_report(isa_tier="excellent")
    for policy in ("nist-civilian", "commercial"):
        sub = pr.recommend(r, policy, "tls-client")["recommendations"][policy]
        assert not any("middlebox" in c for c in sub["caveats"])


def test_tls_client_hybrid_share_size_includes_classical_component() -> None:
    """X25519MLKEM768 = 1184 + 32 bytes, which crosses the threshold."""
    r = _make_report(isa_tier="excellent")
    sub = pr.recommend(r, "eu-anssi-bsi", "tls-client")["recommendations"][
        "eu-anssi-bsi"
    ]
    assert any("1216 bytes" in c for c in sub["caveats"])


def test_ml_kem_encaps_key_sizes_match_pqc_sizes() -> None:
    assert (
        pr.ML_KEM_ENCAPS_KEY_BYTES["ML-KEM-768"] == pr.PQC_SIZES["ML-KEM-768"]["pk"]
    )
    assert pr.ML_KEM_ENCAPS_KEY_BYTES["ML-KEM-1024"] == 1568


def test_tls_client_missing_hybrid_groups_caveat_names_client() -> None:
    r = _make_report(hybrid_groups=[])
    sub = pr.recommend(r, "eu-anssi-bsi", "tls-client")["recommendations"][
        "eu-anssi-bsi"
    ]
    assert any("hybrid TLS client" in c for c in sub["caveats"])


# ---------------------------------------------------------------------------
# signing-service role (#91)
# ---------------------------------------------------------------------------

_PQC_ACCEL = [{"name": "test-hsm", "pqc_capable": True}]


@pytest.mark.parametrize("isa_tier", ["excellent", "good", "poor"])
@pytest.mark.parametrize("policy", ALL_POLICIES)
def test_signing_service_algorithms_per_policy(policy: str, isa_tier: str) -> None:
    r = _make_report(isa_tier=isa_tier)
    sub = pr.recommend(r, policy, "signing-service")["recommendations"][policy]
    assert sub["implemented"] is True
    assert sub["role"] == "signing-service"
    expected_sig = "ML-DSA-87" if policy == "cnsa-2.0" else "ML-DSA-65"
    assert sub["signature"]["algorithm"] == expected_sig
    assert sub["hash"]["algorithm"] == _EXPECTED_TLS[policy][3]
    assert "sign" in sub["signature"]["reason"] or "mandated" in sub["signature"]["reason"]


@pytest.mark.parametrize("policy", ALL_POLICIES)
def test_signing_service_kem_is_null(policy: str) -> None:
    sub = pr.recommend(_make_report(), policy, "signing-service")[
        "recommendations"
    ][policy]
    assert sub["kem"]["algorithm"] is None
    assert sub["kem"]["mode"] == "n/a"
    assert "not applicable" in sub["kem"]["reason"]


@pytest.mark.parametrize("policy", ALL_POLICIES)
def test_signing_service_has_no_tls_group_caveat(policy: str) -> None:
    """Signing services negotiate no TLS groups, so missing groups or a
    missing OpenSSL must not produce TLS caveats."""
    r = _make_report(openssl_available=False, hybrid_groups=[], pure_groups=[])
    sub = pr.recommend(r, policy, "signing-service")["recommendations"][policy]
    assert not any("TLS" in c for c in sub["caveats"])


@pytest.mark.parametrize("policy", ("nist-civilian", "eu-anssi-bsi", "commercial"))
def test_signing_service_notes_slh_dsa_for_low_volume(policy: str) -> None:
    sub = pr.recommend(_make_report(), policy, "signing-service")[
        "recommendations"
    ][policy]
    assert sub["signature"]["algorithm"] == "ML-DSA-65"
    assert any(
        "SLH-DSA-SHA2-128s" in c and "low-volume" in c for c in sub["caveats"]
    )


def test_signing_service_cnsa_does_not_offer_slh_dsa() -> None:
    sub = pr.recommend(_make_report(), "cnsa-2.0", "signing-service")[
        "recommendations"
    ]["cnsa-2.0"]
    assert not any("SLH-DSA" in c for c in sub["caveats"])


@pytest.mark.parametrize(
    ("policy", "algo"), [("cnsa-2.0", "ML-DSA-87"), ("commercial", "ML-DSA-65")]
)
def test_signing_service_hsm_presence_changes_caveats(policy: str, algo: str) -> None:
    without = pr.recommend(_make_report(isa_tier="poor"), policy, "signing-service")[
        "recommendations"
    ][policy]
    with_hsm = pr.recommend(
        _make_report(isa_tier="poor", accelerators=_PQC_ACCEL),
        policy,
        "signing-service",
    )["recommendations"][policy]
    assert any("sign throughput below" in c for c in without["caveats"])
    assert not any("sign throughput below" in c for c in with_hsm["caveats"])
    assert any(f"route {algo} signing through it" in c for c in with_hsm["caveats"])
    assert "accelerator" in with_hsm["signature"]["reason"]


def test_signing_service_reasons_differ_from_tls_server() -> None:
    r = _make_report(isa_tier="good")
    svc = pr.recommend(r, "commercial", "signing-service")["recommendations"][
        "commercial"
    ]
    tls = pr.recommend(r, "commercial", "tls-server")["recommendations"]["commercial"]
    assert svc["signature"]["reason"] != tls["signature"]["reason"]
    assert "handshake" not in svc["signature"]["reason"]


def test_renderers_print_na_for_null_kem() -> None:
    r = _make_report()
    rec = pr.recommend(r, "auto", "signing-service")
    text = pr.render_recommendation_text(r, rec)
    md = pr.render_recommendation_markdown(r, rec)
    assert "KEM:        n/a" in text
    assert "None" not in text
    assert "| KEM (n/a) | n/a |" in md
    assert "`None`" not in md


# ---------------------------------------------------------------------------
# firmware-signing role (#92)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("isa_tier", ["excellent", "good", "poor"])
@pytest.mark.parametrize("policy", ALL_POLICIES)
def test_firmware_signing_algorithms_per_policy(policy: str, isa_tier: str) -> None:
    r = _make_report(isa_tier=isa_tier)
    sub = pr.recommend(r, policy, "firmware-signing")["recommendations"][policy]
    assert sub["implemented"] is True
    assert sub["role"] == "firmware-signing"
    assert sub["kem"]["algorithm"] is None
    assert sub["kem"]["mode"] == "n/a"
    assert sub["hash"]["algorithm"] == _EXPECTED_TLS[policy][3]
    if policy == "cnsa-2.0":
        assert sub["signature"]["algorithm"] == "ML-DSA-87"
    else:
        assert sub["signature"]["algorithm"] == "SLH-DSA-SHA2-128s"
        assert "long-lived" in sub["signature"]["reason"]
        assert "ML-DSA-65" in sub["signature"]["reason"]
    # Build-time signing: no ISA tier / throughput caveats for any host.
    assert not any("ISA tier" in c for c in sub["caveats"])
    assert not any("throughput" in c for c in sub["caveats"])


def test_firmware_signing_cnsa_points_at_cnsa_hash_based_options() -> None:
    """SLH-DSA is not a CNSA 2.0 algorithm; CNSA 2.0's hash-based option
    for firmware is LMS/XMSS (SP 800-208)."""
    sub = pr.recommend(_make_report(), "cnsa-2.0", "firmware-signing")[
        "recommendations"
    ]["cnsa-2.0"]
    assert any("LMS" in c and "SP 800-208" in c for c in sub["caveats"])
    assert sub["signature"]["algorithm"] == "ML-DSA-87"


def test_firmware_signing_reason_cites_signature_size_from_pqc_sizes() -> None:
    sub = pr.recommend(_make_report(), "commercial", "firmware-signing")[
        "recommendations"
    ]["commercial"]
    assert f"{pr.PQC_SIZES['SLH-DSA-SHA2-128s']['sig']}-byte" in sub["signature"][
        "reason"
    ]


def test_firmware_signing_notes_pqc_hsm() -> None:
    sub = pr.recommend(
        _make_report(accelerators=_PQC_ACCEL), "commercial", "firmware-signing"
    )["recommendations"]["commercial"]
    assert any("HSM" in c for c in sub["caveats"])


@pytest.mark.parametrize("policy", ("nist-civilian", "eu-anssi-bsi", "commercial"))
def test_firmware_signing_differs_from_signing_service(policy: str) -> None:
    r = _make_report()
    fw = pr.recommend(r, policy, "firmware-signing")["recommendations"][policy]
    svc = pr.recommend(r, policy, "signing-service")["recommendations"][policy]
    assert fw["signature"]["algorithm"] != svc["signature"]["algorithm"]


@pytest.mark.parametrize("role", ["tls-server", "tls-client", "signing-service", "firmware-signing"])
def test_workload_roles_are_implemented(role: str) -> None:
    sub = pr.recommend(_make_report(), "commercial", role)["recommendations"][
        "commercial"
    ]
    assert sub["implemented"] is True


@pytest.mark.parametrize("role", ["generic"])
def test_other_roles_return_stub(role: str) -> None:
    r = _make_report()
    rec = pr.recommend(r, policy="commercial", role=role)
    sub = rec["recommendations"]["commercial"]
    assert sub["implemented"] is False
    assert sub["role"] == role
    assert "not yet implemented" in sub["note"]


# ---------------------------------------------------------------------------
# Renderers and output shape
# ---------------------------------------------------------------------------


def test_json_output_shape_is_stable() -> None:
    """Audit-trail consumers depend on the recommendation and policy
    basis being separate top-level fields per sub-record."""
    r = _make_report(isa_tier="excellent")
    rec = pr.recommend(r, "cnsa-2.0", "tls-server")
    # Recommendation must round-trip through JSON without loss.
    parsed = json.loads(json.dumps(rec))
    sub = parsed["recommendations"]["cnsa-2.0"]
    assert {
        "role",
        "policy",
        "policy_authority",
        "policy_basis",
        "policy_source",
        "implemented",
        "kem",
        "signature",
        "hash",
        "host_capability_inputs",
        "caveats",
    }.issubset(sub.keys())


def test_text_renderer_includes_policy_and_algorithm() -> None:
    r = _make_report(isa_tier="excellent")
    rec = pr.recommend(r, "cnsa-2.0", "tls-server")
    out = pr.render_recommendation_text(r, rec)
    assert "ML-KEM-1024" in out
    assert "ML-DSA-87" in out
    assert "cnsa-2.0" in out
    assert "Policy basis:" in out


def test_markdown_renderer_includes_policy_and_algorithm() -> None:
    r = _make_report(isa_tier="excellent")
    rec = pr.recommend(r, "auto", "tls-server")
    out = pr.render_recommendation_markdown(r, rec)
    assert "# PQC algorithm recommendation" in out
    for policy in ALL_POLICIES:
        assert f"`{policy}`" in out
    assert "ML-KEM-1024" in out
    assert "ML-KEM-768" in out


def test_policy_preferences_are_documented() -> None:
    """Every policy must declare an authority and a citation; the
    citation is the audit hook for downstream tooling."""
    for name in ALL_POLICIES:
        pref = pr.POLICY_PREFERENCES[name]
        assert pref["authority"], f"{name} missing authority"
        assert pref["citation"], f"{name} missing citation"
        assert pref["source"], f"{name} missing source"
