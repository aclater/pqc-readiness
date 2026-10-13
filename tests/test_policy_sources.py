"""Sourced migration timelines in --recommend output (#141).

The dates asserted here were read from each issuing body's own document on
2026-10-13; changing one should come with a new primary-source check."""

from __future__ import annotations

from pathlib import Path

import pytest

import pqc_readiness as pr
from pqc_readiness import recommendation as rec

REPO = Path(__file__).resolve().parent.parent


def _report() -> pr.Report:
    return pr.Report(
        hostname="t",
        generated_at="2026-10-13T00:00:00+00:00",
        os="Test",
        arch="x86_64",
        isa_tier="excellent",
        fips={"kernel": True, "openssl_provider": True},
        openssl={
            "available": True,
            "tls_groups": {"pure_pqc": ["MLKEM1024"], "hybrid": []},
        },
        kernel_info={"release": "6.12"},
    )


@pytest.mark.parametrize("key", sorted(rec.POLICY_SOURCES))
def test_every_source_is_complete(key: str) -> None:
    src = rec.POLICY_SOURCES[key]
    assert src["authority"]
    assert src["verified"].startswith("2026-10-13")
    assert src["documents"]
    for doc in src["documents"]:
        assert doc["status"] in ("final", "draft")
        assert doc["url"].startswith("https://")
        assert doc["title"]
    for m in src["milestones"]:
        assert m["by"][:4].isdigit() and m["event"]


def test_draft_sources_are_labelled() -> None:
    nist = rec.POLICY_SOURCES["us-nist"]
    assert [d["status"] for d in nist["documents"]] == ["draft"]
    assert all("(draft)" in m["event"] for m in nist["milestones"])


def test_cnsa_category_dates_match_the_2022_advisory() -> None:
    cats = rec.POLICY_SOURCES["us-nss-cnsa-2.0"]["categories"]
    assert cats["software-firmware-signing"] == {
        "support_and_prefer": "2025",
        "exclusive_use": "2030",
    }
    assert cats["web-browsers-servers-cloud"] == {
        "support_and_prefer": "2025",
        "exclusive_use": "2033",
    }
    assert cats["traditional-networking"] == {
        "support_and_prefer": "2026",
        "exclusive_use": "2030",
    }
    assert cats["operating-systems"] == {
        "support_and_prefer": "2027",
        "exclusive_use": "2033",
    }
    assert cats["niche-equipment"] == {
        "support_and_prefer": "2030",
        "exclusive_use": "2033",
    }
    assert cats["custom-legacy"]["exclusive_use"] == "2033"


def test_every_policy_maps_to_known_sources() -> None:
    assert set(rec.POLICY_TIMELINE_SOURCES) == set(pr.VALID_POLICIES)
    for ids in rec.POLICY_TIMELINE_SOURCES.values():
        assert set(ids) <= set(rec.POLICY_SOURCES)


@pytest.mark.parametrize("policy", ["auto", "cnsa-2.0", "commercial"])
def test_recommend_document_carries_all_sources(policy: str) -> None:
    doc = pr.recommend(_report(), policy=policy, role="tls-server")
    assert set(doc["policy_sources"]) == set(rec.POLICY_SOURCES)


@pytest.mark.parametrize(
    ("role", "category", "exclusive"),
    [
        ("tls-server", "web-browsers-servers-cloud", "2033"),
        ("tls-client", "web-browsers-servers-cloud", "2033"),
        ("signing-service", "software-firmware-signing", "2030"),
        ("firmware-signing", "software-firmware-signing", "2030"),
    ],
)
def test_cnsa_records_carry_the_role_category(
    role: str, category: str, exclusive: str
) -> None:
    record = pr.recommend(_report(), policy="cnsa-2.0", role=role)["recommendations"][
        "cnsa-2.0"
    ]
    tl = record["timeline"]
    assert tl["sources"] == ["us-nss-cnsa-2.0"]
    assert tl["cnsa_2_0_category"]["category"] == category
    assert tl["cnsa_2_0_category"]["exclusive_use"] == exclusive


def test_non_cnsa_and_generic_records_have_no_category() -> None:
    doc = pr.recommend(_report(), policy="auto", role="tls-server")
    for policy in ("nist-civilian", "eu-anssi-bsi", "commercial"):
        assert "cnsa_2_0_category" not in doc["recommendations"][policy]["timeline"]
    assert doc["recommendations"]["eu-anssi-bsi"]["timeline"]["sources"] == [
        "eu",
        "de-bsi",
        "fr-anssi",
    ]
    assert doc["recommendations"]["commercial"]["timeline"]["sources"] == []
    stub = pr.recommend(_report(), policy="cnsa-2.0", role="generic")[
        "recommendations"
    ]["cnsa-2.0"]
    assert stub["timeline"] == {"sources": ["us-nss-cnsa-2.0"]}


def test_cnsa_hybrid_position_matches_the_faq() -> None:
    citation = rec.POLICY_PREFERENCES["cnsa-2.0"]["citation"]
    assert "permitted only where" not in citation
    assert "not required" in citation


def test_policy_docs_cite_the_verified_documents() -> None:
    doc = REPO / "docs" / "recommendation-policies.md"
    if not doc.exists():  # docs are absent in the slim container test images
        pytest.skip("docs/ not shipped in this image")
    text = doc.read_text()
    # The ANSSI link used to point at its quantum key distribution paper.
    assert "quantum-key-distribution" not in text
    assert "follow-position-paper-post-quantum-cryptography" in text
    assert "TR-02102-1" in text and "2026-01" in text
    assert "v1.1" in text
