"""--cbom-profile federal-draft and inventory metadata in the CBOM (#144)."""

from __future__ import annotations

import json
import re
from dataclasses import replace
from typing import Any

import pytest
from test_cbom import _make_report, _validate_with_jsonschema

import pqc_readiness as pr
from pqc_readiness.render import cbom, cbom_profiles

FED = cbom_profiles.FEDERAL_DRAFT
META = {
    "fisma_system_id": "ABC-1234",
    "fips199_categorization": "High",
    "hosting": {"model": "government-csp", "provider": "Example Gov Cloud"},
    "data_lifecycle": {"records_categories": ["GRS 3.2"], "time_to_live_years": 25},
}


def _bom(
    version: str = "1.7", profile: str = "federal-draft", r: pr.Report | None = None
) -> dict[str, Any]:
    out: dict[str, Any] = json.loads(
        pr.render_cbom(r or _make_report(), version, profile)
    )
    return out


def _props(component: dict[str, Any]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for p in component.get("properties", []):
        out.setdefault(p["name"], []).append(p["value"])
    return out


def _by_ref(bom: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {c["bom-ref"]: c for c in bom["components"]}


def _meta(bom: dict[str, Any]) -> dict[str, str]:
    return {p["name"]: p["value"] for p in bom["metadata"].get("properties", [])}


@pytest.mark.parametrize("version", ["1.6", "1.7"])
def test_default_profile_output_is_unchanged(version: str) -> None:
    r = _make_report()
    a = json.loads(pr.render_cbom(r, version))
    b = json.loads(pr.render_cbom(r, version, "none"))
    a["serialNumber"] = b["serialNumber"] = "x"
    assert a == b
    assert "properties" not in a["metadata"]
    assert not any(
        p["name"].startswith("federal:")
        for c in a["components"]
        for p in c.get("properties", [])
    )


@pytest.mark.parametrize("version", ["1.6", "1.7"])
def test_federal_draft_validates_against_the_schema(version: str) -> None:
    r = replace(_make_report(), inventory_metadata=META)
    _validate_with_jsonschema(_bom(version, r=r), version)


def test_unknown_profile_is_rejected() -> None:
    with pytest.raises(ValueError, match="unsupported CBOM profile"):
        pr.render_cbom(_make_report(), "1.7", "federal-final")


@pytest.mark.parametrize("version", ["1.6", "1.7"])
def test_classical_groups_are_added_as_quantum_vulnerable_key_establishment(
    version: str,
) -> None:
    comps = _by_ref(_bom(version))
    for ref in ("openssl/tls-classical/X25519", "openssl/tls-classical/P-256"):
        props = _props(comps[ref])
        assert props["federal:function"] == ["key-establishment"]
        assert props["federal:quantum_vulnerable"] == ["true"]
        assert props["federal:migration_deadline"] == ["2030-12-31"]
        assert props["federal:migration_deadline:source"] == ["EO 14412 §4(b)(ii)"]
        assert props["federal:in_use_including_fallback"] == ["possible"]
        assert props["federal:in_use_basis"] == ["library-capability"]


def test_classical_ssh_kex_is_added() -> None:
    r = _make_report()
    r = replace(
        r,
        ssh_pqc={
            **r.ssh_pqc,
            "kex_groups": {
                **r.ssh_pqc["kex_groups"],
                "classical": ["curve25519-sha256"],
            },
        },
    )
    comps = _by_ref(_bom(r=r))
    props = _props(comps["ssh/kex/classical/curve25519-sha256"])
    assert props["federal:quantum_vulnerable"] == ["true"]
    # 1.7: the classical kex is linked from the SSH protocol component too.
    refs = [
        a["ref"]
        for a in comps["protocol/ssh"]["cryptoProperties"]["protocolProperties"][
            "relatedCryptographicAssets"
        ]
    ]
    assert "ssh/kex/classical/curve25519-sha256" in refs


def test_pqc_and_hybrid_assets_are_not_vulnerable_and_have_no_deadline() -> None:
    comps = _by_ref(_bom())
    for ref, function in (
        ("openssl/kem/ML-KEM-768", "key-establishment"),
        ("openssl/sig/ML-DSA-65", "digital-signature"),
        (
            "openssl/tls-hybrid/X25519MLKEM768",  # pragma: allowlist secret
            "key-establishment",
        ),
        ("ssh/kex/hybrid/mlkem768x25519-sha256", "key-establishment"),
    ):
        props = _props(comps[ref])
        assert props["federal:function"] == [function], ref
        assert props["federal:quantum_vulnerable"] == ["false"], ref
        assert "federal:migration_deadline" not in props, ref


def test_hardware_assets_get_no_federal_annotations() -> None:
    checked = 0
    for ref, comp in _by_ref(_bom()).items():
        if ref.startswith(
            ("isa/", "accel/", "tpm/", "pkcs11/", "ipsec/", "trust-store/")
        ):
            assert not any(n.startswith("federal:") for n in _props(comp)), ref
            checked += 1
    assert checked >= 6


def test_certificates_are_classified_as_signatures() -> None:
    r = _make_report()
    r = replace(
        r,
        trust_store={
            **r.trust_store,
            "certificates": [
                {
                    "sha256": "a" * 64,
                    "subject": "CN=Classical",
                    "category": "classical",
                },
                {"sha256": "b" * 64, "subject": "CN=PQC", "category": "pure_pqc"},
            ],
        },
    )
    comps = _by_ref(_bom(r=r))
    classical = _props(comps["cert/sha256:" + "a" * 64])
    assert classical["federal:function"] == ["digital-signature"]
    assert classical["federal:migration_deadline"] == ["2031-12-31"]
    assert classical["federal:migration_deadline:source"] == ["EO 14412 §4(b)(iii)"]
    pqc = _props(comps["cert/sha256:" + "b" * 64])
    assert pqc["federal:quantum_vulnerable"] == ["false"]


def test_profile_metadata_records_status_sources_and_counts() -> None:
    meta = _meta(_bom())
    assert meta["federal:profile"] == "federal-draft"
    assert "EO 14412 §5(d)" in meta["federal:profile:status"]
    for key in ("eo_14412", "omb_m_26_15", "omb_m_23_02"):
        assert meta[f"federal:source:{key}"].startswith("https://")
    assert meta["federal:tls13_deadline"] == "2030-01-02"
    assert meta["federal:tls13_deadline:source"] == "OMB M-26-15 §4 (EO 14306)"
    # synthetic report: X25519 + P-256 classical; 3 KEM + 3 sig + 1 hybrid
    # + 1 pure TLS group + 2 hybrid SSH kex are PQC-protected.
    assert meta["federal:quantum_vulnerable_assets"] == "2"
    assert meta["federal:quantum_resistant_assets"] == "10"


@pytest.mark.parametrize(
    ("openssl", "status"),
    [
        ({"available": True, "version_tuple": [3, 5, 5]}, "capable"),
        ({"available": True, "version_tuple": [1, 1, 1]}, "capable"),
        ({"available": True, "version_tuple": [1, 1, 0]}, "not-capable"),
        ({"available": True, "version_tuple": None}, "unknown"),
        ({"available": False}, "unknown"),
    ],
)
def test_tls13_status(openssl: dict[str, Any], status: str) -> None:
    r = replace(_make_report(), openssl=openssl)
    assert _meta(_bom(r=r))["federal:tls13_status"] == status


def test_m23_02_items_without_and_with_metadata() -> None:
    bare = _meta(_bom())
    assert bare["federal:m23_02:item1"] == "not-provided"
    assert bare["federal:m23_02:item4"] == "collected"
    assert bare["federal:m23_02:item5"] == "not-collected"  # no --scan-packages
    assert bare["federal:m23_02:item6"] == "collected"
    assert bare["federal:m23_02:item7"] == "not-provided"
    r = replace(_make_report(), inventory_metadata=META, packages={"available": True})
    full = _meta(_bom(r=r))
    for item in (1, 2, 7, 8):
        assert full[f"federal:m23_02:item{item}"] == "provided", item
    assert full["federal:m23_02:item3"] == "not-provided"  # no HVA id
    assert full["federal:m23_02:item5"] == "partial"
    assert full["federal:m23_02:item9:label"] == "Additional notes"


@pytest.mark.parametrize("profile", ["none", "federal-draft"])
def test_inventory_metadata_lands_on_the_host_component(profile: str) -> None:
    r = replace(_make_report(), inventory_metadata=META)
    host = _bom(profile=profile, r=r)["metadata"]["component"]
    props = _props(host)
    assert props["inventory:fisma_system_id"] == ["ABC-1234"]
    assert props["inventory:fips199_categorization"] == ["High"]
    assert props["inventory:hosting:model"] == ["government-csp"]
    assert props["inventory:hosting:provider"] == ["Example Gov Cloud"]
    assert props["inventory:data_lifecycle:records_category"] == ["GRS 3.2"]
    assert props["inventory:data_lifecycle:time_to_live_years"] == ["25"]


def test_profile_table_is_well_formed() -> None:
    """The profile is data; keep it internally consistent so a remap (#150)
    can't silently drop a deadline or a source."""
    functions = set(FED["function_by_primitive"].values())
    assert functions == set(FED["deadlines"])
    for date, clause in (*FED["deadlines"].values(), FED["tls13_deadline"]):
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", date)
        assert clause
    assert [n for n, _, _ in FED["m23_02_items"]] == list(range(1, 10))
    for _, _, source in FED["m23_02_items"]:
        kind, _, what = source.partition(":")
        assert kind in ("metadata", "scan") and what
    assert set(cbom_profiles.PROFILES) == {"none", "federal-draft"}


def test_cli_profile_selection_does_not_leak_between_runs(monkeypatch, capsys) -> None:
    from pqc_readiness import cli

    monkeypatch.setattr(cli, "collect_report", lambda args: _make_report())
    cli.main(["--cbom", "--cbom-profile", "federal-draft"])
    assert (
        _meta(json.loads(capsys.readouterr().out))["federal:profile"] == "federal-draft"
    )
    cli.main(["--cbom"])
    assert "properties" not in json.loads(capsys.readouterr().out)["metadata"]
    assert cbom._selected_profile == "none"


def test_discovered_host_certificates_are_classified_too() -> None:
    """#178: the federal profile classifies host certificates found by
    --scan-crypto-material, not only trust-store anchors."""
    r = replace(
        _make_report(),
        crypto_material={
            "available": True,
            "certificates": [
                {
                    "sha256": "d" * 64,
                    "subject": "CN=web",
                    "category": "classical",
                    "role": "leaf",
                },
                {
                    "sha256": "e" * 64,
                    "subject": "CN=pqc",
                    "category": "pure_pqc",
                    "role": "leaf",
                },
            ],
        },
    )
    comps = _by_ref(_bom(r=r))
    classical = _props(comps["cert/sha256:" + "d" * 64])
    assert classical["federal:function"] == ["digital-signature"]
    assert classical["federal:quantum_vulnerable"] == ["true"]
    assert classical["federal:migration_deadline"] == ["2031-12-31"]
    assert _props(comps["cert/sha256:" + "e" * 64])["federal:quantum_vulnerable"] == [
        "false"
    ]
