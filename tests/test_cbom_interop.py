"""--cbom-interop: CBOM shapes for SBOM-oriented consumers (#175).

Behaviour these modes target was observed with real uploads (#147,
docs/integrations/dependency-track.md): Dependency-Track 5.x keeps
cryptographic-asset components but drops `cryptoProperties` (its export is
CycloneDX 1.5), keeping free-form `properties`; 4.x rejects any BOM that
contains a cryptographic asset.
"""

from __future__ import annotations

import json
from collections import Counter
from typing import Any

import pytest
from conftest import FIXTURES
from test_cbom import _make_report, _validate_with_jsonschema

import pqc_readiness as pr
from pqc_readiness.render import cbom

MIRROR = "pqc-readiness:crypto:"


def _report() -> pr.Report:
    r = _make_report()
    r.trust_store["certificates"] = [
        {
            "sha256": "ab" * 32,
            "subject": "CN=Fixture Root",
            "issuer": "CN=Fixture Root",
            "not_before": "2020-01-01T00:00:00+00:00",
            "not_after": "2099-01-01T00:00:00+00:00",
            "category": "classical",
            "role": "ca",
        }
    ]
    return r


def _bom(version: str, interop: str, r: pr.Report | None = None) -> dict[str, Any]:
    return json.loads(cbom.render_cbom(r or _report(), version, "none", interop))


def _mirrored(comp: dict[str, Any]) -> dict[str, str]:
    return {
        p["name"][len(MIRROR) :]: p["value"]
        for p in comp.get("properties", [])
        if p["name"].startswith(MIRROR)
    }


def _strip_volatile(bom: dict[str, Any]) -> dict[str, Any]:
    bom = dict(bom)
    bom.pop("serialNumber", None)
    return bom


@pytest.mark.parametrize("version", ["1.7", "1.6"])
def test_default_interop_leaves_output_unchanged(version: str) -> None:
    r = _report()
    default = json.loads(cbom.render_cbom(r, version))
    explicit = _bom(version, cbom.INTEROP_NONE, r)
    assert _strip_volatile(default) == _strip_volatile(explicit)
    assert "dependencies" not in default
    assert all(c["type"] == "cryptographic-asset" for c in default["components"])


@pytest.mark.parametrize("version", ["1.7", "1.6"])
def test_dependency_track_mode_mirrors_crypto_facts(version: str) -> None:
    bom = _bom(version, cbom.INTEROP_DEPENDENCY_TRACK)
    _validate_with_jsonschema(bom, version)
    crypto = [c for c in bom["components"] if c["type"] == "cryptographic-asset"]
    assert crypto and all("assetType" in _mirrored(c) for c in crypto)
    mlkem = next(c for c in crypto if c["name"] == "ML-KEM-1024")
    facts = _mirrored(mlkem)
    algo = mlkem["cryptoProperties"]["algorithmProperties"]
    assert facts["primitive"] == algo["primitive"] == "kem"
    assert facts["parameterSetIdentifier"] == str(algo["parameterSetIdentifier"])
    assert facts["nistQuantumSecurityLevel"] == str(algo["nistQuantumSecurityLevel"])
    assert facts["classification"] == "pure-pqc"
    # cryptoProperties stays the authoritative field.
    assert mlkem["cryptoProperties"]["assetType"] == "algorithm"


def test_dependency_track_mode_mirrors_certificate_facts() -> None:
    bom = _bom("1.7", cbom.INTEROP_DEPENDENCY_TRACK)
    cert = next(
        c for c in bom["components"] if c["bom-ref"] == "cert/sha256:" + "ab" * 32
    )
    facts = _mirrored(cert)
    assert facts["assetType"] == "certificate"
    assert facts["certificateSha256"] == "ab" * 32
    assert facts["subjectName"] == "CN=Fixture Root"
    assert facts["certificateState"] == "active"
    assert facts["classification"] == "classical"


@pytest.mark.parametrize("version", ["1.7", "1.6"])
def test_library_components_have_purls_and_provide_links(version: str) -> None:
    bom = _bom(version, cbom.INTEROP_DEPENDENCY_TRACK)
    refs = {c["bom-ref"] for c in bom["components"]} | {
        bom["metadata"]["component"]["bom-ref"]
    }
    libs = [c for c in bom["components"] if c["type"] == "library"]
    assert libs, "probed stacks should yield library components"
    for lib in libs:
        assert lib["purl"] == lib["bom-ref"] and lib["purl"].startswith("pkg:")
    deps = {d["ref"]: d for d in bom["dependencies"]}
    host = deps[bom["metadata"]["component"]["bom-ref"]]
    assert sorted(host["dependsOn"]) == sorted(lib["bom-ref"] for lib in libs)
    provided = [ref for d in bom["dependencies"] for ref in d.get("provides", [])]
    assert provided and set(provided) <= refs
    openssl = next(lib for lib in libs if lib["name"] == "openssl")
    assert openssl["purl"].startswith("pkg:generic/openssl@")
    assert deps[openssl["bom-ref"]]["provides"]


@pytest.mark.parametrize("version", ["1.7", "1.6"])
def test_sbom_only_mode_has_no_cryptographic_assets(version: str) -> None:
    bom = _bom(version, cbom.INTEROP_SBOM_ONLY)
    _validate_with_jsonschema(bom, version)
    assert bom["components"] and {c["type"] for c in bom["components"]} == {"library"}
    refs = {c["bom-ref"] for c in bom["components"]} | {
        bom["metadata"]["component"]["bom-ref"]
    }
    for dep in bom["dependencies"]:
        assert dep["ref"] in refs and "provides" not in dep
        assert set(dep.get("dependsOn", [])) <= refs


def test_distro_packages_get_distro_purls_with_encoded_versions() -> None:
    r = _report()
    r.os_release = {"family": "debian", "id": "debian", "version_id": "13"}
    r.packages = {
        "available": True,
        "bundled_crypto": [
            {
                "package": "openjdk-21-jre-headless",
                "version": "21.0.8+9-1",
                "note": "Java",
            },
            {"package": "libgnutls30t64", "version": "3.8.9-3", "note": "GnuTLS"},
            {"package": "epochpkg", "version": "1:2.3-4", "note": "epoch"},
        ],
    }
    libs = {
        c["name"]: c["purl"]
        for c in _bom("1.7", cbom.INTEROP_SBOM_ONLY, r)["components"]
        if c["type"] == "library"
    }
    assert (
        libs["libgnutls30t64"]
        == "pkg:deb/debian/libgnutls30t64@3.8.9-3?distro=debian-13"
    )
    assert libs["openjdk-21-jre-headless"] == (
        "pkg:deb/debian/openjdk-21-jre-headless@21.0.8+9-1?distro=debian-13"
    )
    assert libs["epochpkg"] == "pkg:deb/debian/epochpkg@1%3A2.3-4?distro=debian-13"


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (
            "openssl@OpenSSL 3.5.9 29 Sep 2026 (Library: OpenSSL 3.5.9 29 Sep 2026)",
            ("openssl", "3.5.9"),
        ),
        (
            "openssl@OpenSSL 3.5.1 1 Jul 2025 (Library: OpenSSL 3.5.5 27 Jan 2026)",
            ("openssl", "3.5.5"),
        ),
        ("openssl@OpenSSL 3.0.13 30 Jan 2024", ("openssl", "3.0.13")),
        ("openssl@3.5.5", ("openssl", "3.5.5")),
        ("openssh@10.2p1", ("openssh", "10.2p1")),
        ("openssh@unknown", None),
        ("noversion", None),
        ("openssl@garbage", None),
    ],
)
def test_library_from_source(source: str, expected: tuple[str, str] | None) -> None:
    assert cbom._library_from_source(source) == expected


def test_unknown_interop_mode_is_rejected() -> None:
    with pytest.raises(ValueError, match="interop"):
        cbom.render_cbom(_report(), "1.7", "none", "nope")


def test_mirrored_facts_survive_dependency_track_round_trip() -> None:
    """Fixture: the dependency-track-mode CBOM of this exact stub report,
    uploaded to Dependency-Track 5.2.0 and exported back (2026-10-13, #175;
    regenerated for the #194 `providedBy` mirror).
    DT exports CycloneDX 1.5 and drops cryptoProperties; every mirrored
    property set must still be there.  If the mirroring changes on purpose,
    regenerate the fixture against a real 5.x server."""
    exported = json.loads(
        (
            FIXTURES / "dependency-track" / "dt-5.2.0-export-of-interop-cbom.json"
        ).read_text()
    )
    assert exported["specVersion"] == "1.5"
    assert not any(c.get("cryptoProperties") for c in exported["components"])
    ours = _bom("1.7", cbom.INTEROP_DEPENDENCY_TRACK)

    def signature(
        bom: dict[str, Any],
    ) -> Counter[tuple[str, tuple[tuple[str, str], ...]]]:
        return Counter(
            (c["name"], tuple(sorted(_mirrored(c).items())))
            for c in bom["components"]
            if _mirrored(c)
        )

    assert signature(ours) == signature(exported)
    assert {c["purl"] for c in ours["components"] if c["type"] == "library"} == {
        c["purl"] for c in exported["components"] if c.get("purl")
    }


def test_cli_interop_selection_does_not_leak_between_runs(monkeypatch, capsys) -> None:
    from pqc_readiness import cli

    monkeypatch.setattr(cli, "collect_report", lambda args: _report())
    cli.main(["--cbom", "--cbom-interop", "sbom-only"])
    assert {c["type"] for c in json.loads(capsys.readouterr().out)["components"]} == {
        "library"
    }
    cli.main(["--cbom"])
    out = json.loads(capsys.readouterr().out)
    assert "dependencies" not in out
    assert cbom._selected_interop == cbom.INTEROP_NONE
