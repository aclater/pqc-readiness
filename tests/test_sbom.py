# SPDX-License-Identifier: Apache-2.0
"""--sbom: plain CycloneDX package SBOM without crypto assets (#157)."""

from __future__ import annotations

import dataclasses
import json
from typing import Any

import pytest

from pqc_readiness.render import sbom
from test_cbom import _validate_with_jsonschema
from test_sarif import _empty_report

FEDORA = {
    "family": "rhel",
    "id": "fedora",
    "version_id": "44",
    "pretty_name": "Fedora 44",
}


def _report(os_release: dict[str, Any]) -> Any:
    return dataclasses.replace(_empty_report(), os_release=os_release, hostname="h1")


@pytest.mark.parametrize(
    ("pkg", "osr", "expected"),
    [
        (
            {
                "name": "openssl-libs",
                "version": "3.5.5",
                "release": "1.fc44",
                "arch": "x86_64",
                "epoch": 1,
            },
            FEDORA,
            "pkg:rpm/fedora/openssl-libs@3.5.5-1.fc44?arch=x86_64&distro=fedora-44&epoch=1",
        ),
        (
            {
                "name": "bash",
                "version": "5.2.37",
                "release": "1.el10",
                "arch": "x86_64",
                "epoch": None,
            },
            {"family": "rhel", "id": "rhel", "version_id": "10.2"},
            "pkg:rpm/rhel/bash@5.2.37-1.el10?arch=x86_64&distro=rhel-10.2",
        ),
        (
            {"name": "libssl3t64", "version": "3.5.4-1"},
            {"family": "debian", "id": "debian", "version_id": "13"},
            "pkg:deb/debian/libssl3t64@3.5.4-1?distro=debian-13",
        ),
        (
            {"name": "musl", "version": "1.2.5-r10"},
            {"family": "alpine", "id": "alpine", "version_id": "3.22.6"},
            "pkg:apk/alpine/musl@1.2.5-r10?distro=alpine-3.22.6",
        ),
        (
            {"name": "openssl", "version": "3.6.0-1"},
            {"family": "arch", "id": "arch"},
            "pkg:alpm/arch/openssl@3.6.0-1?distro=arch",
        ),
        ({"name": "x", "version": "1"}, {"family": "unknown", "id": "foo"}, None),
        ({"name": "x", "version": "1"}, {"family": "rhel"}, None),
    ],
)
def test_package_purl(
    pkg: dict[str, Any], osr: dict[str, Any], expected: str | None
) -> None:
    assert sbom.package_purl(pkg, osr) == expected


def test_sbom_lists_packages_without_crypto_assets(monkeypatch) -> None:
    pkgs = [
        {
            "name": "openssl-libs",
            "version": "3.5.5",
            "release": "1.fc44",
            "arch": "x86_64",
        },
        {
            "name": "openssl-libs",
            "version": "3.5.5",
            "release": "1.fc44",
            "arch": "x86_64",
        },
        {"name": "gpg-pubkey", "version": "abcd1234", "release": "5f0a"},
        {"name": "bash", "version": "5.3.0", "release": "2.fc44", "arch": "x86_64"},
    ]
    monkeypatch.setattr(sbom, "installed_packages", lambda osr: (pkgs, None))
    doc = sbom.build_sbom(_report(FEDORA))
    _validate_with_jsonschema(doc, "1.6")
    names = [c["name"] for c in doc["components"]]
    assert names == [
        "fedora",
        "bash",
        "openssl-libs",
    ]  # OS first, then sorted, deduplicated
    assert all(c["type"] != "cryptographic-asset" for c in doc["components"])
    assert doc["specVersion"] == "1.6"
    deps = doc["dependencies"][0]
    assert deps["ref"] == "host/h1" and len(deps["dependsOn"]) == 3
    props = {p["name"]: p["value"] for p in doc["metadata"]["properties"]}
    assert props["pqc-readiness:sbom:package-count"] == "2"


def test_sbom_reports_unavailable_inventory(monkeypatch) -> None:
    monkeypatch.setattr(
        sbom, "installed_packages", lambda osr: ([], "rpm database unavailable")
    )
    doc = json.loads(sbom.render_sbom(_report(FEDORA)))
    _validate_with_jsonschema(doc, "1.6")
    props = {p["name"]: p["value"] for p in doc["metadata"]["properties"]}
    assert props["pqc-readiness:sbom:unavailable-reason"] == "rpm database unavailable"
    assert [c["type"] for c in doc["components"]] == ["operating-system"]


def test_rpm_family_reads_shared_inventory(monkeypatch) -> None:
    inv = {"available": True, "packages": [{"name": "zlib", "version": "1.3"}]}
    monkeypatch.setattr(sbom._packages, "query_rpm_packages", lambda: inv)
    pkgs, reason = sbom.installed_packages(FEDORA)
    assert reason is None and pkgs == inv["packages"]


def test_sbom_host_ref_matches_cbom_host_component() -> None:
    # The plain SBOM and the CBOM join per host on the same bom-ref (#157).
    from pqc_readiness.render import cbom

    r = dataclasses.replace(_empty_report(), hostname="h1")
    s_ref = json.loads(sbom.render_sbom(r))["metadata"]["component"]["bom-ref"]
    c_ref = json.loads(cbom.render_cbom(r))["metadata"]["component"]["bom-ref"]
    assert s_ref == c_ref == "host/h1"
