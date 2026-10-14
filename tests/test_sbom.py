# SPDX-License-Identifier: Apache-2.0
"""--sbom: plain CycloneDX package SBOM without crypto assets (#157)."""

from __future__ import annotations

import dataclasses
import gzip
import json
import shutil
from pathlib import Path
from typing import Any

import pytest

from pqc_readiness.render import sbom
from test_cbom import _validate_with_jsonschema
from test_sarif import _empty_report

EMBEDDED = Path(__file__).parent / "fixtures" / "embedded"

OPENWRT_24 = {"family": "openwrt", "id": "openwrt", "version_id": "24.10.8"}

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
        # Probed databases (#227).  purl-spec has no opkg type.
        (
            {"name": "busybox", "version": "1.36.1-r3", "db": "opkg"},
            OPENWRT_24,
            "pkg:generic/openwrt/busybox@1.36.1-r3",
        ),
        (
            {"name": "openssl", "version": "3.5.7-r0", "db": "opkg"},
            {"family": "unknown", "id": "unknown"},
            "pkg:generic/openssl@3.5.7-r0",
        ),
        # OpenWrt 25.12 moved to apk; the apk type lowercases names.
        (
            {"name": "libMixed", "version": "1-r1", "db": "alpine"},
            {"family": "openwrt", "id": "openwrt", "version_id": "25.12.5"},
            "pkg:apk/openwrt/libmixed@1-r1?distro=openwrt-25.12.5",
        ),
        # A probed rpm tree with no os-release and no Yocto marker has no
        # vendor namespace: no purl (counted, not dropped silently).
        (
            {"name": "zlib", "version": "1.3", "db": "rpm"},
            {"family": "unknown", "id": "unknown"},
            None,
        ),
        # Yocto via os-release ID=poky: the recipe purl from SOURCERPM.
        (
            {
                "name": "libc6",
                "version": "2.43+git0+e9517114ac",
                "release": "r1",
                "arch": "x86_64_v3",
                "sourcerpm": "glibc-2.43+git0+e9517114ac-r1.src.rpm",
                "db": "rpm",
            },
            {"family": "unknown", "id": "poky", "version_id": "6.0.3"},
            "pkg:yocto/glibc@2.43%2Bgit0%2Be9517114ac",
        ),
    ],
)
def test_package_purl(
    pkg: dict[str, Any], osr: dict[str, Any], expected: str | None
) -> None:
    assert sbom.package_purl(pkg, osr) == expected


def test_yocto_rpm_without_sourcerpm_falls_back_to_the_distro_vendor() -> None:
    # The rpm CLI fallback doesn't carry SOURCERPM; /etc/buildinfo still
    # names the distro, so the package gets an rpm purl under it.
    pkg = {"name": "zlib", "version": "1.3.1", "release": "r0", "db": "rpm"}
    osr = {"family": "unknown", "id": "unknown"}
    info = {"DISTRO": "poky", "DISTRO_VERSION": "6.0.3"}
    assert (
        sbom.package_purl(pkg, osr, info)
        == "pkg:rpm/poky/zlib@1.3.1-r0?distro=poky-6.0.3"
    )


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


# ------------------------------------------- probed databases (#227)


@pytest.fixture
def prefix(monkeypatch: pytest.MonkeyPatch):
    """Point the readers at a tree; no subprocesses (offline reads only)."""
    from pqc_readiness.detect import packages

    def use(root: Path) -> None:
        monkeypatch.setattr(sbom._platform, "HOST_PREFIX", str(root))
        packages._PROBE_CACHE.clear()
        packages._query_rpm_packages_cached.cache_clear()

    def refuse(cmd: list[str], timeout: int = 10) -> tuple[int, str]:
        raise AssertionError(f"subprocess in an offline SBOM: {cmd}")

    monkeypatch.setattr(sbom._platform, "_run", refuse)
    yield use
    packages._PROBE_CACHE.clear()
    packages._query_rpm_packages_cached.cache_clear()


def _components(doc: dict[str, Any]) -> list[dict[str, Any]]:
    return [c for c in doc["components"] if c["type"] == "library"]


def test_openwrt_opkg_sbom_matches_opkg_list_installed(tmp_path, prefix) -> None:
    root = tmp_path / "openwrt"
    shutil.copytree(EMBEDDED / "openwrt-24.10.8", root)
    prefix(root)
    doc = sbom.build_sbom(_report(OPENWRT_24))
    _validate_with_jsonschema(doc, "1.6")
    lines = (EMBEDDED / "openwrt-24.10.8.opkg-list-installed.txt").read_text()
    expected = sorted(tuple(x.split(" - ", 1)) for x in lines.splitlines())
    comps = _components(doc)
    assert sorted((c["name"], c["version"]) for c in comps) == expected
    assert len(comps) == 129
    assert all(c["purl"].startswith("pkg:generic/openwrt/") for c in comps)


def test_openwrt_25_apk_sbom_matches_apk_info(tmp_path, prefix) -> None:
    root = tmp_path / "openwrt"
    shutil.copytree(EMBEDDED / "openwrt-25.12.5", root)
    prefix(root)
    osr = {"family": "openwrt", "id": "openwrt", "version_id": "25.12.5"}
    doc = sbom.build_sbom(_report(osr))
    _validate_with_jsonschema(doc, "1.6")
    lines = (EMBEDDED / "openwrt-25.12.5.apk-info-v.txt").read_text().split()
    comps = _components(doc)
    assert sorted(f"{c['name']}-{c['version']}" for c in comps) == sorted(lines)
    assert all(c["purl"].startswith("pkg:apk/openwrt/") for c in comps)


def _yocto_tree(tmp_path: Path) -> Path:
    root = tmp_path / "yocto"
    shutil.copytree(EMBEDDED / "yocto-6.0.3-core-image-full-cmdline", root)
    gz = root / "var/lib/rpm/rpmdb.sqlite.gz"
    (root / "var/lib/rpm/rpmdb.sqlite").write_bytes(gzip.decompress(gz.read_bytes()))
    gz.unlink()
    return root


def test_yocto_rpm_sbom_uses_recipe_purls(tmp_path, prefix) -> None:
    prefix(_yocto_tree(tmp_path))
    # Prebuilt Yocto images ship no os-release: the report has placeholders.
    osr = {"family": "unknown", "id": "unknown", "pretty_name": "Linux 7.2.10"}
    doc = sbom.build_sbom(_report(osr))
    _validate_with_jsonschema(doc, "1.6")
    comps = {c["name"]: c for c in _components(doc)}
    # Values from the image's own .manifest and the rpm SOURCERPM tags.
    assert {n: (c["version"], c["purl"]) for n, c in comps.items()} == {
        "libcrypto3": ("3.5.7-r0", "pkg:yocto/openssl@3.5.7"),
        "libssl3": ("3.5.7-r0", "pkg:yocto/openssl@3.5.7"),
        "openssl-bin": ("3.5.7-r0", "pkg:yocto/openssl@3.5.7"),
        "libsmartcols1": ("2.41.5-r0", "pkg:yocto/util-linux@2.41.5"),
    }
    # One recipe, three binary packages: bom-refs stay unique.
    refs = [c["bom-ref"] for c in doc["components"]]
    assert len(refs) == len(set(refs))
    assert comps["libssl3"]["bom-ref"] == "pkg:yocto/openssl@3.5.7#libssl3"
    # /etc/buildinfo names the OS; the kernel fallback isn't the OS name.
    os_comp = doc["components"][0]
    assert (os_comp["bom-ref"], os_comp["name"], os_comp["version"]) == (
        "os:poky",
        "poky",
        "6.0.3",
    )
    assert "description" not in os_comp


def test_tree_without_package_database_says_so(tmp_path, prefix) -> None:
    (tmp_path / "etc").mkdir()
    prefix(tmp_path)
    doc = sbom.build_sbom(_report({"family": "unknown", "id": "unknown"}))
    props = {p["name"]: p["value"] for p in doc["metadata"]["properties"]}
    assert props["pqc-readiness:sbom:package-count"] == "0"
    assert "no package database found" in props["pqc-readiness:sbom:unavailable-reason"]


def test_packages_without_purl_are_counted(monkeypatch) -> None:
    pkgs = [{"name": "zlib", "version": "1.3", "db": "rpm"}]
    monkeypatch.setattr(sbom, "installed_packages", lambda osr: (pkgs, None))
    monkeypatch.setattr(sbom, "read_buildinfo", lambda: {})
    doc = sbom.build_sbom(_report({"family": "unknown", "id": "unknown"}))
    props = {p["name"]: p["value"] for p in doc["metadata"]["properties"]}
    assert props["pqc-readiness:sbom:packages-without-purl"] == "1"
    assert _components(doc) == []
