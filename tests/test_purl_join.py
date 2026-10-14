# SPDX-License-Identifier: Apache-2.0
"""--cbom and --sbom spell every package purl the same way (#257, #243).

For each real fixture tree, every installed package is sent through the
two paths the CBOM uses to name a package (a detected library's owning
package, and a bundled-crypto package row), and the result must be the
exact purl --sbom emits for it.  Purls are compared as strings: an importer
joining the two documents does the same.
"""

from __future__ import annotations

import dataclasses
import gzip
import shutil
from pathlib import Path
from typing import Any

import pytest

from pqc_readiness.detect import osinfo, packages
from pqc_readiness.render import cbom, sbom
from test_sarif import _empty_report

FIXTURES = Path(__file__).parent / "fixtures"


def _rpm_tree(tmp: Path, name: str, os_release_text: str) -> Path:
    root = tmp / name
    shutil.copytree(FIXTURES / "rpmdb" / name, root)
    (root / "etc").mkdir(exist_ok=True)
    (root / "etc/os-release").write_text(os_release_text)
    return root


def _yocto_tree(tmp: Path) -> Path:
    root = tmp / "yocto"
    shutil.copytree(FIXTURES / "embedded/yocto-6.0.3-core-image-full-cmdline", root)
    gz = root / "var/lib/rpm/rpmdb.sqlite.gz"
    (root / "var/lib/rpm/rpmdb.sqlite").write_bytes(gzip.decompress(gz.read_bytes()))
    gz.unlink()
    return root


def _copy(tmp: Path, rel: str) -> Path:
    root = tmp / Path(rel).name
    shutil.copytree(FIXTURES / rel, root)
    return root


# (tree id, builder, os-release text written into the tree or None to use
# the tree's own).  The rpm database fixtures carry no os-release; the
# Fedora one comes from a Fedora 44 image and the el9 one from RHEL 9.
TREES = {
    "fedora44-rpm": lambda t: _rpm_tree(
        t, "fedora44", 'ID=fedora\nVERSION_ID=44\nNAME="Fedora Linux"\n'
    ),
    "el9-rpm": lambda t: _rpm_tree(
        t, "el9", (FIXTURES / "os-release/rhel-9.txt").read_text()
    ),
    "debian13-dpkg": lambda t: _copy(t, "packages/debian-13"),
    "openwrt-24.10.8-opkg": lambda t: _copy(t, "embedded/openwrt-24.10.8"),
    "openwrt-25.12.5-apk": lambda t: _copy(t, "embedded/openwrt-25.12.5"),
    "yocto-6.0.3-rpm": _yocto_tree,
}

# Fixture trees without an os-release of their own: what the scanner's
# OpenWrt release-file reader reports for them.
OPENWRT_RELEASE = {
    "openwrt-24.10.8-opkg": {
        "family": "openwrt",
        "id": "openwrt",
        "version_id": "24.10.8",
    },
    "openwrt-25.12.5-apk": {
        "family": "openwrt",
        "id": "openwrt",
        "version_id": "25.12.5",
    },
}


@pytest.fixture
def tree(
    request: pytest.FixtureRequest, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    def refuse(cmd: list[str], timeout: int = 10) -> tuple[int, str]:
        raise AssertionError(f"subprocess in an offline scan: {cmd}")

    root = TREES[request.param](tmp_path)
    monkeypatch.setattr(sbom._platform, "HOST_PREFIX", str(root))
    monkeypatch.setattr(sbom._platform, "_run", refuse)
    packages._PROBE_CACHE.clear()
    packages._query_rpm_packages_cached.cache_clear()
    sbom._PURL_INDEX.clear()
    if request.param in OPENWRT_RELEASE:
        osr = dict(OPENWRT_RELEASE[request.param])
    elif (root / "etc/os-release").exists():
        osr = osinfo.parse_os_release((root / "etc/os-release").read_text())
    else:
        # Prebuilt Yocto images ship no os-release: the report has placeholders.
        osr = {"family": "unknown", "id": "unknown"}
    yield request.param, osr
    packages._PROBE_CACHE.clear()
    packages._query_rpm_packages_cached.cache_clear()
    sbom._PURL_INDEX.clear()


def _sbom_purls(osr: dict[str, Any]) -> dict[tuple[str, str], str]:
    r = dataclasses.replace(_empty_report(), os_release=osr, hostname="h1")
    doc = sbom.build_sbom(r)
    return {
        (c["name"], c["version"]): c["purl"]
        for c in doc["components"]
        if c["type"] == "library"
    }


def _records(osr: dict[str, Any]) -> list[dict[str, Any]]:
    pkgs, reason = sbom.installed_packages(osr)
    assert pkgs, reason
    return [p for p in pkgs if p.get("name") != "gpg-pubkey"]


def _as_library_owner(pkg: dict[str, Any]) -> dict[str, Any]:
    """The owning-package record --scan-crypto-libraries attaches."""
    return {"name": pkg["name"], "version": pkg["version"]} | {
        k: str(pkg[k])
        for k in ("release", "epoch", "arch")
        if pkg.get(k) not in (None, "")
    }


def _as_bundled_row(pkg: dict[str, Any]) -> dict[str, Any]:
    """The bundled_crypto row --scan-packages emits."""
    return {"package": pkg["name"], "version": pkg["version"], "note": "x"} | {
        k: str(pkg[k])
        for k in ("release", "epoch", "arch")
        if pkg.get(k) not in (None, "")
    }


@pytest.mark.parametrize("tree", list(TREES), indirect=True)
def test_every_cbom_package_purl_is_the_sbom_purl(tree) -> None:
    name, osr = tree
    expected = _sbom_purls(osr)
    assert expected, f"{name}: the SBOM has no package components"
    r = dataclasses.replace(_empty_report(), os_release=osr, hostname="h1")
    checked = 0
    for pkg in _records(osr):
        version = str(pkg["version"]) + (
            f"-{pkg['release']}" if pkg.get("release") else ""
        )
        want = expected.get((str(pkg["name"]), version))
        if want is None:
            continue  # --sbom has no purl for it, so nothing to join on
        assert cbom._package_purl(r, _as_library_owner(pkg)) == want, pkg
        assert (
            sbom.sbom_purl(cbom._package_fields(_as_bundled_row(pkg)), osr) == want
        ), pkg
        # Library ownership on a probed database can carry no release; the
        # name and upstream version still find the package when only one
        # matches (Yocto's libgnutls30 3.8.12 -> pkg:yocto/gnutls@3.8.12).
        same = [
            p
            for p in _records(osr)
            if p["name"] == pkg["name"] and p["version"] == pkg["version"]
        ]
        if len(same) == 1:
            bare = {"name": pkg["name"], "version": pkg["version"]}
            assert cbom._package_purl(r, bare) == want, pkg
        checked += 1
    assert checked == len(expected), f"{name}: {checked} of {len(expected)} joined"


def test_canonical_encoding_follows_ecma_427() -> None:
    # Clause 5.4: alphanumerics, ". - _ ~" and ':' stay; everything else,
    # '+' included, is percent-encoded.
    assert sbom.purl_encode("1:2.41.5-0+deb13u1") == "1:2.41.5-0%2Bdeb13u1"
    assert sbom.purl_encode("3.5.7-1~deb13u3") == "3.5.7-1~deb13u3"
    assert sbom.purl_encode("a b/c@d?e#f") == "a%20b%2Fc%40d%3Fe%23f"
    assert cbom._purl_part("2.43+git0") == "2.43%2Bgit0"


@pytest.mark.parametrize("tree", ["debian13-dpkg"], indirect=True)
def test_debian_purls_are_canonical(tree) -> None:
    _, osr = tree
    purls = _sbom_purls(osr)
    assert purls[("bsdutils", "1:2.41.5-0+deb13u1")] == (
        "pkg:deb/debian/bsdutils@1:2.41.5-0%2Bdeb13u1?distro=debian-13"
    )
    assert purls[("libssl3t64", "3.5.7-1~deb13u3")] == (
        "pkg:deb/debian/libssl3t64@3.5.7-1~deb13u3?distro=debian-13"
    )
    assert not any("+" in p for p in purls.values())
