# SPDX-License-Identifier: Apache-2.0
"""Embedded and minimal rootfs (#217): opkg databases, probing for the
package database of families without a registered tool, file-based
OpenSSL and library versions, Mbed TLS.

Package databases are the real files from the official OpenWrt rootfs
tarballs (provenance in tests/fixtures/embedded/README.md), checked
against the images' own `opkg list-installed` / `apk info -v` output.
Library files are synthetic: a few bytes around the exact strings the real
libraries embed (OpenWrt 24.10.8, Yocto 6.0.3, Buildroot 2026.08 builds),
under the real file names."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

import pqc_readiness as pr
from pqc_readiness import cli
from pqc_readiness.detect import osinfo
from pqc_readiness.detect import packages as pkgs
from pqc_readiness.detect import protocols_libraries as libs

FIXTURES = Path(__file__).parent / "fixtures" / "embedded"

# Strings copied from the real binaries (see the fixture README).
OPENSSL_357 = b"OpenSSL 3.5.7 9 Jun 2026"
GNUTLS_3812 = b"Enabled GnuTLS 3.8.12 logging...\n"
LIBGCRYPT_1121 = b"\n\nThis is Libgcrypt 1.12.1 - The GNU Crypto Library\n"


def _write(path: Path, data: bytes | str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, str):
        path.write_text(data)
    else:
        path.write_bytes(data)
    return path


def _lib(root: Path, rel: str, *strings: bytes) -> Path:
    return _write(
        root / rel.lstrip("/"), b"\x7fELF" + b"\0".join([b"pad", *strings, b"end"])
    )


def _ground_truth_opkg() -> list[tuple[str, str]]:
    # `opkg list-installed` prints "name - version".
    lines = (
        (FIXTURES / "openwrt-24.10.8.opkg-list-installed.txt").read_text().splitlines()
    )
    return sorted(tuple(line.split(" - ", 1)) for line in lines)  # type: ignore[misc]


@pytest.fixture
def no_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pr._platform, "HOST_PREFIX", "")
    monkeypatch.setattr(pr._platform, "OFFLINE_ROOT", "")
    pkgs._PROBE_CACHE.clear()


@pytest.fixture
def no_subprocess(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    calls: list[list[str]] = []

    def refuse(cmd: list[str], timeout: int = 10) -> tuple[int, str]:
        calls.append(cmd)
        return 127, "subprocess refused in offline test"

    monkeypatch.setattr(pr._platform, "_run", refuse)
    return calls


def _openwrt_tree(tmp_path: Path, version: str) -> Path:
    """The real OpenWrt database and os-release, plus the real Mbed TLS
    library layout (OpenWrt strips the version strings, so the files carry
    none: only the file names name the release)."""
    root = tmp_path / f"openwrt-{version}"
    shutil.copytree(FIXTURES / f"openwrt-{version}", root)
    (root / "etc").mkdir(exist_ok=True)
    (root / "etc/os-release").symlink_to("../usr/lib/os-release")
    for name, link in (
        ("libmbedtls.so.3.6.6", "libmbedtls.so.21"),
        ("libmbedcrypto.so.3.6.6", "libmbedcrypto.so.16"),
        ("libmbedx509.so.3.6.6", "libmbedx509.so.7"),
    ):
        _lib(root, f"/usr/lib/{name}", b"mbedtls_ssl_handshake")
        (root / "usr/lib" / link).symlink_to(name)
    return root


def _run(capsys: pytest.CaptureFixture[str], fmt: str, *argv: str) -> dict:
    rc = cli.main([*argv, fmt])
    assert rc == 0
    return json.loads(capsys.readouterr().out)


# ---------------------------------------------------------------- parsers


def test_opkg_status_matches_opkg_list_installed() -> None:
    text = (FIXTURES / "openwrt-24.10.8/usr/lib/opkg/status").read_text()
    got = sorted((p["name"], p["version"]) for p in pkgs.parse_opkg_status(text))
    assert got == _ground_truth_opkg()
    assert len(got) == 129


def test_opkg_status_counts_installed_and_unpacked_only() -> None:
    text = (
        "Package: a\nVersion: 1\nStatus: install ok installed\n\n"
        "Package: b\nVersion: 2\nStatus: install hold installed\n\n"
        "Package: c\nVersion: 3\nStatus: install ok unpacked\n\n"
        "Package: d\nVersion: 4\nStatus: deinstall ok not-installed\n\n"
        "Package: e\nStatus: install ok installed\n"
    )
    assert [p["name"] for p in pkgs.parse_opkg_status(text)] == ["a", "b", "c"]


def test_openwrt_25_apk_database_matches_apk_info() -> None:
    text = (FIXTURES / "openwrt-25.12.5/lib/apk/db/installed").read_text()
    got = sorted(f"{p['name']}-{p['version']}" for p in pkgs.parse_apk_installed(text))
    truth = sorted((FIXTURES / "openwrt-25.12.5.apk-info-v.txt").read_text().split())
    assert got == truth
    assert len(got) == 136


def test_openwrt_is_its_own_family(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _openwrt_tree(tmp_path, "24.10.8")
    monkeypatch.setattr(pr._platform, "HOST_PREFIX", str(root))
    assert osinfo.detect_os()["family"] == "openwrt"


# ---------------------------------------------------------------- probing


@pytest.mark.parametrize(
    ("version", "manager", "source", "db_root", "total"),
    [
        ("24.10.8", "opkg", "opkg-status", "/usr/lib/opkg/status", 129),
        ("25.12.5", "apk", "apk-installed-db", "/lib/apk/db/installed", 136),
    ],
)
def test_openwrt_inventory_is_probed_in_process(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    no_prefix: None,
    no_subprocess: list[list[str]],
    version: str,
    manager: str,
    source: str,
    db_root: str,
    total: int,
) -> None:
    root = _openwrt_tree(tmp_path, version)
    monkeypatch.setattr(pr._platform, "HOST_PREFIX", str(root))
    out = pkgs.scan_packages({"family": "openwrt"})
    assert no_subprocess == []
    assert out["available"] is True
    assert (out["package_manager"], out["source"], out["db_root"]) == (
        manager,
        source,
        db_root,
    )
    assert out["total_packages"] == total


def test_yocto_opkg_location_is_found(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, no_prefix: None
) -> None:
    _write(
        tmp_path / "var/lib/opkg/status",
        "Package: openssl\nVersion: 3.5.7-r0\nStatus: install ok installed\n",
    )
    monkeypatch.setattr(pr._platform, "HOST_PREFIX", str(tmp_path))
    out = pkgs.scan_packages({"family": "unknown"})
    assert (out["source"], out["db_root"], out["total_packages"]) == (
        "opkg-status",
        "/var/lib/opkg/status",
        1,
    )


def test_unknown_family_rpm_tree_is_probed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, no_prefix: None
) -> None:
    # Yocto's prebuilt images use rpm and ship no os-release: family unknown.
    shutil.copytree(Path(__file__).parent / "fixtures/rpmdb/el9/var", tmp_path / "var")
    monkeypatch.setattr(pr._platform, "HOST_PREFIX", str(tmp_path))
    out = pkgs.scan_packages({"family": "unknown"})
    assert (out["package_manager"], out["source"], out["total_packages"]) == (
        "rpm",
        "rpmdb-sqlite",
        5,
    )


def test_no_package_database_is_unavailable_with_reason(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    no_prefix: None,
    no_subprocess: list[list[str]],
) -> None:
    monkeypatch.setattr(pr._platform, "HOST_PREFIX", str(tmp_path))
    out = pkgs.scan_packages({"family": "unknown"})
    assert out["available"] is False
    assert "opkg" in out["reason"] and "rpm" in out["reason"]
    assert no_subprocess == []


# ---------------------------------------------------------------- offline reports


def test_openwrt_offline_report(
    tmp_path: Path,
    no_prefix: None,
    no_subprocess: list[list[str]],
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = _openwrt_tree(tmp_path, "24.10.8")
    flags = ("--root", str(root), "--scan-packages", "--scan-crypto-libraries")
    r = _run(capsys, "--json", *flags)
    assert no_subprocess == []
    assert r["os_release"]["family"] == "openwrt"
    assert r["packages"]["total_packages"] == 129
    mb = r["crypto_libraries"]["libraries"]["mbedtls"]
    assert mb["installed"] is True
    assert (mb["version"], mb["version_source"]) == ("3.6.6-r2", "package")
    assert [p["name"] for p in mb["packages"]] == ["libmbedtls21"]
    assert mb["pqc_capable"] is False
    assert mb["caveats"], "the no-release-offers-PQC note"
    # OpenWrt ships no OpenSSL: not in the tree, so nothing to judge.
    assert r["openssl"]["installed"] is False
    assert r["openssl"]["pqc_native_expected"] is None
    sarif = _run(capsys, "--sarif", *flags)
    ids = sorted(res["ruleId"] for res in sarif["runs"][0]["results"])
    assert "pqc-013-crypto-library-without-pqc" in ids
    assert not any(
        res["ruleId"].startswith("pqc-018") and "OpenSSL" in res["message"]["text"]
        for res in sarif["runs"][0]["results"]
    )


@pytest.fixture
def packageless_tree(tmp_path: Path) -> Path:
    """A Buildroot / minimal-Yocto style tree: libraries, no package database."""
    root = tmp_path / "minimal"
    _write(root / "etc/hostname", "buildroot\n")
    _lib(root, "/usr/lib/libcrypto.so.3", OPENSSL_357)
    _lib(root, "/usr/lib/libgnutls.so.30.41.1", GNUTLS_3812)
    _lib(root, "/usr/lib/libgcrypt.so.20.7.1", LIBGCRYPT_1121)
    return root


def test_packageless_tree_versions_come_from_library_files(
    packageless_tree: Path,
    no_prefix: None,
    no_subprocess: list[list[str]],
    capsys: pytest.CaptureFixture[str],
) -> None:
    r = _run(
        capsys,
        "--json",
        "--root",
        str(packageless_tree),
        "--scan-packages",
        "--scan-crypto-libraries",
    )
    assert no_subprocess == []
    assert r["packages"]["available"] is False
    o = r["openssl"]
    assert o["package"] is None
    assert o["library"] == {"path": "/usr/lib/libcrypto.so.3", "version": "3.5.7"}
    assert (o["installed"], o["version_source"]) == (True, "library")
    assert o["pqc_native_expected"] is True
    lib = r["crypto_libraries"]["libraries"]
    assert (lib["gnutls"]["version"], lib["gnutls"]["version_source"]) == (
        "3.8.12",
        "library",
    )
    assert (lib["libgcrypt"]["version"], lib["libgcrypt"]["version_source"]) == (
        "1.12.1",
        "library",
    )


def test_old_library_only_openssl_raises_pqc_001_with_library_properties(
    tmp_path: Path,
    no_prefix: None,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _lib(tmp_path, "/usr/lib/libcrypto.so.1.1", b"OpenSSL 1.1.1w  11 Sep 2023")
    sarif = _run(capsys, "--sarif", "--root", str(tmp_path))
    (finding,) = [
        res
        for res in sarif["runs"][0]["results"]
        if res["ruleId"].startswith("pqc-001")
    ]
    props = finding["properties"]
    assert props["openssl:library"] == "/usr/lib/libcrypto.so.1.1"
    assert props["openssl:library_version"] == "1.1.1w"


def test_libcrypto_without_version_string_is_undetermined(
    tmp_path: Path, no_prefix: None, capsys: pytest.CaptureFixture[str]
) -> None:
    _lib(tmp_path, "/usr/lib/libcrypto.so.3", b"no version here")
    r = _run(capsys, "--json", "--root", str(tmp_path))
    assert r["openssl"]["installed"] is True
    assert r["openssl"]["pqc_native_expected"] is None
    sarif = _run(capsys, "--sarif", "--root", str(tmp_path))
    assert any(
        res["ruleId"].startswith("pqc-018") for res in sarif["runs"][0]["results"]
    )


def test_openssl_compatible_forks_are_not_openssl(
    tmp_path: Path, no_prefix: None, capsys: pytest.CaptureFixture[str]
) -> None:
    _lib(
        tmp_path,
        "/usr/lib/libcrypto.so",
        b"OpenSSL 1.1.1 (compatible; AWS-LC 1.61.0)",
        b"AWS-LC 1.61.0",
    )
    r = _run(capsys, "--json", "--root", str(tmp_path))
    assert r["openssl"]["library"] is None
    assert r["openssl"]["installed"] is False


# ---------------------------------------------------------------- Mbed TLS


@pytest.fixture
def host(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    monkeypatch.setattr(pr._platform, "HOST_PREFIX", str(tmp_path))
    monkeypatch.setattr(pr._platform, "is_linux", lambda: True)
    pkgs._PROBE_CACHE.clear()
    return tmp_path


def test_mbedtls_version_from_file_name_when_stripped(host: Path) -> None:
    _lib(host, "/usr/lib/libmbedtls.so.3.6.6", b"mbedtls_ssl_handshake")
    _lib(host, "/usr/lib/libtfpsacrypto.so.1.2.0", b"psa_crypto_init")
    mb = libs.scan_crypto_libraries({"family": "unknown"})["libraries"]["mbedtls"]
    assert (mb["version"], mb["version_source"]) == ("3.6.6", "library-filename")
    assert mb["evidence"] == "binary"
    assert mb["pqc_capable"] is False
    assert mb["version_thresholds"] == {}


def test_libssh_version_from_its_banner(host: Path) -> None:
    # Buildroot 2026.08 libssh 0.12.1: no package database, banner string only.
    _lib(host, "/usr/lib/libssh.so.4.11.1", b"SSH-2.0-libssh_0.12.1")
    ls = libs.scan_crypto_libraries({"family": "unknown"})["libraries"]["libssh"]
    assert (ls["version"], ls["version_source"]) == ("0.12.1", "library")
    assert ls["version_thresholds"]["ssh_pqc_kex"]["met"] is True


def test_mbedtls_embedded_version_string_wins(host: Path) -> None:
    _lib(host, "/usr/lib/libmbedcrypto.so.3.6.2", b"Mbed TLS 3.6.2")
    mb = libs.scan_crypto_libraries({"family": "unknown"})["libraries"]["mbedtls"]
    assert (mb["version"], mb["version_source"]) == ("3.6.2", "library")


def test_mbedtls_4_tf_psa_crypto_name_is_not_a_version(host: Path) -> None:
    # libtfpsacrypto carries the TF-PSA-Crypto version (1.x), not Mbed TLS.
    _lib(host, "/usr/lib/libtfpsacrypto.so.1.2.0", b"psa_crypto_init")
    mb = libs.scan_crypto_libraries({"family": "unknown"})["libraries"]["mbedtls"]
    assert mb["installed"] is True
    assert mb["version"] is None
    assert mb["pqc_capable"] is False


def test_mbedtls_with_ml_kem_groups_in_the_binary_is_capable(host: Path) -> None:
    _lib(host, "/usr/lib/libmbedtls.so.4.9.0", b"X25519MLKEM768")
    mb = libs.scan_crypto_libraries({"family": "unknown"})["libraries"]["mbedtls"]
    assert mb["pqc_capable"] is True
    assert mb["algorithms"]["tls_hybrid_groups"] == ["X25519MLKEM768"]


def test_mbedtls_debian_package(host: Path) -> None:
    _write(
        host / "var/lib/dpkg/status",
        "Package: libmbedtls21\nStatus: install ok installed\nVersion: 3.6.4-2\n",
    )
    mb = libs.scan_crypto_libraries({"family": "debian"})["libraries"]["mbedtls"]
    assert (mb["version"], mb["version_source"], mb["evidence"]) == (
        "3.6.4-2",
        "package",
        "version",
    )
    assert mb["pqc_capable"] is False
