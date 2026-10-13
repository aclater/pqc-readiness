# SPDX-License-Identifier: Apache-2.0
"""--scan-crypto-libraries (#110): PQC capability of GnuTLS, libgcrypt,
libssh, wolfSSL, AWS-LC, JDKs and Go toolchains.

Library files are synthetic: a few bytes of padding around the algorithm
names each real library embeds (taken from Fedora 44 / Alpine builds),
under a fake --host-mount root, so the probes run without the libraries
installed."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

import pqc_readiness as pr
from pqc_readiness.detect import packages as pkgs_mod
from pqc_readiness.detect import protocols_libraries as libs


@pytest.fixture
def host(monkeypatch, tmp_path):
    monkeypatch.setattr(pr._platform, "HOST_PREFIX", str(tmp_path))
    monkeypatch.setattr(pr._platform, "is_linux", lambda: True)
    monkeypatch.setattr(pkgs_mod, "query_rpm_named", lambda names: {"available": False})
    return tmp_path


def _lib(root: Path, rel: str, *markers: bytes) -> Path:
    p = root / rel.lstrip("/")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(b"\x7fELF" + b"\0".join([b"padding", *markers, b"end"]))
    return p


def _rpm(monkeypatch, packages: dict[str, str]) -> None:
    def fake(names):
        return {
            "available": True,
            "source": "rpmdb-sqlite",
            "packages": [
                {"name": n, "version": v} for n, v in packages.items() if n in names
            ],
        }

    monkeypatch.setattr(pkgs_mod, "query_rpm_named", fake)


def _scan(family: str = "rhel") -> dict[str, Any]:
    return libs.scan_crypto_libraries({"family": family})


# ---------------------------------------------------------------- versions


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("3.8.13-1.fc44", (3, 8, 13)),
        ("1:3.8.13-1", (3, 8, 13)),
        ("0.12.2", (0, 12, 2)),
        ("21.0.5", (21, 0, 5)),
        ("", None),
        (None, None),
        ("abc", None),
    ],
)
def test_version_tuple(text, expected) -> None:
    assert libs._version_tuple(text) == expected


# ---------------------------------------------------------------- GnuTLS


def test_gnutls_binary_evidence_reports_groups_and_signatures(
    host, monkeypatch
) -> None:
    _lib(
        host,
        "/usr/lib64/libgnutls.so.30.42.0",
        b"X25519-MLKEM768",
        b"SECP384R1-MLKEM1024",
        b"ML-KEM-768",
        b"ML-DSA-65",
    )
    _rpm(monkeypatch, {"gnutls": "3.8.13"})
    g = _scan()["libraries"]["gnutls"]
    assert g["evidence"] == "binary"
    assert g["pqc_capable"] is True
    assert g["algorithms"]["tls_hybrid_groups"] == [
        "X25519MLKEM768",
        "SecP384r1MLKEM1024",
    ]
    assert g["algorithms"]["signatures"] == ["ML-DSA-65"]
    assert g["version"] == "3.8.13" and g["version_source"] == "package"
    assert g["files"] == ["/usr/lib64/libgnutls.so.30.42.0"]
    assert g["version_thresholds"]["ml_dsa_tls"] == {
        "minimum_version": "3.8.10",
        "met": True,
        "note": "ML-DSA TLS signatures",
    }


def test_gnutls_without_pqc_backend_is_classical_despite_new_version(
    host, monkeypatch
) -> None:
    # A 3.8.13 built without leancrypto embeds no ML-KEM names: the binary
    # wins over the version threshold.
    _lib(host, "/usr/lib64/libgnutls.so.30.42.0", b"SECP256R1", b"X25519")
    _rpm(monkeypatch, {"gnutls": "3.8.13"})
    g = _scan()["libraries"]["gnutls"]
    assert g["evidence"] == "binary" and g["pqc_capable"] is False
    assert g["version_thresholds"]["tls_hybrid_mlkem768"]["met"] is True


def test_gnutls_version_only_is_unknown_because_build_dependent(
    host, monkeypatch
) -> None:
    _rpm(monkeypatch, {"gnutls": "3.8.13"})
    g = _scan()["libraries"]["gnutls"]
    assert g["evidence"] == "version"
    assert g["pqc_capable"] is None
    assert "gnutls" in _scan()["summary"]["unknown"]


def test_old_gnutls_version_only_is_classical(host, monkeypatch) -> None:
    _rpm(monkeypatch, {"gnutls": "3.8.3"})
    g = _scan()["libraries"]["gnutls"]
    assert g["evidence"] == "version" and g["pqc_capable"] is False


# ---------------------------------------------------------------- libgcrypt / libssh


def test_libgcrypt_markers_map_to_standard_names(host) -> None:
    _lib(
        host,
        "/usr/lib64/libgcrypt.so.20.7.2",
        b"kyber768",
        b"kyber1024",
        b"sntrup761",
        b"dilithium3",
    )
    g = _scan()["libraries"]["libgcrypt"]
    assert g["algorithms"]["kem"] == ["ML-KEM-768", "ML-KEM-1024", "sntrup761"]
    assert g["algorithms"]["signatures"] == ["ML-DSA-65"]
    assert g["pqc_capable"] is True


def test_libssh_pqc_kex_from_binary(host) -> None:
    _lib(
        host,
        "/usr/lib64/libssh.so.4.12.0",
        b"mlkem768x25519-sha256,mlkem768nistp256-sha256,sntrup761x25519-sha512,curve25519-sha256",
    )
    s = _scan()["libraries"]["libssh"]
    assert s["algorithms"]["ssh_kex"] == [
        "mlkem768x25519-sha256",
        "mlkem768nistp256-sha256",
        "sntrup761x25519-sha512",
    ]
    assert s["pqc_capable"] is True


def test_libssh_011_binary_is_classical(host, monkeypatch) -> None:
    _lib(host, "/usr/lib64/libssh.so.4.11.0", b"curve25519-sha256,ecdh-sha2-nistp256")
    _rpm(monkeypatch, {"libssh": "0.11.1"})
    s = _scan()["libraries"]["libssh"]
    assert s["pqc_capable"] is False
    assert s["version_thresholds"]["ssh_pqc_kex"]["met"] is False
    assert "libssh" in _scan()["summary"]["classical_only"]


def test_libssh_version_only_not_build_dependent(host, monkeypatch) -> None:
    _rpm(monkeypatch, {"libssh": "0.12.2"})
    s = _scan()["libraries"]["libssh"]
    assert s["evidence"] == "version" and s["pqc_capable"] is True


# ---------------------------------------------------------------- AWS-LC / wolfSSL


def test_awslc_found_by_embedded_string_and_exact_sibling_only(host) -> None:
    _lib(host, "/usr/lib/libcrypto.so", b"AWS-LC 5.10.0", b"ML-KEM-768", b"ML-DSA-87")
    _lib(host, "/usr/lib/libssl.so", b"SecP384r1MLKEM1024", b"X25519MLKEM768")
    # OpenSSL's libssl in the same directory must not be credited to AWS-LC.
    _lib(host, "/usr/lib/libssl.so.3", b"X25519MLKEM768", b"SecP256r1MLKEM768")
    _lib(host, "/usr/lib/libcrypto.so.3", b"OpenSSL 3.5.5", b"ML-KEM-768")
    a = _scan("alpine")["libraries"]["aws-lc"]
    assert a["files"] == ["/usr/lib/libcrypto.so", "/usr/lib/libssl.so"]
    assert a["version"] == "5.10.0" and a["version_source"] == "library"
    assert "SecP256r1MLKEM768" not in a["algorithms"]["tls_hybrid_groups"]
    assert a["version_thresholds"]["tls_hybrid_mlkem1024"]["met"] is True


def test_awslc_absent_when_only_openssl(host) -> None:
    _lib(host, "/usr/lib64/libcrypto.so.3.5.9", b"OpenSSL 3.5.9", b"ML-KEM-768")
    assert _scan()["libraries"]["aws-lc"] == {"installed": False}


def test_wolfssl_debian_package_and_binary(host) -> None:
    status = host / "var/lib/dpkg/status"
    status.parent.mkdir(parents=True)
    status.write_text(
        "Package: libwolfssl42t64\nStatus: install ok installed\nVersion: 5.7.2-0.1\n\n"
        "Package: libwolfssl-dev\nStatus: deinstall ok config-files\nVersion: 5.7.2-0.1\n"
    )
    _lib(
        host,
        "/usr/lib/x86_64-linux-gnu/libwolfssl.so.42",
        b"Wrong key size for Dilithium.",
    )
    w = _scan("debian")["libraries"]["wolfssl"]
    assert w["packages"] == [{"name": "libwolfssl42t64", "version": "5.7.2-0.1"}]
    assert w["pqc_capable"] is False
    assert w["version_thresholds"]["ml_kem_final"]["met"] is False


# ---------------------------------------------------------------- package databases


def test_dpkg_ignores_removed_packages(host) -> None:
    status = host / "var/lib/dpkg/status"
    status.parent.mkdir(parents=True)
    status.write_text(
        "Package: libgnutls30t64\nStatus: install ok installed\nVersion: 3.8.9-3\n\n"
        "Package: libgnutls30\nStatus: deinstall ok config-files\nVersion: 3.7.9\n"
    )
    assert libs._dpkg_versions(r"^libgnutls30(t64)?$") == [
        {"name": "libgnutls30t64", "version": "3.8.9-3"}
    ]


def test_apk_database(host) -> None:
    db = host / "lib/apk/db/installed"
    db.parent.mkdir(parents=True)
    db.write_text("C:Q1x\nP:gnutls\nV:3.8.13-r0\n\nP:musl\nV:1.2.5-r10\n")
    assert libs._apk_versions(("gnutls",)) == [
        {"name": "gnutls", "version": "3.8.13-r0"}
    ]


def test_pacman_local_database(host) -> None:
    (host / "var/lib/pacman/local/libssh-0.12.2-1").mkdir(parents=True)
    (host / "var/lib/pacman/local/libssh2-1.11.1-1").mkdir(parents=True)
    assert libs._pacman_versions(("libssh",)) == [
        {"name": "libssh", "version": "0.12.2-1"}
    ]


# ---------------------------------------------------------------- JDK / Go


def _jdk(root: Path, name: str, version: str) -> None:
    d = root / "usr/lib/jvm" / name
    d.mkdir(parents=True)
    (d / "release").write_text(
        f'IMPLEMENTOR="Red Hat, Inc."\nJAVA_VERSION="{version}"\n'
    )


def test_jdk_thresholds(host) -> None:
    _jdk(host, "java-21-openjdk", "21.0.5")
    _jdk(host, "java-27-openjdk", "27")
    j = _scan()["libraries"]["java"]
    by_version = {i["version"]: i for i in j["installs"]}
    assert by_version["21.0.5"]["jca_ml_kem_ml_dsa"] is False
    assert by_version["27"]["jca_ml_kem_ml_dsa"] is True
    assert by_version["27"]["tls_hybrid_default"] is True
    assert j["pqc_capable"] is True


def test_go_toolchains(host) -> None:
    for root, ver in (("usr/lib/golang", "go1.25.3"), ("usr/lib/go-1.23", "go1.23.4")):
        d = host / root
        d.mkdir(parents=True)
        (d / "VERSION").write_text(f"{ver}\ntime 2026-01-01T00:00:00Z\n")
    g = _scan()["libraries"]["go"]
    flags = {i["version"]: i["tls_mlkem_default"] for i in g["installs"]}
    assert flags == {"go1.25.3": True, "go1.23.4": False}


# ---------------------------------------------------------------- shape and limits


def test_nothing_installed(host) -> None:
    out = _scan()
    assert out["available"] is True
    assert all(v == {"installed": False} for v in out["libraries"].values())
    assert out["summary"] == {
        "installed": [],
        "pqc_capable": [],
        "classical_only": [],
        "unknown": [],
    }


def test_non_linux_unavailable(monkeypatch) -> None:
    monkeypatch.setattr(pr._platform, "is_linux", lambda: False)
    assert libs.scan_crypto_libraries({"family": "rhel"})["available"] is False


def test_oversized_library_not_read(host, monkeypatch) -> None:
    _lib(host, "/usr/lib64/libssh.so.4.12.0", b"mlkem768x25519-sha256")
    monkeypatch.setattr(libs, "_MAX_LIBRARY_BYTES", 8)
    s = _scan()["libraries"]["libssh"]
    assert s["installed"] is True and s["evidence"] == "none"


def test_absolute_symlink_is_rerooted_under_host_mount(host) -> None:
    real = _lib(host, "/usr/lib64/libssh.so.4.12.0", b"mlkem768x25519-sha256")
    link = host / "usr/lib64/libssh.so.4"
    link.symlink_to("/usr/lib64/libssh.so.4.12.0")  # absolute, host-relative
    s = _scan()["libraries"]["libssh"]
    assert s["files"] == ["/usr/lib64/libssh.so.4.12.0"]
    assert real.exists()


def test_cli_flag_wires_into_report(monkeypatch) -> None:
    called = {}

    def fake(os_release):
        called["family"] = os_release.get("family")
        return {"available": True, "libraries": {}, "summary": {}}

    monkeypatch.setattr(libs, "scan_crypto_libraries", fake)
    ap = pr.cli.build_parser()
    args = ap.parse_args(["--scan-crypto-libraries"])
    assert args.scan_crypto_libraries is True


def test_libgcrypt_below_final_fips203_gets_draft_caveat(host, monkeypatch) -> None:
    # Rocky 10.2 ships libgcrypt 1.11.0: Kyber names present, but upstream
    # 1.11.0 is the FIPS 203 initial public draft.
    _lib(host, "/usr/lib64/libgcrypt.so.20.6.0", b"kyber768", b"sntrup761")
    _rpm(monkeypatch, {"libgcrypt": "1.11.0"})
    g = _scan()["libraries"]["libgcrypt"]
    assert g["pqc_capable"] is True
    assert len(g["caveats"]) == 1 and "initial public draft" in g["caveats"][0]


def test_no_caveat_at_or_above_final_release(host, monkeypatch) -> None:
    _lib(host, "/usr/lib64/libgcrypt.so.20.7.2", b"kyber768", b"dilithium3")
    _rpm(monkeypatch, {"libgcrypt": "1.12.2"})
    assert _scan()["libraries"]["libgcrypt"]["caveats"] == []


def test_no_caveat_for_classical_binary(host, monkeypatch) -> None:
    _lib(host, "/usr/lib64/libgcrypt.so.20.4.0", b"rsa", b"ecc")
    _rpm(monkeypatch, {"libgcrypt": "1.10.0"})
    assert _scan()["libraries"]["libgcrypt"]["caveats"] == []
