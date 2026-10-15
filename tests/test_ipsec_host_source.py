# SPDX-License-Identifier: Apache-2.0
"""#265: under --host-mount (and --root), the IPsec implementation,
version and ML-KEM capability come from the host's package and binaries,
never the scanner's own `swanctl` / `ipsec`.

Strings and versions below were captured on booted cloud images on
2026-10-15 and compared with each host's own tools:

* Rocky 9.8, libreswan-4.15-10.el9_8: `ipsec --version` "Libreswan 4.15";
  /usr/libexec/ipsec/pluto carries "Libreswan 4.15" plus vendor-ID strings
  "Libreswan 3.0 - 3.5", "Libreswan %s" and "strongSwan 2.2.0".
* Ubuntu 26.04, strongswan 6.0.4-1ubuntu3.2 (no `ml` plugin), OpenSSL
  3.5.5: `swanctl --list-algs` lists ML_KEM_512/768/1024 from [openssl].
* Fedora 44, strongswan-6.0.7-4.fc44: ML_KEM_* from [openssl]; charon
  embeds "Starting IKE charon daemon (strongSwan 6.0.7, %s %s, %s)".
* Debian 12, strongswan 5.9.8-5+deb12u5, OpenSSL 3.0.22: no ML-KEM;
  swanctl carries the bare literal "5.9.8" and "strongSwan swanctl %s".
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from pqc_readiness import _platform
from pqc_readiness.detect import ipsec_host, openssl_host, protocols, runtime_offline

PLUTO_4_15 = b"\x00".join(
    [
        b"",
        b"Libreswan 3.0 - 3.5",
        b"Libreswan %s",
        b"strongSwan 2.2.0",
        b"Libreswan 4.15",
        b"IPsec %s",
        b"",
    ]
)
CHARON_6_0_7 = b"\x00".join(
    [
        b"",
        b"Starting IKE charon daemon (strongSwan 6.0.7, %s %s, %s)",
        b"strongSwan %s",
        b"6.0.7",
        b"",
    ]
)
SWANCTL_5_9_8 = b"\x00".join(
    [b"", b"strongSwan swanctl %s", b"strongSwan %s swanctl", b"5.9.8", b""]
)

UBUNTU_DPKG_STATUS = """\
Package: libstrongswan
Status: install ok installed
Version: 6.0.4-1ubuntu3.2

Package: strongswan-swanctl
Status: install ok installed
Version: 6.0.4-1ubuntu3.2

Package: libssl3t64
Status: install ok installed
Version: 3.5.5-1ubuntu1

"""


@pytest.fixture
def host(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "host"
    root.mkdir()
    monkeypatch.setattr(_platform, "HOST_PREFIX", str(root))
    monkeypatch.setattr(_platform, "OFFLINE_ROOT", "")
    return root


def _install(root: Path, rel: str, blob: bytes = b"\x7fELF") -> None:
    p = root / rel.lstrip("/")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(blob)


def _no_packages(monkeypatch: pytest.MonkeyPatch, openssl: str | None = None) -> None:
    monkeypatch.setattr(ipsec_host, "_package", lambda *a, **k: None)
    monkeypatch.setattr(
        openssl_host,
        "openssl_evidence",
        lambda osr: {
            "version": openssl,
            "version_tuple": openssl_host.version_tuple(openssl) if openssl else None,
        },
    )


def _scanner_tools(monkeypatch: pytest.MonkeyPatch, ran: list[list[str]]) -> None:
    """The scanner image has its own strongSwan 5.9 on PATH (the case
    #265 warns about); it must never be consulted."""
    monkeypatch.setattr(protocols.shutil, "which", lambda name: f"/usr/sbin/{name}")

    def fake_run(cmd: list[str], timeout: int = 10) -> tuple[int, str]:
        ran.append(cmd)
        return 0, "strongSwan swanctl 5.9.8"

    monkeypatch.setattr(protocols._platform, "_run", fake_run)


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("5.3.2-1.el10_2", "5.3.2"),
        ("6.0.4-1ubuntu3.2", "6.0.4"),
        ("1:4.10-2+deb12u1", "4.10"),
        ("6.0.7", "6.0.7"),
        ("5.4rc1-1", "5.4rc1"),
    ],
)
def test_package_versions_take_the_tools_form(raw: str, expected: str) -> None:
    assert ipsec_host.normalize_version(raw) == expected


def test_host_mount_reads_the_hosts_strongswan_not_the_scanners(
    host: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The bug: under --host-mount the scanner's swanctl answered (or, with
    none in the image, the node looked like it had no IPsec stack).  Ubuntu
    26.04's strongSwan 6.0.4 offers ML-KEM through the openssl plugin."""
    status = host / "var/lib/dpkg/status"
    status.parent.mkdir(parents=True)
    status.write_text(UBUNTU_DPKG_STATUS)
    _install(host, "/usr/lib/ipsec/plugins/libstrongswan-openssl.so")
    _install(host, "/usr/sbin/swanctl", SWANCTL_5_9_8.replace(b"5.9.8", b"6.0.4"))
    ran: list[list[str]] = []
    _scanner_tools(monkeypatch, ran)
    r = protocols.detect_ipsec_pqc("debian", {"family": "debian"})
    assert r["available"] is True
    assert r["implementation"] == "strongswan"
    assert r["version"] == "6.0.4"
    assert r["version_source"] == "package"
    assert r["package"] == {"name": "libstrongswan", "version": "6.0.4-1ubuntu3.2"}
    assert r["plugins"] == ["openssl"]
    assert r["pqc"] is True
    assert "OpenSSL 3.5.5" in r["evidence"]
    assert r["cli_probe"]["available"] is False
    assert ran == [], "the scanner's swanctl/ipsec must not run under --host-mount"


def test_strongswan_5_9_on_openssl_3_0_is_not_pqc(
    host: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Debian 12: no ML-KEM, and the version comes from swanctl's bare
    literal when there is no package database."""
    _no_packages(monkeypatch, openssl="3.0.22")
    _install(host, "/usr/sbin/swanctl", SWANCTL_5_9_8)
    _install(host, "/usr/lib/ipsec/plugins/libstrongswan-openssl.so")
    r = protocols.ipsec_from_files({"family": "debian"}, "--host-mount")
    assert r["version"] == "5.9.8" and r["version_source"] == "binary"
    assert r["pqc"] is False


def test_strongswan_6_openssl_plugin_needs_openssl_3_5(
    host: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _no_packages(monkeypatch, openssl="3.0.22")
    _install(host, "/usr/libexec/strongswan/charon", CHARON_6_0_7)
    _install(host, "/usr/lib64/strongswan/plugins/libstrongswan-openssl.so")
    r = protocols.ipsec_from_files({"family": "rhel"}, None)
    assert r["version"] == "6.0.7"
    assert r["pqc"] is False and "3.5" in r["evidence"]


def test_strongswan_6_ml_plugin_is_pqc_without_openssl_3_5(
    host: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _no_packages(monkeypatch, openssl="3.0.22")
    _install(host, "/usr/libexec/strongswan/charon", CHARON_6_0_7)
    _install(host, "/usr/lib64/strongswan/plugins/libstrongswan-ml.so")
    r = protocols.ipsec_from_files({"family": "rhel"}, None)
    assert r["pqc"] is True and r["plugins"] == ["ml"]


def test_libreswan_version_from_pluto_ignores_vendor_id_strings(
    host: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Rocky 9's pluto also embeds "Libreswan 3.0 - 3.5" and
    "strongSwan 2.2.0" (vendor IDs); only the NUL-terminated literal
    counts, and pluto is never mistaken for strongSwan."""
    _no_packages(monkeypatch)
    monkeypatch.setattr(
        ipsec_host,
        "_package",
        lambda names, probed, family: (
            {"name": "libreswan", "version": "4.15-10.el9_8"}
            if names is ipsec_host._LIBRESWAN_PACKAGES
            else None
        ),
    )
    _install(host, "/usr/libexec/ipsec/pluto", PLUTO_4_15)
    r = protocols.ipsec_from_files({"family": "rhel"}, "--host-mount")
    assert r["implementation"] == "libreswan"
    assert r["version"] == "4.15" and r["version_source"] == "binary"
    assert r["package"] == {"name": "libreswan", "version": "4.15-10.el9_8"}
    assert r["pqc"] is False


def test_libreswan_5_4_from_package_only_is_pqc(
    host: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        ipsec_host,
        "_package",
        lambda names, probed, family: (
            {"name": "libreswan", "version": "5.4-1.fc45"}
            if names is ipsec_host._LIBRESWAN_PACKAGES
            else None
        ),
    )
    r = protocols.ipsec_from_files({"family": "rhel"}, None)
    assert r["version"] == "5.4" and r["version_source"] == "package"
    assert r["pqc"] is True


def test_no_ipsec_on_the_host(host: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _no_packages(monkeypatch)
    ran: list[list[str]] = []
    _scanner_tools(monkeypatch, ran)
    r = protocols.detect_ipsec_pqc("rhel")
    assert r["available"] is False
    assert "no strongSwan or Libreswan" in r["reason"]
    assert ran == []


def test_live_host_without_cli_falls_back_to_files(
    host: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A bare-metal host with the daemon but no swanctl / ipsec on PATH."""
    monkeypatch.setattr(protocols, "_cli_describes_host", lambda: True)
    monkeypatch.setattr(protocols.shutil, "which", lambda name: None)
    _no_packages(monkeypatch, openssl="3.5.5")
    _install(host, "/usr/libexec/strongswan/charon", CHARON_6_0_7)
    _install(host, "/usr/lib64/strongswan/plugins/libstrongswan-openssl.so")
    r = protocols.detect_ipsec_pqc("rhel")
    assert r["available"] is True and r["pqc"] is True
    assert "cli_probe" not in r


def test_offline_scan_reports_the_trees_ipsec(
    host: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """--root used to report only the configured proposals."""
    monkeypatch.setattr(_platform, "OFFLINE_ROOT", str(host))
    _no_packages(monkeypatch, openssl="3.5.5")
    _install(host, "/usr/libexec/ipsec/pluto", PLUTO_4_15)

    def no_run(cmd: list[str], timeout: int = 10) -> tuple[int, Any]:
        raise AssertionError(f"offline scan ran {cmd}")

    monkeypatch.setattr(protocols._platform, "_run", no_run)
    r = runtime_offline.offline_ipsec({"family": "rhel"})
    assert r["available"] is True
    assert r["implementation"] == "libreswan" and r["version"] == "4.15"
    assert "configured" in r


def test_binary_lookup_never_escapes_the_prefix(
    host: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An absolute link inside the host to a pluto outside it must not be
    followed into the scanner's own filesystem."""
    outside = tmp_path / "outside-pluto"
    outside.write_bytes(PLUTO_4_15)
    link = host / "usr/libexec/ipsec/pluto"
    link.parent.mkdir(parents=True)
    link.symlink_to(outside)
    _no_packages(monkeypatch)
    r = protocols.ipsec_from_files({"family": "rhel"}, "--host-mount")
    assert r.get("version") != "4.15"
