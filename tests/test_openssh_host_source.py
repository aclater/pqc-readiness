# SPDX-License-Identifier: Apache-2.0
"""#256: under --host-mount (and --root), OpenSSH's version and key
exchanges come from the host's package and binary, never the scanner's
own `ssh`."""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

import pytest

from pqc_readiness import _platform
from pqc_readiness.detect import config_sshd, openssh_build, openssh_host, protocols

# What `ssh -Q kex` printed for OpenSSH 10.2p1 (Fedora 44), and the kex
# section of that build's binaries: the names are NUL-separated, and the
# same binary carries fragments that must not count (a bare "mlkem768", a
# source file name, a GSS prefix).  Every name below appears in
# /usr/libexec/openssh/sshd-session of openssh-server-10.2p1.
FEDORA_10_2_KEX = [
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "diffie-hellman-group-exchange-sha1",
    "diffie-hellman-group-exchange-sha256",
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group14-sha256",
    "diffie-hellman-group16-sha512",
    "diffie-hellman-group18-sha512",
    "ecdh-sha2-nistp256",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521",
    "mlkem1024nistp384-sha384",
    "mlkem768nistp256-sha256",
    "mlkem768x25519-sha256",
    "sntrup761x25519-sha512",
    "sntrup761x25519-sha512@openssh.com",
]
NOISE = [b"mlkem768", b"mlkem1024", b"kexmlkem768x25519.c", b"gss-curve25519-sha256-"]
_VADDR = 0x400000


def _elf(strings: list[bytes], pointed: list[bytes]) -> bytes:
    """A minimal little-endian ELF64 with one PT_LOAD covering the file: a
    string area holding `strings` (NUL-terminated, in order) and a pointer
    table with one 8-byte word per entry of `pointed`, each the address of
    the first occurrence of that name.  Models OpenSSH's kex table."""
    header_size, phdr_size = 64, 56
    area = b"".join(x + b"\x00" for x in strings)
    area_off = header_size + phdr_size
    table_off = (area_off + len(area) + 7) & ~7
    table = b""
    for name in pointed:
        idx = area.find(name + b"\x00")
        assert idx >= 0, name
        table += struct.pack("<Q", _VADDR + area_off + idx)
    size = table_off + len(table)
    ehdr = (
        b"\x7fELF\x02\x01\x01"
        + b"\x00" * 9
        + struct.pack(
            "<HHIQQQIHHHHHH",
            3,
            62,
            1,
            0,
            header_size,
            0,
            0,
            header_size,
            phdr_size,
            1,
            64,
            0,
            0,
        )
    )
    phdr = struct.pack("<IIQQQQQQ", 1, 5, 0, _VADDR, _VADDR, size, size, 0x1000)
    body = ehdr + phdr + area
    return body + b"\x00" * (table_off - len(body)) + table


def _binary_blob(kex: list[str], version: str = "10.2p1") -> bytes:
    names = [k.encode() for k in kex]
    strings = [f"OpenSSH_{version.split('p')[0]}".encode(), *names, *NOISE]
    strings.append(f"OpenSSH_{version}".encode())
    return _elf(strings, names)


@pytest.fixture
def host(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "host"
    root.mkdir()
    monkeypatch.setattr(_platform, "HOST_PREFIX", str(root))
    monkeypatch.setattr(_platform, "OFFLINE_ROOT", "")
    monkeypatch.setattr(openssh_host, "openssh_package", lambda family: None)
    return root


def _install(root: Path, rel: str, blob: bytes) -> None:
    p = root / rel.lstrip("/")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(blob)


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("10.0p2", "10.0p2"),
        ("1:9.6p1-3ubuntu13.5", "9.6p1"),
        ("9.9_p1-r2", "9.9p1"),
        ("8.7p1", "8.7p1"),
        ("9.9p1-1", "9.9p1"),
    ],
)
def test_package_versions_take_ssh_v_form(raw: str, expected: str) -> None:
    assert openssh_host.normalize_version(raw) == expected


def test_kex_names_from_binary_equal_ssh_q_kex(host: Path) -> None:
    _install(host, "/usr/libexec/openssh/sshd-session", _binary_blob(FEDORA_10_2_KEX))
    found = openssh_build.openssh_build_kex()
    assert found is not None
    assert found["kex"] == sorted(FEDORA_10_2_KEX)
    assert found["version"] == "10.2p1"
    assert found["binaries"] == ["/usr/libexec/openssh/sshd-session"]


def test_host_mount_reports_the_hosts_openssh_not_the_scanners(
    host: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The bug: a Leap 16 node with OpenSSH 10.0p2 was reported as the
    image's 9.9p1, from the image's `ssh -V` / `ssh -Q kex`."""
    pre_mlkem = [k for k in FEDORA_10_2_KEX if not k.startswith("mlkem")]
    _install(host, "/usr/sbin/sshd", _binary_blob(FEDORA_10_2_KEX, "10.0p2"))
    monkeypatch.setattr(protocols.shutil, "which", lambda name: "/usr/bin/ssh")
    ran: list[list[str]] = []

    def fake_run(cmd: list[str], timeout: int = 10) -> tuple[int, str]:
        ran.append(cmd)
        if cmd == ["ssh", "-V"]:
            return 0, "OpenSSH_9.9p1, OpenSSL 3.5.8 1 Jul 2026"
        return 0, "\n".join(pre_mlkem)

    monkeypatch.setattr(protocols._platform, "_run", fake_run)
    r = protocols.detect_ssh_pqc("suse")
    assert r["version"] == "10.0p2"
    assert r["version_source"] == "binary"
    assert r["kex_source"] == "binary"
    assert "mlkem768x25519-sha256" in r["kex_groups"]["hybrid"]
    assert r["scanner_cli_version"] == "9.9p1"
    assert r["cli_probe"]["available"] is False
    assert ["ssh", "-Q", "kex"] not in ran


def test_binary_version_wins_over_the_package(
    host: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Measured on Debian 13: openssh-server 1:10.0p1-7+deb13u4 prints
    OpenSSH_10.0p2.  The version follows the binary, as `ssh -V` would;
    the raw package stays for SBOM joins."""
    _install(host, "/usr/sbin/sshd", _binary_blob(FEDORA_10_2_KEX, "10.0p2"))
    monkeypatch.setattr(
        openssh_host,
        "openssh_package",
        lambda family: {"name": "openssh-server", "version": "1:10.0p1-7+deb13u4"},
    )
    r = protocols.ssh_from_files({"family": "debian"}, None)
    assert r["version"] == "10.0p2"
    assert r["version_source"] == "binary"
    assert r["package"] == {"name": "openssh-server", "version": "1:10.0p1-7+deb13u4"}


def test_package_without_readable_binary_leaves_kex_unknown(
    host: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        openssh_host,
        "openssh_package",
        lambda family: {"name": "openssh-server", "version": "8.7p1"},
    )
    r = protocols.ssh_from_files({"family": "rhel"}, "--host-mount")
    assert r["available"] is True
    assert r["version"] == "8.7p1"
    assert r["kex_groups"] is None and r["pqc_kex"] is None
    assert r["kex_source"] is None
    # sshd must not read an unknown kex list as "no PQC support".
    _install(host, "/etc/ssh/sshd_config", b"Port 22\n")
    sshd = config_sshd.detect_sshd(r)
    assert sshd["available"] is True
    assert sshd["openssh_supports_pqc_kex"] is None


def test_no_openssh_on_the_host(host: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(protocols.shutil, "which", lambda name: None)
    r = protocols.ssh_from_files({"family": "rhel"}, None)
    assert r["available"] is False
    assert "no OpenSSH" in r["reason"]


def test_binary_lookup_never_escapes_the_prefix(
    host: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression found in live testing: host_path() redirects only state
    directories, so /usr/libexec resolved to the scanning machine's own
    sshd-session.  A tree without OpenSSH must report none."""
    real = Path("/usr/libexec/openssh/sshd-session")
    assert openssh_build.openssh_build_kex() is None, (
        f"read {real} from the scanning machine"
        if real.exists()
        else "read outside prefix"
    )


def test_dropbear_ssh_is_not_openssh(host: Path) -> None:
    _install(host, "/usr/bin/ssh", b"\x7fELF\x00Dropbear SSH client v2024.86\x00")
    assert openssh_build.openssh_build_kex() is None


def test_offline_scan_runs_no_scanner_binary(
    host: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_platform, "OFFLINE_ROOT", str(host))
    _install(host, "/usr/sbin/sshd", _binary_blob(FEDORA_10_2_KEX, "9.9p1"))
    monkeypatch.setattr(protocols.shutil, "which", lambda name: "/usr/bin/ssh")

    def no_run(cmd: list[str], timeout: int = 10) -> tuple[int, str]:
        raise AssertionError(f"offline scan ran {cmd}")

    monkeypatch.setattr(protocols._platform, "_run", no_run)
    r: dict[str, Any] = protocols.ssh_from_files({"family": "rhel"}, "--root")
    assert r["version"] == "9.9p1"
    assert "scanner_cli_version" not in r
    assert r["cli_probe"]["reason"].startswith("--root:")


def test_proposal_list_names_without_a_table_entry_dont_count(host: Path) -> None:
    """Rocky 9 (openssh 9.9p1-12.el9_8): its binary carries
    "mlkem768x25519-sha256,mlkem768nistp256-sha256,mlkem1024nistp384-sha384"
    but its table, and `ssh -Q kex`, has only mlkem768x25519-sha256."""
    table = [b"mlkem768x25519-sha256", b"curve25519-sha256"]
    blob = _elf(
        [
            *table,
            b"mlkem768x25519-sha256,mlkem768nistp256-sha256,mlkem1024nistp384-sha384",
        ],
        table,
    )
    _install(host, "/usr/libexec/openssh/sshd-session", blob)
    found = openssh_build.openssh_build_kex()
    assert found is not None
    assert found["kex"] == ["curve25519-sha256", "mlkem768x25519-sha256"]


def test_table_name_tail_merged_into_a_list_still_counts(host: Path) -> None:
    """Alpine 3.22: the linker stores the table's "ecdh-sha2-nistp521" as
    the tail of "ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521";
    the table points into the list, at the name's first byte."""
    lst = b"ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521"
    area = [b"curve25519-sha256", lst]
    blob = bytearray(_elf(area, [b"curve25519-sha256"]))
    # Point a second table word at the tail-merged name inside the list.
    tail = bytes(blob).find(b"ecdh-sha2-nistp521\x00")
    blob += struct.pack("<Q", _VADDR + tail)
    phdr_off = 64
    struct.pack_into("<QQ", blob, phdr_off + 32, len(blob), len(blob))
    _install(host, "/usr/lib/ssh/sshd-session", bytes(blob))
    found = openssh_build.openssh_build_kex()
    assert found is not None
    assert found["kex"] == ["curve25519-sha256", "ecdh-sha2-nistp521"]


def test_non_elf_input_falls_back_to_nul_bounded_names(host: Path) -> None:
    """A `strings` excerpt (the #247 fixtures) isn't an ELF; its
    NUL-bounded kex-like names are used as before."""
    _install(
        host,
        "/usr/sbin/sshd",
        b"not an elf\x00mlkem768x25519-sha256\x00curve25519-sha256\x00OpenSSH_9.9p1\x00",
    )
    found = openssh_build.openssh_build_kex()
    assert found is not None
    assert found["version"] == "9.9p1"
    assert found["kex"] == ["curve25519-sha256", "mlkem768x25519-sha256"]
