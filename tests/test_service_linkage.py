"""--scan-services (#111): listening sockets -> process -> crypto library.

Everything runs against synthetic /proc trees rooted at a fake host prefix,
so no test depends on the processes of the machine running the suite."""

from __future__ import annotations

import os
import socket
import struct
from pathlib import Path

import pytest

import pqc_readiness
from pqc_readiness import _platform
from pqc_readiness.detect import runtime_services as rs

HOST_NS = "net:[4026531840]"
OTHER_NS = "net:[4026532999]"
SENTINEL = b"0w\xaf\x0c\x92t\x08\x02A\xe1\xc1\x07\xe6\xd6\x18\xe6"


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------


def _hex_v4(addr: str, port: int) -> str:
    (word,) = struct.unpack("=I", socket.inet_aton(addr))
    return f"{word:08X}:{port:04X}"


def _hex_v6(addr: str, port: int) -> str:
    raw = socket.inet_pton(socket.AF_INET6, addr)
    words = struct.unpack("=4I", raw)
    return "".join(f"{w:08X}" for w in words) + f":{port:04X}"


def _net_table(rows: list[tuple[str, str, str, int]]) -> str:
    """rows: (local_hex, remote_hex, state, inode) in /proc/net/tcp layout."""
    head = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
    body = "".join(
        f"   {i}: {loc} {rem} {st} 00000000:00000000 00:00000000 00000000     0        0 {ino} 1 0 0 10 0\n"
        for i, (loc, rem, st, ino) in enumerate(rows)
    )
    return head + body


def _go_blob(version: str, mod_lines: list[str]) -> bytes:
    def uvarint(n: int) -> bytes:
        out = bytearray()
        while True:
            b = n & 0x7F
            n >>= 7
            out.append(b | (0x80 if n else 0))
            if not n:
                return bytes(out)

    header = b"\xff Go buildinf:" + bytes([8, 0x2]) + b"\0" * 16
    mod = SENTINEL + ("\n".join(mod_lines) + "\n").encode() + SENTINEL
    v = version.encode()
    return header + uvarint(len(v)) + v + uvarint(len(mod)) + mod


def _elf(*, interp: bool, buildinfo: bytes | None, big_endian: bool = False) -> bytes:
    """Minimal ELF64: header, optional PT_INTERP, sections [null, .shstrtab,
    .go.buildinfo?]."""
    bo = ">" if big_endian else "<"
    shstr = b"\0.shstrtab\0.go.buildinfo\0"
    phnum = 1 if interp else 0
    phoff = 64
    data_off = phoff + 56 * phnum
    shstr_off = data_off
    bi_off = shstr_off + len(shstr)
    payload = shstr + (buildinfo or b"")
    shoff = data_off + len(payload)
    shnum = 3 if buildinfo else 2
    ident = b"\x7fELF" + bytes([2, 2 if big_endian else 1, 1]) + b"\0" * 9
    ehdr = ident + struct.pack(
        bo + "HHIQQQIHHHHHH",
        2,
        62,
        1,
        0,
        phoff if phnum else 0,
        shoff,
        0,
        64,
        56,
        phnum,
        64,
        shnum,
        1,
    )
    ph = struct.pack(bo + "IIQQQQQQ", 3, 4, 0, 0, 0, 0, 0, 1) if interp else b""
    sh = b"\0" * 64
    sh += struct.pack(bo + "IIQQQQIIQQ", 1, 3, 0, 0, shstr_off, len(shstr), 0, 0, 1, 0)
    if buildinfo:
        sh += struct.pack(
            bo + "IIQQQQIIQQ", 11, 1, 3, 0, bi_off, len(buildinfo), 0, 0, 16, 0
        )
    return ehdr + ph + payload + sh


class FakeHost:
    """A host root with /proc/<pid>/... entries and a filesystem."""

    def __init__(self, root: Path) -> None:
        self.root = root
        (root / "proc").mkdir(parents=True)
        (root / "fs").mkdir()
        self.process(1, comm="systemd", ns=HOST_NS)

    def file(self, path: str, data: bytes) -> Path:
        p = self.root / "fs" / path.lstrip("/")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        return p

    def process(
        self,
        pid: int,
        *,
        comm: str,
        ns: str = HOST_NS,
        sockets: tuple[int, ...] = (),
        maps: str = "",
        exe: Path | None = None,
        cgroup: str = "0::/init.scope\n",
        environ: bytes = b"",
        fd_readable: bool = True,
        ppid: int = 1,
        exe_path: str | None = None,
    ) -> None:
        d = self.root / "proc" / str(pid)
        (d / "ns").mkdir(parents=True)
        os.symlink(ns, d / "ns" / "net")
        (d / "net").mkdir()
        (d / "comm").write_text(comm + "\n")
        # Real stat lines can have spaces and parentheses in comm.
        (d / "stat").write_text(f"{pid} ({comm} (x)) S {ppid} {pid} {pid} 0 -1\n")
        (d / "cgroup").write_text(cgroup)
        (d / "maps").write_text(maps)
        (d / "environ").write_bytes(environ)
        os.symlink(self.root / "fs", d / "root")
        if exe is not None:
            os.symlink(exe, d / "exe")
        elif exe_path is not None:
            # As the kernel shows it: the path inside the process's root.
            os.symlink(exe_path, d / "exe")
        fd = d / "fd"
        fd.mkdir()
        for i, inode in enumerate(sockets, start=3):
            os.symlink(f"socket:[{inode}]", fd / str(i))
        if not fd_readable:
            fd.chmod(0)

    def net(self, pid: int, name: str, rows: list[tuple[str, str, str, int]]) -> None:
        (self.root / "proc" / str(pid) / "net" / name).write_text(_net_table(rows))


@pytest.fixture
def host(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> FakeHost:
    monkeypatch.setattr(_platform, "HOST_PREFIX", str(tmp_path))
    monkeypatch.setattr(_platform, "is_linux", lambda: True)
    h = FakeHost(tmp_path)
    for name in ("tcp", "tcp6", "udp", "udp6"):
        h.net(1, name, [])
    return h


LIBCRYPTO = b"\0junk\0OpenSSL 3.5.9 29 Sep 2026\0more"
ANY4 = _hex_v4("0.0.0.0", 0)


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------


def test_parse_proc_net_tcp_listen_only() -> None:
    text = _net_table(
        [
            (_hex_v4("0.0.0.0", 22), ANY4, "0A", 1111),
            (
                _hex_v4("10.0.0.5", 22),
                _hex_v4("10.0.0.9", 51000),
                "01",
                2222,
            ),  # established
            (_hex_v4("127.0.0.1", 631), ANY4, "0A", 3333),
        ]
    )
    got = rs.parse_proc_net(text, "tcp")
    assert [(s["address"], s["port"], s["inode"]) for s in got] == [
        ("0.0.0.0", 22, 1111),
        ("127.0.0.1", 631, 3333),
    ]


def test_parse_proc_net_ipv6_and_mapped() -> None:
    text = _net_table(
        [
            (_hex_v6("::", 443), _hex_v6("::", 0), "0A", 10),
            (_hex_v6("fe80::1", 8443), _hex_v6("::", 0), "0A", 11),
            (_hex_v6("::ffff:192.0.2.7", 993), _hex_v6("::", 0), "0A", 12),
        ]
    )
    got = rs.parse_proc_net(text, "tcp")
    assert [(s["family"], s["address"], s["port"]) for s in got] == [
        ("ipv6", "::", 443),
        ("ipv6", "fe80::1", 8443),
        ("ipv6", "::ffff:192.0.2.7", 993),
    ]


def test_parse_proc_net_udp_bound_but_not_connected() -> None:
    text = _net_table(
        [
            (_hex_v4("0.0.0.0", 443), ANY4, "07", 20),  # QUIC listener
            (
                _hex_v4("10.0.0.5", 40000),
                _hex_v4("10.0.0.1", 53),
                "07",
                21,
            ),  # connected
            (_hex_v4("0.0.0.0", 0), ANY4, "07", 22),  # unbound
        ]
    )
    assert [s["inode"] for s in rs.parse_proc_net(text, "udp")] == [20]


def test_parse_proc_net_skips_malformed_rows() -> None:
    text = (
        "header\n  0: garbage\n"
        + _net_table([(_hex_v4("0.0.0.0", 22), ANY4, "0A", 5)]).split("\n", 1)[1]
    )
    assert [s["port"] for s in rs.parse_proc_net(text, "tcp")] == [22]


@pytest.mark.parametrize(
    ("address", "scope"),
    [
        ("0.0.0.0", "any"),
        ("::", "any"),
        ("127.0.0.53", "loopback"),
        ("::1", "loopback"),
        ("::ffff:127.0.0.1", "loopback"),
        ("224.0.0.251", "multicast"),
        ("fe80::1", "link-local"),
        ("192.0.2.7", "specific"),
        ("::ffff:192.0.2.7", "specific"),
    ],
)
def test_bind_scope(address: str, scope: str) -> None:
    assert rs.bind_scope(address) == scope


def test_parse_maps_libraries_families_dedupe_and_deleted() -> None:
    maps = "\n".join(
        [
            "7f0000000000-7f0000001000 r--p 00000000 fd:00 11 /usr/lib64/libcrypto.so.3.5.9",
            "7f0000001000-7f0000002000 r-xp 00001000 fd:00 11 /usr/lib64/libcrypto.so.3.5.9",
            "7f0000003000-7f0000004000 r-xp 00000000 fd:00 12 /usr/lib64/libssl.so.3 (deleted)",
            "7f0000005000-7f0000006000 r-xp 00000000 fd:00 13 /usr/lib64/libgnutls.so.30.42.0",
            "7f0000007000-7f0000008000 r-xp 00000000 fd:00 14 /usr/lib64/libnss3.so",
            "7f0000009000-7f000000a000 r-xp 00000000 fd:00 15 /usr/lib64/libwolfssl.so.44",
            "7f000000b000-7f000000c000 r-xp 00000000 fd:00 16 /usr/lib64/libc.so.6",
            "7ffd00000000-7ffd00001000 rw-p 00000000 00:00 0 [stack]",
        ]
    )
    libs = rs.parse_maps_libraries(maps)
    assert [(lib["family"], lib["soname_version"], lib["deleted"]) for lib in libs] == [
        ("openssl", "3.5.9", False),
        ("openssl", "3", True),
        ("gnutls", "30.42.0", False),
        ("nss", None, False),
        ("wolfssl", "44", False),
    ]
    assert libs[1]["map_range"] == "7f0000003000-7f0000004000"


@pytest.mark.parametrize(
    ("family", "blob", "want"),
    [
        ("openssl", LIBCRYPTO, ("openssl", "3.5.9")),
        ("openssl", b"OpenSSL 3.0.13 30 Jan 2024", ("openssl", "3.0.13")),
        ("openssl", b"LibreSSL 3.9.2\0", ("libressl", "3.9.2")),
        ("openssl", b"AWS-LC 1.61.4\0OpenSSL 1.1.1 (compatible)", ("aws-lc", "1.61.4")),
        ("openssl", b"BoringSSL\0", ("boringssl", None)),
        ("gnutls", b"GnuTLS 3.8.13\0", ("gnutls", "3.8.13")),
        ("nss", b"Version: NSS 3.130\0", ("nss", "3.130")),
        ("wolfssl", b"no version here", ("wolfssl", None)),
    ],
)
def test_library_version(
    family: str, blob: bytes, want: tuple[str, str | None]
) -> None:
    assert rs.library_version(family, blob) == want


@pytest.mark.parametrize(
    ("family", "version", "want"),
    [
        ("openssl", "3.5.0", True),
        ("openssl", "3.4.1", False),
        ("openssl", None, None),
        ("nss", "3.108", True),
        ("nss", "3.107.1", False),
        ("gnutls", "3.8.13", None),  # no verified threshold yet (#110)
    ],
)
def test_library_pqc_capable(
    family: str, version: str | None, want: bool | None
) -> None:
    assert rs.library_pqc_capable(family, version) is want


# ---------------------------------------------------------------------------
# Go build info
# ---------------------------------------------------------------------------


def test_parse_go_buildinfo_inline() -> None:
    blob = _go_blob(
        "go1.24.4",
        [
            "path\texample.com/srv",
            "mod\texample.com/srv\t(devel)\t",
            "build\tCGO_ENABLED=0",
            "build\tDefaultGODEBUG=tlsmlkem=0",
        ],
    )
    info = rs.parse_go_buildinfo(blob)
    assert info is not None
    assert info["go_version"] == "go1.24.4"
    assert info["main_module"] == "example.com/srv"
    assert info["settings"] == {"CGO_ENABLED": "0", "DefaultGODEBUG": "tlsmlkem=0"}


def test_parse_go_buildinfo_pointer_format_is_marked_not_guessed() -> None:
    blob = b"\xff Go buildinf:" + bytes([8, 0x0]) + b"\0" * 16
    assert rs.parse_go_buildinfo(blob) == {"go_version": None, "format": "pointer"}


@pytest.mark.parametrize(
    ("version", "default_godebug", "runtime_godebug", "kex", "reverts"),
    [
        ("go1.24.4", None, None, "X25519MLKEM768", []),
        ("go1.25.1", None, None, "X25519MLKEM768", []),
        # Go 1.24 removed X25519Kyber768Draft00: reverting ML-KEM leaves none.
        ("go1.24.4", "tlsmlkem=0", None, None, ["tlsmlkem"]),
        ("go1.24.4", None, "http2client=0,tlsmlkem=0", None, ["tlsmlkem"]),
        ("go1.23.9", None, None, "X25519Kyber768Draft00", []),
        ("go1.23.9", None, "tlskyber=0", None, ["tlskyber"]),
        ("go1.22.12", None, None, None, []),
    ],
)
def test_go_tls_kex_default(
    version: str,
    default_godebug: str | None,
    runtime_godebug: str | None,
    kex: str | None,
    reverts: list[str],
) -> None:
    settings = {"DefaultGODEBUG": default_godebug} if default_godebug else {}
    got = rs.go_tls_kex_default(
        {"go_version": version, "settings": settings}, runtime_godebug
    )
    assert got == {"default_hybrid_kex": kex, "godebug_reverts": reverts}


def test_environ_only_godebug_is_extracted() -> None:
    environ = b"SECRET_TOKEN=hunter2\0GODEBUG=tlsmlkem=0\0PATH=/usr/bin\0"  # pragma: allowlist secret
    assert rs._go_godebug_from_environ(environ) == "tlsmlkem=0"


@pytest.mark.parametrize("big_endian", [False, True])
def test_analyze_executable_static_go(tmp_path: Path, big_endian: bool) -> None:
    exe = tmp_path / "srv"
    exe.write_bytes(
        _elf(
            interp=False,
            buildinfo=_go_blob("go1.24.4", ["path\tx"]),
            big_endian=big_endian,
        )
    )
    out = rs.analyze_executable(exe)
    assert out["static"] is True
    assert out["go"]["go_version"] == "go1.24.4"


def test_analyze_executable_dynamic_non_go(tmp_path: Path) -> None:
    exe = tmp_path / "sshd"
    exe.write_bytes(_elf(interp=True, buildinfo=None))
    assert rs.analyze_executable(exe) == {"static": False, "go": None}


def test_analyze_executable_not_elf_and_unreadable(tmp_path: Path) -> None:
    script = tmp_path / "script"
    script.write_bytes(b"#!/bin/sh\necho hi\n")
    assert rs.analyze_executable(script) == {"static": None, "go": None}
    assert rs.analyze_executable(tmp_path / "missing") == {"static": None, "go": None}


def test_analyze_executable_truncated_elf_does_not_raise(tmp_path: Path) -> None:
    exe = tmp_path / "trunc"
    exe.write_bytes(_elf(interp=True, buildinfo=None)[:70])
    assert rs.analyze_executable(exe)["go"] is None


# ---------------------------------------------------------------------------
# End to end on a synthetic host
# ---------------------------------------------------------------------------


def _populate(host: FakeHost) -> None:
    host.file("/usr/lib64/libcrypto.so.3.5.9", LIBCRYPTO)
    host.file("/usr/lib64/libssl.so.3.5.9", b"no version string in libssl")
    host.file("/usr/lib64/libgnutls.so.30.42.0", b"GnuTLS 3.8.13")
    sshd = host.file("/usr/sbin/sshd", _elf(interp=True, buildinfo=None))
    gosrv = host.file(
        "/opt/srv/srv",
        _elf(
            interp=False,
            buildinfo=_go_blob(
                "go1.24.4", ["path\texample.com/srv", "build\tCGO_ENABLED=0"]
            ),
        ),
    )
    host.net(
        1,
        "tcp",
        [
            (_hex_v4("0.0.0.0", 22), ANY4, "0A", 1001),
            (_hex_v4("0.0.0.0", 8443), ANY4, "0A", 1003),
            (_hex_v4("127.0.0.1", 25), ANY4, "0A", 1004),  # nobody owns it visibly
        ],
    )
    host.net(1, "tcp6", [(_hex_v6("::", 443), _hex_v6("::", 0), "0A", 1002)])
    host.net(1, "udp", [(_hex_v4("0.0.0.0", 443), ANY4, "07", 1005)])
    libmaps = (
        "7f00-7f01 r-xp 00000000 fd:00 1 /usr/lib64/libcrypto.so.3.5.9\n"
        "7f02-7f03 r-xp 00000000 fd:00 2 /usr/lib64/libssl.so.3.5.9\n"
    )
    host.process(
        200,
        comm="sshd",
        sockets=(1001,),
        maps=libmaps,
        exe=sshd,
        cgroup="0::/system.slice/sshd.service\n",
    )
    # nginx master + worker share the listening socket.
    host.process(
        300,
        comm="nginx",
        sockets=(1002, 1005),
        maps=libmaps,
        exe=sshd,
        cgroup="0::/system.slice/nginx.service\n",
    )
    host.process(
        301,
        comm="nginx",
        sockets=(1002, 1005),
        maps=libmaps,
        exe=sshd,
        cgroup="0::/system.slice/nginx.service\n",
    )
    host.process(
        400,
        comm="srv",
        sockets=(1003,),
        exe=gosrv,
        cgroup="0::/system.slice/gosrv.service\n",
        environ=b"API_KEY=do-not-leak\0GODEBUG=tlsmlkem=0\0",  # pragma: allowlist secret
    )


def _by_port(result: dict, protocol: str, port: int) -> dict:
    (entry,) = [
        e
        for e in result["listeners"]
        if e["port"] == port and e["protocol"] == protocol
    ]
    return entry


def test_scan_services_end_to_end(host: FakeHost) -> None:
    _populate(host)
    out = rs.scan_services()
    assert out["available"] is True
    assert out["truncated"] is False

    ssh = _by_port(out, "tcp", 22)
    assert (ssh["pid"], ssh["process"], ssh["systemd_unit"], ssh["bind_scope"]) == (
        200,
        "sshd",
        "sshd.service",
        "any",
    )
    assert ssh["network_namespace"] == "host"
    assert ssh["static_binary"] is False and ssh["go"] is None
    libs = {
        (
            lib["path"],
            lib["family"],
            lib["version"],
            lib["version_source"],
            lib["library_pqc_capable"],
        )
        for lib in ssh["crypto_libraries"]
    }
    assert libs == {
        ("/usr/lib64/libcrypto.so.3.5.9", "openssl", "3.5.9", "embedded", True),
        ("/usr/lib64/libssl.so.3.5.9", "openssl", "3.5.9", "filename", True),
    }

    web = _by_port(out, "tcp", 443)
    assert web["family"] == "ipv6" and web["pids"] == [300, 301] and web["pid"] == 300
    assert _by_port(out, "udp", 443)["process"] == "nginx"

    go = _by_port(out, "tcp", 8443)
    assert go["static_binary"] is True and go["crypto_libraries"] == []
    assert go["go"] == {
        "go_version": "go1.24.4",
        "main_module": "example.com/srv",
        "cgo_enabled": "0",
        "default_hybrid_kex": None,
        "godebug_reverts": ["tlsmlkem"],
    }

    orphan = _by_port(out, "tcp", 25)
    assert orphan["pid"] is None and orphan["bind_scope"] == "loopback"
    assert out["summary"]["unattributed_listeners"] == 1
    assert out["summary"]["listeners_by_crypto_family"] == {
        "go": 1,
        "none": 1,
        "openssl": 3,
    }


def test_scan_services_never_reports_other_environment_variables(
    host: FakeHost,
) -> None:
    _populate(host)
    import json

    assert "do-not-leak" not in json.dumps(rs.scan_services())


def test_scan_services_deleted_library_read_via_map_files(host: FakeHost) -> None:
    upgraded = host.root / "proc" / "500" / "map_files"
    host.net(1, "tcp", [(_hex_v4("0.0.0.0", 636), ANY4, "0A", 2001)])
    host.process(
        500,
        comm="slapd",
        sockets=(2001,),
        maps="7f10-7f11 r-xp 00000000 fd:00 9 /usr/lib64/libcrypto.so.3 (deleted)\n",
    )
    upgraded.mkdir()
    (upgraded / "7f10-7f11").write_bytes(b"OpenSSL 3.2.2 4 Jun 2024")
    (lib,) = _by_port(rs.scan_services(), "tcp", 636)["crypto_libraries"]
    assert (lib["deleted"], lib["version"], lib["library_pqc_capable"]) == (
        True,
        "3.2.2",
        False,
    )


def test_scan_services_other_network_namespace(host: FakeHost) -> None:
    host.process(600, comm="podman-app", ns=OTHER_NS, sockets=(3001,))
    for name in ("tcp6", "udp", "udp6"):
        host.net(600, name, [])
    host.net(600, "tcp", [(_hex_v4("0.0.0.0", 9443), ANY4, "0A", 3001)])
    entry = _by_port(rs.scan_services(), "tcp", 9443)
    assert (entry["network_namespace"], entry["pid"]) == ("other", 600)


@pytest.mark.skipif(os.geteuid() == 0, reason="root can read a mode-000 directory")
def test_scan_services_counts_unreadable_processes(host: FakeHost) -> None:
    host.process(700, comm="secret", sockets=(4001,), fd_readable=False)
    try:
        out = rs.scan_services()
    finally:
        # let pytest clean the tmp tree up
        (host.root / "proc" / "700" / "fd").chmod(0o755)
    assert out["unreadable_pids"] == 1
    assert "CAP_SYS_PTRACE" in out["note"]


def test_scan_services_pid_cap_sets_truncated(host: FakeHost) -> None:
    for pid in range(10, 20):
        host.process(pid, comm="filler")
    out = rs.scan_services(max_pids=5)
    assert out["truncated"] is True and out["scanned_pids"] == 5


def test_scan_services_time_budget_sets_truncated(host: FakeHost) -> None:
    for pid in range(10, 15):
        host.process(pid, comm="filler")
    out = rs.scan_services(time_budget_s=0.0)
    assert out["truncated"] is True


def test_scan_services_unavailable_off_linux(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_platform, "is_linux", lambda: False)
    assert rs.scan_services()["available"] is False


def test_scan_services_container_without_host_mount_is_annotated(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    host = FakeHost(tmp_path)
    for name in ("tcp", "tcp6", "udp", "udp6"):
        host.net(1, name, [])
    monkeypatch.setattr(_platform, "HOST_PREFIX", str(tmp_path))
    monkeypatch.setattr(_platform, "is_linux", lambda: True)
    monkeypatch.setattr(
        _platform,
        "host_fs_unavailable_note",
        lambda label, res: {
            "unavailable_in_container": True,
            "reason": f"{label}: {res}",
        },
    )
    out = rs.scan_services()
    assert out["unavailable_in_container"] is True
    assert "hostPID" in out["reason"]


def test_cli_flag_wires_service_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    from pqc_readiness import cli

    called: list[bool] = []
    monkeypatch.setattr(
        rs,
        "scan_services",
        lambda: called.append(True) or {"available": True, "listeners": []},
    )
    args = cli.build_parser().parse_args(["--scan-services"])
    assert args.scan_services is True
    assert cli.build_parser().parse_args([]).scan_services is False
    assert pqc_readiness.scan_services is not None


def test_libssl_without_versioned_name_inherits_from_libcrypto(host: FakeHost) -> None:
    # Debian / container layout: libssl.so.3 has no release in its name and
    # libssl embeds no version string; libcrypto beside it does.
    host.file("/usr/lib/x86_64-linux-gnu/libcrypto.so.3", LIBCRYPTO)
    host.file("/usr/lib/x86_64-linux-gnu/libssl.so.3", b"nothing")
    host.net(1, "tcp", [(_hex_v4("0.0.0.0", 993), ANY4, "0A", 5001)])
    host.process(
        800,
        comm="dovecot",
        sockets=(5001,),
        maps=(
            "7f20-7f21 r-xp 00000000 fd:00 1 /usr/lib/x86_64-linux-gnu/libssl.so.3\n"
            "7f22-7f23 r-xp 00000000 fd:00 2 /usr/lib/x86_64-linux-gnu/libcrypto.so.3\n"
        ),
    )
    libs = _by_port(rs.scan_services(), "tcp", 993)["crypto_libraries"]
    assert [(lib["version"], lib["version_source"]) for lib in libs] == [
        ("3.5.9", "sibling-libcrypto"),
        ("3.5.9", "embedded"),
    ]


def test_socket_activated_listener_is_attributed_to_the_service_not_pid1(
    host: FakeHost,
) -> None:
    # EL9 rpcbind: systemd (PID 1) and rpcbind both hold the :111 socket.
    host.net(1, "tcp", [(_hex_v4("0.0.0.0", 111), ANY4, "0A", 6001)])
    (host.root / "proc" / "1" / "fd").rmdir()
    (host.root / "proc" / "1" / "fd").mkdir()
    os.symlink("socket:[6001]", host.root / "proc" / "1" / "fd" / "89")
    host.process(
        719,
        comm="rpcbind",
        sockets=(6001,),
        cgroup="0::/system.slice/rpcbind.service\n",
    )
    entry = _by_port(rs.scan_services(), "tcp", 111)
    assert (entry["pid"], entry["process"], entry["systemd_unit"], entry["pids"]) == (
        719,
        "rpcbind",
        "rpcbind.service",
        [1, 719],
    )


def test_pid1_only_owner_is_still_reported(host: FakeHost) -> None:
    host.net(1, "tcp", [(_hex_v4("0.0.0.0", 7), ANY4, "0A", 6002)])
    os.symlink("socket:[6002]", host.root / "proc" / "1" / "fd" / "90")
    assert _by_port(rs.scan_services(), "tcp", 7)["pid"] == 1


# ---------------------------------------------------------------------------
# Master/worker daemons (#240)
# ---------------------------------------------------------------------------


def _elf_dyn(needed: list[str], runpath: str | None = None, is64: bool = True) -> bytes:
    """Minimal dynamically linked ELF: PT_LOAD covering the file, PT_DYNAMIC,
    and a string table addressed by virtual address 0x400000 + offset."""
    bo = "<"
    base = 0x400000
    strtab = b"\0"
    offsets = []
    for name in needed + ([runpath] if runpath else []):
        offsets.append(len(strtab))
        strtab += name.encode() + b"\0"
    ehsize, phentsize = (64, 56) if is64 else (52, 32)
    phoff = ehsize
    str_off = phoff + 2 * phentsize
    dyn_off = str_off + len(strtab)
    entries = [(1, o) for o in offsets[: len(needed)]]
    if runpath:
        entries.append((29, offsets[-1]))
    entries += [(5, base + str_off), (10, len(strtab)), (0, 0)]
    entfmt = bo + ("qQ" if is64 else "iI")
    dyn = b"".join(struct.pack(entfmt, t, v) for t, v in entries)
    total = dyn_off + len(dyn)
    ident = b"\x7fELF" + bytes([2 if is64 else 1, 1, 1]) + b"\0" * 9
    if is64:
        ehdr = ident + struct.pack(
            bo + "HHIQQQIHHHHHH",
            3,
            62,
            1,
            0,
            phoff,
            0,
            0,
            ehsize,
            phentsize,
            2,
            64,
            0,
            0,
        )
        load = struct.pack(bo + "IIQQQQQQ", 1, 5, 0, base, base, total, total, 0x1000)
        dynph = struct.pack(
            bo + "IIQQQQQQ",
            2,
            6,
            dyn_off,
            base + dyn_off,
            base + dyn_off,
            len(dyn),
            len(dyn),
            8,
        )
    else:
        ehdr = ident + struct.pack(
            bo + "HHIIIIIHHHHHH",
            3,
            3,
            1,
            0,
            phoff,
            0,
            0,
            ehsize,
            phentsize,
            2,
            40,
            0,
            0,
        )
        load = struct.pack(bo + "IIIIIIII", 1, 0, base, base, total, total, 5, 0x1000)
        dynph = struct.pack(
            bo + "IIIIIIII",
            2,
            dyn_off,
            base + dyn_off,
            base + dyn_off,
            len(dyn),
            len(dyn),
            6,
            4,
        )
    return ehdr + load + dynph + strtab + dyn


@pytest.mark.parametrize("is64", [True, False])
def test_elf_dynamic_reads_needed_and_runpath(tmp_path: Path, is64: bool) -> None:
    p = tmp_path / "smtpd"
    p.write_bytes(
        _elf_dyn(["libpostfix-tls.so", "libc.so.6"], "/usr/lib64/postfix", is64)
    )
    with p.open("rb") as fh:
        assert rs.elf_dynamic(fh) == {
            "needed": ["libpostfix-tls.so", "libc.so.6"],
            "runpath": ["/usr/lib64/postfix"],
        }


def test_elf_dynamic_static_not_elf_and_truncated(tmp_path: Path) -> None:
    static = tmp_path / "static"
    static.write_bytes(_elf(interp=False, buildinfo=None))
    with static.open("rb") as fh:
        assert rs.elf_dynamic(fh) == {"needed": [], "runpath": []}
    script = tmp_path / "script"
    script.write_bytes(b"#!/bin/sh\n")
    with script.open("rb") as fh:
        assert rs.elf_dynamic(fh) is None
    cut = tmp_path / "cut"
    cut.write_bytes(_elf_dyn(["libssl.so.3"])[:70])
    with cut.open("rb") as fh, pytest.raises((ValueError, struct.error)):
        rs.elf_dynamic(fh)


def _postfix(host: FakeHost, *, layout: str = "el") -> None:
    """Postfix as measured on Rocky 9 / Ubuntu 26.04 (#240): master owns :25
    and maps no crypto library; smtpd links libpostfix-tls.so (via RPATH or
    RUNPATH), which links libssl/libcrypto."""
    if layout == "el":
        daemon, private, libdir = (
            "/usr/libexec/postfix",
            "/usr/lib64/postfix",
            "/usr/lib64",
        )
    else:
        daemon, private, libdir = (
            "/usr/lib/postfix/sbin",
            "/usr/lib/postfix",
            "/usr/lib/x86_64-linux-gnu",
        )
    host.file(f"{libdir}/libc.so.6", _elf_dyn([]))
    host.file(f"{libdir}/libcrypto.so.3", LIBCRYPTO)
    host.file(f"{libdir}/libssl.so.3", _elf_dyn(["libcrypto.so.3", "libc.so.6"]))
    host.file(f"{private}/libpostfix-util.so", _elf_dyn(["libdb-5.3.so", "libc.so.6"]))
    host.file(
        f"{private}/libpostfix-tls.so",
        _elf_dyn(["libssl.so.3", "libcrypto.so.3", "libc.so.6"]),
    )
    host.file(f"{daemon}/master", _elf_dyn(["libpostfix-util.so"], private))
    host.file(f"{daemon}/qmgr", _elf_dyn(["libpostfix-util.so"], private))
    host.file(f"{daemon}/postfix-script", b"#!/bin/sh\n")
    host.file(
        f"{daemon}/smtpd",
        _elf_dyn(["libpostfix-tls.so", "libpostfix-util.so", "libc.so.6"], private),
    )
    host.net(1, "tcp", [(_hex_v4("0.0.0.0", 25), ANY4, "0A", 7001)])
    libc_map = f"7f00-7f01 r-xp 00000000 fd:00 9 {libdir}/libc.so.6\n"
    unit = "0::/system.slice/postfix.service\n"
    host.process(
        900,
        comm="master",
        sockets=(7001,),
        exe_path=f"{daemon}/master",
        cgroup=unit,
        maps=libc_map,
    )
    host.process(
        901,
        comm="qmgr",
        exe_path=f"{daemon}/qmgr",
        cgroup=unit,
        ppid=900,
        maps=libc_map,
    )


@pytest.mark.parametrize("layout", ["el", "debian"])
def test_idle_master_takes_crypto_from_worker_binaries(
    host: FakeHost, layout: str
) -> None:
    # Regression for #240: an idle Postfix (no smtpd running) used to report
    # :25 with no crypto library, so the deployment-gap verdict skipped it.
    _postfix(host, layout=layout)
    entry = _by_port(rs.scan_services(), "tcp", 25)
    assert entry["process"] == "master" and entry["pid"] == 900
    assert {(lib["family"], lib["version"]) for lib in entry["crypto_libraries"]} == {
        ("openssl", "3.5.9")
    }
    daemon = "/usr/libexec/postfix" if layout == "el" else "/usr/lib/postfix/sbin"
    assert entry["crypto_libraries_from"] == {
        "source": "worker-binary",
        "binary": f"{daemon}/smtpd",
    }


def test_master_takes_crypto_from_worker_holding_the_socket(host: FakeHost) -> None:
    # After a connection, smtpd holds the inherited listening socket and maps
    # libssl itself: that process is the evidence, not the binaries on disk.
    _postfix(host)
    smtpd_maps = (
        "7f10-7f11 r-xp 00000000 fd:00 1 /usr/lib64/libcrypto.so.3\n"
        "7f12-7f13 r-xp 00000000 fd:00 2 /usr/lib64/libssl.so.3\n"
    )
    host.process(
        950,
        comm="smtpd",
        sockets=(7001,),
        maps=smtpd_maps,
        exe_path="/usr/libexec/postfix/smtpd",
        ppid=900,
    )
    entry = _by_port(rs.scan_services(), "tcp", 25)
    assert entry["pid"] == 900 and entry["pids"] == [900, 950]
    assert entry["crypto_libraries_from"]["source"] == "socket-holder"
    assert entry["crypto_libraries_from"]["pid"] == 950
    assert entry["crypto_libraries_from"]["process"] == "smtpd"
    assert {lib["version"] for lib in entry["crypto_libraries"]} == {"3.5.9"}


def test_master_takes_crypto_from_a_descendant(host: FakeHost) -> None:
    # A worker that maps the TLS library but doesn't hold the socket (e.g.
    # tlsmgr) settles which library the daemon uses.
    _postfix(host)
    host.process(
        960,
        comm="tlsmgr",
        maps=(
            "7f10-7f11 r-xp 00000000 fd:00 1 /usr/lib64/libcrypto.so.3\n"
            "7f12-7f13 r-xp 00000000 fd:00 2 /usr/lib64/libssl.so.3\n"
        ),
        exe_path="/usr/libexec/postfix/tlsmgr",
        ppid=900,
    )
    entry = _by_port(rs.scan_services(), "tcp", 25)
    assert entry["crypto_libraries_from"]["source"] == "descendant"
    assert entry["crypto_libraries_from"]["process"] == "tlsmgr"


def test_libcrypto_only_descendant_loses_to_a_tls_linked_worker_binary(
    host: FakeHost,
) -> None:
    # Measured on Rocky 9.8: an idle Postfix's pickup maps libcrypto (not
    # libssl).  That is weaker evidence than smtpd's link to libssl, so the
    # worker binary wins; the libcrypto-only process is a last resort.
    _postfix(host)
    host.process(
        961,
        comm="pickup",
        maps="7f10-7f11 r-xp 00000000 fd:00 1 /usr/lib64/libcrypto.so.3\n",
        exe_path="/usr/libexec/postfix/pickup",
        ppid=900,
    )
    entry = _by_port(rs.scan_services(), "tcp", 25)
    assert entry["crypto_libraries_from"] == {
        "source": "worker-binary",
        "binary": "/usr/libexec/postfix/smtpd",
    }


def test_libcrypto_only_descendant_is_the_last_resort(host: FakeHost) -> None:
    host.file("/usr/lib64/libcrypto.so.3", LIBCRYPTO)
    host.file("/opt/d/daemon", _elf_dyn(["libc.so.6"]))
    host.file("/opt/d/helper", _elf_dyn(["libc.so.6"]))
    host.net(1, "tcp", [(_hex_v4("0.0.0.0", 9100), ANY4, "0A", 7301)])
    host.process(990, comm="daemon", sockets=(7301,), exe_path="/opt/d/daemon")
    host.process(
        991,
        comm="helper",
        maps="7f10-7f11 r-xp 00000000 fd:00 1 /usr/lib64/libcrypto.so.3\n",
        exe_path="/opt/d/helper",
        ppid=990,
    )
    entry = _by_port(rs.scan_services(), "tcp", 9100)
    assert entry["crypto_libraries_from"]["source"] == "descendant"
    assert entry["crypto_libraries_from"]["process"] == "helper"


def test_standalone_daemon_does_not_borrow_sibling_binaries(host: FakeHost) -> None:
    # No workers: a daemon in a shared private directory (here one beside a
    # binary that links libcrypto) must not be credited with that library.
    host.file("/usr/lib64/libcrypto.so.3", LIBCRYPTO)
    host.file("/usr/lib/systemd/systemd-networkd", _elf_dyn(["libc.so.6"]))
    host.file("/usr/lib/systemd/systemd-resolved", _elf_dyn(["libcrypto.so.3"]))
    host.net(1, "udp", [(_hex_v4("0.0.0.0", 68), ANY4, "07", 7101)])
    host.process(
        970,
        comm="systemd-network",
        sockets=(7101,),
        exe_path="/usr/lib/systemd/systemd-networkd",
    )
    entry = _by_port(rs.scan_services(), "udp", 68)
    assert entry["crypto_libraries"] == [] and "crypto_libraries_from" not in entry


def test_workers_in_shared_bin_dirs_are_not_scanned(host: FakeHost) -> None:
    host.file("/usr/lib64/libcrypto.so.3", LIBCRYPTO)
    host.file("/usr/bin/openssl", _elf_dyn(["libcrypto.so.3"]))
    host.file("/usr/bin/sh", _elf_dyn(["libc.so.6"]))
    host.file("/opt/srv/srv", _elf_dyn(["libc.so.6"]))
    host.net(1, "tcp", [(_hex_v4("0.0.0.0", 9000), ANY4, "0A", 7201)])
    host.process(980, comm="srv", sockets=(7201,), exe_path="/opt/srv/srv")
    host.process(981, comm="sh", exe_path="/usr/bin/sh", ppid=980)
    entry = _by_port(rs.scan_services(), "tcp", 9000)
    assert entry["crypto_libraries"] == []


def test_worker_binary_lookups_stay_inside_the_root(host: FakeHost) -> None:
    # DT_NEEDED and RUNPATH are read from files on the scanned host: a name
    # with a path in it or a RUNPATH climbing out with ".." must not make
    # the scanner read outside the process's root (AI review on #250).
    outside = host.root / "outside"
    outside.mkdir()
    (outside / "libssl.so.3").write_bytes(_elf_dyn(["libcrypto.so.3"]))
    (outside / "libcrypto.so.3").write_bytes(LIBCRYPTO)
    host.file(
        "/opt/evil/worker",
        # From /opt/evil, three ".." reach the directory above the root.
        _elf_dyn(
            ["../../../outside/libssl.so.3", "libssl.so.3"],
            "/opt/evil:/opt/evil/../../../outside",
        ),
    )
    host.file("/opt/evil/daemon", _elf_dyn(["libc.so.6"]))
    host.net(1, "tcp", [(_hex_v4("0.0.0.0", 9200), ANY4, "0A", 7401)])
    host.process(995, comm="daemon", sockets=(7401,), exe_path="/opt/evil/daemon")
    host.process(996, comm="worker", exe_path="/opt/evil/worker", ppid=995)
    entry = _by_port(rs.scan_services(), "tcp", 9200)
    assert entry["crypto_libraries"] == [] and "crypto_libraries_from" not in entry


def test_elf_dynamic_rejects_oversized_program_header_entries(tmp_path: Path) -> None:
    # AI review on #250: e_phentsize was unbounded, so e_phnum (<= 4096)
    # times a forged 65535-byte entry size made one read allocate ~256 MB.
    blob = bytearray(_elf_dyn(["libssl.so.3"]))
    struct.pack_into("<HH", blob, 54, 0xFFFF, 4096)  # e_phentsize, e_phnum
    p = tmp_path / "forged"
    p.write_bytes(bytes(blob))
    with p.open("rb") as fh, pytest.raises(ValueError):
        rs.elf_dynamic(fh)


# Container identity (#233)
# ---------------------------------------------------------------------------

CID = "466fa36113125f83e8bdd28ce9e110580e1df56d009a5bb778f50bcf0afb8b59"  # pragma: allowlist secret
POD_UID = "96729e5171d4355063effb4f71b182d6"  # pragma: allowlist secret
# Measured on OpenShift Local 4.22.14 (RHCOS): the kube-apiserver static pod.
CRIO_CGROUP = (
    "/kubepods.slice/kubepods-burstable.slice/"
    "kubepods-burstable-pod96729e5171d4355063effb4f71b182d6.slice/"
    f"crio-{CID}.scope"
)


@pytest.mark.parametrize(
    ("cgroup", "runtime", "pod_uid"),
    [
        (
            CRIO_CGROUP,
            "cri-o",
            POD_UID,
        ),
        (
            # systemd escapes the UID's dashes as underscores.
            "/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-"
            "pod1b2c3d4e_5f60_4a1b_8c2d_3e4f5a6b7c8d.slice/"
            f"cri-containerd-{CID}.scope",
            "containerd",
            "1b2c3d4e-5f60-4a1b-8c2d-3e4f5a6b7c8d",
        ),
        (
            f"/kubepods/burstable/pod1b2c3d4e-5f60-4a1b-8c2d-3e4f5a6b7c8d/{CID}",
            None,
            "1b2c3d4e-5f60-4a1b-8c2d-3e4f5a6b7c8d",
        ),
        (f"/machine.slice/libpod-{CID}.scope", "podman", None),
        (f"/system.slice/docker-{CID}.scope", "docker", None),
    ],
)
def test_container_identity_from_cgroup(
    host: FakeHost, cgroup: str, runtime: str | None, pod_uid: str | None
) -> None:
    c = rs.container_identity(cgroup, rs._Cache())
    assert c is not None
    assert (c["runtime"], c["id"], c["pod_uid"]) == (runtime, CID, pod_uid)
    # No kubelet log directory on this host: names stay unknown.
    assert (c["pod_name"], c["pod_namespace"], c["container_name"]) == (None,) * 3


@pytest.mark.parametrize(
    "cgroup", ["/system.slice/sshd.service", "/init.scope", "", None]
)
def test_processes_outside_containers_have_no_container(
    cgroup: str | None,
) -> None:
    assert rs.container_identity(cgroup, rs._Cache()) is None


def _kubelet_logs(host: FakeHost, *names: str) -> None:
    d = host.root / "var" / "log" / "containers"
    d.mkdir(parents=True, exist_ok=True)
    for n in names:
        (d / n).write_text("")


def test_listener_in_a_pod_is_named_from_the_kubelet_log_directory(
    host: FakeHost,
) -> None:
    _kubelet_logs(
        host,
        f"kube-apiserver-crc_openshift-kube-apiserver_kube-apiserver-{CID}.log",
        # Another container of the same pod, and one with a dash-rich name.
        "kube-apiserver-crc_openshift-kube-apiserver_kube-apiserver-check-"
        "endpoints-" + "a" * 64 + ".log",
        "not-a-container-log.txt",
    )
    host.net(1, "tcp6", [(_hex_v6("::", 6443), _hex_v6("::", 0), "0A", 8001)])
    host.process(
        1200,
        comm="kube-apiserver",
        sockets=(8001,),
        exe_path="/usr/bin/kube-apiserver",
        cgroup=f"0::{CRIO_CGROUP}\n",
    )
    entry = _by_port(rs.scan_services(), "tcp", 6443)
    assert entry["systemd_unit"] == f"crio-{CID}.scope"
    assert entry["container"] == {
        "runtime": "cri-o",
        "id": CID,
        "pod_uid": "96729e5171d4355063effb4f71b182d6",  # pragma: allowlist secret
        "pod_name": "kube-apiserver-crc",
        "pod_namespace": "openshift-kube-apiserver",
        "container_name": "kube-apiserver",
    }


def test_host_process_listener_has_null_container(host: FakeHost) -> None:
    _populate(host)
    assert _by_port(rs.scan_services(), "tcp", 22)["container"] is None
