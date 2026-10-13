# SPDX-License-Identifier: Apache-2.0
"""All-process crypto attribution (--scan-processes, #155).

Runs against the synthetic /proc trees from test_service_linkage so the
service and process scans are exercised on the same fixtures."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from pqc_readiness import _platform
from pqc_readiness.detect import runtime_processes as rp
from pqc_readiness.detect import runtime_services as rs

import test_service_linkage as tsl  # sibling module; tests/ is on sys.path

ANY4 = tsl.ANY4
LIBCRYPTO = tsl.LIBCRYPTO
OTHER_NS = tsl.OTHER_NS
FakeHost = tsl.FakeHost
_elf = tsl._elf
_go_blob = tsl._go_blob
_hex_v4 = tsl._hex_v4
_populate = tsl._populate
host = tsl.host  # reuse the synthetic-/proc fixture

OLD_LIBCRYPTO = b"\0OpenSSL 3.2.2 4 Jun 2024\0"
GNUTLS_PQC = b"GnuTLS 3.8.13\0X25519-MLKEM768\0"
GNUTLS_CLASSICAL = b"GnuTLS 3.8.3\0x25519\0"


def _maps(*paths: str, inode0: int = 100) -> str:
    return "".join(
        f"7f{i:02x}0-7f{i:02x}1 r-xp 00000000 fd:00 {inode0 + i} {p}\n"
        for i, p in enumerate(paths)
    )


def _group(out: dict, exe_suffix: str) -> dict:
    (g,) = [g for g in out["groups"] if (g["exe"] or "").endswith(exe_suffix)]
    return g


def _client_host(host: FakeHost) -> None:
    """Services from test_service_linkage plus clients, idle and no-crypto
    processes, kernel threads and a worker pool."""
    _populate(host)
    host.file("/usr/lib64/old/libcrypto.so.3", OLD_LIBCRYPTO)
    curl = host.file("/usr/bin/agent", _elf(interp=True, buildinfo=None))
    cli = host.file("/usr/bin/tool", _elf(interp=True, buildinfo=None))
    plain = host.file("/usr/bin/cat", _elf(interp=True, buildinfo=None))
    # An outbound-only TLS client on an old OpenSSL with two connections.
    host.net(
        1,
        "tcp",
        [
            (_hex_v4("0.0.0.0", 22), ANY4, "0A", 1001),
            (_hex_v4("0.0.0.0", 8443), ANY4, "0A", 1003),
            (_hex_v4("127.0.0.1", 25), ANY4, "0A", 1004),
            (_hex_v4("10.0.0.5", 40000), _hex_v4("10.0.0.9", 443), "01", 5001),
            (_hex_v4("10.0.0.5", 40001), _hex_v4("10.0.0.9", 443), "01", 5002),
        ],
    )
    host.process(
        800,
        comm="agent",
        sockets=(5001, 5002),
        maps=_maps("/usr/lib64/old/libcrypto.so.3"),
        exe=curl,
        cgroup="0::/system.slice/agent.service\n",
    )
    # Three identical idle workers -> one group, process_count 3.
    for pid in (900, 901, 902):
        host.process(
            pid,
            comm="tool",
            maps=_maps("/usr/lib64/libcrypto.so.3.5.9"),
            exe=cli,
            cgroup="0::/user.slice/user-1000.slice/session-3.scope\n",
        )
    host.process(950, comm="cat", maps=_maps("/usr/lib64/libc.so.6"), exe=plain)
    host.process(2, comm="kthreadd", maps="")  # kernel thread: no address space


def test_parse_established_inodes() -> None:
    text = (
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when "
        "retrnsmt   uid  timeout inode\n"
        f"   0: {_hex_v4('10.0.0.5', 40000)} {_hex_v4('10.0.0.9', 443)} 01 0:0 "
        "00:00000000 00000000 0 0 777 1\n"
        f"   1: {_hex_v4('0.0.0.0', 22)} {ANY4} 0A 0:0 00:00000000 00000000 "
        "0 0 888 1\n"
        "   2: garbage\n"
        f"   3: {_hex_v4('10.0.0.5', 40001)} {_hex_v4('10.0.0.9', 443)} 01 0:0 "
        "00:00000000 00000000 0 0 notanint 1\n"
    )
    assert rp.parse_established_inodes(text) == {777}


def test_scan_processes_groups_roles_and_ordering(host: FakeHost) -> None:
    _client_host(host)
    out = rp.scan_processes()
    assert out["available"] is True and out["truncated"] is False
    assert out["kernel_threads"] == 2  # pid 1 fixture + kthreadd

    agent = _group(out, "/agent")
    assert agent["pqc_capable"] is False
    assert agent["roles"] == {"server": 0, "client": 1, "idle": 0}
    assert agent["established_tcp_connections"] == 2
    assert agent["systemd_units"] == ["agent.service"]
    (lib,) = agent["crypto_libraries"]
    assert (lib["version"], lib["library_pqc_capable"], lib["pqc_evidence"]) == (
        "3.2.2",
        False,
        "version",
    )

    tool = _group(out, "/tool")
    assert tool["process_count"] == 3 and tool["sample_pids"] == [900, 901, 902]
    assert tool["roles"]["idle"] == 3 and tool["pqc_capable"] is True

    sshd = _group(out, "/sshd")  # sshd + nginx share the exe fixture
    assert sshd["roles"]["server"] == 3

    go = _group(out, "/srv")
    assert go["pqc_capable"] is False  # GODEBUG=tlsmlkem=0 in its environ
    assert go["go"]["default_hybrid_kex"] is None

    # Groups that cannot do PQC sort first.
    assert [g["pqc_capable"] for g in out["groups"][:2]] == [False, False]
    s = out["summary"]
    assert s["processes_without_crypto"] == 1  # cat (libc only)
    assert s["processes_not_pqc_capable"] == 2  # agent + go srv
    assert s["client_processes_not_pqc_capable"] == 1
    assert s["processes_with_crypto"] == 1 + 3 + 3 + 1


def test_scan_processes_never_reports_environment(host: FakeHost) -> None:
    _client_host(host)
    assert "do-not-leak" not in json.dumps(rp.scan_processes())


@pytest.mark.skipif(os.geteuid() == 0, reason="root can read a mode-000 file")
def test_unreadable_maps_are_counted_not_guessed(host: FakeHost) -> None:
    host.process(700, comm="secret", maps=_maps("/usr/lib64/libcrypto.so.3.5.9"))
    maps = host.root / "proc" / "700" / "maps"
    maps.chmod(0)
    try:
        out = rp.scan_processes()
    finally:
        maps.chmod(0o644)
    assert out["unreadable_pids"] == 1
    assert "CAP_SYS_PTRACE" in out["note"]
    assert out["groups"] == []


def test_sandboxed_process_reuses_library_read_via_another_process(
    host: FakeHost,
) -> None:
    host.file("/usr/lib64/libgnutls.so.30.42.0", GNUTLS_PQC)
    exe = host.file("/opt/browser/browser", _elf(interp=True, buildinfo=None))
    maps = _maps("/usr/lib64/libgnutls.so.30.42.0", inode0=4242)
    host.process(10, comm="browser", maps=maps, exe=exe)
    # Same file (same device + inode in maps) but a private, empty root.
    host.process(11, comm="browser", maps=maps, exe=exe)
    sandbox = host.root / "sandbox-root"
    sandbox.mkdir()
    root_link = host.root / "proc" / "11" / "root"
    root_link.unlink()
    os.symlink(sandbox, root_link)
    out = rp.scan_processes()
    (g,) = out["groups"]
    assert g["process_count"] == 2
    (lib,) = g["crypto_libraries"]
    assert (lib["version"], lib["pqc_evidence"], lib["library_pqc_capable"]) == (
        "3.8.13",
        "binary",
        True,
    )


@pytest.mark.parametrize(
    ("blob", "expected"), [(GNUTLS_PQC, True), (GNUTLS_CLASSICAL, False), (b"", None)]
)
def test_library_tls_pqc_markers(blob: bytes, expected: bool | None) -> None:
    assert rs.library_tls_pqc_markers("gnutls", blob) is expected


def test_markers_unknown_for_version_assessed_families() -> None:
    assert rs.library_tls_pqc_markers("openssl", LIBCRYPTO) is None
    # Binary evidence wins over the version threshold when present.
    assert rs.library_pqc_capable("gnutls", "3.8.13", markers=False) is False
    assert rs.library_pqc_capable("openssl", "3.5.9", markers=None) is True


def test_group_pqc_capable_rules() -> None:
    lib = lambda v: {"library_pqc_capable": v}  # noqa: E731
    f = rp.group_pqc_capable
    assert f({"crypto_libraries": [lib(True), lib(False)], "go": None}) is False
    assert f({"crypto_libraries": [lib(True), lib(True)], "go": None}) is True
    assert f({"crypto_libraries": [lib(True), lib(None)], "go": None}) is None
    assert f({"crypto_libraries": [], "go": None}) is None
    assert (
        f({"crypto_libraries": [], "go": {"default_hybrid_kex": "X25519MLKEM768"}})
        is True
    )


def test_other_network_namespace_is_labelled(host: FakeHost) -> None:
    for name in ("tcp", "tcp6", "udp", "udp6"):
        host.net(1, name, [])
    host.file("/usr/lib64/libcrypto.so.3.5.9", LIBCRYPTO)
    host.process(
        600, comm="app", ns=OTHER_NS, maps=_maps("/usr/lib64/libcrypto.so.3.5.9")
    )
    for name in ("tcp", "tcp6", "udp", "udp6"):
        host.net(600, name, [])
    (g,) = rp.scan_processes()["groups"]
    assert g["network_namespaces"] == ["other"]


def test_pid_cap_time_budget_and_group_cap(host: FakeHost) -> None:
    host.file("/usr/lib64/libcrypto.so.3.5.9", LIBCRYPTO)
    for pid in range(10, 30):
        exe = host.file(f"/usr/bin/b{pid}", _elf(interp=True, buildinfo=None))
        host.process(
            pid, comm=f"b{pid}", maps=_maps("/usr/lib64/libcrypto.so.3.5.9"), exe=exe
        )
    capped = rp.scan_processes(max_pids=5)
    assert capped["truncated"] is True and capped["scanned_pids"] <= 5
    assert rp.scan_processes(time_budget_s=0.0)["truncated"] is True
    grouped = rp.scan_processes(max_groups=3)
    assert len(grouped["groups"]) == 3 and grouped["omitted_groups"] == 20 - 3
    assert grouped["summary"]["groups"] == 20  # summary counts every group


def test_go_static_binary_is_attributed(host: FakeHost) -> None:
    for name in ("tcp", "tcp6", "udp", "udp6"):
        host.net(1, name, [])
    go = host.file(
        "/usr/local/bin/gosvc",
        _elf(interp=False, buildinfo=_go_blob("go1.25.1", ["path\texample.com/x"])),
    )
    host.process(77, comm="gosvc", maps=_maps("/usr/local/bin/gosvc"), exe=go)
    (g,) = rp.scan_processes()["groups"]
    assert g["static_binary"] is True and g["pqc_capable"] is True
    assert g["go"]["default_hybrid_kex"] == "X25519MLKEM768"


def test_unavailable_off_linux(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_platform, "is_linux", lambda: False)
    assert rp.scan_processes()["available"] is False


def test_container_without_host_mount_is_annotated(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    h = FakeHost(tmp_path)
    for name in ("tcp", "tcp6", "udp", "udp6"):
        h.net(1, name, [])
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
    out = rp.scan_processes()
    assert out["unavailable_in_container"] is True and "hostPID" in out["reason"]


def test_cli_flag_wires_process_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    from pqc_readiness import cli

    assert cli.build_parser().parse_args(["--scan-processes"]).scan_processes is True
    assert cli.build_parser().parse_args([]).scan_processes is False


def test_text_report_lists_groups_that_cannot_do_pqc(host: FakeHost) -> None:
    from pqc_readiness import report as _report
    from pqc_readiness.render import text as _text

    _client_host(host)
    r = _report.Report(process_crypto_linkage=rp.scan_processes())  # type: ignore[call-arg]
    lines = "\n".join(_text._render_text_processes(r))
    assert "Processes using crypto" in lines
    assert (
        "/usr/bin/agent x1 [client]" in lines.replace(str(host.root / "fs"), "")
        and "openssl 3.2.2" in lines
    )
    assert "/usr/bin/tool" not in lines  # capable groups are only summarised


def test_scanner_excludes_its_own_process(host: FakeHost) -> None:
    host.file("/usr/lib64/libcrypto.so.3.5.9", LIBCRYPTO)
    exe = host.file("/usr/bin/python3", _elf(interp=True, buildinfo=None))
    host.process(
        4321, comm="python3", maps=_maps("/usr/lib64/libcrypto.so.3.5.9"), exe=exe
    )
    os.symlink("4321", host.root / "proc" / "self")
    out = rp.scan_processes()
    assert out["groups"] == [] and out["summary"]["processes_with_crypto"] == 0
