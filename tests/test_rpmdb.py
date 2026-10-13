# SPDX-License-Identifier: Apache-2.0
"""Direct rpm database reader (#125).

Fixtures under tests/fixtures/rpmdb/ are real rpmdb.sqlite files: the
schema of each distro image's database with a few real package headers
copied in.  `expected-rpm-qa.txt` in each layout is the matching
`rpm -qa --queryformat '%{NAME} %{VERSION} %{RELEASE} %{ARCH}\\n'` output
from that image, so the reader is checked against rpm itself.
"""

from __future__ import annotations

import os
import shutil
import sqlite3
import struct
import sys
from pathlib import Path

import pytest

import pqc_readiness as pr

FIXTURES = Path(__file__).parent / "fixtures" / "rpmdb"
QA_FORMAT = "%{NAME} %{VERSION} %{RELEASE} %{ARCH}"


def _no_subprocess(cmd, timeout=None):  # noqa: ARG001
    raise AssertionError(f"direct read must not fork: {cmd}")


def _as_qa_lines(pkgs: list[dict]) -> list[str]:
    return sorted(
        f"{p['name']} {p['version']} {p.get('release', '')} {p.get('arch', '(none)')}"
        for p in pkgs
    )


def _expected(layout: str) -> list[str]:
    text = (FIXTURES / layout / "expected-rpm-qa.txt").read_text()
    return sorted(line for line in text.splitlines() if line)


def _header(name: str, version: str, release: str = "1", arch: str = "x86_64") -> bytes:
    """Build a minimal valid rpm header blob (no magic, as rpmdb stores it)."""
    entries = [
        (1000, 6, name),
        (1001, 6, version),
        (1002, 6, release),
        (1022, 6, arch),
    ]
    index = b""
    data = b""
    for tag, typ, value in entries:
        index += struct.pack(">IIII", tag, typ, len(data), 1)
        data += value.encode() + b"\0"
    return struct.pack(">II", len(entries), len(data)) + index + data


def _make_sqlite_db(path: Path, blobs: list[bytes]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path)
    con.execute(
        "CREATE TABLE 'Packages' (hnum INTEGER PRIMARY KEY AUTOINCREMENT,"
        "blob BLOB NOT NULL)"
    )
    con.executemany("INSERT INTO Packages(blob) VALUES (?)", [(b,) for b in blobs])
    con.commit()
    con.close()


@pytest.fixture
def host(monkeypatch):
    """Point --host-mount at a directory and forbid real subprocesses."""

    def _use(root: Path) -> Path:
        monkeypatch.setattr(pr, "HOST_PREFIX", str(root))
        monkeypatch.setattr(pr, "_run", _no_subprocess)
        pr._query_rpm_packages_cached.cache_clear()
        return root

    return _use


# ---------------------------------------------------------------------------
# Real-header fixtures, one per measured layout
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("layout", "db_root"),
    [
        # EL10 / Fedora: /var/lib/rpm is a relative symlink to sysimage.
        ("fedora44", "/usr/lib/sysimage/rpm"),
        # EL9: /var/lib/rpm is the real directory.
        ("el9", "/var/lib/rpm"),
        # Oracle Linux 9: live db in /var/lib/rpm plus a stray empty
        # /usr/lib/sysimage/rpm/rpmdb.sqlite that must be ignored.
        ("ol9-stray-empty", "/var/lib/rpm"),
    ],
)
def test_direct_read_matches_rpm_qa(host, layout: str, db_root: str) -> None:
    host(FIXTURES / layout)
    inv = pr.query_rpm_packages()
    assert inv["available"] is True
    assert inv["source"] == "rpmdb-sqlite"
    assert inv["backend"] == "sqlite"
    assert inv["db_root"] == db_root
    assert _as_qa_lines(inv["packages"]) == _expected(layout)


def test_ol9_stray_empty_sysimage_db_is_never_the_answer(host) -> None:
    # Regression: probing /usr/lib/sysimage/rpm first reported 0 packages
    # on Oracle Linux 9.  The live /var/lib/rpm db must win, and the
    # stray db on its own is rejected as invalid rather than read as empty.
    root = host(FIXTURES / "ol9-stray-empty")
    inv = pr.query_rpm_packages()
    assert inv["db_root"] == "/var/lib/rpm"
    assert len(inv["packages"]) == len(_expected("ol9-stray-empty")) > 0
    stray = root / "usr/lib/sysimage/rpm/rpmdb.sqlite"
    with pytest.raises(pr.RpmdbError, match="0 packages"):
        pr.read_rpmdb_sqlite(stray)


def test_empty_sqlite_db_falls_back_to_cli(host, monkeypatch, tmp_path) -> None:
    host(tmp_path)
    shutil.copy(
        FIXTURES / "ol9-stray-empty/usr/lib/sysimage/rpm/rpmdb.sqlite",
        tmp_path / "placeholder",
    )
    (tmp_path / "var/lib/rpm").mkdir(parents=True)
    shutil.move(tmp_path / "placeholder", tmp_path / "var/lib/rpm/rpmdb.sqlite")
    calls: list[list[str]] = []

    def fake_run(cmd, timeout=None):  # noqa: ARG001
        calls.append(cmd)
        return 0, "bash 5.1.8 9.el9 x86_64\n"

    monkeypatch.setattr(pr, "_run", fake_run)
    monkeypatch.setattr(pr.shutil, "which", lambda name: f"/usr/bin/{name}")
    inv = pr.query_rpm_packages()
    assert inv["source"] == "rpm-cli"
    assert calls and calls[0][:5] == ["rpm", "--root", str(tmp_path), "--dbpath", "/var/lib/rpm"]
    assert [p["name"] for p in inv["packages"]] == ["bash"]


# ---------------------------------------------------------------------------
# Symlink resolution under --host-mount
# ---------------------------------------------------------------------------


def test_absolute_host_symlink_is_rerooted_under_prefix(host, tmp_path) -> None:
    # A host symlink /var/lib/rpm -> /usr/lib/sysimage/rpm (absolute) must
    # be followed inside the host mount, never into the scanner's own /usr.
    host(tmp_path)
    target = tmp_path / "usr/lib/sysimage/rpm"
    target.mkdir(parents=True)
    shutil.copy(FIXTURES / "el9/var/lib/rpm/rpmdb.sqlite", target / "rpmdb.sqlite")
    (tmp_path / "var/lib").mkdir(parents=True)
    os.symlink("/usr/lib/sysimage/rpm", tmp_path / "var/lib/rpm")
    inv = pr.query_rpm_packages()
    assert inv["db_root"] == "/usr/lib/sysimage/rpm"
    assert _as_qa_lines(inv["packages"]) == _expected("el9")


def test_resolve_under_prefix_handles_relative_and_dotdot(tmp_path) -> None:
    (tmp_path / "usr/lib/sysimage/rpm").mkdir(parents=True)
    (tmp_path / "var/lib").mkdir(parents=True)
    os.symlink("../../usr/lib/sysimage/rpm", tmp_path / "var/lib/rpm")
    assert pr.resolve_under_prefix("/var/lib/rpm", str(tmp_path)) == "/usr/lib/sysimage/rpm"
    assert pr.resolve_under_prefix("/var/./lib/../lib/rpm", str(tmp_path)) == "/usr/lib/sysimage/rpm"


def test_resolve_under_prefix_rejects_symlink_loops(tmp_path) -> None:
    os.symlink("b", tmp_path / "a")
    os.symlink("a", tmp_path / "b")
    with pytest.raises(pr.RpmdbError, match="too many symlinks"):
        pr.resolve_under_prefix("/a", str(tmp_path))


# ---------------------------------------------------------------------------
# Backend detection by magic, and the CLI fallback for bdb / ndb
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("head", "backend"),
    [
        (b"SQLite format 3\0", "sqlite"),
        (b"RpmP\0\0\0\0\x95\0\0\0\x01\0\0\0", "ndb"),  # SLES 15 SP7 Packages.db
        (b"\0" * 12 + b"\x61\x15\x06\x00", "bdb"),  # EL8 Packages, x86_64
        (b"\0" * 12 + b"\x00\x06\x15\x61", "bdb"),  # big-endian writer (s390x)
        (b"\0" * 16, None),
        (b"Rp", None),
    ],
)
def test_backend_by_magic(tmp_path, head: bytes, backend: str | None) -> None:
    f = tmp_path / "db"
    f.write_bytes(head)
    assert pr.rpmdb_backend_by_magic(f) == backend


def test_magic_beats_file_name(host, tmp_path, monkeypatch) -> None:
    # A file named rpmdb.sqlite that is not sqlite is skipped; the real
    # bdb Packages in the same directory is what gets reported.
    host(tmp_path)
    d = tmp_path / "var/lib/rpm"
    d.mkdir(parents=True)
    (d / "rpmdb.sqlite").write_bytes(b"not a database at all")
    (d / "Packages").write_bytes(b"\0" * 12 + b"\x61\x15\x06\x00")
    assert pr.locate_rpmdb() == ("/var/lib/rpm", d, "bdb")


@pytest.mark.parametrize(
    ("db_dir", "fname", "head", "backend"),
    [
        ("var/lib/rpm", "Packages", b"\0" * 12 + b"\x61\x15\x06\x00", "bdb"),
        ("usr/lib/sysimage/rpm", "Packages.db", b"RpmP" + b"\0" * 12, "ndb"),
    ],
)
def test_bdb_and_ndb_use_cli_rooted_at_host(
    host, monkeypatch, tmp_path, db_dir: str, fname: str, head: bytes, backend: str
) -> None:
    host(tmp_path)
    (tmp_path / db_dir).mkdir(parents=True)
    (tmp_path / db_dir / fname).write_bytes(head)
    if db_dir != "var/lib/rpm":
        (tmp_path / "var/lib").mkdir(parents=True)
        os.symlink("../../usr/lib/sysimage/rpm", tmp_path / "var/lib/rpm")
    calls: list[list[str]] = []

    def fake_run(cmd, timeout=None):  # noqa: ARG001
        calls.append(cmd)
        # Newer rpm warns on stderr (merged into stdout by _run) when it
        # reads an older backend; the warning has four fields too.
        return 0, (
            f"warning: Found {backend} Packages database while attempting "
            "sqlite backend: using bdb_ro backend.\n"
            "openssl-libs 1.1.1k 12.el8_9 x86_64\n"
            "gpg-pubkey fd431d51 4ae0493b (none)\n"
        )

    monkeypatch.setattr(pr, "_run", fake_run)
    monkeypatch.setattr(pr.shutil, "which", lambda name: f"/usr/bin/{name}")
    inv = pr.query_rpm_packages()
    assert inv["source"] == "rpm-cli"
    assert inv["backend"] == backend
    assert calls[0][:5] == ["rpm", "--root", str(tmp_path), "--dbpath", f"/{db_dir}"]
    assert calls[0][5:7] == ["-qa", "--queryformat"]
    assert [p["name"] for p in inv["packages"]] == ["openssl-libs", "gpg-pubkey"]
    assert "arch" not in inv["packages"][1]


def test_host_mount_without_rpmdb_never_reads_the_image(host, monkeypatch, tmp_path) -> None:
    host(tmp_path)
    monkeypatch.setattr(pr.shutil, "which", lambda name: f"/usr/bin/{name}")
    inv = pr.query_rpm_packages()
    assert inv["available"] is False
    assert "is the host rpmdb mounted" in inv["reason"]


def test_bare_metal_cli_fallback_has_no_root(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(pr, "HOST_PREFIX", "")
    monkeypatch.setattr(pr, "RPMDB_DIRS", (str(tmp_path / "nothing-here"),))
    monkeypatch.setattr(pr.shutil, "which", lambda name: f"/usr/bin/{name}")
    calls: list[list[str]] = []

    def fake_run(cmd, timeout=None):  # noqa: ARG001
        calls.append(cmd)
        return 0, "bash 5.1.8 9.el9 x86_64\n"

    monkeypatch.setattr(pr, "_run", fake_run)
    pr._query_rpm_packages_cached.cache_clear()
    inv = pr.query_rpm_packages()
    assert inv["source"] == "rpm-cli"
    assert "--root" not in calls[0]
    assert inv["db_root"] is None


def test_missing_sqlite3_module_falls_back_to_cli(host, monkeypatch) -> None:
    host(FIXTURES / "el9")
    monkeypatch.setitem(sys.modules, "sqlite3", None)  # import -> ImportError
    calls: list[list[str]] = []

    def fake_run(cmd, timeout=None):  # noqa: ARG001
        calls.append(cmd)
        return 0, "bash 5.1.8 9.el9 x86_64\n"

    monkeypatch.setattr(pr, "_run", fake_run)
    monkeypatch.setattr(pr.shutil, "which", lambda name: f"/usr/bin/{name}")
    inv = pr.query_rpm_packages()
    assert inv["source"] == "rpm-cli"
    assert calls[0][1:5] == ["--root", str(FIXTURES / "el9"), "--dbpath", "/var/lib/rpm"]


@pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0,
    reason="root ignores directory permissions, so a read-only dir cannot be simulated",
)
def test_wal_db_without_shm_on_readonly_dir_uses_immutable(tmp_path) -> None:
    # Simulates a read-only bind mount of a WAL-mode db whose -shm file
    # does not exist: mode=ro cannot create -shm, immutable=1 can read.
    d = tmp_path / "ro"
    _make_sqlite_db(d / "rpmdb.sqlite", [_header("bash", "5.1.8")])
    con = sqlite3.connect(d / "rpmdb.sqlite")
    con.execute("PRAGMA journal_mode=WAL")
    con.close()
    for extra in ("rpmdb.sqlite-shm", "rpmdb.sqlite-wal"):
        (d / extra).unlink(missing_ok=True)
    d.chmod(0o555)
    try:
        pkgs = pr.read_rpmdb_sqlite(d / "rpmdb.sqlite")
    finally:
        d.chmod(0o755)
    assert [p["name"] for p in pkgs] == ["bash"]


# ---------------------------------------------------------------------------
# Header parser hardening
# ---------------------------------------------------------------------------


def test_parse_rpm_header_reads_synthetic_header() -> None:
    h = pr.parse_rpm_header(_header("nss", "3.112.0", "2.el9", "x86_64"))
    assert h == {"name": "nss", "version": "3.112.0", "release": "2.el9", "arch": "x86_64"}


@pytest.mark.parametrize(
    "blob",
    [
        b"",
        b"\0\0\0",
        struct.pack(">II", 0, 0),  # no index entries
        struct.pack(">II", 0x10000, 0),  # more tags than rpm allows
        _header("nss", "3.112.0")[:-5],  # truncated data store
        # NAME offset points past the data store
        struct.pack(">II", 1, 4) + struct.pack(">IIII", 1000, 6, 99, 1) + b"abc\0",
        # NAME string not NUL-terminated inside the data store
        struct.pack(">II", 1, 3) + struct.pack(">IIII", 1000, 6, 0, 1) + b"abc",
        # int32 EPOCH overrunning the data store
        struct.pack(">II", 1, 2) + struct.pack(">IIII", 1003, 4, 0, 1) + b"\0\0",
        # no NAME / VERSION at all
        struct.pack(">II", 1, 4) + struct.pack(">IIII", 1022, 6, 0, 1) + b"x86\0",
    ],
)
def test_parse_rpm_header_rejects_malformed(blob: bytes) -> None:
    with pytest.raises(pr.RpmdbError):
        pr.parse_rpm_header(blob)


def test_one_corrupt_header_discards_the_whole_direct_read(host, monkeypatch, tmp_path) -> None:
    # A partial inventory would under-report bundled crypto; the reader
    # must fall back to the CLI instead of returning the readable rows.
    host(tmp_path)
    _make_sqlite_db(
        tmp_path / "var/lib/rpm/rpmdb.sqlite",
        [_header("bash", "5.1.8"), _header("openssl-libs", "3.5.8")[:-4]],
    )
    monkeypatch.setattr(pr.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(pr, "_run", lambda cmd, timeout=None: (0, "bash 5.1.8 9.el9 x86_64\n"))
    inv = pr.query_rpm_packages()
    assert inv["source"] == "rpm-cli"


def test_parse_rpm_qa_nvra_skips_diagnostics() -> None:
    out = pr.parse_rpm_qa_nvra(
        "warning: Found bdb_ro Packages database while attempting sqlite backend\n"
        "error: rpmdbNextIterator: skipping h# 7 blob size(0): BAD\n"
        "\n"
        "bash 5.1.8 9.el9 x86_64\n"
        "gpg-pubkey fd431d51 4ae0493b (none)\n"
        "too few\n"
    )
    assert out == [
        {"name": "bash", "version": "5.1.8", "release": "9.el9", "arch": "x86_64"},
        {"name": "gpg-pubkey", "version": "fd431d51", "release": "4ae0493b"},
    ]


def test_direct_read_is_cached_per_prefix(host, monkeypatch) -> None:
    host(FIXTURES / "el9")
    reads: list[Path] = []
    real = pr.read_rpmdb_sqlite
    monkeypatch.setattr(pr, "read_rpmdb_sqlite", lambda p: reads.append(p) or real(p))
    pr.query_rpm_packages()
    pr.query_rpm_packages()
    assert len(reads) == 1


# ---------------------------------------------------------------------------
# Consumers: scan_packages() and detect_nss()
# ---------------------------------------------------------------------------


def test_scan_packages_reads_host_db_without_forking(host) -> None:
    host(FIXTURES / "fedora44")
    out = pr.scan_packages({"family": "rhel"})
    assert out["available"] is True
    assert out["package_manager"] == "rpm"
    assert out["source"] == "rpmdb-sqlite"
    assert out["db_root"] == "/usr/lib/sysimage/rpm"
    assert out["total_packages"] == len(_expected("fedora44"))
    assert "unavailable_in_container" not in out


def test_scan_packages_in_container_without_host_mount_is_annotated(monkeypatch) -> None:
    monkeypatch.setattr(pr, "HOST_PREFIX", "")
    monkeypatch.setattr(pr, "RPMDB_DIRS", (str(FIXTURES / "el9/var/lib/rpm"),))
    monkeypatch.setattr(pr, "_run", _no_subprocess)
    monkeypatch.setattr(
        pr, "detect_runtime_environment", lambda: {"environment": "container"}
    )
    pr._query_rpm_packages_cached.cache_clear()
    out = pr.scan_packages({"family": "rhel"})
    assert out["available"] is True
    assert out["unavailable_in_container"] is True
    assert "rpm database" in out["reason"]


def test_scan_packages_reports_unavailable_reason(host) -> None:
    host(Path("/nonexistent-host-root"))
    out = pr.scan_packages({"family": "suse"})
    assert out["available"] is False
    assert "is the host rpmdb mounted" in out["reason"]


@pytest.mark.parametrize("pkg_name", ["nss", "mozilla-nss"])
def test_detect_nss_under_host_mount_prefers_host_rpmdb(
    host, monkeypatch, tmp_path, pkg_name: str
) -> None:
    host(tmp_path)
    _make_sqlite_db(
        tmp_path / "var/lib/rpm/rpmdb.sqlite",
        [
            _header(pkg_name, "3.101.0", arch="i686"),
            _header(pkg_name, "3.112.0"),
            _header("bash", "5.1.8"),
        ],
    )
    # certutil exists in the image but must not be consulted: it would
    # report the image's NSS, not the host's.
    monkeypatch.setattr(pr.shutil, "which", lambda name: f"/usr/bin/{name}")
    out = pr.detect_nss()
    assert out["tool"] == "rpmdb (sqlite)"
    assert out["version"] == "3.112.0"  # highest of the multi-arch installs
    assert out["pqc_capable"] is True


def test_detect_nss_bare_metal_still_prefers_certutil(monkeypatch) -> None:
    monkeypatch.setattr(pr, "HOST_PREFIX", "")
    monkeypatch.setattr(pr.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(pr, "_run", lambda cmd, timeout=None: (0, "NSS version 3.112.0"))
    monkeypatch.setattr(
        pr, "detect_runtime_environment", lambda: {"environment": "bare-metal"}
    )
    out = pr.detect_nss()
    assert out["tool"] == "certutil --version"


def test_detect_nss_bare_metal_falls_back_to_rpmdb(monkeypatch, tmp_path) -> None:
    _make_sqlite_db(tmp_path / "rpm/rpmdb.sqlite", [_header("nss", "3.90.0")])
    monkeypatch.setattr(pr, "HOST_PREFIX", "")
    monkeypatch.setattr(pr, "RPMDB_DIRS", (str(tmp_path / "rpm"),))
    monkeypatch.setattr(pr.shutil, "which", lambda name: None)
    monkeypatch.setattr(pr, "_run", _no_subprocess)
    monkeypatch.setattr(
        pr, "detect_runtime_environment", lambda: {"environment": "bare-metal"}
    )
    pr._query_rpm_packages_cached.cache_clear()
    out = pr.detect_nss()
    assert out["tool"] == "rpmdb (sqlite)"
    assert out["version"] == "3.90.0"
    assert out["pqc_capable"] is False
