# SPDX-License-Identifier: Apache-2.0
"""In-process Berkeley DB and ndb rpm database readers (#134).

Real fixtures (built with rpm itself inside UBI 8 and openSUSE Leap 16,
see tests/fixtures/rpmdb/README.md) prove the readers match `rpm -qa`;
synthetic builders cover what the real files can't: big-endian (s390x)
Berkeley DB, inline header values, multi-page overflow chains, free ndb
slots, and every corruption the readers must reject rather than return a
partial inventory for.
"""

from __future__ import annotations

import gzip
import os
import struct
import zlib
from pathlib import Path

import pytest
import shutil

import pqc_readiness as pr

FIXTURES = Path(__file__).parent / "fixtures" / "rpmdb"


def _no_subprocess(cmd, timeout=None):  # noqa: ARG001
    raise AssertionError(f"unexpected subprocess: {cmd}")


@pytest.fixture
def host(monkeypatch):
    def _use(root: Path) -> Path:
        monkeypatch.setattr(pr._platform, "HOST_PREFIX", str(root))
        monkeypatch.setattr(pr._platform, "_run", _no_subprocess)
        pr.detect.packages._query_rpm_packages_cached.cache_clear()
        return root

    yield _use
    pr.detect.packages._query_rpm_packages_cached.cache_clear()


def _header(name: str, version: str, release: str = "1", arch: str = "x86_64") -> bytes:
    """Minimal valid rpm header blob (no magic, as rpmdb stores it)."""
    entries = [(1000, name), (1001, version), (1002, release), (1022, arch)]
    index, data = b"", b""
    for tag, value in entries:
        index += struct.pack(">IIII", tag, 6, len(data), 1)
        data += value.encode() + b"\0"
    return struct.pack(">II", len(entries), len(data)) + index + data


def _qa_lines(pkgs: list[dict]) -> list[str]:
    return sorted(
        f"{p['name']} {p['version']} {p.get('release', '')} {p.get('arch', '(none)')}"
        for p in pkgs
    )


def _expected(layout: str) -> list[str]:
    text = (FIXTURES / layout / "expected-rpm-qa.txt").read_text()
    return sorted(line for line in text.splitlines() if line)


def _el8_host(root: Path) -> Path:
    db = root / "var/lib/rpm/Packages"
    db.parent.mkdir(parents=True)
    db.write_bytes(gzip.decompress((FIXTURES / "el8-bdb/Packages.gz").read_bytes()))
    return db


def _suse_host(root: Path) -> Path:
    # SUSE layout: /var/lib/rpm is a relative symlink to sysimage.
    db = root / "usr/lib/sysimage/rpm/Packages.db"
    db.parent.mkdir(parents=True)
    db.write_bytes(gzip.decompress((FIXTURES / "suse-ndb/Packages.db.gz").read_bytes()))
    (root / "var/lib").mkdir(parents=True)
    os.symlink("../../usr/lib/sysimage/rpm", root / "var/lib/rpm")
    return db


# ---------------------------------------------------------------------------
# Synthetic builders
# ---------------------------------------------------------------------------


def build_bdb(
    blobs: list[bytes], bo: str = "<", pagesize: int = 512, inline_max: int = 200
) -> bytes:
    """A Berkeley DB hash file holding rpm's record 0 plus one record per
    blob (key = header number).  Blobs up to `inline_max` bytes are stored
    on the bucket page; larger ones go to a chain of overflow pages."""
    pages: dict[int, bytearray] = {}
    next_free = 2  # page 0 = meta, page 1 = the single bucket page

    def new_page(pgno: int, ptype: int) -> bytearray:
        pg = bytearray(pagesize)
        struct.pack_into(bo + "I", pg, 8, pgno)
        pg[25] = ptype
        pages[pgno] = pg
        return pg

    def overflow_chain(data: bytes) -> int:
        nonlocal next_free
        room = pagesize - 26
        chunks = [data[i : i + room] for i in range(0, len(data), room)]
        first = next_free
        for i, chunk in enumerate(chunks):
            pgno = next_free
            next_free += 1
            pg = new_page(pgno, 7)
            nxt = pgno + 1 if i + 1 < len(chunks) else 0
            struct.pack_into(bo + "I", pg, 16, nxt)
            struct.pack_into(bo + "H", pg, 22, len(chunk))
            pg[26 : 26 + len(chunk)] = chunk
        return first

    items: list[bytes] = []
    records = [(0, struct.pack(bo + "I", len(blobs)))] + list(enumerate(blobs, 1))
    for hnum, value in records:
        items.append(b"\x01" + struct.pack(bo + "I", hnum))
        if len(value) <= inline_max:
            items.append(b"\x01" + value)
        else:
            items.append(
                b"\x03\0\0\0"
                + struct.pack(bo + "II", overflow_chain(value), len(value))
            )
    bucket = new_page(1, 13)
    struct.pack_into(bo + "H", bucket, 20, len(items))
    off = pagesize
    for i, it in enumerate(items):
        off -= len(it)
        assert off > 26 + 2 * len(items), "bucket page too small for synthetic items"
        bucket[off : off + len(it)] = it
        struct.pack_into(bo + "H", bucket, 26 + 2 * i, off)
    meta = bytearray(pagesize)
    struct.pack_into(bo + "I", meta, 12, 0x00061561)
    struct.pack_into(bo + "II", meta, 16, 9, pagesize)
    struct.pack_into(bo + "I", meta, 32, next_free - 1)  # last page
    struct.pack_into(bo + "I", meta, 72, 0)  # max bucket
    struct.pack_into(bo + "32I", meta, 96, 1, *([0] * 31))  # bucket 0 -> page 1
    return bytes(meta) + b"".join(bytes(pages[n]) for n in range(1, next_free))


def build_ndb(blobs: list[bytes], free_slots_first: int = 1) -> bytes:
    """An ndb Packages.db: header, one slot page (with some free slots),
    then one blob region per package with head, data, tail and Adler-32."""
    slots = bytearray(4096)
    struct.pack_into("<4sIII", slots, 0, b"RpmP", 0, 1, 1)
    regions = b""
    blkoff = 4096 // 16
    slotno = 2
    for _ in range(free_slots_first):
        struct.pack_into("<4sIII", slots, slotno * 16, b"Slot", 0, 0, 0)
        slotno += 1
    for pkgidx, blob in enumerate(blobs, 1):
        blkcnt = -(-(16 + len(blob) + 12) // 16)
        region = bytearray(blkcnt * 16)
        struct.pack_into("<4sIII", region, 0, b"BlbS", pkgidx, 1, len(blob))
        region[16 : 16 + len(blob)] = blob
        adl = zlib.adler32(bytes(region[:-12]))
        struct.pack_into("<II4s", region, len(region) - 12, adl, len(blob), b"BlbE")
        struct.pack_into("<4sIII", slots, slotno * 16, b"Slot", pkgidx, blkoff, blkcnt)
        slotno += 1
        blkoff += blkcnt
        regions += bytes(region)
    while slotno < 4096 // 16:
        struct.pack_into("<4sIII", slots, slotno * 16, b"Slot", 0, 0, 0)
        slotno += 1
    return bytes(slots) + regions


PKGS = [
    _header("nss", "3.112.0"),
    _header("bash", "5.1.8", release="9.el8"),
    _header("bigpkg", "1.0", release="1" * 900),  # forces a multi-page overflow chain
]


def _write(tmp_path: Path, name: str, data: bytes) -> Path:
    p = tmp_path / name
    p.write_bytes(data)
    return p


# ---------------------------------------------------------------------------
# Real databases built by rpm itself
# ---------------------------------------------------------------------------


def test_el8_bdb_fixture_matches_rpm_qa_without_rpm(host, tmp_path) -> None:
    _el8_host(host(tmp_path))
    inv = pr.query_rpm_packages()
    assert (inv["source"], inv["backend"], inv["db_root"]) == (
        "rpmdb-bdb",
        "bdb",
        "/var/lib/rpm",
    )
    assert _qa_lines(inv["packages"]) == _expected("el8-bdb")


def test_suse_ndb_fixture_matches_rpm_qa_without_rpm(host, tmp_path) -> None:
    _suse_host(host(tmp_path))
    inv = pr.query_rpm_packages()
    assert (inv["source"], inv["backend"]) == ("rpmdb-ndb", "ndb")
    assert inv["db_root"] == "/usr/lib/sysimage/rpm"
    assert _qa_lines(inv["packages"]) == _expected("suse-ndb")


@pytest.mark.parametrize(
    ("make_host", "tool", "version"),
    [(_el8_host, "rpmdb (bdb)", "3.124.0"), (_suse_host, "rpmdb (ndb)", "3.125.0")],
)
def test_detect_nss_reads_bdb_and_ndb_in_process(
    host, monkeypatch, tmp_path, make_host, tool, version
) -> None:
    make_host(host(tmp_path))
    # No usable rpm binary: the host database is read in-process and no
    # subprocess may run (certutil would describe the scanner image).
    monkeypatch.setattr(
        shutil, "which", lambda name: None if name == "rpm" else f"/usr/bin/{name}"
    )
    out = pr.detect_nss()
    assert out["tool"] == tool
    assert out["version"] == version
    assert out["pqc_capable"] is True


@pytest.mark.parametrize("make_host", [_el8_host, _suse_host])
def test_named_lookup_on_bdb_and_ndb_without_rpm_is_in_process(
    host, monkeypatch, tmp_path, make_host
) -> None:
    make_host(host(tmp_path))
    monkeypatch.setattr(shutil, "which", lambda name: None)
    out = pr.query_rpm_named(("libgpg-error", "libgpg-error0"))
    assert out["source"].startswith("rpmdb-")
    assert [p["name"] for p in out["packages"]] in (["libgpg-error"], ["libgpg-error0"])


# ---------------------------------------------------------------------------
# Synthetic: byte order, inline values, overflow chains, free slots
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bo", ["<", ">"])
def test_bdb_both_byte_orders(tmp_path, bo: str) -> None:
    db = _write(tmp_path, "Packages", build_bdb(PKGS, bo=bo))
    assert pr.rpmdb_backend_by_magic(db) == "bdb"
    got = pr.read_rpmdb_blobs("bdb", db)
    assert sorted(p["name"] for p in got) == ["bash", "bigpkg", "nss"]


def test_bdb_named_lookup_filters_exactly(tmp_path) -> None:
    db = _write(tmp_path, "Packages", build_bdb(PKGS))
    got = pr.read_rpmdb_blobs("bdb", db, ("nss", "mozilla-nss"))
    assert [(p["name"], p["version"]) for p in got] == [("nss", "3.112.0")]


def test_ndb_synthetic_with_free_slots(tmp_path) -> None:
    db = _write(tmp_path, "Packages.db", build_ndb(PKGS, free_slots_first=3))
    assert pr.rpmdb_backend_by_magic(db) == "ndb"
    assert sorted(p["name"] for p in pr.read_rpmdb_blobs("ndb", db)) == [
        "bash",
        "bigpkg",
        "nss",
    ]


@pytest.mark.parametrize(
    ("backend", "builder", "name"),
    [("bdb", build_bdb, "Packages"), ("ndb", build_ndb, "Packages.db")],
)
def test_database_without_packages_is_invalid(tmp_path, backend, builder, name) -> None:
    db = _write(tmp_path, name, builder([]))
    with pytest.raises(pr.RpmdbError, match="0 packages"):
        pr.read_rpmdb_blobs(backend, db)


# ---------------------------------------------------------------------------
# Corruption: always RpmdbError, never a partial inventory
# ---------------------------------------------------------------------------


def _bdb_corruptions() -> dict[str, bytes]:
    good = build_bdb(PKGS)
    ps = 512
    out: dict[str, bytes] = {}
    out["truncated"] = good[: len(good) - ps]
    bad = bytearray(good)
    struct.pack_into("<I", bad, 16, 7)  # hash version
    out["version"] = bytes(bad)
    bad = bytearray(good)
    struct.pack_into("<I", bad, 20, 1000)  # page size not a power of two
    out["pagesize"] = bytes(bad)
    bad = bytearray(good)
    struct.pack_into("<I", bad, ps + 8, 9)  # bucket page claims another number
    out["pageno"] = bytes(bad)
    # First overflow page (page 2) points back at itself: a loop.
    bad = bytearray(good)
    struct.pack_into("<I", bad, 2 * ps + 16, 2)
    out["overflow-loop"] = bytes(bad)
    bad = bytearray(good)
    bad[ps + 25] = 5  # bucket page is no longer a hash page
    out["page-type"] = bytes(bad)
    bad = bytearray(good)
    struct.pack_into("<H", bad, ps + 20, 1000)  # entry count past the page
    out["entries"] = bytes(bad)
    return out


@pytest.mark.parametrize("case", sorted(_bdb_corruptions()))
def test_corrupt_bdb_raises(tmp_path, case: str) -> None:
    db = _write(tmp_path, "Packages", _bdb_corruptions()[case])
    with pytest.raises(pr.RpmdbError):
        pr.read_rpmdb_blobs("bdb", db)


def _ndb_corruptions() -> dict[str, bytes]:
    good = build_ndb(PKGS)
    out: dict[str, bytes] = {}
    out["truncated"] = good[:-32]
    bad = bytearray(good)
    struct.pack_into("<I", bad, 4, 1)  # version
    out["version"] = bytes(bad)
    first_used = 3 * 16  # build_ndb leaves one free slot at slot 2
    bad = bytearray(good)
    struct.pack_into("<I", bad, first_used + 8, 0xFFFFFF)  # blob past EOF
    out["slot-past-eof"] = bytes(bad)
    bad = bytearray(good)
    bad[first_used : first_used + 4] = b"Xlot"
    out["slot-magic"] = bytes(bad)
    blob0 = 4096
    bad = bytearray(good)
    bad[blob0 : blob0 + 4] = b"XlbS"
    out["blob-magic"] = bytes(bad)
    bad = bytearray(good)
    bad[blob0 + 20] ^= 0xFF  # flip a data byte: Adler-32 mismatch
    out["checksum"] = bytes(bad)
    return out


@pytest.mark.parametrize("case", sorted(_ndb_corruptions()))
def test_corrupt_ndb_raises(tmp_path, case: str) -> None:
    db = _write(tmp_path, "Packages.db", _ndb_corruptions()[case])
    with pytest.raises(pr.RpmdbError):
        pr.read_rpmdb_blobs("ndb", db)


def test_corruption_late_in_file_discards_everything(tmp_path) -> None:
    # The last package's blob is damaged; earlier ones are fine.  The
    # reader must not hand back the first packages as if complete.
    good = bytearray(build_ndb(PKGS))
    good[-20] ^= 0xFF
    db = _write(tmp_path, "Packages.db", bytes(good))
    with pytest.raises(pr.RpmdbError):
        pr.read_rpmdb_blobs("ndb", db)


@pytest.mark.parametrize(
    ("name", "data"),
    [
        ("Packages", _bdb_corruptions()["overflow-loop"]),
        ("Packages.db", _ndb_corruptions()["checksum"]),
    ],
)
def test_unreadable_database_falls_back_to_rpm_cli(
    host, monkeypatch, tmp_path, name, data
) -> None:
    root = host(tmp_path)
    (root / "var/lib/rpm").mkdir(parents=True)
    (root / "var/lib/rpm" / name).write_bytes(data)
    calls: list[list[str]] = []

    def fake_run(cmd, timeout=None):  # noqa: ARG001
        calls.append(cmd)
        return 0, "bash 5.1.8 9.el8 x86_64\n"

    monkeypatch.setattr(pr._platform, "_run", fake_run)
    monkeypatch.setattr(shutil, "which", lambda n: f"/usr/bin/{n}")
    inv = pr.query_rpm_packages()
    assert inv["source"] == "rpm-cli"
    assert calls[0][:5] == ["rpm", "--root", str(root), "--dbpath", "/var/lib/rpm"]


def test_nss_tool_label_on_cli_fallback_is_rpm_q(host, monkeypatch, tmp_path) -> None:
    # Since #129 the CLI path runs `rpm -q <names>`; the label must say so
    # (an AlmaLinux 8.10 VM reported the stale "rpm -qa").
    root = host(tmp_path)
    (root / "var/lib/rpm").mkdir(parents=True)
    (root / "var/lib/rpm/Packages").write_bytes(_bdb_corruptions()["overflow-loop"])
    calls: list[list[str]] = []

    def fake_run(cmd, timeout=None):  # noqa: ARG001
        calls.append(cmd)
        return 1, "nss 3.124.0 5.el8_10 x86_64\npackage mozilla-nss is not installed\n"

    monkeypatch.setattr(pr._platform, "_run", fake_run)
    monkeypatch.setattr(shutil, "which", lambda n: f"/usr/bin/{n}")
    out = pr.detect_nss()
    assert out["tool"] == "rpm -q"
    assert out["version"] == "3.124.0"
    assert "-q" in calls[0] and "-qa" not in calls[0]


@pytest.mark.parametrize(
    ("source", "label"),
    [
        ("rpmdb-sqlite", "rpmdb (sqlite)"),
        ("rpmdb-bdb", "rpmdb (bdb)"),
        ("rpmdb-ndb", "rpmdb (ndb)"),
        ("rpm-cli", "rpm -q"),
    ],
)
def test_nss_tool_label_matches_packages_source(monkeypatch, source, label) -> None:
    monkeypatch.setattr(
        pr.detect.packages,
        "query_rpm_named",
        lambda names: {
            "available": True,
            "source": source,
            "packages": [{"name": "nss", "version": "3.112.0"}],
        },
    )
    assert pr.detect.protocols._nss_from_rpmdb()["tool"] == label


@pytest.mark.parametrize("make_host", [_el8_host, _suse_host])
def test_named_lookup_on_bdb_and_ndb_prefers_rpm_q(
    host, monkeypatch, tmp_path, make_host
) -> None:
    # BDB / ndb have no index we read: a direct named lookup walks the whole
    # database (10-60 ms measured on EL8 / SUSE VMs) while `rpm -q` uses
    # rpm's index (~4 ms).  With rpm available, one `rpm -q` runs, pointed
    # at the host.
    make_host(host(tmp_path))
    calls: list[list[str]] = []

    def fake_run(cmd, timeout=None):  # noqa: ARG001
        calls.append(cmd)
        return 0, "nss 3.124.0 1.el8 x86_64\n"

    monkeypatch.setattr(pr._platform, "_run", fake_run)
    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")
    out = pr.query_rpm_named(("nss",))
    assert out["source"] == "rpm-cli"
    assert [p["version"] for p in out["packages"]] == ["3.124.0"]
    (cmd,) = calls
    assert cmd[:3] == ["rpm", "--root", str(tmp_path)]
    assert "-q" in cmd and "-qa" not in cmd


@pytest.mark.parametrize("make_host", [_el8_host, _suse_host])
def test_named_lookup_falls_back_to_direct_read_when_rpm_q_fails(
    host, monkeypatch, tmp_path, make_host
) -> None:
    make_host(host(tmp_path))
    monkeypatch.setattr(
        pr._platform,
        "_run",
        lambda cmd, timeout=None: (1, "error: cannot open Packages index"),
    )
    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")
    out = pr.query_rpm_named(("libgpg-error", "libgpg-error0"))
    assert out["source"].startswith("rpmdb-")
    assert len(out["packages"]) == 1
