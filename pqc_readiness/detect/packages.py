"""Package inventory (--scan-packages): rpm database readers (sqlite, Berkeley DB, ndb), dpkg/pacman/apk."""

from __future__ import annotations

import argparse
import functools
import logging
import os
import re
import shutil
import struct
from pathlib import Path
from typing import Any, Callable, Iterator

from .. import _platform as _platform
from ..detect import osinfo as _osinfo
from ..detect import runtime as _runtime
from .. import registry as _registry

log = logging.getLogger("pqc-readiness")


# ---------------------------------------------------------------------------
# Bundled-crypto package inventory (--scan-packages)
# ---------------------------------------------------------------------------

# Per-family regex catalogues for runtimes and applications that bundle
# their own crypto implementation rather than relying solely on system
# OpenSSL.  Each entry: (compiled regex matched against the package
# name, hint string surfaced in the report).  Per-family because package
# names diverge sharply: RHEL `java-21-openjdk` vs Debian `openjdk-21-jdk`
# vs SUSE `java-21-openjdk` vs Arch `jdk-openjdk` vs Alpine `openjdk21`.
BUNDLED_CRYPTO_BY_FAMILY: dict[str, list[tuple[str, str]]] = {
    "rhel": [
        (
            r"^java-\d+(\.\d+\.\d+)?-openjdk(-headless|-devel)?$",
            "Java JCE provider (SunJCE / Bouncy Castle)",
        ),
        (r"^bouncycastle", "Bouncy Castle (separate provider)"),
        (
            r"^(golang|go)(-bin)?$",
            "Go runtime (crypto/tls embedded; GODEBUG=fips140=on for FIPS)",
        ),
        (
            r"^nodejs$",
            "Node.js (bundled OpenSSL build; --openssl-config controls FIPS)",
        ),
        (r"^(rust|cargo|rustc)$", "Rust toolchain (rustls embeds ring or openssl-sys)"),
        (r"^firefox$", "Firefox (embeds NSS — separate PQC roadmap)"),
        (r"^thunderbird$", "Thunderbird (embeds NSS)"),
        (r"^chromium$", "Chromium (embeds BoringSSL)"),
        (r"^python3$", "Python ssl module (links system OpenSSL)"),
    ],
    "debian": [
        (
            r"^openjdk-\d+-(jdk|jre)(-headless)?$",
            "Java JCE provider (SunJCE / Bouncy Castle)",
        ),
        (r"^libbcprov-java$", "Bouncy Castle Java library"),
        (r"^golang-(go|\d+(\.\d+)?-go)$", "Go runtime (crypto/tls embedded)"),
        (r"^nodejs$", "Node.js (bundled OpenSSL build)"),
        (r"^(rustc|cargo)$", "Rust toolchain (rustls embeds ring or openssl-sys)"),
        (r"^firefox(-esr)?$", "Firefox (embeds NSS)"),
        (r"^thunderbird$", "Thunderbird (embeds NSS)"),
        (r"^chromium$", "Chromium (embeds BoringSSL)"),
        (r"^python3$", "Python ssl module (links system OpenSSL)"),
    ],
    "suse": [
        (r"^java-\d+(\.\d+\.\d+)?-openjdk(-headless|-devel)?$", "Java JCE provider"),
        (r"^go(1\.\d+)?$", "Go runtime"),
        (r"^nodejs(\d+)?$", "Node.js"),
        (r"^(rust|cargo)$", "Rust toolchain"),
        (r"^MozillaFirefox$", "Firefox (embeds NSS)"),
        (r"^MozillaThunderbird$", "Thunderbird (embeds NSS)"),
        (r"^chromium$", "Chromium (embeds BoringSSL)"),
        (r"^python3$", "Python ssl module"),
    ],
    "arch": [
        (r"^jdk\d+-openjdk$", "Java JCE provider"),
        (r"^go$", "Go runtime"),
        (r"^nodejs$", "Node.js"),
        (r"^rust$", "Rust toolchain"),
        (r"^firefox$", "Firefox (embeds NSS)"),
        (r"^thunderbird$", "Thunderbird"),
        (r"^chromium$", "Chromium"),
        (r"^python$", "Python"),
    ],
    "alpine": [
        (r"^openjdk\d+(-jdk|-jre)?$", "Java JCE provider"),
        (r"^go$", "Go runtime"),
        (r"^nodejs$", "Node.js"),
        (r"^rust$", "Rust toolchain"),
        (r"^firefox$", "Firefox"),
        (r"^chromium$", "Chromium"),
        (r"^python3$", "Python"),
    ],
}


def parse_whitespace_pkg_lines(text: str) -> list[dict[str, str]]:
    """Parse `name version` per line into [{"name", "version"}, ...].

    Used for rpm (`rpm -qa --queryformat '%{NAME} %{VERSION}\\n'`),
    dpkg (`dpkg-query -W -f='${Package} ${Version}\\n'`), and pacman
    (`pacman -Q`) — all three emit the same two-token-per-line format.
    Apk does not (see `parse_apk_packages` below)."""
    out: list[dict[str, str]] = []
    for line in text.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2:
            out.append({"name": parts[0], "version": parts[1]})
    return out


def parse_apk_packages(text: str) -> list[dict[str, str]]:
    """Parse `apk info -v` output.  Each line is `name-VERSION-rRELEASE`
    (e.g. `openssl-3.5.5-r0`).  We split on the LAST hyphen-followed-by-
    digits which is robustly the version boundary."""
    out: list[dict[str, str]] = []
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        # Walk back from the end: the version+release suffix is two
        # hyphen-separated segments at the tail (`<ver>-r<rel>`).
        m = re.match(r"^(.+)-(\d[^-]*-r\d+)$", s)
        if not m:
            # Fallback: single trailing version segment.
            m = re.match(r"^(.+)-(\d[^-]*)$", s)
            if not m:
                continue
        out.append({"name": m.group(1), "version": m.group(2)})
    return out


def classify_bundled_crypto(
    pkgs: list[dict[str, str]], family: str
) -> list[dict[str, str]]:
    """Match each installed package against the family's bundled-crypto
    regex catalogue.  First-match wins per package (so a package can
    appear in only one row even if multiple regexes match).  De-dupes on
    package name across multi-arch installs (i686 + x86_64)."""
    patterns = [
        (re.compile(p), hint) for p, hint in BUNDLED_CRYPTO_BY_FAMILY.get(family, [])
    ]
    seen: set[str] = set()
    out: list[dict[str, str]] = []
    for entry in pkgs:
        name = entry["name"]
        if name in seen:
            continue
        for pat, hint in patterns:
            if pat.match(name):
                seen.add(name)
                out.append({"package": name, "version": entry["version"], "note": hint})
                break
    return out


# ---------------------------------------------------------------------------
# Direct RPM database reader (#125)
# ---------------------------------------------------------------------------
#
# Reading rpmdb.sqlite in-process replaces the `rpm -qa` fork (the single
# most expensive call in a --scan-packages run) and, more importantly,
# lets --host-mount read the *host's* database: `rpm -qa` inside the
# DaemonSet/quadlet image would inventory the image instead.
#
# Database directories, checked in order.  Measured 2026-10-13 across 19
# distro images (matrix on #125): /var/lib/rpm exists everywhere, as the
# real directory on EL8/EL9/Oracle Linux 9/Amazon Linux 2023 and as a
# relative symlink to /usr/lib/sysimage/rpm on EL10, Fedora and SUSE.  It
# must be checked first: Oracle Linux 9 ships a stray, empty
# /usr/lib/sysimage/rpm/rpmdb.sqlite next to the live /var/lib/rpm db.
# /usr/share/rpm is the rpm-ostree location (RHCOS / Fedora CoreOS); not
# verified on hardware.
RPMDB_DIRS: tuple[str, ...] = (
    "/var/lib/rpm",
    "/usr/lib/sysimage/rpm",
    "/usr/share/rpm",
)


# Database files probed inside each directory.  The backend is decided
# by file magic, never by file name or distro version: hosts upgraded in
# place can keep an older format.
_RPMDB_FILES: tuple[str, ...] = ("rpmdb.sqlite", "Packages.db", "Packages")


_SQLITE_MAGIC = b"SQLite format 3\0"


_NDB_MAGIC = b"RpmP"


# Berkeley DB hash magic 0x00061561 at offset 12, in the writer's byte
# order (little-endian on x86_64/aarch64, big-endian on s390x).
_BDB_HASH_MAGICS = (b"\x00\x06\x15\x61", b"\x61\x15\x06\x00")


# Header tags we read (rpmtag.h) and the data types they use.
_RPMTAG_NAMES: dict[int, str] = {
    1000: "name",
    1001: "version",
    1002: "release",
    1003: "epoch",
    1022: "arch",
}


_RPM_TYPE_INT32 = 4


_RPM_TYPE_STRING = 6


_RPM_TYPE_I18NSTRING = 9


# Sanity limits mirroring rpm's own (HEADER_TAGS_MAX / HEADER_DATA_MAX):
# a blob claiming more is corrupt, not merely large.
_RPM_HEADER_MAX_TAGS = 0x0000FFFF


_RPM_HEADER_MAX_DATA = 0x0FFFFFFF


class RpmdbError(Exception):
    """The rpm database could not be read in-process; callers fall back."""


def parse_rpm_header(blob: bytes) -> dict[str, Any]:
    """Extract name/version/release/epoch/arch from an rpmdb header blob.

    rpmdb stores headers without the 8-byte magic: big-endian `il`
    (index entry count) and `dl` (data length), then `il` 16-byte entries
    `{tag, type, offset, count}`, then `dl` bytes of data.  Every offset is
    bounds-checked; anything inconsistent raises RpmdbError so the caller
    can discard the whole read rather than emit a partial inventory."""
    if len(blob) < 8:
        raise RpmdbError("header blob shorter than its preamble")
    il, dl = struct.unpack_from(">II", blob, 0)
    if not 0 < il <= _RPM_HEADER_MAX_TAGS or dl > _RPM_HEADER_MAX_DATA:
        raise RpmdbError(f"implausible header sizes il={il} dl={dl}")
    base = 8 + 16 * il
    if base + dl > len(blob):
        raise RpmdbError("header blob truncated")
    out: dict[str, Any] = {}
    # iter_unpack walks the whole index in C; ~1.5x faster than one
    # unpack_from per entry on a full inventory (#128).
    for tag, typ, off, _count in struct.iter_unpack(">IIII", blob[8:base]):
        key = _RPMTAG_NAMES.get(tag)
        if key is None:
            continue
        if off >= dl:
            raise RpmdbError(f"tag {tag} offset {off} outside data ({dl})")
        start = base + off
        if typ in (_RPM_TYPE_STRING, _RPM_TYPE_I18NSTRING):
            end = blob.find(b"\0", start, base + dl)
            if end < 0:
                raise RpmdbError(f"tag {tag} string not terminated")
            out[key] = blob[start:end].decode("utf-8", "replace")
        elif typ == _RPM_TYPE_INT32:
            if off + 4 > dl:
                raise RpmdbError(f"tag {tag} int32 overruns data")
            out[key] = struct.unpack_from(">I", blob, start)[0]
    if "name" not in out or "version" not in out:
        raise RpmdbError("header has no NAME/VERSION")
    return out


def rpmdb_backend_by_magic(path: Path) -> str | None:
    """Return "sqlite", "ndb" or "bdb" from a database file's magic bytes,
    or None when the file is unreadable or unrecognised."""
    try:
        with path.open("rb") as fh:
            head = fh.read(16)
    except OSError as e:
        log.debug("rpmdb: cannot read %s: %s", path, e)
        return None
    if head.startswith(_SQLITE_MAGIC):
        return "sqlite"
    if head.startswith(_NDB_MAGIC):
        return "ndb"
    if len(head) >= 16 and head[12:16] in _BDB_HASH_MAGICS:
        return "bdb"
    return None


def resolve_under_prefix(path: str, prefix: str, max_links: int = 40) -> str:
    """Resolve symlinks in host path `path` as the host would, reading
    each component under `prefix` and re-rooting absolute link targets
    under it too, so a host symlink is never followed into the scanner
    container's own filesystem.  Returns the resolved host-relative path.
    With an empty prefix this is plain symlink resolution."""
    pending = [c for c in path.split("/") if c]
    done: list[str] = []
    links = 0
    while pending:
        part = pending.pop(0)
        if part == ".":
            continue
        if part == "..":
            if done:
                done.pop()
            continue
        candidate = prefix + "/" + "/".join([*done, part])
        if os.path.islink(candidate):
            links += 1
            if links > max_links:
                raise RpmdbError(f"too many symlinks resolving {path}")
            target = os.readlink(candidate)
            if target.startswith("/"):
                done = []
            pending = [c for c in target.split("/") if c] + pending
            continue
        done.append(part)
    return "/" + "/".join(done)


def locate_rpmdb() -> tuple[str, Path, str] | None:
    """Find the host rpm database.  Returns (host-relative directory, the
    directory as seen by this process, backend) for the first directory in
    RPMDB_DIRS holding a database file whose magic identifies a backend.
    Under --host-mount every path is resolved under HOST_PREFIX."""
    seen: set[str] = set()
    for d in RPMDB_DIRS:
        try:
            host_dir = resolve_under_prefix(d, _platform.HOST_PREFIX)
        except RpmdbError as e:
            log.debug("rpmdb: %s", e)
            continue
        if host_dir in seen:
            continue
        seen.add(host_dir)
        local_dir = Path(_platform.HOST_PREFIX + host_dir)
        for fname in _RPMDB_FILES:
            f = local_dir / fname
            if not f.is_file():
                continue
            backend = rpmdb_backend_by_magic(f)
            if backend is not None:
                return host_dir, local_dir, backend
            log.debug("rpmdb: %s has no recognised magic; skipping", f)
    return None


def _fetch_rpmdb_sqlite(
    db_file: Path, sql: str, params: tuple[str, ...] = ()
) -> list[bytes]:
    """Run one read-only blob query against an rpmdb.sqlite file.

    A read-only bind mount of a WAL-mode database cannot open with mode=ro
    when the -shm file is missing, so retry with immutable=1 in that case
    only (verified with a ro podman mount).  An empty Packages table is
    never a real install (Oracle Linux 9 ships a stray empty rpmdb.sqlite)
    and is rejected even when the query itself legitimately matches
    nothing.  Raises RpmdbError on any failure."""
    try:
        import sqlite3
    except ImportError as e:  # minimal Python builds can lack _sqlite3
        raise RpmdbError(f"sqlite3 module unavailable: {e}") from e
    from urllib.parse import quote

    uri_path = quote(str(db_file))
    last_err: Exception | None = None
    for uri_params in ("mode=ro", "mode=ro&immutable=1"):
        try:
            con = sqlite3.connect(f"file:{uri_path}?{uri_params}", uri=True, timeout=2)
        except sqlite3.Error as e:
            last_err = e
            log.debug("rpmdb: open %s (%s) failed: %s", db_file, uri_params, e)
            continue
        try:
            if con.execute("SELECT EXISTS(SELECT 1 FROM Packages)").fetchone()[0] == 0:
                raise RpmdbError(f"{db_file} holds 0 packages; treating as invalid")
            return [bytes(blob) for (blob,) in con.execute(sql, params).fetchall()]
        except sqlite3.Error as e:
            last_err = e
            log.debug("rpmdb: query %s (%s) failed: %s", db_file, uri_params, e)
            continue
        finally:
            con.close()
    raise RpmdbError(f"cannot read {db_file}: {last_err}")


def read_rpmdb_sqlite(db_file: Path) -> list[dict[str, Any]]:
    """Read every installed package header from an rpmdb.sqlite file.
    Raises RpmdbError on any failure; never returns a partial list."""
    blobs = _fetch_rpmdb_sqlite(db_file, "SELECT blob FROM Packages")
    return [parse_rpm_header(blob) for blob in blobs]


def read_rpmdb_sqlite_named(
    db_file: Path, names: tuple[str, ...]
) -> list[dict[str, Any]]:
    """Read only the headers of packages called `names`, through rpm's own
    Name index table: a fraction of a millisecond, versus reading and
    parsing every header (#128).  Raises RpmdbError (e.g. no Name table)
    so callers can fall back to the full read."""
    marks = ",".join("?" * len(names))
    blobs = _fetch_rpmdb_sqlite(
        db_file,
        f"SELECT blob FROM Packages WHERE hnum IN "
        f"(SELECT hnum FROM Name WHERE key IN ({marks}))",
        names,
    )
    return [parse_rpm_header(blob) for blob in blobs]


# ---------------------------------------------------------------------------
# Berkeley DB (EL8, Leap 15 cloud images) and ndb (SUSE) readers (#134)
# ---------------------------------------------------------------------------
#
# Both formats are read with positional reads (os.pread), never mmap: if
# rpm truncates or compacts the file while we read it, an mmap access past
# the new end of file raises SIGBUS and kills the whole scanner, whereas a
# short pread is just treated as corruption and falls back to the CLI.
# Layouts follow rpm's own read-only implementations, lib/backend/bdb_ro.cc
# and lib/backend/ndb/rpmpkg.c (rpm-software-management/rpm).

_BDB_HASH_MAGIC = 0x00061561


_BDB_PAGE_TYPES_HASH = (2, 13)  # P_HASH_UNSORTED, P_HASH


_BDB_PAGE_OVERFLOW = 7


_BDB_ITEM_KEYDATA = 1


_BDB_ITEM_OFFPAGE = 3


_BDB_PAGE_HEADER = 26


_NDB_PAGE = 4096


_NDB_SLOT = 16


_NDB_BLK = 16


_NDB_HEADER = 32  # first two slots hold the file header


_NDB_BLOBHEAD = 16


_NDB_BLOBTAIL = 12


_NDB_MAX_SLOTNPAGES = 0xFFFFFFFF // (_NDB_PAGE // _NDB_BLK)


def _pread_exact(fd: int, length: int, offset: int) -> bytes:
    data = os.pread(fd, length, offset)
    if len(data) != length:
        raise RpmdbError(f"short read: {len(data)} of {length} bytes at {offset}")
    return data


def _iter_bdb_hash_values(fd: int, size: int) -> Iterator[bytes]:
    """Yield every Packages value (an rpm header blob) from a Berkeley DB
    hash file.  Walks buckets and their next-page chains exactly as rpm's
    bdb_ro does, rather than scanning pages by type, so freed pages that
    still carry a hash type are never read.  Raises RpmdbError on any
    inconsistency."""
    meta = _pread_exact(fd, 512, 0)
    for bo in ("<", ">"):
        if struct.unpack_from(bo + "I", meta, 12)[0] == _BDB_HASH_MAGIC:
            break
    else:
        raise RpmdbError("not a Berkeley DB hash database")
    version, pagesize = struct.unpack_from(bo + "II", meta, 16)
    lastpage = struct.unpack_from(bo + "I", meta, 32)[0]
    maxbucket = struct.unpack_from(bo + "I", meta, 72)[0]
    spares = struct.unpack_from(bo + "32I", meta, 96)
    if not 8 <= version <= 10:
        raise RpmdbError(f"unsupported Berkeley DB hash version {version}")
    if pagesize < 512 or pagesize > 65536 or pagesize & (pagesize - 1):
        raise RpmdbError(f"implausible Berkeley DB page size {pagesize}")
    if (lastpage + 1) * pagesize > size:
        raise RpmdbError("Berkeley DB file shorter than its last page")
    if maxbucket > lastpage:
        raise RpmdbError(f"implausible bucket count {maxbucket}")

    def page(pgno: int) -> bytes:
        if not 0 < pgno <= lastpage:
            raise RpmdbError(f"page {pgno} out of range")
        pg = _pread_exact(fd, pagesize, pgno * pagesize)
        if struct.unpack_from(bo + "I", pg, 8)[0] != pgno:
            raise RpmdbError(f"page {pgno} carries the wrong page number")
        return pg

    def overflow(pgno: int, total: int) -> bytes:
        if total <= 0:
            raise RpmdbError("empty overflow item")
        out = bytearray()
        seen: set[int] = set()
        while len(out) < total:
            if pgno in seen:
                raise RpmdbError(f"overflow chain loops at page {pgno}")
            seen.add(pgno)
            pg = page(pgno)
            if pg[25] != _BDB_PAGE_OVERFLOW:
                raise RpmdbError(f"page {pgno} is not an overflow page")
            used = struct.unpack_from(bo + "H", pg, 22)[0]
            if (
                used == 0
                or used + _BDB_PAGE_HEADER > pagesize
                or len(out) + used > total
            ):
                raise RpmdbError(f"bad overflow length on page {pgno}")
            out += pg[_BDB_PAGE_HEADER : _BDB_PAGE_HEADER + used]
            pgno = struct.unpack_from(bo + "I", pg, 16)[0]
        return bytes(out)

    def item(pg: bytes, off: int, length: int) -> bytes:
        if length <= 0 or off + length > pagesize:
            raise RpmdbError("hash item outside its page")
        kind = pg[off]
        if kind == _BDB_ITEM_KEYDATA:
            return pg[off + 1 : off + length]
        if kind == _BDB_ITEM_OFFPAGE and length == 12:
            pgno, total = struct.unpack_from(bo + "II", pg, off + 4)
            return overflow(pgno, total)
        raise RpmdbError(f"unsupported hash item type {kind}")

    visited: set[int] = set()
    for bucket in range(maxbucket + 1):
        pgno = bucket + spares[bucket.bit_length()]
        while pgno:
            if pgno in visited:
                raise RpmdbError(f"bucket chain loops at page {pgno}")
            visited.add(pgno)
            pg = page(pgno)
            if pg[25] not in _BDB_PAGE_TYPES_HASH:
                raise RpmdbError(f"page {pgno} is not a hash page")
            nent = struct.unpack_from(bo + "H", pg, 20)[0]
            if nent > (pagesize - _BDB_PAGE_HEADER) // 2:
                raise RpmdbError(f"page {pgno} claims {nent} entries")
            offs = struct.unpack_from(bo + f"{nent}H", pg, _BDB_PAGE_HEADER)
            for idx in range(0, nent - 1, 2):
                koff, voff = offs[idx], offs[idx + 1]
                kend = pagesize if idx == 0 else offs[idx - 1]
                if not voff < koff < kend <= pagesize:
                    raise RpmdbError(f"page {pgno} entry {idx} overlaps")
                key = item(pg, koff, kend - koff)
                # Packages is keyed by the 4-byte header number; record 0
                # is rpm's instance counter, not a package.
                if len(key) != 4 or struct.unpack(bo + "I", key)[0] == 0:
                    continue
                yield item(pg, voff, koff - voff)
            pgno = struct.unpack_from(bo + "I", pg, 16)[0]


def _iter_ndb_blobs(fd: int, size: int) -> Iterator[bytes]:
    """Yield every package header blob from an ndb Packages.db (always
    little-endian).  Checks slots, blob head/tail and, when zlib is
    available, the per-blob Adler-32, so a torn or corrupt entry raises
    RpmdbError instead of yielding garbage."""
    try:
        import zlib
    except ImportError:  # minimal builds; head/tail checks still apply
        zlib = None  # type: ignore[assignment]
    head = _pread_exact(fd, _NDB_HEADER, 0)
    magic, version, _generation, slotnpages = struct.unpack_from("<4sIII", head, 0)
    if magic != _NDB_MAGIC:
        raise RpmdbError("not an ndb database")
    if version != 0:
        raise RpmdbError(f"unsupported ndb version {version}")
    if size % _NDB_BLK or not 0 < slotnpages <= _NDB_MAX_SLOTNPAGES:
        raise RpmdbError("implausible ndb file size or slot page count")
    if slotnpages * _NDB_PAGE > size:
        raise RpmdbError("ndb file shorter than its slot pages")
    fileblks = size // _NDB_BLK
    minblkoff = slotnpages * (_NDB_PAGE // _NDB_BLK)
    slots = _pread_exact(fd, slotnpages * _NDB_PAGE, 0)
    for off in range(_NDB_HEADER, len(slots), _NDB_SLOT):
        smagic, pkgidx, blkoff, blkcnt = struct.unpack_from("<4sIII", slots, off)
        if smagic != b"Slot":
            raise RpmdbError(f"bad ndb slot magic at offset {off}")
        if blkoff == 0:
            continue  # free slot
        if not pkgidx or blkoff < minblkoff or blkoff + blkcnt > fileblks:
            raise RpmdbError(f"bad ndb slot at offset {off}")
        region = _pread_exact(fd, blkcnt * _NDB_BLK, blkoff * _NDB_BLK)
        bmagic, bidx, _gen, blen = struct.unpack_from("<4sIII", region, 0)
        need = -(-(_NDB_BLOBHEAD + blen + _NDB_BLOBTAIL) // _NDB_BLK)
        if bmagic != b"BlbS" or bidx != pkgidx or blkcnt != need:
            raise RpmdbError(f"bad ndb blob for package index {pkgidx}")
        adl, tlen, tmagic = struct.unpack_from(
            "<I I 4s", region, len(region) - _NDB_BLOBTAIL
        )
        if tmagic != b"BlbE" or tlen != blen:
            raise RpmdbError(f"bad ndb blob trailer for package index {pkgidx}")
        if zlib is not None and zlib.adler32(region[:-_NDB_BLOBTAIL]) != adl:
            raise RpmdbError(f"ndb blob checksum mismatch for package index {pkgidx}")
        yield region[_NDB_BLOBHEAD : _NDB_BLOBHEAD + blen]


_RPMDB_FILE_BY_BACKEND: dict[str, str] = {
    "sqlite": "rpmdb.sqlite",
    "ndb": "Packages.db",
    "bdb": "Packages",
}


_RPMDB_BLOB_READERS: dict[str, Callable[[int, int], Iterator[bytes]]] = {
    "bdb": _iter_bdb_hash_values,
    "ndb": _iter_ndb_blobs,
}


def read_rpmdb_blobs(
    backend: str, db_file: Path, names: tuple[str, ...] | None = None
) -> list[dict[str, Any]]:
    """Read a Berkeley DB or ndb rpm database in-process, keeping only the
    packages in `names` when given.  There is no name index to use, and a
    substring prefilter measured slower than parsing: headers average
    ~60 KB, while parse_rpm_header only touches the small tag index.  A
    database with no packages is invalid, as for sqlite.  Raises
    RpmdbError; never returns a partial inventory."""
    reader = _RPMDB_BLOB_READERS[backend]
    try:
        fd = os.open(db_file, os.O_RDONLY)
    except OSError as e:
        raise RpmdbError(f"cannot open {db_file}: {e}") from e
    try:
        size = os.fstat(fd).st_size
        out: list[dict[str, Any]] = []
        count = 0
        for blob in reader(fd, size):
            count += 1
            pkg = parse_rpm_header(blob)
            if names is None or pkg["name"] in names:
                out.append(pkg)
    except (OSError, struct.error) as e:
        raise RpmdbError(f"cannot read {db_file}: {e}") from e
    finally:
        os.close(fd)
    if count == 0:
        raise RpmdbError(f"{db_file} holds 0 packages; treating as invalid")
    return out


def _read_rpmdb_direct(
    db: tuple[str, Path, str], names: tuple[str, ...] | None = None
) -> list[dict[str, Any]]:
    """In-process read of any supported backend; raises RpmdbError."""
    backend = db[2]
    db_file = db[1] / _RPMDB_FILE_BY_BACKEND[backend]
    if backend == "sqlite":
        return (
            read_rpmdb_sqlite(db_file)
            if names is None
            else read_rpmdb_sqlite_named(db_file, names)
        )
    return read_rpmdb_blobs(backend, db_file, names)


def parse_rpm_qa_nvra(text: str) -> list[dict[str, Any]]:
    """Parse `rpm -qa --queryformat '%{NAME} %{VERSION} %{RELEASE} %{ARCH}\\n'`.

    _run merges stderr into stdout, and rpm prints diagnostics such as
    `warning: Found bdb_ro Packages` (rpm >= 4.17 reading an EL8 database)
    that also split into four fields, so only lines with exactly four
    fields and no `warning:` / `error:` prefix are packages."""
    out: list[dict[str, Any]] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) != 4 or parts[0].rstrip(":") in ("warning", "error"):
            if line.strip():
                log.debug("rpm -qa: ignoring non-package line %r", line)
            continue
        pkg: dict[str, Any] = {
            "name": parts[0],
            "version": parts[1],
            "release": parts[2],
        }
        if parts[3] != "(none)":
            pkg["arch"] = parts[3]
        out.append(pkg)
    return out


_RPM_NVRA_QUERYFORMAT = "%{NAME} %{VERSION} %{RELEASE} %{ARCH}\\n"


_RPM_QA_ARGV = ["rpm", "-qa", "--queryformat", _RPM_NVRA_QUERYFORMAT]


def _query_rpm_cli(db: tuple[str, Path, str] | None) -> dict[str, Any]:
    """Fallback inventory through the rpm binary, used only when the
    database cannot be read in-process (unrecognised or corrupt file, or
    no sqlite3 module for an sqlite database).  Under --host-mount the
    binary belongs to the scanner image, so it is pointed at the host with
    --root plus the located --dbpath (interpreted inside the root); with no
    host database located it refuses rather than silently reporting the
    image's own packages."""
    if _platform.HOST_PREFIX and db is None:
        return {
            "available": False,
            "reason": f"no rpm database found under {_platform.HOST_PREFIX} "
            f"({', '.join(RPMDB_DIRS)}); is the host rpmdb mounted?",
        }
    if not shutil.which("rpm"):
        return {"available": False, "reason": "rpm not on PATH"}
    argv = list(_RPM_QA_ARGV)
    if _platform.HOST_PREFIX and db is not None:
        argv[1:1] = ["--root", _platform.HOST_PREFIX, "--dbpath", db[0]]
    rc, out = _platform._run(argv, timeout=30)
    if rc != 0:
        return {"available": False, "reason": f"rpm -qa failed (rc={rc})"}
    return {
        "available": True,
        "source": "rpm-cli",
        "db_root": db[0] if db else None,
        "backend": db[2] if db else None,
        "packages": parse_rpm_qa_nvra(out),
    }


@functools.lru_cache(maxsize=None)
def _query_rpm_packages_cached(host_prefix: str) -> dict[str, Any]:
    # host_prefix is the cache key only; locate_rpmdb() reads HOST_PREFIX.
    db = locate_rpmdb()
    if db is not None:
        try:
            pkgs = _read_rpmdb_direct(db)
        except RpmdbError as e:
            log.debug("rpmdb: direct read failed, falling back to rpm CLI: %s", e)
        else:
            return _direct_result(db, pkgs)
    return _query_rpm_cli(db)


def _direct_result(
    db: tuple[str, Path, str], pkgs: list[dict[str, Any]]
) -> dict[str, Any]:
    return {
        "available": True,
        "source": f"rpmdb-{db[2]}",
        "db_root": db[0],
        "backend": db[2],
        "packages": pkgs,
    }


def query_rpm_packages() -> dict[str, Any]:
    """Installed-RPM inventory, read once per process and shared by
    scan_packages() and detect_nss().  Reads sqlite, Berkeley DB (EL8,
    Leap 15 cloud images) and ndb (SUSE) databases in-process; only an
    unreadable database (or a missing sqlite3 module) takes the rpm CLI
    path.  Result: {available, source, db_root, backend,
    packages: [{name, version, release?, epoch?, arch?}]} or
    {available: False, reason}.  Tests reset the cache with
    _query_rpm_packages_cached.cache_clear()."""
    return _query_rpm_packages_cached(_platform.HOST_PREFIX)


def _query_rpm_named_cli(
    db: tuple[str, Path, str] | None, names: tuple[str, ...]
) -> dict[str, Any]:
    """`rpm -q <names>` through the binary, pointed at the host the same
    way as _query_rpm_cli.  rpm exits non-zero for each name that is not
    installed, so its exit code alone does not mean failure."""
    if _platform.HOST_PREFIX and db is None:
        return {
            "available": False,
            "reason": f"no rpm database found under {_platform.HOST_PREFIX}",
        }
    if not shutil.which("rpm"):
        return {"available": False, "reason": "rpm not on PATH"}
    argv = ["rpm", "-q", "--queryformat", _RPM_NVRA_QUERYFORMAT, *names]
    if _platform.HOST_PREFIX and db is not None:
        argv[1:1] = ["--root", _platform.HOST_PREFIX, "--dbpath", db[0]]
    rc, out = _platform._run(argv, timeout=10)
    pkgs = parse_rpm_qa_nvra(out)
    if rc != 0 and not pkgs and "is not installed" not in out:
        return {"available": False, "reason": f"rpm -q failed (rc={rc})"}
    return {
        "available": True,
        "source": "rpm-cli",
        "db_root": db[0] if db else None,
        "backend": db[2] if db else None,
        "packages": pkgs,
    }


def query_rpm_named(names: tuple[str, ...]) -> dict[str, Any]:
    """Look up specific packages without reading the whole inventory.

    Reuses the full inventory when this process already read it
    (--scan-packages); otherwise uses the sqlite Name index.  Berkeley DB
    and ndb have no index we read, so a direct lookup walks the whole
    database (10-60 ms on real EL8 / SUSE VMs) while `rpm -q` uses rpm's
    own index (~4 ms); there `rpm -q` comes first and the direct read is
    the fallback when the binary is missing or fails (#134).  Same result
    shape as query_rpm_packages(), restricted to `names`."""
    if _query_rpm_packages_cached.cache_info().currsize:
        return query_rpm_named_from_inventory(names)
    db = locate_rpmdb()
    if db is None:
        return _query_rpm_named_cli(db, names)
    if db[2] in ("bdb", "ndb"):
        cli = _query_rpm_named_cli(db, names)
        if cli.get("available"):
            return cli
        log.debug(
            "rpmdb: rpm -q unavailable (%s); reading %s directly",
            cli.get("reason"),
            db[2],
        )
    try:
        return _direct_result(db, _read_rpmdb_direct(db, names))
    except RpmdbError as e:
        if db[2] == "sqlite":  # e.g. no Name table: full read, then CLI
            log.debug("rpmdb: indexed lookup failed, using full inventory: %s", e)
            return query_rpm_named_from_inventory(names)
        log.debug("rpmdb: direct read failed, falling back to rpm -q: %s", e)
        return _query_rpm_named_cli(db, names)


def query_rpm_named_from_inventory(names: tuple[str, ...]) -> dict[str, Any]:
    """Fallback for query_rpm_named(): filter the full (cached) inventory."""
    inv = query_rpm_packages()
    if not inv.get("available"):
        return inv
    return {**inv, "packages": [p for p in inv["packages"] if p["name"] in names]}


# Per-family commands for --scan-packages.  The first tuple element is the
# argv to invoke; the second is the parser to apply.  When the family has
# no entry (or the tool is missing on PATH), scan_packages reports
# unavailable rather than guessing.
PACKAGE_QUERY_BY_FAMILY: dict[
    str, tuple[list[str], Callable[[str], list[dict[str, str]]]]
] = {
    "rhel": (
        ["rpm", "-qa", "--queryformat", "%{NAME} %{VERSION}\\n"],
        parse_whitespace_pkg_lines,
    ),
    "suse": (
        ["rpm", "-qa", "--queryformat", "%{NAME} %{VERSION}\\n"],
        parse_whitespace_pkg_lines,
    ),
    "debian": (
        ["dpkg-query", "-W", "-f=${Package} ${Version}\\n"],
        parse_whitespace_pkg_lines,
    ),
    "arch": (["pacman", "-Q"], parse_whitespace_pkg_lines),
    "alpine": (["apk", "info", "-v"], parse_apk_packages),
}


def scan_packages(os_release: dict[str, Any] | None = None) -> dict[str, Any]:
    """Family-aware package inventory.  Returns the same shape regardless
    of which tool produced it: {available, total_packages, bundled_crypto},
    so consumers don't have to special-case rpm/dpkg/pacman/apk output.
    RPM families read the rpm database through query_rpm_packages() and
    additionally report `source` and `db_root` (#125)."""
    family = (os_release or {}).get("family", "unknown")
    if family in ("rhel", "suse"):
        return _scan_rpm_packages(family)
    plan = PACKAGE_QUERY_BY_FAMILY.get(family)
    if plan is None:
        return {
            "available": False,
            "reason": f"no package-query tool registered for family={family}",
        }
    argv, parser = plan
    if not shutil.which(argv[0]):
        return {
            "available": False,
            "reason": f"{argv[0]} not on PATH ({_osinfo._install_hint(argv[0], family)})",
        }
    rc, out = _platform._run(argv, timeout=30)
    if rc != 0:
        return {"available": False, "reason": f"{argv[0]} failed (rc={rc})"}
    pkgs = parser(out)
    return {
        "available": True,
        "package_manager": argv[0],
        "total_packages": len(pkgs),
        "bundled_crypto": classify_bundled_crypto(pkgs, family),
    }


def _scan_rpm_packages(family: str) -> dict[str, Any]:
    inv = query_rpm_packages()
    if not inv.get("available"):
        reason = str(inv.get("reason", "rpm database unavailable"))
        if reason == "rpm not on PATH":
            reason = f"rpm not on PATH ({_osinfo._install_hint('rpm', family)})"
        return {"available": False, "reason": reason}
    pkgs = [{"name": p["name"], "version": p["version"]} for p in inv["packages"]]
    out: dict[str, Any] = {
        "available": True,
        "package_manager": "rpm",
        "source": inv["source"],
        "db_root": inv["db_root"],
        "total_packages": len(pkgs),
        "bundled_crypto": classify_bundled_crypto(pkgs, family),
    }
    note = _runtime._host_fs_note_for("packages")
    if note:
        out.update(note)
    return out


@_registry.register_arguments(51)
def add_arguments(ap: argparse.ArgumentParser) -> None:
    """--scan-packages."""
    ap.add_argument(
        "--scan-packages",
        action="store_true",
        help=(
            "enumerate installed packages with bundled crypto "
            "(rpm, dpkg, pacman and apk families)"
        ),
    )
