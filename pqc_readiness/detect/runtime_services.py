"""Listening-service -> crypto library linkage (--scan-services, #111).

For every listening TCP socket and bound UDP socket, find the owning
process(es) and report which TLS/crypto library the process actually has
mapped (OpenSSL / LibreSSL / BoringSSL / AWS-LC, GnuTLS, NSS, wolfSSL) and,
for Go binaries, the toolchain version embedded in the binary.  This is the
join key that endpoint-observation ingestion (#149) uses: address + port +
protocol on this host -> the library that will negotiate on that port.

Pure /proc inspection through ``host_path`` -- no network connections, no
subprocesses:

* ``/proc/<pid>/net/{tcp,tcp6,udp,udp6}``, read once per network namespace,
  give listening sockets and their inodes.
* ``/proc/<pid>/fd/*`` links (``socket:[inode]``) map inodes to processes.
* ``/proc/<pid>/maps`` lists mapped libraries; each library is read through
  ``/proc/<pid>/root/<path>`` (or ``/proc/<pid>/map_files/`` when the file
  was deleted by an upgrade), so the scanner reads the file the *process*
  sees, including inside containers and under ``--host-mount``.
* ``/proc/<pid>/exe`` is parsed as ELF to find ``.go.buildinfo`` and
  ``PT_INTERP`` (static vs dynamic).

Runtime is bounded by a PID cap and a wall-clock budget; hitting either sets
``truncated``.  Without root (or CAP_SYS_PTRACE + CAP_DAC_READ_SEARCH) other
users' processes are unreadable; those are counted, never guessed.
"""

from __future__ import annotations

import argparse
import ipaddress
import logging
import os
import re
import socket
import struct
import time
from pathlib import Path
from typing import Any

from .. import _platform as _platform
from .. import registry as _registry
from .protocols import NSS_PQC_MIN_VERSION

log = logging.getLogger("pqc-readiness")

# Same rule as openssl_capability()'s `pqc_native` in detect/config.py:
# OpenSSL 3.5 is the first release with ML-KEM / hybrid TLS groups built in.
OPENSSL_PQC_MIN_VERSION = (3, 5)

# Go 1.24 enables X25519MLKEM768 by default when Config.CurvePreferences is
# nil and removes X25519Kyber768Draft00; Go 1.23 enabled the pre-standard
# X25519Kyber768Draft00 by default.
# Source: https://go.dev/doc/go1.24 and https://go.dev/doc/go1.23.  The
# defaults can be reverted with GODEBUG tlsmlkem=0 / tlskyber=0
# (https://go.dev/doc/godebug).
GO_MLKEM_DEFAULT_VERSION = (1, 24)
GO_KYBER_DRAFT_DEFAULT_VERSION = (1, 23)

SERVICES_MAX_PIDS_DEFAULT = 4096
SERVICES_TIME_BUDGET_S_DEFAULT = 15.0
# Upper bound on bytes read from one library when looking for its embedded
# version string (libcrypto is ~5-7 MB; a cap keeps a pathological file
# from stalling the scan).
_LIB_READ_CAP = 64 * 1024 * 1024
# Upper bound on bytes read from an executable when no section table is
# available and .go.buildinfo has to be found by searching.
_EXE_SEARCH_CAP = 64 * 1024 * 1024

_TCP_LISTEN = "0A"
_UDP_UNCONNECTED = "07"

# (family label, basename regex, embedded version regexes in priority order)
# Version strings verified against Fedora 44 libraries: libcrypto embeds
# "OpenSSL 3.5.9 29 Sep 2026", libgnutls "GnuTLS 3.8.13", libnss3
# "Version: NSS 3.130".
_LIBRARIES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("openssl", re.compile(r"^lib(?:ssl|crypto)\.so(?:\.[\w.]+)?$")),
    ("gnutls", re.compile(r"^libgnutls\.so(?:\.[\d.]+)?$")),
    ("nss", re.compile(r"^libnss3\.so(?:\.[\d.]+)?$")),
    ("wolfssl", re.compile(r"^libwolfssl\.so(?:\.[\d.]+)?$")),
)
_OPENSSL_FORK_MARKERS: tuple[tuple[str, bytes], ...] = (
    ("aws-lc", b"AWS-LC"),
    ("boringssl", b"BoringSSL"),
    ("libressl", b"LibreSSL "),
)
_VERSION_RES: dict[str, tuple[re.Pattern[bytes], ...]] = {
    "openssl": (
        re.compile(rb"OpenSSL (\d+\.\d+\.\d+[a-z]?)(?:-\w+)? +\d{1,2} \w{3} \d{4}"),
    ),
    "libressl": (re.compile(rb"LibreSSL (\d+\.\d+\.\d+)"),),
    "aws-lc": (re.compile(rb"AWS-LC (\d+\.\d+\.\d+)"),),
    "boringssl": (),
    "gnutls": (re.compile(rb"GnuTLS (\d+\.\d+\.\d+)"),),
    "nss": (re.compile(rb"Version: NSS (\d+\.\d+(?:\.\d+)?)"),),
    "wolfssl": (re.compile(rb"wolfSSL (\d+\.\d+\.\d+)"),),
}
_SONAME_VERSION_RE = re.compile(r"\.so\.(\d+(?:\.\d+)*)$")
_UNIT_RE = re.compile(r"/([^/]+\.(?:service|scope))$")
_GO_MAGIC = b"\xff Go buildinf:"


# ---------------------------------------------------------------------------
# /proc/net parsing
# ---------------------------------------------------------------------------


def _decode_proc_net_address(hexaddr: str) -> tuple[str, str, int]:
    """Decode ``0100007F:0016`` / 32-hex-digit IPv6 forms from /proc/net.

    The kernel prints each 32-bit word of the address with %08X in host
    byte order, so packing each word natively recovers network byte order
    on both little- and big-endian hosts (x86_64 / aarch64 / s390x)."""
    addr_hex, port_hex = hexaddr.split(":")
    words = [int(addr_hex[i : i + 8], 16) for i in range(0, len(addr_hex), 8)]
    raw = b"".join(struct.pack("=I", w) for w in words)
    port = int(port_hex, 16)
    if len(raw) == 4:
        return "ipv4", socket.inet_ntop(socket.AF_INET, raw), port
    if len(raw) == 16:
        # IPv4-mapped IPv6 (::ffff:a.b.c.d) is reported as written.
        return "ipv6", socket.inet_ntop(socket.AF_INET6, raw), port
    raise ValueError(f"unexpected address length in {hexaddr!r}")


def parse_proc_net(text: str, protocol: str) -> list[dict[str, Any]]:
    """Listening TCP / bound unconnected UDP sockets from a /proc/net table.

    Returns ``[{protocol, family, address, port, inode}]``; malformed rows
    are skipped with a debug log rather than aborting the scan."""
    want = _TCP_LISTEN if protocol == "tcp" else _UDP_UNCONNECTED
    out: list[dict[str, Any]] = []
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 10 or parts[3] != want:
            continue
        try:
            family, address, port = _decode_proc_net_address(parts[1])
            _, _, rport = _decode_proc_net_address(parts[2])
            inode = int(parts[9])
        except (ValueError, OSError) as e:
            log.debug("services: skipping /proc/net row %r: %s", line, e)
            continue
        if port == 0 or inode == 0 or (protocol == "udp" and rport != 0):
            continue
        out.append(
            {
                "protocol": protocol,
                "family": family,
                "address": address,
                "port": port,
                "inode": inode,
            }
        )
    return out


def bind_scope(address: str) -> str:
    """``any`` (wildcard), ``loopback``, ``multicast``, ``link-local`` or
    ``specific`` for a bound address.  Join logic (#149) needs this: an
    endpoint observed on a host IP can match an ``any`` or ``specific``
    listener, never a ``loopback`` one."""
    ip = ipaddress.ip_address(address)
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    if ip.is_unspecified:
        return "any"
    if ip.is_loopback:
        return "loopback"
    if ip.is_multicast:
        return "multicast"
    if ip.is_link_local:
        return "link-local"
    return "specific"


# ---------------------------------------------------------------------------
# Per-process helpers
# ---------------------------------------------------------------------------


def _proc(pid: int, *parts: str) -> Path:
    return _platform.host_path("/proc/" + "/".join([str(pid), *parts]))


def parse_maps_libraries(text: str) -> list[dict[str, Any]]:
    """Crypto libraries mapped by a process, from /proc/<pid>/maps text.

    Returns one entry per distinct path: ``{family, path, soname_version,
    deleted, map_range}``; ``map_range`` is the first mapping's address
    range, used to open ``/proc/<pid>/map_files/<range>`` when the file has
    been deleted (a running service still using a replaced library)."""
    seen: dict[str, dict[str, Any]] = {}
    for line in text.splitlines():
        parts = line.split(None, 5)
        if len(parts) < 6:
            continue
        path = parts[5].strip()
        deleted = path.endswith(" (deleted)")
        if deleted:
            path = path[: -len(" (deleted)")]
        if not path.startswith("/") or path in seen:
            continue
        base = os.path.basename(path)
        for family, pattern in _LIBRARIES:
            if pattern.match(base):
                m = _SONAME_VERSION_RE.search(base)
                try:
                    inode = int(parts[4])
                except ValueError:
                    inode = 0
                seen[path] = {
                    "family": family,
                    "path": path,
                    "soname_version": m.group(1) if m else None,
                    "deleted": deleted,
                    "map_range": parts[0],
                    # Device + inode as the kernel reports them: lets a
                    # process whose root is a private namespace (sandboxed
                    # browsers, chroots) reuse the result for the same file
                    # read through another process (#155).
                    "maps_key": (parts[3], inode) if inode else None,
                }
                break
    return list(seen.values())


def _read_capped(path: Path, cap: int) -> bytes:
    with path.open("rb") as fh:
        return fh.read(cap)


def library_version(family: str, blob: bytes) -> tuple[str, str | None]:
    """Refine the family (OpenSSL forks share sonames) and pull the
    embedded version string.  Returns ``(family, version|None)``."""
    if family == "openssl":
        for fork, marker in _OPENSSL_FORK_MARKERS:
            if marker in blob:
                family = fork
                break
    for pattern in _VERSION_RES.get(family, ()):
        m = pattern.search(blob)
        if m:
            return family, m.group(1).decode("ascii")
    return family, None


def _version_tuple(v: str | None) -> tuple[int, ...] | None:
    if not v:
        return None
    nums = re.findall(r"\d+", v)
    return tuple(int(n) for n in nums[:3]) if nums else None


def library_tls_pqc_markers(family: str, blob: bytes) -> bool | None:
    """Whether the library binary contains hybrid ML-KEM TLS group names.

    Uses the per-library marker strings verified in #110
    (``LIBRARY_SPECS[...]["markers"]["tls_hybrid_groups"]``): their presence
    is definitive evidence, and catches builds a version threshold misses
    (Rocky 9.8's GnuTLS).  None when no markers are encoded for the family
    (OpenSSL / NSS are assessed by version) or the blob is empty."""
    if not blob:
        return None
    # Imported here: protocols_libraries imports this module at load time.
    from .protocols_libraries import LIBRARY_SPECS

    spec = LIBRARY_SPECS.get(family) or {}
    markers = (spec.get("markers") or {}).get("tls_hybrid_groups")
    if not markers:
        return None
    return any(m in blob for m in markers.values())


def library_pqc_capable(
    family: str, version: str | None, markers: bool | None = None
) -> bool | None:
    """Whether the library ships ML-KEM hybrid TLS key exchange.

    ``markers`` is binary evidence from ``library_tls_pqc_markers`` and wins
    when known; otherwise the *version* threshold decides.  Capability
    only: whether a given service enables it is configuration (#106 /
    #107).  None means "not assessed"."""
    if markers is not None:
        return markers
    vt = _version_tuple(version)
    if vt is None:
        return None
    if family == "openssl":
        return vt[:2] >= OPENSSL_PQC_MIN_VERSION
    if family == "nss":
        return vt[:2] >= NSS_PQC_MIN_VERSION
    return None


# ---------------------------------------------------------------------------
# ELF / Go buildinfo
# ---------------------------------------------------------------------------


def _read_uvarint(data: bytes, pos: int) -> tuple[int, int]:
    result = shift = 0
    while pos < len(data):
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, pos
        shift += 7
        if shift > 63:
            break
    raise ValueError("bad uvarint")


def parse_go_buildinfo(blob: bytes) -> dict[str, Any] | None:
    """Decode a Go build-info blob that starts with the 14-byte magic.

    Supports the Go 1.18+ inline-string format (flags bit 0x2), which is
    every toolchain that matters for PQC.  Older pointer-format binaries
    return ``{"go_version": None, "format": "pointer"}``.  Layout per
    src/debug/buildinfo/buildinfo.go: 32-byte header (magic, ptrSize,
    flags, ...) then varint-prefixed version and modinfo strings; modinfo
    is wrapped in 16-byte sentinels."""
    if not blob.startswith(_GO_MAGIC) or len(blob) < 32:
        return None
    flags = blob[15]
    if flags & 0x2 != 0x2:
        return {"go_version": None, "format": "pointer"}
    n, pos = _read_uvarint(blob, 32)
    version = blob[pos : pos + n].decode("utf-8", "replace")
    pos += n
    n, pos = _read_uvarint(blob, pos)
    mod = blob[pos : pos + n].decode("utf-8", "replace")
    if len(mod) >= 33 and mod[len(mod) - 17] == "\n":
        mod = mod[16 : len(mod) - 16]
    settings: dict[str, str] = {}
    main_module = None
    for line in mod.splitlines():
        if line.startswith("build\t") and "=" in line:
            k, _, v = line[len("build\t") :].partition("=")
            settings[k] = v
        elif line.startswith("path\t"):
            main_module = line[len("path\t") :]
    return {
        "go_version": version or None,
        "format": "inline",
        "main_module": main_module,
        "settings": settings,
    }


def _elf_info(fh: Any) -> dict[str, Any] | None:
    """Static/dynamic linkage and the .go.buildinfo section bytes of an ELF
    file, or None if it is not ELF.  Handles 32/64-bit, both byte orders."""
    ident = fh.read(16)
    if ident[:4] != b"\x7fELF":
        return None
    cls, data = ident[4], ident[5]
    bo = "<" if data == 1 else ">"
    is64 = cls == 2
    fh.seek(0)
    hdr = fh.read(64 if is64 else 52)
    if is64:
        (e_phoff, e_shoff) = struct.unpack_from(bo + "QQ", hdr, 32)
        (e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from(
            bo + "HHHHH", hdr, 54
        )
    else:
        (e_phoff, e_shoff) = struct.unpack_from(bo + "II", hdr, 28)
        (e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from(
            bo + "HHHHH", hdr, 42
        )
    if e_phnum > 4096 or e_shnum > 65535:
        raise ValueError("implausible ELF header counts")
    interp = False
    fh.seek(e_phoff)
    ph = fh.read(e_phentsize * e_phnum)
    for i in range(e_phnum):
        (p_type,) = struct.unpack_from(bo + "I", ph, i * e_phentsize)
        if p_type == 3:  # PT_INTERP
            interp = True
            break
    buildinfo: bytes | None = None
    if e_shoff and e_shnum and e_shstrndx < e_shnum:
        fh.seek(e_shoff)
        sh = fh.read(e_shentsize * e_shnum)

        def section(i: int) -> tuple[int, int, int]:
            base = i * e_shentsize
            if is64:
                name, _t, _f, _a, off, size = struct.unpack_from(
                    bo + "IIQQQQ", sh, base
                )
            else:
                name, _t, _f, _a, off, size = struct.unpack_from(
                    bo + "IIIIII", sh, base
                )
            return name, off, size

        _, str_off, str_size = section(e_shstrndx)
        fh.seek(str_off)
        names = fh.read(min(str_size, 1 << 20))
        for i in range(e_shnum):
            name_off, off, size = section(i)
            end = names.find(b"\0", name_off)
            if names[name_off:end] == b".go.buildinfo":
                fh.seek(off)
                buildinfo = fh.read(min(size, 1 << 20))
                break
    return {"static": not interp, "buildinfo": buildinfo}


def elf_dynamic(fh: Any) -> dict[str, list[str]] | None:
    """``{needed, runpath}`` from an ELF file's dynamic section, or None if
    it is not ELF.  DT_RPATH entries are folded into ``runpath``; a static
    binary returns empty lists.  Bounded reads; malformed input raises
    ValueError / struct.error, which callers treat as unreadable."""
    ident = fh.read(16)
    if ident[:4] != b"\x7fELF":
        return None
    bo = "<" if ident[5] == 1 else ">"
    is64 = ident[4] == 2
    fh.seek(0)
    hdr = fh.read(64 if is64 else 52)
    if is64:
        (e_phoff,) = struct.unpack_from(bo + "Q", hdr, 32)
        e_phentsize, e_phnum = struct.unpack_from(bo + "HH", hdr, 54)
    else:
        (e_phoff,) = struct.unpack_from(bo + "I", hdr, 28)
        e_phentsize, e_phnum = struct.unpack_from(bo + "HH", hdr, 42)
    if e_phnum > 4096 or e_phentsize < (56 if is64 else 32):
        raise ValueError("implausible ELF program header table")
    fh.seek(e_phoff)
    ph = fh.read(e_phentsize * e_phnum)
    loads: list[tuple[int, int, int]] = []
    dyn: tuple[int, int] | None = None
    for i in range(e_phnum):
        base = i * e_phentsize
        if is64:
            p_type, _f, p_offset, p_vaddr, _pa, p_filesz = struct.unpack_from(
                bo + "IIQQQQ", ph, base
            )
        else:
            p_type, p_offset, p_vaddr, _pa, p_filesz = struct.unpack_from(
                bo + "IIIII", ph, base
            )
        if p_type == 1:  # PT_LOAD
            loads.append((p_vaddr, p_offset, p_filesz))
        elif p_type == 2:  # PT_DYNAMIC
            dyn = (p_offset, min(p_filesz, 1 << 16))
    out: dict[str, list[str]] = {"needed": [], "runpath": []}
    if dyn is None:
        return out
    fh.seek(dyn[0])
    raw = fh.read(dyn[1])
    entsize = 16 if is64 else 8
    fmt = bo + ("qQ" if is64 else "iI")
    needed: list[int] = []
    runpath: list[int] = []
    strtab = strsz = None
    for off in range(0, len(raw) - entsize + 1, entsize):
        tag, val = struct.unpack_from(fmt, raw, off)
        if tag == 0:  # DT_NULL
            break
        if tag == 1:  # DT_NEEDED
            needed.append(val)
        elif tag in (15, 29):  # DT_RPATH, DT_RUNPATH
            runpath.append(val)
        elif tag == 5:  # DT_STRTAB (a virtual address)
            strtab = val
        elif tag == 10:  # DT_STRSZ
            strsz = val
    if strtab is None:
        return out
    str_off = next(
        (off + strtab - va for va, off, sz in loads if va <= strtab < va + sz), None
    )
    if str_off is None:
        return out
    fh.seek(str_off)
    strings: bytes = fh.read(min(strsz or (1 << 16), 1 << 20))

    def at(i: int) -> str:
        end = strings.find(b"\0", i)
        return strings[i : end if end >= 0 else len(strings)].decode("utf-8", "replace")

    out["needed"] = [at(i) for i in needed if i < len(strings)]
    out["runpath"] = [
        d for i in runpath if i < len(strings) for d in at(i).split(":") if d
    ]
    return out


# analyze_executable() result when the executable can't be read.
_EXE_UNKNOWN: dict[str, Any] = {"static": None, "go": None}


def analyze_executable(path: Path) -> dict[str, Any]:
    """``{static, go}`` for an executable; ``go`` is None for non-Go binaries."""
    out: dict[str, Any] = {"static": None, "go": None}
    try:
        with path.open("rb") as fh:
            info = _elf_info(fh)
            if info is None:
                return out
            out["static"] = info["static"]
            blob = info["buildinfo"]
            if blob is None:
                # Stripped section table: search for the magic directly.
                fh.seek(0)
                data = fh.read(_EXE_SEARCH_CAP)
                at = data.find(_GO_MAGIC)
                blob = data[at : at + (1 << 20)] if at >= 0 else None
    except (OSError, ValueError, struct.error) as e:
        log.debug("services: cannot analyse %s: %s", path, e)
        return out
    if blob:
        try:
            out["go"] = parse_go_buildinfo(blob)
        except ValueError as e:
            log.debug("services: bad Go buildinfo in %s: %s", path, e)
    return out


def _go_godebug_from_environ(raw: bytes) -> str | None:
    """Only the GODEBUG value from /proc/<pid>/environ.  Nothing else from
    the environment is kept or reported: it may hold secrets."""
    for item in raw.split(b"\0"):
        if item.startswith(b"GODEBUG="):
            return item[len(b"GODEBUG=") :].decode("utf-8", "replace")
    return None


def go_tls_kex_default(
    go: dict[str, Any], runtime_godebug: str | None
) -> dict[str, Any]:
    """Default TLS key exchange a Go binary offers when the program leaves
    Config.CurvePreferences nil, honouring GODEBUG reverts from the build
    (DefaultGODEBUG) and the process environment."""
    vt = _version_tuple((go.get("go_version") or "").removeprefix("go"))
    godebug = ",".join(
        x
        for x in ((go.get("settings") or {}).get("DefaultGODEBUG"), runtime_godebug)
        if x
    )
    reverted = {
        kv.split("=", 1)[0] for kv in godebug.split(",") if kv.strip().endswith("=0")
    }
    if vt is None:
        default = None
    elif vt[:2] >= GO_MLKEM_DEFAULT_VERSION:
        # Go 1.24 also removed X25519Kyber768Draft00, so reverting ML-KEM
        # leaves no hybrid default at all.
        default = None if "tlsmlkem" in reverted else "X25519MLKEM768"
    elif vt[:2] >= GO_KYBER_DRAFT_DEFAULT_VERSION:
        default = None if "tlskyber" in reverted else "X25519Kyber768Draft00"
    else:
        default = None
    return {
        "default_hybrid_kex": default,
        "godebug_reverts": sorted(reverted & {"tlsmlkem", "tlskyber", "tlssecpmlkem"}),
    }


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------


def _pids() -> list[int]:
    try:
        entries = os.listdir(_platform.host_path("/proc"))
    except OSError as e:
        log.debug("services: cannot list /proc: %s", e)
        return []
    return sorted(int(e) for e in entries if e.isdigit())


def _socket_inodes(pid: int) -> set[int] | None:
    """Socket inodes held by pid, or None when its fd table is unreadable."""
    try:
        fds = os.listdir(_proc(pid, "fd"))
    except PermissionError:
        return None
    except OSError:
        return set()
    out: set[int] = set()
    for fd in fds:
        try:
            target = os.readlink(_proc(pid, "fd", fd))
        except OSError:
            continue
        if target.startswith("socket:["):
            out.add(int(target[8:-1]))
    return out


def _netns(pid: int) -> str | None:
    try:
        return os.readlink(_proc(pid, "ns", "net"))
    except OSError:
        return None


def _listening_sockets(pid: int) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for name, proto in (
        ("tcp", "tcp"),
        ("tcp6", "tcp"),
        ("udp", "udp"),
        ("udp6", "udp"),
    ):
        try:
            text = _proc(pid, "net", name).read_text()
        except OSError as e:
            log.debug("services: cannot read /proc/%s/net/%s: %s", pid, name, e)
            continue
        out.extend(parse_proc_net(text, proto))
    return out


def _systemd_unit(pid: int) -> tuple[str | None, str | None]:
    try:
        text = _proc(pid, "cgroup").read_text()
    except OSError:
        return None, None
    path = None
    for line in text.splitlines():
        parts = line.split(":", 2)
        if len(parts) == 3 and parts[0] == "0":
            path = parts[2]
            break
        if len(parts) == 3 and "name=systemd" in parts[1]:
            path = parts[2]
    if path is None:
        return None, None
    m = _UNIT_RE.search(path)
    return (m.group(1) if m else None), path[-200:]


def _comm(pid: int) -> str | None:
    try:
        return _proc(pid, "comm").read_text().strip() or None
    except OSError:
        return None


def _exe(pid: int) -> str | None:
    try:
        return os.readlink(_proc(pid, "exe"))
    except OSError:
        return None


def _service_pid(pids: list[int]) -> int | None:
    """The process that serves a socket.  With socket activation systemd
    (PID 1) holds the listening socket alongside the service it hands it
    to (e.g. rpcbind on EL9), so prefer the lowest non-init owner."""
    served = [p for p in pids if p != 1] or pids
    return served[0] if served else None


class _Cache:
    """Per-scan caches keyed by (st_dev, st_ino) so shared libraries and
    worker processes of one binary are read once."""

    def __init__(self) -> None:
        self.libs: dict[tuple[int, int], tuple[str, str | None, bool | None]] = {}
        self.by_maps: dict[tuple[str, int], tuple[str, str | None, bool | None]] = {}
        self.exes: dict[tuple[int, int], dict[str, Any]] = {}
        # Worker attribution (#240): ppid of every scanned pid (built on
        # first use) and dynamic sections of files read through a root.
        self.ppids: dict[int, int] | None = None
        self.dynamic: dict[str, dict[str, list[str]] | None] = {}


# ---------------------------------------------------------------------------
# Master/worker daemons (#240)
# ---------------------------------------------------------------------------
#
# Some daemons accept connections in a master process that never does TLS
# itself: Postfix's `master` owns ports 25/587 and hands each connection to
# an `smtpd` child, which is the process that loads OpenSSL.  When the
# listener's owner maps no crypto library, the library is taken, in order,
# from (1) another process holding the same listening socket (a worker that
# inherited it), (2) a descendant of the owner that maps one, or (3) the
# executables those descendants run from, by following their DT_NEEDED
# entries (workers spawned on demand are often not running when the scan
# happens).  The listener records where the libraries came from.

# Directories of general-purpose executables: siblings there say nothing
# about the daemon, so (3) never scans them.
_SHARED_BIN_DIRS = frozenset(
    {"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin"}
)
# Libraries that never lead to a TLS stack the daemon serves with; not
# followed when walking DT_NEEDED.  (libsasl2 / libldap / libkrb5 link
# libcrypto for their own protocols, not for the daemon's TLS listener.)
_NOT_FOLLOWED = re.compile(
    r"^(?:libc|libm|libdl|libpthread|librt|libresolv|libutil|libnsl|libcrypt|"
    r"ld-linux[\w.-]*|libgcc_s|libstdc\+\+|libz|libzstd|liblzma|libbz2|liblz4|"
    r"libselinux|libpcre2?-?\d*|libcap|libsystemd|libudev|libdb-[\d.]+|"
    r"libicu\w+|libsasl2|libldap[\w.-]*|liblber[\w.-]*|libgssapi_krb5|libkrb5|"
    r"libk5crypto|libcom_err|libkeyutils|libtirpc)\.so"
)
_DEFAULT_LIB_DIRS = (
    "/lib64",
    "/usr/lib64",
    "/lib/x86_64-linux-gnu",
    "/usr/lib/x86_64-linux-gnu",
    "/lib/aarch64-linux-gnu",
    "/usr/lib/aarch64-linux-gnu",
    "/lib/s390x-linux-gnu",
    "/usr/lib/s390x-linux-gnu",
    "/lib",
    "/usr/lib",
)
_WORKER_MAX_DESCENDANTS = 64
_WORKER_MAX_BINARIES = 96
# ELF files opened per listener when walking worker binaries' DT_NEEDED.
_WORKER_ELF_BUDGET = 256
_WORKER_NEEDED_DEPTH = 2


def _ppid(pid: int) -> int | None:
    """Parent pid from /proc/<pid>/stat (the comm field may hold spaces and
    parentheses, so parse after the last ')')."""
    try:
        text = _proc(pid, "stat").read_text()
        return int(text[text.rindex(")") + 2 :].split()[1])
    except (OSError, ValueError, IndexError):
        return None


def _descendants(owner: int, pids: list[int], cache: _Cache) -> list[int]:
    """Descendants of owner among the scanned pids, nearest first."""
    if cache.ppids is None:
        cache.ppids = {}
        for p in pids:
            pp = _ppid(p)
            if pp is not None:
                cache.ppids[p] = pp
    children: dict[int, list[int]] = {}
    for p, pp in cache.ppids.items():
        children.setdefault(pp, []).append(p)
    out: list[int] = []
    frontier = [owner]
    while frontier and len(out) < _WORKER_MAX_DESCENDANTS:
        nxt: list[int] = []
        for p in frontier:
            nxt.extend(sorted(children.get(p, [])))
        out.extend(nxt)
        frontier = nxt
    return out[:_WORKER_MAX_DESCENDANTS]


def _lib_dirs(owner: int) -> list[str]:
    """Library search directories for the owner's root: the directory its
    libc is mapped from first (multiarch layouts differ), then the usual
    ones."""
    dirs: list[str] = []
    try:
        for line in _proc(owner, "maps").read_text().splitlines():
            path = line.split(None, 5)[-1].strip()
            if re.search(r"/libc\.so\.\d+$", path):
                dirs.append(os.path.dirname(path))
                break
    except OSError:
        pass
    return dirs + [d for d in _DEFAULT_LIB_DIRS if d not in dirs]


def _dynamic_through(
    root: Path, path: str, cache: _Cache
) -> dict[str, list[str]] | None:
    key = f"{root}\0{path}"
    if key not in cache.dynamic:
        result = None
        try:
            with (root / path.lstrip("/")).open("rb") as fh:
                result = elf_dynamic(fh)
        except (OSError, ValueError, struct.error) as e:
            log.debug("services: cannot read dynamic section of %s: %s", path, e)
        cache.dynamic[key] = result
    return cache.dynamic[key]


def _linked_crypto_libraries(
    root: Path, binary: str, lib_dirs: list[str], cache: _Cache, budget: list[int]
) -> list[str]:
    """Crypto library paths reachable from binary's DT_NEEDED entries (two
    levels: Postfix's smtpd -> libpostfix-tls.so -> libssl.so.3), resolved
    the way the dynamic linker would for that root: RUNPATH/RPATH (with
    $ORIGIN) first, then the system library directories."""
    found: list[str] = []
    seen: set[str] = set()
    queue: list[tuple[str, int]] = [(binary, 0)]
    while queue and budget[0] > 0:
        path, depth = queue.pop(0)
        if f"{root}\0{path}" not in cache.dynamic:
            budget[0] -= 1
        dyn = _dynamic_through(root, path, cache)
        if not dyn:
            continue
        origin = os.path.dirname(path)
        dirs = [
            d.replace("${ORIGIN}", origin).replace("$ORIGIN", origin)
            for d in dyn["runpath"]
        ] + lib_dirs
        for name in dyn["needed"]:
            if name in seen or _NOT_FOLLOWED.match(name):
                continue
            seen.add(name)
            resolved = next(
                (
                    os.path.join(d, name)
                    for d in dirs
                    if d.startswith("/")
                    and _platform.safe_is_file(root / d.lstrip("/") / name)
                ),
                None,
            )
            if resolved is None:
                continue
            if any(p.match(name) for _f, p in _LIBRARIES):
                found.append(resolved)
            if depth < _WORKER_NEEDED_DEPTH:
                queue.append((resolved, depth + 1))
    return found


def _has_tls_library(paths: list[str]) -> bool:
    """A TLS library, not only libcrypto: daemons and their helpers map
    libcrypto for hashing or through Kerberos/SASL, which says less about
    the TLS stack a worker serves with than libssl / GnuTLS / NSS do."""
    return any(not os.path.basename(p).startswith("libcrypto.") for p in paths)


def _worker_binary_libraries(
    owner: int, worker_dirs: list[str], cache: _Cache
) -> tuple[list[dict[str, Any]], str | None]:
    """Crypto libraries linked by an executable in the directories the
    owner's workers run from, and that executable's path."""
    root = _proc(owner, "root")
    lib_dirs = _lib_dirs(owner)
    budget = [_WORKER_ELF_BUDGET]
    fallback: tuple[list[str], str] | None = None
    chosen: tuple[list[str], str] | None = None
    for d in worker_dirs:
        try:
            names = sorted(os.listdir(root / d.lstrip("/")))[:_WORKER_MAX_BINARIES]
        except OSError:
            continue
        for name in names:
            path = os.path.join(d, name)
            if not _platform.safe_is_file(root / path.lstrip("/")):
                continue
            libs = _linked_crypto_libraries(root, path, lib_dirs, cache, budget)
            if libs and _has_tls_library(libs):
                chosen = (libs, path)
                break
            if libs and fallback is None:
                fallback = (libs, path)
            if budget[0] <= 0:
                break
        if chosen or budget[0] <= 0:
            break
    chosen = chosen or fallback
    if chosen is None:
        return [], None
    entries = []
    for lib_path in chosen[0]:
        base = os.path.basename(lib_path)
        family = next(f for f, p in _LIBRARIES if p.match(base))
        m = _SONAME_VERSION_RE.search(base)
        entries.append(
            _library_details(
                owner,
                {
                    "family": family,
                    "path": lib_path,
                    "soname_version": m.group(1) if m else None,
                    "deleted": False,
                    "map_range": "",
                    "maps_key": None,
                },
                cache,
            )
        )
    return _inherit_libssl_version(entries), chosen[1]


def _worker_crypto(
    owner: int,
    holders: list[int],
    pids: list[int],
    details: dict[int, dict[str, Any]],
    cache: _Cache,
) -> tuple[list[dict[str, Any]], dict[str, Any]] | None:
    """Libraries and their source for an owner that maps none itself (see
    the section comment above), or None."""
    descendants = _descendants(owner, pids, cache)
    candidates = [p for p in holders if p not in (owner, 1)]
    candidates += [p for p in descendants if p not in candidates]

    def from_process(pid: int) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        return details[pid]["crypto_libraries"], {
            "source": "socket-holder" if pid in holders else "descendant",
            "pid": pid,
            "process": details[pid]["process"],
            "exe": details[pid]["exe"],
        }

    crypto_only: int | None = None
    for pid in candidates:
        if pid not in details:
            details[pid] = _process_details(pid, cache)
        paths = [lib["path"] for lib in details[pid]["crypto_libraries"]]
        if paths and _has_tls_library(paths):
            return from_process(pid)
        if paths and crypto_only is None:
            crypto_only = pid
    worker_dirs: list[str] = []
    for pid in descendants:
        exe = _exe(pid)
        d = os.path.dirname(exe) if exe else ""
        if d and d not in _SHARED_BIN_DIRS and d not in worker_dirs:
            worker_dirs.append(d)
    if worker_dirs:
        libs, binary = _worker_binary_libraries(owner, worker_dirs, cache)
        if libs:
            return libs, {"source": "worker-binary", "binary": binary}
    # Last resort: a worker that maps only libcrypto.
    return from_process(crypto_only) if crypto_only is not None else None


def _library_details(pid: int, lib: dict[str, Any], cache: _Cache) -> dict[str, Any]:
    candidates = [_proc(pid, "map_files", lib["map_range"])] if lib["deleted"] else []
    candidates.append(_proc(pid, "root", lib["path"].lstrip("/")))
    family, version, source, markers = lib["family"], None, None, None
    maps_key = lib.get("maps_key")
    for cand in candidates:
        try:
            st = os.stat(cand)
            key = (st.st_dev, st.st_ino)
            if key not in cache.libs:
                blob = _read_capped(cand, _LIB_READ_CAP)
                fam, ver = library_version(lib["family"], blob)
                cache.libs[key] = (fam, ver, library_tls_pqc_markers(fam, blob))
            family, version, markers = cache.libs[key]
            if maps_key:
                cache.by_maps[maps_key] = cache.libs[key]
            source = "embedded" if version else None
            break
        except OSError as e:
            log.debug("services: cannot read %s: %s", cand, e)
    else:
        # Unreadable through this process (private root namespace): the
        # same device + inode already read via another process is the same
        # file.
        if maps_key and maps_key in cache.by_maps:
            family, version, markers = cache.by_maps[maps_key]
            source = "embedded" if version else None
    if (
        version is None
        and lib["soname_version"]
        and lib["soname_version"].count(".") >= 2
    ):
        # e.g. libssl.so.3.5.9 on Fedora/RHEL: the file name carries the
        # release.  Only used when the embedded string is unavailable.
        if lib["family"] == "openssl":
            version, source = lib["soname_version"], "filename"
    return {
        "family": family,
        "path": lib["path"],
        "version": version,
        "version_source": source,
        "deleted": lib["deleted"],
        "library_pqc_capable": library_pqc_capable(family, version, markers),
        "pqc_evidence": (
            "binary"
            if markers is not None
            else (
                "version" if library_pqc_capable(family, version) is not None else None
            )
        ),
    }


def _inherit_libssl_version(libs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """libssl carries no version string of its own; the libcrypto from the
    same directory is the same OpenSSL build, so copy its version (marked
    ``version_source: "sibling-libcrypto"``)."""
    by_dir = {
        os.path.dirname(lib["path"]): lib
        for lib in libs
        if os.path.basename(lib["path"]).startswith("libcrypto.") and lib["version"]
    }
    for lib in libs:
        sibling = by_dir.get(os.path.dirname(lib["path"]))
        if (
            lib["version"] is None
            and sibling
            and os.path.basename(lib["path"]).startswith("libssl.")
        ):
            lib["family"] = sibling["family"]
            lib["version"] = sibling["version"]
            lib["version_source"] = "sibling-libcrypto"
            lib["library_pqc_capable"] = sibling["library_pqc_capable"]
            lib["pqc_evidence"] = sibling["pqc_evidence"]
    return libs


def _process_details(
    pid: int, cache: _Cache, maps: str | None = None
) -> dict[str, Any]:
    """Process identity, mapped crypto libraries and Go details for pid.
    ``maps`` is the already-read /proc/<pid>/maps text when the caller has
    it (--scan-processes reads it first to classify unreadable processes
    and kernel threads, #155)."""
    unit, cgroup = _systemd_unit(pid)
    info: dict[str, Any] = {
        "process": _comm(pid),
        "exe": _exe(pid),
        "systemd_unit": unit,
        "cgroup": cgroup,
        "crypto_libraries": [],
        "static_binary": None,
        "go": None,
    }
    if maps is None:
        try:
            maps = _proc(pid, "maps").read_text()
        except OSError as e:
            log.debug("services: cannot read /proc/%s/maps: %s", pid, e)
            maps = ""
    info["crypto_libraries"] = _inherit_libssl_version(
        [_library_details(pid, lib, cache) for lib in parse_maps_libraries(maps)]
    )
    exe_path = _proc(pid, "exe")
    try:
        st = os.stat(exe_path)
        key = (st.st_dev, st.st_ino)
        if key not in cache.exes:
            cache.exes[key] = analyze_executable(exe_path)
        exe_info = cache.exes[key]
    except OSError as e:
        log.debug("services: cannot stat /proc/%s/exe: %s", pid, e)
        exe_info = _EXE_UNKNOWN
    info["static_binary"] = exe_info["static"]
    go = exe_info["go"]
    if go is not None:
        try:
            environ = _proc(pid, "environ").read_bytes()
        except OSError:
            environ = b""
        go = {
            "go_version": go.get("go_version"),
            "main_module": go.get("main_module"),
            "cgo_enabled": (go.get("settings") or {}).get("CGO_ENABLED"),
            **go_tls_kex_default(go, _go_godebug_from_environ(environ)),
        }
    info["go"] = go
    return info


def scan_services(
    max_pids: int = SERVICES_MAX_PIDS_DEFAULT,
    time_budget_s: float = SERVICES_TIME_BUDGET_S_DEFAULT,
) -> dict[str, Any]:
    """Map listening sockets to their processes and crypto libraries.

    Result: ``{available, listeners: [...], summary, scanned_pids,
    unreadable_pids, truncated, limits}`` or ``{available: False, reason}``.
    Each listener carries the join keys ingestion needs (protocol, family,
    address, port, bind_scope, network_namespace) plus pid(s), process,
    exe, systemd unit, crypto libraries and Go details."""
    if not _platform.is_linux():
        return {
            "available": False,
            "reason": "listening-service scan needs Linux /proc",
        }
    started = time.monotonic()
    pids = _pids()
    if not pids:
        return {"available": False, "reason": "cannot list /proc"}
    host_ns = _netns(1)
    truncated = len(pids) > max_pids
    pids = pids[:max_pids]

    sockets: dict[int, dict[str, Any]] = {}
    owners: dict[int, list[int]] = {}
    seen_ns: set[str | None] = set()
    unreadable = 0
    scanned = 0
    for pid in pids:
        if time.monotonic() - started > time_budget_s:
            truncated = True
            break
        scanned += 1
        ns = _netns(pid)
        if ns not in seen_ns:
            seen_ns.add(ns)
            for s in _listening_sockets(pid):
                s["network_namespace"] = (
                    "host" if ns is not None and ns == host_ns else "other"
                )
                sockets.setdefault(s["inode"], s)
        inodes = _socket_inodes(pid)
        if inodes is None:
            unreadable += 1
            continue
        for inode in inodes:
            owners.setdefault(inode, []).append(pid)

    cache = _Cache()
    details: dict[int, dict[str, Any]] = {}
    listeners: list[dict[str, Any]] = []
    for inode, sock in sockets.items():
        pids_for = sorted(set(owners.get(inode, [])))
        entry: dict[str, Any] = {
            "protocol": sock["protocol"],
            "family": sock["family"],
            "address": sock["address"],
            "port": sock["port"],
            "bind_scope": bind_scope(sock["address"]),
            "network_namespace": sock["network_namespace"],
            "pid": _service_pid(pids_for),
            "pids": pids_for,
        }
        owner = entry["pid"]
        if owner is not None:
            if owner not in details:
                details[owner] = _process_details(owner, cache)
            entry.update(details[owner])
            if not entry["crypto_libraries"] and entry["go"] is None:
                worker = _worker_crypto(owner, pids_for, pids, details, cache)
                if worker is not None:
                    entry["crypto_libraries"] = worker[0]
                    entry["crypto_libraries_from"] = worker[1]
        else:
            entry.update(
                {
                    "process": None,
                    "exe": None,
                    "systemd_unit": None,
                    "cgroup": None,
                    "crypto_libraries": [],
                    "static_binary": None,
                    "go": None,
                }
            )
        listeners.append(entry)
    listeners.sort(key=lambda e: (e["protocol"], e["port"], e["family"], e["address"]))

    by_family: dict[str, int] = {}
    for e in listeners:
        fams = {lib["family"] for lib in e["crypto_libraries"]}
        if e["go"] is not None:
            fams.add("go")
        for f in fams or {"none"}:
            by_family[f] = by_family.get(f, 0) + 1
    result: dict[str, Any] = {
        "available": True,
        "listeners": listeners,
        "summary": {
            "listeners": len(listeners),
            "unattributed_listeners": sum(1 for e in listeners if e["pid"] is None),
            "listeners_by_crypto_family": dict(sorted(by_family.items())),
            "listeners_with_deleted_crypto_library": sum(
                1
                for e in listeners
                if any(lib["deleted"] for lib in e["crypto_libraries"])
            ),
        },
        "scanned_pids": scanned,
        "unreadable_pids": unreadable,
        "truncated": truncated,
        "limits": {"max_pids": max_pids, "time_budget_s": time_budget_s},
    }
    if unreadable:
        result["note"] = (
            f"{unreadable} process(es) could not be inspected; run as root (or with "
            "CAP_SYS_PTRACE and CAP_DAC_READ_SEARCH) for complete attribution"
        )
    container = _platform.host_fs_unavailable_note(
        "Listening-service crypto linkage",
        "/proc/<pid>/{fd,maps,exe,root,net} for host processes (needs hostPID)",
    )
    if container:
        result.update(container)
    return result


@_registry.register_arguments(52)
def add_arguments(ap: argparse.ArgumentParser) -> None:
    """--scan-services."""
    ap.add_argument(
        "--scan-services",
        action="store_true",
        help=(
            "map listening TCP/UDP sockets to their processes and the "
            "crypto library (OpenSSL, GnuTLS, NSS, wolfSSL, Go) each one "
            "actually uses; reads /proc only, needs root for other users' "
            "processes"
        ),
    )
