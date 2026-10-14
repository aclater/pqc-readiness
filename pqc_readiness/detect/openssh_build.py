# SPDX-License-Identifier: Apache-2.0
"""Key exchange methods compiled into a host's or tree's OpenSSH build,
read from its binaries without running them (#247).

`ssh -Q kex` is the authoritative list on a live host, but an offline
`--root` tree can't run its own binaries, and under `--host-mount` the
`ssh` on PATH is the scanner image's (#256).  OpenSSH compiles its kex name
table (kex-names.c) into `ssh`, `sshd` and `sshd-session` as
NUL-terminated strings, so reading those strings gives the same list,
backports included: Rocky 9's OpenSSH 8.7 offers mlkem768x25519-sha256,
which upstream added in 9.9, so a version table would be wrong there.

In an ELF binary a name counts only when the kex table points at it
(see `referenced_kex_names`): name matching alone overcounts on Rocky 9,
whose binary carries a proposal list naming two ML-KEM kexes its table
lacks, and NUL-bounded strings undercount on Alpine, whose linker
tail-merges table names into those lists.  Names are also kept only when
`classify_ssh_kex` recognises them, so stray strings can't add methods.
"""

from __future__ import annotations

import logging
import re
import struct
from typing import Any

from ..detect import config_read as _config_read
from ..detect import protocols as _protocols

log = logging.getLogger("pqc_readiness")

# Server binaries first (sshd-session does the kex from OpenSSH 9.8 on),
# then the client, which ships in the same build on every measured distro.
OPENSSH_BINARIES: tuple[str, ...] = (
    "/usr/sbin/sshd",
    "/usr/libexec/openssh/sshd-session",  # EL, Fedora
    "/usr/lib/openssh/sshd-session",  # Debian, Ubuntu
    "/usr/libexec/ssh/sshd-session",  # openSUSE
    "/usr/lib/ssh/sshd-session",  # Alpine
    "/usr/bin/ssh",
)

# sshd is about 1 MiB on every measured distro; the cap only bounds a
# corrupt or hostile file.
MAX_BINARY_BYTES = 32 * 1024 * 1024
# A kex method name as stored in the binary: lower-case, NUL-terminated,
# preceded by a NUL (or the start of the read).
_KEX_NAME_RE = re.compile(rb"(?<=\x00)([a-z0-9][a-z0-9@.\-]{8,63})(?=\x00)")
_KEX_HINT_RE = re.compile(rb"sha\d|@openssh\.com|@libssh\.org")
# A comma-joined method list (myproposal.h's default proposals).
_KEX_LIST_RE = re.compile(rb"(?<=\x00)([a-z0-9@.\-]+(?:,[a-z0-9@.\-]+){2,})(?=\x00)")
_SERVER_BINARIES: tuple[str, ...] = (
    "/usr/libexec/openssh/sshd-session",
    "/usr/lib/openssh/sshd-session",
    "/usr/libexec/ssh/sshd-session",
    "/usr/lib/ssh/sshd-session",
    "/usr/sbin/sshd",
)
# A complete kex method name in the forms `ssh -Q kex` prints, bounded so
# fragments (a bare "mlkem768", "kexmlkem768x25519.c", a "gss-...-"
# prefix) don't count.  Used with the kex-table pointer check below.
_KEX_METHOD_RE = re.compile(
    rb"(?<![A-Za-z0-9@._-])("
    rb"diffie-hellman-group(?:\d+|-exchange)-sha\d+"
    rb"|ecdh-sha2-nistp\d+"
    rb"|curve(?:25519|448)-sha\d+(?:@libssh\.org)?"
    rb"|(?:sntrup\d+|mlkem\d+)[a-z0-9]*-sha\d+(?:@openssh\.com)?"
    rb")(?![A-Za-z0-9@._-])"
)
_EMBEDDED_VERSION_RE = re.compile(rb"OpenSSH_(\d+\.\d+(?:p\d+)?)")


def _is_kex_list(items: list[str]) -> bool:
    g = _protocols.classify_ssh_kex(items)
    return len(g["pure_pqc"]) + len(g["hybrid"]) + len(g["classical"]) == len(items)


def kex_lists_in(data: bytes) -> list[list[str]]:
    """Distinct comma-joined lists in a binary whose every item is a
    recognised kex method, in first-seen order."""
    seen: list[list[str]] = []
    for m in _KEX_LIST_RE.finditer(data):
        items = m.group(1).decode("ascii").split(",")
        if _is_kex_list(items) and items not in seen:
            seen.append(items)
    return seen


def referenced_kex_names(data: bytes) -> set[str] | None:
    """The kex names an ELF binary's kex table points at.

    OpenSSH's table is an array of structs whose first member points at
    the name.  In a position-independent binary that pointer is a word
    equal to the string's address: a RELA relocation's addend, or the
    value stored in place (RELR, REL, non-PIE).  A name inside a proposal
    list has no pointer to its own start, while a table name the linker
    tail-merged into the end of a list (Alpine's ecdh-sha2-nistp521)
    still does.  So a name counts when some aligned word in the file
    equals its address.  None when `data` isn't a parseable ELF."""
    if data[:4] != b"\x7fELF" or data[4] not in (1, 2) or data[5] not in (1, 2):
        return None
    is64 = data[4] == 2
    end = "<" if data[5] == 1 else ">"
    loads: list[tuple[int, int, int]] = []
    try:
        if is64:
            (phoff,) = struct.unpack_from(end + "Q", data, 0x20)
            phentsize, phnum = struct.unpack_from(end + "HH", data, 0x36)
        else:
            (phoff,) = struct.unpack_from(end + "I", data, 0x1C)
            phentsize, phnum = struct.unpack_from(end + "HH", data, 0x2A)
        for i in range(phnum):
            o = phoff + i * phentsize
            if is64:
                ptype, _, off, vaddr, _, filesz = struct.unpack_from(
                    end + "IIQQQQ", data, o
                )
            else:
                ptype, off, vaddr, _, filesz = struct.unpack_from(
                    end + "IIIII", data, o
                )
            if ptype == 1:  # PT_LOAD
                loads.append((off, vaddr, filesz))
    except struct.error:
        return None
    if not loads:
        return None
    width = 8 if is64 else 4
    words = {
        w[0]
        for w in struct.iter_unpack(
            end + ("Q" if is64 else "I"), data[: len(data) - len(data) % width]
        )
    }
    out: set[str] = set()
    for m in _KEX_METHOD_RE.finditer(data):
        fo = m.start(1)
        for off, vaddr, size in loads:
            if off <= fo < off + size:
                if fo - off + vaddr in words:
                    out.add(m.group(1).decode("ascii"))
                break
    return out


def kex_names_in(data: bytes) -> set[str]:
    """Kex method names in a binary's bytes: the ones its kex table points
    at for an ELF binary, else NUL-bounded strings that look like kex
    names (e.g. a `strings` excerpt)."""
    referenced = referenced_kex_names(data)
    if referenced is not None:
        return referenced
    out: set[str] = set()
    for m in _KEX_NAME_RE.finditer(b"\x00" + data):
        raw = m.group(1)
        if _KEX_HINT_RE.search(raw):
            out.add(raw.decode("ascii"))
    return out


def _read_binary(path: str) -> bytes | None:
    """The host/tree binary at `path`, up to MAX_BINARY_BYTES; None when
    absent or unreadable."""
    try:
        target = _config_read.host_file(path)
    except _config_read.ConfigUnreadable as e:
        log.debug("openssh: %s", e)
        return None
    try:
        with open(target, "rb") as fh:
            return fh.read(MAX_BINARY_BYTES)
    except OSError as e:
        log.debug("openssh: cannot read %s (-> %s): %s", path, target, e)
        return None


def openssh_version_in(data: bytes) -> str | None:
    """The OpenSSH version a binary embeds, in `ssh -V`'s form ("10.2p1").
    Builds carry both "OpenSSH_10.2" and "OpenSSH_10.2p1"; the portable
    form wins."""
    versions = {m.group(1).decode("ascii") for m in _EMBEDDED_VERSION_RE.finditer(data)}
    if not versions:
        return None
    return max(versions, key=lambda v: ("p" in v, len(v)))


def openssh_build_kex() -> dict[str, Any] | None:
    """The kex methods compiled into the host's or tree's OpenSSH build,
    shaped like the `ssh_pqc` probe (`available`, `kex_groups`) so
    `detect_sshd` can use it as the client evidence.  None when no OpenSSH
    binary is present or readable."""
    found: dict[str, list[str]] = {}
    version: str | None = None
    for path in OPENSSH_BINARIES:
        data = _read_binary(path)
        if data is None:
            continue
        names = kex_names_in(data)
        groups = _protocols.classify_ssh_kex(sorted(names))
        recognised = groups["pure_pqc"] + groups["hybrid"] + groups["classical"]
        if recognised:
            found[path] = sorted(recognised)
            # The server binary comes first, so its version wins.
            version = version or openssh_version_in(data)
    if not found:
        return None
    union = sorted({n for names in found.values() for n in names})
    groups = _protocols.classify_ssh_kex(union)
    out: dict[str, Any] = {
        "available": True,
        "source": "binary",
        "binaries": sorted(found),
        "kex": union,
        "kex_groups": groups,
        "version": version,
    }
    default = compiled_default_kex()
    if default is not None:
        out["default_kex"] = default
    return out


def compiled_default_kex() -> dict[str, Any] | None:
    """sshd's compiled-in default KexAlgorithms, read from the server
    binary (sshd-session, else sshd).  Only when the binary holds exactly
    one kex list: distro builds that add others (an EL build carries FIPS
    and ML-KEM-only lists too) can't be told apart, so they stay unknown."""
    for path in _SERVER_BINARIES:
        data = _read_binary(path)
        if data is None:
            continue
        lists = kex_lists_in(b"\x00" + data)
        if len(lists) == 1:
            return {"kex": lists[0], "binary": path}
        log.debug(
            "openssh: %d kex lists in %s; default not determinable", len(lists), path
        )
        return None
    return None


__all__ = [
    "MAX_BINARY_BYTES",
    "OPENSSH_BINARIES",
    "compiled_default_kex",
    "kex_lists_in",
    "kex_names_in",
    "openssh_build_kex",
    "openssh_version_in",
    "referenced_kex_names",
]
