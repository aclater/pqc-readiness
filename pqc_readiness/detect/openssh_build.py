# SPDX-License-Identifier: Apache-2.0
"""Key exchange methods compiled into a host's or tree's OpenSSH build,
read from its binaries without running them (#247).

`ssh -Q kex` is the authoritative list on a live host, but an offline
`--root` tree can't run its own binaries.  OpenSSH compiles its kex name
table (kex-names.c) into `ssh`, `sshd` and `sshd-session` as
NUL-terminated strings, so reading those strings gives the same list,
backports included: Rocky 9's OpenSSH 8.7 offers mlkem768x25519-sha256,
which upstream added in 9.9, so a version table would be wrong there.

Names are kept only when `classify_ssh_kex` recognises them, so stray
strings in the binary can't add methods.
"""

from __future__ import annotations

import logging
import re
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
    "/usr/sbin/sshd",
)


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


def kex_names_in(data: bytes) -> set[str]:
    """Candidate kex method names in a binary's bytes."""
    out: set[str] = set()
    for m in _KEX_NAME_RE.finditer(data):
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


def _read_binary_names(path: str) -> set[str] | None:
    """Kex-like names in the host/tree binary at `path`; None when absent
    or unreadable."""
    data = _read_binary(path)
    return None if data is None else kex_names_in(b"\x00" + data)


def openssh_build_kex() -> dict[str, Any] | None:
    """The kex methods compiled into the host's or tree's OpenSSH build,
    shaped like the `ssh_pqc` probe (`available`, `kex_groups`) so
    `detect_sshd` can use it as the client evidence.  None when no OpenSSH
    binary is present or readable."""
    found: dict[str, list[str]] = {}
    for path in OPENSSH_BINARIES:
        names = _read_binary_names(path)
        if not names:
            continue
        groups = _protocols.classify_ssh_kex(sorted(names))
        recognised = groups["pure_pqc"] + groups["hybrid"] + groups["classical"]
        if recognised:
            found[path] = sorted(recognised)
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
]
