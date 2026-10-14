"""sshd effective configuration: offered key exchange and host keys (#105).

`ssh -Q kex` (the `ssh_pqc` probe) says what the OpenSSH *client binary*
supports.  What a server actually offers is decided by sshd's effective
configuration, which on every measured distro reaches KexAlgorithms
through an Include chain into the system crypto-policy back-end:

- EL9 / EL10 / Fedora / Stream: /etc/ssh/sshd_config ->
  sshd_config.d/*.conf -> 40-redhat-crypto-policies.conf (or, on EL9.8,
  50-redhat.conf) -> /etc/crypto-policies/back-ends/opensshserver.config
- openSUSE Leap 16: no /etc/ssh/sshd_config; sshd reads the vendor file
  /usr/etc/ssh/sshd_config, whose sshd_config.d/40-suse-crypto-policies.conf
  includes the same back-end.

Measured 2026-10-13 on booted cloud images: Fedora 44, Rocky 10.2,
AlmaLinux 10.2 and CentOS Stream 10 offer mlkem768x25519-sha256 first;
Leap 16.0 offers sntrup761x25519-sha512 first and ML-KEM second; Rocky
9.8 (DEFAULT policy) offers no PQC key exchange although its OpenSSH
9.9 client supports mlkem768x25519-sha256 and sntrup761.

Two sources, best first:
1. `sshd -T`: the exact effective config.  Needs root and a live host,
   so it is only used without --host-mount.
2. Parsing the config files: first obtained value wins, Include globs are
   expanded in lexical order at the point of inclusion, and parsing
   stops at the first `Match` block (its options are conditional).

Host keys are inventoried from the `.pub` half only.  The private key
files named by HostKey are never opened.
"""

from __future__ import annotations

import base64
import binascii
import fnmatch
import hashlib
import logging
import os
import shutil
import struct
from typing import Any, Callable

from .. import _platform as _platform
from .. import algorithms as _algorithms
from ..detect import config_read as _config_read
from ..detect import packages as _packages
from ..detect import protocols as _protocols
from ..detect import runtime as _runtime

log = logging.getLogger("pqc-readiness")

SSHD_CONFIG_CANDIDATES = (
    "/etc/ssh/sshd_config",
    # SUSE vendor config, used when /etc/ssh/sshd_config is absent.
    "/usr/etc/ssh/sshd_config",
)
# OpenSSH's built-in HostKey list when sshd_config names none.
DEFAULT_HOST_KEYS = (
    "/etc/ssh/ssh_host_rsa_key",
    "/etc/ssh/ssh_host_ecdsa_key",
    "/etc/ssh/ssh_host_ed25519_key",
)
_MAX_INCLUDE_DEPTH = 16
_KEYWORDS = ("kexalgorithms", "hostkeyalgorithms")


def _read_host_file(path: str) -> str | None:
    try:
        resolved = _packages.resolve_under_prefix(path, _platform.HOST_PREFIX)
    except _packages.RpmdbError as e:
        log.debug("sshd: cannot resolve %s: %s", path, e)
        return None
    try:
        return _platform.host_path(resolved).read_text(errors="replace")
    except OSError as e:
        log.debug("sshd: cannot read %s (-> %s): %s", path, resolved, e)
        return None


def _read_config(path: str) -> str | None:
    """Config file text; None when absent.  Raises ConfigUnreadable when
    the file exists but this user can't read it (#232)."""
    return _config_read.read_host_text(path)


def _glob_host(pattern: str) -> list[str]:
    """Expand a host glob (only the final component may contain wildcards,
    as in every measured Include line), sorted lexically like sshd.
    Raises ConfigUnreadable when the directory exists but can't be listed."""
    directory, _, name = pattern.rpartition("/")
    if not any(c in name for c in "*?["):
        return [pattern]
    entries = _config_read.list_host_dir(directory or "/") or []
    return [f"{directory}/{e}" for e in entries if fnmatch.fnmatch(e, name)]


def _split_directive(line: str) -> tuple[str, str] | None:
    s = line.strip()
    if not s or s.startswith("#"):
        return None
    for i, ch in enumerate(s):
        if ch.isspace() or ch == "=":
            key, rest = s[:i], s[i:].lstrip(" \t=").strip()
            return key.lower(), rest
    return s.lower(), ""


def parse_sshd_config(
    main_path: str,
    read: Callable[[str], str | None] = _read_config,
    glob: Callable[[str], list[str]] = _glob_host,
) -> dict[str, Any]:
    """Global (pre-`Match`) KexAlgorithms / HostKeyAlgorithms / HostKey
    from `main_path` and everything it includes.  Returns the values plus
    the files read, in order.  Relative Include paths resolve against
    /etc/ssh, as sshd does.

    Files or Include directories that exist but can't be read are listed
    under ``unreadable``.  If one is met before KexAlgorithms is set, the
    value found later (or the compiled-in default) may not be the one
    sshd uses, since the first obtained value wins: ``kex_uncertain``."""
    values: dict[str, str] = {}
    host_keys: list[str] = []
    files: list[str] = []
    unreadable: list[dict[str, str]] = []
    kex_uncertain = False
    stopped_at_match = False

    def skipped(e: _config_read.ConfigUnreadable) -> None:
        nonlocal kex_uncertain
        log.debug("sshd: %s", e)
        unreadable.append(e.as_entry())
        if "kexalgorithms" not in values:
            kex_uncertain = True

    def walk(path: str, depth: int) -> bool:
        """Returns False once a Match block ends global parsing."""
        nonlocal stopped_at_match
        if depth > _MAX_INCLUDE_DEPTH:
            log.debug("sshd: Include depth limit reached at %s", path)
            return True
        try:
            text = read(path)
        except _config_read.ConfigUnreadable as e:
            skipped(e)
            return True
        if text is None:
            return True
        files.append(path)
        for line in text.splitlines():
            d = _split_directive(line)
            if d is None:
                continue
            key, value = d
            if key == "match":
                stopped_at_match = True
                return False
            if key == "include":
                for pat in value.split():
                    if not pat.startswith("/"):
                        pat = f"/etc/ssh/{pat}"
                    try:
                        included = glob(pat)
                    except _config_read.ConfigUnreadable as e:
                        skipped(e)
                        continue
                    for inc in included:
                        if not walk(inc, depth + 1):
                            return False
                continue
            if key == "hostkey" and value:
                host_keys.append(value)
            elif key in _KEYWORDS and key not in values and value:
                values[key] = value
        return True

    walk(main_path, 0)
    return {
        "values": values,
        "host_keys": host_keys,
        "files": files,
        "unreadable": unreadable,
        "kex_uncertain": kex_uncertain,
        "stopped_at_match": stopped_at_match,
    }


def parse_sshd_t(text: str) -> dict[str, Any]:
    """`sshd -T` output: one lower-case `keyword value` per line;
    HostKey repeats."""
    values: dict[str, str] = {}
    host_keys: list[str] = []
    for line in text.splitlines():
        d = _split_directive(line)
        if d is None:
            continue
        key, value = d
        if key == "hostkey":
            host_keys.append(value)
        elif key in _KEYWORDS:
            values[key] = value
    return {"values": values, "host_keys": host_keys}


def _ssh_string(blob: bytes, off: int) -> tuple[bytes, int]:
    if off + 4 > len(blob):
        raise ValueError("truncated SSH wire string")
    (n,) = struct.unpack_from(">I", blob, off)
    end = off + 4 + n
    if end > len(blob):
        raise ValueError("truncated SSH wire string")
    return blob[off + 4 : end], end


def describe_public_key(line: str) -> dict[str, Any] | None:
    """Type, size and SHA-256 fingerprint (ssh-keygen -lf format) of one
    OpenSSH public key line.  The comment is not reported."""
    parts = line.strip().split()
    if len(parts) < 2:
        return None
    key_type, b64 = parts[0], parts[1]
    try:
        blob = base64.b64decode(b64, validate=True)
        inner_type, off = _ssh_string(blob, 0)
    except (binascii.Error, ValueError):
        return None
    out: dict[str, Any] = {
        "type": key_type,
        "fingerprint_sha256": "SHA256:"
        + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("="),
    }
    if inner_type.decode(errors="replace") != key_type:
        out["type_mismatch"] = inner_type.decode(errors="replace")
    try:
        if key_type == "ssh-rsa":
            _e, off = _ssh_string(blob, off)
            n, _ = _ssh_string(blob, off)
            out["bits"] = int.from_bytes(n, "big").bit_length()
        elif key_type.startswith("ecdsa-sha2-nistp"):
            out["bits"] = int(key_type.rsplit("nistp", 1)[1])
        elif key_type in ("ssh-ed25519",):
            out["bits"] = 256
        elif key_type in ("ssh-ed448",):
            out["bits"] = 456
    except (ValueError, IndexError):
        log.debug("sshd: cannot size %s key", key_type)
    lowered = key_type.lower()
    out["pqc"] = any(t in lowered for t in ("mldsa", "ml-dsa", "slhdsa", "slh-dsa"))
    return out


def inventory_host_keys(paths: list[str]) -> list[dict[str, Any]]:
    """Describe each HostKey from its `.pub` file.  Only `<path>.pub` is
    read; the private key path itself is never opened."""
    out: list[dict[str, Any]] = []
    for path in paths:
        pub = path if path.endswith(".pub") else f"{path}.pub"
        text = _read_host_file(pub)
        entry: dict[str, Any] = {"path": path}
        if text is None:
            entry["readable"] = False
        else:
            desc = describe_public_key(text.splitlines()[0] if text.strip() else "")
            if desc is None:
                entry["readable"] = False
                entry["reason"] = "unparseable public key"
            else:
                entry.update(readable=True, **desc)
        out.append(entry)
    return out


def _can_run_sshd_t() -> bool:
    return (
        not _platform.HOST_PREFIX
        and hasattr(os, "geteuid")
        and os.geteuid() == 0
        and _sshd_binary() is not None
    )


def _sshd_binary() -> str | None:
    for candidate in ("sshd", "/usr/sbin/sshd"):
        found = shutil.which(candidate)
        if found:
            return found
    return None


def _offered_fields(offered: list[str]) -> dict[str, Any]:
    """The kex fields derived from a concrete offered list."""
    groups = _protocols.classify_ssh_kex(offered)
    pqc_names = set(groups["pure_pqc"]) | set(groups["hybrid"])
    return {
        "kex_offered": offered,
        "kex_groups": groups,
        "kex_references": _algorithms.ssh_kex_references(sorted(pqc_names)),
        "first_kex": offered[0] if offered else None,
        "pqc_offered": bool(pqc_names),
        "pqc_first": bool(offered) and offered[0] in pqc_names,
    }


def detect_sshd(ssh_client: dict[str, Any] | None = None) -> dict[str, Any]:
    """Effective sshd key exchange and host keys.

    `ssh_client` is the `ssh_pqc` probe result; its kex buckets stand in
    for what the installed OpenSSH can do (client and server ship in the
    same OpenSSH build on every measured distro)."""
    parsed: dict[str, Any] | None = None
    source = None
    files: list[str] = []
    unreadable: list[dict[str, str]] = []
    kex_uncertain = False
    if _can_run_sshd_t():
        rc, out = _platform._run([_sshd_binary() or "sshd", "-T"], timeout=10)
        if rc == 0 and "kexalgorithms" in out.lower():
            parsed = parse_sshd_t(out)
            source = "sshd -T"
        else:
            log.debug("sshd: sshd -T failed (rc=%s); parsing config files", rc)
    if parsed is None:
        main = None
        for candidate in SSHD_CONFIG_CANDIDATES:
            try:
                if _read_config(candidate) is not None:
                    main = candidate
                    break
            except _config_read.ConfigUnreadable as e:
                # sshd uses /etc/ssh/sshd_config whenever it exists, so an
                # unreadable one ends the search; the vendor file isn't it.
                unreadable.append(e.as_entry())
                break
        if main is None:
            result: dict[str, Any]
            if unreadable:
                u = unreadable[0]
                result = {
                    "available": False,
                    "reason": f"{u['path']} is not readable ({u['reason']})",
                    "unreadable": unreadable,
                }
            else:
                result = {
                    "available": False,
                    "reason": "no sshd_config found (/etc/ssh or /usr/etc/ssh)",
                }
            note = _runtime._host_fs_note_for("sshd")
            if note:
                result.update(note)
            return result
        cfg = parse_sshd_config(main)
        parsed = {"values": cfg["values"], "host_keys": cfg["host_keys"]}
        files = cfg["files"]
        unreadable = cfg["unreadable"]
        kex_uncertain = cfg["kex_uncertain"]
        source = "config files"

    values = parsed["values"]
    raw_kex = values.get("kexalgorithms")
    result = {"available": True, "source": source}
    if files:
        result["config_files"] = files
    if unreadable:
        result["unreadable"] = unreadable
    if kex_uncertain:
        # An unreadable file came before any KexAlgorithms line; it may
        # set the value sshd actually uses (first obtained value wins).
        result.update(
            kex_offered=None,
            kex_source="unreadable-config",
            pqc_offered=None,
            pqc_first=None,
        )
    elif raw_kex is None and (ssh_client or {}).get("default_kex"):
        # Nothing sets KexAlgorithms, and the build's compiled-in default
        # was read unambiguously from its server binary (offline, #247).
        default = (ssh_client or {})["default_kex"]
        result.update(_offered_fields(list(default["kex"])))
        result.update(
            kex_source="openssh-compiled-default",
            kex_default_source={"source": "binary", "binary": default["binary"]},
        )
    elif raw_kex is None:
        # Nothing sets KexAlgorithms: sshd uses its compiled-in default,
        # which depends on the OpenSSH version.  Report unknown rather
        # than guessing.
        result.update(
            kex_offered=None,
            kex_source="openssh-compiled-default",
            pqc_offered=None,
            pqc_first=None,
        )
    elif raw_kex[:1] in "+-^":
        # Relative to the compiled-in default (e.g. `+sntrup761...`);
        # the full list isn't knowable without sshd -T.
        names = [k for k in raw_kex[1:].split(",") if k]
        result.update(
            kex_offered=None,
            kex_source="openssh-compiled-default",
            kex_modifier={"operator": raw_kex[0], "algorithms": names},
            pqc_offered=None,
            pqc_first=None,
        )
    else:
        result.update(_offered_fields([k for k in raw_kex.split(",") if k]))
        result["kex_source"] = "configured"
    hka = values.get("hostkeyalgorithms")
    if hka and hka[:1] not in "+-^":
        result["host_key_algorithms"] = [a for a in hka.split(",") if a]
    host_key_paths = parsed["host_keys"] or list(DEFAULT_HOST_KEYS)
    result["host_keys"] = inventory_host_keys(host_key_paths)
    result["host_keys_pqc"] = any(k.get("pqc") for k in result["host_keys"])

    client = ssh_client or {}
    cg = client.get("kex_groups")
    if client.get("available") and isinstance(cg, dict):
        result["openssh_supports_pqc_kex"] = bool(
            cg.get("hybrid") or cg.get("pure_pqc")
        )
        if client.get("source") == "binary":
            # Offline: read from the build's binaries, not `ssh -Q kex` (#247).
            result["openssh_kex_evidence"] = {
                "source": "binary",
                "binaries": client.get("binaries") or [],
                "pqc_kex": sorted(
                    (cg.get("hybrid") or []) + (cg.get("pure_pqc") or [])
                ),
            }
    else:
        # No client probe, or a kex list that couldn't be read (#256).
        result["openssh_supports_pqc_kex"] = None

    note = _runtime._host_fs_note_for("sshd")
    if note:
        result.update(note)
    return result


def sshd_pqc_gap(sshd: dict[str, Any]) -> str | None:
    """'not_offered' when the installed OpenSSH supports a PQC kex but the
    effective sshd config offers none; 'not_first' when it is offered but
    a classical method is preferred.  None otherwise (including unknown)."""
    if not sshd.get("available") or not sshd.get("openssh_supports_pqc_kex"):
        return None
    if sshd.get("pqc_offered") is False:
        return "not_offered"
    if sshd.get("pqc_offered") and sshd.get("pqc_first") is False:
        return "not_first"
    return None


__all__ = [
    "DEFAULT_HOST_KEYS",
    "SSHD_CONFIG_CANDIDATES",
    "describe_public_key",
    "detect_sshd",
    "inventory_host_keys",
    "parse_sshd_config",
    "parse_sshd_t",
    "sshd_pqc_gap",
]
