"""Kerberos encryption types and PKINIT (--scan-kerberos, #109).

Kerberos tickets and keytab keys are symmetric, so the quantum concern is
Grover's algorithm (a 128-bit key keeps ~64-bit security; CNSA 2.0
requires AES-256) plus the legacy DES / 3DES / RC4 enctypes the IETF has
deprecated.  PKINIT is the asymmetric exception: it uses RSA / (EC)DH,
and post-quantum PKINIT exists only as an individual Internet-Draft
(draft-bokovoy-kitten-pkinit-pqc-02).

Read in-process, no subprocess:

* ``krb5.conf`` (``KRB5_CONFIG`` is not consulted: it describes the
  scanner's environment, not the host) with ``include`` / ``includedir``
  followed, symlinks resolved under the host prefix, so the RHEL
  crypto-policies back-end in ``/etc/krb5.conf.d`` is read from the host.
  Enctype lists are expanded with MIT's rules (doc/admin/conf_files/
  kdc_conf.rst "Encryption types": aliases, families, ``DEFAULT``,
  ``-`` removal); an unset list is MIT's built-in default
  (doc/conf.py ``|defetypes|``).
* ``kdc.conf``: ``supported_enctypes`` and ``master_key_type`` per realm.
* Keytabs, parsed from MIT's FILE keytab format (doc/formats/
  keytab_file_format.rst): principal, timestamp-free kvno and enctype.
  Key bytes are stepped over and never stored.

Enctype numbers and deprecation status follow the IANA "Kerberos
Encryption Type Numbers" registry (RFC 3961 / 3962 / 6649 / 6803 / 8009 /
8429).
"""

from __future__ import annotations

import argparse
import logging
import re
import struct
from pathlib import Path
from typing import Any

from .. import _platform as _platform
from .. import registry as _registry
from . import certs as _certs
from . import packages as _packages

log = logging.getLogger("pqc-readiness")


# ---------------------------------------------------------------------------
# Enctypes (IANA Kerberos Encryption Type Numbers)
# ---------------------------------------------------------------------------

# etype -> (canonical MIT name, status).  status: "deprecated" (IETF
# deprecated: RFC 6649 / 8429), "aes128" (128-bit key: Grover leaves ~64-bit
# security; CNSA 2.0 requires 256-bit), "ok" (256-bit).
ENCTYPES: dict[int, tuple[str, str]] = {
    1: ("des-cbc-crc", "deprecated"),
    2: ("des-cbc-md4", "deprecated"),
    3: ("des-cbc-md5", "deprecated"),
    5: ("des3-cbc-md5", "deprecated"),
    7: ("des3-cbc-sha1", "deprecated"),
    16: ("des3-cbc-sha1", "deprecated"),
    17: ("aes128-cts-hmac-sha1-96", "aes128"),
    18: ("aes256-cts-hmac-sha1-96", "ok"),
    19: ("aes128-cts-hmac-sha256-128", "aes128"),
    20: ("aes256-cts-hmac-sha384-192", "ok"),
    23: ("arcfour-hmac", "deprecated"),
    24: ("arcfour-hmac-exp", "deprecated"),
    25: ("camellia128-cts-cmac", "aes128"),
    26: ("camellia256-cts-cmac", "ok"),
}
_NAME_STATUS = {name: status for name, status in ENCTYPES.values()}

# MIT aliases (kdc_conf.rst "Encryption types") -> canonical names.
_ALIASES: dict[str, list[str]] = {
    "des3-cbc-raw": ["des3-cbc-raw"],
    "des3-hmac-sha1": ["des3-cbc-sha1"],
    "des3-cbc-sha1-kd": ["des3-cbc-sha1"],
    "aes256-cts": ["aes256-cts-hmac-sha1-96"],
    "aes256-sha1": ["aes256-cts-hmac-sha1-96"],
    "aes128-cts": ["aes128-cts-hmac-sha1-96"],
    "aes128-sha1": ["aes128-cts-hmac-sha1-96"],
    "aes256-sha2": ["aes256-cts-hmac-sha384-192"],
    "aes128-sha2": ["aes128-cts-hmac-sha256-128"],
    "rc4-hmac": ["arcfour-hmac"],
    "arcfour-hmac-md5": ["arcfour-hmac"],
    "rc4-hmac-exp": ["arcfour-hmac-exp"],
    "arcfour-hmac-md5-exp": ["arcfour-hmac-exp"],
    "camellia256-cts": ["camellia256-cts-cmac"],
    "camellia128-cts": ["camellia128-cts-cmac"],
    # Families.
    "des3": ["des3-cbc-sha1"],
    "aes": [
        "aes256-cts-hmac-sha1-96",
        "aes128-cts-hmac-sha1-96",
        "aes256-cts-hmac-sha384-192",
        "aes128-cts-hmac-sha256-128",
    ],
    "rc4": ["arcfour-hmac"],
    "camellia": ["camellia256-cts-cmac", "camellia128-cts-cmac"],
    "des": ["des-cbc-crc", "des-cbc-md4", "des-cbc-md5"],
}
_NAME_STATUS["des3-cbc-raw"] = "deprecated"

# MIT krb5 built-in default for permitted / default_tgs / default_tkt
# enctypes (doc/conf.py |defetypes|).  allow_weak_crypto=false filters only
# the "weak" types, so des3-cbc-sha1 and arcfour-hmac stay in the default.
MIT_DEFAULT_ENCTYPES: list[str] = [
    "aes256-cts-hmac-sha1-96",
    "aes128-cts-hmac-sha1-96",
    "aes256-cts-hmac-sha384-192",
    "aes128-cts-hmac-sha256-128",
    "des3-cbc-sha1",
    "arcfour-hmac",
    "camellia256-cts-cmac",
    "camellia128-cts-cmac",
]
# "weak" in MIT's table (filtered unless allow_weak_crypto = true).
_MIT_WEAK = {
    "des-cbc-crc",
    "des-cbc-md4",
    "des-cbc-md5",
    "arcfour-hmac-exp",
    "des3-cbc-raw",
}

ENCTYPE_LIST_KEYS = (
    "permitted_enctypes",
    "default_tkt_enctypes",
    "default_tgs_enctypes",
)


def enctype_status(name: str) -> str:
    return _NAME_STATUS.get(name, "unknown")


def expand_enctypes(value: str | None, allow_weak: bool = False) -> list[str]:
    """Expand an MIT enctype list (space / comma separated) to canonical
    names in order: aliases and families expanded, DEFAULT inserted, `-x`
    removes, weak types filtered unless allow_weak_crypto."""
    if value is None:
        tokens = ["DEFAULT"]
    else:
        tokens = [t for t in re.split(r"[\s,]+", value) if t]
    out: list[str] = []
    for tok in tokens:
        remove = tok.startswith("-")
        tok = tok.lstrip("+-").lower()
        if tok == "default":
            names = list(MIT_DEFAULT_ENCTYPES)
        else:
            names = _ALIASES.get(tok, [tok])
        for n in names:
            if remove:
                out = [x for x in out if x != n]
            elif n not in out:
                out.append(n)
    if not allow_weak:
        out = [n for n in out if n not in _MIT_WEAK]
    return out


# ---------------------------------------------------------------------------
# krb5.conf / kdc.conf (MIT profile format)
# ---------------------------------------------------------------------------

KRB5_CONF = "/etc/krb5.conf"
KDC_CONF_PATHS = ("/var/kerberos/krb5kdc/kdc.conf", "/etc/krb5kdc/kdc.conf")
MAX_CONF_BYTES = 1024 * 1024
MAX_INCLUDES = 64
_INCLUDEDIR_NAME = re.compile(r"^[A-Za-z0-9_-]+$|\.conf$")


def _host_file(path: str) -> Path:
    resolved = _packages.resolve_under_prefix(path, _platform.HOST_PREFIX)
    return Path(_platform.HOST_PREFIX + resolved)


def _read(path: str) -> str | None:
    try:
        p = _host_file(path)
        if p.stat().st_size > MAX_CONF_BYTES:
            log.debug("kerberos: %s is larger than %d bytes", path, MAX_CONF_BYTES)
            return None
        return p.read_text(errors="replace")
    except (OSError, _packages.RpmdbError) as e:
        log.debug("kerberos: cannot read %s: %s", path, e)
        return None


def parse_profile(text: str) -> tuple[dict[str, dict[str, Any]], list[tuple[str, str]]]:
    """Parse MIT profile text into {section: {tag: value-or-subsection}}
    plus the include / includedir directives, in order.  Subsections
    (``tag = { ... }``) become nested dicts; repeated tags keep the first
    value, as MIT does for single-valued relations."""
    sections: dict[str, dict[str, Any]] = {}
    directives: list[tuple[str, str]] = []
    current: dict[str, Any] | None = None
    stack: list[dict[str, Any]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line[0] in "#;":
            continue
        m = re.match(r"^(include|includedir)\s+(\S.*)$", line)
        if m and not stack:
            directives.append((m.group(1), m.group(2).strip()))
            continue
        m = re.match(r"^\[([^\]]+)\]", line)
        if m:
            current = sections.setdefault(m.group(1).strip(), {})
            stack = []
            continue
        if current is None:
            continue
        if line.startswith("}"):
            if stack:
                stack.pop()
            continue
        m = re.match(r"^([^=\s]+)\s*=\s*(.*?)\s*$", line)
        if not m:
            continue
        tag, value = m.group(1).lower(), m.group(2)
        target = stack[-1] if stack else current
        if value == "{":
            existing = target.get(tag)
            sub: dict[str, Any] = existing if isinstance(existing, dict) else {}
            target[tag] = sub
            stack.append(sub)
        elif tag not in target:
            target[tag] = value
    return sections, directives


def _merge(into: dict[str, dict[str, Any]], new: dict[str, dict[str, Any]]) -> None:
    for name, rel in new.items():
        dest = into.setdefault(name, {})
        for k, v in rel.items():
            dest.setdefault(k, v)


def read_krb5_conf(
    path: str = KRB5_CONF,
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """Merged profile from `path` and everything it includes, and the list
    of files read (host paths, in order)."""
    merged: dict[str, dict[str, Any]] = {}
    files: list[str] = []
    queue = [path]
    while queue and len(files) < MAX_INCLUDES:
        f = queue.pop(0)
        if f in files:
            continue
        text = _read(f)
        if text is None:
            continue
        files.append(f)
        sections, directives = parse_profile(text)
        _merge(merged, sections)
        for kind, target in directives:
            if kind == "include":
                queue.append(target)
                continue
            try:
                d = _host_file(target)
                names = sorted(
                    e.name for e in d.iterdir() if e.is_file() or e.is_symlink()
                )
            except (OSError, _packages.RpmdbError) as e:
                log.debug("kerberos: cannot list includedir %s: %s", target, e)
                continue
            queue.extend(
                f"{target.rstrip('/')}/{n}" for n in names if _INCLUDEDIR_NAME.search(n)
            )
    return merged, files


def _bool(value: Any) -> bool | None:
    if not isinstance(value, str):
        return None
    v = value.strip().lower()
    if v in ("true", "yes", "on", "1"):
        return True
    if v in ("false", "no", "off", "0"):
        return False
    return None


def _file_certificates(value: str) -> dict[str, Any]:
    """Certificates in a PKINIT ``FILE:`` value (``FILE:cert[,key]``); only
    the certificate half is read."""
    cert_path = value[5:].split(",", 1)[0]
    out: dict[str, Any] = {"path": cert_path}
    try:
        f = _host_file(cert_path)
        if not f.exists():
            out.update(exists=False)
            return out
        ders = _certs._certs_in_file(f)
    except (OSError, _packages.RpmdbError) as e:
        log.debug("kerberos: cannot read PKINIT file %s: %s", cert_path, e)
        out.update(exists=True, reason=str(e))
        return out
    categories: dict[str, int] = {}
    algorithms: set[str] = set()
    for der in ders:
        try:
            c = _certs.parse_certificate(der)
        except _certs.DERError:
            continue
        categories[c["category"]] = categories.get(c["category"], 0) + 1
        size = c.get("key_size")
        algorithms.add(
            f"{c['key_algorithm']}-{size}"
            if c["key_algorithm"] == "RSA"
            else str(c["key_algorithm"])
        )
    out.update(
        exists=True,
        certificates=sum(categories.values()),
        categories=categories,
        key_algorithms=sorted(algorithms),
    )
    return out


def _pkinit(profile: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """PKINIT settings found in libdefaults, realms and kdcdefaults.
    Anchors alone (Fedora's stock krb5.conf names the system CA bundle)
    don't mean PKINIT is used; an identity does."""
    settings: dict[str, str] = {}
    for sec in ("libdefaults", "realms", "kdcdefaults"):
        stack: list[Any] = [profile.get(sec) or {}]
        while stack:
            node = stack.pop()
            for k, v in node.items():
                if isinstance(v, dict):
                    stack.append(v)
                elif k.startswith("pkinit_"):
                    settings.setdefault(k, v)
    anchors = settings.get("pkinit_anchors")
    identity = settings.get("pkinit_identity") or settings.get("pkinit_identities")
    out: dict[str, Any] = {
        "settings": sorted(settings),
        "anchors": _file_certificates(anchors)
        if anchors and anchors.startswith("FILE:")
        else ({"value": anchors.split(":", 1)[0] + ":..."} if anchors else None),
        "identity_configured": identity is not None,
        "identity": None,
    }
    if identity:
        if identity.startswith("FILE:"):
            out["identity"] = _file_certificates(identity)
        else:
            # PKCS11:, PKCS12:, DIR:, ENV: — the store type only.
            out["identity"] = {"store": identity.split(":", 1)[0]}
    return out


def kerberos_config(profile: dict[str, dict[str, Any]]) -> dict[str, Any]:
    lib = profile.get("libdefaults") or {}
    allow_weak = _bool(lib.get("allow_weak_crypto"))
    lists: dict[str, Any] = {}
    permitted_raw = lib.get("permitted_enctypes")
    for key in ENCTYPE_LIST_KEYS:
        raw = lib.get(key)
        source = "configured"
        if raw is None and key != "permitted_enctypes" and permitted_raw is not None:
            # From 1.18, permitted_enctypes is the default for the other two.
            raw, source = permitted_raw, "permitted_enctypes"
        elif raw is None:
            source = "mit_default"
        expanded = expand_enctypes(
            raw if isinstance(raw, str) else None, bool(allow_weak)
        )
        lists[key] = {"raw": raw, "source": source, "enctypes": expanded}
    return {
        "allow_weak_crypto": allow_weak,
        "default_keytab_name": lib.get("default_keytab_name"),
        "enctype_lists": lists,
        "pkinit": _pkinit(profile),
    }


def read_kdc_conf() -> dict[str, Any] | None:
    for path in KDC_CONF_PATHS:
        text = _read(path)
        if text is None:
            continue
        sections, _ = parse_profile(text)
        realms: dict[str, Any] = {}
        for realm, rel in (sections.get("realms") or {}).items():
            if not isinstance(rel, dict):
                continue
            supported = rel.get("supported_enctypes")
            names = (
                [t.split(":", 1)[0] for t in re.split(r"[\s,]+", supported) if t]
                if isinstance(supported, str)
                else []
            )
            realms[realm] = {
                "supported_enctypes": [n for x in names for n in _ALIASES.get(x, [x])],
                "master_key_type": rel.get("master_key_type"),
            }
        return {"path": path, "realms": realms}
    return None


# ---------------------------------------------------------------------------
# Keytabs (MIT FILE keytab format)
# ---------------------------------------------------------------------------

MAX_KEYTAB_BYTES = 16 * 1024 * 1024
DEFAULT_KEYTABS = ("/etc/krb5.keytab",)
KEYTAB_GLOBS = ("/etc/*.keytab", "/etc/*/*.keytab", "/etc/*/*/*.keytab")


class KeytabError(ValueError):
    """Malformed keytab."""


def parse_keytab(data: bytes) -> dict[str, Any]:
    """Principals, kvnos and enctypes of a FILE keytab.  Key contents are
    skipped by length and never kept."""
    if len(data) < 2 or data[0] != 5 or data[1] not in (1, 2):
        raise KeytabError("not an MIT keytab (bad version bytes)")
    version = data[1]
    order = ">" if version == 2 else "="
    pos = 2
    entries: list[dict[str, Any]] = []

    def take(fmt: str, at: int, limit: int) -> tuple[Any, ...]:
        size = struct.calcsize(order + fmt)
        if at + size > limit:
            raise KeytabError("truncated record")
        return struct.unpack_from(order + fmt, data, at)

    def data_field(at: int, limit: int) -> tuple[bytes, int]:
        (n,) = take("H", at, limit)
        at += 2
        if at + n > limit:
            raise KeytabError("truncated data field")
        return data[at : at + n], at + n

    while pos + 4 <= len(data):
        (length,) = take("i", pos, len(data))
        pos += 4
        if length == 0:
            break
        if length < 0:
            pos += -length
            continue
        end = pos + length
        if end > len(data):
            raise KeytabError("record runs past the end of the file")
        at = pos
        (count,) = take("H", at, end)
        at += 2
        if version == 1:
            count -= 1  # v1 counts the realm as a component
        realm, at = data_field(at, end)
        comps = []
        for _ in range(count):
            comp, at = data_field(at, end)
            comps.append(comp.decode("utf-8", "replace"))
        if version == 2:
            at += 4  # name type
        at += 4  # timestamp
        (kvno8,) = take("B", at, end)
        at += 1
        (enctype, keylen) = take("hH", at, end)
        at += 4 + keylen  # key contents: skipped, never read
        if at > end:
            raise KeytabError("key runs past its record")
        kvno = kvno8
        if end - at >= 4:
            (kvno32,) = take("I", at, end)
            if kvno32:
                kvno = kvno32
        name, status = ENCTYPES.get(enctype, (f"etype-{enctype}", "unknown"))
        entries.append(
            {
                "principal": "/".join(comps) + "@" + realm.decode("utf-8", "replace"),
                "kvno": kvno,
                "enctype": name,
                "enctype_number": enctype,
                "status": status,
            }
        )
        pos = end
    return {"format_version": version, "entries": entries}


def _keytab_paths(config: dict[str, Any]) -> list[str]:
    paths: list[str] = list(DEFAULT_KEYTABS)
    name = config.get("default_keytab_name")
    if isinstance(name, str):
        if name.startswith(("FILE:", "WRFILE:")):
            name = name.split(":", 1)[1]
        if name.startswith("/") and "%" not in name:
            paths.insert(0, name)
    for pattern in KEYTAB_GLOBS:
        # Directories resolve inside the tree, not the scanner's (#258).
        for host in _platform.host_glob(pattern):
            if host not in paths:
                paths.append(host)
    return paths


def scan_keytab(path: str) -> dict[str, Any] | None:
    """One keytab's entries, or None when the file doesn't exist."""
    try:
        p = _host_file(path)
        if not p.exists():
            return None
        size = p.stat().st_size
        if size > MAX_KEYTAB_BYTES:
            return {"path": path, "readable": False, "reason": "larger than 16 MiB"}
        data = p.read_bytes()
    except PermissionError as e:
        return {"path": path, "readable": False, "reason": f"{e.strerror} (needs root)"}
    except (OSError, _packages.RpmdbError) as e:
        return {"path": path, "readable": False, "reason": str(e)}
    try:
        parsed = parse_keytab(data)
    except KeytabError as e:
        return {"path": path, "readable": True, "parsed": False, "reason": str(e)}
    enctypes: dict[str, int] = {}
    for entry in parsed["entries"]:
        enctypes[entry["enctype"]] = enctypes.get(entry["enctype"], 0) + 1
    return {
        "path": path,
        "readable": True,
        "parsed": True,
        "format_version": parsed["format_version"],
        "entries": parsed["entries"],
        "enctypes": enctypes,
    }


# ---------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------


def _pkinit_classical(pk: dict[str, Any]) -> bool | None:
    """PKINIT in use with a classical identity: True; not in use: False;
    in use with an identity we can't read (PKCS#11 token): None.  Today's
    PKINIT is classical by construction (RSA / (EC)DH); the post-quantum
    variant is an individual draft only."""
    if not pk.get("identity_configured"):
        return False
    ident = pk.get("identity") or {}
    cats = ident.get("categories")
    if not cats:
        return None
    return not (cats.get("pure_pqc") or cats.get("hybrid_composite"))


def _summary(
    cfg: dict[str, Any], keytabs: list[dict[str, Any]], kdc: dict[str, Any] | None
) -> dict[str, Any]:
    configured: set[str] = set()
    for lst in cfg["enctype_lists"].values():
        configured.update(lst["enctypes"])
    for realm in (kdc or {}).get("realms", {}).values():
        configured.update(realm.get("supported_enctypes") or [])
    in_keytabs = {e["enctype"] for kt in keytabs for e in kt.get("entries") or []}
    allowed = sorted(configured | in_keytabs)
    deprecated = sorted(n for n in allowed if enctype_status(n) == "deprecated")
    aes128 = sorted(n for n in allowed if enctype_status(n) == "aes128")
    key_256 = sorted(n for n in in_keytabs if enctype_status(n) == "ok")
    keytab_128_only = bool(in_keytabs) and not key_256
    return {
        "enctypes_allowed": allowed,
        "enctypes_in_keytabs": sorted(in_keytabs),
        "deprecated_enctypes": deprecated,
        "aes128_enctypes": aes128,
        "keytab_keys_128_bit_only": keytab_128_only,
        "pkinit_classical": _pkinit_classical(cfg["pkinit"]),
    }


def describe_findings(kb: dict[str, Any]) -> tuple[str | None, list[str]]:
    """(SARIF level or None, one sentence per issue) for pqc-031."""
    if not kb.get("available"):
        return None, []
    s = kb.get("summary") or {}
    parts: list[str] = []
    level: str | None = None
    if s.get("deprecated_enctypes"):
        level = "warning"
        where = []
        if set(s["deprecated_enctypes"]) & set(s.get("enctypes_in_keytabs") or []):
            where.append("keytab keys")
        sources = {
            lst["source"]
            for lst in ((kb.get("config") or {}).get("enctype_lists") or {}).values()
        }
        if "mit_default" in sources:
            where.append("MIT krb5's default enctype list (no permitted_enctypes set)")
        parts.append(
            "deprecated Kerberos enctypes are allowed: "
            + ", ".join(s["deprecated_enctypes"])
            + (f" ({'; '.join(where)})" if where else "")
        )
    if s.get("keytab_keys_128_bit_only"):
        level = level or "note"
        parts.append(
            "keytab keys are 128-bit only ("
            + ", ".join(s.get("enctypes_in_keytabs") or [])
            + "); CNSA 2.0 requires AES-256"
        )
    elif s.get("aes128_enctypes"):
        level = level or "note"
        parts.append(
            "128-bit enctypes are permitted ("
            + ", ".join(s["aes128_enctypes"])
            + "); Grover's algorithm leaves them ~64-bit security and CNSA 2.0 "
            "requires AES-256"
        )
    if s.get("pkinit_classical"):
        level = level or "note"
        parts.append(
            "PKINIT is configured with a classical identity; post-quantum "
            "PKINIT is only an individual Internet-Draft"
        )
    return level, parts


def scan_kerberos() -> dict[str, Any]:
    """Kerberos client/KDC configuration and keytab enctypes."""
    profile, files = read_krb5_conf()
    kdc = read_kdc_conf()
    if not files and kdc is None:
        return {
            "available": False,
            "reason": f"no {KRB5_CONF} or kdc.conf on the host (Kerberos not configured)",
        }
    cfg = kerberos_config(profile)
    keytabs = [
        kt for kt in (scan_keytab(p) for p in _keytab_paths(cfg)) if kt is not None
    ]
    out: dict[str, Any] = {
        "available": True,
        "config_files": files,
        "config": cfg,
        "kdc": kdc,
        "keytabs": keytabs,
        "summary": _summary(cfg, keytabs, kdc),
    }
    note = _platform.host_fs_unavailable_note(
        "Kerberos inventory", "/etc/krb5.conf, kdc.conf and keytabs under /etc"
    )
    if note:
        out.update(note)
    return out


@_registry.register_arguments(54)
def add_arguments(ap: argparse.ArgumentParser) -> None:
    ap.add_argument(
        "--scan-kerberos",
        action="store_true",
        help=(
            "inventory Kerberos encryption types (krb5.conf / kdc.conf enctype "
            "lists, keytab entries; enctypes only, never keys) and PKINIT"
        ),
    )
