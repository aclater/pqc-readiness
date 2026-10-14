"""OpenSSL effective configuration (#106).

`openssl_capability()` reports what the installed OpenSSL *exposes*; this
module reports what it is *configured to use by default*: the config
file (and everything it `.include`s), the providers it activates, and
the default TLS groups / signature algorithms for `system_default`.

Measured layouts (2026-10-13, fixtures in tests/fixtures/openssl_config/):

* RHEL-family 9 / 10, Fedora 44: OPENSSLDIR `/etc/pki/tls`.  `[ssl_module]
  system_default = crypto_policy`, and `[crypto_policy]` `.include`s the
  crypto-policies back-end; third-party provider snippets go in the
  `.include /etc/pki/tls/openssl.d` directory.
* openSUSE Leap 16: `/etc/ssl/openssl.cnf`, same crypto-policies include.
* Debian 13, Ubuntu 26.04: OPENSSLDIR `/usr/lib/ssl` (its `openssl.cnf` is a
  symlink to `/etc/ssl/openssl.cnf`); no `ssl_conf` at all, so OpenSSL's
  built-in defaults apply.
* Fedora 44's `openssl` package obsoletes `oqsprovider < 0.9.0`, and Debian
  13 / Ubuntu 26.04 don't package it: a third-party PQC provider now
  appears only when built from source.

Everything is read through the host prefix, so the result describes the
host under --host-mount.  The loaded-provider and algorithm lists come
from the `openssl` binary; `openssl_capability()` reports them, and leaves
them null under --host-mount, where the binary is the scanner image's.
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Any, Callable

from .. import _platform as _platform
from . import config_policy as _config_policy
from . import packages as _packages
from . import runtime as _runtime

log = logging.getLogger("pqc-readiness")

# Providers shipped inside OpenSSL itself.  Anything else is third-party.
BUILTIN_PROVIDERS = frozenset({"default", "base", "fips", "legacy", "null"})

# OpenSSL 3.5.0 changed the built-in default TLS group list to
#   ?*X25519MLKEM768 / ?*X25519:?secp256r1 / ?X448:?secp384r1:?secp521r1
#   / ?ffdhe2048:?ffdhe3072
# (CHANGES.md, "Changes between 3.4 and 3.5.0 [8 Apr 2025]"), i.e. a
# hybrid ML-KEM key share is offered unless configuration says otherwise.
OPENSSL_35_DEFAULT_GROUPS = (
    "X25519MLKEM768",
    "X25519",
    "secp256r1",
    "X448",
    "secp384r1",
    "secp521r1",
    "ffdhe2048",
    "ffdhe3072",
)

# Where each family keeps openssl.cnf when OPENSSLDIR can't be asked
# (always the case under --host-mount: the binary belongs to the image).
_CONFIG_CANDIDATES = {
    "rhel": ("/etc/pki/tls/openssl.cnf", "/etc/ssl/openssl.cnf"),
    # /usr/lib/ssl/openssl.cnf is a symlink to /etc/ssl/openssl.cnf here.
    "debian": ("/etc/ssl/openssl.cnf", "/usr/lib/ssl/openssl.cnf"),
    "suse": ("/etc/ssl/openssl.cnf",),
}
_FALLBACK_CANDIDATES = (
    "/etc/pki/tls/openssl.cnf",
    "/etc/ssl/openssl.cnf",
    "/usr/lib/ssl/openssl.cnf",
)

_MAX_INCLUDE_DEPTH = 8
_SECTION_RE = re.compile(r"^\s*\[\s*([^\]]+?)\s*\]\s*$")
_INCLUDE_RE = re.compile(r"^\s*\.include\s*=?\s*(\S.*?)\s*$")
_KV_RE = re.compile(r"^\s*([^=#\s][^=]*?)\s*=\s*(.*?)\s*$")


def _strip_comment(line: str) -> str:
    # OpenSSL treats an unescaped `#` as a comment start.
    out = []
    i = 0
    while i < len(line):
        c = line[i]
        if c == "\\" and i + 1 < len(line):
            out.append(line[i + 1])
            i += 2
            continue
        if c == "#":
            break
        out.append(c)
        i += 1
    return "".join(out)


def parse_openssl_cnf(
    path: str,
    read: Callable[[str], str | None],
    list_dir: Callable[[str], list[str] | None],
) -> dict[str, Any]:
    """Parse an OpenSSL config file and its `.include`s.

    Returns {sections: {name: {key: value}}, files: [...], include_errors:
    [...]}.  Keys before any header land in section `default`; repeated
    sections merge, later values winning, as OpenSSL does.  An include of
    a directory reads its `*.cnf` / `*.conf` files in sorted order.
    Relative include paths are taken relative to the including file's
    directory (OpenSSL itself uses the process working directory unless
    OPENSSL_CONF_INCLUDE is set, which a host scan can't reproduce)."""
    sections: dict[str, dict[str, str]] = {}
    files: list[str] = []
    errors: list[str] = []
    seen: set[str] = set()

    def load(p: str, current: str, depth: int) -> str:
        if depth > _MAX_INCLUDE_DEPTH or p in seen:
            errors.append(p)
            return current
        seen.add(p)
        entries = list_dir(p)
        if entries is not None:
            for name in sorted(entries):
                if name.endswith((".cnf", ".conf")):
                    current = load(f"{p.rstrip('/')}/{name}", current, depth + 1)
            return current
        text = read(p)
        if text is None:
            errors.append(p)
            return current
        files.append(p)
        for raw in text.splitlines():
            line = _strip_comment(raw).rstrip()
            if not line.strip() or line.lstrip().startswith(".pragma"):
                continue
            m = _INCLUDE_RE.match(line)
            if m:
                target = m.group(1)
                if not target.startswith("/"):
                    target = os.path.normpath(os.path.join(os.path.dirname(p), target))
                current = load(target, current, depth + 1)
                continue
            m = _SECTION_RE.match(line)
            if m:
                current = m.group(1)
                sections.setdefault(current, {})
                continue
            m = _KV_RE.match(line)
            if m:
                value = m.group(2).strip()
                if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                    value = value[1:-1]
                sections.setdefault(current, {})[m.group(1).strip()] = value
        return current

    load(path, "default", 0)
    return {"sections": sections, "files": files, "include_errors": errors}


def _section_value(
    sections: dict[str, dict[str, str]], section: str | None, key: str
) -> str | None:
    if not section:
        return None
    s = sections.get(section) or {}
    for k, v in s.items():
        if k.lower() == key.lower():
            return v
    return None


def effective_settings(parsed: dict[str, Any]) -> dict[str, Any]:
    """Walk `openssl_conf -> providers / ssl_conf -> system_default`."""
    sections = parsed["sections"]
    init = _section_value(sections, "default", "openssl_conf")
    providers_sect = _section_value(sections, init, "providers")
    providers: list[dict[str, Any]] = []
    for name, sect in (sections.get(providers_sect or "", {}) or {}).items():
        body = sections.get(sect) or {}
        activate = _section_value(sections, sect, "activate")
        providers.append(
            {
                "name": name,
                "section": sect,
                "activate": (
                    None
                    if activate is None
                    else activate.strip().lower() in ("1", "yes", "true", "on")
                ),
                "module": body.get("module"),
                "third_party": name not in BUILTIN_PROVIDERS,
            }
        )
    ssl_sect = _section_value(sections, init, "ssl_conf")
    sysdef = _section_value(sections, ssl_sect, "system_default")
    sys_body = sections.get(sysdef or "") or {}
    lines = "\n".join(f"{k} = {v}" for k, v in sys_body.items())
    tls = _config_policy.parse_opensslcnf_backend(lines)
    return {
        "init_section": init,
        "system_default_section": sysdef,
        "providers_configured": providers,
        "min_protocol": _section_value(sections, sysdef, "MinProtocol"),
        "groups_configured": tls["groups"] or None,
        "signature_algorithms_configured": tls["signature_algorithms"] or None,
    }


def _host_file(path: str) -> Path:
    """`path` on the host.  Config files can live outside the namespaces
    host_path() redirects (e.g. /usr/lib/ssl), so the prefix is applied
    unconditionally after resolving symlinks inside it."""
    resolved = _packages.resolve_under_prefix(path, _platform.HOST_PREFIX)
    return Path(_platform.HOST_PREFIX + resolved)


def _read(path: str) -> str | None:
    try:
        return _host_file(path).read_text(errors="replace")
    except (OSError, _packages.RpmdbError) as e:
        log.debug("openssl config: cannot read %s: %s", path, e)
        return None


def _list_dir(path: str) -> list[str] | None:
    try:
        p = _host_file(path)
        if not p.is_dir():
            return None
        return [e.name for e in p.iterdir() if e.is_file()]
    except (OSError, _packages.RpmdbError) as e:
        log.debug("openssl config: cannot list %s: %s", path, e)
        return None


def _openssldir_from_binary() -> str | None:
    rc, out = _platform._run(["openssl", "version", "-d"], timeout=5)
    m = re.search(r'OPENSSLDIR:\s*"([^"]+)"', out) if rc == 0 else None
    return m.group(1) if m else None


def locate_openssl_config(family: str) -> tuple[str | None, str]:
    """(path, how it was found).  Without --host-mount, OPENSSL_CONF and
    the binary's OPENSSLDIR describe this host; under --host-mount both
    belong to the scanner image, so only the family's default locations
    are tried."""
    if not _platform.HOST_PREFIX:
        env = os.environ.get("OPENSSL_CONF")
        if env:
            return env, "OPENSSL_CONF"
        d = _openssldir_from_binary()
        if d and _read(f"{d}/openssl.cnf") is not None:
            return f"{d}/openssl.cnf", "OPENSSLDIR"
    for p in _CONFIG_CANDIDATES.get(family, _FALLBACK_CANDIDATES):
        if _read(p) is not None:
            return p, "distribution default"
    return None, "not found"


def detect_openssl_config(
    os_release: dict[str, Any] | None, version_tuple: list[int] | None
) -> dict[str, Any]:
    family = (os_release or {}).get("family", "unknown")
    path, how = locate_openssl_config(family)
    if path is None:
        out: dict[str, Any] = {
            "available": False,
            "reason": "no openssl.cnf found in the distribution's default locations",
        }
    else:
        parsed = parse_openssl_cnf(path, _read, _list_dir)
        eff = effective_settings(parsed)
        groups = eff["groups_configured"]
        builtin = version_tuple is not None and tuple(version_tuple[:2]) >= (3, 5)
        if groups is not None:
            effective = groups
            source = "config"
        elif builtin:
            effective = list(OPENSSL_35_DEFAULT_GROUPS)
            source = "openssl built-in default (3.5+)"
        else:
            effective = []
            source = "openssl built-in default (pre-3.5: no PQC groups)"
        pqc = _config_policy.parse_opensslcnf_backend(
            "Groups = " + ":".join(effective)
        )["pqc_groups"]
        out = {
            "available": True,
            "path": path,
            "path_source": how,
            "files": parsed["files"],
            "include_errors": parsed["include_errors"],
            **eff,
            "default_groups": effective,
            "default_groups_source": source,
            "default_pqc_groups": pqc,
            "pqc_key_exchange_by_default": bool(pqc["hybrid"] or pqc["pure_pqc"]),
            "third_party_providers_configured": [
                p["name"]
                for p in eff["providers_configured"]
                if p["third_party"] and p["activate"]
            ],
        }
    note = _runtime._host_fs_note_for("openssl_config")
    if note:
        out.update(note)
    return out


_ALGO_LINE_RE = re.compile(r"^\s*(\S+)\s+@\s+(\S+)\s*$")


def third_party_algorithms(text: str) -> list[dict[str, str]]:
    """`openssl list -kem-algorithms` / `-signature-algorithms` lines of the
    form `  p256_mldsa44 @ oqsprovider` whose provider is not built in."""
    out = []
    for line in text.splitlines():
        m = _ALGO_LINE_RE.match(line)
        if m and m.group(2) not in BUILTIN_PROVIDERS:
            out.append({"name": m.group(1), "provider": m.group(2)})
    return out


def third_party_providers(records: dict[str, dict[str, str]]) -> list[dict[str, Any]]:
    """Loaded providers (from `openssl list -providers -verbose` records)
    that are not built into OpenSSL."""
    return [
        {
            "name": name,
            "display_name": rec.get("name"),
            "version": rec.get("version"),
            "build_info": rec.get("build info"),
            "status": rec.get("status"),
        }
        for name, rec in sorted(records.items())
        if name not in BUILTIN_PROVIDERS
    ]
