"""DNSSEC signing and validation algorithms (--scan-dnssec, #113).

DNSSEC signatures are long-lived public signatures, so their algorithm is
a post-quantum concern for authoritative servers that sign zones.  The
IANA "DNS Security Algorithm Numbers" registry
(https://www.iana.org/assignments/dns-sec-alg-numbers/) now lists
ML-DSA-44 as algorithm 18 (``MLDSA44``, draft-westerbaan-dnssec-mldsa,
"MAY"); everything else in use is classical, and several older
algorithms are "MUST NOT" for signing.

Read in-process from configuration and key file names:

* BIND: ``named.conf`` (with ``include``): ``dnssec-policy`` key
  algorithms, the zones that use each policy (the built-in ``default``
  policy is one ECDSAP256SHA256 CSK, per the BIND 9 reference manual),
  ``dnssec-validation``, and the algorithm number encoded in
  ``K<zone>+<alg>+<id>.key`` files in the key directory.
* Knot DNS: ``policy`` algorithms and zones with ``dnssec-signing: on``.
* PowerDNS: ``default-ksk-algorithm`` / ``default-zsk-algorithm``.
* Validators: Unbound (``validator`` module, trust anchors) and
  systemd-resolved (``DNSSEC=``).
"""

from __future__ import annotations

import argparse
import logging
import re
from pathlib import Path
from typing import Any

from .. import _platform as _platform
from .. import registry as _registry
from . import packages as _packages

log = logging.getLogger("pqc-readiness")

# number -> (IANA mnemonic, status).  status: "pqc", "deprecated" (MUST NOT
# for signing), "classical".
DNSSEC_ALGORITHMS: dict[int, tuple[str, str]] = {
    1: ("RSAMD5", "deprecated"),
    3: ("DSA", "deprecated"),
    5: ("RSASHA1", "deprecated"),
    6: ("DSA-NSEC3-SHA1", "deprecated"),
    7: ("RSASHA1-NSEC3-SHA1", "deprecated"),
    8: ("RSASHA256", "classical"),
    10: ("RSASHA512", "classical"),
    12: ("ECC-GOST", "deprecated"),
    13: ("ECDSAP256SHA256", "classical"),
    14: ("ECDSAP384SHA384", "classical"),
    15: ("ED25519", "classical"),
    16: ("ED448", "classical"),
    17: ("SM2SM3", "classical"),
    18: ("MLDSA44", "pqc"),
    23: ("ECC-GOST12", "classical"),
}
_BY_NAME = {name.lower(): num for num, (name, _) in DNSSEC_ALGORITHMS.items()}
# BIND / Knot / PowerDNS spellings.
_BY_NAME.update(
    {
        "nsec3rsasha1": 7,
        "ecdsa256": 13,
        "ecdsa384": 14,
        "ecdsap256sha256": 13,
        "ecdsap384sha384": 14,
        "ed25519": 15,
        "ed448": 16,
        "rsasha1": 5,
        "rsasha256": 8,
        "rsasha512": 10,
        "mldsa44": 18,
    }
)
# BIND's built-in "default" dnssec-policy: one ECDSAP256SHA256 CSK.
BIND_DEFAULT_POLICY_ALGORITHM = 13

MAX_CONF_BYTES = 2 * 1024 * 1024
MAX_INCLUDES = 64


def algorithm_record(value: str | int) -> dict[str, Any]:
    """{number, name, status} for a mnemonic or number; unknown names keep
    the raw value."""
    num: int | None
    if isinstance(value, int):
        num = value
    else:
        v = value.strip().strip('"').lower()
        num = int(v) if v.isdigit() else _BY_NAME.get(v)
    if num is None or num not in DNSSEC_ALGORITHMS:
        return {"number": num, "name": str(value), "status": "unknown"}
    name, status = DNSSEC_ALGORITHMS[num]
    return {"number": num, "name": name, "status": status}


def _host_file(path: str) -> Path:
    resolved = _packages.resolve_under_prefix(path, _platform.HOST_PREFIX)
    return Path(_platform.HOST_PREFIX + resolved)


# Configs that exist but couldn't be read during the current scan
# (named.conf is root:named 0640 on RHEL / Fedora).  Reported so an
# unprivileged scan says "unknown" instead of "no DNS server" (#113).
_UNREADABLE: list[dict[str, str]] = []


def _read(path: str) -> str | None:
    try:
        p = _host_file(path)
        if not p.is_file() or p.stat().st_size > MAX_CONF_BYTES:
            return None
        return p.read_text(errors="replace")
    except PermissionError as e:
        log.debug("dnssec: cannot read %s: %s", path, e)
        _UNREADABLE.append({"path": path, "reason": f"{e.strerror} (needs root)"})
        return None
    except (OSError, _packages.RpmdbError) as e:
        log.debug("dnssec: cannot read %s: %s", path, e)
        return None


# ---------------------------------------------------------------------------
# BIND named.conf
# ---------------------------------------------------------------------------

_TOKEN = re.compile(r'"(?:[^"\\]|\\.)*"|[{};]|[^\s{};"]+')


def _strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    lines = []
    for line in text.splitlines():
        # // and # comments, outside quoted strings (good enough for named.conf)
        out, q = [], False
        i = 0
        while i < len(line):
            c = line[i]
            if c == '"':
                q = not q
            if not q and (c == "#" or line.startswith("//", i)):
                break
            out.append(c)
            i += 1
        lines.append("".join(out))
    return "\n".join(lines)


def parse_named_conf(text: str) -> list[Any]:
    """named.conf as nested statements: each statement is a list of tokens
    (quotes stripped) whose last element is a child list when the
    statement has a { ... } block."""
    tokens = _TOKEN.findall(_strip_comments(text))
    pos = 0

    def block() -> list[Any]:
        nonlocal pos
        stmts: list[Any] = []
        cur: list[Any] = []
        while pos < len(tokens):
            t = tokens[pos]
            pos += 1
            if t == "{":
                cur.append(block())
            elif t == "}":
                if cur:
                    stmts.append(cur)
                return stmts
            elif t == ";":
                if cur:
                    stmts.append(cur)
                cur = []
            else:
                cur.append(t.strip('"') if t.startswith('"') else t)
        if cur:
            stmts.append(cur)
        return stmts

    return block()


def _expand_includes(stmts: list[Any], seen: list[str]) -> list[Any]:
    out: list[Any] = []
    for st in stmts:
        if st and st[0] == "include" and len(st) > 1 and isinstance(st[1], str):
            path = st[1]
            if path in seen or len(seen) >= MAX_INCLUDES:
                continue
            text = _read(path)
            if text is None:
                continue
            seen.append(path)
            out.extend(_expand_includes(parse_named_conf(text), seen))
        else:
            out.append(st)
    return out


def _child(st: list[Any]) -> list[Any]:
    return st[-1] if st and isinstance(st[-1], list) else []


def scan_bind() -> dict[str, Any] | None:
    for main in ("/etc/named.conf", "/etc/bind/named.conf"):
        text = _read(main)
        if text is not None:
            break
    else:
        return None
    files = [main]
    stmts = _expand_includes(parse_named_conf(text), files)
    policies: dict[str, list[dict[str, Any]]] = {}
    validation = None
    key_directory = None
    zones: list[dict[str, Any]] = []
    for st in stmts:
        if not st:
            continue
        if st[0] == "dnssec-policy" and len(st) >= 2 and isinstance(st[1], str):
            algs = []
            for sub in _child(st):
                if sub and sub[0] == "keys":
                    for key in _child(sub):
                        if "algorithm" in key:
                            i = key.index("algorithm")
                            if i + 1 < len(key) and isinstance(key[i + 1], str):
                                rec = algorithm_record(key[i + 1])
                                rec["role"] = key[0]
                                algs.append(rec)
            policies[st[1]] = algs
        elif st[0] == "options":
            for opt in _child(st):
                if opt and opt[0] == "dnssec-validation" and len(opt) > 1:
                    validation = opt[1]
                elif opt and opt[0] == "key-directory" and len(opt) > 1:
                    key_directory = opt[1]
        elif st[0] == "zone" and len(st) >= 2 and isinstance(st[1], str):
            for opt in _child(st):
                if (
                    opt
                    and opt[0] == "dnssec-policy"
                    and len(opt) > 1
                    and opt[1] != "none"
                ):
                    zones.append({"zone": st[1], "policy": opt[1]})
    if any(z["policy"] == "default" for z in zones) and "default" not in policies:
        rec = algorithm_record(BIND_DEFAULT_POLICY_ALGORITHM)
        rec["role"] = "csk"
        policies["default"] = [rec]
    key_files = _bind_key_files(key_directory or "/var/named")
    return {
        "config_files": files,
        "dnssec_validation": validation,
        "policies": policies,
        "signed_zones": zones,
        "key_directory": key_directory,
        "key_files": key_files,
    }


_KEYFILE = re.compile(r"^K(.+)\.\+(\d{3})\+(\d{5})\.key$")


def _bind_key_files(directory: str) -> list[dict[str, Any]]:
    """Algorithm and zone of each ``K<zone>+<alg>+<id>.key`` file under the
    key directory and BIND's usual data directories.  The search is
    recursive and the directories can nest (``key-directory
    /var/named/keys`` sits under ``/var/named``), so files are de-duplicated
    by resolved path."""
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for d in dict.fromkeys(
        (directory, "/var/named", "/var/cache/bind", "/var/lib/bind")
    ):
        try:
            base = _host_file(d)
            if not base.is_dir():
                continue
            files = sorted(base.rglob("K*.key"))[:500]
        except (OSError, _packages.RpmdbError) as e:
            log.debug("dnssec: cannot list %s: %s", d, e)
            continue
        for f in files:
            m = _KEYFILE.match(f.name)
            try:
                key = str(f.resolve())
            except (OSError, RuntimeError) as e:  # RuntimeError: symlink loop, <3.13
                log.debug("dnssec: cannot resolve %s: %s", f, e)
                continue
            if not m or key in seen:
                continue
            seen.add(key)
            rec = algorithm_record(int(m.group(2)))
            rec["zone"] = m.group(1)
            rec["directory"] = str(f.parent)[len(_platform.HOST_PREFIX) :] or "/"
            out.append(rec)
    return out


# ---------------------------------------------------------------------------
# Knot, PowerDNS, validators
# ---------------------------------------------------------------------------


def scan_knot() -> dict[str, Any] | None:
    text = _read("/etc/knot/knot.conf")
    if text is None:
        return None
    algs = [
        algorithm_record(v) for v in re.findall(r"^\s*algorithm:\s*(\S+)", text, re.M)
    ]
    signing = len(re.findall(r"^\s*dnssec-signing:\s*on\b", text, re.M))
    return {
        "config_files": ["/etc/knot/knot.conf"],
        "policy_algorithms": algs,
        "signing_zones": signing,
    }


def scan_powerdns() -> dict[str, Any] | None:
    for path in ("/etc/pdns/pdns.conf", "/etc/powerdns/pdns.conf"):
        text = _read(path)
        if text is None:
            continue
        settings = dict(
            re.findall(r"^\s*(default-(?:ksk|zsk)-algorithm)\s*=\s*(\S+)", text, re.M)
        )
        return {
            "config_files": [path],
            "default_algorithms": {k: algorithm_record(v) for k, v in settings.items()},
        }
    return None


def scan_validators() -> dict[str, Any]:
    out: dict[str, Any] = {}
    text = _read("/etc/unbound/unbound.conf")
    if text is not None:
        conf_d = []
        try:
            d = _host_file("/etc/unbound/conf.d")
            if d.is_dir():
                conf_d = sorted(f.name for f in d.iterdir() if f.name.endswith(".conf"))
        except (OSError, _packages.RpmdbError) as e:
            log.debug("dnssec: cannot list /etc/unbound/conf.d: %s", e)
        texts = [text] + [
            t for t in (_read(f"/etc/unbound/conf.d/{n}") for n in conf_d) if t
        ]
        joined = "\n".join(texts)
        module = re.search(r'^\s*module-config:\s*"?([^"\n]+)', joined, re.M)
        anchors = bool(re.search(r"^\s*(auto-)?trust-anchor(-file)?:", joined, re.M))
        out["unbound"] = {
            "validating": (("validator" in module.group(1)) if module else anchors),
            "trust_anchor_configured": anchors,
        }
    # systemd >= 255 ships the defaults in /usr/lib/systemd; later files and
    # drop-ins override earlier ones (systemd.syntax(7) order).
    resolved = None
    seen_conf = False
    paths = ["/usr/lib/systemd/resolved.conf", "/etc/systemd/resolved.conf"]
    for dropin in (
        "/usr/lib/systemd/resolved.conf.d",
        "/run/systemd/resolved.conf.d",
        "/etc/systemd/resolved.conf.d",
    ):
        paths += [f"{dropin}/{n}" for n in _listdir(dropin) if n.endswith(".conf")]
    for path in paths:
        t = _read(path)
        if t is None:
            continue
        seen_conf = True
        m = re.search(r"^\s*DNSSEC\s*=\s*(\S+)", t, re.M)
        if m:
            resolved = m.group(1)
    if seen_conf:
        out["systemd_resolved"] = {"dnssec": resolved}
    return out


def _listdir(path: str) -> list[str]:
    try:
        d = _host_file(path)
        return sorted(e.name for e in d.iterdir()) if d.is_dir() else []
    except (OSError, _packages.RpmdbError) as e:
        log.debug("dnssec: cannot list %s: %s", path, e)
        return []


# ---------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------


def _signing_algorithms(
    bind: dict[str, Any] | None,
    knot: dict[str, Any] | None,
    pdns: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    algs: list[dict[str, Any]] = []
    if bind:
        used = {z["policy"] for z in bind["signed_zones"]}
        for name, recs in bind["policies"].items():
            if name in used:
                algs.extend(recs)
        algs.extend(bind["key_files"])
    if knot and knot["signing_zones"]:
        algs.extend(knot["policy_algorithms"])
    if pdns:
        algs.extend(pdns["default_algorithms"].values())
    seen: dict[str, dict[str, Any]] = {}
    for a in algs:
        seen.setdefault(str(a["name"]), {k: a[k] for k in ("number", "name", "status")})
    return sorted(seen.values(), key=lambda a: (a["number"] or 0, a["name"]))


def describe(dn: dict[str, Any]) -> tuple[str | None, str | None]:
    """(level, message) for pqc-034, or (None, None)."""
    if not dn.get("available"):
        return None, None
    s = dn.get("summary") or {}
    if not s.get("signing_configured") or s.get("signing_pqc"):
        return None, None
    names = ", ".join(a["name"] for a in s.get("signing_algorithms") or [])
    if s.get("deprecated_signing"):
        return (
            "warning",
            "DNSSEC signing uses algorithms IANA marks MUST NOT for signing: "
            + ", ".join(s["deprecated_signing"])
            + f" (all signing algorithms: {names})",
        )
    return (
        "note",
        f"DNSSEC zones are signed with classical algorithms only ({names}); "
        "ML-DSA-44 (IANA algorithm 18, draft) is the only post-quantum "
        "algorithm registered",
    )


def scan_dnssec() -> dict[str, Any]:
    _UNREADABLE.clear()
    bind = scan_bind()
    knot = scan_knot()
    pdns = scan_powerdns()
    validators = scan_validators()
    unreadable = list(_UNREADABLE)
    if not (bind or knot or pdns or validators or unreadable):
        return {
            "available": False,
            "reason": "no BIND, Knot, PowerDNS, Unbound or systemd-resolved configuration found",
        }
    signing = _signing_algorithms(bind, knot, pdns)
    out: dict[str, Any] = {
        "available": True,
        "bind": bind,
        "knot": knot,
        "powerdns": pdns,
        "validators": validators,
        "summary": {
            "signing_algorithms": signing,
            "signing_configured": bool(signing),
            "signing_pqc": any(a["status"] == "pqc" for a in signing),
            "deprecated_signing": [
                a["name"] for a in signing if a["status"] == "deprecated"
            ],
            "unreadable_configs": unreadable,
        },
    }
    note = _platform.host_fs_unavailable_note(
        "DNSSEC inventory", "named.conf, knot.conf, pdns.conf and resolver configs"
    )
    if note:
        out.update(note)
    return out


@_registry.register_arguments(56)
def add_arguments(ap: argparse.ArgumentParser) -> None:
    ap.add_argument(
        "--scan-dnssec",
        action="store_true",
        help=(
            "inventory DNSSEC signing algorithms (BIND, Knot, PowerDNS) and "
            "validation (Unbound, systemd-resolved, BIND)"
        ),
    )
