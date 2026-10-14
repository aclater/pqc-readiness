"""Text parsers for per-service TLS configuration (#216).

Each parser reads one service's own configuration and returns its TLS
*endpoints*: a listening socket (or, for daemons configured once for all
their ports, the whole service) with the settings that decide which key
exchanges it offers.  No filesystem access happens here: callers pass a
``reader(path) -> text | None`` and a ``lister(glob) -> [paths]`` so the
same code serves a live host, ``--host-mount`` and an offline ``--root``
tree, and unit tests feed real configuration files from fixtures.

What decides PQC key exchange for a service is, in order:

1. the service's own group setting (nginx ``ssl_ecdh_curve``, Apache
   ``SSLOpenSSLConfCmd Groups``, HAProxy ``curves``, stunnel ``curves``,
   Postfix ``tls_eecdh_auto_curves``, Dovecot ``ssl_curve_list``,
   PostgreSQL ``ssl_groups`` / ``ssl_ecdh_curve``, OpenLDAP
   ``TLSECName``).  A list without an ML-KEM group keeps PQC out even
   where the system policy allows it, and a list with one turns it on
   even where the policy doesn't (measured on Rocky 9.8: nginx with
   ``ssl_ecdh_curve X25519MLKEM768:X25519`` negotiates X25519MLKEM768
   under the DEFAULT policy);
2. a built-in default list compiled into the service, which the caller
   supplies (``service_default_groups``) because it depends on the
   service's version: Postfix before 3.11, stunnel built before
   OpenSSL 3.5 support and PostgreSQL all set classical lists;
3. otherwise the TLS library's own default, i.e. the system crypto
   policy / ``openssl.cnf`` (``groups`` stays None).

Hybrid ML-KEM groups exist only in TLS 1.3, so a configuration that caps
the protocol below 1.3 can't offer them whatever its groups say.
"""

from __future__ import annotations

import fnmatch
import posixpath
import re
import xml.etree.ElementTree as ET
from typing import Any, Callable, Iterable, Optional

from . import config_policy as _config_policy

Reader = Callable[[str], Optional[str]]
Lister = Callable[[str], "list[str]"]

MAX_INCLUDE_DEPTH = 8

# TLS / SSL protocol names -> comparable numbers.
_PROTO_RANK = {
    "sslv2": 0.2,
    "sslv3": 0.3,
    "tlsv1": 1.0,
    "tlsv1.0": 1.0,
    "tls1": 1.0,
    "tls1.0": 1.0,
    "1.0": 1.0,
    "tlsv1.1": 1.1,
    "tls1.1": 1.1,
    "1.1": 1.1,
    "tlsv1.2": 1.2,
    "tls1.2": 1.2,
    "1.2": 1.2,
    "tlsv1.3": 1.3,
    "tls1.3": 1.3,
    "1.3": 1.3,
}


def proto_rank(name: str | None) -> float | None:
    if not name:
        return None
    return _PROTO_RANK.get(name.strip().strip("'\"").lower().replace("_", "."))


def tls13_allowed(
    allowed: Iterable[str] | None = None,
    minimum: str | None = None,
    maximum: str | None = None,
) -> bool | None:
    """Whether TLS 1.3 can be negotiated: False when the allowed set
    lacks it or the maximum is below it; None when nothing restricts it
    (the library default, TLS 1.3 on every OpenSSL that has ML-KEM)."""
    if maximum is not None:
        r = proto_rank(maximum)
        if r is not None and r < 1.3:
            return False
    if minimum is not None:
        r = proto_rank(minimum)
        if r is not None and r > 1.3:
            return False
    if allowed is not None:
        ranks = {proto_rank(a) for a in allowed}
        ranks.discard(None)
        if ranks:
            return 1.3 in ranks
    return None


def split_groups(value: str | None) -> list[str] | None:
    """A group / curve list as services spell it: colon, comma or space
    separated, OpenSSL 3.5 tuple ``/`` and ``*`` / ``?`` / ``-`` markers
    allowed.  "auto" (nginx) and an empty value mean "library default"."""
    if value is None:
        return None
    v = value.strip().strip("'\"")
    if not v or v.lower() == "auto":
        return None
    out = []
    for tok in re.split(r"[:,\s/]+", v):
        tok = tok.strip()
        if tok and not tok.startswith("-"):
            out.append(tok.lstrip("*?"))
    return out or None


def classify_groups(groups: list[str]) -> dict[str, list[str]]:
    """hybrid / pure_pqc buckets of a group list (shared token rules with
    the crypto-policy back-end parsers)."""
    return _config_policy._classify_pqc(groups, _config_policy._PQC_KEM_TOKEN_RE)


def make_endpoint(
    *,
    file: str,
    line: int | None,
    ports: list[int],
    context: str | None = None,
    groups: list[str] | None = None,
    groups_setting: str | None = None,
    service_default_groups: list[str] | None = None,
    service_supports_pqc_groups: bool | None = None,
    protocols: list[str] | None = None,
    min_protocol: str | None = None,
    max_protocol: str | None = None,
    ciphers: str | None = None,
    ciphersuites: str | None = None,
    certificates: list[str] | None = None,
    role: str = "server",
    note: str | None = None,
) -> dict[str, Any]:
    """One endpoint record with its PQC judgement.

    ``pqc_key_exchange`` is True / False when the service's own settings
    (or its built-in default) decide it, None when it follows the TLS
    library's default (system policy / openssl.cnf)."""
    if groups is not None:
        effective: list[str] | None = groups
        source = "config"
    elif service_default_groups is not None:
        effective = service_default_groups
        source = "service default"
    else:
        effective = None
        source = "library default"
    t13 = tls13_allowed(protocols, min_protocol, max_protocol)
    pqc_groups = classify_groups(effective) if effective is not None else None
    pqc: bool | None
    if t13 is False:
        pqc = False
        reason = "TLS 1.3 is disabled; hybrid ML-KEM groups need TLS 1.3"
    elif service_supports_pqc_groups is False:
        pqc = False
        reason = "the service can only use a single elliptic curve, never ML-KEM"
    elif pqc_groups is not None:
        pqc = bool(pqc_groups["hybrid"] or pqc_groups["pure_pqc"])
        where = groups_setting or "groups"
        reason = (
            f"{where} ({source}) includes an ML-KEM group"
            if pqc
            else f"{where} ({source}) has no ML-KEM group"
        )
    else:
        pqc = None
        reason = "no group setting: follows the TLS library default (crypto policy / openssl.cnf)"
    out: dict[str, Any] = {
        "file": file,
        "line": line,
        "context": context,
        "role": role,
        "ports": sorted(set(ports)),
        "groups": effective,
        "groups_setting": groups_setting,
        "groups_source": source,
        "pqc_groups": pqc_groups,
        "protocols": protocols,
        "min_protocol": min_protocol,
        "max_protocol": max_protocol,
        "tls13_allowed": t13,
        "ciphers": ciphers,
        "ciphersuites": ciphersuites,
        "certificates": certificates or [],
        "service_supports_pqc_groups": service_supports_pqc_groups,
        "follows_library_default": pqc is None,
        "pqc_key_exchange": pqc,
        "reason": reason,
    }
    if note:
        out["note"] = note
    return out


def _resolve(base: str, pattern: str) -> str:
    pattern = pattern.strip().strip("'\"")
    return pattern if pattern.startswith("/") else posixpath.join(base, pattern)


def _expand(pattern: str, lister: Lister) -> list[str]:
    if any(c in pattern for c in "*?["):
        return sorted(lister(pattern))
    return [pattern]


def _port_of(addr: str) -> int | None:
    """Port from "443", "[::]:443", "1.2.3.4:443", "*:443", "host:443"."""
    a = addr.strip()
    if a.startswith("unix:") or a.startswith("/"):
        return None
    m = re.search(r"(?:^|:)(\d{1,5})$", a)
    if m:
        p = int(m.group(1))
        return p if 0 < p < 65536 else None
    return None


# ---------------------------------------------------------------------------
# nginx
# ---------------------------------------------------------------------------


def _nginx_tokens(text: str) -> list[tuple[str, int]]:
    toks: list[tuple[str, int]] = []
    i, n, line = 0, len(text), 1
    while i < n:
        c = text[i]
        if c == "\n":
            line += 1
            i += 1
        elif c.isspace():
            i += 1
        elif c == "#":
            while i < n and text[i] != "\n":
                i += 1
        elif c in "{};":
            toks.append((c, line))
            i += 1
        elif c in "\"'":
            j = i + 1
            buf = []
            while j < n and text[j] != c:
                if text[j] == "\\" and j + 1 < n:
                    j += 1
                if text[j] == "\n":
                    line += 1
                buf.append(text[j])
                j += 1
            toks.append(("".join(buf), line))
            i = j + 1
        else:
            j = i
            while j < n and not text[j].isspace() and text[j] not in "{};#":
                j += 1
            toks.append((text[i:j], line))
            i = j
    return toks


def _nginx_statements(
    toks: list[tuple[str, int]], pos: int = 0
) -> tuple[list[dict[str, Any]], int]:
    out: list[dict[str, Any]] = []
    cur: list[tuple[str, int]] = []
    while pos < len(toks):
        tok, line = toks[pos]
        if tok == ";":
            if cur:
                out.append(
                    {
                        "name": cur[0][0],
                        "args": [t for t, _ in cur[1:]],
                        "line": cur[0][1],
                        "block": None,
                    }
                )
            cur = []
            pos += 1
        elif tok == "{":
            block, pos = _nginx_statements(toks, pos + 1)
            if cur:
                out.append(
                    {
                        "name": cur[0][0],
                        "args": [t for t, _ in cur[1:]],
                        "line": cur[0][1],
                        "block": block,
                    }
                )
            cur = []
        elif tok == "}":
            return out, pos + 1
        else:
            cur.append((tok, line))
            pos += 1
    return out, pos


_NGINX_INHERITED = (
    "ssl_protocols",
    "ssl_ciphers",
    "ssl_ecdh_curve",
    "ssl_certificate",
    "ssl_conf_command",
    "ssl",
)


def parse_nginx(main: str, reader: Reader, lister: Lister) -> dict[str, Any]:
    """Endpoints of every ``server`` (http, stream and mail) that listens
    with ``ssl`` or ``quic``.  ``ssl_*`` directives are inherited from the
    enclosing block; ``ssl_conf_command Groups|Curves`` overrides
    ``ssl_ecdh_curve`` as it does in nginx (it is applied last)."""
    files: list[str] = []
    unreadable: list[dict[str, str]] = []
    prefix = posixpath.dirname(main)

    def load(path: str, depth: int) -> list[dict[str, Any]]:
        text = reader(path)
        if text is None:
            unreadable.append({"path": path, "reason": "missing or not readable"})
            return []
        files.append(path)
        stmts, _ = _nginx_statements(_nginx_tokens(text))
        return expand(stmts, path, depth)

    def expand(
        stmts: list[dict[str, Any]], path: str, depth: int
    ) -> list[dict[str, Any]]:
        out = []
        for s in stmts:
            s["file"] = path
            if s["name"] == "include" and s["args"] and depth < MAX_INCLUDE_DEPTH:
                for p in _expand(_resolve(prefix, s["args"][0]), lister):
                    out.extend(load(p, depth + 1))
            else:
                if s["block"] is not None:
                    s["block"] = expand(s["block"], path, depth)
                out.append(s)
        return out

    tree = load(main, 0)
    endpoints: list[dict[str, Any]] = []

    def settings_of(
        stmts: list[dict[str, Any]], inherited: dict[str, Any]
    ) -> dict[str, Any]:
        st = dict(inherited)
        for s in stmts:
            if s["name"] in _NGINX_INHERITED:
                if s["name"] == "ssl_certificate":
                    st["ssl_certificate"] = (
                        list(st.get("ssl_certificate", [])) + s["args"][:1]
                    )
                elif s["name"] == "ssl_conf_command" and len(s["args"]) >= 2:
                    cmds = dict(st.get("ssl_conf_command", {}))
                    cmds[s["args"][0].lower()] = (s["args"][1], s)
                    st["ssl_conf_command"] = cmds
                else:
                    st[s["name"]] = (s["args"], s)
        return st

    def walk(stmts: list[dict[str, Any]], inherited: dict[str, Any], ctx: str) -> None:
        st = settings_of(stmts, inherited)
        for s in stmts:
            if s["block"] is None:
                continue
            if s["name"] in ("http", "stream", "mail"):
                walk(s["block"], st, s["name"])
            elif s["name"] == "server" and ctx in ("http", "stream", "mail"):
                server(s, settings_of(s["block"], st), ctx)

    def server(s: dict[str, Any], st: dict[str, Any], ctx: str) -> None:
        ports: list[int] = []
        tls = False
        legacy_ssl = st.get("ssl")
        if legacy_ssl and legacy_ssl[0][:1] == ["on"]:
            tls = True
        for d in s["block"]:
            if d["name"] != "listen" or not d["args"]:
                continue
            params = set(d["args"][1:])
            if (
                "ssl" in params
                or "quic" in params
                or (legacy_ssl and legacy_ssl[0][:1] == ["on"])
            ):
                p = _port_of(d["args"][0])
                if (
                    p is None
                    and re.fullmatch(r"[\w.\-*\[\]:]+", d["args"][0])
                    and not re.search(r"\d+$", d["args"][0])
                ):
                    p = 443 if ctx == "http" else None
                if p is not None:
                    ports.append(p)
                    tls = True
        if not tls or not ports:
            return
        groups_val = None
        setting = None
        line = s["line"]
        if "ssl_ecdh_curve" in st:
            args, d = st["ssl_ecdh_curve"]
            groups_val = args[0] if args else None
            setting = "ssl_ecdh_curve"
        cmds = st.get("ssl_conf_command") or {}
        for key in ("groups", "curves"):
            if key in cmds:
                groups_val, _d = cmds[key]
                setting = f"ssl_conf_command {key.capitalize()}"
        protos = st.get("ssl_protocols")
        ciphers = st.get("ssl_ciphers")
        endpoints.append(
            make_endpoint(
                file=s["file"],
                line=line,
                ports=ports,
                context=f"{ctx} server",
                groups=split_groups(groups_val),
                groups_setting=setting
                if split_groups(groups_val) is not None
                else None,
                protocols=protos[0] if protos else None,
                ciphers=" ".join(ciphers[0]) if ciphers else None,
                ciphersuites=(cmds.get("ciphersuites") or (None,))[0],
                certificates=st.get("ssl_certificate", []),
            )
        )

    walk(tree, {}, "main")
    return {"files": files, "unreadable": unreadable, "endpoints": endpoints}


# ---------------------------------------------------------------------------
# Apache httpd (mod_ssl)
# ---------------------------------------------------------------------------


def _apache_lines(text: str) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    buf = ""
    start = 0
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip()
        if not buf:
            start = i
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        full = (buf + line).strip()
        buf = ""
        if full and not full.startswith("#"):
            out.append((start, full))
    return out


def _apache_protocols(value: str) -> list[str]:
    """``SSLProtocol all -SSLv3 -TLSv1`` -> the allowed protocol names."""
    every = ["TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"]
    allowed: list[str] = []
    for tok in value.split():
        t = tok.strip()
        sign = ""
        if t[:1] in "+-":
            sign, t = t[0], t[1:]
        names = every if t.lower() == "all" else [t]
        for name in names:
            canon = next(
                (e for e in every + ["SSLv3", "SSLv2"] if e.lower() == name.lower()),
                name,
            )
            if sign == "-":
                allowed = [a for a in allowed if a.lower() != canon.lower()]
            elif canon not in allowed:
                allowed.append(canon)
    return allowed


_APACHE_SSL = {
    "sslengine": "engine",
    "sslprotocol": "protocol",
    "sslciphersuite": "ciphers",
    "sslcertificatefile": "cert",
}


def parse_apache(
    main: str, server_root: str, reader: Reader, lister: Lister
) -> dict[str, Any]:
    """Endpoints of every ``<VirtualHost>`` with ``SSLEngine on``.  Server
    level SSL directives are the defaults for every virtual host;
    ``<IfModule>`` / ``<IfDefine>`` sections are read as active (the
    packaged ssl.conf files sit inside them)."""
    files: list[str] = []
    unreadable: list[dict[str, str]] = []
    flat: list[tuple[str, int, str]] = []

    def load(path: str, depth: int, optional: bool = False) -> None:
        text = reader(path)
        if text is None:
            if not optional:
                unreadable.append({"path": path, "reason": "missing or not readable"})
            return
        files.append(path)
        nonlocal server_root
        for line_no, line in _apache_lines(text):
            parts = line.split(None, 1)
            key = parts[0].lower()
            arg = parts[1] if len(parts) > 1 else ""
            if key == "serverroot":
                server_root = arg.strip("'\"")
            if key in ("include", "includeoptional") and depth < MAX_INCLUDE_DEPTH:
                for p in _expand(_resolve(server_root, arg), lister):
                    load(p, depth + 1, optional=key == "includeoptional")
                continue
            flat.append((path, line_no, line))

    load(main, 0)
    globals_: dict[str, Any] = {}
    endpoints: list[dict[str, Any]] = []
    vhost: dict[str, Any] | None = None

    def conf_cmd(st: dict[str, Any], arg: str) -> None:
        bits = arg.split(None, 1)
        if len(bits) == 2:
            st.setdefault("confcmd", {})[bits[0].lower()] = bits[1].strip().strip("'\"")

    for path, line_no, line in flat:
        parts = line.split(None, 1)
        key = parts[0].lower()
        arg = parts[1].strip() if len(parts) > 1 else ""
        if key == "<virtualhost":
            vhost = {
                "file": path,
                "line": line_no,
                "addrs": arg.rstrip(">").split(),
                "confcmd": {},
            }
            continue
        if key == "</virtualhost>":
            if vhost is not None:
                st = {**globals_, **{k: v for k, v in vhost.items() if k != "confcmd"}}
                cmds = {
                    **(globals_.get("confcmd") or {}),
                    **(vhost.get("confcmd") or {}),
                }
                if str(st.get("engine", "")).lower() == "on":
                    ports = [p for p in (_port_of(a) for a in vhost["addrs"]) if p]
                    gv, setting = None, None
                    for k in ("curves", "groups"):
                        if k in cmds:
                            gv, setting = cmds[k], f"SSLOpenSSLConfCmd {k.capitalize()}"
                    if "ecdhparameters" in cmds and gv is None:
                        gv, setting = (
                            cmds["ecdhparameters"],
                            "SSLOpenSSLConfCmd ECDHParameters",
                        )
                    proto = st.get("protocol")
                    endpoints.append(
                        make_endpoint(
                            file=vhost["file"],
                            line=vhost["line"],
                            ports=ports or [443],
                            context="VirtualHost " + " ".join(vhost["addrs"]),
                            groups=split_groups(gv),
                            groups_setting=setting
                            if split_groups(gv) is not None
                            else None,
                            protocols=_apache_protocols(proto) if proto else None,
                            min_protocol=cmds.get("minprotocol"),
                            max_protocol=cmds.get("maxprotocol"),
                            ciphers=st.get("ciphers"),
                            ciphersuites=cmds.get("ciphersuites"),
                            certificates=[st["cert"]] if st.get("cert") else [],
                        )
                    )
            vhost = None
            continue
        target = vhost if vhost is not None else globals_
        if key == "sslopensslconfcmd":
            conf_cmd(target, arg)
        elif key in _APACHE_SSL:
            target[_APACHE_SSL[key]] = arg.strip("'\"")
    return {"files": files, "unreadable": unreadable, "endpoints": endpoints}


# ---------------------------------------------------------------------------
# HAProxy
# ---------------------------------------------------------------------------


def parse_haproxy(paths: list[str], reader: Reader) -> dict[str, Any]:
    """Endpoints of every ``bind`` line with ``ssl``.  ``curves`` on the
    bind line wins over ``ssl-default-bind-curves`` in ``global``; with
    neither, HAProxy leaves OpenSSL's default list in place (measured on
    HAProxy 2.8, 3.0 and 3.2)."""
    files: list[str] = []
    unreadable: list[dict[str, str]] = []
    glob: dict[str, str] = {}
    binds: list[tuple[str, int, str, list[str]]] = []
    for path in paths:
        text = reader(path)
        if text is None:
            unreadable.append({"path": path, "reason": "missing or not readable"})
            continue
        files.append(path)
        section = ""
        for i, raw in enumerate(text.splitlines(), 1):
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            words = line.split()
            kw = words[0].lower()
            if kw in (
                "global",
                "defaults",
                "frontend",
                "backend",
                "listen",
                "peers",
                "resolvers",
                "userlist",
                "program",
                "cache",
                "ring",
                "http-errors",
                "mailers",
            ):
                section = f"{kw} {' '.join(words[1:2])}".strip()
                continue
            if section == "global" and kw.startswith("ssl-default-bind-"):
                glob[kw] = " ".join(words[1:])
            elif kw == "bind" and (
                section.startswith("frontend") or section.startswith("listen")
            ):
                binds.append((path, i, section, words[1:]))
    endpoints = []
    gopts = (glob.get("ssl-default-bind-options") or "").split()
    for path, line_no, section, words in binds:
        if "ssl" not in words:
            continue
        ports = []
        for addr in words[0].split(","):
            p = _port_of(addr)
            if p:
                ports.append(p)
        opts: dict[str, str] = {}
        flags = set()
        i = 1
        while i < len(words):
            w = words[i]
            if w in (
                "curves",
                "ecdhe",
                "ssl-min-ver",
                "ssl-max-ver",
                "ciphers",
                "ciphersuites",
                "crt",
            ) and i + 1 < len(words):
                opts.setdefault(w, words[i + 1]) if w != "crt" else opts.update(
                    {"crt": words[i + 1]}
                )
                i += 2
                continue
            flags.add(w)
            i += 1
        min_v = opts.get("ssl-min-ver")
        max_v = opts.get("ssl-max-ver")
        for j, w in enumerate(gopts):
            if w == "ssl-min-ver" and j + 1 < len(gopts) and not min_v:
                min_v = gopts[j + 1]
            if w == "ssl-max-ver" and j + 1 < len(gopts) and not max_v:
                max_v = gopts[j + 1]
        if "no-tlsv13" in flags or "no-tlsv13" in gopts or "force-tlsv12" in flags:
            max_v = "TLSv1.2"
        gv = (
            opts.get("curves")
            or opts.get("ecdhe")
            or glob.get("ssl-default-bind-curves")
        )
        setting = (
            "bind curves"
            if opts.get("curves")
            else "bind ecdhe"
            if opts.get("ecdhe")
            else "ssl-default-bind-curves"
            if glob.get("ssl-default-bind-curves")
            else None
        )
        endpoints.append(
            make_endpoint(
                file=path,
                line=line_no,
                ports=ports,
                context=section,
                groups=split_groups(gv),
                groups_setting=setting,
                min_protocol=min_v,
                max_protocol=max_v,
                ciphers=opts.get("ciphers") or glob.get("ssl-default-bind-ciphers"),
                ciphersuites=opts.get("ciphersuites")
                or glob.get("ssl-default-bind-ciphersuites"),
                certificates=[opts["crt"]] if opts.get("crt") else [],
            )
        )
    return {"files": files, "unreadable": unreadable, "endpoints": endpoints}


# ---------------------------------------------------------------------------
# stunnel
# ---------------------------------------------------------------------------


def parse_stunnel(
    paths: list[str], reader: Reader, lister: Lister, default_curves: list[str] | None
) -> dict[str, Any]:
    """Endpoints of every service section with ``accept``.  stunnel always
    sets a group list: ``curves`` when configured, otherwise its compiled
    default (``default_curves``, read from the binary by the caller),
    which has no ML-KEM group unless stunnel was built for OpenSSL 3.5
    (stunnel 5.76+; measured classical on EL9 5.71 and EL10 5.72, ML-KEM
    on Fedora 44 and Ubuntu 26.04)."""
    files: list[str] = []
    unreadable: list[dict[str, str]] = []
    sections: list[tuple[str, int, str, dict[str, str]]] = []

    def load(path: str, depth: int) -> None:
        text = reader(path)
        if text is None:
            unreadable.append({"path": path, "reason": "missing or not readable"})
            return
        files.append(path)
        cur: dict[str, str] = {}
        sections.append((path, 1, "", cur))
        for i, raw in enumerate(text.splitlines(), 1):
            line = raw.strip()
            if not line or line[0] in "#;":
                continue
            m = re.match(r"^\[([^\]]+)\]$", line)
            if m:
                cur = {}
                sections.append((path, i, m.group(1).strip(), cur))
                continue
            if "=" not in line:
                continue
            k, v = (x.strip() for x in line.split("=", 1))
            k = k.lower()
            if k == "include" and depth < MAX_INCLUDE_DEPTH:
                for p in sorted(lister(posixpath.join(v, "*.conf"))):
                    load(p, depth + 1)
                continue
            cur[k] = v

    for p in paths:
        load(p, 0)
    glob: dict[str, str] = {}
    for _path, _line, name, opts in sections:
        if not name:
            glob.update(opts)
    endpoints = []
    for path, line_no, name, opts in sections:
        if not name or "accept" not in opts:
            continue
        st = {**glob, **opts}
        port = _port_of(st["accept"])
        client = st.get("client", "no").lower() in ("yes", "true", "1")
        gv = st.get("curves") or st.get("curve")
        version = st.get("sslversion")
        endpoints.append(
            make_endpoint(
                file=path,
                line=line_no,
                ports=[port] if port else [],
                context=f"[{name}]",
                role="client" if client else "server",
                groups=split_groups(gv),
                groups_setting=("curves" if gv else None),
                service_default_groups=default_curves,
                protocols=[version] if version and version.lower() != "all" else None,
                min_protocol=st.get("sslversionmin"),
                max_protocol=st.get("sslversionmax"),
                ciphers=st.get("ciphers"),
                ciphersuites=st.get("ciphersuites"),
                certificates=[st["cert"]] if st.get("cert") else [],
            )
        )
    return {"files": files, "unreadable": unreadable, "endpoints": endpoints}


# ---------------------------------------------------------------------------
# Squid
# ---------------------------------------------------------------------------


def parse_squid(main: str, reader: Reader, lister: Lister) -> dict[str, Any]:
    """Endpoints of every ``https_port`` (and ``http_port`` with a TLS
    certificate, i.e. ssl-bump).  ``tls-dh=curve:file`` pins one curve;
    otherwise the OpenSSL default list applies."""
    files: list[str] = []
    unreadable: list[dict[str, str]] = []
    endpoints = []

    def load(path: str, depth: int) -> None:
        text = reader(path)
        if text is None:
            unreadable.append({"path": path, "reason": "missing or not readable"})
            return
        files.append(path)
        for i, raw in enumerate(text.splitlines(), 1):
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            words = line.split()
            kw = words[0].lower()
            if kw == "include" and len(words) > 1 and depth < MAX_INCLUDE_DEPTH:
                for p in _expand(_resolve(posixpath.dirname(main), words[1]), lister):
                    load(p, depth + 1)
                continue
            if kw not in ("https_port", "http_port") or len(words) < 2:
                continue
            opts = dict(w.split("=", 1) for w in words[2:] if "=" in w)
            cert = opts.get("tls-cert") or opts.get("cert")
            if kw == "http_port" and not cert:
                continue
            port = _port_of(words[1])
            dh = opts.get("tls-dh") or opts.get("dhparams")
            curve = None
            if dh and ":" in dh and not dh.startswith("/"):
                curve = dh.split(":", 1)[0]
            tls_opts = (opts.get("tls-options") or opts.get("options") or "").upper()
            max_v = "TLSv1.2" if "NO_TLSV1_3" in tls_opts else None
            endpoints.append(
                make_endpoint(
                    file=path,
                    line=i,
                    ports=[port] if port else [],
                    context=kw,
                    groups=[curve] if curve else None,
                    groups_setting="tls-dh" if curve else None,
                    min_protocol=opts.get("tls-min-version"),
                    max_protocol=max_v,
                    ciphers=opts.get("cipher"),
                    certificates=[cert] if cert else [],
                )
            )

    load(main, 0)
    return {"files": files, "unreadable": unreadable, "endpoints": endpoints}


# ---------------------------------------------------------------------------
# Postfix
# ---------------------------------------------------------------------------


def parse_postfix_main(text: str) -> dict[str, tuple[str, int]]:
    """main.cf: ``name = value`` with whitespace-led continuation lines."""
    out: dict[str, tuple[str, int]] = {}
    key: str | None = None
    for i, raw in enumerate(text.splitlines(), 1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if raw[0].isspace() and key:
            v, ln = out[key]
            out[key] = ((v + " " + raw.strip()).strip(), ln)
            continue
        if "=" in raw:
            k, v = raw.split("=", 1)
            key = k.strip()
            out[key] = (v.strip(), i)
    return out


_POSTFIX_PORTS = {"smtp": 25, "submission": 587, "submissions": 465, "smtps": 465}


def parse_postfix_master(text: str) -> list[dict[str, Any]]:
    """master.cf ``inet`` services running smtpd, with their ``-o`` overrides."""
    entries: list[tuple[int, str]] = []
    for i, raw in enumerate(text.splitlines(), 1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if raw[0].isspace() and entries:
            ln, prev = entries[-1]
            entries[-1] = (ln, prev + " " + raw.strip())
        else:
            entries.append((i, raw.strip()))
    out = []
    for ln, e in entries:
        words = e.split()
        if len(words) < 8 or words[1] != "inet" or words[7] != "smtpd":
            continue
        svc = words[0]
        port = _POSTFIX_PORTS.get(svc.rsplit(":", 1)[-1]) or _port_of(svc)
        overrides: dict[str, str] = {}
        rest = " ".join(words[8:])
        for m in re.finditer(
            r"-o\s+\{\s*([\w.]+)\s*=\s*([^}]*)\}|-o\s+([\w.]+)=(\S*)", rest
        ):
            k = m.group(1) or m.group(3)
            v = (m.group(2) if m.group(1) else m.group(4)) or ""
            overrides[k] = v.strip()
        out.append({"service": svc, "line": ln, "port": port, "overrides": overrides})
    return out


POSTFIX_CLASSICAL_DEFAULT = ["X25519", "X448", "prime256v1", "secp384r1", "secp521r1"]


def parse_postfix(
    main_path: str, master_path: str, reader: Reader, default_curves: list[str] | None
) -> dict[str, Any]:
    """smtpd endpoints.  Postfix always hands OpenSSL a group list taken
    from ``tls_eecdh_auto_curves``: its compiled default is classical
    before Postfix 3.11 (``postconf -d`` on EL9 3.5, EL10 3.8, Fedora
    3.10, Ubuntu 3.10, Leap 3.10; every one negotiated classical TLS 1.3
    with an ML-KEM-offering client), ``?X25519MLKEM768:DEFAULT`` from 3.11
    with OpenSSL 3.5.  An explicitly empty value (allowed from 3.10)
    leaves the choice to OpenSSL's configuration."""
    files: list[str] = []
    unreadable: list[dict[str, str]] = []
    mtext = reader(main_path)
    if mtext is None:
        unreadable.append({"path": main_path, "reason": "not readable"})
        return {"files": files, "unreadable": unreadable, "endpoints": []}
    files.append(main_path)
    main = parse_postfix_main(mtext)
    services: list[dict[str, Any]] = []
    master_text = reader(master_path)
    if master_text is not None:
        files.append(master_path)
        services = parse_postfix_master(master_text)
    else:
        services = [{"service": "smtp", "line": None, "port": 25, "overrides": {}}]
    endpoints = []
    for svc in services:

        def get(
            k: str, svc: dict[str, Any] = svc
        ) -> tuple[str | None, str, int | None]:
            if k in svc["overrides"]:
                return svc["overrides"][k], master_path, svc["line"]
            if k in main:
                return main[k][0], main_path, main[k][1]
            return None, main_path, None

        level = (get("smtpd_tls_security_level")[0] or "").lower()
        use = (get("smtpd_use_tls")[0] or "").lower() == "yes"
        wrapper = (get("smtpd_tls_wrappermode")[0] or "").lower() == "yes"
        cert = (
            get("smtpd_tls_cert_file")[0]
            or get("smtpd_tls_chain_files")[0]
            or get("smtpd_tls_eccert_file")[0]
        )
        if not cert or not (level in ("may", "encrypt") or use or wrapper):
            continue
        curves, cfile, cline = get("tls_eecdh_auto_curves")
        groups = None
        setting = None
        follows_openssl = False
        if curves is not None:
            if curves.strip() == "":
                follows_openssl = True
            else:
                groups = split_groups(curves)
                setting = "tls_eecdh_auto_curves"
        protos = get(
            "smtpd_tls_mandatory_protocols" if wrapper else "smtpd_tls_protocols"
        )[0]
        min_v, max_v, allowed = _postfix_protocols(protos)
        endpoints.append(
            make_endpoint(
                file=master_path if svc["line"] else main_path,
                line=svc["line"],
                ports=[svc["port"]] if svc["port"] else [],
                context=f"smtpd {svc['service']}",
                groups=groups,
                groups_setting=setting,
                service_default_groups=None if follows_openssl else default_curves,
                protocols=allowed,
                min_protocol=min_v,
                max_protocol=max_v,
                ciphers=get("smtpd_tls_ciphers")[0],
                certificates=[cert.split(",")[0].strip()],
            )
        )
    return {"files": files, "unreadable": unreadable, "endpoints": endpoints}


def _postfix_protocols(
    value: str | None,
) -> tuple[str | None, str | None, list[str] | None]:
    """``>=TLSv1.2`` / ``<=TLSv1.2`` or the older ``!SSLv2, !TLSv1.3`` form."""
    if not value:
        return None, None, None
    v = value.replace(",", " ").split()
    mn = mx = None
    excluded = set()
    for tok in v:
        if tok.startswith(">="):
            mn = tok[2:]
        elif tok.startswith("<="):
            mx = tok[2:]
        elif tok.startswith("!"):
            excluded.add(tok[1:].lower())
    allowed = None
    if excluded:
        allowed = [
            p
            for p in ("TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3")
            if p.lower() not in excluded
        ]
    return mn, mx, allowed


# ---------------------------------------------------------------------------
# Dovecot
# ---------------------------------------------------------------------------


_DOVECOT_PORTS = {
    "imap": [143, 993],
    "pop3": [110, 995],
    "submission": [587, 465],
    "sieve": [4190],
}


def parse_dovecot(main: str, reader: Reader, lister: Lister) -> dict[str, Any]:
    """One endpoint for the daemon's top-level TLS settings (Dovecot 2.3
    ``ssl_cert`` and 2.4 ``ssl_server_cert_file`` spellings), with the
    ports of its enabled protocols.  ``ssl_curve_list`` defaults to empty
    = OpenSSL's list (measured: CentOS Stream 10, 2.3.21, negotiated
    X25519MLKEM768)."""
    files: list[str] = []
    unreadable: list[dict[str, str]] = []
    settings: dict[str, tuple[str, str, int]] = {}
    listener_ports: list[int] = []

    def load(path: str, depth: int, optional: bool = False) -> None:
        text = reader(path)
        if text is None:
            if not optional:
                unreadable.append({"path": path, "reason": "missing or not readable"})
            return
        files.append(path)
        stack: list[str] = []
        cur_listener: dict[str, str] | None = None
        for i, raw in enumerate(text.splitlines(), 1):
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            m = re.match(r"^!include(_try)?\s+(\S+)", line)
            if m and depth < MAX_INCLUDE_DEPTH:
                for p in _expand(_resolve(posixpath.dirname(path), m.group(2)), lister):
                    load(p, depth + 1, optional=bool(m.group(1)))
                continue
            if line.endswith("{"):
                head = line[:-1].strip()
                stack.append(head)
                if head.startswith("inet_listener"):
                    cur_listener = {}
                continue
            if line == "}":
                if (
                    stack
                    and stack[-1].startswith("inet_listener")
                    and cur_listener is not None
                ):
                    port = cur_listener.get("port")
                    if port and port.isdigit() and int(port) > 0:
                        listener_ports.append(int(port))
                    cur_listener = None
                if stack:
                    stack.pop()
                continue
            if "=" not in line:
                continue
            k, v = (x.strip() for x in line.split("=", 1))
            if cur_listener is not None:
                cur_listener[k] = v
            elif not stack:
                settings[k] = (v, path, i)

    load(main, 0)
    endpoints = []
    ssl = (settings.get("ssl", ("yes", main, 0))[0]).lower()
    cert = (
        settings.get("ssl_server_cert_file") or settings.get("ssl_cert") or (None,)
    )[0]
    if ssl != "no" and cert:
        protocols = (settings.get("protocols") or ("imap pop3 lmtp",))[0].split()
        ports = list(listener_ports)
        for proto in protocols:
            ports.extend(_DOVECOT_PORTS.get(proto, []))
        curve = settings.get("ssl_curve_list")
        where = (
            settings.get("ssl_server_cert_file")
            or settings.get("ssl_cert")
            or (None, main, None)
        )
        endpoints.append(
            make_endpoint(
                file=where[1],
                line=where[2],
                ports=ports,
                context="global",
                groups=split_groups(curve[0]) if curve else None,
                groups_setting="ssl_curve_list"
                if curve and split_groups(curve[0])
                else None,
                min_protocol=(settings.get("ssl_min_protocol") or (None,))[0],
                ciphers=(settings.get("ssl_cipher_list") or (None,))[0],
                ciphersuites=(settings.get("ssl_cipher_suites") or (None,))[0],
                certificates=[cert.lstrip("<")],
            )
        )
    return {"files": files, "unreadable": unreadable, "endpoints": endpoints}


# ---------------------------------------------------------------------------
# PostgreSQL
# ---------------------------------------------------------------------------


def parse_pg_conf(text: str) -> list[tuple[str, str, int]]:
    out = []
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^([\w.]+)\s*(?:=\s*|\s+)(.*)$", line)
        if not m:
            continue
        val = m.group(2).strip()
        if val.startswith("'"):
            end = val.find("'", 1)
            val = val[1:end] if end > 0 else val[1:]
        else:
            val = val.split("#", 1)[0].strip()
        out.append((m.group(1).lower(), val, i))
    return out


def parse_postgresql(
    confs: list[str], reader: Reader, lister: Lister, major: int | None
) -> dict[str, Any]:
    """The server's single TLS endpoint when ``ssl = on``.  PostgreSQL
    always sets its own group list: before 18, ``ssl_ecdh_curve`` (one
    elliptic curve, default prime256v1, applied with
    ``SSL_CTX_set_tmp_ecdh``, so ML-KEM can never be configured); from 18,
    ``ssl_groups`` (default ``X25519:prime256v1``, applied with
    ``SSL_CTX_set1_groups_list``).  ``confs`` lists postgresql.conf then
    postgresql.auto.conf (ALTER SYSTEM), later values win."""
    files: list[str] = []
    unreadable: list[dict[str, str]] = []
    settings: dict[str, tuple[str, str, int]] = {}

    def load(path: str, depth: int, optional: bool = False) -> None:
        text = reader(path)
        if text is None:
            if not optional:
                unreadable.append({"path": path, "reason": "missing or not readable"})
            return
        files.append(path)
        for k, v, ln in parse_pg_conf(text):
            if k in ("include", "include_if_exists") and depth < MAX_INCLUDE_DEPTH:
                load(
                    _resolve(posixpath.dirname(path), v),
                    depth + 1,
                    k == "include_if_exists",
                )
            elif k == "include_dir" and depth < MAX_INCLUDE_DEPTH:
                for p in sorted(
                    lister(
                        posixpath.join(_resolve(posixpath.dirname(path), v), "*.conf")
                    )
                ):
                    load(p, depth + 1)
            else:
                settings[k] = (v, path, ln)

    for i, c in enumerate(confs):
        load(c, 0, optional=i > 0)
    endpoints = []
    if (settings.get("ssl") or ("off",))[0].lower() in ("on", "true", "yes", "1"):
        port = (settings.get("port") or ("5432",))[0]
        gkey = "ssl_groups" if "ssl_groups" in settings else "ssl_ecdh_curve"
        gv = settings.get(gkey)
        if major is not None and major < 18:
            default = ["prime256v1"]
            supports: bool | None = False
            setting_name = "ssl_ecdh_curve"
        elif major is not None:
            default = ["X25519", "prime256v1"]
            supports = None
            setting_name = gkey if gv else "ssl_groups"
        else:
            default = None
            supports = None
            setting_name = gkey
        where = settings.get("ssl") or ("", confs[0], None)
        endpoints.append(
            make_endpoint(
                file=where[1],
                line=where[2],
                ports=[int(port)] if port.isdigit() else [5432],
                context="server",
                groups=split_groups(gv[0]) if gv else None,
                groups_setting=setting_name,
                service_default_groups=default,
                service_supports_pqc_groups=supports,
                min_protocol=(settings.get("ssl_min_protocol_version") or ("TLSv1.2",))[
                    0
                ]
                or None,
                max_protocol=(settings.get("ssl_max_protocol_version") or ("",))[0]
                or None,
                ciphers=(settings.get("ssl_ciphers") or (None,))[0],
                ciphersuites=(settings.get("ssl_tls13_ciphers") or (None,))[0],
                certificates=[(settings.get("ssl_cert_file") or ("server.crt",))[0]],
                note=(
                    "PostgreSQL before 18 sets one elliptic curve for key exchange; "
                    "ML-KEM needs PostgreSQL 18 and ssl_groups"
                    if supports is False
                    else None
                ),
            )
        )
    return {"files": files, "unreadable": unreadable, "endpoints": endpoints}


# ---------------------------------------------------------------------------
# MariaDB / MySQL
# ---------------------------------------------------------------------------


_MYSQL_SERVER_SECTIONS = ("mysqld", "mariadb", "mariadbd", "server")


def parse_mysql(
    main_paths: list[str], reader: Reader, lister: Lister
) -> dict[str, Any]:
    """The server endpoint when a certificate is configured.  Neither
    MariaDB nor MySQL has a key-exchange group option, so the TLS library
    default applies (measured: MariaDB 10.11 on Stream 10 and 11.8 on
    Fedora 44 / Leap 16 negotiated X25519MLKEM768)."""
    files: list[str] = []
    unreadable: list[dict[str, str]] = []
    settings: dict[str, tuple[str, str, int]] = {}

    def load(path: str, depth: int) -> None:
        text = reader(path)
        if text is None:
            unreadable.append({"path": path, "reason": "missing or not readable"})
            return
        files.append(path)
        section = ""
        for i, raw in enumerate(text.splitlines(), 1):
            line = raw.strip()
            if not line or line[0] in "#;":
                continue
            m = re.match(r"^!include(dir)?\s+(\S+)", line)
            if m and depth < MAX_INCLUDE_DEPTH:
                if m.group(1):
                    for p in sorted(lister(posixpath.join(m.group(2), "*.cnf"))):
                        load(p, depth + 1)
                else:
                    load(m.group(2), depth + 1)
                continue
            m = re.match(r"^\[([^\]]+)\]$", line)
            if m:
                section = m.group(1).strip().lower()
                continue
            if section.split("-")[0] not in _MYSQL_SERVER_SECTIONS:
                continue
            k, _, v = line.partition("=")
            settings[k.strip().lower().replace("-", "_")] = (
                v.strip().strip("'\""),
                path,
                i,
            )

    for p in main_paths:
        if reader(p) is not None:
            load(p, 0)
            break
    endpoints = []
    cert = settings.get("ssl_cert")
    if cert or (settings.get("ssl") or ("",))[0].lower() in ("on", "1", "true"):
        port = (settings.get("port") or ("3306",))[0]
        tv = settings.get("tls_version")
        endpoints.append(
            make_endpoint(
                file=(cert or settings["ssl"])[1],
                line=(cert or settings["ssl"])[2],
                ports=[int(port)] if port.isdigit() else [3306],
                context="server",
                protocols=[x.strip() for x in tv[0].split(",")] if tv else None,
                ciphers=(settings.get("ssl_cipher") or (None,))[0],
                ciphersuites=(settings.get("tls_ciphersuites") or (None,))[0],
                certificates=[cert[0]] if cert else [],
            )
        )
    return {"files": files, "unreadable": unreadable, "endpoints": endpoints}


# ---------------------------------------------------------------------------
# Redis / Valkey
# ---------------------------------------------------------------------------


def parse_redis(main: str, reader: Reader, lister: Lister) -> dict[str, Any]:
    """The ``tls-port`` endpoint.  No group option exists; the TLS library
    default applies (measured: Redis 6.2 / 8.0 and Valkey 8.1 / 9.0)."""
    files: list[str] = []
    unreadable: list[dict[str, str]] = []
    settings: dict[str, tuple[str, str, int]] = {}

    def load(path: str, depth: int) -> None:
        text = reader(path)
        if text is None:
            unreadable.append({"path": path, "reason": "missing or not readable"})
            return
        files.append(path)
        for i, raw in enumerate(text.splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            k = parts[0].lower()
            v = parts[1].strip().strip('"') if len(parts) > 1 else ""
            if k == "include" and depth < MAX_INCLUDE_DEPTH:
                for p in _expand(v, lister):
                    load(p, depth + 1)
            else:
                settings[k] = (v, path, i)

    load(main, 0)
    endpoints = []
    tp = settings.get("tls-port")
    if tp and tp[0].isdigit() and int(tp[0]) > 0:
        protos = settings.get("tls-protocols")
        endpoints.append(
            make_endpoint(
                file=tp[1],
                line=tp[2],
                ports=[int(tp[0])],
                context="tls-port",
                protocols=protos[0].split() if protos else None,
                ciphers=(settings.get("tls-ciphers") or (None,))[0],
                ciphersuites=(settings.get("tls-ciphersuites") or (None,))[0],
                certificates=[
                    x for x in [(settings.get("tls-cert-file") or (None,))[0]] if x
                ],
            )
        )
    return {"files": files, "unreadable": unreadable, "endpoints": endpoints}


# ---------------------------------------------------------------------------
# OpenLDAP
# ---------------------------------------------------------------------------


_LDAP_PROTO = {"3.1": "TLSv1", "3.2": "TLSv1.1", "3.3": "TLSv1.2", "3.4": "TLSv1.3"}


def parse_openldap(
    paths: list[str], reader: Reader, urls: str | None
) -> dict[str, Any]:
    """slapd's TLS settings from cn=config (``olcTLS*`` in
    ``slapd.d/cn=config.ldif``) or slapd.conf (``TLS*``).  ``TLSECName``
    is OpenLDAP's group list; unset, the library default applies
    (measured: Fedora 44, OpenSSL, negotiated X25519MLKEM768)."""
    files: list[str] = []
    unreadable: list[dict[str, str]] = []
    settings: dict[str, tuple[str, str, int]] = {}
    for path in paths:
        text = reader(path)
        if text is None:
            unreadable.append({"path": path, "reason": "missing or not readable"})
            continue
        files.append(path)
        for i, raw in enumerate(text.splitlines(), 1):
            line = raw.strip()
            m = re.match(r"^(?:olc)?(TLS\w+)\s*:?\s+(.+)$", line, re.IGNORECASE)
            if m:
                settings[m.group(1).lower()] = (m.group(2).strip().strip('"'), path, i)
    endpoints = []
    cert = settings.get("tlscertificatefile")
    if cert:
        ports = [389]
        if urls and "ldaps://" in urls:
            ports.append(636)
        pm = settings.get("tlsprotocolmin")
        ec = settings.get("tlsecname")
        endpoints.append(
            make_endpoint(
                file=cert[1],
                line=cert[2],
                ports=ports,
                context="slapd",
                groups=split_groups(ec[0]) if ec else None,
                groups_setting="TLSECName" if ec else None,
                min_protocol=_LDAP_PROTO.get(pm[0]) if pm else None,
                ciphers=(settings.get("tlsciphersuite") or (None,))[0],
                certificates=[cert[0]],
            )
        )
    return {"files": files, "unreadable": unreadable, "endpoints": endpoints}


# ---------------------------------------------------------------------------
# 389 Directory Server
# ---------------------------------------------------------------------------


def parse_dse_ldif(path: str, reader: Reader) -> dict[str, Any]:
    """``nsslapd-security: on`` instances.  389 DS uses NSS, whose groups
    follow the system crypto policy's NSS back-end."""
    text = reader(path)
    if text is None:
        return {
            "files": [],
            "unreadable": [{"path": path, "reason": "not readable"}],
            "endpoints": [],
        }
    entries: list[dict[str, tuple[str, int]]] = []
    cur: dict[str, tuple[str, int]] = {}
    for i, raw in enumerate(text.splitlines(), 1):
        if not raw.strip():
            if cur:
                entries.append(cur)
            cur = {}
            continue
        if ":" in raw and not raw.startswith(" "):
            k, v = raw.split(":", 1)
            cur.setdefault(k.strip().lower(), (v.strip(), i))
    if cur:
        entries.append(cur)
    config = next(
        (e for e in entries if e.get("dn", ("",))[0].lower() == "cn=config"), {}
    )
    enc = next(
        (
            e
            for e in entries
            if e.get("dn", ("",))[0].lower() == "cn=encryption,cn=config"
        ),
        {},
    )
    endpoints = []
    if config.get("nsslapd-security", ("off",))[0].lower() == "on":
        port = config.get("nsslapd-secureport", ("636", 0))[0]
        endpoints.append(
            make_endpoint(
                file=path,
                line=config.get("nsslapd-security", ("", None))[1],
                ports=[int(port)] if port.isdigit() else [636],
                context="nsslapd-security",
                min_protocol=enc.get("sslversionmin", (None,))[0],
                max_protocol=enc.get("sslversionmax", (None,))[0],
                ciphers=enc.get("nsssl3ciphers", (None,))[0],
                note="NSS-based: key exchange groups follow the NSS crypto policy",
            )
        )
    return {"files": [path], "unreadable": [], "endpoints": endpoints}


# ---------------------------------------------------------------------------
# Tomcat
# ---------------------------------------------------------------------------


def parse_tomcat(path: str, reader: Reader) -> dict[str, Any]:
    """``<Connector SSLEnabled="true">`` endpoints from server.xml.  The
    JSSE implementation (the default) follows the JDK's TLS defaults; the
    OpenSSL implementation follows OpenSSL's.  ``groups`` on
    ``SSLHostConfig`` is read when present."""
    text = reader(path)
    if text is None:
        return {
            "files": [],
            "unreadable": [{"path": path, "reason": "not readable"}],
            "endpoints": [],
        }
    try:
        root = ET.fromstring(text)
    except ET.ParseError as e:
        return {
            "files": [path],
            "unreadable": [{"path": path, "reason": f"XML parse error: {e}"}],
            "endpoints": [],
        }
    endpoints = []
    for conn in root.iter("Connector"):
        if conn.get("SSLEnabled", "").lower() != "true":
            continue
        port = conn.get("port", "")
        impl = conn.get("sslImplementationName") or ""
        host = conn.find("SSLHostConfig")
        attrs = dict(conn.attrib)
        if host is not None:
            attrs.update(host.attrib)
        protos = attrs.get("protocols") or attrs.get("sslEnabledProtocols")
        allowed = (
            [
                p.lstrip("+")
                for p in re.split(r"[,+\s]+", protos)
                if p and not p.startswith("-")
            ]
            if protos
            else None
        )
        certs = []
        if host is not None:
            for c in host.iter("Certificate"):
                certs.append(
                    c.get("certificateFile") or c.get("certificateKeystoreFile") or ""
                )
        engine = (
            "openssl"
            if "openssl" in impl.lower() or "OpenSSLImplementation" in impl
            else "jsse"
        )
        endpoints.append(
            make_endpoint(
                file=path,
                line=None,
                ports=[int(port)] if port.isdigit() else [],
                context=f"Connector {conn.get('protocol') or ''} ({engine})".strip(),
                groups=split_groups(attrs.get("groups")),
                groups_setting="groups" if attrs.get("groups") else None,
                protocols=[a for a in allowed if a.lower() != "all"]
                if allowed and "all" not in [a.lower() for a in allowed]
                else None,
                ciphers=attrs.get("ciphers"),
                certificates=[c for c in certs if c],
                note="JSSE: key exchange groups follow the JDK's jdk.tls.namedGroups default"
                if engine == "jsse"
                else None,
            )
        )
    return {"files": [path], "unreadable": [], "endpoints": endpoints}


def matches_any(name: str, patterns: Iterable[str]) -> bool:
    return any(fnmatch.fnmatch(name, p) for p in patterns)
