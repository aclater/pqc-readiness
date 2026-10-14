"""Per-service TLS configuration (--scan-service-configs, #216).

A listening service's key exchange is decided by its own settings before
the system crypto policy or ``openssl.cnf`` get a say.  This module reads
the TLS configuration of the server daemons commonly found on Linux and
records, per endpoint, the groups it offers and whether that includes a
hybrid ML-KEM group.  The deployment-gap verdict (gap.py) uses it to judge
each listening service on its own configuration, and SARIF rule pqc-021
reports services whose own configuration keeps PQC out although the TLS
library could do it.

Measured 2026-10-14 on booted cloud images (Rocky 9.8, CentOS Stream 10,
Fedora 44, Ubuntu 26.04, openSUSE Leap 16.0), each daemon configured with
TLS and probed by a client offering X25519MLKEM768:

* services without a group setting follow the TLS library default:
  nginx, Apache httpd, HAProxy, Squid, Dovecot, MariaDB, Redis / Valkey
  and OpenLDAP negotiated X25519MLKEM768 wherever the crypto policy
  allows it (not on Rocky 9.8's DEFAULT policy);
* an explicit group list wins over the policy in both directions: a list
  without ML-KEM negotiated classical everywhere, and nginx with
  ``ssl_ecdh_curve X25519MLKEM768:X25519`` negotiated ML-KEM on Rocky 9.8;
* Postfix (3.5 to 3.10) and stunnel on EL9 / EL10 (5.71 / 5.72, built
  against OpenSSL 3.2) apply compiled-in classical lists and stay
  classical on every distribution; stunnel on Fedora 44 and Ubuntu 26.04
  carries an ML-KEM default.

Sources are files only (no subprocess), read through the host prefix so
the same code serves live hosts, --host-mount and offline --root trees.
"""

from __future__ import annotations

import argparse
import functools
import logging
import re
from pathlib import Path
from typing import Any, Callable

from .. import _platform as _platform
from .. import registry as _registry
from . import config_read as _config_read
from . import packages as _packages
from . import protocols_libraries as _libraries
from . import config_services_parsers as _p

log = logging.getLogger("pqc-readiness")

MAX_CONFIG_BYTES = 1024 * 1024
MAX_GLOB_RESULTS = 500


def _host(path: str) -> Path:
    resolved = _packages.resolve_under_prefix(path, _platform.HOST_PREFIX)
    return Path(_platform.HOST_PREFIX + resolved)


def read_text(path: str) -> str | None:
    """Host config file text, or None when missing / unreadable / too big."""
    try:
        p = _host(path)
        if not p.is_file() or p.stat().st_size > MAX_CONFIG_BYTES:
            return None
        return p.read_text(errors="replace")
    except (OSError, _packages.RpmdbError) as e:
        log.debug("service-configs: cannot read %s: %s", path, e)
        return None


def read_error(path: str) -> str | None:
    """Why an existing path can't be read, or None (readable or absent)."""
    if not _config_read.present(path):
        return None
    reason = _config_read.probe(path)
    if reason is None:
        try:
            if _host(path).is_file() and _host(path).stat().st_size > MAX_CONFIG_BYTES:
                return f"larger than {MAX_CONFIG_BYTES} bytes; skipped"
        except (OSError, _packages.RpmdbError):
            pass
    return reason


def _sort_unreadable(svc: dict[str, Any]) -> dict[str, Any]:
    """Parsers list every file their reader got no text for as unreadable.
    Split those into files that don't exist (``missing``, e.g. an Include
    naming an absent file) and files that exist but can't be read, each
    with the precise reason (#232)."""
    entries = svc.get("unreadable") or []
    if not entries:
        return svc
    unreadable: list[dict[str, str]] = []
    missing: list[str] = []
    for u in entries:
        path = u.get("path", "")
        if path and not _config_read.present(path):
            missing.append(path)
            continue
        reason = read_error(path) if path else None
        unreadable.append({"path": path, "reason": reason or u.get("reason", "")})
    svc["unreadable"] = unreadable
    if missing:
        svc["missing"] = missing
    return svc


def list_glob(pattern: str) -> list[str]:
    """Host paths matching a glob (sorted, capped).  Directories on the
    way resolve inside the tree, not the scanner's (#258)."""
    try:
        found = _platform.host_glob(pattern)
    except (OSError, ValueError) as e:
        log.debug("service-configs: glob %s failed: %s", pattern, e)
        return []
    return found[:MAX_GLOB_RESULTS]


def _exists(path: str) -> bool:
    """Exists on the host, counting a path behind a directory this user
    can't search as existing (#232)."""
    return _config_read.present(path)


def _first(paths: tuple[str, ...]) -> str | None:
    for p in paths:
        if _exists(p):
            return p
    return None


# ---------------------------------------------------------------------------
# Versions and compiled-in defaults
# ---------------------------------------------------------------------------


def _version(spec: dict[str, Any], family: str) -> str | None:
    try:
        pkgs = _libraries._package_versions(spec, family)
    except Exception as e:  # noqa: BLE001 - any package-db failure means "unknown"
        log.debug("service-configs: version lookup failed: %s", e)
        return None
    return str(pkgs[0].get("version") or "") or None if pkgs else None


def _vtuple(v: str | None) -> tuple[int, ...] | None:
    if not v:
        return None
    m = re.match(r"(?:\d+:)?(\d+)(?:\.(\d+))?(?:\.(\d+))?", v)
    if not m:
        return None
    return tuple(int(x) for x in m.groups() if x is not None)


# Postfix's compiled default tls_eecdh_auto_curves (src/global/mail_params.h):
# ML-KEM from the 3.11 cycle (HISTORY 20251102) when built with OpenSSL 3.5.
POSTFIX_MLKEM_DEFAULT_VERSION = (3, 11)


def postfix_default_curves(
    version: str | None, openssl_pqc: bool | None
) -> list[str] | None:
    vt = _vtuple(version)
    if vt is None:
        return None
    if vt[:2] >= POSTFIX_MLKEM_DEFAULT_VERSION and openssl_pqc:
        return ["X25519MLKEM768", "DEFAULT"]
    return list(_p.POSTFIX_CLASSICAL_DEFAULT)


# stunnel's DEFAULT_CURVES (src/options.c) is chosen at build time; the
# string is in the binary, so read it there rather than guess from the
# version (EL10's 5.72 was built against OpenSSL 3.2 and runs on 3.5).
STUNNEL_BINARIES = ("/usr/bin/stunnel", "/usr/bin/stunnel4", "/usr/sbin/stunnel")
_STUNNEL_DEFAULT_RE = re.compile(
    rb"(X25519MLKEM768:)?X25519:P-256:(?:X448:)?P-521:P-384"
)


def stunnel_default_curves() -> tuple[list[str] | None, str | None]:
    """(default curve list, binary path) from the stunnel binary."""
    for b in STUNNEL_BINARIES:
        try:
            p = _host(b)
            if not p.is_file():
                continue
            data = p.read_bytes()
        except (OSError, _packages.RpmdbError):
            continue
        m = _STUNNEL_DEFAULT_RE.search(data)
        if m:
            return m.group(0).decode().split(":"), b
        return None, b
    return None, None


def _pg_major(conf: str, family: str) -> int | None:
    """PostgreSQL major from the data directory's PG_VERSION, the Debian
    /etc/postgresql/<major>/ path, or the server package."""
    m = re.search(r"/etc/postgresql/(\d+)/", conf)
    if m:
        return int(m.group(1))
    text = read_text(str(Path(conf).parent / "PG_VERSION"))
    if text and text.strip().isdigit():
        return int(text.strip())
    v = _version(
        {
            "packages": {
                "rhel": ("postgresql-server",),
                "suse": tuple(f"postgresql{n}-server" for n in range(19, 11, -1)),
            },
            "debian_package_re": r"^postgresql-\d+$",
        },
        family,
    )
    vt = _vtuple(v)
    return vt[0] if vt else None


# ---------------------------------------------------------------------------
# Service catalogue
# ---------------------------------------------------------------------------

# Process names (as /proc/<pid>/comm shows them) that own each service's
# listening sockets, for joining endpoints to --scan-services listeners.
SERVICE_PROCESSES: dict[str, tuple[str, ...]] = {
    "nginx": ("nginx",),
    "apache": ("httpd", "apache2", "httpd-prefork", "httpd-worker", "httpd-event"),
    "haproxy": ("haproxy",),
    "stunnel": ("stunnel", "stunnel4"),
    "squid": ("squid",),
    "postfix": ("master", "smtpd"),
    "dovecot": ("dovecot", "imap-login", "pop3-login", "submission-login"),
    "postgresql": ("postgres", "postmaster"),
    "mysql": ("mariadbd", "mysqld"),
    "redis": ("redis-server", "valkey-server"),
    "openldap": ("slapd",),
    "389-ds": ("ns-slapd",),
    "tomcat": ("java",),
}

# Executable path fragments that disambiguate generic process names.
SERVICE_EXE_HINTS: dict[str, tuple[str, ...]] = {
    "postfix": ("/postfix/",),
    "tomcat": ("java", "jre", "jdk"),
}


def _scan_nginx(family: str, openssl_pqc: bool | None) -> list[dict[str, Any]]:
    main = _first(("/etc/nginx/nginx.conf",))
    if not main:
        return []
    r = _p.parse_nginx(main, read_text, list_glob)
    return [{"service": "nginx", **r}]


def _scan_apache(family: str, openssl_pqc: bool | None) -> list[dict[str, Any]]:
    for main, root in (
        ("/etc/httpd/conf/httpd.conf", "/etc/httpd"),
        ("/etc/apache2/apache2.conf", "/etc/apache2"),
        ("/etc/apache2/httpd.conf", "/etc/apache2"),
    ):
        if _exists(main):
            return [
                {
                    "service": "apache",
                    **_p.parse_apache(main, root, read_text, list_glob),
                }
            ]
    return []


def _with_running(
    service: dict[str, Any], paths: list[str], extra: tuple[str, ...]
) -> dict[str, Any]:
    used = [p for p in extra if p in paths]
    if used:
        service["config_from_command_line"] = used
    return service


def _scan_haproxy(
    family: str, openssl_pqc: bool | None, extra: tuple[str, ...] = ()
) -> list[dict[str, Any]]:
    paths = [p for p in ("/etc/haproxy/haproxy.cfg",) if _exists(p)]
    paths += list_glob("/etc/haproxy/conf.d/*.cfg")
    paths = _merge_paths(paths, extra)
    if not paths:
        return []
    svc = {"service": "haproxy", **_p.parse_haproxy(paths, read_text)}
    return [_with_running(svc, paths, extra)]


def _scan_stunnel(
    family: str, openssl_pqc: bool | None, extra: tuple[str, ...] = ()
) -> list[dict[str, Any]]:
    paths = _merge_paths(list_glob("/etc/stunnel/*.conf"), extra)
    if not paths:
        return []
    default, binary = stunnel_default_curves()
    r = _p.parse_stunnel(paths, read_text, list_glob, default)
    svc = {
        "service": "stunnel",
        "default_groups_from": binary if default else None,
        **r,
    }
    return [_with_running(svc, paths, extra)]


def _scan_squid(family: str, openssl_pqc: bool | None) -> list[dict[str, Any]]:
    main = _first(("/etc/squid/squid.conf",))
    if not main:
        return []
    return [{"service": "squid", **_p.parse_squid(main, read_text, list_glob)}]


def _scan_postfix(family: str, openssl_pqc: bool | None) -> list[dict[str, Any]]:
    if not _exists("/etc/postfix/main.cf"):
        return []
    version = _version(
        {
            "packages": {
                "rhel": ("postfix",),
                "suse": ("postfix",),
                "arch": ("postfix",),
                "alpine": ("postfix",),
            },
            "debian_package_re": r"^postfix$",
        },
        family,
    )
    default = postfix_default_curves(version, openssl_pqc)
    r = _p.parse_postfix(
        "/etc/postfix/main.cf", "/etc/postfix/master.cf", read_text, default
    )
    return [{"service": "postfix", "version": version, **r}]


def _scan_dovecot(family: str, openssl_pqc: bool | None) -> list[dict[str, Any]]:
    main = _first(("/etc/dovecot/dovecot.conf",))
    if not main:
        return []
    return [{"service": "dovecot", **_p.parse_dovecot(main, read_text, list_glob)}]


PG_CONF_GLOBS = (
    "/etc/postgresql/*/*/postgresql.conf",
    "/var/lib/pgsql/data/postgresql.conf",
    "/var/lib/pgsql/*/data/postgresql.conf",
    "/var/lib/postgresql/data/postgresql.conf",
)
PG_DATA_DIRS = ("/var/lib/pgsql/data", "/var/lib/pgsql", "/var/lib/postgresql")


def _scan_postgresql(family: str, openssl_pqc: bool | None) -> list[dict[str, Any]]:
    out = []
    confs: list[str] = []
    for g in PG_CONF_GLOBS:
        confs.extend(list_glob(g))
    if not confs:
        # Data directories are 0700 postgres: an unprivileged scan sees
        # nothing inside, which is "unknown", not "no TLS".
        for d in PG_DATA_DIRS:
            err = read_error(d)
            if err:
                return [
                    {
                        "service": "postgresql",
                        "files": [],
                        "unreadable": [{"path": d, "reason": err}],
                        "endpoints": [],
                    }
                ]
        return []
    for conf in confs:
        auto = str(Path(conf).parent / "postgresql.auto.conf")
        major = _pg_major(conf, family)
        r = _p.parse_postgresql([conf, auto], read_text, list_glob, major)
        out.append(
            {"service": "postgresql", "version": str(major) if major else None, **r}
        )
    return out


def _scan_mysql(family: str, openssl_pqc: bool | None) -> list[dict[str, Any]]:
    mains = [
        p
        for p in ("/etc/my.cnf", "/etc/mysql/my.cnf", "/etc/mysql/mariadb.cnf")
        if _exists(p)
    ]
    if not mains:
        return []
    return [{"service": "mysql", **_p.parse_mysql(mains, read_text, list_glob)}]


def _scan_redis(family: str, openssl_pqc: bool | None) -> list[dict[str, Any]]:
    out = []
    for main in (
        "/etc/redis/redis.conf",
        "/etc/redis.conf",
        "/etc/valkey/valkey.conf",
        "/etc/redis/default.conf",
        "/etc/valkey/default.conf",
    ):
        if _exists(main):
            r = _p.parse_redis(main, read_text, list_glob)
            out.append({"service": "redis", **r})
    return out


def _scan_openldap(family: str, openssl_pqc: bool | None) -> list[dict[str, Any]]:
    paths = [
        p
        for p in (
            "/etc/openldap/slapd.d/cn=config.ldif",
            "/etc/ldap/slapd.d/cn=config.ldif",
            "/etc/openldap/slapd.conf",
            "/etc/ldap/slapd.conf",
        )
        if _exists(p)
    ]
    if not paths:
        for d in ("/etc/openldap/slapd.d", "/etc/ldap/slapd.d"):
            err = read_error(d)
            if err:
                return [
                    {
                        "service": "openldap",
                        "files": [],
                        "unreadable": [{"path": d, "reason": err}],
                        "endpoints": [],
                    }
                ]
        return []
    urls = None
    for env in (
        "/etc/sysconfig/slapd",
        "/etc/default/slapd",
        "/etc/sysconfig/openldap",
    ):
        text = read_text(env)
        if text:
            m = re.search(
                r'^\s*(?:SLAPD_URLS|OPENLDAP_START_LDAPS)\s*=\s*"?([^"\n]*)', text, re.M
            )
            if m:
                urls = (
                    m.group(1)
                    if "URLS" in m.group(0)
                    else ("ldaps://" if m.group(1).lower() == "yes" else "")
                )
    return [{"service": "openldap", **_p.parse_openldap(paths, read_text, urls)}]


def _scan_389ds(family: str, openssl_pqc: bool | None) -> list[dict[str, Any]]:
    out = []
    for dse in list_glob("/etc/dirsrv/slapd-*/dse.ldif"):
        out.append({"service": "389-ds", **_p.parse_dse_ldif(dse, read_text)})
    return out


def _scan_tomcat(family: str, openssl_pqc: bool | None) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for g in ("/etc/tomcat/server.xml", "/etc/tomcat*/server.xml"):
        for path in list_glob(g):
            if any(o.get("files") == [path] for o in out):
                continue
            out.append({"service": "tomcat", **_p.parse_tomcat(path, read_text)})
    return out


# ---------------------------------------------------------------------------
# Config files named on a running daemon's command line
# ---------------------------------------------------------------------------

MAX_CMDLINE_BYTES = 64 * 1024


def _merge_paths(paths: list[str], extra: tuple[str, ...]) -> list[str]:
    out = list(paths)
    for p in extra:
        if p not in out:
            out.append(p)
    return out


def config_paths_from_cmdline(service: str, argv: list[str]) -> list[str]:
    """Config paths a daemon was started with, beyond the standard ones.

    haproxy takes one or more ``-f <file|dir>`` (a directory means its
    ``*.cfg`` files, in order); stunnel takes its config file as the first
    argument that isn't an option.  Relative paths are skipped: they depend
    on the daemon's working directory, which isn't recorded."""
    out: list[str] = []
    if service == "haproxy":
        i = 1
        while i < len(argv):
            a = argv[i]
            if a == "-f" and i + 1 < len(argv):
                out.append(argv[i + 1])
                i += 2
                continue
            if a.startswith("-f") and len(a) > 2:
                out.append(a[2:])
            i += 1
    elif service == "stunnel":
        for a in argv[1:]:
            if a == "-fd":
                break
            if not a.startswith("-"):
                out.append(a)
                break
    return [p for p in out if p.startswith("/")]


def _cmdline(pid: int) -> list[str]:
    try:
        p = _platform.host_path(f"/proc/{pid}/cmdline")
        with open(p, "rb") as f:
            raw = f.read(MAX_CMDLINE_BYTES)
    except OSError:
        return []
    return [a.decode("utf-8", "replace") for a in raw.split(b"\0") if a]


def running_config_paths(services_info: dict[str, Any] | None) -> dict[str, list[str]]:
    """Per service, config files named on the command line of a process
    that owns a listening socket (from ``--scan-services``).  Directories
    are expanded to their ``*.cfg`` files."""
    out: dict[str, list[str]] = {}
    seen: set[int] = set()
    for lst in (services_info or {}).get("listeners") or []:
        pid = lst.get("pid")
        name = service_for_listener(lst)
        if not isinstance(pid, int) or pid in seen or name not in CMDLINE_SERVICES:
            continue
        seen.add(pid)
        for path in config_paths_from_cmdline(name, _cmdline(pid)):
            try:
                is_dir = _host(path).is_dir()
            except (OSError, _packages.RpmdbError):
                is_dir = False
            for f in list_glob(path.rstrip("/") + "/*.cfg") if is_dir else [path]:
                if f not in out.setdefault(name, []):
                    out[name].append(f)
    return out


CMDLINE_SERVICES = ("haproxy", "stunnel")


SCANNERS: tuple[
    tuple[str, Callable[[str, "bool | None"], list[dict[str, Any]]]], ...
] = (
    ("nginx", _scan_nginx),
    ("apache", _scan_apache),
    ("haproxy", _scan_haproxy),
    ("stunnel", _scan_stunnel),
    ("squid", _scan_squid),
    ("postfix", _scan_postfix),
    ("dovecot", _scan_dovecot),
    ("postgresql", _scan_postgresql),
    ("mysql", _scan_mysql),
    ("redis", _scan_redis),
    ("openldap", _scan_openldap),
    ("389-ds", _scan_389ds),
    ("tomcat", _scan_tomcat),
)


def scan_service_configs(
    os_release: dict[str, Any] | None = None,
    openssl: dict[str, Any] | None = None,
    services_info: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """The ``service_tls_config`` report object.  With ``services_info``
    (a live ``--scan-services`` result), config files named on a running
    daemon's command line are read too."""
    family = (os_release or {}).get("family", "unknown")
    o = openssl or {}
    openssl_pqc: bool | None = None
    if o.get("pqc_native") is not None:
        openssl_pqc = bool(o.get("pqc_native"))
    elif o.get("pqc_native_expected") is not None:
        openssl_pqc = bool(o.get("pqc_native_expected"))
    running = running_config_paths(services_info)
    services: list[dict[str, Any]] = []
    for name, fn in SCANNERS:
        if running.get(name):
            fn = functools.partial(fn, extra=tuple(running[name]))  # type: ignore[call-arg]
        try:
            services.extend(_sort_unreadable(svc) for svc in fn(family, openssl_pqc))
        except Exception as e:  # noqa: BLE001 - one parser must not sink the scan
            log.debug("service-configs: %s scan failed: %s", name, e)
            services.append(
                {
                    "service": name,
                    "files": [],
                    "unreadable": [],
                    "endpoints": [],
                    "error": str(e),
                }
            )
    if not services:
        return {
            "available": False,
            "reason": "no supported service configuration found",
        }
    endpoints = [e for s in services for e in s.get("endpoints") or []]
    out: dict[str, Any] = {
        "available": True,
        "services": services,
        "summary": {
            "services": sorted({s["service"] for s in services}),
            "services_with_tls": sorted(
                {s["service"] for s in services if s.get("endpoints")}
            ),
            "endpoints": len(endpoints),
            "pqc_configured": sum(
                1 for e in endpoints if e["pqc_key_exchange"] is True
            ),
            "pqc_blocked": sum(1 for e in endpoints if e["pqc_key_exchange"] is False),
            "follow_library_default": sum(
                1 for e in endpoints if e["pqc_key_exchange"] is None
            ),
            "unreadable": sorted(
                {u["path"] for s in services for u in s.get("unreadable") or []}
            ),
        },
    }
    note = _platform.host_fs_unavailable_note(
        "Service TLS configuration scan",
        "service configuration under /etc and the PostgreSQL data directory",
    )
    if note:
        out.update(note)
    return out


# ---------------------------------------------------------------------------
# Joining endpoints to listeners and findings
# ---------------------------------------------------------------------------


def service_for_listener(listener: dict[str, Any]) -> str | None:
    proc = str(listener.get("process") or "")
    exe = str(listener.get("exe") or "")
    unit = str(listener.get("systemd_unit") or "")
    for name, procs in SERVICE_PROCESSES.items():
        if proc not in procs:
            continue
        hints = SERVICE_EXE_HINTS.get(name)
        if hints and not any(h in exe for h in hints):
            continue
        if name == "tomcat" and "tomcat" not in unit:
            continue
        return name
    return None


def endpoint_for_listener(
    stc: dict[str, Any], listener: dict[str, Any]
) -> tuple[str, dict[str, Any]] | None:
    """(JSON path, endpoint) of the configured endpoint serving this
    listener: same service and a matching port.  None when the service has
    no TLS endpoint on that port (e.g. httpd's plain :80)."""
    name = service_for_listener(listener)
    if not name or not stc.get("available"):
        return None
    port = listener.get("port")
    for i, svc in enumerate(stc.get("services") or []):
        if svc.get("service") != name:
            continue
        for j, ep in enumerate(svc.get("endpoints") or []):
            if ep.get("role") == "server" and port in (ep.get("ports") or []):
                return f"service_tls_config.services[{i}].endpoints[{j}]", ep
    return None


def blocked_endpoints(
    stc: dict[str, Any], tls_capable: bool | None
) -> list[dict[str, Any]]:
    """Server endpoints whose own configuration keeps PQC out (pqc-021):
    a group list without ML-KEM, TLS 1.3 disabled, or a service that can
    only set one elliptic curve.  Only reported when the host's TLS
    library can do PQC, so the configuration is what's in the way;
    NSS / JSSE endpoints are judged by the library default and never
    listed."""
    if not stc.get("available") or tls_capable is not True:
        return []
    out = []
    for i, svc in enumerate(stc.get("services") or []):
        for j, ep in enumerate(svc.get("endpoints") or []):
            if ep.get("role") != "server" or ep.get("pqc_key_exchange") is not False:
                continue
            out.append(
                {
                    "service": svc.get("service"),
                    "path": f"service_tls_config.services[{i}].endpoints[{j}]",
                    "endpoint": ep,
                    "version": svc.get("version"),
                }
            )
    return out


SERVICE_LABELS = {
    "apache": "Apache httpd",
    "mysql": "MariaDB/MySQL",
    "redis": "Redis/Valkey",
    "postgresql": "PostgreSQL",
    "openldap": "OpenLDAP",
    "389-ds": "389 Directory Server",
    "postfix": "Postfix smtpd",
    "dovecot": "Dovecot",
    "haproxy": "HAProxy",
    "stunnel": "stunnel",
    "squid": "Squid",
    "tomcat": "Tomcat",
    "nginx": "nginx",
}


def describe_blocked(item: dict[str, Any]) -> str:
    ep = item["endpoint"]
    label = SERVICE_LABELS.get(str(item["service"]), str(item["service"]))
    where = ep["file"] + (f":{ep['line']}" if ep.get("line") else "")
    ports = ", ".join(str(p) for p in ep.get("ports") or [])
    head = f"{label} ({where}" + (f", port {ports}" if ports else "") + ")"
    if ep.get("tls13_allowed") is False:
        return f"{head} disables TLS 1.3, so it can't offer hybrid ML-KEM"
    if ep.get("service_supports_pqc_groups") is False:
        return f"{head}: {ep.get('note') or ep['reason']}"
    groups = ":".join(ep.get("groups") or [])
    if ep.get("groups_source") == "service default":
        return f"{head} uses its built-in group list {groups}, which has no ML-KEM group; set {ep.get('groups_setting') or 'the group list'} to include X25519MLKEM768"
    return f"{head} sets {ep.get('groups_setting')} {groups}, which has no ML-KEM group"


@_registry.register_arguments(57)
def add_arguments(ap: argparse.ArgumentParser) -> None:
    ap.add_argument(
        "--scan-service-configs",
        action="store_true",
        help=(
            "read the TLS settings of common server daemons (web, proxy, mail, "
            "database, directory) and report which endpoints offer hybrid "
            "ML-KEM; implied by --scan-services; works with --root"
        ),
    )
