"""Capability vs configuration verdict per protocol and service (#107).

The scanner already knows, separately, what a host *can* do (library and
binary capability) and what it is *set up* to do (crypto policy, OpenSSL
config, sshd's effective KexAlgorithms, IKE proposals).  This module joins
the two into one state per protocol, and per listening service when
`--scan-services` ran, and per outbound-client process group when
`--scan-processes` ran (#202).  A service's own TLS configuration (#216,
`service_tls_config`) decides its `configured` judgement when it sets a
group list, caps TLS below 1.3 or can't use ML-KEM at all; otherwise the
host default applies:

  deployed                 capable and configured to use PQC
  capable_not_configured   capable, but configuration keeps it classical
                           (usually fixed by a policy / config change)
  configured_not_capable   configured for PQC the software can't do
                           (connections fail or silently fall back)
  not_capable              the software can't do PQC (upgrade needed)
  unknown                  the evidence doesn't decide it
  not_present              the protocol's software isn't on the host

Everything is computed from fields already in the report: no probes run
here, so the same functions serve a live scan, an offline (--root) scan
and the fleet aggregator re-reading old reports.  The aggregator's
endpoint-observation join (#149) adds the third state, what an endpoint
was *observed* to negotiate, using the same capable / configured
judgements (observations.py imports them from here).

Each verdict carries `evidence`: JSON paths into the report for the
fields that decided `capable` and `configured`, so a reader can check the
reasoning without re-deriving it.
"""

from __future__ import annotations

import re
from typing import Any, Mapping

from .detect import config_read as _config_read
from .detect import config_services as _config_services
from .detect import runtime_services as _svc

STATES: tuple[str, ...] = (
    "deployed",
    "capable_not_configured",
    "configured_not_capable",
    "not_capable",
    "unknown",
    "not_present",
)
PROTOCOLS: tuple[str, ...] = ("tls", "ssh", "ipsec")

# Process names whose listener speaks SSH rather than TLS.
_SSH_DAEMONS = frozenset({"sshd", "sshd-session", "sshd-auth"})


def _bool(value: object) -> bool | None:
    return value if isinstance(value, bool) else None


def classify(capable: bool | None, configured: bool | None) -> str:
    """State for one protocol or service from its two judgements."""
    if capable is True:
        if configured is True:
            return "deployed"
        if configured is False:
            return "capable_not_configured"
        return "unknown"
    if capable is False:
        return "configured_not_capable" if configured is True else "not_capable"
    return "unknown"


def _verdict(
    capable: bool | None,
    configured: bool | None,
    capable_from: list[str],
    configured_from: list[str],
    note: str | None = None,
    present: bool = True,
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "state": classify(capable, configured) if present else "not_present",
        "capable": capable if present else None,
        "configured": configured if present else None,
        "evidence": (
            {"capable": capable_from, "configured": configured_from}
            if present
            else {"capable": [], "configured": []}
        ),
    }
    if note:
        out["note"] = note
    return out


# ---------------------------------------------------------------------------
# Per-protocol judgements (shared with observations.py)
# ---------------------------------------------------------------------------


def tls_capable(report: Mapping[str, Any]) -> tuple[bool | None, list[str]]:
    """Whether the system TLS library can negotiate a PQC key exchange."""
    o = report.get("openssl") or {}
    groups = o.get("tls_groups")
    if o.get("available") and isinstance(groups, dict):
        return bool(groups.get("hybrid") or groups.get("pure_pqc")), [
            "openssl.tls_groups"
        ]
    native = _bool(o.get("pqc_native"))
    if native is not None:
        return native, ["openssl.pqc_native"]
    # Offline (--root) scans infer it from the packaged OpenSSL version.
    expected = _bool(o.get("pqc_native_expected"))
    if expected is not None:
        return expected, ["openssl.pqc_native_expected"]
    return None, []


def tls_configured(report: Mapping[str, Any]) -> tuple[bool | None, list[str]]:
    """Whether the system default (policy, then OpenSSL config) offers a
    PQC TLS key exchange."""
    policy = (report.get("crypto_policy") or {}).get("pqc_enabled") or {}
    v = _bool(policy.get("tls_key_exchange"))
    if v is not None:
        return v, ["crypto_policy.pqc_enabled.tls_key_exchange"]
    cfg = (report.get("openssl") or {}).get("config") or {}
    v = _bool(cfg.get("pqc_key_exchange_by_default"))
    if v is not None:
        return v, ["openssl.config.pqc_key_exchange_by_default"]
    return None, []


def ssh_capable(report: Mapping[str, Any]) -> tuple[bool | None, list[str]]:
    """Whether the installed OpenSSH build supports a PQC key exchange
    (client and server ship in the same build)."""
    v = _bool((report.get("sshd") or {}).get("openssh_supports_pqc_kex"))
    if v is not None:
        return v, ["sshd.openssh_supports_pqc_kex"]
    kex = (report.get("ssh_pqc") or {}).get("kex_groups")
    if isinstance(kex, dict):
        return bool(kex.get("hybrid") or kex.get("pure_pqc")), ["ssh_pqc.kex_groups"]
    return None, []


def ssh_configured(report: Mapping[str, Any]) -> tuple[bool | None, list[str]]:
    """Whether sshd offers a PQC key exchange: its effective KexAlgorithms
    first (#105), the crypto policy's server setting otherwise."""
    v = _bool((report.get("sshd") or {}).get("pqc_offered"))
    if v is not None:
        return v, ["sshd.pqc_offered"]
    policy = (report.get("crypto_policy") or {}).get("pqc_enabled") or {}
    v = _bool(policy.get("ssh_key_exchange_server"))
    if v is not None:
        return v, ["crypto_policy.pqc_enabled.ssh_key_exchange_server"]
    return None, []


def ike_capable(report: Mapping[str, Any]) -> tuple[bool | None, list[str]]:
    ipsec = report.get("ipsec_pqc") or {}
    if not ipsec.get("available"):
        return None, []
    v = _bool(ipsec.get("pqc"))
    return v, (["ipsec_pqc.pqc"] if v is not None else [])


def ike_configured(report: Mapping[str, Any]) -> tuple[bool | None, list[str]]:
    """The configured IKE proposals (#154) say more than the policy."""
    ipsec = report.get("ipsec_pqc") or {}
    summary = (ipsec.get("configured") or {}).get("summary") or {}
    if summary.get("connections"):
        return bool(summary.get("connections_offering_pqc")), [
            "ipsec_pqc.configured.summary.connections_offering_pqc"
        ]
    policy = (report.get("crypto_policy") or {}).get("pqc_enabled") or {}
    v = _bool(policy.get("ike_key_exchange"))
    if v is not None:
        return v, ["crypto_policy.pqc_enabled.ike_key_exchange"]
    return None, []


def listener_capability(listener: Mapping[str, Any]) -> dict[str, Any]:
    """PQC capability of the crypto a listening process actually maps
    (#111): a PQC-capable library, or a Go binary whose crypto/tls
    defaults to hybrid ML-KEM and isn't reverted by GODEBUG."""
    libs = listener.get("crypto_libraries") or []
    go = listener.get("go") or None
    families = sorted({str(x.get("family")) for x in libs if x.get("family")})
    if go:
        families.append("go")
    flags = [x.get("library_pqc_capable") for x in libs]
    go_capable: bool | None = None
    if go:
        reverted = {"tlsmlkem"} & set(go.get("godebug_reverts") or [])
        go_capable = bool(go.get("default_hybrid_kex")) and not reverted
    capable: bool | None
    if True in flags or go_capable:
        capable = True
    elif (flags and all(f is False for f in flags)) or go_capable is False:
        capable = False
    else:
        capable = None
    return {
        "crypto_families": families,
        "library_pqc_capable": capable,
        "go_default_hybrid": bool(go_capable),
    }


# OpenSSL sonames before 3.0: libssl.so.1.1 / .so.1.0.0 upstream,
# libssl.so.10 on RHEL 7 (1.0.2).  OpenSSL 3.x uses .so.3, so a 1.x / 10
# soname is definite evidence of a pre-3.5 library even when no version
# string could be read (measured: AlmaLinux 8.10 sshd, OpenSSL 1.1.1k).
OPENSSL_PRE3_SONAME = re.compile(
    r"/lib(?:ssl|crypto)\.so\.(?:1(?:\.[0-9][0-9a-z.]*)?|10)$"
)

# Service-linkage families that --scan-crypto-libraries also probes from the
# library file itself (#110); its binary evidence settles libraries whose
# version has no threshold in the service probe.
LIBRARY_PROBE_NAME = {"gnutls": "gnutls", "wolfssl": "wolfssl", "aws-lc": "aws-lc"}


def library_capable(
    lib: dict[str, Any], probes: dict[str, Any]
) -> tuple[bool | None, str]:
    """PQC capability of one crypto library a process maps (#193), with
    the evidence used: the service probe's own verdict, then the library probe's
    reading of the same file (or same version), then the OpenSSL soname."""
    capable = lib.get("library_pqc_capable")
    if capable is not None:
        return bool(capable), "version"
    name = LIBRARY_PROBE_NAME.get(str(lib.get("family")))
    probe = probes.get(name) if name else None
    if probe and probe.get("installed") and probe.get("pqc_capable") is not None:
        same_file = lib.get("path") in (probe.get("files") or [])
        same_version = lib.get("version") and lib.get("version") == probe.get("version")
        if same_file or same_version:
            return bool(probe["pqc_capable"]), "crypto_libraries"
    if lib.get("family") == "openssl" and OPENSSL_PRE3_SONAME.search(
        str(lib.get("path") or "")
    ):
        return False, "soname"
    return None, ""


def go_tls_capability(go: Mapping[str, Any]) -> tuple[bool | None, bool | None]:
    """(capable, configured) for a Go binary's own crypto/tls default.

    Go's TLS stack ignores the system crypto policy, so its default *is*
    its configuration.  Go >= 1.24 can negotiate X25519MLKEM768 and offers
    it by default; GODEBUG tlsmlkem=0 (from the environment, or the
    binary's DefaultGODEBUG via an old ``go`` line in go.mod) turns it off:
    capable, configured classical.  Older Go offers no standard hybrid
    (1.23 only the pre-standard Kyber draft): not capable, matching the
    #193 failure finding (pqc-012)."""
    vt = _svc._version_tuple(str(go.get("go_version") or "").removeprefix("go"))
    if vt is None:
        return None, None
    if vt[:2] < _svc.GO_MLKEM_DEFAULT_VERSION:
        return False, None
    reverted = "tlsmlkem" in (go.get("godebug_reverts") or [])
    return True, not reverted


# ---------------------------------------------------------------------------
# Report-level verdict
# ---------------------------------------------------------------------------


def _tls(report: Mapping[str, Any]) -> dict[str, Any]:
    o = report.get("openssl") or {}
    present = bool(o.get("available")) or o.get("pqc_native_expected") is not None
    cap, cap_from = tls_capable(report)
    conf, conf_from = tls_configured(report)
    return _verdict(cap, conf, cap_from, conf_from, present=present)


def _ssh(report: Mapping[str, Any]) -> dict[str, Any]:
    sshd = report.get("sshd") or {}
    # An sshd_config that exists but can't be read means sshd is there and
    # its configuration unknown, not that it's absent (#232).
    present = bool(
        sshd.get("available")
        or sshd.get("unreadable")
        or (report.get("ssh_pqc") or {}).get("available")
    )
    cap, cap_from = ssh_capable(report)
    conf, conf_from = ssh_configured(report)
    note = None
    if conf is True and sshd.get("pqc_first") is False:
        note = f"PQC offered, but {sshd.get('first_kex')} is preferred first"
    elif sshd.get("unreadable") and (
        not sshd.get("available") or sshd.get("kex_source") == "unreadable-config"
    ):
        note = "sshd configuration not readable by this user; " + (
            _config_read.PERMISSION_HINT
        )
    return _verdict(cap, conf, cap_from, conf_from, note=note, present=present)


def _ipsec(report: Mapping[str, Any]) -> dict[str, Any]:
    ipsec = report.get("ipsec_pqc") or {}
    summary = (ipsec.get("configured") or {}).get("summary") or {}
    present = bool(ipsec.get("available") or summary.get("connections"))
    cap, cap_from = ike_capable(report)
    conf, conf_from = ike_configured(report)
    note = None
    mismatch = (ipsec.get("configured") or {}).get("capability_mismatch") or {}
    if mismatch.get("connections"):
        note = "connections the installed stack can't load: " + ", ".join(
            str(c) for c in mismatch["connections"]
        )
    return _verdict(cap, conf, cap_from, conf_from, note=note, present=present)


def _service_kind(listener: Mapping[str, Any]) -> str:
    name = str(listener.get("process") or "")
    exe = str(listener.get("exe") or "")
    if name in _SSH_DAEMONS or exe.rsplit("/", 1)[-1] in _SSH_DAEMONS:
        return "ssh"
    return "tls"


def _services(
    report: Mapping[str, Any], protocols: Mapping[str, dict[str, Any]]
) -> dict[str, Any]:
    scl = report.get("service_crypto_linkage") or {}
    if not scl.get("available"):
        return {"available": False}
    stc = report.get("service_tls_config") or {}
    items: dict[tuple[Any, ...], dict[str, Any]] = {}
    no_crypto = 0
    unattributed = 0
    for i, ln in enumerate(scl.get("listeners") or []):
        if not ln.get("process"):
            unattributed += 1
            continue
        cap = listener_capability(ln)
        if not cap["crypto_families"]:
            no_crypto += 1
            continue
        kind = _service_kind(ln)
        own_default = False
        own_config = (
            _config_services.endpoint_for_listener(stc, ln) if kind == "tls" else None
        )
        if kind == "ssh":
            v = dict(protocols["ssh"])
        else:
            capable = cap["library_pqc_capable"]
            cap_from = [f"service_crypto_linkage.listeners[{i}].crypto_libraries"] + (
                [f"service_crypto_linkage.listeners[{i}].go"] if ln.get("go") else []
            )
            if cap["go_default_hybrid"]:
                # Go's crypto/tls ignores the system policy: its default is
                # the configuration.
                configured: bool | None = True
                conf_from = [f"service_crypto_linkage.listeners[{i}].go"]
                own_default = True
            elif own_config and own_config[1].get("pqc_key_exchange") is not None:
                # The service's own settings (a group list, a TLS 1.3 cap or
                # a single-curve option) win over the system policy (#216).
                configured = bool(own_config[1]["pqc_key_exchange"])
                conf_from = [own_config[0]]
                own_default = True
                if own_config[1].get("service_supports_pqc_groups") is False:
                    capable = False
                    cap_from = cap_from + [own_config[0]]
            else:
                configured, conf_from = tls_configured(report)
                if own_config:
                    conf_from = conf_from + [own_config[0]]
            v = _verdict(capable, configured, cap_from, conf_from)
        # One entry per process / port / verdict: several instances (IPv4 +
        # IPv6 sockets, or one daemon per systemd scope) collapse unless
        # their crypto differs.
        key = (ln.get("process"), ln.get("protocol"), ln.get("port"), v["state"])
        unit = ln.get("systemd_unit")
        if key in items:
            items[key]["listeners"].append(f"service_crypto_linkage.listeners[{i}]")
            if unit and unit not in items[key]["systemd_units"]:
                items[key]["systemd_units"].append(unit)
            continue
        items[key] = {
            "process": ln.get("process"),
            "systemd_units": [unit] if unit else [],
            "protocol": ln.get("protocol"),
            "port": ln.get("port"),
            "kind": kind,
            "crypto_families": cap["crypto_families"],
            **v,
            # Same state as the host's protocol verdict, reached through the
            # host default: the service adds nothing to that verdict.  Many
            # daemons map a TLS library without speaking TLS on the port
            # (rpcbind, httpd :80, a DNS stub), so only services that differ
            # (a bundled old library, a Go binary's own default) are gaps
            # in their own right.
            "follows_host_default": (
                not own_default and v["state"] == protocols[kind]["state"]
            ),
            "listeners": [f"service_crypto_linkage.listeners[{i}]"],
        }
        if own_config:
            items[key]["service_config"] = own_config[0]
    services = sorted(
        items.values(),
        key=lambda s: (str(s["process"]), int(s["port"] or 0), str(s["protocol"])),
    )
    by_state: dict[str, int] = {}
    for s in services:
        by_state[s["state"]] = by_state.get(s["state"], 0) + 1
    return {
        "available": True,
        "items": services,
        "by_state": dict(sorted(by_state.items())),
        "differing_from_host": sum(
            1 for s in services if not s["follows_host_default"]
        ),
        "listeners_without_crypto_library": no_crypto,
        "listeners_unattributed": unattributed,
    }


def _clients(
    report: Mapping[str, Any], protocols: Mapping[str, dict[str, Any]]
) -> dict[str, Any]:
    """Per outbound-client process group (#202): process groups from
    --scan-processes (#155) with at least one process in the ``client``
    role.  Listening servers are covered by `services`; idle processes
    negotiate nothing.

    A Go binary is judged on its own crypto/tls default (it ignores the
    system policy).  Otherwise a client negotiates with the libraries it
    maps under the host's TLS configuration, and is not capable when any
    of them is known not to be (it may be the one in use) -- the same
    judgement the #193 failure findings make for services."""
    pcl = report.get("process_crypto_linkage") or {}
    if not pcl.get("available"):
        return {"available": False}
    probes = (report.get("crypto_libraries") or {}).get("libraries") or {}
    items: list[dict[str, Any]] = []
    for i, grp in enumerate(pcl.get("groups") or []):
        clients = int((grp.get("roles") or {}).get("client") or 0)
        if not clients:
            continue
        path = f"process_crypto_linkage.groups[{i}]"
        libs = grp.get("crypto_libraries") or []
        go = grp.get("go") or None
        families = sorted({str(x.get("family")) for x in libs if x.get("family")})
        own_default = False
        capable: bool | None
        configured: bool | None
        if go:
            families.append("go")
            capable, configured = go_tls_capability(go)
            cap_from = conf_from = [f"{path}.go"]
            own_default = True
        else:
            verdicts = [library_capable(dict(lib), probes)[0] for lib in libs]
            if any(v is False for v in verdicts):
                capable = False
            elif verdicts and all(v is True for v in verdicts):
                capable = True
            else:
                capable = None
            cap_from = [f"{path}.crypto_libraries"]
            configured, conf_from = tls_configured(report)
        v = _verdict(capable, configured, cap_from, conf_from)
        items.append(
            {
                "exe": grp.get("exe"),
                "process": grp.get("process"),
                "systemd_units": list(grp.get("systemd_units") or []),
                "client_processes": clients,
                "crypto_families": families,
                **v,
                # Same state as the host's TLS verdict, reached through the
                # host default: the group restates that verdict.  Groups that
                # differ (an old bundled library, a Go binary's own default)
                # are gaps in their own right.
                "follows_host_default": (
                    not own_default and v["state"] == protocols["tls"]["state"]
                ),
                "group": path,
            }
        )
    items.sort(key=lambda c: (STATES.index(c["state"]), -c["client_processes"]))
    by_state: dict[str, int] = {}
    processes_by_state: dict[str, int] = {}
    for c in items:
        by_state[c["state"]] = by_state.get(c["state"], 0) + 1
        processes_by_state[c["state"]] = (
            processes_by_state.get(c["state"], 0) + c["client_processes"]
        )
    out: dict[str, Any] = {
        "available": True,
        "items": items,
        "by_state": dict(sorted(by_state.items())),
        "client_processes_by_state": dict(sorted(processes_by_state.items())),
        "differing_from_host": sum(1 for c in items if not c["follows_host_default"]),
    }
    omitted = pcl.get("omitted_groups")
    if omitted:
        out["groups_omitted_by_scan"] = omitted
    return out


def compute_gap(report: Mapping[str, Any]) -> dict[str, Any]:
    """The `pqc_deployment_gap` object for one report (dict form)."""
    protocols = {"tls": _tls(report), "ssh": _ssh(report), "ipsec": _ipsec(report)}
    services = _services(report, protocols)
    clients = _clients(report, protocols)
    gaps: list[str] = []
    for name, v in protocols.items():
        if v["state"] in ("capable_not_configured", "configured_not_capable"):
            gaps.append(f"{name}:{v['state']}")
    for s in services.get("items") or []:
        if s["follows_host_default"]:
            continue
        if s["state"] in ("capable_not_configured", "configured_not_capable"):
            gaps.append(
                f"service:{s['process']}/{s['protocol']}/{s['port']}:{s['state']}"
            )
    for c in clients.get("items") or []:
        if c["follows_host_default"]:
            continue
        if c["state"] in ("capable_not_configured", "configured_not_capable"):
            gaps.append(f"client:{c['exe'] or c['process']}:{c['state']}")
    return {
        "protocols": protocols,
        "services": services,
        "clients": clients,
        "gaps": gaps,
    }


def service_config_blocks(report: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Server endpoints whose own TLS configuration keeps PQC out while
    the host's TLS library could negotiate it (#216, SARIF pqc-021)."""
    return _config_services.blocked_endpoints(
        dict(report.get("service_tls_config") or {}), tls_capable(report)[0]
    )


def gap_for(report: Mapping[str, Any]) -> dict[str, Any]:
    """The report's own `pqc_deployment_gap` when present, else computed
    from its fields (reports written before #107 have none)."""
    existing = report.get("pqc_deployment_gap")
    if isinstance(existing, dict) and existing.get("protocols"):
        return existing
    return compute_gap(report)
