"""Capability vs configuration verdict per protocol and service (#107).

The scanner already knows, separately, what a host *can* do (library and
binary capability) and what it is *set up* to do (crypto policy, OpenSSL
config, sshd's effective KexAlgorithms, IKE proposals).  This module joins
the two into one state per protocol, and per listening service when
`--scan-services` ran:

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

from typing import Any, Mapping

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
    present = bool(
        sshd.get("available") or (report.get("ssh_pqc") or {}).get("available")
    )
    cap, cap_from = ssh_capable(report)
    conf, conf_from = ssh_configured(report)
    note = None
    if conf is True and sshd.get("pqc_first") is False:
        note = f"PQC offered, but {sshd.get('first_kex')} is preferred first"
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
        if kind == "ssh":
            v = dict(protocols["ssh"])
        else:
            capable = cap["library_pqc_capable"]
            if cap["go_default_hybrid"]:
                # Go's crypto/tls ignores the system policy: its default is
                # the configuration.
                configured: bool | None = True
                conf_from = [f"service_crypto_linkage.listeners[{i}].go"]
            else:
                configured, conf_from = tls_configured(report)
            v = _verdict(
                capable,
                configured,
                [f"service_crypto_linkage.listeners[{i}].crypto_libraries"]
                + (
                    [f"service_crypto_linkage.listeners[{i}].go"]
                    if ln.get("go")
                    else []
                ),
                conf_from,
            )
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
            "listeners": [f"service_crypto_linkage.listeners[{i}]"],
        }
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
        "listeners_without_crypto_library": no_crypto,
        "listeners_unattributed": unattributed,
    }


def compute_gap(report: Mapping[str, Any]) -> dict[str, Any]:
    """The `pqc_deployment_gap` object for one report (dict form)."""
    protocols = {"tls": _tls(report), "ssh": _ssh(report), "ipsec": _ipsec(report)}
    services = _services(report, protocols)
    gaps: list[str] = []
    for name, v in protocols.items():
        if v["state"] in ("capable_not_configured", "configured_not_capable"):
            gaps.append(f"{name}:{v['state']}")
    for s in services.get("items") or []:
        if s["state"] in ("capable_not_configured", "configured_not_capable"):
            gaps.append(
                f"service:{s['process']}/{s['protocol']}/{s['port']}:{s['state']}"
            )
    return {"protocols": protocols, "services": services, "gaps": gaps}


def gap_for(report: Mapping[str, Any]) -> dict[str, Any]:
    """The report's own `pqc_deployment_gap` when present, else computed
    from its fields (reports written before #107 have none)."""
    existing = report.get("pqc_deployment_gap")
    if isinstance(existing, dict) and existing.get("protocols"):
        return existing
    return compute_gap(report)
