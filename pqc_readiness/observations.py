"""Endpoint-observation ingestion for the fleet aggregator (#149).

Network-side tools see what an endpoint actually negotiates; the
scanner sees what the host could do (library capability) and what its
policy allows (configuration).  `--aggregate DIR --observations FILE`
joins the two: each observation record is matched to a host report and,
within it, to the listening socket from `service_crypto_linkage` (#111).
The result feeds the three-state verdict (#107); this module only joins
and counts, it does not grade.

The input is a neutral, versioned record format (schema 1.0, published
as docs/schemas/endpoint-observation-1.0.schema.json).  Producers write
small adapters that convert their own output into it; no tool-specific
parser lives in this repository.  The validator here is stdlib-only,
because the zipapp ships no data files, and tests keep it in agreement
with the JSON Schema.
"""

from __future__ import annotations

import ipaddress
import json
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Iterator

from . import algorithms as _algorithms
from .detect import config as _config
from .detect import protocols as _protocols

OBSERVATION_SCHEMA_VERSION = "1.0"
_SUPPORTED_MAJOR = 1
_SUPPORTED_MINOR = 0

# Transport each protocol runs over.  An observation may state `transport`
# explicitly; it must then agree with this table.
PROTOCOL_TRANSPORT: dict[str, str] = {
    "tls": "tcp",
    "ssh": "tcp",
    "quic": "udp",
    "dtls": "udp",
    "ikev2": "udp",
}

# Kinds of producer, so consumers can weigh evidence without the
# repository naming any particular tool.
SOURCE_CATEGORIES = (
    "active-endpoint-scan",
    "passive-network-sensor",
    "edge-or-proxy-log",
    "client-telemetry",
    "manual",
)

DEFAULT_MAX_AGE_DAYS = 7.0

_RECORD_KEYS = {
    "observation_schema_version",
    "id",
    "observed_at",
    "protocol",
    "transport",
    "fqdn",
    "ip",
    "port",
    "sni",
    "negotiated_group",
    "additional_key_exchanges",
    "offered_groups",
    "tls_version",
    "certificate_sha256",
    "source",
}
_SOURCE_KEYS = {"category", "name", "version"}
_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")
_HOSTNAME = re.compile(
    r"^(?=.{1,253}\.?$)[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,62})"
    r"(?:\.[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,62}))*\.?$"
)

# Classical TLS Supported Groups codepoints (IANA registry), so a record
# carrying a numeric codepoint classifies like one carrying the name.
# PQC codepoints come from algorithms.TLS_PQC_GROUPS.
_CLASSICAL_TLS_CODEPOINTS: dict[int, str] = {
    0x0017: "secp256r1",
    0x0018: "secp384r1",
    0x0019: "secp521r1",
    0x001D: "x25519",
    0x001E: "x448",
    0x0100: "ffdhe2048",
    0x0101: "ffdhe3072",
    0x0102: "ffdhe4096",
    0x0103: "ffdhe6144",
    0x0104: "ffdhe8192",
}
_CLASSICAL_TLS_ALIASES = {
    "p256": "secp256r1",
    "p384": "secp384r1",
    "p521": "secp521r1",
    "prime256v1": "secp256r1",
}
_IKE_PQC_RE = re.compile(r"ml-?kem", re.IGNORECASE)
_IKE_CLASSICAL_RE = re.compile(
    r"^(?:modp\d+|ecp\d+|curve(?:25519|448)|x(?:25519|448)|"
    r"(?:dh|group)\d+|brainpool\d+r?\d*)$",
    re.IGNORECASE,
)


class ObservationFileError(Exception):
    """The observations file as a whole is unusable (unreadable, not
    JSON, unsupported major version)."""


# ---------------------------------------------------------------------------
# Loading and validation
# ---------------------------------------------------------------------------


def _parse_time(value: object) -> datetime | None:
    """RFC 3339 date-time with an explicit offset, or None."""
    if not isinstance(value, str):
        return None
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        return None
    return dt


def _normalise_ip(value: str) -> str | None:
    try:
        addr = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return str(addr.ipv4_mapped)
    return str(addr)


def _version_tuple(value: object) -> tuple[int, int] | None:
    if not isinstance(value, str):
        return None
    m = re.fullmatch(r"(\d+)\.(\d+)", value.strip())
    if not m:
        return None
    return int(m.group(1)), int(m.group(2))


def validate_record(rec: object, inherited_version: str | None = None) -> list[str]:
    """Problems with one observation record; empty when valid.

    Mirrors docs/schemas/endpoint-observation-1.0.schema.json.  Keys
    starting with `x-` are producer extensions and always allowed.  A
    record from a newer *minor* version may carry keys this scanner does
    not know yet; those are ignored rather than rejected (additive
    changes only within a major version)."""
    if not isinstance(rec, dict):
        return ["record is not a JSON object"]
    errors: list[str] = []
    version = rec.get("observation_schema_version", inherited_version)
    vt = _version_tuple(version)
    if vt is None:
        errors.append("observation_schema_version missing or not MAJOR.MINOR")
    elif vt[0] != _SUPPORTED_MAJOR:
        errors.append(
            f"observation_schema_version {version} unsupported "
            f"(this scanner reads {_SUPPORTED_MAJOR}.x)"
        )
    newer_minor = (
        vt is not None and vt[0] == _SUPPORTED_MAJOR and vt[1] > _SUPPORTED_MINOR
    )
    unknown = sorted(
        k for k in rec if k not in _RECORD_KEYS and not str(k).startswith("x-")
    )
    if unknown and not newer_minor:
        errors.append(f"unknown keys: {', '.join(unknown)}")

    if _parse_time(rec.get("observed_at")) is None:
        errors.append("observed_at missing or not an RFC 3339 date-time with offset")
    protocol = rec.get("protocol")
    if protocol not in PROTOCOL_TRANSPORT:
        errors.append(f"protocol must be one of {', '.join(PROTOCOL_TRANSPORT)}")
    transport = rec.get("transport")
    if transport is not None:
        if transport not in ("tcp", "udp"):
            errors.append("transport must be tcp or udp")
        elif (
            protocol in PROTOCOL_TRANSPORT and transport != PROTOCOL_TRANSPORT[protocol]
        ):
            errors.append(f"transport {transport} does not carry {protocol}")
    port = rec.get("port")
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        errors.append("port must be an integer 1-65535")

    fqdn, ip, sni = rec.get("fqdn"), rec.get("ip"), rec.get("sni")
    if fqdn is None and ip is None:
        errors.append("at least one of fqdn or ip is required")
    for key, value in (("fqdn", fqdn), ("sni", sni)):
        if value is not None and (
            not isinstance(value, str) or not _HOSTNAME.match(value)
        ):
            errors.append(f"{key} is not a DNS name")
    if ip is not None and (not isinstance(ip, str) or _normalise_ip(ip) is None):
        errors.append("ip is not an IPv4 or IPv6 address")

    for key in ("negotiated_group", "tls_version", "id"):
        value = rec.get(key)
        if value is not None and (not isinstance(value, str) or not value.strip()):
            errors.append(f"{key} must be a non-empty string")
    for key in ("additional_key_exchanges", "offered_groups"):
        value = rec.get(key)
        if value is not None and (
            not isinstance(value, list)
            or not all(isinstance(v, str) and v for v in value)
        ):
            errors.append(f"{key} must be a list of non-empty strings")
    cert = rec.get("certificate_sha256")
    if cert is not None and (not isinstance(cert, str) or not _HEX64.match(cert)):
        errors.append("certificate_sha256 must be 64 hex characters")

    source = rec.get("source")
    if not isinstance(source, dict):
        errors.append("source object is required")
    else:
        if source.get("category") not in SOURCE_CATEGORIES:
            errors.append(
                f"source.category must be one of {', '.join(SOURCE_CATEGORIES)}"
            )
        for key in ("name", "version"):
            value = source.get(key)
            if value is not None and not isinstance(value, str):
                errors.append(f"source.{key} must be a string")
        extra = sorted(
            k for k in source if k not in _SOURCE_KEYS and not str(k).startswith("x-")
        )
        if extra and not newer_minor:
            errors.append(f"unknown source keys: {', '.join(extra)}")
    return errors


@dataclass
class LoadedObservations:
    records: list[dict[str, Any]] = field(default_factory=list)
    # {"record": <envelope list index or JSON Lines line number, 1-based>,
    #  "reason": "..."} for rejected records
    invalid: list[dict[str, Any]] = field(default_factory=list)
    file_format: str = "envelope"


def load_observations(path: Path) -> LoadedObservations:
    """Read an observations file: either an envelope object
    `{"observation_schema_version": "1.0", "observations": [...]}` (records
    inherit the envelope version) or JSON Lines with one self-describing
    record per line.  Invalid records are reported, not fatal; a file that
    can't be read at all raises ObservationFileError."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        raise ObservationFileError(f"cannot read {path}: {e}") from e
    out = LoadedObservations()
    # (position, record, inherited version): position is the 1-based index
    # in the envelope's list, or the line number in JSON Lines.
    raw: list[tuple[int, object, str | None]] = []
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        doc = None
    if isinstance(doc, dict) and "observations" in doc:
        version = doc.get("observation_schema_version")
        vt = _version_tuple(version)
        if vt is None or vt[0] != _SUPPORTED_MAJOR:
            raise ObservationFileError(
                f"envelope observation_schema_version {version!r} unsupported "
                f"(this scanner reads {_SUPPORTED_MAJOR}.x)"
            )
        records = doc["observations"]
        if not isinstance(records, list):
            raise ObservationFileError("envelope `observations` must be a list")
        raw = [(n, r, str(version)) for n, r in enumerate(records, 1)]
    else:
        out.file_format = "jsonl"
        for n, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            try:
                raw.append((n, json.loads(line), None))
            except json.JSONDecodeError as e:
                out.invalid.append(
                    {"record": n, "reason": f"line is not JSON: {e.msg}"}
                )
    for position, rec, version in raw:
        problems = validate_record(rec, inherited_version=version)
        if problems:
            out.invalid.append({"record": position, "reason": "; ".join(problems)})
            continue
        assert isinstance(rec, dict)
        out.records.append({"_position": position, **rec})
    out.invalid.sort(key=lambda i: int(i["record"]))
    return out


# ---------------------------------------------------------------------------
# Host index, built while the aggregator streams the reports
# ---------------------------------------------------------------------------


@dataclass
class HostEntry:
    hostname: str
    generated_at: datetime | None
    service_scan: bool
    listeners: list[dict[str, Any]]
    cert_sha256: set[str]
    tls_configured: bool | None
    ssh_configured: bool | None
    ike_configured: bool | None
    ssh_capable: bool | None
    ike_capable: bool | None


@dataclass
class HostIndex:
    hosts: list[HostEntry] = field(default_factory=list)
    by_name: dict[str, list[int]] = field(default_factory=dict)
    by_short: dict[str, list[int]] = field(default_factory=dict)
    by_ip: dict[str, list[int]] = field(default_factory=dict)
    by_cert: dict[str, list[int]] = field(default_factory=dict)

    def add(self, report: dict[str, Any]) -> None:
        entry = _host_entry(report)
        i = len(self.hosts)
        self.hosts.append(entry)
        name = entry.hostname.lower().rstrip(".")
        if name:
            self.by_name.setdefault(name, []).append(i)
            self.by_short.setdefault(name.split(".", 1)[0], []).append(i)
        for ip in {
            ln["address"]
            for ln in entry.listeners
            if ln["bind_scope"] == "specific" and ln["address"]
        }:
            self.by_ip.setdefault(ip, []).append(i)
        for fp in entry.cert_sha256:
            self.by_cert.setdefault(fp, []).append(i)


def index_reports(
    reports: Iterable[dict[str, Any]], index: HostIndex
) -> Iterator[dict[str, Any]]:
    """Pass reports through unchanged while indexing them, so the
    aggregator's single streaming pass also builds the join index.  The
    index keeps only names, a compact listener list and certificate
    fingerprints per host, never whole reports."""
    for r in reports:
        index.add(r)
        yield r


def _bool_or_none(value: object) -> bool | None:
    return value if isinstance(value, bool) else None


def _compact_listener(ln: dict[str, Any]) -> dict[str, Any]:
    libs = ln.get("crypto_libraries") or []
    go = ln.get("go") or None
    families = sorted({str(x.get("family")) for x in libs if x.get("family")})
    if go:
        families.append("go")
    capable_flags = [x.get("library_pqc_capable") for x in libs]
    go_capable: bool | None = None
    if go:
        reverted = {"tlsmlkem"} & set(go.get("godebug_reverts") or [])
        go_capable = bool(go.get("default_hybrid_kex")) and not reverted
    if True in capable_flags or go_capable:
        capable: bool | None = True
    elif (
        capable_flags and all(f is False for f in capable_flags)
    ) or go_capable is False:
        capable = False
    else:
        capable = None
    address = ln.get("address")
    return {
        "protocol": ln.get("protocol"),
        "address": _normalise_ip(address) if isinstance(address, str) else None,
        "port": ln.get("port"),
        "bind_scope": ln.get("bind_scope"),
        "network_namespace": ln.get("network_namespace"),
        "process": ln.get("process"),
        "systemd_unit": ln.get("systemd_unit"),
        "crypto_families": families,
        "library_pqc_capable": capable,
        "go_default_hybrid": bool(go_capable),
    }


def _host_entry(report: dict[str, Any]) -> HostEntry:
    scl = report.get("service_crypto_linkage") or {}
    service_scan = bool(scl.get("available"))
    listeners = (
        [_compact_listener(ln) for ln in scl.get("listeners") or []]
        if service_scan
        else []
    )
    certs: set[str] = set()
    for src in (report.get("crypto_material") or {}, report.get("trust_store") or {}):
        for c in src.get("certificates") or []:
            fp = c.get("sha256")
            if isinstance(fp, str) and _HEX64.match(fp):
                certs.add(fp.lower())
    policy = (report.get("crypto_policy") or {}).get("pqc_enabled") or {}
    openssl_cfg = (report.get("openssl") or {}).get("config") or {}
    tls_configured = _bool_or_none(policy.get("tls_key_exchange"))
    if tls_configured is None:
        tls_configured = _bool_or_none(openssl_cfg.get("pqc_key_exchange_by_default"))
    kex = (report.get("ssh_pqc") or {}).get("kex_groups") or {}
    ssh_capable: bool | None = None
    if kex:
        ssh_capable = bool(kex.get("hybrid") or kex.get("pure_pqc"))
    ipsec = report.get("ipsec_pqc") or {}
    # IKEv2: the configured proposals (#154) say more than the policy.
    ike_summary = (ipsec.get("configured") or {}).get("summary") or {}
    ike_configured = _bool_or_none(policy.get("ike_key_exchange"))
    if ike_summary.get("connections"):
        ike_configured = bool(ike_summary.get("connections_offering_pqc"))
    return HostEntry(
        hostname=str(report.get("hostname") or ""),
        generated_at=_parse_time(report.get("generated_at")),
        service_scan=service_scan,
        listeners=listeners,
        cert_sha256=certs,
        tls_configured=tls_configured,
        ssh_configured=_bool_or_none(policy.get("ssh_key_exchange_server")),
        ike_configured=ike_configured,
        ssh_capable=ssh_capable,
        ike_capable=_bool_or_none(ipsec.get("pqc")),
    )


# ---------------------------------------------------------------------------
# Classification of what was negotiated
# ---------------------------------------------------------------------------


def _tls_canonical(name: str) -> str:
    text = name.strip()
    if re.fullmatch(r"0[xX][0-9a-fA-F]{1,4}|\d{1,5}", text):
        cp = int(text, 16) if text.lower().startswith("0x") else int(text)
        for pqc_name, g in _algorithms.TLS_PQC_GROUPS.items():
            if g["codepoint"] == cp:
                return pqc_name
        return _CLASSICAL_TLS_CODEPOINTS.get(cp, text)
    squashed = re.sub(r"[-_ ]", "", text).lower()
    for pqc_name in _algorithms.TLS_PQC_GROUPS:
        if pqc_name.lower() == squashed:
            return pqc_name
    return _CLASSICAL_TLS_ALIASES.get(squashed, text)


def classify_observed(rec: dict[str, Any]) -> tuple[str | None, str]:
    """(canonical negotiated name, class) where class is pure_pqc,
    hybrid, classical or unknown (no group reported, or a name no
    catalogue recognises)."""
    raw = rec.get("negotiated_group")
    protocol = rec.get("protocol")
    if protocol == "ikev2":
        names = [n for n in [raw, *(rec.get("additional_key_exchanges") or [])] if n]
        pqc = [n for n in names if _IKE_PQC_RE.search(n)]
        classical = [n for n in names if _IKE_CLASSICAL_RE.match(n)]
        canonical = "+".join(names) if names else None
        if pqc and classical:
            return canonical, "hybrid"
        if pqc:
            return canonical, "pure_pqc"
        if classical:
            return canonical, "classical"
        return canonical, "unknown"
    if not raw:
        return None, "unknown"
    if protocol == "ssh":
        buckets = _protocols.classify_ssh_kex([raw])
        canonical = raw
    else:
        canonical = _tls_canonical(raw)
        buckets = _config.classify_tls_groups([canonical])
    for cls in ("pure_pqc", "hybrid", "classical"):
        if buckets.get(cls):
            return canonical, cls
    return canonical, "unknown"


# ---------------------------------------------------------------------------
# The join
# ---------------------------------------------------------------------------


def _candidates(
    index: HostIndex, rec: dict[str, Any]
) -> tuple[list[int], str | None, list[int]]:
    """(matched host indexes, basis, ambiguous candidates).  Tiers are
    tried strongest first; within a tier more than one host is narrowed
    by the certificate fingerprint before being called ambiguous."""
    fqdn = (rec.get("fqdn") or "").lower().rstrip(".")
    sni = (rec.get("sni") or "").lower().rstrip(".")
    ip = _normalise_ip(rec["ip"]) if rec.get("ip") else None
    cert = (rec.get("certificate_sha256") or "").lower()
    cert_hosts = set(index.by_cert.get(cert, [])) if cert else set()
    shorts = {n.split(".", 1)[0] for n in (fqdn, sni) if n}
    tiers: list[tuple[str, list[int]]] = [
        ("fqdn", index.by_name.get(fqdn, []) if fqdn else []),
        ("sni", index.by_name.get(sni, []) if sni else []),
        ("ip", index.by_ip.get(ip, []) if ip else []),
        ("short-name", sorted({i for s in shorts for i in index.by_short.get(s, [])})),
        ("certificate", sorted(cert_hosts)),
    ]
    for basis, hits in tiers:
        hits = sorted(set(hits))
        if len(hits) == 1:
            return hits, basis, []
        if len(hits) > 1:
            narrowed = [h for h in hits if h in cert_hosts]
            if len(narrowed) == 1 and basis != "certificate":
                return narrowed, f"{basis}+certificate", []
            return [], None, hits
    return [], None, []


def _pick_listener(
    entry: HostEntry, rec: dict[str, Any]
) -> tuple[dict[str, Any] | None, int, str | None]:
    """(listener, matching listener count, note).  Only wildcard or
    specific binds are reachable from the network; a specific bind must
    be on the observed address when one is given."""
    transport = rec.get("transport") or PROTOCOL_TRANSPORT[rec["protocol"]]
    ip = _normalise_ip(rec["ip"]) if rec.get("ip") else None
    hits = [
        ln
        for ln in entry.listeners
        if ln["protocol"] == transport
        and ln["port"] == rec["port"]
        and ln["bind_scope"] in ("any", "specific")
        and not (ln["bind_scope"] == "specific" and ip and ln["address"] != ip)
    ]
    if not hits:
        return None, 0, None
    in_host_ns = [ln for ln in hits if ln["network_namespace"] == "host"]
    if in_host_ns:
        return in_host_ns[0], len(hits), None
    return (
        hits[0],
        len(hits),
        "listener is in another network namespace: reachable only through port mapping",
    )


def _capable(
    entry: HostEntry, listener: dict[str, Any] | None, protocol: str
) -> bool | None:
    if protocol == "ssh":
        return entry.ssh_capable
    if protocol == "ikev2":
        return entry.ike_capable
    return listener["library_pqc_capable"] if listener else None


def _configured(
    entry: HostEntry, listener: dict[str, Any] | None, protocol: str
) -> bool | None:
    if protocol == "ssh":
        return entry.ssh_configured
    if protocol == "ikev2":
        return entry.ike_configured
    if listener and listener["go_default_hybrid"]:
        # Go's crypto/tls ignores the system policy; its default is the setting.
        return True
    return entry.tls_configured


def join_observations(
    loaded: LoadedObservations,
    index: HostIndex,
    max_age_days: float = DEFAULT_MAX_AGE_DAYS,
) -> dict[str, Any]:
    """Match every valid observation to a host and listener and roll the
    results up.  Returns the `observations` object of the rollup."""
    by_status: Counter[str] = Counter()
    by_class: Counter[str] = Counter()
    states: Counter[tuple[str, str, str]] = Counter()
    per_host: dict[str, dict[str, Any]] = {}
    stale_count = 0
    matches: list[dict[str, Any]] = []
    for rec in loaded.records:
        canonical, cls = classify_observed(rec)
        by_class[cls] += 1
        hits, basis, ambiguous = _candidates(index, rec)
        m: dict[str, Any] = {
            "record": rec["_position"],
            "id": rec.get("id"),
            "protocol": rec["protocol"],
            "port": rec["port"],
            "fqdn": rec.get("fqdn"),
            "ip": rec.get("ip"),
            "sni": rec.get("sni"),
            "observed_group": canonical,
            "observed_class": cls,
            "source_category": rec["source"]["category"],
            "status": "unmatched_host",
            "match_basis": None,
            "host": None,
            "candidates": [],
            "listener": None,
            "capable": None,
            "configured": None,
            "certificate_on_host": None,
            "stale": None,
            "note": None,
        }
        if ambiguous:
            m["status"] = "ambiguous"
            m["candidates"] = sorted(index.hosts[i].hostname for i in ambiguous)
        elif hits:
            entry = index.hosts[hits[0]]
            m["host"] = entry.hostname
            m["match_basis"] = basis
            cert = (rec.get("certificate_sha256") or "").lower()
            if cert:
                m["certificate_on_host"] = cert in entry.cert_sha256
            observed_at = _parse_time(rec["observed_at"])
            if entry.generated_at and observed_at:
                age = abs((entry.generated_at - observed_at).total_seconds()) / 86400
                m["stale"] = age > max_age_days
                stale_count += bool(m["stale"])
            listener: dict[str, Any] | None = None
            if rec["protocol"] in ("ssh", "ikev2") or entry.service_scan:
                listener, count, note = _pick_listener(entry, rec)
                m["note"] = note
                if listener:
                    m["status"] = "matched"
                    m["listener"] = {**listener, "matching_listeners": count}
                elif entry.service_scan:
                    m["status"] = "unmatched_listener"
                else:
                    m["status"] = "no_service_scan"
            else:
                m["status"] = "no_service_scan"
            if m["status"] in ("matched", "no_service_scan"):
                m["capable"] = _capable(entry, listener, rec["protocol"])
                m["configured"] = _configured(entry, listener, rec["protocol"])
                h = per_host.setdefault(
                    entry.hostname,
                    {
                        "endpoints": 0,
                        "by_observed_class": {},
                        "capable_but_observed_classical": 0,
                        "configured_but_observed_classical": 0,
                        "stale": 0,
                    },
                )
                h["endpoints"] += 1
                h["by_observed_class"][cls] = h["by_observed_class"].get(cls, 0) + 1
                h["stale"] += bool(m["stale"])
                if cls == "classical" and m["capable"] is True:
                    h["capable_but_observed_classical"] += 1
                if cls == "classical" and m["configured"] is True:
                    h["configured_but_observed_classical"] += 1
                states[(_tri(m["capable"]), _tri(m["configured"]), cls)] += 1
        by_status[m["status"]] += 1
        matches.append(m)
    return {
        "observation_schema_version": OBSERVATION_SCHEMA_VERSION,
        "file_format": loaded.file_format,
        "total": len(loaded.records) + len(loaded.invalid),
        "valid": len(loaded.records),
        "invalid": loaded.invalid,
        "max_age_days": max_age_days,
        "stale": stale_count,
        "by_status": dict(sorted(by_status.items())),
        "by_observed_class": dict(sorted(by_class.items())),
        "states": [
            {"capable": c, "configured": g, "observed": o, "endpoints": n}
            for (c, g, o), n in sorted(states.items())
        ],
        "per_host": dict(sorted(per_host.items())),
        "matches": matches,
    }


def _tri(value: bool | None) -> str:
    return "unknown" if value is None else ("yes" if value else "no")
