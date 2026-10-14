"""IKEv2 post-quantum key exchange in configured IPsec proposals (#154).

What the host's IPsec configuration actually asks IKEv2 to negotiate,
as opposed to what the IPsec stack could do.  Two standards matter:

* RFC 9370 (final): up to seven Additional Key Exchanges negotiated in
  IKE_INTERMEDIATE, which is how a classical (EC)DH and ML-KEM are
  combined into a hybrid key exchange.
* draft-ietf-ipsecme-ikev2-mlkem (not yet an RFC: IESG-approved and in
  the RFC Editor queue as -09 on 2026-10-13): ML-KEM in IKEv2.  IANA
  already lists Transform Type 4 IDs 35/36/37 for ML-KEM-512/768/1024
  against it.

Configuration dialects parsed, from the implementations' own docs and
test suites:

* strongSwan ``swanctl.conf`` (``proposals`` / ``esp_proposals``) and
  legacy ``ipsec.conf`` (``ike=`` / ``esp=``): ``-`` separated keywords;
  ``keX_<method>`` (X = 1-7) adds an Additional Key Exchange and
  ``keX_none`` makes it optional (strongSwan 6.0.0+; ML-KEM keywords
  ``mlkem512`` / ``mlkem768`` / ``mlkem1024``).
* Libreswan ``ipsec.conf`` and ``/etc/ipsec.d/*.conf`` (``ike=`` /
  ``esp=`` / ``phase2alg=``): ``;`` separates the key exchange from the
  ciphers (``ike=aes;ke=ml_kem_768``), ``addkeN=<method>`` adds an
  Additional Key Exchange (``ike=aes128-sha2-dh31;addke1=ml_kem_1024``),
  ``+`` lists alternatives (Libreswan 5.4+ for ML-KEM).

Each proposal is classified into the report-wide buckets ``classical``
/ ``hybrid`` / ``pure_pqc`` by the most post-quantum key exchange it can
negotiate, and ``pqc_mandatory`` says whether every acceptable
negotiation includes ML-KEM (false when a classical alternative or an
optional ``keX_none`` / ``addkeN=none`` slot lets a peer avoid it).
"""

from __future__ import annotations

import glob as _glob
import logging
import re
from pathlib import Path
from typing import Any

from .. import _platform as _platform

log = logging.getLogger("pqc-readiness")

# Standards status as cited in output (verified 2026-10-13 against the
# IETF datatracker and the IANA IKEv2 registry).
IKE_PQC_STANDARDS: list[dict[str, str]] = [
    {
        "mechanism": "Multiple key exchanges in IKEv2 (IKE_INTERMEDIATE)",
        "reference": "RFC 9370",
        "status": "final",
    },
    {
        "mechanism": "ML-KEM in IKEv2",
        "reference": "draft-ietf-ipsecme-ikev2-mlkem-09",
        "status": "draft",
        "note": (
            "IESG-approved, in the RFC Editor queue; IANA Transform Type 4 "
            "IDs 35/36/37 (ML-KEM-512/768/1024) assigned"
        ),
    },
]

# Key-exchange method keywords -> (canonical name, pqc?).  strongSwan
# keywords from proposal_keywords_static.txt; Libreswan names from its
# algorithm parser and test suite (dhN group numbers, ml_kem_N).
_MODP = {768: 1, 1024: 2, 1536: 5, 2048: 14, 3072: 15, 4096: 16, 6144: 17, 8192: 18}
_DH_GROUPS = {
    1: "MODP-768",
    2: "MODP-1024",
    5: "MODP-1536",
    14: "MODP-2048",
    15: "MODP-3072",
    16: "MODP-4096",
    17: "MODP-6144",
    18: "MODP-8192",
    19: "ECP-256",
    20: "ECP-384",
    21: "ECP-521",
    22: "MODP-1024-160",
    23: "MODP-2048-224",
    24: "MODP-2048-256",
    25: "ECP-192",
    26: "ECP-224",
    27: "ECP-224-BP",
    28: "ECP-256-BP",
    29: "ECP-384-BP",
    30: "ECP-512-BP",
    31: "Curve25519",
    32: "Curve448",
    35: "ML-KEM-512",
    36: "ML-KEM-768",
    37: "ML-KEM-1024",
}


def _ke_method(token: str) -> str | None:
    """Canonical key-exchange method name for a proposal token, or None
    when the token is not a key-exchange method (cipher, integrity, PRF,
    ESN ...).  ``none`` is returned as-is (optional additional slot)."""
    t = token.strip().lower()
    if t == "none":
        return "none"
    m = re.fullmatch(r"ml[_-]?kem[_-]?(512|768|1024)", t)
    if m:
        return f"ML-KEM-{m.group(1)}"
    m = re.fullmatch(r"modp(\d+)", t)
    if m and int(m.group(1)) in _MODP:
        return f"MODP-{m.group(1)}"
    m = re.fullmatch(r"(?:dh|ecp_?)(\d+)(bp)?", t)
    if m:
        n = int(m.group(1))
        if t.startswith("dh") and n in _DH_GROUPS:
            return _DH_GROUPS[n]
        if t.startswith("ecp") and n in (192, 224, 256, 384, 521, 512):
            return f"ECP-{n}" + ("-BP" if m.group(2) else "")
    if t in ("curve25519", "x25519"):
        return "Curve25519"
    if t in ("curve448", "x448"):
        return "Curve448"
    return None


def _is_pqc(method: str) -> bool:
    return method.startswith("ML-KEM-")


def parse_ike_proposal(text: str) -> dict[str, Any]:
    """Key exchanges in one proposal, either dialect.

    Returns ``{proposal, primary: [...], additional: {"1": [...]}, ...}``
    plus the classification.  An empty ``primary`` means the proposal
    names no key exchange (the implementation's default applies)."""
    raw = text.strip().rstrip("!")
    primary: list[str] = []
    additional: dict[str, list[str]] = {}

    def add(slot: str | None, value: str) -> None:
        for alt in value.split("+"):
            method = _ke_method(alt)
            if method is None:
                continue
            target = primary if slot is None else additional.setdefault(slot, [])
            if method not in target:
                target.append(method)

    for seg in raw.split(";"):
        seg = seg.strip()
        if not seg:
            continue
        if "=" in seg:  # Libreswan ke= / addkeN=
            key, _, value = seg.partition("=")
            key = key.strip().lower()
            m = re.fullmatch(r"addke([1-7])", key)
            if key == "ke":
                add(None, value)
            elif m:
                add(m.group(1), value)
            continue
        for tok in seg.split("-"):
            m = re.fullmatch(r"ke([1-7])_(.+)", tok.strip().lower())
            if m:  # strongSwan keX_<method>
                add(m.group(1), m.group(2))
            else:
                add(None, tok)

    result: dict[str, Any] = {
        "proposal": raw,
        "primary": primary,
        "additional": dict(sorted(additional.items())),
    }
    result.update(_classify(primary, additional))
    return result


def _classify(primary: list[str], additional: dict[str, list[str]]) -> dict[str, Any]:
    if not primary and not additional:
        return {
            "category": None,
            "pqc_mandatory": False,
            "note": "no key exchange named; the implementation default applies",
        }
    # Best negotiable combination: prefer ML-KEM wherever offered.
    chosen: list[str] = []
    if primary:
        pqc_primary = [m for m in primary if _is_pqc(m)]
        chosen.append((pqc_primary or primary)[0])
    for options in additional.values():
        real = [m for m in options if m != "none"]
        pqc = [m for m in real if _is_pqc(m)]
        if pqc or real:
            chosen.append((pqc or real)[0])
    has_pqc = any(_is_pqc(m) for m in chosen)
    has_classical = any(not _is_pqc(m) for m in chosen)
    category = (
        "hybrid"
        if has_pqc and has_classical
        else "pure_pqc"
        if has_pqc
        else "classical"
    )
    mandatory = bool(primary) and all(_is_pqc(m) for m in primary)
    for options in additional.values():
        if options and all(_is_pqc(m) for m in options):
            mandatory = True
    return {"category": category, "pqc_mandatory": mandatory}


# ---------------------------------------------------------------------------
# Config file parsing
# ---------------------------------------------------------------------------


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(errors="replace")
    except OSError as e:
        log.debug("ike: cannot read %s: %s", path, e)
        return None


def _expand_include(pattern: str, base: Path) -> list[Path]:
    """Include targets, relative to the including file, under the host
    prefix.  Globs are expanded in sorted order."""
    p = pattern.strip().strip('"')
    if not p.startswith("/"):
        local = base.parent / p
    else:
        local = _platform.host_path(p)
    return [Path(x) for x in sorted(_glob.glob(str(local)))]


def _strip_prefix(path: Path) -> str:
    s = str(path)
    pre = _platform.HOST_PREFIX
    return s[len(pre) :] if pre and s.startswith(pre) else s


def parse_swanctl_conf(path: Path, _depth: int = 0) -> list[dict[str, Any]]:
    """IKE and child proposals from a strongSwan settings-format file
    (``swanctl.conf`` and its ``include`` files)."""
    text = _read_text(path)
    if text is None or _depth > 8:
        return []
    out: list[dict[str, Any]] = []
    stack: list[str] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("include "):
            for inc in _expand_include(line[len("include ") :], path):
                out.extend(parse_swanctl_conf(inc, _depth + 1))
            continue
        while line.startswith("}"):
            if stack:
                stack.pop()
            line = line[1:].strip()
        if not line:
            continue
        if line.endswith("{"):
            stack.append(line[:-1].strip())
            continue
        key, sep, value = line.partition("=")
        if not sep:
            continue
        key = key.strip()
        if key not in ("proposals", "esp_proposals", "ah_proposals"):
            continue
        conn = stack[1] if len(stack) > 1 and stack[0] == "connections" else None
        child = stack[3] if len(stack) > 3 and stack[2] == "children" else None
        for prop in value.split(","):
            if prop.strip():
                entry = parse_ike_proposal(prop)
                entry.update(
                    connection=conn,
                    child=child,
                    kind="ike" if key == "proposals" else "child",
                    source=_strip_prefix(path),
                )
                out.append(entry)
    return out


def parse_ipsec_conf(path: Path, _depth: int = 0) -> list[dict[str, Any]]:
    """IKE and child proposals from an ``ipsec.conf``-style file: Libreswan
    (``ike=`` / ``esp=`` / ``phase2alg=``, ``include``) or strongSwan's
    legacy starter format (``ike=`` / ``esp=``)."""
    text = _read_text(path)
    if text is None or _depth > 8:
        return []
    out: list[dict[str, Any]] = []
    section: str | None = None
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        stripped = line.strip()
        if not raw[:1].isspace():
            if stripped.startswith("include "):
                for inc in _expand_include(stripped[len("include ") :], path):
                    out.extend(parse_ipsec_conf(inc, _depth + 1))
                section = None
                continue
            m = re.match(r"conn\s+(\S+)", stripped)
            section = m.group(1) if m else None
            continue
        if section is None:  # config setup, or before the first conn
            continue
        key, sep, value = stripped.partition("=")
        if not sep:
            continue
        key = key.strip().lower()
        if key not in ("ike", "esp", "phase2alg", "ah"):
            continue
        value = value.strip().strip('"')
        for prop in value.split(","):
            if prop.strip():
                entry = parse_ike_proposal(prop)
                entry.update(
                    connection=section,
                    child=None,
                    kind="ike" if key == "ike" else "child",
                    source=_strip_prefix(path),
                )
                out.append(entry)
    return out


# Config entry points, by dialect.  Fedora / RHEL package strongSwan's
# swanctl directory under /etc/strongswan.
_SWANCTL_FILES = ("/etc/swanctl/swanctl.conf", "/etc/strongswan/swanctl/swanctl.conf")
_IPSEC_CONF_FILES = ("/etc/ipsec.conf", "/etc/strongswan/ipsec.conf")


def scan_ike_proposals() -> dict[str, Any]:
    """Every IKE / child-SA proposal configured on the host, classified.

    Returns ``{files, proposals, summary, standards}``.  Connections whose
    proposals name no key exchange (implementation defaults) are listed
    with ``category: null``."""
    files: list[str] = []
    proposals: list[dict[str, Any]] = []
    for f in _SWANCTL_FILES:
        p = _platform.host_path(f)
        if _platform.safe_is_file(p):
            files.append(f)
            proposals.extend(parse_swanctl_conf(p))
    for f in _IPSEC_CONF_FILES:
        p = _platform.host_path(f)
        if _platform.safe_is_file(p):
            files.append(f)
            proposals.extend(parse_ipsec_conf(p))
    ike = [p for p in proposals if p["kind"] == "ike"]
    counts = {"classical": 0, "hybrid": 0, "pure_pqc": 0, "unclassified": 0}
    for prop in ike:
        counts[prop["category"] or "unclassified"] += 1
    # "%default" (Libreswan, strongSwan starter) is a template that other
    # connections inherit, not a connection.
    conns = sorted(
        {
            p["connection"]
            for p in ike
            if p["connection"] and not p["connection"].startswith("%")
        }
    )
    pqc_conns = sorted(
        {
            c
            for c in conns
            if any(
                p["connection"] == c and p["category"] in ("hybrid", "pure_pqc")
                for p in ike
            )
        }
    )
    return {
        "files": files,
        "proposals": proposals,
        "summary": {
            "ike_proposals": len(ike),
            **counts,
            "connections": len(conns),
            "connections_offering_pqc": len(pqc_conns),
            "connections_requiring_pqc": len(
                {
                    p["connection"]
                    for p in ike
                    if p["connection"] in conns and p["pqc_mandatory"]
                }
            ),
        },
        "standards": IKE_PQC_STANDARDS,
    }
