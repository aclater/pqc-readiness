"""OpenSSH, IPsec (libreswan / strongSwan) and NSS PQC capability."""

from __future__ import annotations

import re
import shutil
from typing import Any

from .. import _platform as _platform
from ..detect import osinfo as _osinfo
from ..detect import packages as _packages
from ..detect import runtime as _runtime


# ---------------------------------------------------------------------------
# OpenSSH / strongSwan / NSS PQC capability
# ---------------------------------------------------------------------------

# OpenSSH PQC kex names embed both a PQC token (mlkem*, kyber*, sntrup*)
# and — so far, always — a classical token (nistp*, x25519, x448).  Pure
# PQC SSH kex is not yet in OpenSSH as of 2026; the pure_pqc bucket below
# is reserved for the day a `mlkem768-sha256`-style name ships.
# No word-boundary anchors here — OpenSSH concatenates the PQC and
# classical tokens with no separator (e.g. `mlkem768x25519-sha256`),
# and `\b` on the leading side would suppress the classical match
# because the boundary between two word characters does not exist.
_PQC_SSH_TOKEN_RE = re.compile(r"(?:mlkem\d+|kyber\d+|sntrup\d+)", re.IGNORECASE)


_CLASSICAL_SSH_TOKEN_RE = re.compile(
    r"(?:nistp\d+|x25519|x448|secp\d+r1)",
    re.IGNORECASE,
)


# Full classical SSH kex names recognised by OpenSSH's `-Q kex` set.
# Used to populate the `classical` bucket for parity with
# classify_tls_groups (issue #9, audit #40).  Names that match no
# pattern are dropped rather than silently lumped into classical, the
# same way classify_tls_groups handles unknown TLS group names.
_CLASSICAL_SSH_KEX_RE = re.compile(
    r"^(?:"
    r"diffie-hellman-group(?:\d+|-exchange)-sha\d+"
    r"|ecdh-sha2-nistp\d+"
    r"|curve(?:25519|448)-sha\d+(?:@\S+)?"
    r")$",
    re.IGNORECASE,
)


def classify_ssh_kex(kexes: list[str]) -> dict[str, list[str]]:
    """Split SSH kex algorithm names into pure_pqc / hybrid / classical
    buckets, mirroring classify_tls_groups.  A name with a PQC token and
    a classical token is hybrid; PQC-token-only names are pure_pqc;
    recognised classical kex names (DH groups, ECDH NIST, curve25519/448)
    land in classical.  As of 2026 every shipped OpenSSH PQC kex is
    hybrid, but the pure_pqc bucket exists so future RFC-adopted pure-PQC
    kex surface the day they arrive.  Unrecognised names are dropped so
    the report stays honest about what we don't catalogue yet."""
    pure: set[str] = set()
    hybrid: set[str] = set()
    classical: set[str] = set()
    for k in kexes:
        if _PQC_SSH_TOKEN_RE.search(k):
            if _CLASSICAL_SSH_TOKEN_RE.search(k):
                hybrid.add(k)
            else:
                pure.add(k)
        elif _CLASSICAL_SSH_KEX_RE.match(k):
            classical.add(k)
    return {
        "pure_pqc": sorted(pure),
        "hybrid": sorted(hybrid),
        "classical": sorted(classical),
    }


def parse_ssh_kex(text: str) -> dict[str, Any]:
    """Parse `ssh -Q kex` output.  Returns a dict with the full kex
    count, the flat PQC subset (ML-KEM hybrids and the older sntrup761
    NTRU Prime hybrid), and a `kex_groups` split into pure_pqc / hybrid /
    classical.

    The flat `pqc_kex` list is preserved for back-compat with consumers
    that already key off it; new consumers should prefer `kex_groups`."""
    kexes = [line.strip() for line in text.splitlines() if line.strip()]
    pqc = sorted({k for k in kexes if _PQC_SSH_TOKEN_RE.search(k)})
    return {
        "available": True,
        "kex_count": len(kexes),
        "pqc_kex": pqc,
        "kex_groups": classify_ssh_kex(kexes),
    }


def parse_ssh_version(text: str) -> str | None:
    """Parse `ssh -V` (printed to stderr).  Format:
    OpenSSH_9.9p1, OpenSSL 3.5.5 27 Jan 2026"""
    m = re.search(r"OpenSSH_([^\s,]+)", text)
    return m.group(1) if m else None


def detect_ssh_pqc(family: str = "unknown") -> dict[str, Any]:
    if not shutil.which("ssh"):
        return {
            "available": False,
            "reason": f"ssh not on PATH ({_osinfo._install_hint('ssh', family)})",
        }
    # ssh -V writes to stderr, captured via _run's stderr merge.
    _, ver_out = _platform._run(["ssh", "-V"], timeout=3)
    version = parse_ssh_version(ver_out)
    rc, out = _platform._run(["ssh", "-Q", "kex"], timeout=5)
    if rc != 0:
        return {
            "available": False,
            "version": version,
            "reason": f"ssh -Q kex failed (rc={rc})",
        }
    parsed = parse_ssh_kex(out)
    parsed["version"] = version
    return parsed


def parse_libreswan_version(text: str) -> str | None:
    """Parse `ipsec --version` for the Libreswan release string.  Format:
    Linux Libreswan 4.15 (netkey) on 5.14.0-..."""
    m = re.search(r"Libreswan\s+(\S+)", text)
    return m.group(1) if m else None


def detect_ipsec_pqc(family: str = "unknown") -> dict[str, Any]:
    """Detect IPsec PQC support across the two major implementations.

    strongSwan exposes algorithms via `swanctl --list-algs`; Libreswan
    (more common on RHEL) does not have a single equivalent — it
    advertises supported KE methods through the `ipsec` command's
    config-validation output, but PQC support there is still
    pre-release as of early 2026.  We report both implementations
    when present so customers know which stack the host runs."""
    out: dict[str, Any] = {"available": False}
    if shutil.which("swanctl"):
        rc, sw_out = _platform._run(["swanctl", "--list-algs"], timeout=10)
        if rc == 0:
            pqc_match = re.search(
                r"\b(ML[-_ ]?KEM|kyber|mlkem)\b", sw_out, re.IGNORECASE
            )
            out.update(
                {
                    "available": True,
                    "implementation": "strongswan",
                    "pqc": bool(pqc_match),
                    "evidence": pqc_match.group(0) if pqc_match else None,
                }
            )
            return out
        out["reason"] = f"swanctl --list-algs failed (rc={rc})"
    if shutil.which("ipsec"):
        rc, ip_out = _platform._run(["ipsec", "--version"], timeout=5)
        if rc == 0 and "Libreswan" in ip_out:
            out.update(
                {
                    "available": True,
                    "implementation": "libreswan",
                    "version": parse_libreswan_version(ip_out),
                    "pqc": False,
                    "note": "Libreswan PQC support is pre-release as of 2026; "
                    "verify against upstream release notes.",
                }
            )
            return out
    if not out.get("reason"):
        out["reason"] = (
            f"neither swanctl nor ipsec on PATH ({_osinfo._install_hint('swanctl', family)})"
        )
    return out


# Mozilla NSS 3.108 (Aug 2025) added hybrid PQC TLS support; earlier
# versions cannot negotiate the hybrid groups even when OpenSSL can.
NSS_PQC_MIN_VERSION = (3, 108)


def parse_nss_version(text: str) -> tuple[int, int, int] | None:
    m = re.search(r"\b(\d+)\.(\d+)(?:\.(\d+))?\b", text)
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or "0"))


# Package names that carry the NSS libraries: `nss` on RHEL/Fedora,
# `mozilla-nss` on SLES/openSUSE.
NSS_RPM_PACKAGE_NAMES = ("nss", "mozilla-nss")


# nss.tool label for each packages.source value; the CLI path is `rpm -q`.
_NSS_TOOL_BY_SOURCE: dict[str, str] = {
    "rpmdb-sqlite": "rpmdb (sqlite)",
    "rpmdb-bdb": "rpmdb (bdb)",
    "rpmdb-ndb": "rpmdb (ndb)",
}


def _nss_from_rpmdb() -> dict[str, Any] | None:
    """NSS version from the shared rpm inventory (#125), or None when the
    inventory is unavailable or has no NSS package.  Multi-arch installs
    (i686 + x86_64) report the highest parsed version."""
    inv = _packages.query_rpm_named(NSS_RPM_PACKAGE_NAMES)
    if not inv.get("available"):
        return None
    versions = [p["version"] for p in inv["packages"]]
    if not versions:
        return None
    parsed = [(parse_nss_version(v), v) for v in versions]
    known = [(ver, raw) for ver, raw in parsed if ver is not None]
    ver, raw = max(known) if known else (None, versions[0])
    tool = _NSS_TOOL_BY_SOURCE.get(inv["source"], "rpm -q")
    return {
        "available": True,
        "tool": tool,
        "version": ("%d.%d.%d" % ver) if ver else raw,
        "pqc_capable": ver is not None and ver >= NSS_PQC_MIN_VERSION,
        "note": "rpm-only check; NSS version reflects RHEL/Fedora package, not necessarily upstream",
    }


def _nss_from_certutil() -> dict[str, Any] | None:
    if not shutil.which("certutil"):
        return None
    rc, out = _platform._run(["certutil", "--version"], timeout=5)
    if rc != 0:
        return None
    ver = parse_nss_version(out)
    return {
        "available": True,
        "tool": "certutil --version",
        "version": "%d.%d.%d" % ver if ver else "unknown",
        "pqc_capable": ver is not None and ver >= NSS_PQC_MIN_VERSION,
    }


def detect_nss() -> dict[str, Any]:
    """Probe NSS version via certutil --version (preferred) or the rpm
    database as a fallback.  PQC capability is inferred from version
    >= NSS_PQC_MIN_VERSION (3.108).

    Under --host-mount the order flips: certutil is the container image's
    binary, so the host's rpm database is consulted first and certutil is
    only a last resort (flagged as reflecting the image)."""
    if _platform.HOST_PREFIX:
        found = _nss_from_rpmdb()
        if found is None:
            found = _nss_from_certutil()
            if found is not None:
                found["note"] = (
                    "certutil belongs to the scanner image; no NSS package "
                    "found in the host rpm database"
                )
    else:
        found = _nss_from_certutil() or _nss_from_rpmdb()
    if found is None:
        return {
            "available": False,
            "reason": "neither certutil nor a package manager that can query nss is on PATH",
        }
    note = _runtime._host_fs_note_for("nss")
    if note:
        found.update(note)
    return found
