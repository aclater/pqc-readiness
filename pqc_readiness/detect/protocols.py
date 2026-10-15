"""OpenSSH, IPsec (libreswan / strongSwan) and NSS PQC capability."""

from __future__ import annotations

import re
import shutil
from typing import Any

from .. import _platform as _platform
from ..detect import osinfo as _osinfo
from ..detect import packages as _packages
from ..detect import runtime as _runtime
from ..detect import protocols_ike as _ike


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


_SCANNER_SSH_REASON = (
    "{mode}: the ssh on PATH, if any, is the scanner's{version}, so `ssh -V` and "
    "`ssh -Q kex` would describe it, not the host"
)
_NO_SSH_REASON = "ssh client not on PATH; read the host's OpenSSH files instead"


def _scanner_ssh_version() -> str:
    _, out = _platform._run(["ssh", "-V"], timeout=3)
    return parse_ssh_version(out) or "unknown"


def ssh_from_files(
    os_release: dict[str, Any] | None, scanner_cli: str | None
) -> dict[str, Any]:
    """The `ssh_pqc` section when the `ssh` CLI can't describe the host:
    under --host-mount or --root, where it is the scanner's own (#256), or
    on a host with sshd but no client.  The version comes from the host's
    OpenSSH package, else its binary; the kex names are read from the
    binary.  `scanner_cli` names the scan mode when a CLI exists but
    belongs to the scanner, None when there is no CLI."""
    # Imported here: openssh_build (via openssh_host) imports this module.
    from ..detect import openssh_host as _openssh_host

    osr = os_release or {}
    ev = _openssh_host.openssh_evidence(osr)
    if scanner_cli:
        # Offline scans run no binaries at all, not even the scanner's own
        # `ssh -V`; only --host-mount reports the image's version.
        scanner_version: str | None = (
            _scanner_ssh_version() if scanner_cli == "--host-mount" else None
        )
        reason = _SCANNER_SSH_REASON.format(
            mode=scanner_cli,
            version=f" ({scanner_version})" if scanner_version else "",
        )
    else:
        scanner_version = None
        reason = _NO_SSH_REASON
    if not ev["installed"]:
        out: dict[str, Any] = {
            "available": False,
            "reason": "no OpenSSH package or binary found on the host",
        }
        if scanner_version:
            out["scanner_cli_version"] = scanner_version
        return out
    kexes = ev["kex"]
    build = ev["binary"] or {}
    out = {
        "available": True,
        "version": ev["version"],
        "version_source": ev["version_source"],
        "package": ev["package"],
        "binaries": build.get("binaries") or [],
        "cli_probe": {"available": False, "reason": reason},
    }
    if kexes is not None:
        parsed = parse_ssh_kex("\n".join(kexes))
        out.update(
            kex_count=parsed["kex_count"],
            pqc_kex=parsed["pqc_kex"],
            kex_groups=parsed["kex_groups"],
            kex_source="binary",
            # The shape detect_sshd reads from openssh_build (#247), so the
            # binary evidence and compiled-in default carry over.
            source="binary",
        )
        if build.get("default_kex"):
            out["default_kex"] = build["default_kex"]
    else:
        # Package found but no readable binary: the version is known, the
        # kex list isn't.  Null, not empty, so nothing reads it as "none".
        out.update(kex_count=None, pqc_kex=None, kex_groups=None, kex_source=None)
    if scanner_version:
        out["scanner_cli_version"] = scanner_version
    return out


def detect_ssh_pqc(
    family: str = "unknown", os_release: dict[str, Any] | None = None
) -> dict[str, Any]:
    osr = os_release if os_release is not None else dict(family=family)
    has_cli = bool(shutil.which("ssh"))
    # Under --host-mount the ssh on PATH is the scanner image's (#256).
    if _platform.HOST_PREFIX and not _platform.OFFLINE_ROOT:
        return ssh_from_files(osr, "--host-mount" if has_cli else None)
    if not has_cli:
        found = ssh_from_files(osr, None)
        if found.get("available"):
            return found
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
    parsed["version_source"] = "cli"
    parsed["kex_source"] = "cli"
    return parsed


def parse_libreswan_version(text: str) -> str | None:
    """Parse `ipsec --version` for the Libreswan release string.  Format:
    Linux Libreswan 4.15 (netkey) on 5.14.0-..."""
    m = re.search(r"Libreswan\s+(\S+)", text)
    return m.group(1) if m else None


# Libreswan's upstream CHANGES list ML_KEM_768 in IKE_SA_INIT and
# IKE_INTERMEDIATE (RFC 9370) from v5.4 (2026-08-13).  Distributions may
# backport; the configured-proposal scan below reports what is asked for
# either way.
LIBRESWAN_PQC_MIN_VERSION = (5, 4)


def _libreswan_pqc(version: str | None) -> bool:
    m = re.match(r"v?(\d+)\.(\d+)", version or "")
    if m is None:
        return False
    return (int(m.group(1)), int(m.group(2))) >= LIBRESWAN_PQC_MIN_VERSION


_SCANNER_IPSEC_REASON = (
    "under {mode} the swanctl / ipsec on PATH are the scanner's own, not the "
    "host's; implementation and version are read from the host's package "
    "and binaries"
)


def _cli_describes_host() -> bool:
    """True when tools on PATH describe the scanned host: a bare-metal or
    VM scan.  Under --host-mount they are the scanner image's own."""
    return not (_platform.HOST_PREFIX and not _platform.OFFLINE_ROOT)


def ipsec_from_files(
    os_release: dict[str, Any] | None, scanner_cli: str | None
) -> dict[str, Any]:
    """IPsec capability when `swanctl` / `ipsec` can't describe the host:
    under --host-mount or --root (#265), or on a host with the daemon but
    no CLI.  Implementation, version and PQC capability come from the
    host's package and binaries (see ipsec_host).  `scanner_cli` names the
    scan mode when the tools on PATH belong to the scanner, None when the
    host simply has no CLI."""
    # Imported here: ipsec_host imports this module.
    from ..detect import ipsec_host as _ipsec_host

    ev = _ipsec_host.ipsec_evidence(os_release or {})
    if ev is None:
        return {
            "available": False,
            "reason": "no strongSwan or Libreswan package or binary found on the host",
        }
    out: dict[str, Any] = {"available": True, **ev}
    if scanner_cli:
        out["cli_probe"] = {
            "available": False,
            "reason": _SCANNER_IPSEC_REASON.format(mode=scanner_cli),
        }
    return out


def detect_ipsec_pqc(
    family: str = "unknown", os_release: dict[str, Any] | None = None
) -> dict[str, Any]:
    """IPsec PQC capability and configuration.

    Capability: strongSwan exposes algorithms via `swanctl --list-algs`;
    Libreswan has no equivalent, so its version decides (ML-KEM from
    5.4).  Under --host-mount, or when neither CLI is installed, the
    host's package and binaries decide instead (#265).  Configuration
    (#154): `configured` classifies every IKE and child-SA proposal in
    swanctl.conf / ipsec.conf (and their includes), whether or not an
    IPsec daemon is installed."""
    osr = os_release if os_release is not None else dict(family=family)
    has_cli = bool(shutil.which("swanctl") or shutil.which("ipsec"))
    if not _cli_describes_host():
        out = ipsec_from_files(osr, "--host-mount" if has_cli else None)
    else:
        out = _detect_ipsec_capability(family)
        if not out.get("available") and not has_cli:
            found = ipsec_from_files(osr, None)
            if found.get("available"):
                out = found
    configured = _ike.scan_ike_proposals()
    offering = configured["summary"]["connections_offering_pqc"]
    if out.get("available") and not out.get("pqc") and offering:
        # Configured but not capable: verified on Rocky 10, whose
        # Libreswan 5.3.2 rejects `ke=ml_kem_768` and `addke1=` outright,
        # so such a connection fails to load rather than falling back.
        configured["capability_mismatch"] = {
            "connections": sorted(
                {
                    p["connection"]
                    for p in configured["proposals"]
                    if p["kind"] == "ike" and p["category"] in ("hybrid", "pure_pqc")
                }
            ),
            "reason": (
                f"{offering} connection(s) configure ML-KEM but the installed "
                f"{out.get('implementation')} reports no ML-KEM support"
            ),
        }
    out["configured"] = configured
    return out


def _detect_ipsec_capability(family: str) -> dict[str, Any]:
    out: dict[str, Any] = {"available": False}
    if shutil.which("swanctl"):
        rc, sw_out = _platform._run(["swanctl", "--list-algs"], timeout=10)
        if rc == 0:
            # strongSwan prints ML_KEM_768 etc.; a trailing \b after "KEM"
            # never matched there because "_" is a word character, so
            # PQC-capable strongSwan was reported as pqc=false.
            pqc_match = re.search(
                r"\b(ML[-_ ]?KEM(?:[-_ ]?\d+)?|kyber\d*|mlkem\d*)",
                sw_out,
                re.IGNORECASE,
            )
            _, ver_out = _platform._run(["swanctl", "--version"], timeout=5)
            m = re.search(r"strongSwan swanctl (\S+)", ver_out)
            out.update(
                {
                    "available": True,
                    "implementation": "strongswan",
                    "version": m.group(1) if m else None,
                    "version_source": "cli" if m else None,
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
                    "version_source": "cli",
                    "pqc": _libreswan_pqc(parse_libreswan_version(ip_out)),
                    "note": "Libreswan supports ML-KEM-768 from upstream 5.4 "
                    "(RFC 9370 additional key exchanges); earlier "
                    "distribution builds may carry backports.",
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
