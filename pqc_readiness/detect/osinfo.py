"""OS identity (single source of truth for distro family), install hints, kernel info."""

from __future__ import annotations

import logging
import platform
import re
import shutil
from typing import Any

from .. import _platform as _platform

log = logging.getLogger("pqc-readiness")


# ---------------------------------------------------------------------------
# OS identity (single source of truth for distro family / package manager)
# ---------------------------------------------------------------------------
#
# Linux distros vary in tool names, package layout, and FIPS posture.  Rather
# than peppering checks throughout the codebase (`if "rhel" in ... else if
# "ubuntu" in ...`), every distro-conditional path resolves through the dict
# returned by detect_os().  /etc/os-release is the freedesktop standard and
# is present on every modern Linux distro; we fall back to legacy distro
# files only when it's missing.

OS_FAMILY_BY_ID: dict[str, str] = {
    # rhel family
    "rhel": "rhel",
    "fedora": "rhel",
    "centos": "rhel",
    "rocky": "rhel",
    "almalinux": "rhel",
    "ol": "rhel",
    "amzn": "rhel",
    # debian family
    "debian": "debian",
    "ubuntu": "debian",
    "linuxmint": "debian",
    "pop": "debian",
    "kali": "debian",
    "raspbian": "debian",
    "neon": "debian",
    "elementary": "debian",
    # suse family
    "sles": "suse",
    "opensuse-leap": "suse",
    "opensuse-tumbleweed": "suse",
    "sled": "suse",
    # arch family
    "arch": "arch",
    "manjaro": "arch",
    "endeavouros": "arch",
    "garuda": "arch",
    # alpine
    "alpine": "alpine",
    # OpenWrt: opkg up to 24.10, apk from 25.12 (#217); its package
    # database is found by probing rather than by a family tool.
    "openwrt": "openwrt",
}


# When `ID` is not in the table above, fall back to checking each token in
# `ID_LIKE` against the same map.  Ubuntu derivatives, for instance, may
# self-identify as `ID=foo ID_LIKE="ubuntu debian"` — we resolve to debian.

PKG_MANAGER_ORDER: dict[str, list[str]] = {
    # First entry that is on PATH wins.  apt-get is preferred over apt for
    # scripting (apt's CLI is explicitly not stable for scripts per the
    # apt(8) manpage).  microdnf only when dnf is absent (UBI minimal).
    "rhel": ["dnf", "microdnf", "yum"],
    "debian": ["apt-get", "apt"],
    "suse": ["zypper"],
    "arch": ["pacman"],
    "alpine": ["apk"],
    "openwrt": ["apk", "opkg"],
}


def parse_os_release(text: str) -> dict[str, Any]:
    """Parse /etc/os-release content into the canonical os_release dict.

    /etc/os-release is `KEY=value` per line, values optionally wrapped in
    single or double quotes.  We extract ID, ID_LIKE, VERSION_ID,
    VERSION_CODENAME, PRETTY_NAME, then resolve family from ID first and
    fall back to ID_LIKE tokens.  Returns a dict with package_manager=None
    — the caller (`detect_os`) fills that in by probing PATH because we
    cannot do I/O from a pure parser used in unit tests.
    """
    raw: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        v = v.strip()
        if (v.startswith('"') and v.endswith('"')) or (
            v.startswith("'") and v.endswith("'")
        ):
            v = v[1:-1]
        raw[k.strip()] = v
    id_ = raw.get("ID", "").lower().strip()
    id_like = [t.lower() for t in raw.get("ID_LIKE", "").split() if t]
    family = OS_FAMILY_BY_ID.get(id_, "")
    if not family:
        for tok in id_like:
            if tok in OS_FAMILY_BY_ID:
                family = OS_FAMILY_BY_ID[tok]
                break
    return {
        "family": family or "unknown",
        "id": id_ or "unknown",
        "version_id": raw.get("VERSION_ID") or None,
        "version_codename": raw.get("VERSION_CODENAME") or None,
        "pretty_name": raw.get("PRETTY_NAME") or None,
        "package_manager": None,
    }


def _resolve_package_manager(family: str) -> str | None:
    for tool in PKG_MANAGER_ORDER.get(family, []):
        if shutil.which(tool):
            return tool
    return None


def detect_os() -> dict[str, Any]:
    """Single source of truth for distro identity.  Returns:

    family            rhel / debian / suse / arch / alpine / openwrt / macos / unknown
    id                rhel / fedora / ubuntu / debian / sles / ... / macos
    version_id        e.g. "9.6", "24.04", "44"
    version_codename  e.g. "jammy", "bookworm", or None
    pretty_name       full string from os-release / sysctl
    package_manager   first tool on PATH for this family, or None

    When running inside a container without --host-mount, the result
    additionally carries `unavailable_in_container: True` and a `reason`
    string — /etc/os-release inside a container is the container image's
    OS, not the host's, so consumers can warn rather than misreport."""
    out = _detect_os_impl()
    note = _platform.host_fs_unavailable_note(
        "OS release detection",
        "/etc/os-release, /usr/lib/os-release, /etc/redhat-release, /etc/debian_version",
    )
    if note:
        out.update(note)
    return out


def _detect_os_impl() -> dict[str, Any]:
    if _platform.is_macos():
        ver = _platform._sysctl("kern.osproductversion") or platform.mac_ver()[0]
        return {
            "family": "macos",
            "id": "macos",
            "version_id": ver or None,
            "version_codename": None,
            "pretty_name": f"macOS {ver}".rstrip() if ver else "macOS",
            "package_manager": "brew" if shutil.which("brew") else None,
        }
    # /etc/os-release is the freedesktop standard.  On most modern
    # distros it's a symlink to /usr/lib/os-release; in containerised
    # invocations the symlink can dangle when /usr/lib is not host-
    # mounted, so we try both paths explicitly.
    for candidate in ("/etc/os-release", "/usr/lib/os-release"):
        p = _platform.host_path(candidate)
        try:
            text = p.read_text()
        except OSError as e:
            log.debug("detect_os: cannot read %s: %s", candidate, e)
            continue
        out = parse_os_release(text)
        out["package_manager"] = _resolve_package_manager(out["family"])
        return out
    # Legacy fallbacks — only triggered when /etc/os-release is missing.
    rh_text: str | None = None
    if _platform.safe_exists(_platform.host_path("/etc/redhat-release")):
        try:
            rh_text = _platform.host_path("/etc/redhat-release").read_text()
        except OSError as e:
            log.debug("detect_os: cannot read /etc/redhat-release: %s", e)
    if rh_text is not None:
        rh = parse_redhat_release(rh_text)
        return {
            "family": "rhel",
            "id": rh.get("distro", "").lower().split()[0] or "rhel",
            "version_id": rh.get("version"),
            "version_codename": None,
            "pretty_name": rh.get("raw"),
            "package_manager": _resolve_package_manager("rhel"),
        }
    if _platform.safe_exists(_platform.host_path("/etc/debian_version")):
        try:
            deb_ver: str | None = (
                _platform.host_path("/etc/debian_version").read_text().strip()
            )
        except OSError as e:
            log.debug("detect_os: cannot read /etc/debian_version: %s", e)
            deb_ver = None
        return {
            "family": "debian",
            "id": "debian",
            "version_id": deb_ver,
            "version_codename": None,
            "pretty_name": f"Debian {deb_ver}" if deb_ver else "Debian",
            "package_manager": _resolve_package_manager("debian"),
        }
    if _platform.safe_exists(_platform.host_path("/etc/SuSE-release")):
        return {
            "family": "suse",
            "id": "suse",
            "version_id": None,
            "version_codename": None,
            "pretty_name": "SUSE Linux (legacy /etc/SuSE-release)",
            "package_manager": _resolve_package_manager("suse"),
        }
    return {
        "family": "unknown",
        "id": "unknown",
        "version_id": None,
        "version_codename": None,
        "pretty_name": f"{platform.system()} {platform.release()}".strip(),
        "package_manager": None,
    }


# Per-family install-hint table for missing tools.  Used in error
# messages so a Debian customer doesn't see `dnf install pciutils` and a
# RHEL customer doesn't see `apt-get install pciutils`.  Keys are the
# *binary* name, not the package name — the packages all happen to
# match the binary on these distros.
_INSTALL_HINT_BY_FAMILY: dict[str, dict[str, str]] = {
    "rhel": {
        "lspci": "dnf install pciutils",
        "tpm2_getcap": "dnf install tpm2-tools",
        "swanctl": "dnf install strongswan",
        "ssh": "dnf install openssh-clients",
        "certutil": "dnf install nss-tools",
        "rpm": "(should already be present on RHEL/Fedora)",
        "dpkg-query": "n/a — RHEL uses rpm",
    },
    "debian": {
        "lspci": "apt-get install pciutils",
        "tpm2_getcap": "apt-get install tpm2-tools",
        "swanctl": "apt-get install strongswan-swanctl",
        "ssh": "apt-get install openssh-client",
        "certutil": "apt-get install libnss3-tools",
        "dpkg-query": "(should already be present on Debian/Ubuntu)",
        "rpm": "n/a — Debian uses dpkg",
    },
    "suse": {
        "lspci": "zypper install pciutils",
        "tpm2_getcap": "zypper install tpm2.0-tools",
        "swanctl": "zypper install strongswan",
        "ssh": "zypper install openssh-clients",
        "certutil": "zypper install mozilla-nss-tools",
        "rpm": "(should already be present on SLES/openSUSE)",
    },
    "arch": {
        "lspci": "pacman -S pciutils",
        "tpm2_getcap": "pacman -S tpm2-tools",
        "swanctl": "pacman -S strongswan",
        "ssh": "pacman -S openssh",
        "certutil": "pacman -S nss",
        "pacman": "(should already be present on Arch)",
    },
    "alpine": {
        "lspci": "apk add pciutils",
        "tpm2_getcap": "apk add tpm2-tools",
        "swanctl": "apk add strongswan",
        "ssh": "apk add openssh-client",
        "certutil": "apk add nss-tools",
        "apk": "(should already be present on Alpine)",
    },
}


def _install_hint(binary: str, family: str) -> str:
    """Return a family-correct 'how to install <binary>' fragment for
    inclusion in error messages.  Falls back to a generic instruction
    when the family or binary is not in the table."""
    table = _INSTALL_HINT_BY_FAMILY.get(family, {})
    return table.get(binary, f"install the package providing {binary}")


# ---------------------------------------------------------------------------
# Kernel + RHEL minor + /proc/crypto PQC awareness
# ---------------------------------------------------------------------------


def parse_redhat_release(text: str) -> dict[str, Any]:
    """Parse /etc/redhat-release one-liner.  Examples:

    Red Hat Enterprise Linux release 9.4 (Plow)
    CentOS Stream release 9
    Fedora release 44 (Forty Four)
    """
    s = text.strip()
    out: dict[str, Any] = {"raw": s}
    m = re.search(r"^(.+?)\s+release\s+(\d+(?:\.\d+)?)", s)
    if m:
        out["distro"] = m.group(1).strip()
        out["version"] = m.group(2)
        if m.group(2).count(".") == 1:
            out["minor"] = m.group(2).split(".", 1)[1]
    return out


def parse_proc_crypto_pqc(text: str) -> list[str]:
    """Return /proc/crypto driver names whose `name` line mentions a PQC
    primitive (ML-KEM, ML-DSA, SLH-DSA, Kyber, Dilithium, SPHINCS).  As
    of 2026 this almost always returns an empty list — kernel-side PQC
    primitives are not yet in mainline."""
    out: list[str] = []
    pqc_re = re.compile(
        r"ml[-_ ]?kem|ml[-_ ]?dsa|slh[-_ ]?dsa|kyber|dilithium|sphincs", re.IGNORECASE
    )
    block: list[str] = []
    for line in text.splitlines() + [""]:
        if line.strip():
            block.append(line)
            continue
        if not block:
            continue
        joined = "\n".join(block)
        if pqc_re.search(joined):
            for ln in block:
                if ln.startswith("driver"):
                    out.append(ln.split(":", 1)[1].strip())
                    break
        block = []
    return out


def detect_kernel_info(os_release: dict[str, Any] | None = None) -> dict[str, Any]:
    """Kernel-specific facts.  Distro identity (ID, VERSION_ID, pretty
    name) lives in detect_os() / Report.os_release; this function used to
    duplicate that and now consumes the precomputed dict for backward
    compatibility — `os_release_id` and `os_release_version_id` are kept
    on the kernel_info dict so existing aggregator/CSV consumers don't
    break when they read either location.

    When running inside a container without --host-mount, the dict
    additionally carries `unavailable_in_container: True` and a `reason`
    string — /etc/redhat-release reflects the container image, and
    /proc/crypto is shared with the host kernel but PQC awareness still
    needs explicit acknowledgement that the container is in play."""
    info: dict[str, Any] = {
        "release": platform.release(),
        "system": platform.system(),
    }
    if not _platform.is_linux():
        return info
    if os_release:
        if os_release.get("id") and os_release["id"] != "unknown":
            info["os_release_id"] = os_release["id"]
        if os_release.get("version_id"):
            info["os_release_version_id"] = os_release["version_id"]
    # /etc/redhat-release is retained as a legacy hint — modern distros
    # are sourced via os_release above.
    rh = _platform.host_path("/etc/redhat-release")
    if _platform.safe_exists(rh):
        try:
            info["redhat_release"] = parse_redhat_release(rh.read_text())
        except OSError as e:
            log.debug("detect_kernel_info: cannot read /etc/redhat-release: %s", e)
    try:
        info["proc_crypto_pqc"] = parse_proc_crypto_pqc(
            _platform.host_path("/proc/crypto").read_text()
        )
    except OSError as e:
        log.debug("detect_kernel_info: cannot read /proc/crypto: %s", e)
        info["proc_crypto_pqc"] = []
    note = _platform.host_fs_unavailable_note(
        "Kernel info detection",
        "/etc/redhat-release and /proc/crypto",
    )
    if note:
        info.update(note)
    return info
