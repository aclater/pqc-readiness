# SPDX-License-Identifier: Apache-2.0
"""Where the IPsec facts about a host come from when `swanctl` / `ipsec`
can't be trusted to describe it.

`swanctl --list-algs` and `ipsec --version` describe the host only on a
bare-metal or VM scan.  Under --host-mount (#265) they are the scanner
image's own tools (usually absent, so a node running strongSwan or
Libreswan looked like it had no IPsec stack), under --root they would be
the scanning machine's, and some hosts have the daemon but not the CLI.
In those cases the implementation and version come from the host's
package, else from the strings its binaries embed, and PQC capability is
derived from files.  Files are read, never run.

Capability rules, from booted hosts compared with their own tools
(2026-10-15):

* strongSwan offers ML-KEM from 6.0, through the `ml` plugin or through
  the `openssl` plugin on OpenSSL 3.5 or newer.  Fedora 44 (6.0.7) and
  Ubuntu 26.04 (6.0.4, no `ml` plugin) both list ML_KEM_512/768/1024
  from `[openssl]`; Debian 12 (5.9.8, OpenSSL 3.0) lists none.
* Libreswan: version >= 5.4 (protocols.LIBRESWAN_PQC_MIN_VERSION).  Its
  `pluto` binary embeds "Libreswan <version>", exactly what
  `ipsec --version` prints (Rocky 9: 4.15; Rocky 10, Fedora 44: 5.3.2).
"""

from __future__ import annotations

import logging
import re
from typing import Any

from .. import _platform
from ..detect import config_read as _config_read
from ..detect import openssl_host as _openssl_host
from ..detect import packages as _packages

log = logging.getLogger("pqc_readiness")

# Package names per family, in preference order.  Debian splits
# strongSwan; libstrongswan carries the version every part shares.
_STRONGSWAN_PACKAGES: dict[str, tuple[str, ...]] = {
    "rhel": ("strongswan",),
    "suse": ("strongswan", "strongswan-ipsec"),
    "debian": (
        "libstrongswan",
        "strongswan-swanctl",
        "charon-systemd",
        "strongswan-charon",
    ),
    "alpine": ("strongswan",),
    "arch": ("strongswan",),
}
_LIBRESWAN_PACKAGES: dict[str, tuple[str, ...]] = {
    "rhel": ("libreswan",),
    "suse": ("libreswan",),
    "debian": ("libreswan",),
    "alpine": ("libreswan",),
    "arch": ("libreswan",),
}
# Trees with no registered package tool (#217): OpenWrt and Yocto names.
_PROBED_STRONGSWAN = (
    "strongswan",
    "strongswan-full",
    "strongswan-minimal",
    "libstrongswan",
)
_PROBED_LIBRESWAN = ("libreswan",)

# Daemon binaries first: they embed the full version string.
_STRONGSWAN_BINARIES: tuple[str, ...] = (
    "/usr/libexec/strongswan/charon",  # EL, Fedora
    "/usr/lib/ipsec/charon",  # Debian, Ubuntu
    "/usr/libexec/ipsec/charon",  # openSUSE, Alpine
    "/usr/sbin/charon-systemd",
    "/usr/sbin/swanctl",
)
_LIBRESWAN_BINARIES: tuple[str, ...] = (
    "/usr/libexec/ipsec/pluto",
    "/usr/lib/ipsec/pluto",
)
_PLUGIN_DIRS: tuple[str, ...] = (
    "/usr/lib64/strongswan/plugins",
    "/usr/lib/strongswan/plugins",
    "/usr/lib/ipsec/plugins",
    "/usr/lib64/ipsec/plugins",
    "/usr/lib/x86_64-linux-gnu/ipsec/plugins",
    "/usr/lib/aarch64-linux-gnu/ipsec/plugins",
)

# pluto/charon are about 2 MiB; the cap only bounds a corrupt or hostile
# file.
MAX_BINARY_BYTES = 32 * 1024 * 1024
# The literal is NUL-terminated; pluto also carries vendor-ID strings such
# as "Libreswan 3.0 - 3.5" and "Libreswan %s" that must not match.
_LIBRESWAN_EMBEDDED = re.compile(
    rb"(?<=\x00)Libreswan (\d+\.\d+(?:\.\d+)?(?:(?:dr|rc)\d+)?)(?=\x00)"
)
_STRONGSWAN_EMBEDDED = re.compile(
    rb"strongSwan (\d+\.\d+\.\d+(?:(?:dr|rc)\d+)?)(?![\d.])"
)
# swanctl and charon-systemd carry the version only as a bare literal next
# to "strongSwan %s" format strings.
_BARE_VERSION = re.compile(rb"(?<=\x00)(\d+\.\d+\.\d+)(?=\x00)")
STRONGSWAN_PQC_MIN_VERSION = (6, 0)
OPENSSL_PQC_MIN_VERSION = [3, 5, 0]


def _version_tuple(version: str | None) -> tuple[int, ...] | None:
    m = re.match(r"v?(\d+)\.(\d+)(?:\.(\d+))?", version or "")
    if m is None:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))


def normalize_version(version: str) -> str:
    """A package version in the tools' form: "5.3.2-1.el10_2" -> "5.3.2",
    "6.0.4-1ubuntu3.2" -> "6.0.4", "1:4.10-2+deb12u1" -> "4.10"."""
    v = re.sub(r"^\d+:", "", version.strip())
    m = re.match(r"\d+\.\d+(?:\.\d+)?(?:(?:dr|rc)\d+)?", v)
    return m.group(0) if m else v


def _package(
    names_by_family: dict[str, tuple[str, ...]], probed: tuple[str, ...], family: str
) -> dict[str, str] | None:
    names = names_by_family.get(family)
    if not names:
        found = _packages.probe_package_db_cached()
        if not found:
            return None
        by_name = {p["name"]: p for p in found["packages"]}
        for name in probed:
            if name in by_name:
                return {"name": name, "version": by_name[name]["version"]}
        return None
    pkgs: list[dict[str, str]] = []
    if family in ("rhel", "suse"):
        # The cached in-process inventory, never the scanner's own `rpm -q`.
        inv = _packages.query_rpm_packages()
        if inv.get("available"):
            pkgs = [
                {"name": p["name"], "version": p["version"]}
                for p in inv["packages"]
                if p["name"] in names
            ]
    else:
        try:
            all_pkgs, _ = _packages.read_prefixed_package_db(family)
        except OSError as e:
            log.debug("ipsec: no %s package database: %s", family, e)
            return None
        pkgs = [
            {"name": p["name"], "version": p["version"]}
            for p in all_pkgs
            if p["name"] in names
        ]
    for name in names:
        for p in pkgs:
            if p["name"] == name:
                return p
    return None


def _read_binary(path: str) -> bytes | None:
    try:
        target = _config_read.host_file(path)
    except _config_read.ConfigUnreadable as e:
        log.debug("ipsec: %s", e)
        return None
    try:
        with open(target, "rb") as fh:
            return fh.read(MAX_BINARY_BYTES)
    except OSError as e:
        log.debug("ipsec: cannot read %s (-> %s): %s", path, target, e)
        return None


def _binary_version(
    paths: tuple[str, ...], embedded: re.Pattern[bytes], allow_bare: bool
) -> tuple[str | None, list[str]]:
    """(version, binaries found).  The first binary that names its version
    wins; a bare "x.y.z" literal is accepted only when it is the binary's
    only one (strongSwan's swanctl / charon-systemd)."""
    found: list[str] = []
    version: str | None = None
    for path in paths:
        data = _read_binary(path)
        if data is None:
            continue
        found.append(path)
        if version:
            continue
        hits = {m.group(1).decode("ascii") for m in embedded.finditer(b"\x00" + data)}
        if hits:
            version = max(hits, key=lambda v: _version_tuple(v) or ())
            continue
        if allow_bare:
            bare = {
                m.group(1).decode("ascii")
                for m in _BARE_VERSION.finditer(b"\x00" + data + b"\x00")
            }
            if len(bare) == 1:
                version = bare.pop()
    return version, found


def strongswan_plugins() -> list[str]:
    """Names of the host's strongSwan plugins that matter for ML-KEM."""
    out: set[str] = set()
    for d in _PLUGIN_DIRS:
        for name in ("libstrongswan-ml.so", "libstrongswan-openssl.so"):
            try:
                target = _config_read.host_file(f"{d}/{name}")
            except _config_read.ConfigUnreadable:
                continue
            if _platform.safe_exists(target):
                out.add(name[len("libstrongswan-") : -len(".so")])
    return sorted(out)


def _strongswan_evidence(os_release: dict[str, Any]) -> dict[str, Any] | None:
    family = os_release.get("family", "unknown")
    pkg = _package(_STRONGSWAN_PACKAGES, _PROBED_STRONGSWAN, family)
    bin_version, binaries = _binary_version(
        _STRONGSWAN_BINARIES, _STRONGSWAN_EMBEDDED, allow_bare=True
    )
    if not pkg and not binaries:
        return None
    if pkg:
        version: str | None = normalize_version(pkg["version"])
        source: str | None = "package"
    elif bin_version:
        version, source = bin_version, "binary"
    else:
        version, source = None, None
    plugins = strongswan_plugins()
    ossl = _openssl_host.openssl_evidence(os_release)
    ossl_ok = bool(
        ossl["version_tuple"] and ossl["version_tuple"] >= OPENSSL_PQC_MIN_VERSION
    )
    vt = _version_tuple(version)
    if vt is None:
        pqc: bool | None = None
        evidence = "strongSwan version unknown"
    elif vt[:2] < STRONGSWAN_PQC_MIN_VERSION:
        pqc, evidence = False, f"strongSwan {version} predates ML-KEM (6.0)"
    elif "ml" in plugins:
        pqc, evidence = True, f"strongSwan {version} with the ml plugin"
    elif "openssl" in plugins and ossl_ok:
        pqc, evidence = (
            True,
            f"strongSwan {version} openssl plugin on OpenSSL {ossl['version']}",
        )
    elif "openssl" in plugins:
        pqc = False
        evidence = f"strongSwan {version} openssl plugin, but OpenSSL {ossl['version'] or 'unknown'} has no ML-KEM (3.5+)"
    else:
        pqc, evidence = False, f"strongSwan {version} without the ml or openssl plugin"
    return {
        "implementation": "strongswan",
        "package": pkg,
        "binaries": binaries,
        "version": version,
        "version_source": source,
        "plugins": plugins,
        "pqc": pqc,
        "evidence": evidence,
    }


def _libreswan_evidence(os_release: dict[str, Any]) -> dict[str, Any] | None:
    # Imported here: protocols imports this module.
    from ..detect import protocols as _protocols

    family = os_release.get("family", "unknown")
    pkg = _package(_LIBRESWAN_PACKAGES, _PROBED_LIBRESWAN, family)
    bin_version, binaries = _binary_version(
        _LIBRESWAN_BINARIES, _LIBRESWAN_EMBEDDED, allow_bare=False
    )
    if not pkg and not binaries:
        return None
    # The binary wins: it is what `ipsec --version` prints.  The package
    # (raw version) is kept for SBOM joins.
    if bin_version:
        version: str | None = bin_version
        source: str | None = "binary"
    elif pkg:
        version, source = normalize_version(pkg["version"]), "package"
    else:
        version, source = None, None
    return {
        "implementation": "libreswan",
        "package": pkg,
        "binaries": binaries,
        "version": version,
        "version_source": source,
        "pqc": _protocols._libreswan_pqc(version) if version else None,
    }


def ipsec_evidence(os_release: dict[str, Any]) -> dict[str, Any] | None:
    """The host's IPsec stack from files, strongSwan first (as the live
    probe prefers swanctl).  None when neither is installed."""
    return _strongswan_evidence(os_release) or _libreswan_evidence(os_release)
