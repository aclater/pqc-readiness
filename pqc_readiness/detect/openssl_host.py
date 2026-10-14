# SPDX-License-Identifier: Apache-2.0
"""Where the OpenSSL facts about a host come from when the `openssl` CLI
can't be trusted to describe it.

The CLI on PATH describes the host only on a bare-metal or VM scan.  Under
--root (#152) and --host-mount (#228) it is the scanning machine's or the
scanner image's own binary, and on minimal hosts (OpenWrt, Buildroot,
#225) there is no CLI at all.  In those cases the host's OpenSSL version
comes from its package database, else from the version string its
libcrypto embeds (#217).  Files are read, never run.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from ..detect import packages as _packages
from ..detect import protocols_libraries as _libraries

log = logging.getLogger("pqc_readiness")

# OpenSSL library packages per family, in preference order.
_OPENSSL_PACKAGES: dict[str, tuple[str, ...]] = {
    "rhel": ("openssl-libs", "openssl"),
    "suse": ("libopenssl3", "openssl-3", "openssl"),
    "debian": ("libssl3t64", "libssl3", "openssl"),
    "alpine": ("libssl3", "openssl"),
    "arch": ("openssl",),
}

# OpenSSL library package names in trees whose family has no registered
# tool, matched against whichever database the tree has (#217): Yocto
# (libcrypto3 / libssl3), OpenWrt (libopenssl3), and generic names.
_OPENSSL_PROBED_PACKAGES: tuple[str, ...] = (
    "libcrypto3",
    "libopenssl3",
    "libssl3",
    "openssl-libs",
    "libopenssl1.1",
    "openssl",
)

# libcrypto files, newest ABI first, for trees with no package database
# (Buildroot, minimal Yocto images; #217).
_LIBCRYPTO_FILES: tuple[str, ...] = (
    "libcrypto.so.3*",
    "libcrypto.so.1.1*",
    "libcrypto.so",
)
_OPENSSL_EMBEDDED_VERSION = re.compile(rb"OpenSSL (\d+\.\d+\.\d+[a-z]?) ")
# Forks that embed an "OpenSSL x.y.z" compatibility string.
_NOT_OPENSSL = (b"AWS-LC", b"BoringSSL", b"LibreSSL")


def version_tuple(version: str) -> list[int] | None:
    m = re.match(r"(?:\d+:)?(\d+)\.(\d+)(?:\.(\d+))?", version)
    if not m:
        return None
    return [int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)]


def openssl_package(family: str) -> dict[str, str] | None:
    """The host's or tree's OpenSSL library package (name, version), from
    its own package database."""
    names = _OPENSSL_PACKAGES.get(family)
    if not names:
        found = _packages.probe_package_db_cached()
        if not found:
            return None
        by_name: dict[str, dict[str, str]] = {p["name"]: p for p in found["packages"]}
        for name in _OPENSSL_PROBED_PACKAGES:
            if name in by_name:
                return by_name[name]
        return None
    pkgs: list[dict[str, str]] = []
    if family in ("rhel", "suse"):
        # The full inventory, not a named lookup: it is read in-process for
        # every rpm database format, whereas named lookups on Berkeley DB /
        # ndb run the scanner's `rpm -q` (and on sqlite trust the Name
        # index).  It is cached, so the NSS lookup reuses it.
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
            log.debug("openssl: no %s package database: %s", family, e)
            return None
        pkgs = [p for p in all_pkgs if p["name"] in names]
    for name in names:
        for p in pkgs:
            if p["name"] == name:
                return p
    return None


def openssl_library() -> dict[str, Any] | None:
    """The tree's libcrypto file and the version it embeds ("OpenSSL
    3.5.7 ..."), for trees with no package database.  Read, never run.
    Returns {path, version}; version is None when the file carries no
    version string.  None when the tree has no OpenSSL libcrypto."""
    for f in _libraries._find_files(_LIBCRYPTO_FILES):
        blob = _libraries._read_library(f)
        if blob is None or any(mark in blob for mark in _NOT_OPENSSL):
            continue
        m = _OPENSSL_EMBEDDED_VERSION.search(blob)
        return {
            "path": _libraries._unhost(f),
            "version": m.group(1).decode() if m else None,
        }
    return None


def openssl_evidence(os_release: dict[str, Any]) -> dict[str, Any]:
    """The host's OpenSSL from files: the library package, else the
    libcrypto file.  Returns {package, library, installed, version,
    version_source, version_tuple}; `version_source` is "package",
    "library" or None, and `installed` is False when neither exists."""
    pkg = openssl_package(os_release.get("family", "unknown"))
    lib = None if pkg else openssl_library()
    version: str | None
    if pkg:
        version, source = pkg["version"], "package"
    elif lib and lib["version"]:
        version, source = lib["version"], "library"
    else:
        version, source = None, None
    return {
        "package": pkg,
        "library": lib,
        "installed": bool(pkg or lib),
        "version": version,
        "version_source": source,
        "version_tuple": version_tuple(version) if version else None,
    }
