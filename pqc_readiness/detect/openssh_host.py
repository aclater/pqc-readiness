# SPDX-License-Identifier: Apache-2.0
"""Where the OpenSSH facts about a host come from when the `ssh` CLI
can't be trusted to describe it.

`ssh -V` and `ssh -Q kex` describe the host only on a bare-metal or VM
scan.  Under --host-mount (#256) they run the scanner image's own client,
under --root the scanning machine's, and some hosts have sshd but no
client.  In those cases the kex names and version come from the host's
binaries (`openssh_build`, #247): the version string there is exactly what
`ssh -V` prints.  The host's OpenSSH package is the fallback version and
is kept for SBOM joins.  Files are read, never run.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from ..detect import openssh_build as _openssh_build
from ..detect import packages as _packages

log = logging.getLogger("pqc_readiness")

# OpenSSH packages per family, in preference order: the server first,
# since sshd is what the deployment-gap verdict is about, then the client
# and the common package (one build, one version).
_OPENSSH_PACKAGES: dict[str, tuple[str, ...]] = {
    "rhel": ("openssh-server", "openssh-clients", "openssh"),
    "suse": ("openssh-server", "openssh-clients", "openssh-common", "openssh"),
    "debian": ("openssh-server", "openssh-client"),
    "alpine": ("openssh-server", "openssh-client", "openssh"),
    "arch": ("openssh",),
}

# Names in trees whose family has no registered package tool (#217):
# OpenWrt (openssh-server / openssh-client), Yocto (openssh-sshd /
# openssh-ssh / openssh).
_OPENSSH_PROBED_PACKAGES: tuple[str, ...] = (
    "openssh-server",
    "openssh-sshd",
    "openssh-client",
    "openssh-ssh",
    "openssh",
)


def normalize_version(version: str) -> str:
    """A package version in `ssh -V`'s form: "1:9.6p1-3ubuntu13.5" (Debian)
    -> "9.6p1", "9.9_p1-r2" (Alpine) -> "9.9p1", "10.0p2" unchanged."""
    v = re.sub(r"^\d+:", "", version.strip())
    v = v.replace("_p", "p")
    m = re.match(r"\d+\.\d+(?:p\d+)?", v)
    return m.group(0) if m else v


def openssh_package(family: str) -> dict[str, str] | None:
    """The host's or tree's OpenSSH package (name, version), from its own
    package database."""
    names = _OPENSSH_PACKAGES.get(family)
    if not names:
        found = _packages.probe_package_db_cached()
        if not found:
            return None
        by_name: dict[str, dict[str, str]] = {p["name"]: p for p in found["packages"]}
        for name in _OPENSSH_PROBED_PACKAGES:
            if name in by_name:
                return {"name": name, "version": by_name[name]["version"]}
        return None
    pkgs: list[dict[str, str]] = []
    if family in ("rhel", "suse"):
        # The cached in-process inventory, as openssl_host does: never the
        # scanner's own `rpm -q`.
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
            log.debug("openssh: no %s package database: %s", family, e)
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


def openssh_evidence(os_release: dict[str, Any]) -> dict[str, Any]:
    """The host's OpenSSH from files: version from the binary, else the
    package; kex names from the binary.  Returns {package, binary,
    installed, version, version_source, kex}; `binary` is the
    `openssh_build_kex()` result, `version_source` is "binary", "package"
    or None, `kex` is None when no binary is readable, and `installed` is
    False when neither exists.

    The binary wins because the package version can differ from what the
    build reports: Debian 13's openssh-server 1:10.0p1-7+deb13u4 prints
    OpenSSH_10.0p2.  The package (raw version) is kept for SBOM joins."""
    pkg = openssh_package(os_release.get("family", "unknown"))
    binary = _openssh_build.openssh_build_kex()
    version: str | None
    if binary and binary.get("version"):
        version, source = binary["version"], "binary"
    elif pkg:
        version, source = normalize_version(pkg["version"]), "package"
    else:
        version, source = None, None
    return {
        "package": pkg,
        "binary": binary,
        "installed": bool(pkg or binary),
        "version": version,
        "version_source": source,
        "kex": binary["kex"] if binary else None,
    }
