# SPDX-License-Identifier: Apache-2.0
"""--sbom: a plain CycloneDX package SBOM, no cryptographic assets (#157).

Graph and SBOM tools that understand ordinary package components but not
CycloneDX cryptographic assets (which some flatten into generic packages)
get one component per installed OS package, identified by a purl from
https://github.com/package-url/purl-spec (rpm, deb, apk, alpm types, with
the os-release ID as the vendor namespace).  Use --cbom for crypto assets.

Families without a package tool (OpenWrt, Yocto, unknown IDs) are read
from whichever database the host or tree has, as --scan-packages does
(#217, #227).  purl-spec has no opkg type, so opkg packages get
`pkg:generic/<vendor>/<name>@<version>`.  Packages of a Yocto image get the
spec's `yocto` type, which identifies the recipe (BPN@PV): the recipe comes
from the rpm SOURCERPM tag, and binary packages built from one recipe share
its purl (their bom-refs add the package name).  A Yocto image is
recognised by /etc/buildinfo (image-buildinfo class) or os-release ID=poky.

The package list comes from the same readers as --scan-packages (the rpm
database read in-process, dpkg / apk / pacman databases under a prefix,
otherwise the family's query tool), so --host-mount and --root are
honoured.  It is read here rather than kept in the report because only
this output needs every package; the report keeps the crypto-relevant
subset.

CycloneDX 1.6 is emitted for compatibility with SBOM consumers that
predate 1.7; nothing here uses 1.7-only fields.
"""

from __future__ import annotations

import argparse
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

from .. import _platform
from .. import registry as _registry
from .. import report as _report
from ..detect import packages as _packages

SBOM_SPEC_VERSION = "1.6"

# os-release family -> package database kind (the kinds probe_package_db
# reports).
_DB_BY_FAMILY = {
    "rhel": "rpm",
    "suse": "rpm",
    "debian": "debian",
    "alpine": "alpine",
    "arch": "arch",
}

# Package database kind -> purl type.  opkg has none (see the module
# docstring).
_PURL_TYPE_BY_DB = {
    "rpm": "rpm",
    "debian": "deb",
    "alpine": "apk",
    "arch": "alpm",
}

# Distribution IDs built with the Yocto Project reference distro.
_YOCTO_IDS = ("poky",)

_SRPM_RE = re.compile(r"^(?P<name>.+)-(?P<version>[^-]+)-(?P<release>[^-]+)\.src\.rpm$")


def _q(value: str) -> str:
    return quote(value, safe=".+-_~")


def installed_packages(
    os_release: dict[str, Any],
) -> tuple[list[dict[str, Any]], str | None]:
    """(packages, reason-if-unavailable).  Each package is a dict with
    name and version, plus release / epoch / arch where the source has
    them (the rpm readers do)."""
    family = str(os_release.get("family", "unknown"))
    if family in ("rhel", "suse"):
        inv = _packages.query_rpm_packages()
        if not inv.get("available"):
            return [], str(inv.get("reason", "rpm database unavailable"))
        return list(inv.get("packages") or []), None
    if _platform.HOST_PREFIX and family in _packages._PREFIXED_PACKAGE_DBS:
        try:
            pkgs, _ = _packages.read_prefixed_package_db(family)
        except OSError as e:
            return [], f"package database unreadable under the prefix: {e}"
        return list(pkgs), None
    plan = _packages.PACKAGE_QUERY_BY_FAMILY.get(family)
    if plan is None:
        return _probed_packages()
    argv, parser = plan
    rc, out = _platform._run(argv, timeout=30)
    if rc != 0:
        return [], f"{argv[0]} failed (rc={rc})"
    return list(parser(out)), None


def _probed_packages() -> tuple[list[dict[str, Any]], str | None]:
    """Packages from whichever database the host or tree has, each tagged
    with the database kind (`db`) so package_purl can pick the purl type."""
    found = _packages.probe_package_db_cached()
    if found is None:
        return [], (
            "no package database found "
            "(looked for rpm, dpkg, apk, opkg and pacman databases)"
        )
    kind = str(found["kind"])
    pkgs: list[dict[str, Any]] = list(found["packages"])
    if kind == "rpm":
        # The probe keeps name and version only; the purl wants release,
        # arch, epoch and SOURCERPM.  Same cached inventory, no second read.
        inv = _packages.query_rpm_packages()
        if inv.get("available"):
            pkgs = list(inv.get("packages") or [])
    return [{**p, "db": kind} for p in pkgs], None


def read_buildinfo() -> dict[str, str]:
    """DISTRO and DISTRO_VERSION from a Yocto image's /etc/buildinfo
    (written by the image-buildinfo class), under HOST_PREFIX.  Empty when
    the file is absent or unreadable."""
    try:
        rel = _packages.resolve_under_prefix("/etc/buildinfo", _platform.HOST_PREFIX)
        with open(
            _platform.HOST_PREFIX + rel, encoding="utf-8", errors="replace"
        ) as fh:
            text = fh.read(64 * 1024)
    except (OSError, _packages.RpmdbError):
        return {}
    out: dict[str, str] = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        key = key.strip()
        if sep and key in ("DISTRO", "DISTRO_VERSION") and value.strip():
            out[key] = value.strip()
    return out


def _os_id(os_release: dict[str, Any]) -> str | None:
    """The os-release ID, or None when the report has only its
    "unknown" placeholder (no os-release on the host or tree)."""
    value = os_release.get("id")
    return str(value) if value and value != "unknown" else None


def _is_yocto(os_release: dict[str, Any], buildinfo: dict[str, str]) -> bool:
    return bool(buildinfo.get("DISTRO")) or _os_id(os_release) in _YOCTO_IDS


def _yocto_purl(pkg: dict[str, Any]) -> str | None:
    """pkg:yocto/<recipe>@<PV> from the SOURCERPM tag.  The layer (the
    optional namespace) isn't recorded in the image, so it's left out."""
    m = _SRPM_RE.match(str(pkg.get("sourcerpm") or ""))
    if not m:
        return None
    return f"pkg:yocto/{_q(m['name'])}@{_q(m['version'])}"


def package_purl(
    pkg: dict[str, Any],
    os_release: dict[str, Any],
    buildinfo: dict[str, str] | None = None,
) -> str | None:
    """purl for one OS package, or None when its database kind has no
    purl type or the vendor namespace is unknown.  The kind is the
    package's `db` (probed databases) or follows from the family."""
    buildinfo = buildinfo or {}
    db = pkg.get("db") or _DB_BY_FAMILY.get(str(os_release.get("family")))
    name, version = pkg.get("name"), pkg.get("version")
    if not db or not name or not version:
        return None
    if db == "rpm" and _is_yocto(os_release, buildinfo):
        purl = _yocto_purl(pkg)
        if purl:
            return purl
    vendor = _os_id(os_release) or buildinfo.get("DISTRO")
    if db == "opkg":
        ns = f"{_q(str(vendor).lower())}/" if vendor else ""
        return f"pkg:generic/{ns}{_q(str(name))}@{_q(str(version))}"
    ptype = _PURL_TYPE_BY_DB.get(str(db))
    if not ptype or not vendor:
        return None
    if ptype == "apk":
        # The apk type's names are case-insensitive and lowercased.
        name = str(name).lower()
    full = str(version)
    if pkg.get("release"):
        full += f"-{pkg['release']}"
    quals: list[tuple[str, str]] = []
    if pkg.get("arch"):
        quals.append(("arch", str(pkg["arch"])))
    if pkg.get("epoch") not in (None, "", 0, "0"):
        quals.append(("epoch", str(pkg["epoch"])))
    distro_version = os_release.get("version_id") or (
        buildinfo.get("DISTRO_VERSION") if not _os_id(os_release) else None
    )
    distro = f"{vendor}-{distro_version or ''}".rstrip("-")
    quals.append(("distro", distro))
    qs = "&".join(f"{k}={_q(v)}" for k, v in sorted(quals))
    return f"pkg:{ptype}/{_q(str(vendor).lower())}/{_q(str(name))}@{_q(full)}?{qs}"


def build_sbom(r: _report.Report) -> dict[str, Any]:
    osr = r.os_release or {}
    pkgs, reason = installed_packages(osr)
    buildinfo = read_buildinfo()
    components: dict[str, dict[str, Any]] = {}
    no_purl = 0
    for pkg in pkgs:
        # rpm lists trusted signing keys as gpg-pubkey pseudo-packages;
        # they aren't software (--scan-signing-keys covers them).
        if pkg.get("name") == "gpg-pubkey":
            continue
        purl = package_purl(pkg, osr, buildinfo)
        if purl is None:
            no_purl += 1
            continue
        # A recipe purl is shared by the binary packages built from it.
        ref = f"{purl}#{pkg['name']}" if purl.startswith("pkg:yocto/") else purl
        if ref in components:
            continue
        version = str(pkg["version"]) + (
            f"-{pkg['release']}" if pkg.get("release") else ""
        )
        components[ref] = {
            "type": "library",
            "bom-ref": ref,
            "name": str(pkg["name"]),
            "version": version,
            "purl": purl,
        }
    # Same bom-ref form as the CBOM's host component, so the two
    # documents join per host.
    host_ref = f"host/{r.hostname or 'unknown'}"
    # Yocto images often ship no os-release; /etc/buildinfo names the distro.
    os_id = _os_id(osr) or buildinfo.get("DISTRO")
    os_version = osr.get("version_id") or (
        buildinfo.get("DISTRO_VERSION") if not _os_id(osr) else None
    )
    os_component: dict[str, Any] = {
        "type": "operating-system",
        "bom-ref": f"os:{os_id or 'unknown'}",
        "name": str(os_id or r.os or "unknown"),
    }
    if os_version:
        os_component["version"] = str(os_version)
    # Without os-release, pretty_name is a kernel fallback, not the OS.
    if osr.get("pretty_name") and _os_id(osr):
        os_component["description"] = str(osr["pretty_name"])
    props = [
        {"name": "pqc-readiness:sbom:package-count", "value": str(len(components))},
    ]
    if no_purl:
        props.append(
            {"name": "pqc-readiness:sbom:packages-without-purl", "value": str(no_purl)}
        )
    if reason:
        props.append({"name": "pqc-readiness:sbom:unavailable-reason", "value": reason})
    mode = (r.scan_mode or {}).get("mode") if r.scan_mode else None
    if mode:
        props.append({"name": "pqc-readiness:scan-mode", "value": str(mode)})
    ordered = [components[k] for k in sorted(components)]
    return {
        "bomFormat": "CycloneDX",
        "specVersion": SBOM_SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": r.generated_at
            or datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "pqc-readiness",
                        "version": _report.SCRIPT_VERSION,
                    }
                ]
            },
            "component": {
                "type": "device",
                "bom-ref": host_ref,
                "name": r.hostname or "unknown",
            },
            "properties": props,
        },
        "components": [os_component, *ordered],
        "dependencies": [
            {
                "ref": host_ref,
                "dependsOn": [
                    os_component["bom-ref"],
                    *(c["bom-ref"] for c in ordered),
                ],
            }
        ],
    }


def render_sbom(r: _report.Report) -> str:
    return json.dumps(build_sbom(r), indent=2)


@_registry.register_arguments(17)
def add_arguments(ap: argparse.ArgumentParser) -> None:
    """--sbom."""
    ap.add_argument(
        "--sbom",
        action="store_true",
        help=(
            "emit a plain CycloneDX 1.6 SBOM of installed OS packages (purls, "
            "no crypto assets) for SBOM / graph tools; use --cbom for crypto"
        ),
    )


_registry.register_output(_registry.OutputFormat("sbom", 25, lambda r: render_sbom(r)))
