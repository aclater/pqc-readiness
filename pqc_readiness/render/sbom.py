# SPDX-License-Identifier: Apache-2.0
"""--sbom: a plain CycloneDX package SBOM, no cryptographic assets (#157).

Graph and SBOM tools that understand ordinary package components but not
CycloneDX cryptographic assets (which some flatten into generic packages)
get one component per installed OS package, identified by a purl from
https://github.com/package-url/purl-spec (rpm, deb, apk, alpm types, with
the os-release ID as the vendor namespace).  Use --cbom for crypto assets.

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
import uuid
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

from .. import _platform
from .. import registry as _registry
from .. import report as _report
from ..detect import packages as _packages

SBOM_SPEC_VERSION = "1.6"

# os-release family -> purl type.
_PURL_TYPE = {
    "rhel": "rpm",
    "suse": "rpm",
    "debian": "deb",
    "alpine": "apk",
    "arch": "alpm",
}


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
        return [], f"no package source for family={family}"
    argv, parser = plan
    rc, out = _platform._run(argv, timeout=30)
    if rc != 0:
        return [], f"{argv[0]} failed (rc={rc})"
    return list(parser(out)), None


def package_purl(pkg: dict[str, Any], os_release: dict[str, Any]) -> str | None:
    """purl for one OS package, or None when the family has no purl type
    or the os-release ID (the vendor namespace) is unknown."""
    ptype = _PURL_TYPE.get(str(os_release.get("family")))
    vendor = os_release.get("id")
    name, version = pkg.get("name"), pkg.get("version")
    if not ptype or not vendor or not name or not version:
        return None
    full = str(version)
    if pkg.get("release"):
        full += f"-{pkg['release']}"
    quals: list[tuple[str, str]] = []
    if pkg.get("arch"):
        quals.append(("arch", str(pkg["arch"])))
    if pkg.get("epoch") not in (None, "", 0, "0"):
        quals.append(("epoch", str(pkg["epoch"])))
    distro = f"{vendor}-{os_release.get('version_id') or ''}".rstrip("-")
    quals.append(("distro", distro))
    qs = "&".join(f"{k}={_q(v)}" for k, v in sorted(quals))
    return f"pkg:{ptype}/{_q(str(vendor).lower())}/{_q(str(name))}@{_q(full)}?{qs}"


def build_sbom(r: _report.Report) -> dict[str, Any]:
    osr = r.os_release or {}
    pkgs, reason = installed_packages(osr)
    components: dict[str, dict[str, Any]] = {}
    for pkg in pkgs:
        # rpm lists trusted signing keys as gpg-pubkey pseudo-packages;
        # they aren't software (--scan-signing-keys covers them).
        if pkg.get("name") == "gpg-pubkey":
            continue
        purl = package_purl(pkg, osr)
        if purl is None or purl in components:
            continue
        version = str(pkg["version"]) + (
            f"-{pkg['release']}" if pkg.get("release") else ""
        )
        components[purl] = {
            "type": "library",
            "bom-ref": purl,
            "name": str(pkg["name"]),
            "version": version,
            "purl": purl,
        }
    # Same bom-ref form as the CBOM's host component, so the two
    # documents join per host.
    host_ref = f"host/{r.hostname or 'unknown'}"
    os_component: dict[str, Any] = {
        "type": "operating-system",
        "bom-ref": f"os:{osr.get('id', 'unknown')}",
        "name": str(osr.get("id") or r.os or "unknown"),
    }
    if osr.get("version_id"):
        os_component["version"] = str(osr["version_id"])
    if osr.get("pretty_name"):
        os_component["description"] = str(osr["pretty_name"])
    props = [
        {"name": "pqc-readiness:sbom:package-count", "value": str(len(components))},
    ]
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
