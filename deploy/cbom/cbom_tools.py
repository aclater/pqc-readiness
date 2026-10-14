#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Helpers for feeding pqc-readiness CBOMs into CBOM importers.

Standard library only.  See docs/integrations/posture-platforms.md.

Subcommands::

    name-host IN OUT NAME
        Give an offline (--root) CBOM a host identity.  Offline scans have
        no hostname, so every one is ``host/unknown``; rename it to
        ``host/NAME`` before importing several images side by side.

    repair-merge IN OUT
        Repair two defects in BOMs written by the CycloneDX CLI 0.33.1
        ``merge`` / ``convert`` commands: ``relatedCryptoMaterialProperties``
        gains ``"state": "null"`` and ``"size": 0`` (rejected by the 1.7
        schema), and a hierarchical merge prefixes bom-refs and ``dependsOn``
        entries with ``<name>@<version>:`` but not ``provides`` entries.

    join-certificates HOST_CBOM OTHER_CBOM
        List certificates present in both documents, matched on the
        SHA-256 fingerprint (e.g. a host CBOM and a network-side CBOM).

    join-packages HOST_CBOM SBOM
        Map each library component in a CBOM to the packages in an SBOM
        (e.g. ``--sbom``).  CBOM library purls carry the upstream version
        without release, arch or epoch, so the match is on
        type/namespace/name and upstream version.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterator
from typing import Any

Bom = dict[str, Any]


def _load(path: str) -> Bom:
    with open(path, encoding="utf-8") as fh:
        data: Bom = json.load(fh)
    return data


def _dump(bom: Bom, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(bom, fh, indent=2)
        fh.write("\n")


def walk(components: list[dict[str, Any]]) -> Iterator[dict[str, Any]]:
    """Every component, nested ones included."""
    for c in components:
        yield c
        yield from walk(c.get("components", []))


def name_host(bom: Bom, name: str) -> Bom:
    """Rename the document's host component to ``host/<name>``."""
    meta = bom["metadata"]["component"]
    old = meta["bom-ref"]
    new = "host/" + name
    meta["bom-ref"] = new
    meta["name"] = name
    for dep in bom.get("dependencies", []):
        if dep["ref"] == old:
            dep["ref"] = new
        if "dependsOn" in dep:
            dep["dependsOn"] = [new if r == old else r for r in dep["dependsOn"]]
    return bom


def repair_merge(bom: Bom) -> Bom:
    """Undo the CycloneDX CLI merge defects described in the module doc."""
    refs = set()
    for c in walk(bom.get("components", [])):
        refs.add(c.get("bom-ref"))
        rcm = c.get("cryptoProperties", {}).get("relatedCryptoMaterialProperties")
        if rcm:
            if rcm.get("state") in (None, "null"):
                rcm.pop("state", None)
            if rcm.get("size") == 0:
                rcm.pop("size", None)
    for dep in bom.get("dependencies", []):
        head = dep["ref"].split(":", 1)[0]
        if "@" in head and "provides" in dep:
            prefix = head + ":"
            dep["provides"] = [p if p in refs else prefix + p for p in dep["provides"]]
    return bom


def certificates(bom: Bom) -> dict[str, dict[str, Any]]:
    """SHA-256 fingerprint (lower-case hex) -> certificate component."""
    out = {}
    for c in walk(bom.get("components", [])):
        fp = (
            c.get("cryptoProperties", {})
            .get("certificateProperties", {})
            .get("fingerprint", {})
        )
        if fp.get("alg") == "SHA-256" and fp.get("content"):
            out[fp["content"].lower()] = c
    return out


def join_certificates(host: Bom, other: Bom) -> list[tuple[str, dict[str, Any]]]:
    mine, theirs = certificates(host), certificates(other)
    return [(fp, mine[fp]) for fp in sorted(mine.keys() & theirs.keys())]


def package_key(purl: str) -> tuple[str, str]:
    """(type/namespace/name, upstream version) of a purl."""
    head, _, version = purl.split("?", 1)[0].partition("@")
    return head, version.split("-", 1)[0]


def join_packages(cbom: Bom, sbom: Bom) -> list[tuple[str, list[str]]]:
    packages: dict[tuple[str, str], list[str]] = {}
    for c in sbom.get("components", []):
        if c.get("purl"):
            packages.setdefault(package_key(c["purl"]), []).append(c["purl"])
    return [
        (c["purl"], packages.get(package_key(c["purl"]), []))
        for c in walk(cbom.get("components", []))
        if c.get("type") == "library" and c.get("purl")
    ]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("name-host")
    p.add_argument("input")
    p.add_argument("output")
    p.add_argument("name")
    p = sub.add_parser("repair-merge")
    p.add_argument("input")
    p.add_argument("output")
    p = sub.add_parser("join-certificates")
    p.add_argument("host_cbom")
    p.add_argument("other_cbom")
    p = sub.add_parser("join-packages")
    p.add_argument("cbom")
    p.add_argument("sbom")
    args = ap.parse_args(argv)

    if args.cmd == "name-host":
        _dump(name_host(_load(args.input), args.name), args.output)
    elif args.cmd == "repair-merge":
        _dump(repair_merge(_load(args.input)), args.output)
    elif args.cmd == "join-certificates":
        other = _load(args.other_cbom)
        matches = join_certificates(_load(args.host_cbom), other)
        for fp, cert in matches:
            print(f"{fp}\t{cert.get('name', '')}")
        total = len(certificates(other))
        print(
            f"{len(matches)} of {total} certificates found on the host", file=sys.stderr
        )
    else:
        for purl, found in join_packages(_load(args.cbom), _load(args.sbom)):
            print(f"{purl}\t{' '.join(found) or 'no package match'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
