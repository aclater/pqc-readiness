#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Convert CustomResourceDefinition YAML files into kubeconform JSON schemas.

Used by CI to validate the ACM and Compliance Operator samples under
deploy/openshift-summary (#157) against schemas from pinned upstream CRDs.
Writes <out>/<kind>_<version>.json (lowercase kind), for kubeconform's
`-schema-location '<out>/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json'`.
Objects that don't preserve unknown fields get additionalProperties: false,
so `kubeconform -strict` rejects misspelt fields.

Usage: crd_to_jsonschema.py OUT_DIR CRD.yaml [CRD.yaml ...]   (needs PyYAML)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import yaml


def strictify(node: Any) -> None:
    if isinstance(node, dict):
        if (
            node.get("type") == "object"
            and "properties" in node
            and "additionalProperties" not in node
            and not node.get("x-kubernetes-preserve-unknown-fields")
        ):
            node["additionalProperties"] = False
        for v in node.values():
            strictify(v)
    elif isinstance(node, list):
        for v in node:
            strictify(v)


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2
    out = Path(argv[1])
    out.mkdir(parents=True, exist_ok=True)
    written = 0
    for path in argv[2:]:
        for doc in yaml.safe_load_all(Path(path).read_text()):
            if not doc or doc.get("kind") != "CustomResourceDefinition":
                continue
            kind = doc["spec"]["names"]["kind"].lower()
            for version in doc["spec"]["versions"]:
                schema = version["schema"]["openAPIV3Schema"]
                strictify(schema)
                (out / f"{kind}_{version['name']}.json").write_text(json.dumps(schema))
                written += 1
    if not written:
        print("crd_to_jsonschema: no CRD versions found", file=sys.stderr)
        return 1
    print(f"crd_to_jsonschema: wrote {written} schema(s) to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
