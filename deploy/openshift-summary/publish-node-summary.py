#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Publish a per-node pqc-readiness summary as a ConfigMap (#157).

Runs inside the opt-in "summary" overlay of the DaemonSet.  After each probe
iteration it scans the node, condenses the result into flat string keys
(what a policy engine can match on), and creates or replaces the ConfigMap
``pqc-readiness-node-<node>`` in the pod's namespace through the in-cluster
API.  ACM ConfigurationPolicy and Compliance Operator CEL rules then evaluate
those ConfigMaps instead of parsing full reports.

Stdlib only, like the scanner.  Environment:
  NODE_NAME            node name (downward API, spec.nodeName)       required
  POD_NAMESPACE        namespace to write into (downward API)        required
  PQC_READINESS_BIN    scanner launcher (default /usr/local/bin/pqc-readiness)
  PQC_HOST_MOUNT       host root inside the pod (default /host)
Exit status: 0 published, 1 scan or API failure (details on stderr).
"""

from __future__ import annotations

import json
import os
import re
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
from typing import Any, Callable

SA_DIR = "/var/run/secrets/kubernetes.io/serviceaccount"
SUMMARY_LABEL = "pqc-readiness/summary"
FAILURE_RULE = re.compile(r"^pqc-01[1-7]-")  # software that will fail at PQC (#193)
GAP_STATES = ("capable_not_configured", "configured_not_capable")


def configmap_name(node: str) -> str:
    """DNS-1123 subdomain for the node's ConfigMap (lowercase, [a-z0-9.-],
    at most 253 characters, alphanumeric at both ends)."""
    slug = re.sub(r"[^a-z0-9.-]+", "-", node.lower()).strip("-.")
    return ("pqc-readiness-node-" + (slug or "unknown"))[:253].rstrip("-.")


def build_summary(
    report: dict[str, Any], events: list[dict[str, Any]]
) -> dict[str, str]:
    """Flat, string-valued summary (ConfigMap data values must be strings)."""
    gap = report.get("pqc_deployment_gap") or {}
    protocols = gap.get("protocols") or {}
    gaps = list(gap.get("gaps") or [])
    by_rule: dict[str, int] = {}
    for e in events:
        if e.get("class_uid") != 2003:
            continue
        uid = ((e.get("finding_info") or {}).get("analytic") or {}).get("uid")
        if uid:
            by_rule[uid] = by_rule.get(uid, 0) + 1
    data = {
        "node": str(report.get("hostname") or ""),
        "generated_at": str(report.get("generated_at") or ""),
        "schema_version": str(report.get("schema_version") or ""),
        "verdict": str(report.get("verdict") or ""),
        "exit_code": str(report.get("exit_code", "")),
        "gap_count": str(len(gaps)),
        "gaps": "\n".join(gaps),
        "capable_not_configured": str(
            sum(1 for g in gaps if g.endswith(":capable_not_configured"))
        ),
        "failure_findings": str(
            sum(n for uid, n in by_rule.items() if FAILURE_RULE.match(uid))
        ),
        "findings_by_rule": json.dumps(dict(sorted(by_rule.items())), sort_keys=True),
    }
    for proto in ("tls", "ssh", "ipsec"):
        data[f"gap_{proto}"] = str(
            (protocols.get(proto) or {}).get("state") or "unknown"
        )
    return data


def configmap(name: str, namespace: str, data: dict[str, str]) -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": {
                "app.kubernetes.io/name": "pqc-readiness",
                SUMMARY_LABEL: "node",
            },
        },
        "data": data,
    }


Opener = Callable[[urllib.request.Request], Any]


def publish(obj: dict[str, Any], api: str, token: str, opener: Opener) -> str:
    """Replace the ConfigMap, creating it on 404.  Returns "replaced" or
    "created"; raises urllib.error.HTTPError on any other API error."""
    ns, name = obj["metadata"]["namespace"], obj["metadata"]["name"]
    body = json.dumps(obj).encode()
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    base = f"{api}/api/v1/namespaces/{ns}/configmaps"
    try:
        opener(
            urllib.request.Request(
                f"{base}/{name}", data=body, headers=headers, method="PUT"
            )
        )
        return "replaced"
    except urllib.error.HTTPError as e:
        if e.code != 404:
            raise
    opener(urllib.request.Request(base, data=body, headers=headers, method="POST"))
    return "created"


def _scan(binary: str, host_mount: str, fmt: str) -> str:
    # The scanner's exit status is its readiness verdict (0-3), not success;
    # only 5 (output write failure) or a crash (no output) is an error here.
    out = subprocess.run(
        [binary, "--host-mount", host_mount, fmt],
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    if not out.stdout.strip():
        raise RuntimeError(
            f"{binary} {fmt} produced no output (rc={out.returncode}): {out.stderr[-500:]}"
        )
    return out.stdout


def main() -> int:
    node, namespace = os.environ.get("NODE_NAME"), os.environ.get("POD_NAMESPACE")
    if not node or not namespace:
        print(
            "publish-node-summary: NODE_NAME and POD_NAMESPACE are required",
            file=sys.stderr,
        )
        return 1
    binary = os.environ.get("PQC_READINESS_BIN", "/usr/local/bin/pqc-readiness")
    host_mount = os.environ.get("PQC_HOST_MOUNT", "/host")
    try:
        report = json.loads(_scan(binary, host_mount, "--json"))
        events = [
            json.loads(line)
            for line in _scan(binary, host_mount, "--ndjson").splitlines()
            if line.strip()
        ]
    except (RuntimeError, ValueError, OSError, subprocess.SubprocessError) as e:
        print(f"publish-node-summary: scan failed: {e}", file=sys.stderr)
        return 1
    try:
        with open(f"{SA_DIR}/token", encoding="utf-8") as fh:
            token = fh.read().strip()
    except OSError as e:
        print(
            f"publish-node-summary: no service-account token ({e}); is automountServiceAccountToken on?",
            file=sys.stderr,
        )
        return 1
    host = os.environ.get("KUBERNETES_SERVICE_HOST", "kubernetes.default.svc")
    port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
    api = f"https://{'[' + host + ']' if ':' in host else host}:{port}"
    ctx = ssl.create_default_context(cafile=f"{SA_DIR}/ca.crt")
    opener: Opener = lambda req: urllib.request.urlopen(req, context=ctx, timeout=30)  # noqa: E731
    obj = configmap(configmap_name(node), namespace, build_summary(report, events))
    try:
        result = publish(obj, api, token, opener)
    except urllib.error.HTTPError as e:
        print(
            f"publish-node-summary: API error {e.code}: {e.read()[:500]!r}",
            file=sys.stderr,
        )
        return 1
    except (urllib.error.URLError, OSError) as e:
        print(f"publish-node-summary: API unreachable: {e}", file=sys.stderr)
        return 1
    print(f"publish-node-summary: {result} {namespace}/{obj['metadata']['name']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
