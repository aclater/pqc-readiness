# SPDX-License-Identifier: Apache-2.0
"""Posture tests for the Kubernetes / RKE2 / K3s manifests (#219).

deploy/kubernetes reuses the OpenShift DaemonSets through kustomize and
swaps the SCC for Pod Security Admission labels.  These tests pin that the
result keeps the OpenShift posture: non-root, no added capabilities in the
base, read-only host mounts, and a package-database mount that exists on
every node.

The built output comes from `kustomize build` (CI writes it to
$PQC_K8S_BUILT_DIR) or from a local `kubectl kustomize` / `kustomize`;
without either, only the source-level tests run.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

yaml = pytest.importorskip("yaml")

REPO = Path(__file__).resolve().parent.parent
K8S = REPO / "deploy" / "kubernetes"
VARIANTS = {"base": K8S, "services": K8S / "services"}


def _built(variant: str) -> list[dict[str, Any]]:
    prebuilt = os.environ.get("PQC_K8S_BUILT_DIR")
    if prebuilt:
        text = (Path(prebuilt) / f"{variant}.yaml").read_text()
    else:
        if shutil.which("kustomize"):
            argv = ["kustomize", "build", str(VARIANTS[variant])]
        elif shutil.which("kubectl"):
            argv = ["kubectl", "kustomize", str(VARIANTS[variant])]
        else:
            pytest.skip("no kustomize or kubectl, and PQC_K8S_BUILT_DIR unset")
        text = subprocess.run(argv, check=True, capture_output=True, text=True).stdout
    return [d for d in yaml.safe_load_all(text) if d]


def _one(docs: list[dict[str, Any]], kind: str) -> dict[str, Any]:
    found = [d for d in docs if d["kind"] == kind]
    assert len(found) == 1, f"expected one {kind}, got {len(found)}"
    return found[0]


def test_services_namespace_matches_the_openshift_one() -> None:
    # kustomize can't load deploy/openshift/namespace.yaml from services/,
    # so deploy/kubernetes/namespace carries a copy; it must not drift.
    ours = yaml.safe_load((K8S / "namespace" / "namespace.yaml").read_text())
    theirs = yaml.safe_load(
        (REPO / "deploy" / "openshift" / "namespace.yaml").read_text()
    )
    assert ours == theirs
    assert ours["metadata"]["labels"]["pod-security.kubernetes.io/enforce"] == (
        "privileged"
    )


@pytest.mark.parametrize("variant", sorted(VARIANTS))
def test_each_variant_creates_its_namespace(variant: str) -> None:
    # `kubectl apply -k` on a fresh cluster must not fail on a missing
    # namespace (#220 found that on OpenShift).
    ns = _one(_built(variant), "Namespace")
    assert ns["metadata"]["name"] == "pqc-readiness"


@pytest.mark.parametrize("variant", sorted(VARIANTS))
def test_pod_uses_runtime_default_seccomp(variant: str) -> None:
    pod = _one(_built(variant), "DaemonSet")["spec"]["template"]["spec"]
    assert pod["securityContext"]["seccompProfile"] == {"type": "RuntimeDefault"}


@pytest.mark.parametrize("variant", sorted(VARIANTS))
def test_reports_name_the_node_and_land_on_a_writable_volume(variant: str) -> None:
    pod = _one(_built(variant), "DaemonSet")["spec"]["template"]["spec"]
    probe = pod["containers"][0]
    env = {e["name"]: e for e in probe["env"]}
    assert env["PQC_HOSTNAME"]["valueFrom"]["fieldRef"]["fieldPath"] == (
        "spec.nodeName"
    )
    home = env["HOME"]["value"]
    mount = next(m for m in probe["volumeMounts"] if m["mountPath"] == home)
    volume = next(v for v in pod["volumes"] if v["name"] == mount["name"])
    # A hostPath output dir is created root-owned and the UID 1001 pod
    # can't write it; an emptyDir is writable by the pod's fsGroup.
    assert "emptyDir" in volume


def test_both_variants_reuse_the_openshift_daemonsets() -> None:
    base = yaml.safe_load((K8S / "kustomization.yaml").read_text())
    svc = yaml.safe_load((K8S / "services" / "kustomization.yaml").read_text())
    assert "../openshift" in base["resources"]
    assert "../../openshift/services" in svc["resources"]
    assert base["components"] == ["portable"]
    assert svc["components"] == ["../portable"]


@pytest.mark.parametrize("variant", sorted(VARIANTS))
def test_no_openshift_only_objects(variant: str) -> None:
    kinds = {d["kind"] for d in _built(variant)}
    assert kinds == {"Namespace", "ServiceAccount", "DaemonSet"}


@pytest.mark.parametrize("variant", sorted(VARIANTS))
def test_pod_is_non_root_with_read_only_root_fs(variant: str) -> None:
    pod = _one(_built(variant), "DaemonSet")["spec"]["template"]["spec"]
    assert pod["securityContext"]["runAsNonRoot"] is True
    assert pod["securityContext"]["runAsUser"] == 1001
    assert pod["securityContext"]["seccompProfile"]["type"] == "RuntimeDefault"
    assert pod["automountServiceAccountToken"] is False
    assert pod.get("hostNetwork", False) is False
    (c,) = pod["containers"]
    assert c["securityContext"]["readOnlyRootFilesystem"] is True
    assert c["securityContext"]["capabilities"]["drop"] == ["ALL"]
    assert not c["securityContext"].get("privileged", False)


def test_base_adds_no_capabilities_and_no_escalation() -> None:
    (c,) = _one(_built("base"), "DaemonSet")["spec"]["template"]["spec"]["containers"]
    assert "add" not in c["securityContext"]["capabilities"]
    assert c["securityContext"]["allowPrivilegeEscalation"] is False
    assert "--scan-services" not in " ".join(c["command"])


def test_services_adds_exactly_the_two_capabilities() -> None:
    (c,) = _one(_built("services"), "DaemonSet")["spec"]["template"]["spec"][
        "containers"
    ]
    assert sorted(c["securityContext"]["capabilities"]["add"]) == [
        "DAC_READ_SEARCH",
        "SYS_PTRACE",
    ]
    assert "--scan-services" in " ".join(c["command"])


@pytest.mark.parametrize("variant", sorted(VARIANTS))
def test_host_mounts_are_read_only_and_exist_on_every_node(variant: str) -> None:
    pod = _one(_built(variant), "DaemonSet")["spec"]["template"]["spec"]
    (c,) = pod["containers"]
    host_volumes = {v["name"]: v["hostPath"] for v in pod["volumes"] if "hostPath" in v}
    mounts = {m["name"]: m for m in c["volumeMounts"]}
    # rpm-only mount replaced: /var/lib/rpm is absent on dpkg/apk nodes.
    assert "host-rpmdb" not in host_volumes
    assert host_volumes["host-varlib"] == {"path": "/var/lib", "type": "Directory"}
    assert mounts["host-varlib"]["recursiveReadOnly"] == "Enabled"
    for name, hp in host_volumes.items():
        if name == "readiness-output":
            assert hp["path"] == "/var/lib/pqc-readiness"
            continue
        # Never create anything on the node.
        assert hp["type"] == "Directory", name
        assert mounts[name]["readOnly"] is True, name
        assert mounts[name]["mountPath"] == "/host" + hp["path"], name
