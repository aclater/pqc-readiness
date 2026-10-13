"""Security-posture tests for the OpenShift manifests (#181).

The base DaemonSet/SCC must stay least-privilege; the opt-in services
overlay may add exactly CAP_SYS_PTRACE + CAP_DAC_READ_SEARCH and nothing
else.  Skipped when PyYAML or deploy/ is absent (e.g. the UBI 8 image job);
the ci-openshift-manifests workflow installs PyYAML and runs this file.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest

yaml = pytest.importorskip("yaml")

REPO = Path(__file__).resolve().parent.parent
BASE = REPO / "deploy" / "openshift" / "daemonset.yaml"
OVERLAY = REPO / "deploy" / "openshift" / "services" / "services.yaml"
CONTAINERFILE = REPO / "deploy" / "openshift" / "services" / "Containerfile"
OVERLAY_CAPS = {"SYS_PTRACE", "DAC_READ_SEARCH"}
CAPPED_PYTHON = "/usr/local/libexec/pqc-readiness/python3"

pytestmark = pytest.mark.skipif(not BASE.exists(), reason="deploy/ not present")


def _docs(path: Path) -> dict[str, dict[str, Any]]:
    return {d["kind"]: d for d in yaml.safe_load_all(path.read_text()) if d}


def _container(ds: dict[str, Any]) -> dict[str, Any]:
    (c,) = ds["spec"]["template"]["spec"]["containers"]
    return c


# ---------------------------------------------------------------- base


def test_base_scc_grants_no_capabilities_or_escalation() -> None:
    scc = _docs(BASE)["SecurityContextConstraints"]
    assert scc["allowedCapabilities"] == []
    assert scc["defaultAddCapabilities"] == []
    assert scc["requiredDropCapabilities"] == ["ALL"]
    assert scc["allowPrivilegeEscalation"] is False
    assert scc["allowPrivilegedContainer"] is False
    assert scc["allowHostNetwork"] is False


def test_base_daemonset_drops_all_and_adds_nothing() -> None:
    c = _container(_docs(BASE)["DaemonSet"])
    sc = c["securityContext"]
    assert sc["capabilities"] == {"drop": ["ALL"]}
    assert sc["allowPrivilegeEscalation"] is False
    assert "--scan-services" not in " ".join(c["command"])


# ---------------------------------------------------------------- overlay


def test_overlay_scc_allows_exactly_the_two_capabilities() -> None:
    scc = _docs(OVERLAY)["SecurityContextConstraints"]
    assert set(scc["allowedCapabilities"]) == OVERLAY_CAPS
    assert scc["defaultAddCapabilities"] == []
    assert scc["requiredDropCapabilities"] == ["ALL"]
    assert scc["allowPrivilegedContainer"] is False
    assert scc["allowHostNetwork"] is False
    assert scc["allowHostIPC"] is False
    assert scc["readOnlyRootFilesystem"] is True
    assert scc["runAsUser"] == {"type": "MustRunAs", "uid": 1001}
    assert scc["users"] == [
        "system:serviceaccount:pqc-readiness:pqc-readiness-services"
    ]


def test_overlay_container_is_non_root_and_adds_only_the_two_caps() -> None:
    ds = _docs(OVERLAY)["DaemonSet"]
    pod = ds["spec"]["template"]["spec"]
    assert pod["securityContext"]["runAsNonRoot"] is True
    assert pod["serviceAccountName"] == "pqc-readiness-services"
    sc = _container(ds)["securityContext"]
    assert sc["capabilities"]["drop"] == ["ALL"]
    assert set(sc["capabilities"]["add"]) == OVERLAY_CAPS
    assert sc["runAsUser"] == 1001
    assert sc["readOnlyRootFilesystem"] is True
    assert "privileged" not in sc


def test_overlay_runs_capped_interpreter_in_isolated_mode() -> None:
    cmd = " ".join(_container(_docs(OVERLAY)["DaemonSet"])["command"])
    assert re.search(re.escape(CAPPED_PYTHON) + r"\s+-I\b", cmd)
    assert "--scan-services" in cmd
    assert "--host-mount /host" in cmd


def test_overlay_host_mounts_match_base_and_are_read_only() -> None:
    def mounts(path: Path) -> dict[str, bool]:
        c = _container(_docs(path)["DaemonSet"])
        return {m["mountPath"]: bool(m.get("readOnly")) for m in c["volumeMounts"]}

    base, overlay = mounts(BASE), mounts(OVERLAY)
    assert set(overlay) == set(base), "overlay mounts drifted from the base DaemonSet"
    for path, ro in overlay.items():
        if path.startswith("/host/"):
            assert ro, f"{path} must be read-only"


def test_containerfile_sets_exactly_the_two_file_capabilities() -> None:
    text = CONTAINERFILE.read_text()
    (caps,) = re.findall(r"setcap '([^']+)'", text)
    names, _, flags = caps.partition("=")
    assert {
        n.strip().upper().removeprefix("CAP_") for n in names.split(",")
    } == OVERLAY_CAPS
    assert flags == "ep"
    assert re.findall(r"^USER (\S+)", text, re.M)[-1] == "1001"
    assert f'"{CAPPED_PYTHON}", "-I"' in text
