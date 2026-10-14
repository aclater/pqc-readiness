"""Regression tests for the published container images (#212).

Two contracts:

* ``.github/workflows/release-images.yml`` builds, signs and attests every
  image the repo ships (each root ``Containerfile.*`` plus the services
  overlay), and never uses a ``:latest`` tag.
* The deploy manifests reference the image of the *current* release
  (``SCRIPT_VERSION``), so a release PR that bumps the version cannot leave
  the quadlet, DaemonSet or services overlay pointing at an old image.

Stdlib string matching only, like test_ci_workflows.py.  Skips where the
build infrastructure is not shipped (the UBI 8 test image copies only
``tests/`` and the package).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from pqc_readiness.report import SCRIPT_VERSION

REPO_ROOT = Path(__file__).resolve().parent.parent
RELEASE_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "release-images.yml"
SERVICES_CONTAINERFILE = (
    REPO_ROOT / "deploy" / "openshift" / "services" / "Containerfile"
)

IMAGE_REFS = {
    "deploy/openshift/daemonset.yaml": r"image:\s*(ghcr\.io/aclater/pqc-readiness:\S+)",
    "deploy/openshift/services/services.yaml": r"image:\s*(ghcr\.io/aclater/pqc-readiness-services:\S+)",
    "deploy/quadlet/pqc-readiness.container": r"^Image=(ghcr\.io/aclater/pqc-readiness:\S+)",
    "deploy/openshift/services/Containerfile": r"^ARG BASE=(ghcr\.io/aclater/pqc-readiness:\S+)",
}


def _workflow() -> str:
    if not RELEASE_WORKFLOW.is_file():
        pytest.skip("release workflow not present in this checkout")
    return RELEASE_WORKFLOW.read_text(encoding="utf-8")


def test_release_workflow_builds_every_shipped_image() -> None:
    body = _workflow()
    shipped = sorted(p.name for p in REPO_ROOT.glob("Containerfile.*"))
    assert shipped, "no Containerfiles found next to the workflow"
    missing = [name for name in shipped if f"containerfile: {name}" not in body]
    assert not missing, f"release workflow does not build: {missing}"
    assert "-f deploy/openshift/services/Containerfile" in body
    assert SERVICES_CONTAINERFILE.is_file()


def test_release_workflow_tests_signs_and_attests() -> None:
    body = _workflow()
    assert "sha256sum -c pqc-readiness.pyz.sha256" in body, (
        "must ship the verified release zipapp"
    )
    assert "-m pytest tests/ -q" in body, "must run the suite inside each image"
    assert body.count("cosign sign --yes") == 2, (
        "base and services images must both be signed"
    )
    assert "actions/attest@" in body and "push-to-registry: true" in body
    assert "--root rootfs --sbom" in body, (
        "SBOM attestation comes from the scanner itself"
    )
    assert "container-images.txt" in body


def test_release_workflow_never_moves_or_floats_tags() -> None:
    body = _workflow()
    assert ":latest" not in body
    assert "refusing to move a version tag" in body


@pytest.mark.parametrize("path", sorted(IMAGE_REFS))
def test_deploy_manifests_reference_the_current_release_image(path: str) -> None:
    file = REPO_ROOT / path
    if not file.is_file():
        pytest.skip(f"{path} not present in this checkout")
    refs = re.findall(IMAGE_REFS[path], file.read_text(encoding="utf-8"), re.MULTILINE)
    assert refs, f"no published image reference found in {path}"
    for ref in refs:
        assert ref.rsplit(":", 1)[1] == SCRIPT_VERSION, (
            f"{path} references {ref}; release {SCRIPT_VERSION} images are "
            f"tagged :{SCRIPT_VERSION} (update it in the release PR)"
        )
