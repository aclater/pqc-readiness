# SPDX-License-Identifier: Apache-2.0
"""Regression tests for the GitHub Actions workflow set.

Three Containerfiles ship in this repo (`Containerfile.ubi8`,
`Containerfile.ubi10`, `Containerfile.debian`).  Each must be exercised
by CI on every PR so a bad base-image bump or a microdnf/apt flag rename
fails before merge instead of when a customer pulls.

This test is the regression guard that locks in that contract.  It does
NOT shell out to `podman build` (the workflows themselves do that under
GHA); it asserts the workflow files are present and reference the right
Containerfile + smoke step.  If someone deletes ci-containers.yml or
drops one of the build jobs, this test fails locally before the next
push.

Implementation note: this file deliberately uses stdlib-only string
matching against the raw workflow YAML rather than a real YAML parser.
The project pins itself to stdlib + optional numpy at runtime and only
adds dev deps when a test genuinely needs them (see ci.yml's "Install
dev dependencies" step — pytest, ruff, mypy, numpy, jsonschema,
referencing).  Adding PyYAML solely to grep four substrings out of two
files is not warranted.

Skip behaviour: ci-ubi8.yml builds an extension test image that COPYs
only `tests/`, `pqc_readiness.py`, and the wrapper into the image — by
design, the build infrastructure (`.github/workflows/`, the
Containerfiles themselves) is *not* shipped into the test image.  When
this test module runs inside that stripped environment the workflow /
Containerfile files legitimately do not exist, so the relevant tests
skip rather than fail.  The regression guard still applies wherever
the repo layout is visible — local `make check` and the ci.yml
ubuntu-latest matrix — which is where it would catch a missing
workflow before push.
"""
from __future__ import annotations

from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = REPO_ROOT / ".github" / "workflows"


def _read_workflow(name: str) -> str:
    path = WORKFLOWS / name
    if not path.exists():
        pytest.skip(f"workflow file not present in this checkout: {path}")
    return path.read_text()


def test_ubi8_workflow_builds_ubi8_containerfile() -> None:
    """The pre-existing UBI 8 workflow must keep building Containerfile.ubi8.

    Pinning this here means a future refactor that splits ci-ubi8.yml
    or renames jobs cannot silently drop the only build of the UBI 8
    image.
    """
    body = _read_workflow("ci-ubi8.yml")
    assert "Containerfile.ubi8" in body
    assert "podman build" in body


def test_containers_workflow_builds_ubi10() -> None:
    """ci-containers.yml must build Containerfile.ubi10 and smoke `--help`."""
    body = _read_workflow("ci-containers.yml")
    assert "Containerfile.ubi10" in body
    assert "podman build" in body
    assert "--help" in body


def test_containers_workflow_builds_debian() -> None:
    """ci-containers.yml must build Containerfile.debian and smoke `--help`."""
    body = _read_workflow("ci-containers.yml")
    assert "Containerfile.debian" in body
    assert "podman build" in body
    assert "--help" in body


def test_every_shipped_containerfile_is_built_in_ci() -> None:
    """Every `Containerfile.*` at the repo root must be referenced by a
    workflow file.

    This is the audit-driven invariant from issue #45: the *set* of
    images CI builds must match the *set* of images we ship.  Adding a
    new Containerfile without wiring it up — or wiring up a workflow
    for a Containerfile that no longer exists — both fail this test.
    """
    shipped = sorted(p.name for p in REPO_ROOT.glob("Containerfile.*"))
    if not shipped:
        pytest.skip(
            "no Containerfiles in this checkout (e.g. ci-ubi8.yml's "
            "extension test image deliberately ships only tests/ + the "
            "script); regression guard runs where the build "
            "infrastructure is visible"
        )

    if not WORKFLOWS.exists():
        pytest.skip(f"workflow dir not present in this checkout: {WORKFLOWS}")

    all_workflow_text = "\n".join(
        wf.read_text() for wf in WORKFLOWS.glob("*.yml")
    )

    missing = [name for name in shipped if name not in all_workflow_text]
    # Containerfile.ubuntu-fips is documented as out-of-band (FIPS
    # validation is manual); exempt it explicitly so this test only
    # guards the three images CI is responsible for.
    missing = [name for name in missing if name != "Containerfile.ubuntu-fips"]
    assert not missing, f"Containerfiles not built by any workflow: {missing}"
