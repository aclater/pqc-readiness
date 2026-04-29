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
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = REPO_ROOT / ".github" / "workflows"


def _load_workflow(name: str) -> dict[str, Any]:
    path = WORKFLOWS / name
    assert path.exists(), f"workflow missing: {path}"
    with path.open() as f:
        data = yaml.safe_load(f)
    assert isinstance(data, dict), f"{name} is not a YAML mapping"
    return data


def _job_run_steps(workflow: dict[str, Any], job_name: str) -> list[str]:
    """Return the concatenated `run:` script bodies for one job's steps."""
    jobs = workflow.get("jobs") or {}
    assert job_name in jobs, f"job {job_name!r} missing; have {sorted(jobs)}"
    steps = jobs[job_name].get("steps") or []
    return [step["run"] for step in steps if "run" in step]


def test_ubi8_workflow_builds_ubi8_containerfile() -> None:
    """The pre-existing UBI 8 workflow must keep building Containerfile.ubi8.

    Pinning this here means a future refactor that splits ci-ubi8.yml
    or renames jobs cannot silently drop the only build of the UBI 8
    image.
    """
    wf = _load_workflow("ci-ubi8.yml")
    runs = " \n ".join(_job_run_steps(wf, "build-and-test"))
    assert "Containerfile.ubi8" in runs
    assert "podman build" in runs


def test_containers_workflow_builds_ubi10() -> None:
    """ci-containers.yml must build Containerfile.ubi10 and smoke `--help`."""
    wf = _load_workflow("ci-containers.yml")
    runs = " \n ".join(_job_run_steps(wf, "build-ubi10"))
    assert "Containerfile.ubi10" in runs
    assert "podman build" in runs
    assert "--help" in runs


def test_containers_workflow_builds_debian() -> None:
    """ci-containers.yml must build Containerfile.debian and smoke `--help`."""
    wf = _load_workflow("ci-containers.yml")
    runs = " \n ".join(_job_run_steps(wf, "build-debian"))
    assert "Containerfile.debian" in runs
    assert "podman build" in runs
    assert "--help" in runs


def test_every_shipped_containerfile_is_built_in_ci() -> None:
    """Every `Containerfile.*` at the repo root must be referenced by a
    workflow's `run:` script.

    This is the audit-driven invariant from issue #45: the *set* of
    images CI builds must match the *set* of images we ship.  Adding a
    new Containerfile without wiring it up — or wiring up a workflow
    for a Containerfile that no longer exists — both fail this test.
    """
    shipped = sorted(p.name for p in REPO_ROOT.glob("Containerfile.*"))
    assert shipped, "no Containerfiles found at repo root"

    all_runs: list[str] = []
    for wf_path in WORKFLOWS.glob("*.yml"):
        with wf_path.open() as f:
            wf = yaml.safe_load(f) or {}
        for job in (wf.get("jobs") or {}).values():
            for step in job.get("steps") or []:
                if "run" in step:
                    all_runs.append(step["run"])
    joined = "\n".join(all_runs)

    missing = [name for name in shipped if name not in joined]
    # Containerfile.ubuntu-fips is documented as out-of-band (FIPS
    # validation is manual); exempt it explicitly so this test only
    # guards the three images CI is responsible for.
    missing = [name for name in missing if name != "Containerfile.ubuntu-fips"]
    assert not missing, f"Containerfiles not built by any workflow: {missing}"
