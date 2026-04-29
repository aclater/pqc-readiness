# SPDX-License-Identifier: Apache-2.0
"""Regression test for the README's "Distribution support" table.

Issue #44: the table previously claimed Tier 1 distros (RHEL 9, RHEL 10,
Ubuntu 24.04 LTS, Debian 12) were validated on "Every change (CI)" when
the only PR-CI surfaces were the `ubuntu-latest` GitHub-hosted runner
and a UBI 8 image build. The "Validation cadence" column is now expected
to be verifiable against `.github/workflows/`: any tier row whose
cadence cell claims PR-CI coverage must name an actual workflow file
that exists in the repo. Drift in either direction (a tier added to the
"every change" promise without a workflow, or a workflow renamed
without updating the README) is caught here before it ships.
"""
from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
README = REPO_ROOT / "README.md"
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"

PR_CI_PHRASE = re.compile(
    r"\b(every\s+(?:change|PR|push)|on\s+every\s+(?:change|PR|push))\b",
    re.IGNORECASE,
)
WORKFLOW_REF = re.compile(r"([A-Za-z0-9_.-]+\.ya?ml)")


def _tier_rows() -> list[tuple[str, str, str]]:
    text = README.read_text(encoding="utf-8")
    rows = re.findall(
        r"\n\|\s*\*\*([^*|]+)\*\*\s*\|([^|\n]+)\|([^|\n]+)\|",
        text,
    )
    return [(tier.strip(), distros.strip(), cadence.strip()) for tier, distros, cadence in rows]


def test_distribution_support_table_is_present() -> None:
    """Sanity check: the table the rest of this module reasons about
    actually exists. If someone drops the table the other assertions
    would silently pass on an empty list."""
    text = README.read_text(encoding="utf-8")
    assert "## Distribution support" in text, "Distribution support § missing from README"
    rows = _tier_rows()
    tier_labels = {tier for tier, _, _ in rows}
    assert {"1", "2", "3"}.issubset(tier_labels), (
        f"Distribution support table must contain tiers 1, 2, and 3; got {sorted(tier_labels)}"
    )


def test_pr_ci_cadence_claims_reference_real_workflows() -> None:
    """Any tier row whose Validation cadence cell claims PR-CI coverage
    must name at least one workflow file that exists in
    `.github/workflows/`. This is the regression-catching property for
    issue #44: the previous Tier 1 cadence cell said "Every change (CI)"
    with no pointer, and four of its four distros had no CI job at all.
    """
    workflow_files = {p.name for p in WORKFLOWS_DIR.glob("*.y*ml")}
    assert workflow_files, f"no workflow files found in {WORKFLOWS_DIR}"

    offenders: list[tuple[str, str]] = []
    for tier, _distros, cadence in _tier_rows():
        if not PR_CI_PHRASE.search(cadence):
            continue
        referenced = set(WORKFLOW_REF.findall(cadence))
        if not referenced & workflow_files:
            offenders.append((tier, cadence))

    assert not offenders, (
        "README distribution-support rows claim PR-CI coverage in their "
        "Validation cadence cell without naming an existing workflow "
        f"file. Existing workflows: {sorted(workflow_files)}. "
        f"Offending rows: {offenders}"
    )


def test_named_workflow_files_actually_exist() -> None:
    """Every `*.yml` / `*.yaml` filename mentioned in the Distribution
    support table must resolve to a real file. Catches typos like
    `ci-ubi-8.yml` and stale references after a workflow rename."""
    text = README.read_text(encoding="utf-8")
    section_match = re.search(
        r"## Distribution support\n(.*?)(?:\n## |\Z)", text, re.DOTALL
    )
    assert section_match, "Distribution support § not found"
    section = section_match.group(1)

    workflow_files = {p.name for p in WORKFLOWS_DIR.glob("*.y*ml")}
    referenced = {name for name in WORKFLOW_REF.findall(section)}
    missing = sorted(name for name in referenced if name not in workflow_files)
    assert not missing, (
        f"README Distribution support § references workflow files that "
        f"do not exist: {missing}. Existing workflows: {sorted(workflow_files)}."
    )
