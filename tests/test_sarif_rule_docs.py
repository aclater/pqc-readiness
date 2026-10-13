# SPDX-License-Identifier: Apache-2.0
"""Every registered SARIF rule must have a help page (#179).

Code-scanning UIs link each rule's `helpUri`; a missing page is a 404 in
front of the operator who is trying to act on the finding."""

from __future__ import annotations

from pathlib import Path

import pytest

from pqc_readiness.render import sarif

RULES_DIR = Path(__file__).resolve().parent.parent / "docs" / "rules"

pytestmark = pytest.mark.skipif(
    not RULES_DIR.is_dir(),
    reason="docs/ is not shipped in this environment (e.g. container images)",
)


@pytest.mark.parametrize("spec", sarif.RULE_SPECS, ids=lambda s: s.id)
def test_rule_help_uri_points_at_existing_page(spec: sarif.RuleSpec) -> None:
    prefix = sarif.SARIF_HELP_BASE + "/"
    assert spec.help_uri.startswith(prefix), spec.help_uri
    page = RULES_DIR / spec.help_uri[len(prefix) :]
    assert page.is_file(), (
        f"{spec.id}: missing {page.relative_to(RULES_DIR.parent.parent)}"
    )
    text = page.read_text()
    assert text.startswith(f"# {spec.id}\n"), (
        f"{page.name} must start with '# {spec.id}'"
    )
    assert f"**Default level:** {spec.default_level}" in text


def test_rule_pages_have_required_sections() -> None:
    for spec in sarif.RULE_SPECS:
        text = (RULES_DIR / f"{spec.id}.md").read_text()
        for heading in (
            "## What it detects",
            "## Why it matters",
            "## Remediation",
            "## False positives and limitations",
        ):
            assert heading in text, f"{spec.id}: missing '{heading}'"


def test_index_lists_every_rule_and_no_orphans() -> None:
    index = (RULES_DIR / "README.md").read_text()
    ids = {s.id for s in sarif.RULE_SPECS}
    for rule_id in ids:
        assert f"]({rule_id}.md)" in index, f"index missing {rule_id}"
    pages = {p.stem for p in RULES_DIR.glob("pqc-*.md")}
    assert pages == ids, f"orphan pages: {sorted(pages - ids)}"
