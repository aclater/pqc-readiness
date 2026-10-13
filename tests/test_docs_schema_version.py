# SPDX-License-Identifier: Apache-2.0
"""Docs ↔ code drift guards for the `--json` schema (#96).

`SCHEMA_VERSION` moved to "1.1" when the role-aware `memory` field
landed, but three docs kept saying "1.0" and docs/json-output.md never
gained a `memory` row.  These tests fail the next time the version or
the Report dataclass changes without the reference docs following.
"""
from __future__ import annotations

import dataclasses
import re
from pathlib import Path

import pytest

import pqc_readiness as pr

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCS = REPO_ROOT / "docs"

pytestmark = pytest.mark.skipif(
    not DOCS.is_dir(), reason="docs/ not present (e.g. inside a container test image)"
)

# Sample-output forms: `schema_version: "X"` (YAML) and
# `"schema_version": "X"` (JSON).
SAMPLE_VERSION_RE = re.compile(r'"?schema_version"?:\s*"([0-9.]+)"')


def test_doc_sample_outputs_use_current_schema_version() -> None:
    stale = []
    for doc in sorted(DOCS.glob("*.md")):
        for version in SAMPLE_VERSION_RE.findall(doc.read_text(encoding="utf-8")):
            if version != pr.SCHEMA_VERSION:
                stale.append((doc.name, version))
    assert not stale, f"docs show a stale schema_version (code: {pr.SCHEMA_VERSION}): {stale}"


def test_json_output_doc_states_current_schema_version() -> None:
    text = (DOCS / "json-output.md").read_text(encoding="utf-8")
    assert f'`"{pr.SCHEMA_VERSION}"`' in text


def test_json_output_doc_has_a_row_for_every_report_field() -> None:
    text = (DOCS / "json-output.md").read_text(encoding="utf-8")
    documented = set(re.findall(r"^\| `([a-z0-9_]+)` \|", text, re.MULTILINE))
    missing = [f.name for f in dataclasses.fields(pr.Report) if f.name not in documented]
    assert not missing, f"Report fields missing from docs/json-output.md: {missing}"
