# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the markdown renderer (`render_markdown`).

Audit issue #46. Mirrors `tests/test_render_text.py` for the markdown
output and adds two markdown-specific structural invariants:

- contiguous blocks of `|`-prefixed rows (i.e. tables) must have a
  consistent column count, so the rendered report does not produce a
  visually broken table when piped through a markdown viewer; and
- triple-backtick code-fence delimiters must come in matched pairs, so
  no section opens a fence and silently swallows the rest of the
  document.

The current `render_markdown` implementation does not emit any
triple-backtick fences; the assertion is in place so a future addition
that opens one without closing it fails the suite immediately.
"""
from __future__ import annotations

import re
from typing import Any

import pytest

import pqc_readiness as pr
from test_cbom import _make_report

# Same color-state pin as test_render_text — keep `C.wrap` as identity
# so heading assertions match source verbatim and tests are independent
# of color-toggle ordering across files.
pr.C.configure(False)


def _make_full_coverage_report() -> pr.Report:
    """Populate every conditional section the markdown renderer reads.
    Same shape as `test_render_text._make_full_coverage_report` but
    duplicated locally so a future field that only one renderer
    consumes does not silently drift one of the test fixtures out of
    sync with the other."""
    r = _make_report()
    r.cpu_freq_mhz = 4500.0
    r.cores_physical = 8
    r.cores_logical = 16
    r.memory_bandwidth_gb_s = 65.0
    r.isa_score = 5
    r.isa_tier = "good"
    r.isa_reason = "AVX-512 + AES-NI present"
    r.per_algo = {
        "ml-kem-768": {
            "tier": "good",
            "rate_per_core": 12345.6,
            "rate_host_estimate": 98765.0,
            "metric": "encap/sec",
            "reason": "above per-core threshold",
            "notes": [],
        },
        "ml-dsa-65": {
            "tier": "good",
            "rate_per_core": 5000.0,
            "rate_host_estimate": 40000.0,
            "metric": "sign/sec",
            "reason": "ok",
            "notes": [],
        },
    }
    r.production_estimate = {
        "tls_pqc_handshakes_per_sec": 5000,
        "ml_dsa_signatures_per_sec": 10000,
        "concurrent_connections_realistic": 50000,
        "assumptions": "60% CPU headroom",
    }
    r.benchmark_tls_handshake = {
        "available": True,
        "engine": "openssl",
        "transport": "loopback",
        "iterations_per_suite": 100,
        "openssl_version": "3.5.5",
        "suites": [
            {
                "label": "TLS_AES_128_GCM_SHA256",
                "role": "client",
                "handshakes_per_sec": 1000.5,
                "ttfb_ms_median": 1.5,
                "bytes_on_wire_per_handshake": 4500,
            },
            {
                "label": "ML-KEM-768",
                "role": "client",
                "handshakes_per_sec": 800.5,
                "ttfb_ms_median": 2.0,
                "bytes_on_wire_per_handshake": 6500,
            },
        ],
    }
    r.verdict = "good"
    r.verdict_reason = "PQC primitives present and benchmarked above threshold"
    return r


# Section labels asserted are the literal `## …` lines emitted by the
# renderer at lines around pqc_readiness.py:5602+.
ALWAYS_PRESENT_HEADINGS = (
    "## Host",
    "## ISA tier:",  # the suffix is a tier value, asserted as a prefix only
    "## Accelerators",
)
CONDITIONAL_HEADINGS = (
    "## OpenSSL PQC capability",
    "## Per-algorithm verdict",
    "## Production capacity (60% headroom)",
    "## TLS handshake benchmark (loopback)",
)


def _table_row_blocks(lines: list[str]) -> list[list[str]]:
    """Group contiguous markdown table-row lines (lines starting with
    `|` after lstrip). Tables are delimited by any non-pipe row, so a
    block break is a blank line, a heading, a paragraph, etc."""
    blocks: list[list[str]] = []
    current: list[str] = []
    for ln in lines:
        if ln.lstrip().startswith("|"):
            current.append(ln)
        elif current:
            blocks.append(current)
            current = []
    if current:
        blocks.append(current)
    return blocks


def test_render_markdown_full_coverage_does_not_leak_none() -> None:
    """Same null-leak guard as the text-renderer test: a fully populated
    Report must not surface the literal string `None`."""
    out = pr.render_markdown(_make_full_coverage_report())
    assert "None" not in out, (
        "render_markdown leaked the literal 'None' into customer-facing "
        f"output — likely an f-string of an unguarded null field. Output:\n{out}"
    )


def test_render_markdown_full_coverage_includes_all_section_headings() -> None:
    """Both unconditional and conditional `## …` headings must appear
    when every input field is populated. Catches a heading rename / drop
    during a refactor."""
    out = pr.render_markdown(_make_full_coverage_report())
    missing = [
        h for h in (*ALWAYS_PRESENT_HEADINGS, *CONDITIONAL_HEADINGS) if h not in out
    ]
    assert not missing, f"render_markdown missing section heading(s): {missing}"


def test_render_markdown_tables_are_balanced() -> None:
    """Every contiguous block of `|`-prefixed rows is a markdown table;
    every row in that block must have the same number of `|` characters
    as the first row (the header). A drift here renders as a visually
    broken table when piped through any markdown viewer."""
    out = pr.render_markdown(_make_full_coverage_report())
    for block in _table_row_blocks(out.splitlines()):
        header = block[0]
        expected = header.count("|")
        offenders = [(i, row) for i, row in enumerate(block) if row.count("|") != expected]
        assert not offenders, (
            f"Markdown table block has unbalanced rows. Header={header!r} "
            f"(|-count={expected}); offenders={offenders}; full block:\n"
            + "\n".join(block)
        )


def test_render_markdown_code_fences_are_matched() -> None:
    """Triple-backtick fences must come in matched pairs. The current
    renderer does not emit any (count is 0, which is even); the test
    is in place so a future addition that opens a fence without
    closing it — which would swallow the rest of the document on every
    markdown viewer — fails the suite immediately."""
    out = pr.render_markdown(_make_full_coverage_report())
    fence_count = len(re.findall(r"^```", out, flags=re.MULTILINE))
    assert fence_count % 2 == 0, (
        f"render_markdown emitted {fence_count} triple-backtick fences "
        "(odd count → at least one fence is unclosed). Output:\n" + out
    )


def test_render_markdown_empty_report_is_non_empty_and_safe() -> None:
    """A bare `Report()` must still render — no exception on default
    fields, no `None` leak, and the always-on `## Host` / `## ISA
    tier:` / `## Accelerators` headings must appear."""
    out = pr.render_markdown(pr.Report())
    assert out.strip(), "render_markdown on default Report() produced empty output"
    assert "None" not in out, (
        "render_markdown leaked 'None' on default Report() — at least one "
        f"f-string is missing a guard:\n{out}"
    )
    for heading in ALWAYS_PRESENT_HEADINGS:
        assert heading in out, f"unconditional heading missing on empty Report: {heading}"


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(lambda r: setattr(r, "per_algo", {}), id="per-algo-empty"),
        pytest.param(
            lambda r: setattr(r, "production_estimate", {}),
            id="prod-estimate-empty",
        ),
        pytest.param(
            lambda r: setattr(r, "benchmark_tls_handshake", {}),
            id="bench-tls-empty",
        ),
        pytest.param(
            lambda r: setattr(r, "openssl", {"available": False}),
            id="openssl-unavailable",
        ),
        pytest.param(
            lambda r: setattr(r, "accelerators", []),
            id="no-accelerators",
        ),
        pytest.param(
            lambda r: setattr(r, "isa_features", {}),
            id="no-isa-features",
        ),
    ],
)
def test_render_markdown_partial_population_does_not_raise_or_leak_none(
    mutate: Any,
) -> None:
    """Property-style: vary which optional fields are populated and
    assert (a) the renderer returns without raising, (b) no `None` is
    f-string'd into the output, and (c) any tables that are emitted
    remain balanced. Future conditional sections must keep all three
    invariants."""
    r = _make_full_coverage_report()
    mutate(r)
    out = pr.render_markdown(r)
    assert out.strip(), "render_markdown returned empty output for partial Report"
    assert "None" not in out, (
        f"render_markdown leaked 'None' for partial Report mutation; output:\n{out}"
    )
    for block in _table_row_blocks(out.splitlines()):
        header = block[0]
        expected = header.count("|")
        offenders = [(i, row) for i, row in enumerate(block) if row.count("|") != expected]
        assert not offenders, (
            f"Markdown table unbalanced after mutation. header={header!r}; "
            f"offenders={offenders}"
        )
