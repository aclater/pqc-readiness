# SPDX-License-Identifier: Apache-2.0
"""Null/empty convention for optional Report fields (issue #82).

"Not run / not measured" is always JSON `null` for the fields that
used to mix `{}` (benchmark, benchmark_tls_handshake) and `""`
(memory_bandwidth_method), so consumers test one sentinel."""
from __future__ import annotations

import json
import sys
from dataclasses import asdict

import pytest

import pqc_readiness as pr

NORMALIZED_FIELDS = (
    "benchmark",
    "benchmark_tls_handshake",
    "memory_bandwidth_method",
)


@pytest.mark.parametrize("name", NORMALIZED_FIELDS)
def test_report_default_is_none(name: str) -> None:
    assert getattr(pr.Report(), name) is None


def test_default_report_serialises_null() -> None:
    data = json.loads(json.dumps(asdict(pr.Report())))
    for name in NORMALIZED_FIELDS:
        assert data[name] is None, name
    # memory_bandwidth_gb_s already used null; keep it that way.
    assert data["memory_bandwidth_gb_s"] is None


@pytest.mark.parametrize("render", [pr.render_text, pr.render_markdown])
def test_renderers_accept_default_report(render: object) -> None:
    out = render(pr.Report())  # type: ignore[operator]
    assert "None" not in out


def test_main_json_without_bench_emits_null(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """End-to-end: no --bench / --bench-tls means all three fields are
    null in --json output (previously {} / {} / "")."""
    monkeypatch.setattr(sys, "argv", ["pqc_readiness.py", "--json"])
    pr.main()
    data = json.loads(capsys.readouterr().out)
    for name in NORMALIZED_FIELDS:
        assert data[name] is None, name
    assert data["per_algo"] == {}
