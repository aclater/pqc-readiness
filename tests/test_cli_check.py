# SPDX-License-Identifier: Apache-2.0
"""End-to-end exit codes for ``--check cnsa-2.0`` through ``main()``.

``evaluate_cnsa_2_0`` is unit-tested in isolation; these tests cover the
CLI glue that maps its ``status`` onto the process exit code (README
"Exit codes": 4 when ``--check`` is not met, otherwise the verdict code).

Detection runs for real against the test host; only the two inputs that
decide the exit code are pinned so the result is host-independent.
"""

from __future__ import annotations

import json
import subprocess
import sys
from typing import Any

import pytest

from conftest import PQC_CLI, PQC_ENV
import pqc_readiness as pr

_VERDICT_CODE = 0  # pinned "excellent" so the non-check exit is predictable


def _run_main(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    cnsa_status: str,
    argv: list[str],
) -> tuple[int, dict[str, Any]]:
    monkeypatch.setattr(
        pr.verdict,
        "evaluate_cnsa_2_0",
        lambda *_a, **_k: {"status": cnsa_status, "findings": []},
    )
    monkeypatch.setattr(
        pr.verdict,
        "overall_verdict",
        lambda *_a, **_k: ("EXCELLENT - pinned", "pinned.", _VERDICT_CODE, None),
    )
    monkeypatch.setattr(sys, "argv", ["pqc_readiness.py", *argv])
    rc = pr.main()
    report = json.loads(capsys.readouterr().out)
    return rc, report


@pytest.mark.parametrize("status", ["partial", "non_compliant", "unknown"])
def test_check_cnsa_2_0_not_compliant_exits_4(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    status: str,
) -> None:
    rc, report = _run_main(
        monkeypatch, capsys, status, ["--check", "cnsa-2.0", "--json"]
    )
    assert report["cnsa_2_0"]["status"] == status
    assert rc == 4


def test_check_cnsa_2_0_compliant_exits_with_verdict_code(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    rc, report = _run_main(
        monkeypatch, capsys, "compliant", ["--check", "cnsa-2.0", "--json"]
    )
    assert report["cnsa_2_0"]["status"] == "compliant"
    assert rc == _VERDICT_CODE


def test_no_check_flag_ignores_cnsa_status(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Without --check, a non-compliant CNSA status must not leak into
    the exit code — 4 is reserved for an explicit gate."""
    rc, _ = _run_main(monkeypatch, capsys, "non_compliant", ["--json"])
    assert rc == _VERDICT_CODE


def test_check_cnsa_2_0_subprocess_exit_code_matches_report() -> None:
    """Real process, real host: whatever CNSA status this host has, the
    exit code must be 4 iff the reported status is not 'compliant'."""
    proc = subprocess.run(
        [*PQC_CLI, "--check", "cnsa-2.0", "--json"],
        env=PQC_ENV,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    report = json.loads(proc.stdout)
    if report["cnsa_2_0"]["status"] == "compliant":
        assert proc.returncode == report["exit_code"]
    else:
        assert proc.returncode == 4, proc.stderr
