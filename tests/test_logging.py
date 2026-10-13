# SPDX-License-Identifier: Apache-2.0
"""Tests for --debug / module logging (issue #81).

The contract: detection fallbacks log at DEBUG instead of silently
swallowing errors, the default level emits nothing, and --debug output
goes to stderr so stdout stays a clean report stream."""
from __future__ import annotations

import logging
import subprocess
import sys
from pathlib import Path

import pytest

import pqc_readiness as pr

from conftest import PQC_CLI, PQC_ENV


def test_run_logs_missing_binary(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.DEBUG, logger="pqc-readiness"):
        rc, _ = pr._platform._run(["pqc-readiness-definitely-not-a-binary"])
    assert rc == 127
    assert any(
        "pqc-readiness-definitely-not-a-binary" in r.getMessage()
        and "failed" in r.getMessage()
        for r in caplog.records
    )


def test_run_logs_exit_code(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.DEBUG, logger="pqc-readiness"):
        rc, _ = pr._platform._run([sys.executable, "-c", "raise SystemExit(3)"])
    assert rc == 3
    assert any("rc=3" in r.getMessage() for r in caplog.records)


@pytest.mark.parametrize(
    "probe, expected",
    [
        (pr.linux_cpu_flags, "linux_cpu_flags"),
        (pr.detect_kernel_crypto_hw, "detect_kernel_crypto_hw"),
        (pr.memory_info, "memory_info"),
    ],
)
def test_unreadable_host_file_is_logged_not_swallowed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    probe: object,
    expected: str,
) -> None:
    # Point every host_path() read at an empty directory so the
    # /proc reads fail with OSError.
    monkeypatch.setattr(pr._platform, "HOST_PREFIX", str(tmp_path))
    monkeypatch.setattr(pr._platform, "is_linux", lambda: True)
    with caplog.at_level(logging.DEBUG, logger="pqc-readiness"):
        probe()  # type: ignore[operator]
    assert any(expected in r.getMessage() for r in caplog.records)


def test_default_level_is_silent_on_stderr() -> None:
    proc = subprocess.run(
        [*PQC_CLI, "--quiet", "--no-color"],
        env=PQC_ENV,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert "DEBUG" not in proc.stderr


def test_debug_goes_to_stderr_not_stdout() -> None:
    proc = subprocess.run(
        [*PQC_CLI, "--quiet", "--no-color", "--debug"],
        env=PQC_ENV,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert "pqc-readiness: DEBUG:" in proc.stderr
    assert "DEBUG" not in proc.stdout
    # --quiet stdout is exactly one verdict line.
    assert len(proc.stdout.strip().splitlines()) == 1
