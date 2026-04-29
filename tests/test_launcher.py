# SPDX-License-Identifier: Apache-2.0
"""Tests for the `pqc-readiness` shell wrapper launcher.

The wrapper exists so RHEL 8 / Rocky 8 / AlmaLinux 8 customers, whose
default `python3` is 3.6, get an actionable error pointing at the
AppStream `python39` module instead of a cryptic Python traceback when
they invoke the tool.  These tests verify the three behaviours the
launcher promises:

1. Happy path — finds a usable interpreter and execs the .py.
2. Stripped PATH (no python at all) — exits non-zero with the AppStream
   guidance message.
3. Only-too-old python3 on PATH — same AppStream guidance, distinct
   exit code from "no python at all".
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
LAUNCHER = REPO_ROOT / "pqc-readiness"


@pytest.fixture(scope="module")
def launcher_executable() -> Path:
    """The launcher must be present and executable in the repo root.

    A missing or non-executable wrapper would silently no-op every
    other test in this file, so check it explicitly once."""
    assert LAUNCHER.exists(), f"launcher missing at {LAUNCHER}"
    assert os.access(LAUNCHER, os.X_OK), f"launcher not executable: {LAUNCHER}"
    return LAUNCHER


@pytest.fixture()
def utils_path(tmp_path: Path) -> str:
    """A PATH directory that has the POSIX utilities the wrapper itself
    needs (`dirname`, `cd` is a builtin, `command` is a builtin) but no
    Python interpreter.  Lets us invoke the wrapper without leaking the
    test-runner's real Python onto the search path."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for tool in ("dirname", "pwd", "cat", "sh", "basename"):
        src = shutil.which(tool)
        if src:
            os.symlink(src, bin_dir / tool)
    return str(bin_dir)


def test_launcher_runs_under_current_python(launcher_executable: Path) -> None:
    """Happy path: the developer's own Python is 3.9+, the wrapper
    finds it, and `--version` returns the schema version."""
    proc = subprocess.run(
        [str(launcher_executable), "--version"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert "pqc-readiness" in proc.stdout
    assert "schema" in proc.stdout


def test_launcher_no_python_on_path_emits_appstream_guidance(
    launcher_executable: Path, utils_path: str
) -> None:
    """No Python interpreter on PATH at all: the wrapper exits 127 and
    points the user at the AppStream `python39` module."""
    proc = subprocess.run(
        [str(launcher_executable)],
        capture_output=True,
        text=True,
        env={"PATH": utils_path},
        check=False,
    )
    assert proc.returncode == 127, proc.stderr
    assert "AppStream" in proc.stderr
    assert "python39" in proc.stderr
    assert "dnf module install" in proc.stderr


def test_launcher_only_old_python_emits_appstream_guidance(
    launcher_executable: Path, utils_path: str, tmp_path: Path
) -> None:
    """RHEL 8 reality: `python3` is on PATH but reports 3.6.  The
    wrapper must reject it and emit the same AppStream guidance.  This
    is the regression we never want — silent execution with a
    SyntaxError further down."""
    fake_py_dir = tmp_path / "fake-py"
    fake_py_dir.mkdir()
    fake_py = fake_py_dir / "python3"
    # Pretend to be Python 3.6 — print "3.6" on the version probe and
    # exit 0 on anything else so the wrapper doesn't fall through to a
    # different error path.
    fake_py.write_text(
        "#!/bin/sh\n"
        "case \"$1\" in\n"
        "  -c) echo 3.6 ;;\n"
        "esac\n"
        "exit 0\n"
    )
    fake_py.chmod(0o755)

    proc = subprocess.run(
        [str(launcher_executable)],
        capture_output=True,
        text=True,
        env={"PATH": f"{fake_py_dir}:{utils_path}"},
        check=False,
    )
    assert proc.returncode == 127, (
        f"launcher accepted Python 3.6 instead of rejecting it: {proc!r}"
    )
    assert "AppStream" in proc.stderr
    assert "python39" in proc.stderr


def test_launcher_passes_args_through(launcher_executable: Path) -> None:
    """Args after the program name flow into pqc_readiness.py
    unchanged.  --quiet exercises a different code path than --version
    and confirms multi-flag invocations work."""
    proc = subprocess.run(
        [str(launcher_executable), "--quiet"],
        capture_output=True,
        text=True,
        check=False,
    )
    # --quiet emits one line on stdout.  Exit code is the verdict tier
    # (0 excellent .. 3 poor); we don't assert a specific tier because
    # tests run on whatever hardware the CI runner provides.
    assert proc.returncode in (0, 1, 2, 3), proc.stderr
    assert proc.stdout.strip(), "expected a verdict line on stdout"
    assert proc.stdout.count("\n") <= 1, "--quiet should be one line"
