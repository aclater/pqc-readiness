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

The second half of the file covers the *polyglot shebang* baked into
``pqc_readiness.py`` itself (issue #36).  EL8 cloud images ship no
``/usr/bin/python3`` symlink, so users who invoke the .py directly
(rather than through the ``pqc-readiness`` wrapper) used to get
``/usr/bin/env: 'python3': No such file or directory`` and exit 127
before the script could even run.  The polyglot replicates the
wrapper's interpreter probe inline, so direct invocation now gets the
same AppStream guidance instead of a cryptic env(1) error.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
LAUNCHER = REPO_ROOT / "pqc-readiness"
SCRIPT = REPO_ROOT / "pqc_readiness.py"


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


# ---------------------------------------------------------------------------
# Polyglot shebang on pqc_readiness.py itself (issue #36).
#
# The .py file's shebang is `#!/bin/sh` followed by a sh/Python polyglot
# block that probes for a usable interpreter and execs the script under
# it.  This makes direct invocation safe on EL8 cloud images that ship
# no /usr/bin/python3 symlink — the regression we're guarding against
# is the original `env: 'python3': No such file or directory` exit 127.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def script_executable() -> Path:
    """The .py script must be present and executable so the polyglot
    shebang fires on direct invocation.  A non-executable file would
    force callers through `python3 pqc_readiness.py`, defeating the
    purpose of the polyglot."""
    assert SCRIPT.exists(), f"script missing at {SCRIPT}"
    assert os.access(SCRIPT, os.X_OK), f"script not executable: {SCRIPT}"
    return SCRIPT


def test_polyglot_shebang_is_sh_not_env_python3() -> None:
    """The shebang must be `#!/bin/sh` so EL8 cloud images (which lack a
    /usr/bin/python3 symlink) can run the polyglot interpreter probe.

    Regression for #36: prior to the polyglot, the shebang was
    `#!/usr/bin/env python3` and aborted with exit 127 before any
    Python code ran.  This test pins the shebang in a way that
    `env python3` cannot pass."""
    first_line = SCRIPT.read_text(encoding="utf-8").splitlines()[0]
    assert first_line == "#!/bin/sh", (
        f"expected `#!/bin/sh` polyglot shebang, got: {first_line!r}.  "
        "Reverting to `#!/usr/bin/env python3` reintroduces the EL8 "
        "exit-127 regression tracked in issue #36."
    )


def test_polyglot_runs_under_current_python(script_executable: Path) -> None:
    """Happy path: the developer's Python is 3.9+, the polyglot finds
    it, and `--version` returns the schema version line.  Mirrors the
    wrapper's happy-path test against the .py directly."""
    proc = subprocess.run(
        [str(script_executable), "--version"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert "pqc-readiness" in proc.stdout
    assert "schema" in proc.stdout


def test_polyglot_no_python_on_path_emits_appstream_guidance(
    script_executable: Path, utils_path: str
) -> None:
    """EL8 cloud-image reproducer: no Python interpreter on PATH at
    all.  Direct invocation `./pqc_readiness.py` must exit 127 with
    the AppStream guidance — the same actionable message the wrapper
    emits — instead of `env: 'python3': No such file or directory`.

    This is the core regression from #36: distro-matrix runs against
    fresh RHEL/Rocky/Alma 8 cloud qcow2s saw exit 127 with no JSON
    output before this fix."""
    proc = subprocess.run(
        [str(script_executable)],
        capture_output=True,
        text=True,
        env={"PATH": utils_path},
        check=False,
    )
    assert proc.returncode == 127, proc.stderr
    assert "AppStream" in proc.stderr
    assert "python39" in proc.stderr
    assert "dnf module install" in proc.stderr
    # Negative assertion: confirm the failure is *not* the env(1) error
    # that motivated this fix.  If the polyglot ever silently regresses
    # to `#!/usr/bin/env python3`, env's message would leak through here.
    assert "/usr/bin/env" not in proc.stderr
    assert "No such file or directory" not in proc.stderr


def test_polyglot_only_old_python_emits_appstream_guidance(
    script_executable: Path, utils_path: str, tmp_path: Path
) -> None:
    """RHEL 8 reality with the AppStream module *not* installed: a
    too-old `python3` (3.6) is on PATH.  The polyglot must reject it
    via the version probe and emit the AppStream guidance, not silently
    fall through to a Python `SyntaxError` on modern type-hint syntax."""
    fake_py_dir = tmp_path / "fake-py-script"
    fake_py_dir.mkdir()
    fake_py = fake_py_dir / "python3"
    # Pretend to be Python 3.6 — print "3.6" on the version probe and
    # exit 0 on anything else so the polyglot doesn't fall through to a
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
        [str(script_executable)],
        capture_output=True,
        text=True,
        env={"PATH": f"{fake_py_dir}:{utils_path}"},
        check=False,
    )
    assert proc.returncode == 127, (
        f"polyglot accepted Python 3.6 instead of rejecting it: {proc!r}"
    )
    assert "AppStream" in proc.stderr
    assert "python39" in proc.stderr


def test_polyglot_passes_args_through(script_executable: Path) -> None:
    """Args after the program name flow into the underlying Python
    script unchanged.  Confirms the polyglot's `exec "$c" "$0" "$@"`
    line does not eat or reorder positional arguments."""
    proc = subprocess.run(
        [str(script_executable), "--quiet"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode in (0, 1, 2, 3), proc.stderr
    assert proc.stdout.strip(), "expected a verdict line on stdout"
    assert proc.stdout.count("\n") <= 1, "--quiet should be one line"


def test_polyglot_module_doc_preserved(script_executable: Path) -> None:
    """The polyglot must not corrupt `__doc__` — argparse uses it as
    the `--help` description.  `--help` includes the docstring's
    leading sentence, so we assert that fragment is reachable through
    a real CLI invocation rather than poking at module internals."""
    proc = subprocess.run(
        [str(script_executable), "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert (
        "assess host suitability for Post-Quantum Cryptography"
        in proc.stdout
    ), "module docstring not surfaced through argparse --help"
