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
OS_RELEASE_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "os-release"
# Guidance is family-aware (#127); pin the EL8 tests to an EL8 host so
# they do not depend on the OS of the machine running the suite.
EL8_OS_RELEASE = str(OS_RELEASE_FIXTURES / "rhel-8.txt")


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
        env={"PATH": utils_path, "PQC_READINESS_OS_RELEASE": EL8_OS_RELEASE},
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
    fake_py.write_text('#!/bin/sh\ncase "$1" in\n  -c) echo 3.6 ;;\nesac\nexit 0\n')
    fake_py.chmod(0o755)

    proc = subprocess.run(
        [str(launcher_executable)],
        capture_output=True,
        text=True,
        env={
            "PATH": f"{fake_py_dir}:{utils_path}",
            "PQC_READINESS_OS_RELEASE": EL8_OS_RELEASE,
        },
        check=False,
    )
    assert proc.returncode == 127, (
        f"launcher accepted Python 3.6 instead of rejecting it: {proc!r}"
    )
    assert "AppStream" in proc.stderr
    assert "python39" in proc.stderr


def test_launcher_passes_args_through(launcher_executable: Path) -> None:
    """Args after the program name flow into the zipapp / package
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


EL8_INSTALL_CMD = "sudo dnf module install -y python39"


def test_launcher_and_readme_give_the_same_el8_prerequisite(
    launcher_executable: Path, utils_path: str
) -> None:
    """Issue #36 was resolved by documenting the EL8 prerequisite rather
    than supporting platform-python 3.6.  The wrapper's guidance on a
    stock EL8 cloud image (no python3 on PATH) and the README must give
    the operator the same copy-pasteable install command, and the README
    must explain the bare-script failure mode operators actually see."""
    proc = subprocess.run(
        [str(launcher_executable)],
        capture_output=True,
        text=True,
        env={"PATH": utils_path, "PQC_READINESS_OS_RELEASE": EL8_OS_RELEASE},
        check=False,
    )
    assert proc.returncode == 127
    assert EL8_INSTALL_CMD in proc.stderr
    assert "platform-python" in proc.stderr

    readme = REPO_ROOT / "README.md"
    if not readme.exists():
        pytest.skip("README.md not present in this checkout")
    text = readme.read_text(encoding="utf-8")
    assert EL8_INSTALL_CMD in text
    assert "/usr/bin/env: 'python3': No such file or directory" in text


# ---------------------------------------------------------------------------
# Family-aware guidance (#127)
# ---------------------------------------------------------------------------

SUSE_INSTALL_CMD = "sudo zypper -n in python311"


def _no_python_guidance(
    utils_path: str, os_release: str
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(LAUNCHER)],
        capture_output=True,
        text=True,
        env={"PATH": utils_path, "PQC_READINESS_OS_RELEASE": os_release},
        check=False,
    )


@pytest.mark.parametrize(
    ("fixture", "expected", "absent"),
    [
        ("sles-15sp6.txt", SUSE_INSTALL_CMD, "dnf module install"),
        ("opensuse-leap-156.txt", SUSE_INSTALL_CMD, "dnf module install"),
        ("rhel-8.txt", EL8_INSTALL_CMD, "zypper"),
        ("rocky-8.txt", EL8_INSTALL_CMD, "zypper"),  # via ID_LIKE
        ("almalinux-8.txt", EL8_INSTALL_CMD, "zypper"),
        ("ubuntu-2404.txt", "sudo apt-get install -y python3", "zypper"),
        ("debian-12.txt", "sudo apt-get install -y python3", "dnf module install"),
    ],
)
def test_launcher_guidance_matches_host_family(
    launcher_executable: Path, utils_path: str, fixture: str, expected: str, absent: str
) -> None:
    proc = _no_python_guidance(utils_path, str(OS_RELEASE_FIXTURES / fixture))
    assert proc.returncode == 127
    assert expected in proc.stderr
    assert absent not in proc.stderr


def test_launcher_suse_guidance_refreshes_repos_first(
    launcher_executable: Path, utils_path: str
) -> None:
    # Minimal SUSE images may have no usable repo metadata yet, and
    # non-interactive zypper won't import repo keys on its own, so the
    # refresh (with key auto-import) must come before the install.
    proc = _no_python_guidance(utils_path, str(OS_RELEASE_FIXTURES / "sles-15sp6.txt"))
    err = proc.stderr
    assert "zypper --gpg-auto-import-keys ref" in err
    assert err.index("zypper --gpg-auto-import-keys ref") < err.index(SUSE_INSTALL_CMD)


def test_launcher_unknown_family_lists_the_common_hints(
    launcher_executable: Path, utils_path: str
) -> None:
    proc = _no_python_guidance(utils_path, str(OS_RELEASE_FIXTURES / "arch.txt"))
    assert proc.returncode == 127
    assert "dnf module install -y python39" in proc.stderr
    assert "zypper -n in python311" in proc.stderr


def test_launcher_finds_side_installed_python311(
    launcher_executable: Path, utils_path: str, tmp_path: Path
) -> None:
    """SLES/Leap after `zypper in python311`: `python3` is still 3.6 and
    a separate `python3.11` exists.  The launcher must pick python3.11."""
    bin_dir = tmp_path / "py"
    bin_dir.mkdir()
    old = bin_dir / "python3"
    old.write_text('#!/bin/sh\ncase "$1" in -c) echo 3.6 ;; esac\nexit 0\n')
    new = bin_dir / "python3.11"
    marker = tmp_path / "ran-with"
    new.write_text(
        '#!/bin/sh\ncase "$1" in -c) echo 3.11 ; exit 0 ;; esac\n'
        f'echo "$@" > {marker}\nexit 0\n'
    )
    for f in (old, new):
        f.chmod(0o755)
    proc = subprocess.run(
        [str(launcher_executable), "--version"],
        capture_output=True,
        text=True,
        env={"PATH": f"{bin_dir}:{utils_path}"},
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    ran = marker.read_text()
    assert "--version" in ran
    assert "pqc_readiness" in ran or "pqc-readiness.pyz" in ran


def test_launcher_and_readme_give_the_same_suse_prerequisite(
    launcher_executable: Path, utils_path: str
) -> None:
    proc = _no_python_guidance(utils_path, str(OS_RELEASE_FIXTURES / "sles-15sp6.txt"))
    assert SUSE_INSTALL_CMD in proc.stderr
    readme = REPO_ROOT / "README.md"
    if not readme.exists():
        pytest.skip("README.md not present in this checkout")
    text = readme.read_text(encoding="utf-8")
    assert SUSE_INSTALL_CMD in text
    assert "zypper --gpg-auto-import-keys ref" in text
