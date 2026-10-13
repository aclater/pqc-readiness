# SPDX-License-Identifier: Apache-2.0
"""--output FILE (issue #89): write any report format to a chosen path."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

import pqc_readiness as pr

from conftest import PQC_CLI, PQC_ENV


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [*PQC_CLI, *args],
        env=PQC_ENV,
        capture_output=True,
        text=True,
        timeout=120,
    )


@pytest.mark.parametrize(
    "fmt_args, check",
    [
        (["--json"], "json"),
        (["--cbom"], "json"),
        (["--spdx"], "json"),
        (["--sarif"], "json"),
        (["--ansible"], "json"),
        (["--recommend", "--json"], "json"),
        (["--markdown"], "text"),
        (["--quiet"], "text"),
        ([], "text"),
    ],
)
def test_output_writes_file_and_keeps_stdout_empty(
    tmp_path: Path, fmt_args: list[str], check: str
) -> None:
    dest = tmp_path / "report.out"
    proc = _run("--no-color", *fmt_args, "--output", str(dest))
    assert proc.stdout == ""
    assert dest.is_file()
    text = dest.read_text()
    assert text.strip()
    if check == "json":
        json.loads(text)
    else:
        assert "\x1b[" not in text  # never ANSI colour in a file


def test_output_matches_stdout_json(tmp_path: Path) -> None:
    dest = tmp_path / "r.json"
    _run("--json", "--output", str(dest))
    from_file = json.loads(dest.read_text())
    from_stdout = json.loads(_run("--json").stdout)
    # generated_at differs between runs; everything else is host-stable.
    from_file.pop("generated_at")
    from_stdout.pop("generated_at")
    assert from_file.keys() == from_stdout.keys()


def test_output_with_aggregate(tmp_path: Path) -> None:
    fleet = tmp_path / "fleet"
    fleet.mkdir()
    (fleet / "h.json").write_text(json.dumps({"schema_version": pr.SCHEMA_VERSION}))
    dest = tmp_path / "rollup.csv"
    proc = _run("--aggregate", str(fleet), "--aggregate-format", "csv", "--output", str(dest))
    assert proc.returncode == 0
    assert proc.stdout == ""
    assert dest.read_text().startswith("group,key,count")


def test_missing_parent_is_usage_error_and_creates_nothing(tmp_path: Path) -> None:
    dest = tmp_path / "missing" / "deeper" / "r.json"
    proc = _run("--json", "--output", str(dest))
    assert proc.returncode == 2
    assert "does not exist" in proc.stderr
    assert not (tmp_path / "missing").exists()


def test_output_pointing_at_directory_is_usage_error(tmp_path: Path) -> None:
    proc = _run("--json", "--output", str(tmp_path))
    assert proc.returncode == 2
    assert "is a directory" in proc.stderr


def test_output_and_save_are_mutually_exclusive(tmp_path: Path) -> None:
    proc = _run("--save", "--output", str(tmp_path / "r.json"))
    assert proc.returncode == 2
    assert "not allowed with argument" in proc.stderr


def test_emit_reports_write_failure(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # A directory path passes no validation here and fails at write time,
    # standing in for a disk-full / permission race after probing.
    assert pr.cli._emit("x", tmp_path) is False
    assert "cannot write" in capsys.readouterr().err


def test_emit_without_path_prints(capsys: pytest.CaptureFixture[str]) -> None:
    assert pr.cli._emit("hello", None) is True
    assert capsys.readouterr().out == "hello\n"
