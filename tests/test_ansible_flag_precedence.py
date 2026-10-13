# SPDX-License-Identifier: Apache-2.0
"""--ansible vs --check / --fips-strict precedence (#95).

--ansible must always exit 0 so an Ansible play never fails a host on
its verdict, which means the --check and --fips-strict exit-code gates
cannot take effect under it.  The combination stays legal, but the
script now warns on stderr instead of silently ignoring the gate.
"""
from __future__ import annotations

import argparse
import json
import subprocess

import pqc_readiness as pr

from conftest import PQC_CLI, PQC_ENV


def _ns(**kw: object) -> argparse.Namespace:
    base: dict[str, object] = {"ansible": False, "check": None, "fips_strict": False}
    base.update(kw)
    return argparse.Namespace(**base)


def test_no_warning_without_ansible() -> None:
    assert pr.ansible_ignored_flag_warnings(_ns(check="good", fips_strict=True)) == []


def test_no_warning_for_plain_ansible() -> None:
    assert pr.ansible_ignored_flag_warnings(_ns(ansible=True)) == []


def test_warns_for_each_ignored_gate() -> None:
    warnings = pr.ansible_ignored_flag_warnings(
        _ns(ansible=True, check="cnsa-2.0", fips_strict=True)
    )
    assert len(warnings) == 2
    assert "--check cnsa-2.0 is ignored" in warnings[0]
    assert "--fips-strict is ignored" in warnings[1]


def test_end_to_end_warns_on_stderr_and_keeps_stdout_json() -> None:
    proc = subprocess.run(
        [*PQC_CLI, "--ansible", "--check", "excellent"],
        env=PQC_ENV,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert proc.returncode == 0
    assert "warning: --check excellent is ignored when --ansible is active" in proc.stderr
    assert "pqc_readiness" in json.loads(proc.stdout)["ansible_facts"]


def test_help_documents_precedence() -> None:
    proc = subprocess.run(
        [*PQC_CLI, "--help"],
        env=PQC_ENV,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    flat = " ".join(proc.stdout.split())
    assert "takes precedence over --check and --fips-strict" in flat
