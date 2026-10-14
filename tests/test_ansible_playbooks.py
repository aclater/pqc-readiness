# SPDX-License-Identifier: Apache-2.0
"""The example playbooks must not fail a host on its readiness verdict.

pqc-readiness exits 0-3 for the verdict (excellent .. poor) and 4/5 for a
gate or write failure.  `ansible.builtin.script` fails a task on any
non-zero exit, so playbook-fleet-aggregate.yml failed on every host whose
verdict wasn't "excellent" until it gained a `failed_when` (#218).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

yaml = pytest.importorskip("yaml")

ANSIBLE = Path(__file__).resolve().parent.parent / "deploy" / "ansible"
if not ANSIBLE.is_dir():  # container test images ship tests/ but not deploy/
    pytest.skip("deploy/ not present", allow_module_level=True)


def _scanner_script_tasks() -> list[tuple[str, dict[str, Any]]]:
    out = []
    for path in sorted(ANSIBLE.glob("playbook-*.yml")):
        for play in yaml.safe_load(path.read_text()) or []:
            for task in play.get("tasks", []):
                script = task.get("ansible.builtin.script")
                if script and "pqc-readiness" in str(script):
                    out.append((path.name, task))
    return out


def test_playbooks_run_the_scanner() -> None:
    names = {name for name, _ in _scanner_script_tasks()}
    assert {"playbook-fleet-aggregate.yml", "playbook-cbom-collect.yml"} <= names


@pytest.mark.parametrize(
    "name,task", _scanner_script_tasks(), ids=lambda v: v if isinstance(v, str) else ""
)
def test_verdict_exit_codes_do_not_fail_the_task(
    name: str, task: dict[str, Any]
) -> None:
    cmd = str(task["ansible.builtin.script"])
    if "--ansible" in cmd:
        return  # --ansible always exits 0
    failed_when = str(task.get("failed_when", ""))
    assert "rc not in [0, 1, 2, 3]" in failed_when, (
        f"{name}: task {task.get('name')!r} runs the scanner without "
        "failed_when accepting verdict exit codes 0-3"
    )
