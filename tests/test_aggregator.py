# SPDX-License-Identifier: Apache-2.0
"""Boundary cases for ``run_aggregator`` (fleet rollup over per-host JSON).

The happy paths for ``aggregate_reports`` and ``aggregate_to_csv`` are
covered in ``tests/test_parsers.py``.  This module exercises the documented
skip behaviour in ``run_aggregator`` itself: empty input, single host,
mixed schema versions, malformed JSON, and CSV format on an empty dir.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pqc_readiness as pr


def _valid_report(
    arch: str = "x86_64",
    isa: str = "excellent",
    cpu: str = "AMD EPYC",
) -> dict[str, Any]:
    return {
        "schema_version": pr.SCHEMA_VERSION,
        "arch": arch,
        "isa_tier": isa,
        "verdict": "EXCELLENT - software PQC at production speed",
        "cpu_model": cpu,
        "kernel_info": {"os_release_id": "rhel"},
        "runtime_environment": {"environment": "host"},
        "accelerators": [],
        "replace_required": False,
    }


def test_run_aggregator_empty_dir_emits_zero_hosts(tmp_path: Path) -> None:
    out_text, exit_code = pr.run_aggregator(tmp_path, output="json")
    assert exit_code == 0
    rollup = json.loads(out_text)
    assert rollup["total_hosts"] == 0
    assert rollup["skipped"] == []
    assert rollup["by_arch"] == {}
    assert rollup["replace_required_count"] == 0


def test_run_aggregator_single_host(tmp_path: Path) -> None:
    (tmp_path / "host1.json").write_text(json.dumps(_valid_report()))
    out_text, exit_code = pr.run_aggregator(tmp_path, output="json")
    assert exit_code == 0
    rollup = json.loads(out_text)
    assert rollup["total_hosts"] == 1
    assert rollup["by_arch"] == {"x86_64": 1}
    assert rollup["by_isa_tier"] == {"excellent": 1}
    assert rollup["unique_cpu_models"] == ["AMD EPYC"]
    assert rollup["skipped"] == []


def test_run_aggregator_mixed_schema_skips_old_version(tmp_path: Path) -> None:
    (tmp_path / "current.json").write_text(json.dumps(_valid_report()))
    old = _valid_report(arch="aarch64")
    old["schema_version"] = "0.9"
    old_path = tmp_path / "legacy.json"
    old_path.write_text(json.dumps(old))

    out_text, exit_code = pr.run_aggregator(tmp_path, output="json")
    assert exit_code == 0
    rollup = json.loads(out_text)
    # Only the current-schema file aggregates; the 0.9 file lands in skipped[].
    assert rollup["total_hosts"] == 1
    assert rollup["by_arch"] == {"x86_64": 1}
    assert len(rollup["skipped"]) == 1
    entry = rollup["skipped"][0]
    assert entry["file"] == str(old_path)
    assert entry["reason"] == (
        f"schema mismatch: file='0.9' expected={pr.SCHEMA_VERSION!r}"
    )


def test_run_aggregator_malformed_json_skipped_others_aggregate(
    tmp_path: Path,
) -> None:
    (tmp_path / "good.json").write_text(json.dumps(_valid_report()))
    bad_path = tmp_path / "broken.json"
    bad_path.write_text("{not: valid json,,,")

    out_text, exit_code = pr.run_aggregator(tmp_path, output="json")
    assert exit_code == 0
    rollup = json.loads(out_text)
    # The good file still aggregates.
    assert rollup["total_hosts"] == 1
    assert rollup["by_arch"] == {"x86_64": 1}
    # The malformed file is reported with an "unreadable:" reason.
    assert len(rollup["skipped"]) == 1
    entry = rollup["skipped"][0]
    assert entry["file"] == str(bad_path)
    assert entry["reason"].startswith("unreadable: ")


def test_run_aggregator_csv_on_empty_dir_emits_header_only(
    tmp_path: Path,
) -> None:
    out_text, exit_code = pr.run_aggregator(tmp_path, output="csv")
    assert exit_code == 0
    lines = [ln for ln in out_text.splitlines() if ln.strip()]
    # Header plus the two scalar rows (total_hosts, replace_required_count)
    # that aggregate_to_csv always emits, even for an empty rollup.
    assert lines[0] == "group,key,count"
    assert "total_hosts,,0" in lines
    assert "replace_required_count,,0" in lines
