# SPDX-License-Identifier: Apache-2.0
"""Boundary cases for ``run_aggregator`` (fleet rollup over per-host JSON).

The happy paths for ``aggregate_reports`` and ``aggregate_to_csv`` are
covered in ``tests/test_parsers.py``.  This module exercises the documented
skip behaviour in ``run_aggregator`` itself: empty input, single host,
mixed schema versions, malformed JSON, and CSV format on an empty dir.
"""

from __future__ import annotations

import csv
import io
import json
import math
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


_ROLLUP_COUNTER_KEYS = (
    "by_arch",
    "by_os_release_id",
    "by_isa_tier",
    "by_verdict",
    "by_runtime_environment",
    "accelerator_kinds_host_count",
    "host_fs_detections_unavailable_host_count",
)


def test_run_aggregator_empty_dir_emits_zero_hosts(tmp_path: Path) -> None:
    out_text, exit_code = pr.run_aggregator(tmp_path, output="json")
    assert exit_code == 0
    rollup = json.loads(out_text)
    assert rollup["total_hosts"] == 0
    assert rollup["skipped"] == []
    assert rollup["by_arch"] == {}
    assert rollup["replace_required_count"] == 0


def test_run_aggregator_empty_dir_emits_every_rollup_key_empty(
    tmp_path: Path,
) -> None:
    """A DaemonSet volume before any pod reports is an empty dir.  The
    rollup must still carry the full key set (zeroed) so dashboards and
    CSV loaders see a stable shape rather than missing columns."""
    out_text, _ = pr.run_aggregator(tmp_path, output="json")
    rollup = json.loads(out_text)
    assert rollup["schema_version"] == pr.SCHEMA_VERSION
    for key in _ROLLUP_COUNTER_KEYS:
        assert rollup[key] == {}, key
    assert rollup["unique_cpu_models"] == []
    assert rollup["replace_required_count"] == 0
    assert rollup["skipped"] == []


def test_aggregate_reports_empty_list_matches_run_aggregator_shape(
    tmp_path: Path,
) -> None:
    """Programmatic callers hit aggregate_reports directly; its empty-input
    result must have the same keys as the run_aggregator path (minus the
    `skipped` list run_aggregator adds)."""
    direct = pr.aggregate_reports([])
    via_dir = json.loads(pr.run_aggregator(tmp_path, output="json")[0])
    via_dir.pop("skipped")
    assert direct == via_dir


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


def _assert_all_finite(value: Any, path: str = "rollup") -> None:
    """Recursively assert no NaN/Inf hides anywhere in a rollup."""
    if isinstance(value, float):
        assert math.isfinite(value), f"{path} is {value!r}"
    elif isinstance(value, dict):
        for k, v in value.items():
            _assert_all_finite(v, f"{path}.{k}")
    elif isinstance(value, list):
        for i, v in enumerate(value):
            _assert_all_finite(v, f"{path}[{i}]")


def test_aggregate_reports_single_host_counts_are_one() -> None:
    """Degenerate one-host fleet: every populated counter is exactly 1 and
    no averaging/division artifact (NaN/Inf) appears."""
    report = _valid_report()
    report["accelerators"] = [{"kind": "hsm"}, {"kind": "hsm"}]
    report["replace_required"] = True
    report["host_fs_detections_unavailable"] = {
        "tpm_pqc": {"unavailable_in_container": True},
    }
    rollup = pr.aggregate_reports([report])
    assert rollup["total_hosts"] == 1
    assert rollup["replace_required_count"] == 1
    assert rollup["unique_cpu_models"] == ["AMD EPYC"]
    for key in _ROLLUP_COUNTER_KEYS:
        assert all(v == 1 for v in rollup[key].values()), (key, rollup[key])
    # Duplicate accelerator kinds on one host still count that host once.
    assert rollup["accelerator_kinds_host_count"] == {"hsm": 1}
    assert rollup["host_fs_detections_unavailable_host_count"] == {"tpm_pqc": 1}
    assert rollup["by_verdict"] == {"EXCELLENT": 1}
    _assert_all_finite(rollup)
    # And the rollup is strict-JSON serialisable (json rejects NaN/Inf).
    json.dumps(rollup, allow_nan=False)


def test_aggregate_to_csv_single_host() -> None:
    rollup = pr.aggregate_reports([_valid_report()])
    rows = list(csv.reader(io.StringIO(pr.aggregate_to_csv(rollup))))
    assert rows[0] == ["group", "key", "count"]
    assert ["total_hosts", "", "1"] in rows
    assert ["replace_required_count", "", "0"] in rows
    assert ["by_arch", "x86_64", "1"] in rows
    assert ["by_isa_tier", "excellent", "1"] in rows
    assert ["unique_cpu_models", "AMD EPYC", "1"] in rows
    for row in rows[1:]:
        assert len(row) == 3
        assert row[2].lower() not in ("nan", "inf", "-inf"), row


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


def test_run_aggregator_mixed_schema_counts_only_current_version(
    tmp_path: Path,
) -> None:
    """Fleet dirs accumulate reports across tool upgrades.  Several older
    versions, a newer major, and a report with no schema_version at all
    must each be skipped with a reason; total_hosts counts only the
    current-schema reports."""
    for i in range(2):
        (tmp_path / f"current-{i}.json").write_text(
            json.dumps(_valid_report(cpu=f"cpu-{i}"))
        )
    mismatched = {"v0_9.json": "0.9", "v1_0.json": "1.0", "v9_0.json": "9.0"}
    for name, version in mismatched.items():
        stale = _valid_report(arch="aarch64")
        stale["schema_version"] = version
        (tmp_path / name).write_text(json.dumps(stale))
    unversioned = _valid_report(arch="s390x")
    del unversioned["schema_version"]
    (tmp_path / "unversioned.json").write_text(json.dumps(unversioned))

    rollup = json.loads(pr.run_aggregator(tmp_path, output="json")[0])
    assert rollup["total_hosts"] == 2
    assert rollup["by_arch"] == {"x86_64": 2}
    assert rollup["unique_cpu_models"] == ["cpu-0", "cpu-1"]
    reasons = {Path(s["file"]).name: s["reason"] for s in rollup["skipped"]}
    for name, version in mismatched.items():
        assert reasons[name] == (
            f"schema mismatch: file={version!r} expected={pr.SCHEMA_VERSION!r}"
        )
    assert reasons["unversioned.json"] == (
        f"schema mismatch: file=None expected={pr.SCHEMA_VERSION!r}"
    )
    assert len(reasons) == 4


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
