# SPDX-License-Identifier: Apache-2.0
"""Streaming behaviour of the fleet aggregator (issue #88).

``run_aggregator`` must reduce reports one file at a time instead of
materialising every parsed report in a list, while ``aggregate_reports``
keeps working for callers that already hold an in-memory list."""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import pytest

import pqc_readiness as pr

ARCHES = ("x86_64", "aarch64", "s390x")
TIERS = ("excellent", "good", "marginal", "poor")


def _report(i: int) -> dict[str, Any]:
    return {
        "schema_version": pr.SCHEMA_VERSION,
        "arch": ARCHES[i % len(ARCHES)],
        "isa_tier": TIERS[i % len(TIERS)],
        "verdict": f"{TIERS[i % len(TIERS)].upper()} - synthetic",
        "cpu_model": f"cpu-{i % 5}",
        "kernel_info": {"os_release_id": "rhel" if i % 2 else "debian"},
        "runtime_environment": {"environment": "host"},
        "accelerators": [{"kind": "tpm"}, {"kind": "tpm"}] if i % 10 == 0 else [],
        "replace_required": i % 7 == 0,
    }


def _write_fleet(d: Path, n: int) -> list[dict[str, Any]]:
    reports = [_report(i) for i in range(n)]
    for i, r in enumerate(reports):
        (d / f"host-{i:04d}.json").write_text(json.dumps(r))
    return reports


def test_large_fleet_counts_are_correct(tmp_path: Path) -> None:
    n = 150
    _write_fleet(tmp_path, n)
    rollup = json.loads(pr.run_aggregator(tmp_path)[0])
    assert rollup["total_hosts"] == n
    assert rollup["skipped"] == []
    assert sum(rollup["by_arch"].values()) == n
    assert rollup["by_arch"] == {"x86_64": 50, "aarch64": 50, "s390x": 50}
    assert sum(rollup["by_isa_tier"].values()) == n
    assert rollup["by_os_release_id"] == {"debian": 75, "rhel": 75}
    # i % 10 == 0 for i < 150 → 15 hosts; duplicate kinds count once per host.
    assert rollup["accelerator_kinds_host_count"] == {"tpm": 15}
    # i % 7 == 0 for i < 150 → 0, 7, ..., 147 → 22 hosts.
    assert rollup["replace_required_count"] == 22
    assert rollup["unique_cpu_models"] == [f"cpu-{k}" for k in range(5)]


def test_run_aggregator_does_not_materialise_report_list(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_fleet(tmp_path, 120)
    real = pr.aggregate._aggregate_iter
    seen_types: list[type] = []

    def spy(reports: Iterable[dict[str, Any]]) -> dict[str, Any]:
        seen_types.append(type(reports))
        return real(reports)

    monkeypatch.setattr(pr.aggregate, "_aggregate_iter", spy)
    pr.run_aggregator(tmp_path)
    assert len(seen_types) == 1
    assert seen_types[0] is not list


def test_streaming_matches_in_memory_wrapper(tmp_path: Path) -> None:
    reports = _write_fleet(tmp_path, 101)
    streamed = json.loads(pr.run_aggregator(tmp_path)[0])
    streamed.pop("skipped")
    assert streamed == json.loads(json.dumps(pr.aggregate_reports(reports)))


def test_skips_are_recorded_while_streaming(tmp_path: Path) -> None:
    _write_fleet(tmp_path, 3)
    (tmp_path / "zz-old.json").write_text(json.dumps({"schema_version": "0.9"}))
    (tmp_path / "zz-list.json").write_text("[1, 2, 3]")
    rollup = json.loads(pr.run_aggregator(tmp_path)[0])
    assert rollup["total_hosts"] == 3
    reasons = {Path(s["file"]).name: s["reason"] for s in rollup["skipped"]}
    assert reasons["zz-old.json"].startswith("schema mismatch")
    assert reasons["zz-list.json"].startswith("unreadable")


def test_aggregate_reports_accepts_list_and_empty() -> None:
    assert pr.aggregate_reports([])["total_hosts"] == 0
    assert pr.aggregate_reports([_report(1)])["total_hosts"] == 1
