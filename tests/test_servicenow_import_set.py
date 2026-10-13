# SPDX-License-Identifier: Apache-2.0
"""The ServiceNow Import Set sample (#156) against real --ndjson output.

No ServiceNow instance is involved: these tests pin what the sample
sends (the Import Set API's insertMultiple body, string-only columns)
and that the correlation ID a transform map coalesces on stays stable
across runs.
"""

from __future__ import annotations

import dataclasses
import importlib.util
import json
from pathlib import Path
from types import ModuleType

import pytest

import pqc_readiness as pr
from test_sarif import _full_trigger_report

SAMPLE = (
    Path(__file__).resolve().parent.parent / "deploy/servicenow/ndjson_to_import_set.py"
)


def _sample() -> ModuleType:
    spec = importlib.util.spec_from_file_location("ndjson_to_import_set", SAMPLE)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _ndjson(r: pr.Report) -> list[str]:
    return pr.render_ndjson(r).splitlines()


def test_only_findings_become_rows_with_string_values() -> None:
    lines = _ndjson(_full_trigger_report())
    findings = [json.loads(ln) for ln in lines if json.loads(ln)["class_uid"] == 2003]
    bodies = list(_sample().convert(lines))
    rows = [rec for body in bodies for rec in body["records"]]
    assert len(rows) == len(findings) > 0
    for rec in rows:
        # The Import Set API accepts only string values.
        assert all(isinstance(v, str) for v in rec.values())
        assert rec["u_correlation_id"]
        assert rec["u_rule_id"].startswith("pqc-")
        assert rec["u_hostname"]


def test_correlation_id_is_stable_across_runs_and_event_uid_is_not() -> None:
    r1 = _full_trigger_report()
    r2 = dataclasses.replace(r1, generated_at="2030-01-02T03:04:05+00:00")
    mod = _sample()
    rows1 = [rec for b in mod.convert(_ndjson(r1)) for rec in b["records"]]
    rows2 = [rec for b in mod.convert(_ndjson(r2)) for rec in b["records"]]
    assert [x["u_correlation_id"] for x in rows1] == [
        x["u_correlation_id"] for x in rows2
    ]
    assert [x["u_event_uid"] for x in rows1] != [x["u_event_uid"] for x in rows2]
    assert len({x["u_correlation_id"] for x in rows1}) == len(rows1)


def test_batching_and_time_format() -> None:
    lines = _ndjson(_full_trigger_report())
    mod = _sample()
    total = sum(len(b["records"]) for b in mod.convert(lines))
    small = list(mod.convert(lines, batch=1))
    assert len(small) == total
    assert all(len(b["records"]) == 1 for b in small)
    rec = small[0]["records"][0]
    # ServiceNow glide date-time format, UTC.
    assert len(rec["u_last_found"]) == 19 and rec["u_last_found"][10] == " "
    with pytest.raises(ValueError):
        list(mod.convert(lines, batch=0))


def test_cli_reads_files_and_writes_one_body_per_line(tmp_path: Path, capsys) -> None:
    f = tmp_path / "findings.ndjson"
    f.write_text("\n".join(_ndjson(_full_trigger_report())) + "\n")
    assert _sample().main([str(f), "--batch", "2"]) == 0
    out = capsys.readouterr().out.splitlines()
    assert out and all(set(json.loads(ln)) == {"records"} for ln in out)


def test_rejects_non_json_lines(tmp_path: Path) -> None:
    with pytest.raises(SystemExit, match="line 2"):
        list(_sample().convert(['{"class_uid": 5001}', "not json"]))
