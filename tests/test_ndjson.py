"""SIEM-shaped NDJSON output (--ndjson, #146).

Every event is validated against the OCSF 1.9.0 JSON Schema exported from
schema.ocsf.io (base classes, no profiles), bundled under
tests/fixtures/ocsf/ so CI is hermetic.  The schema sets
additionalProperties: false, so a misspelt or invented field fails here.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

import pytest

import pqc_readiness as pr
from conftest import FIXTURES
from test_sarif import _empty_report, _full_trigger_report

OCSF = FIXTURES / "ocsf" / "1.9.0"
ndjson = pr.render.ndjson
sarif = pr.render.sarif


def _schema(name: str) -> dict[str, Any]:
    return json.loads((OCSF / f"{name}.schema.json").read_text())


def _validate(event: dict[str, Any]) -> None:
    jsonschema = pytest.importorskip("jsonschema")
    name = {2003: "compliance_finding", 5001: "inventory_info"}[event["class_uid"]]
    jsonschema.Draft7Validator(_schema(name)).validate(event)


def _events(r: pr.Report) -> list[dict[str, Any]]:
    text = pr.render_ndjson(r)
    lines = text.split("\n")
    assert all(line.strip() for line in lines), "no blank lines"
    return [json.loads(line) for line in lines]


def test_every_event_validates_against_ocsf_schema() -> None:
    events = _events(_full_trigger_report())
    assert len(events) == 1 + len(pr.RULE_SPECS)
    for event in events:
        _validate(event)


def test_summary_first_then_one_finding_per_rule_in_rule_order() -> None:
    r = _full_trigger_report()
    events = _events(r)
    summary, findings = events[0], events[1:]
    assert summary["class_uid"] == 5001
    assert summary["type_uid"] == 500101
    assert summary["unmapped"]["pqc_readiness"]["findings_count"] == len(findings)
    assert [e["compliance"]["control"] for e in findings] == [
        f.rule_id for f in sarif.build_findings(r)
    ]
    assert {e["type_uid"] for e in findings} == {200301}


def test_clean_host_emits_only_the_summary() -> None:
    events = _events(_empty_report())
    assert [e["class_uid"] for e in events] == [5001]
    _validate(events[0])


def test_finding_uid_is_stable_and_shared_with_sarif() -> None:
    r = _full_trigger_report()
    first = [e["finding_info"]["uid"] for e in _events(r)[1:]]
    second = [e["finding_info"]["uid"] for e in _events(r)[1:]]
    assert first == second
    rules = [e["compliance"]["control"] for e in _events(r)[1:]]
    assert first == [sarif.finding_fingerprint(r.hostname, rule) for rule in rules]


def test_event_uid_changes_per_run_but_finding_uid_does_not() -> None:
    r1 = _full_trigger_report()
    r2 = _full_trigger_report()
    r2.generated_at = "2030-01-02T00:00:00+00:00"
    e1, e2 = _events(r1)[1], _events(r2)[1]
    assert e1["finding_info"]["uid"] == e2["finding_info"]["uid"]
    assert e1["metadata"]["uid"] != e2["metadata"]["uid"]


def test_time_is_epoch_milliseconds_of_generated_at() -> None:
    r = _full_trigger_report()
    expected = int(datetime.fromisoformat(r.generated_at).timestamp() * 1000)
    assert {e["time"] for e in _events(r)} == {expected}


@pytest.mark.parametrize(
    ("score", "severity_id"),
    [(None, 1), ("2.0", 2), ("3.9", 2), ("4.0", 3), ("6.9", 3), ("7.0", 4), ("8.9", 4)],
)
def test_severity_follows_cvss_bands(score: str | None, severity_id: int) -> None:
    assert ndjson._severity_id(score) == severity_id


def test_lines_are_compact_single_line_json() -> None:
    text = pr.render_ndjson(_full_trigger_report())
    for line in text.split("\n"):
        assert "\n" not in line
        assert json.loads(line) == json.loads(json.dumps(json.loads(line)))


def test_cli_ndjson_flag_selects_the_format(monkeypatch, capsys) -> None:
    from pqc_readiness import cli

    monkeypatch.setattr(cli, "collect_report", lambda args: _full_trigger_report())
    cli.main(["--ndjson"])
    lines = capsys.readouterr().out.strip().split("\n")
    assert json.loads(lines[0])["class_uid"] == 5001
    assert len(lines) == 1 + len(pr.RULE_SPECS)
