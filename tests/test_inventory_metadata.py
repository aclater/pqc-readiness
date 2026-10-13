"""--inventory-metadata FILE (#144): validation, CLI wiring, report field."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from pqc_readiness import inventory_metadata as im

FULL: dict[str, Any] = {
    "fisma_system_id": "ABC-1234",
    "fips199_categorization": "moderate",
    "hva_id": "HVA-0042",
    "hosting": {"model": "commercial-csp", "provider": "Example Cloud"},
    "data_lifecycle": {"records_categories": ["GRS 3.2"], "time_to_live_years": 25},
    "notes": "pilot system",
}


def _write(tmp_path: Path, data: Any, name: str = "meta.json") -> Path:
    p = tmp_path / name
    p.write_text(json.dumps(data) if not isinstance(data, str) else data)
    return p


def test_full_file_is_normalised() -> None:
    out = im.validate(FULL)
    assert out["fips199_categorization"] == "Moderate"
    assert list(out) == [
        "fisma_system_id",
        "fips199_categorization",
        "hva_id",
        "hosting",
        "data_lifecycle",
        "notes",
    ]
    assert out["hosting"] == {"model": "commercial-csp", "provider": "Example Cloud"}


def test_every_key_is_optional() -> None:
    assert im.validate({}) == {}


def test_on_premises_needs_no_provider() -> None:
    assert im.validate({"hosting": {"model": "on-premises"}}) == {
        "hosting": {"model": "on-premises"}
    }


@pytest.mark.parametrize(
    ("data", "message"),
    [
        ([], "top level must be a JSON object"),
        ({"fisma_id": "x"}, "unknown key"),
        ({"fisma_system_id": ""}, "fisma_system_id must be a non-empty string"),
        ({"fisma_system_id": 7}, "fisma_system_id must be a non-empty string"),
        ({"fips199_categorization": "Severe"}, "fips199_categorization must be one of"),
        ({"hosting": {"model": "cloud"}}, "hosting.model must be one of"),
        ({"hosting": {"model": "hybrid"}}, "hosting.provider (required for hybrid)"),
        ({"hosting": {"model": "on-premises", "region": "x"}}, "hosting: unknown key"),
        ({"hosting": "on-premises"}, "hosting must be an object"),
        ({"data_lifecycle": {"records_categories": []}}, "non-empty list"),
        ({"data_lifecycle": {"time_to_live_years": -1}}, "number >= 0"),
        ({"data_lifecycle": {"time_to_live_years": True}}, "number >= 0"),
        ({"data_lifecycle": {"ttl": 3}}, "data_lifecycle: unknown key"),
    ],
)
def test_invalid_metadata_is_rejected(data: Any, message: str) -> None:
    with pytest.raises(im.InventoryMetadataError, match=None) as exc:
        im.validate(data)
    assert message in str(exc.value)


def test_load_rejects_unreadable_and_invalid_files(tmp_path: Path) -> None:
    with pytest.raises(im.InventoryMetadataError, match="No such file"):
        im.load(str(tmp_path / "missing.json"))
    with pytest.raises(im.InventoryMetadataError, match="not valid JSON"):
        im.load(str(_write(tmp_path, "{not json")))
    big = _write(tmp_path, '{"notes": "' + "x" * im.MAX_BYTES + '"}', "big.json")
    with pytest.raises(im.InventoryMetadataError, match="exceeds"):
        im.load(str(big))


def test_cli_parses_file_into_args(tmp_path: Path) -> None:
    from pqc_readiness import cli

    args = cli.build_parser().parse_args(
        ["--inventory-metadata", str(_write(tmp_path, FULL))]
    )
    assert args.inventory_metadata["fips199_categorization"] == "Moderate"
    assert cli.build_parser().parse_args([]).inventory_metadata is None


def test_cli_bad_file_is_a_usage_error_before_probing(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    from pqc_readiness import cli

    def no_probe(args: Any) -> Any:
        raise AssertionError("must fail at argument parsing, before probing")

    monkeypatch.setattr(cli, "collect_report", no_probe)
    bad = _write(tmp_path, {"fips199_categorization": "Severe"})
    with pytest.raises(SystemExit) as exc:
        cli.main(["--json", "--inventory-metadata", str(bad)])
    assert exc.value.code == 2
    assert "fips199_categorization must be one of" in capsys.readouterr().err


def test_json_report_carries_the_metadata(tmp_path: Path, monkeypatch, capsys) -> None:
    """The real collect_report (host probes stubbed) copies the parsed
    metadata into the Report, so --json / --ansible / aggregation carry it."""
    from test_main_decompose import _stub_host

    from pqc_readiness import cli

    _stub_host(monkeypatch)
    meta = _write(tmp_path, FULL)
    cli.main(["--json", "--inventory-metadata", str(meta)])
    out = json.loads(capsys.readouterr().out)
    assert out["inventory_metadata"]["fisma_system_id"] == "ABC-1234"
    assert out["inventory_metadata"]["hosting"]["provider"] == "Example Cloud"
    cli.main(["--json"])
    assert json.loads(capsys.readouterr().out)["inventory_metadata"] is None
