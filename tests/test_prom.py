"""--prometheus output for node_exporter's textfile collector (#140)."""

from __future__ import annotations

import argparse
import os
import re
import stat
from pathlib import Path
from typing import Any

import pytest

import pqc_readiness as pr
from test_main_decompose import _stub_host

_SAMPLE = re.compile(
    r"^(?P<name>[a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(?P<labels>[^}]*)\})? (?P<value>\S+)$"
)
_LABEL = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"')
# Bounded label names only: no hostnames, certificate names or algorithm lists.
_ALLOWED_LABELS = {
    "version",
    "schema",
    "tier",
    "protocol",
    "kind",
    "layer",
    "status",
    "category",
}


def _parse(text: str) -> dict[tuple[str, frozenset[tuple[str, str]]], float]:
    """Minimal text-format parser: every sample belongs to a family that
    has HELP and TYPE lines first, and no series repeats."""
    typed: set[str] = set()
    helped: set[str] = set()
    series: dict[tuple[str, frozenset[tuple[str, str]]], float] = {}
    for line in text.splitlines():
        if line.startswith("# HELP "):
            helped.add(line.split()[2])
            continue
        if line.startswith("# TYPE "):
            _, _, name, mtype = line.split()
            assert mtype == "gauge", line
            typed.add(name)
            continue
        m = _SAMPLE.match(line)
        assert m, f"not a sample line: {line!r}"
        name = m["name"]
        assert name in helped and name in typed, f"{name} lacks HELP/TYPE"
        assert name.startswith("pqc_readiness_")
        labels = frozenset(_LABEL.findall(m["labels"] or ""))
        assert {k for k, _ in labels} <= _ALLOWED_LABELS, line
        key = (name, labels)
        assert key not in series, f"duplicate series {line!r}"
        series[key] = float(m["value"])
    return series


def _value(series: dict[Any, float], name: str, **labels: str) -> float | None:
    return series.get((f"pqc_readiness_{name}", frozenset(labels.items())))


def _names(series: dict[Any, float]) -> set[str]:
    return {name for name, _ in series}


def _args(*argv: str) -> argparse.Namespace:
    return pr.build_parser().parse_args(list(argv))


@pytest.fixture()
def stubbed(monkeypatch: pytest.MonkeyPatch) -> pr.Report:
    _stub_host(monkeypatch)
    return pr.collect_report(_args())


def test_stubbed_host_output_is_well_formed(stubbed: pr.Report) -> None:
    series = _parse(pr.render_prometheus(stubbed))
    assert (
        _value(series, "info", version=pr.SCRIPT_VERSION, schema=pr.SCHEMA_VERSION) == 1
    )
    assert _value(series, "last_run_timestamp_seconds") is not None


@pytest.mark.parametrize(
    ("exit_code", "tier"), [(0, "excellent"), (1, "good"), (2, "marginal"), (3, "poor")]
)
def test_verdict_tier_is_a_state_set(exit_code: int, tier: str) -> None:
    series = _parse(pr.render_prometheus(pr.Report(exit_code=exit_code)))
    states = {
        dict(lbl)["tier"]: v
        for (name, lbl), v in series.items()
        if name.endswith("_verdict_tier")
    }
    assert states == {
        t: (1.0 if t == tier else 0.0)
        for t in ("excellent", "good", "marginal", "poor")
    }


def _report(**overrides: Any) -> pr.Report:
    r = pr.Report(exit_code=1)
    for k, v in overrides.items():
        setattr(r, k, v)
    return r


def test_group_counts_and_hybrid_availability() -> None:
    r = _report(
        openssl={
            "available": True,
            "pqc_native": True,
            "tls_groups": {
                "pure_pqc": ["MLKEM768"],
                "hybrid": ["X25519MLKEM768", "SecP384r1MLKEM1024"],
                "classical": ["x25519"],
            },
        },
        ssh_pqc={
            "available": True,
            "kex_groups": {
                "pure_pqc": [],
                "hybrid": [],
                "classical": ["curve25519-sha256"],
            },
        },
    )
    series = _parse(pr.render_prometheus(r))
    assert _value(series, "key_exchange_groups", protocol="tls", kind="hybrid") == 2
    assert _value(series, "key_exchange_groups", protocol="ssh", kind="classical") == 1
    assert _value(series, "hybrid_kex_available", protocol="tls") == 1
    assert _value(series, "hybrid_kex_available", protocol="ssh") == 0
    assert _value(series, "openssl_pqc_native") == 1


def test_unavailable_probes_are_omitted_not_zeroed() -> None:
    # Absence means "unknown" in Prometheus; a 0 would claim a fact we
    # don't have (e.g. "no hybrid TLS" when OpenSSL wasn't even found).
    r = _report(
        openssl={"available": False, "reason": "openssl not on PATH"},
        ssh_pqc={"available": False},
        nss={"available": False},
        trust_store={},
        packages={},
        cnsa_2_0={},
    )
    names = _names(_parse(pr.render_prometheus(r)))
    for absent in (
        "openssl_pqc_native",
        "key_exchange_groups",
        "hybrid_kex_available",
        "nss_pqc_capable",
        "trust_store_certificates",
        "packages",
        "cnsa_2_0_status",
    ):
        assert f"pqc_readiness_{absent}" not in names


def test_fips_fence_only_reported_when_the_check_ran() -> None:
    off = _parse(
        pr.render_prometheus(
            _report(
                fips={
                    "kernel": False,
                    "fence_check_active": False,
                    "algorithm_fence_engaged": False,
                }
            )
        )
    )
    assert "pqc_readiness_fips_algorithm_fence_engaged" not in _names(off)
    on = _parse(
        pr.render_prometheus(
            _report(
                fips={
                    "kernel": True,
                    "fence_check_active": True,
                    "algorithm_fence_engaged": False,
                }
            )
        )
    )
    assert _value(on, "fips_algorithm_fence_engaged") == 0
    assert _value(on, "fips_mode", layer="kernel") == 1


def test_trust_store_and_packages_when_scanned() -> None:
    r = _report(
        trust_store={
            "available": True,
            "cert_categories": {"classical": 5, "hybrid_composite": 0, "pure_pqc": 2},
            "truncated": False,
        },
        packages={
            "available": True,
            "total_packages": 42,
            "bundled_crypto": [{"package": "x"}],
        },
    )
    series = _parse(pr.render_prometheus(r))
    assert _value(series, "trust_store_certificates", category="pure_pqc") == 2
    assert _value(series, "trust_store_truncated") == 0
    assert _value(series, "packages") == 42
    assert _value(series, "bundled_crypto_packages") == 1


def test_label_values_are_escaped() -> None:
    m = pr.render.prom._Metrics()
    m.family("x", "h", [({"tier": 'a"b\\c\nd'}, 1.0)])
    assert m.lines[-1] == 'pqc_readiness_x{tier="a\\"b\\\\c\\nd"} 1'


def test_cli_flag_and_precedence(stubbed: pr.Report) -> None:
    assert pr.render_output(stubbed, _args("--prometheus")).startswith(
        "# HELP pqc_readiness_info"
    )
    # Like every other format flag pair, the higher-precedence one wins.
    assert (
        pr.render_output(stubbed, _args("--prometheus", "--json"))
        .lstrip()
        .startswith("{")
    )


def test_output_file_is_written_atomically(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _stub_host(monkeypatch)
    target = tmp_path / "pqc_readiness.prom"
    target.write_text("old\n")
    target.chmod(0o640)
    pr.main(["--prometheus", "--output", str(target)])
    assert target.read_text().startswith("# HELP pqc_readiness_info")
    assert stat.S_IMODE(target.stat().st_mode) == 0o640  # existing mode kept
    assert [p.name for p in tmp_path.iterdir()] == [
        "pqc_readiness.prom"
    ]  # no temp left


def test_new_output_file_gets_umask_mode(tmp_path: Path) -> None:
    old = os.umask(0o022)
    try:
        pr.cli._write_atomically(tmp_path / "f.prom", "x\n")
    finally:
        os.umask(old)
    assert stat.S_IMODE((tmp_path / "f.prom").stat().st_mode) == 0o644


def test_failed_atomic_write_leaves_no_temp_file(tmp_path: Path) -> None:
    target = tmp_path / "dir-in-the-way"
    target.mkdir()
    with pytest.raises(OSError):
        pr.cli._write_atomically(target, "x\n")
    assert [p.name for p in tmp_path.iterdir()] == ["dir-in-the-way"]
