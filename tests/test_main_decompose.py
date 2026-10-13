# SPDX-License-Identifier: Apache-2.0
"""Tests for the main() decomposition (#80 PR A).

main() is glue over four functions: build_parser(), collect_report(),
render_output() and exit_code_for().  These tests pin each piece, plus a
golden end-to-end run on a fully stubbed host whose expected output was
produced by the pre-refactor main(), so the decomposition is provably a
pure refactor.

Regenerate the golden file (only when a JSON change is intended) with:
    PQC_WRITE_GOLDEN=1 pytest tests/test_main_decompose.py -k golden
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest

from conftest import FIXTURES
import platform
import socket
import pqc_readiness as pr

GOLDEN = FIXTURES / "golden" / "stubbed-host-report.json"


# ---------------------------------------------------------------------------
# Stubbed host
# ---------------------------------------------------------------------------


def _stub_host(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin every probe collect_report() calls so the report is identical
    on any machine.  Values are deliberately mid-range (AVX2 x86, 32 GiB,
    OpenSSL 3.5 with hybrid groups) so most report sections are populated."""
    flags = {"avx2", "aes", "pclmulqdq", "sha_ni", "bmi2", "adx"}
    monkeypatch.setattr(platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(socket, "gethostname", lambda: "golden-host")
    monkeypatch.setattr(pr.detect.hardware, "cpu_flags", lambda arch: set(flags))
    monkeypatch.setattr(pr.detect.hardware, "cpu_model", lambda: "Stub CPU @ 3.0GHz")
    monkeypatch.setattr(pr.detect.hardware, "cpu_freq_mhz", lambda: 3000.0)
    monkeypatch.setattr(pr.detect.hardware, "memory_info", lambda: (32.0, 24.0))
    monkeypatch.setattr(pr.detect.hardware, "core_counts", lambda: (16, 8))
    monkeypatch.setattr(
        pr.detect.runtime,
        "detect_runtime_environment",
        lambda: {"environment": "bare_metal", "evidence": []},
    )
    monkeypatch.setattr(
        pr.detect.runtime, "build_host_fs_detections_unavailable", lambda: {}
    )
    monkeypatch.setattr(pr.detect.hardware, "detect_accelerators", lambda: [])
    monkeypatch.setattr(pr.detect.hardware, "detect_network_hsms", lambda: [])
    monkeypatch.setattr(
        pr.detect.osinfo,
        "detect_os",
        lambda: {
            "id": "rhel",
            "version_id": "10.0",
            "family": "rhel",
            "pretty_name": "Red Hat Enterprise Linux 10.0 (Stub)",
        },
    )
    monkeypatch.setattr(
        pr.detect.hardware, "detect_pkcs11_modules", lambda family="unknown": []
    )
    monkeypatch.setattr(
        pr.detect.hardware,
        "detect_kernel_crypto_hw_annotated",
        lambda: {"items": ["aesni_intel"]},
    )
    monkeypatch.setattr(
        pr.detect.hardware, "detect_ktls_annotated", lambda: {"supported": True}
    )
    monkeypatch.setattr(
        pr.detect.config, "detect_fips_mode", lambda: {"enabled": False, "sources": []}
    )
    monkeypatch.setattr(
        pr.detect.hardware, "detect_tpm_pqc", lambda: {"present": False}
    )
    monkeypatch.setattr(
        pr.detect.config,
        "openssl_capability",
        lambda os_release=None: {
            "version": "OpenSSL 3.5.0 stub",
            "pqc_native": True,
            "kem_algorithms": ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"],
            "signature_algorithms": ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"],
            "tls_groups": {
                "pure_pqc": ["MLKEM768"],
                "hybrid": ["X25519MLKEM768"],
                "classical": ["X25519", "secp256r1"],
            },
        },
    )
    monkeypatch.setattr(
        pr.detect.protocols,
        "detect_ssh_pqc",
        lambda family="unknown": {"available": False},
    )
    monkeypatch.setattr(
        pr.detect.protocols,
        "detect_ipsec_pqc",
        lambda family="unknown": {"available": False},
    )
    monkeypatch.setattr(pr.detect.protocols, "detect_nss", lambda: {"available": False})
    # Real parser over a captured EL9.8 policy tree, so the golden report
    # carries the full crypto_policy shape deterministically (#104).
    real_crypto_policy = pr.detect.config_policy.detect_crypto_policy

    def _crypto_policy_from_fixture() -> dict[str, Any]:
        saved = pr._platform.HOST_PREFIX
        pr._platform.HOST_PREFIX = str(FIXTURES / "crypto_policies" / "el9-default")
        try:
            return real_crypto_policy()
        finally:
            pr._platform.HOST_PREFIX = saved

    monkeypatch.setattr(
        pr.detect.config_policy, "detect_crypto_policy", _crypto_policy_from_fixture
    )
    monkeypatch.setattr(
        pr.detect.osinfo,
        "detect_kernel_info",
        lambda os_release=None: {"release": "6.12.0-stub"},
    )
    monkeypatch.setattr(
        pr.detect.config, "interpret_fips", lambda fips, osinfo, osr: fips
    )
    monkeypatch.setattr(
        pr.detect.config, "fips_pqc_conflict_check", lambda fips, osinfo: None
    )
    monkeypatch.setattr(pr._platform, "is_linux", lambda: False)


def _report_json_without_timestamp(text: str) -> dict[str, Any]:
    data: dict[str, Any] = json.loads(text)
    data.pop("generated_at")
    return data


# ---------------------------------------------------------------------------
# Golden end-to-end: identical to the pre-refactor main()
# ---------------------------------------------------------------------------


def test_golden_json_report_unchanged_by_decomposition(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _stub_host(monkeypatch)
    monkeypatch.setattr(sys, "argv", ["pqc_readiness.py", "--json"])
    rc = pr.main()
    report = _report_json_without_timestamp(capsys.readouterr().out)
    actual = {"exit_code": rc, "report": report}
    if os.environ.get("PQC_WRITE_GOLDEN"):
        GOLDEN.parent.mkdir(parents=True, exist_ok=True)
        GOLDEN.write_text(json.dumps(actual, indent=2, sort_keys=True) + "\n")
    expected = json.loads(GOLDEN.read_text())
    assert actual == expected


# ---------------------------------------------------------------------------
# build_parser
# ---------------------------------------------------------------------------


def test_build_parser_defaults() -> None:
    args = pr.build_parser().parse_args([])
    assert args.policy == "auto"
    assert args.role is None
    assert args.seconds == 1 and args.threads == 1
    assert args.trust_store_max_certs == pr.TRUST_STORE_MAX_CERTS_DEFAULT
    assert args.aggregate_format == "json"
    assert not (args.json or args.ansible or args.recommend or args.save)


def test_build_parser_save_and_output_are_mutually_exclusive(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as exc:
        pr.build_parser().parse_args(["--save", "--output", "x.json"])
    assert exc.value.code == 2
    assert "not allowed with argument" in capsys.readouterr().err


def test_main_accepts_argv_without_touching_sys_argv(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _stub_host(monkeypatch)
    monkeypatch.setattr(sys, "argv", ["pqc_readiness.py", "--bogus-flag"])
    pr.main(["--quiet"])  # would exit 2 if sys.argv were parsed
    assert capsys.readouterr().out.strip() != ""


# ---------------------------------------------------------------------------
# collect_report
# ---------------------------------------------------------------------------


def test_collect_report_has_no_output_side_effects(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _stub_host(monkeypatch)
    r = pr.collect_report(pr.build_parser().parse_args([]))
    assert isinstance(r, pr.Report)
    assert r.hostname == "golden-host"
    assert capsys.readouterr() == ("", "")


def test_collect_report_role_drives_memory_tier_basis(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_host(monkeypatch)
    r = pr.collect_report(pr.build_parser().parse_args(["--role", "tls-client"]))
    assert r.memory["tier_basis"] == {
        "role": "tls-client",
        "threshold_gib_good": pr.MEMORY_TIER_GOOD_THRESHOLD_BY_ROLE["tls-client"],
        "role_supplied": True,
    }
    assert "tier_by_role" not in r.memory


# ---------------------------------------------------------------------------
# render_output
# ---------------------------------------------------------------------------


def _args(*argv: str) -> argparse.Namespace:
    return pr.build_parser().parse_args(list(argv))


@pytest.fixture()
def stub_renderers(monkeypatch: pytest.MonkeyPatch) -> pr.Report:
    _stub_host(monkeypatch)
    for module, name in (
        (pr.render.cbom, "render_cbom"),
        (pr.render.spdx, "render_spdx"),
        (pr.render.sarif, "render_sarif"),
        (pr.render.text, "render_markdown"),
        (pr.render.text, "render_text"),
    ):
        monkeypatch.setattr(module, name, lambda r, _n=name: _n)
    return pr.collect_report(_args())


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        ((), "render_text"),
        (("--markdown",), "render_markdown"),
        (("--sarif", "--markdown"), "render_sarif"),
        (("--spdx", "--sarif"), "render_spdx"),
        (("--cbom", "--spdx"), "render_cbom"),
    ],
)
def test_render_output_format_precedence(
    stub_renderers: pr.Report, argv: tuple[str, ...], expected: str
) -> None:
    assert pr.render_output(stub_renderers, _args(*argv)) == expected


def test_render_output_json_beats_every_other_format(
    stub_renderers: pr.Report,
) -> None:
    out = pr.render_output(
        stub_renderers, _args("--json", "--cbom", "--markdown", "--quiet")
    )
    assert json.loads(out)["hostname"] == "golden-host"


def test_render_output_quiet_is_verdict_only(stub_renderers: pr.Report) -> None:
    assert pr.render_output(stub_renderers, _args("--quiet")) == stub_renderers.verdict


def test_render_output_ansible_wraps_report_and_beats_json(
    stub_renderers: pr.Report,
) -> None:
    out = json.loads(pr.render_output(stub_renderers, _args("--ansible", "--json")))
    assert out["ansible_facts"]["pqc_readiness"]["hostname"] == "golden-host"


@pytest.mark.parametrize(
    ("argv", "expected_prefix"),
    [
        (("--recommend", "--json"), "{"),
        (("--recommend", "--markdown"), "#"),
    ],
)
def test_render_output_recommend_formats(
    stub_renderers: pr.Report, argv: tuple[str, ...], expected_prefix: str
) -> None:
    assert (
        pr.render_output(stub_renderers, _args(*argv))
        .lstrip()
        .startswith(expected_prefix)
    )


def test_render_output_recommend_defaults_role_to_tls_server(
    stub_renderers: pr.Report,
) -> None:
    rec = json.loads(pr.render_output(stub_renderers, _args("--recommend", "--json")))
    assert rec["role"] == "tls-server"


# ---------------------------------------------------------------------------
# exit_code_for
# ---------------------------------------------------------------------------


def _report(exit_code: int = 0, **overrides: Any) -> pr.Report:
    r = pr.Report(exit_code=exit_code)
    for k, v in overrides.items():
        setattr(r, k, v)
    return r


@pytest.mark.parametrize("flag", ["--ansible", "--recommend"])
def test_exit_code_alternate_documents_always_zero(flag: str) -> None:
    r = _report(exit_code=3, cnsa_2_0={"status": "non_compliant"})
    assert pr.exit_code_for(r, _args(flag, "--check", "cnsa-2.0")) == 0


@pytest.mark.parametrize(
    ("fips", "expected"),
    [
        ({"fence_check_active": True, "algorithm_fence_engaged": False}, 4),
        ({"fence_check_active": True, "algorithm_fence_engaged": True}, 1),
        ({"fence_check_active": False, "algorithm_fence_engaged": False}, 1),
        ({}, 1),
    ],
)
def test_exit_code_fips_strict(fips: dict[str, Any], expected: int) -> None:
    assert pr.exit_code_for(_report(1, fips=fips), _args("--fips-strict")) == expected


def test_exit_code_fips_fence_ignored_without_flag() -> None:
    r = _report(1, fips={"fence_check_active": True, "algorithm_fence_engaged": False})
    assert pr.exit_code_for(r, _args()) == 1


@pytest.mark.parametrize(
    ("status", "expected"),
    [("compliant", 2), ("partial", 4), ("non_compliant", 4), ("unknown", 4)],
)
def test_exit_code_check_cnsa(status: str, expected: int) -> None:
    r = _report(2, cnsa_2_0={"status": status})
    assert pr.exit_code_for(r, _args("--check", "cnsa-2.0")) == expected


# Report.exit_code: 0 excellent, 1 good, 2 marginal, 3 poor.
@pytest.mark.parametrize("verdict_code", [0, 1, 2, 3])
@pytest.mark.parametrize(
    ("check", "min_rank"),
    [("excellent", 3), ("good", 2), ("marginal", 1), ("poor", 0)],
)
def test_exit_code_check_tier_ranks(
    verdict_code: int, check: str, min_rank: int
) -> None:
    verdict_rank = 3 - verdict_code
    expected = verdict_code if verdict_rank >= min_rank else 4
    assert pr.exit_code_for(_report(verdict_code), _args("--check", check)) == expected


def test_exit_code_without_gates_is_verdict_code() -> None:
    assert pr.exit_code_for(_report(3), _args()) == 3


# ---------------------------------------------------------------------------
# set_host_prefix
# ---------------------------------------------------------------------------


def test_set_host_prefix_strips_trailing_slash_and_resets() -> None:
    try:
        pr.set_host_prefix("/host/")
        assert pr._platform.HOST_PREFIX == "/host"
        assert pr.host_path("/proc/cpuinfo") == Path("/host/proc/cpuinfo")
        assert pr.host_path("/opt/tool") == Path("/opt/tool")
    finally:
        pr.set_host_prefix("")
    assert pr.host_path("/proc/cpuinfo") == Path("/proc/cpuinfo")
