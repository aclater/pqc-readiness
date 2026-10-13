# SPDX-License-Identifier: Apache-2.0
"""Issue #117: never hand `openssl speed` an algorithm name the local
OpenSSL does not provide.  Given an unknown name, `openssl speed
-signature-algorithms NAME` benchmarks every signature algorithm instead,
burning the whole timeout.  These tests stub `_run`, so no real
benchmark ever runs."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import shutil

import pqc_readiness as pr

SPEED = Path(__file__).parent / "fixtures" / "openssl-speed"
SPEED_FIXTURE = {
    "ML-KEM-768": "ml-kem-768.txt",
    "ML-DSA-65": "ml-dsa-65.txt",
    "SLH-DSA-SHA2-128s": "slh-dsa-sha2-128s.txt",
}
VERSION_35 = "OpenSSL 3.5.5 1 Jan 2026 (Library: OpenSSL 3.5.5 1 Jan 2026)\n"


class FakeOpenSSL:
    """Stand-in for `_run` that records every argv and answers `openssl
    speed` from fixtures and `openssl list` from a configurable listing."""

    def __init__(self, listing: dict[str, str] | None = None) -> None:
        self.calls: list[list[str]] = []
        self.listing = listing or {}

    def __call__(self, cmd: list[str], timeout: int = 10) -> tuple[int, str]:
        self.calls.append(cmd)
        if cmd[:2] == ["openssl", "version"]:
            return 0, VERSION_35
        if cmd[:2] == ["openssl", "list"]:
            return 0, self.listing.get(cmd[2], "")
        if cmd[:2] == ["openssl", "speed"]:
            algo = cmd[-1]
            if algo in SPEED_FIXTURE:
                return 0, (SPEED / SPEED_FIXTURE[algo]).read_text()
            if algo == "ecdhx25519":  # classical baseline
                return 0, (SPEED / "classical.txt").read_text()
            raise AssertionError(f"unexpected openssl speed target: {cmd}")
        raise AssertionError(f"unexpected command: {cmd}")

    def speed_targets(self) -> list[str]:
        return [c[-1] for c in self.calls if c[:2] == ["openssl", "speed"]]

    def list_calls(self) -> list[list[str]]:
        return [c for c in self.calls if c[:2] == ["openssl", "list"]]


@pytest.fixture
def fake(monkeypatch: pytest.MonkeyPatch) -> FakeOpenSSL:
    f = FakeOpenSSL()
    monkeypatch.setattr(pr._platform, "_run", f)
    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")
    return f


def test_missing_algorithm_is_skipped_not_benchmarked(fake: FakeOpenSSL) -> None:
    provided = {"ML-KEM-768", "ML-DSA-65"}  # no SLH-DSA in this build
    out = pr.run_pqc_bench(1, 1, provided)
    assert "SLH-DSA-SHA2-128s" not in fake.speed_targets()
    assert out["SLH-DSA-SHA2-128s"] == {"skipped": pr.BENCH_SKIPPED_NOT_PROVIDED}
    # Provided algorithms still run and parse normally.
    assert fake.speed_targets() == ["ML-KEM-768", "ML-DSA-65"]
    assert out["ML-KEM-768"]["encaps/s"] > 0


def test_multi_thread_run_also_skipped(fake: FakeOpenSSL) -> None:
    pr.run_pqc_bench(1, 4, {"ML-KEM-768"})
    speed_calls = [c for c in fake.calls if c[:2] == ["openssl", "speed"]]
    assert all(c[-1] == "ML-KEM-768" for c in speed_calls)
    assert any("-multi" in c for c in speed_calls)


def test_membership_is_case_insensitive(fake: FakeOpenSSL) -> None:
    # openssl_capability() reports e.g. SLH-DSA-SHA2-128S from some builds.
    out = pr.run_pqc_bench(1, 1, {"ML-KEM-768", "ML-DSA-65", "SLH-DSA-SHA2-128S"})
    assert "skipped" not in out["SLH-DSA-SHA2-128s"]


def test_run_benchmarks_reuses_capability_lists(fake: FakeOpenSSL) -> None:
    osinfo: dict[str, Any] = {
        "available": True,
        "kem_algorithms": ["ML-KEM-768"],
        "sig_algorithms": ["ML-DSA-65"],
    }
    out = pr.run_benchmarks(seconds=1, threads=1, osinfo=osinfo)
    assert fake.list_calls() == []  # no second `openssl list` round
    assert out["pqc"]["SLH-DSA-SHA2-128s"] == {"skipped": pr.BENCH_SKIPPED_NOT_PROVIDED}


def test_run_benchmarks_standalone_looks_up_lists(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Called without osinfo (tests / programmatic callers): the guard
    # must still apply, via a direct lookup.
    f = FakeOpenSSL(
        listing={
            "-kem-algorithms": "  { 2.16.840.1.101.3.4.4.2, id-alg-ml-kem-768, ML-KEM-768 } @ default\n",
            "-signature-algorithms": "  { 2.16.840.1.101.3.4.3.18, id-ml-dsa-65, ML-DSA-65 } @ default\n",
        }
    )
    monkeypatch.setattr(pr._platform, "_run", f)
    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")
    out = pr.run_benchmarks(seconds=1, threads=1)
    assert len(f.list_calls()) == 2
    assert "SLH-DSA-SHA2-128s" not in f.speed_targets()
    assert out["pqc"]["SLH-DSA-SHA2-128s"]["skipped"]
    assert out["pqc"]["ML-DSA-65"]["sign/s"] > 0


def test_capability_unavailable_falls_back_to_lookup() -> None:
    assert pr.bench._bench_provided_algorithms(None) is None
    assert pr.bench._bench_provided_algorithms({"available": False}) is None


def test_verdict_reports_skip_reason() -> None:
    bench = {
        "available": True,
        "pqc": {"SLH-DSA-SHA2-128s": {"skipped": pr.BENCH_SKIPPED_NOT_PROVIDED}},
    }
    verdicts = pr.per_algo_verdict(bench, cores=4)
    slh = [v for k, v in verdicts.items() if k.startswith("SLH-DSA")]
    assert slh and all(v["tier"] == "unknown" for v in slh)
    assert all(v["reason"] == pr.BENCH_SKIPPED_NOT_PROVIDED for v in slh)


# ---------------------------------------------------------------------------
# One `openssl list -providers -verbose` call serves FIPS detection and the
# provider list (#117 follow-up: the plain `-providers` call was redundant).
# ---------------------------------------------------------------------------

MULTI_PROVIDERS = """Providers:
  base
    name: OpenSSL Base Provider
    status: active
  default
    name: OpenSSL Default Provider
    version: 3.5.5
    status: active
    build info: 3.5.5
    gettable provider parameters:
      name: pointer to a UTF8 encoded string (arbitrary size)
      status: integer (arbitrary size)
  fips
    name: OpenSSL FIPS Provider
    status: active
"""


def test_provider_records_ignore_parameter_listing() -> None:
    recs = pr.parse_openssl_provider_records(MULTI_PROVIDERS)
    assert sorted(recs) == ["base", "default", "fips"]
    assert recs["default"]["status"] == "active"
    # Deeper-indented gettable-parameter lines must not overwrite fields.
    assert recs["default"]["name"] == "OpenSSL Default Provider"


def test_providers_listed_once_for_fips_and_capability(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[str]] = []

    def fake_run(cmd: list[str], timeout: int = 10) -> tuple[int, str]:
        calls.append(cmd)
        if cmd[:3] == ["openssl", "list", "-providers"]:
            return 0, MULTI_PROVIDERS
        if cmd[:2] == ["openssl", "version"]:
            return 0, VERSION_35
        return 0, ""

    monkeypatch.setattr(pr._platform, "_run", fake_run)
    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")
    cap = pr.openssl_capability()
    fips = pr.detect_fips_mode()
    assert cap["providers"] == ["base", "default", "fips"]
    assert fips["openssl_provider"] is True
    provider_calls = [c for c in calls if c[:3] == ["openssl", "list", "-providers"]]
    assert provider_calls == [["openssl", "list", "-providers", "-verbose"]]
