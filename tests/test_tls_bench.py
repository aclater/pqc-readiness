# SPDX-License-Identifier: Apache-2.0
"""Unit and integration tests for the TLS-handshake benchmark.

The pure helpers (suite selection, composite-signature detection) are
exercised with synthetic inputs and don't need OpenSSL at all.  The
end-to-end smoke test that actually drives `s_server` and `s_client`
is gated on OpenSSL >= 3.5 with at least one ML-KEM TLS group exposed,
which is the same precondition the production code checks.
"""

from __future__ import annotations

import re
import shutil
import socket
import subprocess
from typing import Any

import pytest

import pqc_readiness as pr


# ---------------------------------------------------------------------------
# Pure helpers — no external process required
# ---------------------------------------------------------------------------


def test_pick_classical_group_prefers_x25519() -> None:
    assert pr._tls_pick_classical_group(["secp256r1", "x25519", "secp384r1"]) == "x25519"


def test_pick_classical_group_falls_back_to_secp256r1() -> None:
    assert pr._tls_pick_classical_group(["secp384r1", "secp256r1"]) == "secp256r1"


def test_pick_classical_group_last_resort_returns_first_entry() -> None:
    assert pr._tls_pick_classical_group(["ffdhe2048"]) == "ffdhe2048"


def test_pick_classical_group_empty_returns_none() -> None:
    assert pr._tls_pick_classical_group([]) is None


def test_find_composite_signature_alg_matches_mldsa_rsa() -> None:
    sigs = ["ML-DSA-65", "RSA-PSS", "id-MLDSA65-RSA3072-PSS-SHA512"]
    assert pr._tls_find_composite_signature_alg(sigs) == "id-MLDSA65-RSA3072-PSS-SHA512"


def test_find_composite_signature_alg_matches_oqs_naming() -> None:
    sigs = ["mldsa65_p256", "ed25519"]
    assert pr._tls_find_composite_signature_alg(sigs) == "mldsa65_p256"


def test_find_composite_signature_alg_returns_none_for_pure_pqc() -> None:
    assert pr._tls_find_composite_signature_alg(["ML-DSA-65", "ML-DSA-87"]) is None


def test_build_suites_picks_classical_hybrid_pure_pqc() -> None:
    osinfo: dict[str, Any] = {
        "tls_groups": {
            "classical": ["secp256r1", "x25519", "secp384r1"],
            "hybrid": ["X25519MLKEM768", "SecP256r1MLKEM768"],
            "pure_pqc": ["MLKEM512", "MLKEM768"],
        }
    }
    suites = pr._tls_build_suites(osinfo)
    roles = [s["role"] for s in suites]
    assert roles == ["classical", "hybrid", "pure_pqc"]
    classical, hybrid, pure = suites
    assert classical["group"] == "x25519"
    assert hybrid["group"] == "X25519MLKEM768"
    assert pure["group"] == "MLKEM768"


def test_build_suites_omits_unavailable_categories() -> None:
    osinfo: dict[str, Any] = {
        "tls_groups": {
            "classical": ["x25519"],
            "hybrid": [],
            "pure_pqc": [],
        }
    }
    suites = pr._tls_build_suites(osinfo)
    assert len(suites) == 1
    assert suites[0]["role"] == "classical"


def test_build_suites_handles_missing_tls_groups_key() -> None:
    assert pr._tls_build_suites({}) == []


def test_build_suites_falls_back_when_preferred_hybrid_unavailable() -> None:
    osinfo: dict[str, Any] = {
        "tls_groups": {
            "classical": ["x25519"],
            "hybrid": ["SecP384r1MLKEM1024"],
            "pure_pqc": ["MLKEM1024"],
        }
    }
    suites = pr._tls_build_suites(osinfo)
    hybrid = next(s for s in suites if s["role"] == "hybrid")
    pure = next(s for s in suites if s["role"] == "pure_pqc")
    assert hybrid["group"] == "SecP384r1MLKEM1024"
    assert pure["group"] == "MLKEM1024"


def test_get_free_port_returns_bindable_port() -> None:
    port = pr._tls_get_free_port()
    assert 0 < port < 65536
    # Confirm the port is free at the moment we observed it.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", port))


def test_wait_for_port_returns_false_for_dead_port() -> None:
    # _tls_get_free_port closes its probe socket, so this port is
    # almost certainly unbound right now — that's the negative case.
    port = pr._tls_get_free_port()
    assert pr._tls_wait_for_port(port, timeout=0.3) is False


# ---------------------------------------------------------------------------
# run_tls_handshake_bench: graceful-skip dispatch
# ---------------------------------------------------------------------------


def test_run_tls_handshake_bench_unavailable_when_openssl_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(pr.shutil, "which", lambda _name: None)
    out = pr.run_tls_handshake_bench(seconds=1)
    assert out == {"available": False, "reason": "openssl not on PATH"}


def test_run_tls_handshake_bench_unavailable_for_old_openssl(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(pr.shutil, "which", lambda _name: "/usr/bin/openssl")

    def fake_run(cmd: list[str], timeout: int = 10) -> tuple[int, str]:
        return 0, "OpenSSL 3.0.13 30 Jan 2024\n"

    monkeypatch.setattr(pr, "_run", fake_run)
    out = pr.run_tls_handshake_bench(seconds=1)
    assert out["available"] is False
    assert "pre-3.5" in out["reason"]


def test_run_tls_handshake_bench_unavailable_when_no_groups(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(pr.shutil, "which", lambda _name: "/usr/bin/openssl")

    def fake_run(cmd: list[str], timeout: int = 10) -> tuple[int, str]:
        return 0, "OpenSSL 3.5.5 27 Jan 2026\n"

    monkeypatch.setattr(pr, "_run", fake_run)
    out = pr.run_tls_handshake_bench(
        seconds=1,
        osinfo={"available": True, "tls_groups": {}},
    )
    assert out["available"] is False
    assert "no TLS groups" in out["reason"]


# ---------------------------------------------------------------------------
# End-to-end smoke test
#
# Skipped when OpenSSL is not present or pre-3.5, or when the local
# OpenSSL has not been built with ML-KEM TLS groups.  On stock Fedora
# 44 / OpenSSL 3.5+, this exercises the full s_server -> proxy ->
# s_client path against a real loopback socket.
# ---------------------------------------------------------------------------


def _has_pqc_openssl() -> bool:
    if not shutil.which("openssl"):
        return False
    try:
        out = subprocess.run(
            ["openssl", "version"], capture_output=True, text=True, timeout=5
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
    m = re.search(r"OpenSSL\s+(\d+)\.(\d+)", out.stdout)
    if not m or (int(m.group(1)), int(m.group(2))) < (3, 5):
        return False
    cap = pr.openssl_capability()
    groups = cap.get("tls_groups") or {}
    return bool(groups.get("hybrid") or groups.get("pure_pqc") or groups.get("classical"))


@pytest.mark.skipif(not _has_pqc_openssl(), reason="OpenSSL 3.5+ with TLS groups required")
def test_run_tls_handshake_bench_end_to_end() -> None:
    out = pr.run_tls_handshake_bench(seconds=1)
    assert out["available"] is True
    assert out["engine"] == "tls-handshake"
    assert out["transport"] == "loopback"
    assert isinstance(out["suites"], list) and out["suites"]
    seen_classical = False
    for s in out["suites"]:
        assert "label" in s and "role" in s and "group" in s
        if s["role"] == "classical":
            seen_classical = True
        if "error" in s or s.get("skipped"):
            continue
        assert s["iterations"] > 0
        assert s["handshakes_per_sec"] > 0
        assert s["ttfb_ms_median"] >= 0
        # Bytes-on-wire is best-effort: the Python proxy may miss a
        # connection on a slow CI runner, but the field must always
        # be present and an int when populated.
        if s.get("bytes_on_wire_per_handshake") is not None:
            assert isinstance(s["bytes_on_wire_per_handshake"], int)
            assert s["bytes_on_wire_per_handshake"] > 0
    assert seen_classical, "classical baseline must always be measurable"


@pytest.mark.skipif(not _has_pqc_openssl(), reason="OpenSSL 3.5+ with TLS groups required")
def test_bench_tls_handshake_attaches_to_report_json(tmp_path: Any) -> None:
    """Smoke-test the `--bench-tls` CLI flag end-to-end.

    Runs the script with `--bench-tls --json --quiet` (quiet keeps stdout
    short on green hosts) and confirms the resulting JSON has the
    benchmark_tls_handshake field populated with engine = tls-handshake.
    """
    import json
    import sys
    from pathlib import Path

    script = Path(pr.__file__)
    proc = subprocess.run(
        [sys.executable, str(script), "--bench-tls", "--json", "--seconds", "1"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode in (0, 1, 2, 3), proc.stderr
    payload = json.loads(proc.stdout)
    assert "benchmark_tls_handshake" in payload
    bt = payload["benchmark_tls_handshake"]
    assert bt.get("available") is True
    assert bt.get("engine") == "tls-handshake"
    assert isinstance(bt.get("suites"), list) and bt["suites"]
