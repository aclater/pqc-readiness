# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the human-readable text renderer (`render_text`).

Audit issue #46: the human-facing text and markdown renderers had no
dedicated tests covering invariants. The CBOM / SPDX / SARIF projections
are validated against external schemas; the text and markdown ones —
which are what a customer most often reads — only had a recommendation-
block test (`tests/test_recommendation.py`).

The synthetic Report below intentionally populates every conditional
branch in `render_text`, so any future drift that f-strings a `None`
field without guarding it surfaces here. Section headings are asserted
literally so a heading rename in one renderer (without the matching
docs / aggregator update) fails fast.
"""
from __future__ import annotations

from typing import Any

import pytest

import pqc_readiness as pr
from test_cbom import _make_report

# Color is class-level state on `pr.C`; tests assume the renderer's
# default (color off) so that `C.wrap(...)` is a plain-text passthrough
# and section-heading assertions match the source strings verbatim.
# Any test elsewhere in the suite that toggles color would leak across
# pytest workers — pin it here.
pr.C.configure(False)


def _make_full_coverage_report() -> pr.Report:
    """Extend `_make_report()` from the CBOM tests with the conditional-
    section fields the text renderer consumes (benchmark, per-algo
    verdict, production estimate, CNSA 2.0, kernel info, FIPS status,
    NSS, ktls, verdict block). The CBOM test only populates what the
    CBOM projection reads; this helper makes sure every `if r.<field>:`
    branch in `render_text` fires."""
    r = _make_report()
    r.cpu_freq_mhz = 4500.0
    r.cores_physical = 8
    r.cores_logical = 16
    r.memory_bandwidth_gb_s = 65.0
    r.memory_bandwidth_method = "stream-triad"
    r.isa_score = 5
    r.isa_tier = "good"
    r.isa_reason = "AVX-512 + AES-NI present"
    r.kernel_info = {
        "release": "6.19.13-300.vpe1.fc44.x86_64",
        "redhat_release": {"raw": "Fedora release 44 (Workstation Edition)"},
        "proc_crypto_pqc": ["ml-kem-768"],
    }
    r.kernel_crypto_hw = ["aesni", "ghash-clmulni", "sha256-avx2"]
    r.ktls_supported = True
    r.fips = {"kernel": False, "openssl_provider": False}
    r.fips_pqc_conflict = {"in_conflict": False}
    r.nss = {"available": True, "version": "3.108", "pqc_capable": False}
    r.benchmark = {
        "available": True,
        "engine": "openssl",
        "seconds_per_test": 1,
        "threads": 1,
        "pqc": {
            "ML-KEM-768": {
                "keygen": 12345.6,
                "encap": 23456.7,
                "decap": 34567.8,
                "sizes": {"public_key": 1184, "ciphertext": 1088},
            },
        },
        "classical": {
            "ecdsa": {"sign": 1000.5, "verify": 5000.5},
        },
    }
    r.benchmark_tls_handshake = {
        "available": True,
        "engine": "openssl",
        "transport": "loopback",
        "iterations_per_suite": 100,
        "openssl_version": "3.5.5",
        "suites": [
            {
                "label": "TLS_AES_128_GCM_SHA256",
                "role": "client",
                "handshakes_per_sec": 1000.5,
                "ttfb_ms_median": 1.5,
                "bytes_on_wire_per_handshake": 4500,
            },
        ],
    }
    r.per_algo = {
        "ml-kem-768": {
            "tier": "good",
            "rate_per_core": 12345.6,
            "rate_host_estimate": 98765.0,
            "metric": "encap/sec",
            "reason": "above per-core threshold",
            "notes": ["informational note"],
        },
    }
    r.production_estimate = {
        "tls_pqc_handshakes_per_sec": 5000,
        "ml_dsa_signatures_per_sec": 10000,
        "slh_dsa_sha2_128s_signatures_per_sec": 25,
        "concurrent_connections_realistic": 50000,
        "concurrent_connections_theoretical_max": 300000,
        "assumptions": "60% CPU headroom",
    }
    r.cnsa_2_0 = {
        "status": "compliant",
        "kem_compliant": True,
        "signature_compliant": True,
        "symmetric_compliant": True,
        "hash_compliant": True,
        "notes": ["national-security-system bucket"],
    }
    r.trust_store = {
        **r.trust_store,
        "cert_categories": {
            "classical": 142,
            "hybrid_composite": 0,
            "pure_pqc": 0,
        },
    }
    r.verdict = "good"
    r.verdict_reason = "PQC primitives present and benchmarked above threshold"
    r.verdict_caveat = "TLS handshake bench was loopback only"
    return r


# Section labels asserted are the literal Bold-wrapped strings emitted
# in `render_text` (color is off in tests, so `C.wrap` is identity).
ALWAYS_PRESENT_HEADINGS = (
    "1. CPU instruction-set support for PQC",
    "2. Cryptographic accelerators / HSMs / TPMs",
    "3. Operating-system crypto plumbing",
    "4. PQC library capability (OpenSSL)",
    "5. NIST PQC parameter sizes (bytes)",
)
CONDITIONAL_HEADINGS = (
    "6. Microbenchmark",
    "6b. TLS handshake benchmark (loopback)",
    "7. Per-algorithm production verdict",
    "8. Production capacity estimate (60% CPU headroom)",
    "9. Trust store inventory",
    "10. CNSA 2.0 compliance (NSA national security suite)",
)


def test_render_text_full_coverage_does_not_leak_none() -> None:
    """A fully-populated synthetic Report must not surface the literal
    string `None` anywhere in the human-readable output. This is the
    canonical f-string-of-an-unguarded-null-field regression: e.g.
    `f"   reason: {r.foo.get('reason')}"` where `reason` is missing
    yields `'None'` in the rendered text."""
    out = pr.render_text(_make_full_coverage_report())
    assert "None" not in out, (
        "render_text leaked the literal string 'None' into customer-facing "
        f"output — likely an f-string of an unguarded null field. Output:\n{out}"
    )


def test_render_text_full_coverage_includes_all_section_headings() -> None:
    """Both unconditional sections (1–5) and the six conditional ones
    must be present when every input field is populated. Catches a
    section being silently dropped during a refactor."""
    out = pr.render_text(_make_full_coverage_report())
    missing = [
        h for h in (*ALWAYS_PRESENT_HEADINGS, *CONDITIONAL_HEADINGS) if h not in out
    ]
    assert not missing, f"render_text missing section heading(s): {missing}"


def test_render_text_empty_report_is_non_empty_and_safe() -> None:
    """A bare `Report()` must still render — the script never produces
    an empty inventory in practice, but the renderer must not raise on
    default-initialised dataclass fields. Also asserts the always-on
    sections (1–5) appear and that no `None` leaks via a default-empty
    dict / list."""
    out = pr.render_text(pr.Report())
    assert out.strip(), "render_text on default Report() produced empty output"
    assert "None" not in out, (
        "render_text leaked 'None' on a default Report() — at least one "
        f"f-string is missing a guard:\n{out}"
    )
    for heading in ALWAYS_PRESENT_HEADINGS:
        assert heading in out, f"unconditional heading missing on empty Report: {heading}"


@pytest.mark.parametrize(
    "mutate",
    [
        # Each entry is a (label, callable) pair where the callable mutates
        # the synthetic Report to remove or null-shape one optional field.
        # Property-style: render must still succeed and not surface 'None'.
        pytest.param(lambda r: setattr(r, "benchmark", {}), id="benchmark-empty"),
        pytest.param(
            lambda r: setattr(r, "benchmark", {"available": False, "reason": "openssl missing"}),
            id="benchmark-unavailable-with-reason",
        ),
        pytest.param(
            lambda r: setattr(r, "benchmark", {"available": False}),
            id="benchmark-unavailable-without-reason",
        ),
        pytest.param(
            lambda r: setattr(r, "benchmark_tls_handshake", {}),
            id="bench-tls-empty",
        ),
        pytest.param(
            lambda r: setattr(r, "benchmark_tls_handshake", {"available": False, "reason": "loopback failed"}),
            id="bench-tls-unavailable-with-reason",
        ),
        pytest.param(
            lambda r: setattr(r, "benchmark_tls_handshake", {"available": False}),
            id="bench-tls-unavailable-without-reason",
        ),
        pytest.param(lambda r: setattr(r, "per_algo", {}), id="per-algo-empty"),
        pytest.param(
            lambda r: setattr(r, "production_estimate", {}),
            id="prod-estimate-empty",
        ),
        pytest.param(lambda r: setattr(r, "cnsa_2_0", {}), id="cnsa-empty"),
        pytest.param(
            lambda r: setattr(r, "trust_store", {}),
            id="trust-store-absent",
        ),
        pytest.param(
            lambda r: setattr(r, "openssl", {"available": False, "reason": "openssl not installed"}),
            id="openssl-unavailable",
        ),
        pytest.param(
            lambda r: setattr(r, "ssh_pqc", {}),
            id="ssh-pqc-empty",
        ),
        pytest.param(
            lambda r: setattr(r, "ipsec_pqc", {}),
            id="ipsec-empty",
        ),
        pytest.param(
            lambda r: setattr(r, "accelerators", []) or setattr(r, "tpm_pqc", {}),
            id="no-accelerators-no-tpm",
        ),
    ],
)
def test_render_text_partial_population_does_not_raise_or_leak_none(
    mutate: Any,
) -> None:
    """Vary which optional fields are populated and assert
    (a) the renderer returns without raising and
    (b) no f-string leaks `None` into the rendered output.

    This is the property-style guard the audit asked for: future
    additions of conditional sections must keep both invariants."""
    r = _make_full_coverage_report()
    mutate(r)
    out = pr.render_text(r)
    assert out.strip(), "render_text returned empty output for partial Report"
    assert "None" not in out, (
        f"render_text leaked 'None' for partial Report mutation; output:\n{out}"
    )
