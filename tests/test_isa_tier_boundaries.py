# SPDX-License-Identifier: Apache-2.0
"""Boundary-value tests for ``isa_tier`` thresholds.

The score thresholds (x86_64 excellent >= 18, good >= 6; aarch64
excellent >= 8; s390x msa8+msa9) directly decide fleet-planning
verdicts, so an off-by-one would silently re-tier hosts.  Each case
builds a real flag set, derives the score with ``detect_isa`` (so the
catalog weights are exercised too), asserts the score lands exactly on
the boundary, then asserts the tier on each side of it.
"""

from __future__ import annotations

import pytest

import pqc_readiness as pr

# x86_64 — AVX-512 PQC core (f + vbmi + ifma = 9) + avx2/aes/pclmulqdq (4)
# + bw/vaes (4) = 17.  avx512vl (+1) tips it to 18.  aes + pclmulqdq keep
# the below-boundary case in "good" rather than falling to "marginal".
_X86_AVX512_17 = {
    "avx512f", "avx512vbmi", "avx512ifma",
    "avx2", "aes", "pclmulqdq", "avx512bw", "vaes",
}
_X86_AVX512_18 = _X86_AVX512_17 | {"avx512vl"}

# x86_64 — AVX2 + AES-NI + PCLMULQDQ = 4.  +avx512vl (1) = 5; +sha_ni (2) = 6.
_X86_AVX2_5 = {"avx2", "aes", "pclmulqdq", "avx512vl"}
_X86_AVX2_6 = {"avx2", "aes", "pclmulqdq", "sha_ni"}

# aarch64 — sha3 + aes + sha2 + pmull = 6.  +sha512 (1) = 7; +sve (2) = 8.
# No sve2 in either set: sve2 alone short-circuits to excellent.
_ARM_7 = {"sha3", "aes", "sha2", "pmull", "sha512"}
_ARM_8 = {"sha3", "aes", "sha2", "pmull", "sve"}


@pytest.mark.parametrize(
    ("arch", "flags", "expected_score", "expected_tier"),
    [
        ("x86_64", _X86_AVX512_17, 17, "good"),
        ("x86_64", _X86_AVX512_18, 18, "excellent"),
        ("x86_64", _X86_AVX2_5, 5, "marginal"),
        ("x86_64", _X86_AVX2_6, 6, "good"),
        ("aarch64", _ARM_7, 7, "good"),
        ("aarch64", _ARM_8, 8, "excellent"),
    ],
    ids=[
        "x86-17-not-excellent",
        "x86-18-excellent",
        "x86-5-not-good",
        "x86-6-good",
        "arm-7-not-excellent",
        "arm-8-excellent",
    ],
)
def test_isa_tier_score_boundaries(
    arch: str, flags: set[str], expected_score: int, expected_tier: str
) -> None:
    _, score = pr.detect_isa(arch, flags)
    assert score == expected_score, "fixture no longer sits on the boundary"
    tier, _ = pr.isa_tier(arch, score, flags)
    assert tier == expected_tier


def test_x86_score_18_without_avx512_pqc_core_is_not_excellent() -> None:
    """The score alone is not enough: >= 18 without the AVX-512 PQC
    instruction core (f+vbmi+ifma or f+vaes+vpclmulqdq) stays below
    excellent."""
    flags = {
        "avx2", "aes", "pclmulqdq", "avx512bw", "avx512vbmi2", "gfni",
        "sha_ni", "avx512vl", "avx512_vpopcntdq", "avx512_bitalg",
        "vaes", "avx512vbmi",
    }
    _, score = pr.detect_isa("x86_64", flags)
    assert score >= 18
    tier, _ = pr.isa_tier("x86_64", score, flags)
    assert tier == "good"


def test_x86_alternate_avx512_core_reaches_excellent_at_18() -> None:
    """The second AVX-512 PQC core (f + vaes + vpclmulqdq, no VBMI/IFMA)
    is accepted at exactly score 18."""
    flags = {
        "avx512f", "vaes", "vpclmulqdq",  # 7
        "avx2", "aes", "pclmulqdq",       # 4  -> 11
        "avx512bw", "gfni", "sha_ni",     # 6  -> 17
        "avx512vl",                       # 1  -> 18
    }
    _, score = pr.detect_isa("x86_64", flags)
    assert score == 18
    assert pr.isa_tier("x86_64", score, flags)[0] == "excellent"
    flags.discard("avx512vl")
    _, score = pr.detect_isa("x86_64", flags)
    assert score == 17
    assert pr.isa_tier("x86_64", score, flags)[0] == "good"


@pytest.mark.parametrize(
    ("flags", "expected_tier"),
    [
        ({"msa", "msa8", "msa9"}, "excellent"),
        ({"msa", "msa8"}, "marginal"),
        ({"msa", "msa9"}, "marginal"),
        ({"msa8", "msa9"}, "excellent"),
        (set(), "poor"),
    ],
    ids=["msa8+msa9", "msa8-only", "msa9-only", "msa8+msa9-no-base", "none"],
)
def test_s390x_requires_both_msa8_and_msa9_for_excellent(
    flags: set[str], expected_tier: str
) -> None:
    _, score = pr.detect_isa("s390x", flags)
    assert pr.isa_tier("s390x", score, flags)[0] == expected_tier
