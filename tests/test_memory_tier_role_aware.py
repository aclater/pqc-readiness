"""Tests for role-aware memory tiering (#61).

The fleet test that motivated #61 ran three memory profiles (2 GiB,
6 GiB, 18 GiB) against a 12-VM matrix.  These tests assert the
per-role tier decisions the issue spec'd at those exact profiles, plus
the `memory.tier_by_role` behavior when --role is not supplied.
"""

from __future__ import annotations

import pqc_readiness as pr


# Three memory profiles from the fleet test runs (after the kernel's
# ~5% reservation, 16384 MiB lands at ~15.6 GiB, hence the explicit
# below-/at-/above-threshold split rather than round numbers).
PROFILES_GIB = (2.0, 6.0, 18.0)


# Role → expected tier at (2, 6, 18 GiB) — driven by the per-role good
# thresholds in MEMORY_TIER_GOOD_THRESHOLD_BY_ROLE.
EXPECTED_TIERS_BY_ROLE: dict[str, tuple[str, str, str]] = {
    # 2 GiB lands below every role's good threshold except firmware-signing
    # (2 GiB).  6 GiB clears tls-client (4) and firmware-signing (2) but
    # not signing-service (8) or tls-server/generic (16).  18 GiB clears
    # all roles' good thresholds.
    "tls-server":       ("poor", "marginal", "good"),     # threshold 16
    "tls-client":       ("poor", "good",     "good"),     # threshold 4
    "signing-service":  ("poor", "marginal", "good"),     # threshold 8
    "firmware-signing": ("good", "good",     "good"),     # threshold 2
    "generic":          ("poor", "marginal", "good"),     # threshold 16
}


def test_memory_tier_thresholds_table_is_complete() -> None:
    """Every role in VALID_ROLES has a threshold; no extras."""
    assert set(pr.MEMORY_TIER_GOOD_THRESHOLD_BY_ROLE) == set(pr.VALID_ROLES)


def test_memory_tier_per_role_at_fleet_profiles() -> None:
    """All five roles × all three fleet-profile memory values produce
    the tier the issue spec'd."""
    for role, (t2, t6, t18) in EXPECTED_TIERS_BY_ROLE.items():
        tier_2, _ = pr.memory_tier(2.0, role)
        tier_6, _ = pr.memory_tier(6.0, role)
        tier_18, _ = pr.memory_tier(18.0, role)
        assert tier_2 == t2, f"role={role} @ 2 GiB: expected {t2}, got {tier_2}"
        assert tier_6 == t6, f"role={role} @ 6 GiB: expected {t6}, got {tier_6}"
        assert tier_18 == t18, f"role={role} @ 18 GiB: expected {t18}, got {tier_18}"


def test_memory_tier_unknown_role_falls_back_to_generic() -> None:
    """A role not in the table falls back to generic (16 GiB threshold)."""
    tier_unknown, _ = pr.memory_tier(8.0, "made-up-role")
    tier_generic, _ = pr.memory_tier(8.0, "generic")
    assert tier_unknown == tier_generic == "marginal"


def test_memory_tier_default_role_is_generic_back_compat() -> None:
    """Calling memory_tier(gb) with no role argument preserves the
    pre-#61 behavior — 16 GiB threshold, equivalent to generic."""
    for gb in PROFILES_GIB:
        tier_default, reason_default = pr.memory_tier(gb)
        tier_generic, reason_generic = pr.memory_tier(gb, "generic")
        assert tier_default == tier_generic
        assert reason_default == reason_generic


def test_memory_tier_all_roles_returns_one_entry_per_role() -> None:
    """memory_tier_all_roles() emits one entry per VALID_ROLES role."""
    for gb in PROFILES_GIB:
        out = pr.memory_tier_all_roles(gb)
        assert set(out) == set(pr.VALID_ROLES)
        for role, entry in out.items():
            assert "tier" in entry
            assert "reason" in entry
            assert "threshold_gib_good" in entry
            assert (
                entry["threshold_gib_good"]
                == pr.MEMORY_TIER_GOOD_THRESHOLD_BY_ROLE[role]
            )


def test_memory_tier_excellent_is_role_independent() -> None:
    """The 64 GiB excellent threshold is role-independent — only the
    marginal/good boundary varies by role."""
    for role in pr.VALID_ROLES:
        tier, _ = pr.memory_tier(128.0, role)
        assert tier == "excellent"


def test_memory_tier_poor_is_role_independent() -> None:
    """The 4 GiB poor threshold is role-independent — even firmware-
    signing (which lists 2 GiB as good) returns "poor" below 4 GiB
    because the absolute floor is unchanged."""
    for role in pr.VALID_ROLES:
        tier, _ = pr.memory_tier(1.0, role)
        assert tier == "poor"


def test_schema_version_bumped_for_role_aware_memory() -> None:
    """Adding role-aware memory fields is additive but bumps the schema
    minor version — the aggregator rejects mismatched schemas, so this
    bump is what causes 1.0 reports to be skipped rather than silently
    merged with reports that have memory.tier_by_role populated."""
    assert pr.SCHEMA_VERSION == "1.1"
