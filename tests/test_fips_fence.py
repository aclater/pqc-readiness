"""Tests for the FIPS algorithm-fence check (#60).

Fixtures synthesized from the fleet-test captures:

- RHEL 10 FIPS-on: fence engaged (default-provider algorithm set is a
  subset of the FIPS-provider set).
- Rebuild-distro 10 FIPS-on: fence absent (default-provider exposes 3
  ML-KEM variants, the full ML-DSA suite, and the full SLH-DSA SHAKE/
  SHA2 suite that the FIPS provider does not list).
- FIPS-off: fence check skipped, no opinion.
"""

from __future__ import annotations

import re
from typing import Any

import pqc_readiness as pr


# ---------------------------------------------------------------------------
# Captured `openssl list ...` output by host class.  These are minimized
# but faithful to the per-class differences observed in the fleet test:
# the rebuild distro lists exactly the same FIPS-validated algorithms in
# the FIPS column AND the upstream-PQC algorithms in the default column.
# ---------------------------------------------------------------------------

# RHEL 10 FIPS-on: FIPS provider lists no ML-KEM (PQC not yet validated
# in RHEL FIPS); default provider with FIPS active is gated to the same
# (empty for KEMs) set by the downstream patches.
RHEL_FIPS_KEMS_FIPS = ""  # FIPS provider, no PQC KEMs validated
RHEL_FIPS_KEMS_DEFAULT = ""  # default provider, gated by downstream patch

# Rebuild distro FIPS-on: FIPS provider matches RHEL (same source of
# truth for the validated set), but the default provider exposes the
# upstream PQC set unchanged because the gating patches aren't carried.
REBUILD_FIPS_KEMS_FIPS = ""
REBUILD_FIPS_KEMS_DEFAULT = """
Provided KEMs:
  ML-KEM-512 @ default
  ML-KEM-768 @ default
  ML-KEM-1024 @ default
"""

REBUILD_FIPS_SIGS_FIPS = ""
REBUILD_FIPS_SIGS_DEFAULT = """
Provided signature algorithms:
  ML-DSA-44 @ default
  ML-DSA-65 @ default
  ML-DSA-87 @ default
  SLH-DSA-SHA2-128f @ default
  SLH-DSA-SHA2-128s @ default
  SLH-DSA-SHA2-192f @ default
  SLH-DSA-SHA2-192s @ default
  SLH-DSA-SHA2-256f @ default
  SLH-DSA-SHA2-256s @ default
  SLH-DSA-SHAKE-128f @ default
  SLH-DSA-SHAKE-128s @ default
  SLH-DSA-SHAKE-192f @ default
  SLH-DSA-SHAKE-192s @ default
  SLH-DSA-SHAKE-256f @ default
  SLH-DSA-SHAKE-256s @ default
"""


def test_fence_check_skipped_when_fips_inactive() -> None:
    """No kernel FIPS, no FIPS provider → fence check is skipped, not
    treated as a violation."""
    fips = {"kernel": False, "openssl_provider": False}
    out = pr.fips_fence_check(fips)
    assert out["active"] is False
    assert "skip_reason" in out
    assert out["algorithm_fence_engaged"] is False  # default until proven
    assert out["algorithms_reachable_outside_fence"]["kems"] == []
    assert out["algorithms_reachable_outside_fence"]["signatures"] == []


def test_fence_check_skipped_when_only_kernel_fips() -> None:
    """Kernel fips=1 alone (no active FIPS provider) is not enough — the
    fence concept is undefined without a FIPS provider to fence against."""
    fips = {"kernel": True, "openssl_provider": False}
    out = pr.fips_fence_check(fips)
    assert out["active"] is False
    assert "skip_reason" in out


def test_fence_parse_extracts_kem_names() -> None:
    """Parser extracts canonical ML-KEM names from openssl list output
    regardless of ordering, dedupes, and ignores noise."""
    extracted = pr._fence_parse_algos(REBUILD_FIPS_KEMS_DEFAULT, pr._FENCE_KEM_RE)
    assert extracted == ["ML-KEM-1024", "ML-KEM-512", "ML-KEM-768"]


def test_fence_parse_extracts_signature_names() -> None:
    extracted = pr._fence_parse_algos(REBUILD_FIPS_SIGS_DEFAULT, pr._FENCE_SIG_RE)
    # 3 ML-DSA + 6 SLH-DSA-SHA2 + 6 SLH-DSA-SHAKE = 15
    assert len(extracted) == 15
    assert "ML-DSA-87" in extracted
    assert "SLH-DSA-SHAKE-256f" in extracted
    assert "SLH-DSA-SHA2-128s" in extracted


def test_fence_engaged_when_default_subset_of_fips(monkeypatch: Any) -> None:
    """Both providers list the same (empty) PQC set → fence engaged.
    Models the RHEL FIPS-on case where the gating patches do their job."""

    def fake_provider_algos(
        list_arg: str, pattern: re.Pattern[str], provider: str
    ) -> list[str]:
        return []  # RHEL: neither column lists PQC

    monkeypatch.setattr(pr, "_fence_provider_algos", fake_provider_algos)
    monkeypatch.setattr(
        pr, "_run", lambda *a, **kw: (1, "")
    )  # tls-groups query unavailable / no diff

    fips = {"kernel": True, "openssl_provider": True}
    out = pr.fips_fence_check(fips)
    assert out["active"] is True
    assert out["algorithm_fence_engaged"] is True
    assert out["algorithms_reachable_outside_fence"]["kems"] == []
    assert out["algorithms_reachable_outside_fence"]["signatures"] == []


def test_fence_absent_when_default_strict_superset(monkeypatch: Any) -> None:
    """Default provider exposes ML-KEM and ML-DSA/SLH-DSA that the FIPS
    provider does not → fence absent.  Models the rebuild-distro case
    that motivated #60."""
    fence_outputs = {
        ("-kem-algorithms", "fips"): [],
        ("-kem-algorithms", "default"): ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"],
        ("-signature-algorithms", "fips"): [],
        ("-signature-algorithms", "default"): [
            "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
            "SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-128s",
            "SLH-DSA-SHA2-192f", "SLH-DSA-SHA2-192s",
            "SLH-DSA-SHA2-256f", "SLH-DSA-SHA2-256s",
            "SLH-DSA-SHAKE-128f", "SLH-DSA-SHAKE-128s",
            "SLH-DSA-SHAKE-192f", "SLH-DSA-SHAKE-192s",
            "SLH-DSA-SHAKE-256f", "SLH-DSA-SHAKE-256s",
        ],
    }

    def fake_provider_algos(
        list_arg: str, pattern: re.Pattern[str], provider: str
    ) -> list[str]:
        return fence_outputs.get((list_arg, provider), [])

    monkeypatch.setattr(pr, "_fence_provider_algos", fake_provider_algos)
    monkeypatch.setattr(pr, "_run", lambda *a, **kw: (1, ""))

    fips = {"kernel": True, "openssl_provider": True}
    out = pr.fips_fence_check(fips)
    assert out["active"] is True
    assert out["algorithm_fence_engaged"] is False
    assert out["algorithms_reachable_outside_fence"]["kems"] == [
        "ML-KEM-1024", "ML-KEM-512", "ML-KEM-768"
    ]
    sigs_outside = out["algorithms_reachable_outside_fence"]["signatures"]
    assert len(sigs_outside) == 15
    assert "ML-DSA-87" in sigs_outside


def test_fence_absent_when_default_partial_overlap(monkeypatch: Any) -> None:
    """FIPS validates ML-DSA but the default provider also exposes
    SLH-DSA → fence absent because the default set is a strict superset."""
    fence_outputs = {
        ("-kem-algorithms", "fips"): [],
        ("-kem-algorithms", "default"): [],
        ("-signature-algorithms", "fips"): ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"],
        ("-signature-algorithms", "default"): [
            "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
            "SLH-DSA-SHAKE-256f",  # only this is "outside the fence"
        ],
    }

    def fake_provider_algos(
        list_arg: str, pattern: re.Pattern[str], provider: str
    ) -> list[str]:
        return fence_outputs.get((list_arg, provider), [])

    monkeypatch.setattr(pr, "_fence_provider_algos", fake_provider_algos)
    monkeypatch.setattr(pr, "_run", lambda *a, **kw: (1, ""))

    fips = {"kernel": True, "openssl_provider": True}
    out = pr.fips_fence_check(fips)
    assert out["algorithm_fence_engaged"] is False
    assert out["algorithms_reachable_outside_fence"]["kems"] == []
    assert out["algorithms_reachable_outside_fence"]["signatures"] == [
        "SLH-DSA-SHAKE-256f"
    ]


def test_sarif_rule_pqc_007_registered() -> None:
    """The new rule descriptor is in RULE_SPECS and is rated 'error'."""
    rule_ids = {spec.id for spec in pr.RULE_SPECS}
    assert "pqc-007-fips-without-algorithm-fence" in rule_ids
    rule = next(
        s for s in pr.RULE_SPECS if s.id == "pqc-007-fips-without-algorithm-fence"
    )
    assert rule.default_level == "error"
