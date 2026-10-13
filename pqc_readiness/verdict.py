"""CNSA 2.0 evaluation, per-algorithm verdicts, production estimates and the overall verdict."""

from __future__ import annotations

import logging
import re
from typing import Any

from . import algorithms as _algorithms

log = logging.getLogger("pqc-readiness")


# ---------------------------------------------------------------------------
# CNSA 2.0 compliance (NSA Commercial National Security Algorithm Suite 2.0)
# ---------------------------------------------------------------------------
# CNSA 2.0 is the NSA's mandatory algorithm suite for U.S. National Security
# Systems with full deployment required by 2035.  Federal customers (and any
# defence-supply-chain customer) ask "are we CNSA 2.0 compliant?".  The suite
# is locked to the highest-security NIST PQC parameter sets (ML-KEM-1024,
# ML-DSA-87) plus AES-256 and SHA-384/512 — note the 1024 / 87 selections,
# not the more common ML-KEM-768 / ML-DSA-65 most stacks default to today.
#
# Source: NSA CSA "Announcing the Commercial National Security Algorithm
# Suite 2.0" (Sept 2022) plus the NSA timeline updates published since.
# https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF
#
# Updates as CNSA evolves are a one-line edit in this dict.
CNSA_2_0_REQUIREMENTS: dict[str, list[str]] = {
    "kem": ["ML-KEM-1024"],
    "signature": ["ML-DSA-87"],
    "symmetric": ["AES-256"],
    "hash": ["SHA-384", "SHA-512"],
}


# Driver-name suffixes that indicate a hardware-accelerated /proc/crypto
# entry — matches the same set used by detect_kernel_crypto_hw() so the
# CNSA hash check stays consistent with the rest of the report.
_HW_DRIVER_SUFFIXES: tuple[str, ...] = (
    "-ni",
    "-ce",
    "-ssse3",
    "-avx2",
    "-avx",
    "-arm64-ce",
    "-arm64",
    "-aesni",
    "-pclmul",
    "-sha-ce",
    "-sha-ni",
    "_asm",
    "-paes",
)


def parse_proc_crypto_cnsa(text: str) -> dict[str, Any]:
    """Inspect /proc/crypto blocks for CNSA 2.0 symmetric and hash inputs.

    Returns:
        {
            "aes_256":            bool,        # AES cipher with 256-bit key
            "sha_384_hw_driver":  str | None,  # name of HW-accel driver
            "sha_512_hw_driver":  str | None,
        }

    AES-256 is detected as any /proc/crypto block whose `name` mentions
    `aes` and whose `max keysize` is >= 32 (256 bits).  SHA-384/SHA-512
    are reported only when the matching block's `driver` ends in a known
    hardware-accel suffix — software-only fallbacks do not satisfy CNSA.
    """
    blocks: list[dict[str, str]] = []
    cur: dict[str, str] = {}
    # Trailing empty entry forces flush of the final block.
    for line in text.splitlines() + [""]:
        if not line.strip():
            if cur:
                blocks.append(cur)
                cur = {}
            continue
        m = re.match(r"^\s*([^:]+?)\s*:\s*(.*)$", line)
        if m:
            cur[m.group(1).strip().lower()] = m.group(2).strip()
    aes_256 = False
    sha_384_hw: str | None = None
    sha_512_hw: str | None = None
    for b in blocks:
        name = b.get("name", "").lower()
        driver = b.get("driver", "")
        if "aes" in name:
            try:
                if int(b.get("max keysize", "0")) >= 32:
                    aes_256 = True
            except ValueError as e:
                log.debug(
                    "parse_proc_crypto_cnsa: unparseable max keysize %r for %s: %s",
                    b.get("max keysize"),
                    name,
                    e,
                )
        if name == "sha384" and sha_384_hw is None:
            if any(s in driver for s in _HW_DRIVER_SUFFIXES):
                sha_384_hw = driver
        if name == "sha512" and sha_512_hw is None:
            if any(s in driver for s in _HW_DRIVER_SUFFIXES):
                sha_512_hw = driver
    return {
        "aes_256": aes_256,
        "sha_384_hw_driver": sha_384_hw,
        "sha_512_hw_driver": sha_512_hw,
    }


def _cnsa_tls_key_exchange(openssl: dict[str, Any]) -> dict[str, list[str]]:
    """Split the PQC TLS groups OpenSSL offers into CNSA 2.0-compliant
    (ML-KEM-1024 component) and not.  X25519MLKEM768, the IANA-recommended
    default, is *not* compliant: CNSA 2.0 approves ML-KEM-1024 only (NSA
    CNSA 2.0 FAQ v2.1).  Hybrids are permitted but not required, so
    SecP384r1MLKEM1024 counts.  Informational: `status` is decided by the
    algorithm checks, not by which groups are configured."""
    groups = openssl.get("tls_groups") or {}
    offered = [*(groups.get("pure_pqc") or []), *(groups.get("hybrid") or [])]
    refs = _algorithms.tls_group_references(offered)
    return {
        "compliant_groups": sorted(n for n, r in refs.items() if r["cnsa_2_0"]),
        "non_compliant_pqc_groups": sorted(
            n for n in offered if not (refs.get(n) or {}).get("cnsa_2_0")
        ),
    }


def evaluate_cnsa_2_0(
    openssl: dict[str, Any],
    proc_crypto_text: str | None,
) -> dict[str, Any]:
    """Classify the host against CNSA 2.0.

    Returns a dict matching the cnsa_2_0 report schema:
        status:               "compliant" | "partial" | "non_compliant" | "unknown"
        kem_compliant:        bool   # ML-KEM-1024 detected and usable
        signature_compliant:  bool   # ML-DSA-87 detected and usable
        symmetric_compliant:  bool   # AES-256 in /proc/crypto
        hash_compliant:       bool   # SHA-384 AND SHA-512 hardware-accelerated
        notes:                list[str]   # human-readable gap explanations
        requirements:         dict        # declarative copy of CNSA_2_0_REQUIREMENTS

    Each compliance bool is True only when affirmative evidence was found.
    A False reading covers both "checked and missing" and "could not check"
    — the reason is captured in `notes` so a human reading the report can
    distinguish a genuinely non-compliant host from one we lack the
    detection inputs for.  When NO underlying detection produced evidence
    (openssl absent AND /proc/crypto absent), status is "unknown" rather
    than "non_compliant" so callers do not act on a vacuously-False reading.
    """
    notes: list[str] = []
    openssl_known = bool(openssl.get("available"))
    proc_known = proc_crypto_text is not None

    kem = openssl_known and "ML-KEM-1024" in (openssl.get("kem_algorithms") or [])
    sig = openssl_known and "ML-DSA-87" in (openssl.get("sig_algorithms") or [])
    if not openssl_known:
        notes.append(
            "OpenSSL not available; cannot verify ML-KEM-1024 (KEM) or "
            "ML-DSA-87 (signature) availability."
        )
    else:
        if not kem:
            notes.append(
                "ML-KEM-1024 is not exposed by OpenSSL.  CNSA 2.0 mandates "
                "ML-KEM-1024 (not ML-KEM-768) for asymmetric key establishment."
            )
        if not sig:
            notes.append(
                "ML-DSA-87 is not exposed by OpenSSL.  CNSA 2.0 mandates "
                "ML-DSA-87 (not ML-DSA-65) for asymmetric signatures."
            )

    if proc_known:
        pc = parse_proc_crypto_cnsa(proc_crypto_text or "")
        sym = bool(pc["aes_256"])
        hash_ok = bool(pc["sha_384_hw_driver"]) and bool(pc["sha_512_hw_driver"])
        if not sym:
            notes.append(
                "AES-256 not found in /proc/crypto (no AES driver block "
                "with max keysize >= 32 bytes)."
            )
        if not hash_ok:
            missing: list[str] = []
            if not pc["sha_384_hw_driver"]:
                missing.append("SHA-384")
            if not pc["sha_512_hw_driver"]:
                missing.append("SHA-512")
            notes.append(
                f"{' and '.join(missing)} not hardware-accelerated in "
                "/proc/crypto.  CNSA 2.0 mandates SHA-384 and SHA-512; "
                "software-only kernel fallbacks do not satisfy the suite."
            )
    else:
        sym = False
        hash_ok = False
        notes.append(
            "/proc/crypto not available; cannot verify AES-256 (symmetric) "
            "or hardware-accelerated SHA-384/SHA-512 (hash)."
        )

    tls_kex = _cnsa_tls_key_exchange(openssl)
    if tls_kex["non_compliant_pqc_groups"] and not tls_kex["compliant_groups"]:
        notes.append(
            "TLS offers PQC key exchange only through groups that do not meet "
            f"CNSA 2.0 ({', '.join(tls_kex['non_compliant_pqc_groups'])}): their "
            "ML-KEM component is not ML-KEM-1024.  A CNSA 2.0 TLS deployment "
            "needs SecP384r1MLKEM1024 (RFC 10024) or pure MLKEM1024 "
            "(draft-ietf-tls-mlkem)."
        )

    fields = (kem, sig, sym, hash_ok)
    if not openssl_known and not proc_known:
        status = "unknown"
    elif all(fields):
        status = "compliant"
    elif not any(fields):
        status = "non_compliant"
    else:
        status = "partial"

    return {
        "status": status,
        "kem_compliant": kem,
        "signature_compliant": sig,
        "symmetric_compliant": sym,
        "hash_compliant": hash_ok,
        "tls_key_exchange": tls_kex,
        "notes": notes,
        "requirements": {k: list(v) for k, v in CNSA_2_0_REQUIREMENTS.items()},
    }


# ---------------------------------------------------------------------------
# Per-algorithm and overall verdicts
# ---------------------------------------------------------------------------

_TIER_ORDER = ["poor", "marginal", "good", "excellent"]


def per_algo_verdict(
    bench: dict[str, Any],
    cores: int,
    mem_bw_gb_s: float | None = None,
    tls_hybrid_available: bool = False,
) -> dict[str, dict[str, Any]]:
    """Score each entry in ALGO_THRESHOLDS against measured rates.

    ALGO_THRESHOLDS keys may be a bare algorithm name (`ML-DSA-65`) or
    suffixed with the operation being scored (`ML-DSA-65/verify`).  The
    bare prefix is the bench lookup key; the trailing token disambiguates
    multiple thresholds on the same algorithm.

    SLH-DSA tier is downgraded by one step when measured memory
    bandwidth falls below SLH_DSA_MEM_BANDWIDTH_FLOOR_GB_S.  The
    downgrade is only applied when mem_bw_gb_s is non-None (the probe
    actually ran); a missing measurement does not trigger it.

    When `tls_hybrid_available` is True, ML-KEM verdicts get a
    transitional-deployment note pointing at the hybrid TLS groups —
    the IETF-recommended path while pure PQC interop is still
    stabilising.
    """
    out: dict[str, dict[str, Any]] = {}
    pqc = bench.get("pqc") if bench.get("available") else None
    for key, (op, thresholds) in _algorithms.ALGO_THRESHOLDS.items():
        algo = key.split("/", 1)[0]
        bench_algo = (pqc or {}).get(algo)
        notes = list(_algorithms.ALGO_NOTES.get(algo, []))
        if tls_hybrid_available and algo.startswith("ML-KEM"):
            notes.append(
                "Hybrid TLS groups (e.g. X25519MLKEM768, SecP256r1MLKEM768) "
                "are exposed by OpenSSL — preferred over pure PQC for "
                "transitional deployments where peer interoperability "
                "and PQC-stack maturity are still in flux."
            )
        if not bench_algo or op not in bench_algo:
            out[key] = {
                "algorithm": algo,
                "tier": "unknown",
                "reason": (bench_algo or {}).get("skipped") or "no benchmark data",
                "metric": op,
                "notes": notes,
            }
            continue
        rate = float(bench_algo[op])
        if rate >= thresholds["excellent"]:
            tier = "excellent"
        elif rate >= thresholds["good"]:
            tier = "good"
        elif rate >= thresholds["marginal"]:
            tier = "marginal"
        else:
            tier = "poor"
        if (
            algo == "SLH-DSA-SHA2-128s"
            and mem_bw_gb_s is not None
            and mem_bw_gb_s < _algorithms.SLH_DSA_MEM_BANDWIDTH_FLOOR_GB_S
        ):
            old_tier = tier
            idx = max(0, _TIER_ORDER.index(tier) - 1)
            tier = _TIER_ORDER[idx]
            notes.append(
                f"Tier downgraded from '{old_tier}' to '{tier}': measured "
                f"memory bandwidth {mem_bw_gb_s:.1f} GB/s is below the "
                f"{_algorithms.SLH_DSA_MEM_BANDWIDTH_FLOOR_GB_S:.0f} GB/s floor for "
                "SLH-DSA hash-tree throughput."
            )
        host_rate = rate * cores
        out[key] = {
            "algorithm": algo,
            "tier": tier,
            "metric": op,
            "rate_per_core": round(rate, 2),
            "rate_host_estimate": round(host_rate, 2),
            "thresholds": thresholds,
            "reason": f"{rate:.1f} {op}/core - threshold for '{tier}' is {thresholds.get(tier, '-')}",
            "notes": notes,
        }
    return out


def production_estimate(
    per_algo: dict[str, dict[str, Any]], mem_gb: float
) -> dict[str, Any]:
    """Translate per-core rates into 'how many TLS-PQC handshakes / signatures
    can this host realistically sustain?'  Conservative: assume 60% CPU
    headroom for non-crypto work in a real TLS server."""
    headroom = 0.6
    out: dict[str, Any] = {}
    kem = per_algo.get("ML-KEM-768", {})
    if "rate_host_estimate" in kem:
        out["tls_pqc_handshakes_per_sec"] = int(kem["rate_host_estimate"] * headroom)
    dsa = per_algo.get("ML-DSA-65", {})
    if "rate_host_estimate" in dsa:
        out["ml_dsa_signatures_per_sec"] = int(dsa["rate_host_estimate"] * headroom)
    slh = per_algo.get("SLH-DSA-SHA2-128s", {})
    if "rate_host_estimate" in slh:
        out["slh_dsa_sha2_128s_signatures_per_sec"] = round(
            slh["rate_host_estimate"] * headroom, 1
        )
    # Per-connection memory accounting.  The earlier 32 KB figure ignored
    # default Linux socket buffers, ML-KEM ciphertext (1088 B), the
    # ML-DSA cert chain (typically 8-12 KB across 2-3 certs), TLS state,
    # and userspace buffers.  192 KB is a realistic floor for a TLS
    # server doing PQC; 32 KB is the lower theoretical bound for
    # comparison.  50% of RAM is reserved for non-connection use
    # (binary, kernel, working memory headroom).
    if mem_gb > 0:
        usable_bytes = mem_gb * (1024**3) * 0.5
        out["concurrent_connections_realistic"] = int(usable_bytes / (192 * 1024))
        out["concurrent_connections_theoretical_max"] = int(usable_bytes / (32 * 1024))
        out["assumptions"] = (
            "realistic: 192 KB/conn (TCP buffers + ML-KEM ct + ML-DSA cert "
            "chain + TLS state + userspace); theoretical max: 32 KB/conn "
            "(minimal PQC handshake state only); 50% RAM reserved"
        )
    return out


def overall_verdict(
    isa: str,
    mem: str,
    dedicated: bool,
    per_algo: dict[str, dict[str, Any]],
) -> tuple[str, str, int, str]:
    """Compose ISA, memory, and (when available) measured per-algorithm
    tiers into one verdict.  Returns (verdict, why, exit_code, caveat).

    Distinguishes 'tested and bad' from 'could not test':
      - When per-algo verdicts are present, they participate in min().
      - When all per-algo verdicts are 'unknown' (bench didn't run, or
        OpenSSL too old), the verdict is based on ISA + memory only and
        a caveat string is returned explaining what was not measured.
        A missing benchmark must not falsely drag an otherwise-capable
        host to the floor.
    """
    if dedicated:
        return (
            "EXCELLENT - dedicated PQC silicon present",
            "Use the accelerator for keygen/sign/decap; software path covers the rest.",
            0,
            "",
        )
    rank = {
        "excellent": 4,
        "good": 3,
        "marginal": 2,
        "poor": 1,
        "unknown": 2,
    }
    bench_tiers = [
        v["tier"] for v in per_algo.values() if v.get("tier") not in (None, "unknown")
    ]
    has_bench = bool(bench_tiers)
    isa_score = rank.get(isa, 2)
    mem_score = rank.get(mem, 2)
    if has_bench:
        composite = min(isa_score, mem_score, min(rank[t] for t in bench_tiers))
        caveat = ""
    else:
        composite = min(isa_score, mem_score)
        caveat = (
            "Verdict reflects CPU instruction-set and memory only; no PQC "
            "microbenchmark was run on this host.  Re-run with --bench for "
            "measured per-algorithm rates and tier validation."
        )
    if composite >= 4:
        return (
            "EXCELLENT - software PQC at production speed",
            "On-chip SIMD covers ML-KEM/ML-DSA easily; SLH-DSA acceptable for non-hot paths.",
            0,
            caveat,
        )
    if composite == 3:
        return (
            "GOOD - production-capable in software",
            "Fine for TLS termination at moderate QPS; benchmark before committing to SLH-DSA.",
            1,
            caveat,
        )
    if composite == 2:
        return (
            "MARGINAL - works, but plan for an accelerator",
            "Software PQC will be a hot spot under load; consider HSM/QAT offload.",
            2,
            caveat,
        )
    return (
        "POOR - not suitable for production PQC",
        "Add a dedicated accelerator or upgrade the host.",
        3,
        caveat,
    )
