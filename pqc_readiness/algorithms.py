"""PQC parameter sizes, production thresholds and per-algorithm notes."""

from __future__ import annotations


# ---------------------------------------------------------------------------
# NIST PQC parameter sizes (bytes) and per-algorithm production thresholds
# ---------------------------------------------------------------------------

PQC_SIZES = {
    "ML-KEM-768": {"role": "TLS KEM", "pk": 1184, "sk": 2400, "ct": 1088, "shared": 32},
    "ML-DSA-65": {"role": "general sig", "pk": 1952, "sk": 4032, "sig": 3309},
    "ML-DSA-87": {"role": "high-sec sig", "pk": 2592, "sk": 4896, "sig": 4627},
    "SLH-DSA-SHA2-128s": {"role": "small/slow sig", "pk": 32, "sk": 64, "sig": 7856},
    "SLH-DSA-SHA2-128f": {"role": "fast/large sig", "pk": 32, "sk": 64, "sig": 17088},
    "SLH-DSA-SHA2-256f": {"role": "high-sec sig", "pk": 64, "sk": 128, "sig": 49856},
}


# Per-core ops/sec thresholds for the bottleneck operation of each
# algorithm.  ML-KEM bottleneck = decaps (server-side TLS).  ML-DSA = sign
# (cert/JWT issuance) AND verify (clients consuming PQC certs are
# verify-bound, especially in mTLS hot paths).  SLH-DSA = sign
# (catastrophically slow without an accelerator).  Calibrated against
# published Intel SPR / AMD Zen 4 / Graviton 3 numbers (Cloudflare CIRCL
# benchmarks 2024–2025) and conservative for non-AVX-512 hosts.
#
# An algorithm may appear more than once when distinct operations
# matter — the per-algo verdict picks the worst tier across them.
ALGO_THRESHOLDS: dict[str, tuple[str, dict[str, float]]] = {
    "ML-KEM-768": ("decaps/s", {"excellent": 20000, "good": 8000, "marginal": 2000}),
    "ML-DSA-65": ("sign/s", {"excellent": 1500, "good": 600, "marginal": 150}),
    "ML-DSA-65/verify": (
        "verify/s",
        {"excellent": 8000, "good": 3000, "marginal": 500},
    ),
    "ML-DSA-87": ("sign/s", {"excellent": 1000, "good": 400, "marginal": 100}),
    "ML-DSA-87/verify": (
        "verify/s",
        {"excellent": 5000, "good": 2000, "marginal": 300},
    ),
    "SLH-DSA-SHA2-128s": ("sign/s", {"excellent": 5, "good": 2, "marginal": 0.5}),
}


# Memory-bandwidth threshold (GB/s) below which SLH-DSA tier is
# downgraded one level.  SLH-DSA's hash-tree work is bounded by main-
# memory bandwidth far more than by ALU throughput — a host with
# excellent ISA but poor RAM can still bottleneck on it.
SLH_DSA_MEM_BANDWIDTH_FLOOR_GB_S = 10.0


# Per-algorithm operational notes appended to the verdict.  Customer-
# facing text — be precise about what the tier label does and does not
# imply.  SLH-DSA's "excellent" tier still warrants the warning.
ALGO_NOTES: dict[str, list[str]] = {
    "SLH-DSA-SHA2-128s": [
        "SLH-DSA is unsuitable for hot-path use in software regardless of "
        "tier — even at the 'excellent' threshold of 5 sign/s/core it is "
        "orders of magnitude slower than ML-DSA.  Reserve for offline "
        "code-signing or rare-use cases; consider hardware offload for "
        "anything resembling production sign throughput."
    ],
}
