"""PQC parameter sizes, production thresholds and per-algorithm notes."""

from __future__ import annotations

from typing import Any


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


# ---------------------------------------------------------------------------
# Standards references and registered key-exchange names (#139)
# ---------------------------------------------------------------------------
#
# Every entry was checked against the primary source on 2026-10-13:
# the IANA TLS Supported Groups and SSH Key Exchange Method Names
# registries, rfc-editor.org metadata, the IETF datatracker and NIST CSRC.
# `status` is "final" for a published RFC / FIPS and "draft" for anything
# still an Internet-Draft or a NIST initial public draft, so reports never
# present a draft as settled.  Update this table, not the call sites.
STANDARDS: dict[str, dict[str, str]] = {
    "FIPS 203": {
        "title": "Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM)",
        "status": "final",
        "date": "2024-08-13",
        "url": "https://csrc.nist.gov/pubs/fips/203/final",
    },
    "FIPS 204": {
        "title": "Module-Lattice-Based Digital Signature Standard (ML-DSA)",
        "status": "final",
        "date": "2024-08-13",
        "url": "https://csrc.nist.gov/pubs/fips/204/final",
    },
    "FIPS 205": {
        "title": "Stateless Hash-Based Digital Signature Standard (SLH-DSA)",
        "status": "final",
        "date": "2024-08-13",
        "url": "https://csrc.nist.gov/pubs/fips/205/final",
    },
    "NIST IR 8547": {
        "title": "Transition to Post-Quantum Cryptography Standards",
        "status": "draft",
        "date": "2024-11-12",
        "note": "initial public draft; no final version published",
        "url": "https://csrc.nist.gov/pubs/ir/8547/ipd",
    },
    "RFC 10024": {
        "title": "Post-Quantum Traditional (PQ/T) Hybrid Key Agreement Mechanisms for TLS 1.3",
        "status": "final",
        "date": "2026-08",
        "note": "Proposed Standard",
        "url": "https://www.rfc-editor.org/rfc/rfc10024",
    },
    "RFC 9954": {
        "title": "Hybrid Key Exchange in TLS 1.3",
        "status": "final",
        "date": "2026-07",
        "note": "Informational",
        "url": "https://www.rfc-editor.org/rfc/rfc9954",
    },
    "RFC 10042": {
        "title": "Post-Quantum/Traditional Hybrid Key Exchange with ML-KEM in SSH",
        "status": "final",
        "date": "2026-08",
        "note": "Informational",
        "url": "https://www.rfc-editor.org/rfc/rfc10042",
    },
    "RFC 9941": {
        "title": "SSH Key Exchange Method Using Hybrid sntrup761 and X25519",
        "status": "final",
        "date": "2026-04",
        "note": "Informational",
        "url": "https://www.rfc-editor.org/rfc/rfc9941",
    },
    "draft-ietf-tls-mlkem": {
        "title": "ML-KEM Post-Quantum Key Agreement for TLS 1.3",
        "status": "draft",
        "date": "2026-10-12",
        "note": "revision -11, in the RFC Editor queue",
        "url": "https://datatracker.ietf.org/doc/draft-ietf-tls-mlkem/",
    },
    "draft-ietf-lamps-pq-composite-sigs": {
        "title": "Composite ML-DSA for use in X.509 PKI and CMS",
        "status": "draft",
        "date": "2026-10-02",
        "note": "revision -19, in the RFC Editor queue",
        "url": "https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/",
    },
}


# TLS 1.3 named groups carrying ML-KEM (IANA TLS Supported Groups).
# `recommended` mirrors the IANA "Recommended" column.  `cnsa_2_0` is True
# only when the ML-KEM component is ML-KEM-1024: CNSA 2.0 approves
# ML-KEM-1024 alone for key establishment and does not require (but
# permits) hybrids (NSA CNSA 2.0 FAQ v2.1, Dec 2024), so the P-384 hybrid
# qualifies and every ML-KEM-768 group does not.
TLS_PQC_GROUPS: dict[str, dict[str, object]] = {
    "X25519MLKEM768": {
        "codepoint": 0x11EC,
        "kem": "ML-KEM-768",
        "classical": "X25519",
        "reference": "RFC 10024",
        "recommended": True,
        "cnsa_2_0": False,
    },
    "SecP256r1MLKEM768": {
        "codepoint": 0x11EB,
        "kem": "ML-KEM-768",
        "classical": "secp256r1",
        "reference": "RFC 10024",
        "recommended": False,
        "cnsa_2_0": False,
    },
    "SecP384r1MLKEM1024": {
        "codepoint": 0x11ED,
        "kem": "ML-KEM-1024",
        "classical": "secp384r1",
        "reference": "RFC 10024",
        "recommended": False,
        "cnsa_2_0": True,
    },
    "MLKEM512": {
        "codepoint": 0x0200,
        "kem": "ML-KEM-512",
        "classical": None,
        "reference": "draft-ietf-tls-mlkem",
        "recommended": False,
        "cnsa_2_0": False,
    },
    "MLKEM768": {
        "codepoint": 0x0201,
        "kem": "ML-KEM-768",
        "classical": None,
        "reference": "draft-ietf-tls-mlkem",
        "recommended": False,
        "cnsa_2_0": False,
    },
    "MLKEM1024": {
        "codepoint": 0x0202,
        "kem": "ML-KEM-1024",
        "classical": None,
        "reference": "draft-ietf-tls-mlkem",
        "recommended": False,
        "cnsa_2_0": True,
    },
    # Pre-standard Kyber groups, obsoleted by RFC 10024 (IANA marks them
    # OBSOLETE / "D"); still worth naming when an old build offers them.
    "X25519Kyber768Draft00": {
        "codepoint": 0x6399,
        "kem": "Kyber768 (pre-standard)",
        "classical": "X25519",
        "reference": "RFC 10024",
        "recommended": False,
        "cnsa_2_0": False,
        "obsolete": True,
    },
    "SecP256r1Kyber768Draft00": {
        "codepoint": 0x639A,
        "kem": "Kyber768 (pre-standard)",
        "classical": "secp256r1",
        "reference": "RFC 10024",
        "recommended": False,
        "cnsa_2_0": False,
        "obsolete": True,
    },
}


# SSH key exchange method names (IANA SSH Key Exchange Method Names).
# OpenSSH also ships the pre-RFC `@openssh.com` alias for sntrup761.
SSH_PQC_KEX: dict[str, dict[str, object]] = {
    "mlkem768x25519-sha256": {
        "kem": "ML-KEM-768",
        "classical": "X25519",
        "reference": "RFC 10042",
        "cnsa_2_0": False,
    },
    "mlkem768nistp256-sha256": {
        "kem": "ML-KEM-768",
        "classical": "nistp256",
        "reference": "RFC 10042",
        "cnsa_2_0": False,
    },
    "mlkem1024nistp384-sha384": {
        "kem": "ML-KEM-1024",
        "classical": "nistp384",
        "reference": "RFC 10042",
        "cnsa_2_0": True,
    },
    "sntrup761x25519-sha512": {
        "kem": "sntrup761",
        "classical": "X25519",
        "reference": "RFC 9941",
        "cnsa_2_0": False,
    },
    "sntrup761x25519-sha512@openssh.com": {
        "kem": "sntrup761",
        "classical": "X25519",
        "reference": "RFC 9941",
        "cnsa_2_0": False,
        "alias_of": "sntrup761x25519-sha512",
    },
}


def standard_ref(key: str) -> dict[str, str]:
    """`{reference, status, url}` for a STANDARDS key, for embedding next
    to a name in report output."""
    std = STANDARDS[key]
    return {"reference": key, "status": std["status"], "url": std["url"]}


def tls_group_references(group_names: list[str]) -> dict[str, dict[str, object]]:
    """Registry facts for every known PQC TLS group in `group_names`:
    codepoint (hex string, as IANA lists it), components, reference and
    its draft/final status, IANA recommendation and CNSA 2.0 eligibility.
    Unknown names are omitted, matching classify_tls_groups."""
    out: dict[str, dict[str, object]] = {}
    for name in group_names:
        g = TLS_PQC_GROUPS.get(name)
        if g is None:
            continue
        entry: dict[str, object] = {
            "codepoint": f"0x{int(g['codepoint']):04X}",  # type: ignore[call-overload]
            "kem": g["kem"],
            "classical": g["classical"],
            "recommended": g["recommended"],
            "cnsa_2_0": g["cnsa_2_0"],
            **standard_ref(str(g["reference"])),
        }
        if g.get("obsolete"):
            entry["obsolete"] = True
        out[name] = entry
    return out


def ssh_kex_references(kex_names: list[str]) -> dict[str, dict[str, object]]:
    """Registry facts for every known PQC SSH kex in `kex_names`."""
    out: dict[str, dict[str, object]] = {}
    for name in kex_names:
        k = SSH_PQC_KEX.get(name)
        if k is None:
            continue
        entry: dict[str, object] = {
            "kem": k["kem"],
            "classical": k["classical"],
            "cnsa_2_0": k["cnsa_2_0"],
            **standard_ref(str(k["reference"])),
        }
        if k.get("alias_of"):
            entry["alias_of"] = k["alias_of"]
        out[name] = entry
    return out


def annotate_key_exchange(openssl: dict[str, Any], ssh: dict[str, Any]) -> None:
    """Attach registry references next to the classified PQC groups:
    `openssl.tls_group_references` and `ssh_pqc.kex_references`.  Sibling
    keys, so consumers of the `tls_groups` / `kex_groups` buckets are
    unaffected.  Only added when the probe ran."""
    if openssl.get("available"):
        groups = openssl.get("tls_groups") or {}
        openssl["tls_group_references"] = tls_group_references(
            [*(groups.get("pure_pqc") or []), *(groups.get("hybrid") or [])]
        )
    if ssh.get("available"):
        kex = ssh.get("kex_groups") or {}
        ssh["kex_references"] = ssh_kex_references(
            [*(kex.get("pure_pqc") or []), *(kex.get("hybrid") or [])]
        )
