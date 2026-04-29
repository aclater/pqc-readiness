#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""pqc-readiness: assess host suitability for Post-Quantum Cryptography.

Determines whether on-chip ISA features accelerate NIST PQC primitives
(ML-KEM / Kyber, ML-DSA / Dilithium, SLH-DSA / SPHINCS+), enumerates
cryptographic accelerator devices, inspects what the OS and crypto
libraries actually expose, runs a real microbenchmark, and reports
per-algorithm production suitability with quantitative throughput
estimates.

Supported platforms:
    Linux: x86_64, aarch64, s390x   (uses /proc, lspci, optional tpm2-tools)
    macOS: x86_64, arm64            (uses sysctl)

Usage:
    pqc-readiness                           human-readable report
    pqc-readiness --json                    machine-readable (stable schema)
    pqc-readiness --cbom                    CycloneDX 1.6 CBOM JSON (NIST IR 8547)
    pqc-readiness --spdx                    SPDX 3.0 JSON-LD (Security profile)
    pqc-readiness --sarif                   SARIF 2.1.0 findings (OASIS)
    pqc-readiness --markdown                markdown report (for tickets)
    pqc-readiness --bench                   run PQC + classical microbench
    pqc-readiness --bench-tls               run loopback TLS 1.3 handshake bench
    pqc-readiness --threads N               include N-way scaling test
    pqc-readiness --check TIER              exit nonzero if verdict < TIER
    pqc-readiness --check cnsa-2.0          exit nonzero if not CNSA 2.0 compliant
    pqc-readiness --save                    write JSON to ~/.cache/pqc-readiness/
    pqc-readiness --quiet                   print only the verdict line
    pqc-readiness --no-color                disable ANSI color

TIER values: excellent | good | marginal | poor

Exit codes:
    0  Excellent  - dedicated PQC silicon OR optimized SIMD + ample RAM
    1  Good       - software PQC fast enough for production
    2  Marginal   - works, but plan for an accelerator at scale
    3  Poor       - software-only and too slow for production
    4  --check threshold not met (TIER below floor, or cnsa-2.0 not compliant)
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import select
import shutil
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

SCRIPT_VERSION = "2.0.0"
SCHEMA_VERSION = "1.0"

# Host-filesystem prefix for DaemonSet / containerized invocations.  When
# the tool runs inside a container with the host's /proc /sys /dev /etc
# bind-mounted under (e.g.) /host, --host-mount /host sets this prefix
# so detection still reads from the host rather than the container's
# own pid 1 namespace.  Empty in normal bare-metal use.
HOST_PREFIX: str = ""

# Path namespaces that should be redirected through HOST_PREFIX when set.
# Paths outside these namespaces (binary lookups, /opt/..., /tmp/...) are
# left alone — they belong to the running container, not the host kernel.
# /usr/lib/os-release is enumerated explicitly because /etc/os-release is
# a symlink to it on most modern distros (Fedora, Debian, Ubuntu, Arch);
# bind-mounting only /etc would dangle the symlink in the container.
_HOST_NAMESPACES = (
    "/proc",
    "/sys",
    "/dev",
    "/etc",
    "/var/lib/dpkg",
    "/usr/share",
    "/usr/lib/os-release",
)


def host_path(p: str) -> Path:
    """Return Path(p) under HOST_PREFIX when --host-mount is in effect
    and p targets a kernel/state namespace.  Bare-metal callers and
    user-space paths are unaffected."""
    if HOST_PREFIX and any(
        p == ns or p.startswith(ns + "/") for ns in _HOST_NAMESPACES
    ):
        return Path(HOST_PREFIX + p)
    return Path(p)


def host_fs_unavailable_note(
    detection_label: str, host_resources: str
) -> dict[str, Any] | None:
    """Return an `unavailable_in_container` annotation when running inside
    a container without `--host-mount` for a detection whose result
    depends on the host filesystem (any of /proc /sys /dev /etc /var/lib
    /usr/lib) or on `lspci` / `dmidecode` whose output reflects the
    container's view, not the host.  Returns None when the detection is
    trustworthy: bare-metal invocation, or --host-mount in effect.

    detection_label is the human-readable name of the detection (e.g.
    "PCI accelerator detection"); host_resources names the host-fs
    paths or commands the detection consults.  Both are surfaced verbatim
    in the returned `reason` field so consumers can render a precise
    "X is unavailable because Y" message."""
    if HOST_PREFIX:
        return None
    env = detect_runtime_environment()
    if env.get("environment") != "container":
        return None
    return {
        "unavailable_in_container": True,
        "reason": (
            f"{detection_label} reads {host_resources}; running inside a "
            f"container without --host-mount, so the result reflects the "
            f"container's namespace, not the host."
        ),
    }


# ---------------------------------------------------------------------------
# ISA feature catalogs
# Per-flag tuple = (display name, purpose, weight in tier scoring)
# Weight rationale: 3 = enables a major fast path; 2 = clear speedup;
# 1 = useful but not by itself decisive.
# Refs: Intel Crypto Acceleration whitepapers; liboqs SIMD backends;
# pq-crystals reference impl notes; Cloudflare CIRCL benchmarks.
# ---------------------------------------------------------------------------

X86_FEATURES: dict[str, tuple[str, str, int]] = {
    "avx2": ("AVX2", "256-bit SIMD; baseline for optimized PQC", 2),
    "avx512f": ("AVX-512 F", "Vector polynomial arithmetic", 3),
    "avx512bw": ("AVX-512 BW", "Byte/word ops for Keccak/SHAKE", 2),
    "avx512vl": ("AVX-512 VL", "VL-aware AVX-512", 1),
    "avx512vbmi": ("AVX-512 VBMI", "Permute-bytes; major Keccak speedup", 3),
    "avx512vbmi2": ("AVX-512 VBMI2", "Compress/expand; SHAKE/Keccak", 2),
    "avx512ifma": ("AVX-512 IFMA", "52-bit FMA; lattice multiplication", 3),
    "avx512_vpopcntdq": ("AVX-512 VPOPCNTDQ", "Bitcount; SLH-DSA hash trees", 1),
    "avx512_bitalg": ("AVX-512 BITALG", "Bit algorithms", 1),
    "vaes": ("VAES", "Vector AES-NI; AES-CTR DRBG", 2),
    "vpclmulqdq": ("VPCLMULQDQ", "Vector carry-less multiply", 2),
    "gfni": ("GFNI", "Galois field; Keccak speedup", 2),
    "sha_ni": ("SHA-NI", "SHA-256 hardware (hybrid TLS)", 2),
    "aes": ("AES-NI", "AES hardware (DRBG, hybrid)", 1),
    "pclmulqdq": ("PCLMULQDQ", "Carry-less multiply", 1),
}

ARM_FEATURES: dict[str, tuple[str, str, int]] = {
    "aes": ("AES", "ARMv8 AES instructions", 1),
    "sha2": ("SHA-2", "SHA-256 hardware", 1),
    "sha3": ("SHA-3", "Keccak/SHAKE hardware - major PQC win", 3),
    "sha512": ("SHA-512", "SHA-512 hardware", 1),
    "pmull": ("PMULL", "Polynomial multiply long", 1),
    "sve": ("SVE", "Scalable Vector Extension", 2),
    "sve2": ("SVE2", "SVE2; lattice arithmetic", 3),
    "i8mm": ("I8MM", "Int8 matrix multiply (Neoverse V1/V2)", 2),
}

# IBM z facilities. MSA8 added SHA-3/SHAKE on-chip; MSA9 added EdDSA.
# IBM z16 (CEX8) is the first widely-deployed system with on-chip
# acceleration of NIST PQC algorithms in hardware.
S390_FEATURES: dict[str, tuple[str, str, int]] = {
    "msa": ("MSA", "Message Security Assist baseline (CPACF)", 1),
    "msa3": ("MSA3", "SHA-256/512", 1),
    "msa4": ("MSA4", "AES-192/256, GHASH", 1),
    "msa5": ("MSA5", "PRNG/PPNO", 1),
    "msa8": ("MSA8", "AES-GCM, SHA-3, SHAKE - PQC hashing", 3),
    "msa9": ("MSA9", "EdDSA on-chip; precursor to PQC accel", 2),
    "vx": ("VX", "Vector facility", 1),
    "vxe": ("VXE", "Vector enhancements", 1),
    "vxe2": ("VXE2", "Vector enhancements 2", 1),
}

# macOS sysctl flag prefixes -> normalized flag names matching the catalogs.
MACOS_X86_SYSCTL = {
    "machdep.cpu.features": ["AVX1.0", "AES", "PCLMULQDQ", "SSE4.2"],
    "machdep.cpu.leaf7_features": [
        "AVX2",
        "AVX512F",
        "AVX512BW",
        "AVX512VL",
        "AVX512VBMI",
        "AVX512VBMI2",
        "AVX512IFMA",
        "AVX512_VPOPCNTDQ",
        "AVX512_BITALG",
        "VAES",
        "VPCLMULQDQ",
        "GFNI",
        "SHA",
    ],
}
MACOS_X86_TO_LINUX = {
    "AVX2": "avx2",
    "AVX512F": "avx512f",
    "AVX512BW": "avx512bw",
    "AVX512VL": "avx512vl",
    "AVX512VBMI": "avx512vbmi",
    "AVX512VBMI2": "avx512vbmi2",
    "AVX512IFMA": "avx512ifma",
    "AVX512_VPOPCNTDQ": "avx512_vpopcntdq",
    "AVX512_BITALG": "avx512_bitalg",
    "VAES": "vaes",
    "VPCLMULQDQ": "vpclmulqdq",
    "GFNI": "gfni",
    "SHA": "sha_ni",
    "AES": "aes",
    "PCLMULQDQ": "pclmulqdq",
}
MACOS_ARM_SYSCTLS = {
    "hw.optional.arm.FEAT_AES": "aes",
    "hw.optional.arm.FEAT_SHA1": "sha1",
    "hw.optional.arm.FEAT_SHA256": "sha2",
    "hw.optional.arm.FEAT_SHA512": "sha512",
    "hw.optional.arm.FEAT_SHA3": "sha3",
    "hw.optional.arm.FEAT_PMULL": "pmull",
    "hw.optional.arm.FEAT_SVE": "sve",
    "hw.optional.arm.FEAT_I8MM": "i8mm",
}

# ---------------------------------------------------------------------------
# Accelerator catalogs
# ---------------------------------------------------------------------------

ACCEL_PCI_HINTS: list[tuple[str, str, str]] = [
    (r"Marvell.*LiquidSecurity", "Marvell LiquidSecurity HSM", "hsm"),
    (r"Cavium.*Nitrox|Marvell.*Nitrox", "Marvell/Cavium Nitrox", "hsm"),
    (r"Thales.*Luna|SafeNet.*Luna", "Thales Luna PCIe HSM", "hsm"),
    (r"Utimaco", "Utimaco SecurityServer", "hsm"),
    (r"Atos.*Trustway|Bull.*Trustway|Proteccio", "Atos Trustway Proteccio", "hsm"),
    (r"Yubico", "YubiHSM", "hsm"),
    (r"IBM.*Crypto Express|IBM.*47[67][09]", "IBM Crypto Express (CEX)", "hsm"),
    (r"Intel.*QuickAssist|Intel.*QAT", "Intel QuickAssist (QAT)", "accel"),
    (r"AMD.*Secure Processor|AMD.*PSP", "AMD Platform Security Processor", "accel"),
    (r"ARM.*CryptoCell", "ARM CryptoCell", "accel"),
    (
        r"Amazon\.com.*Nitro|Amazon Web Services.*Nitro",
        "AWS Nitro Security Chip",
        "accel",
    ),
    (r"Microchip.*CryptoAuth", "Microchip CryptoAuthentication", "accel"),
    # SmartNICs / DPUs.  These are not PQC silicon today but customers
    # want them inventoried as part of the broader accelerator picture.
    (r"Mellanox.*BlueField|NVIDIA.*BlueField", "NVIDIA BlueField DPU", "dpu"),
    (r"Intel.*IPU(\s+E2000)?|Intel.*Mount Evans", "Intel IPU E2000", "dpu"),
    (r"Pensando|AMD.*Pensando|DSC2|DSC-25", "AMD Pensando DSC", "dpu"),
]

DEVICE_HINTS: list[tuple[str, str, str]] = [
    ("/dev/tpm0", "TPM 2.0 device", "tpm"),
    ("/dev/tpmrm0", "TPM 2.0 resource manager", "tpm"),
    ("/dev/qat_adf_ctl", "Intel QAT control", "accel"),
    ("/dev/z90crypt", "IBM Z crypto express", "hsm"),
    ("/dev/nitro_enclaves", "AWS Nitro Enclaves", "accel"),
    ("/dev/kfd", "AMD ROCm compute (general-purpose)", "gpu"),
    ("/dev/nvidia0", "NVIDIA GPU (general-purpose)", "gpu"),
]

# PKCS#11 module search paths per distro family.  Vendor paths
# (/opt/cloudhsm/lib, /opt/Thales/..., /opt/utimaco/...) are always
# searched because they're not OS-distribution conventions — they ship
# with HSM client packages installed by the operator.  Architecture-
# specific paths (x86_64-linux-gnu, aarch64-linux-gnu) are Debian
# multiarch and only exist there.
_PKCS11_PATHS_BY_FAMILY: dict[str, list[str]] = {
    "rhel": [
        "/usr/lib64/pkcs11",
        "/usr/lib/pkcs11",
        "/usr/local/lib/pkcs11",
    ],
    "debian": [
        "/usr/lib/x86_64-linux-gnu/pkcs11",
        "/usr/lib/aarch64-linux-gnu/pkcs11",
        "/usr/lib/pkcs11",
        "/usr/lib/softhsm",
        "/var/lib/softhsm/tokens",
        "/usr/local/lib/pkcs11",
    ],
    "suse": ["/usr/lib64/pkcs11", "/usr/lib/pkcs11", "/usr/local/lib/pkcs11"],
    "arch": ["/usr/lib/pkcs11", "/usr/local/lib/pkcs11"],
    "alpine": ["/usr/lib/pkcs11"],
    "macos": ["/opt/homebrew/lib/pkcs11", "/usr/local/lib/pkcs11"],
}
_VENDOR_PKCS11_PATHS: list[str] = [
    "/opt/cloudhsm/lib",
    "/opt/Thales/PKCS11",
    "/opt/utimaco/Software/PKCS11",
]


def _pkcs11_search_paths(family: str) -> list[str]:
    """Compose the PKCS#11 search list dynamically per family.  Distro
    paths first, then vendor-installed HSM client paths.  Saves time
    on hosts where Debian-multiarch paths don't exist (RHEL) and vice
    versa, and produces tighter output."""
    return _PKCS11_PATHS_BY_FAMILY.get(family, []) + _VENDOR_PKCS11_PATHS


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
# Output helpers
# ---------------------------------------------------------------------------


class C:
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    RED = "\033[31m"
    CYAN = "\033[36m"
    MAGENTA = "\033[35m"
    enabled = False

    @classmethod
    def configure(cls, on: bool) -> None:
        cls.enabled = on

    @classmethod
    def wrap(cls, color: str, text: str) -> str:
        return f"{color}{text}{cls.RESET}" if cls.enabled else text


TIER_COLOR = {
    "excellent": C.GREEN,
    "good": C.GREEN,
    "marginal": C.YELLOW,
    "poor": C.RED,
    "unknown": C.DIM,
}

# ---------------------------------------------------------------------------
# Dataclass
# ---------------------------------------------------------------------------


@dataclass
class Report:
    schema_version: str = SCHEMA_VERSION
    generated_at: str = ""
    hostname: str = ""
    os: str = ""
    arch: str = ""
    cpu_model: str = ""
    cpu_freq_mhz: float = 0.0
    cores_logical: int = 0
    cores_physical: int = 0
    mem_total_gb: float = 0.0
    mem_avail_gb: float = 0.0
    isa_features: dict[str, dict[str, str]] = field(default_factory=dict)
    isa_score: int = 0
    isa_tier: str = ""
    isa_reason: str = ""
    accelerators: list[dict[str, Any]] = field(default_factory=list)
    hsm_present_but_not_pqc: bool = False
    pkcs11_modules: list[str] = field(default_factory=list)
    kernel_crypto_hw: list[str] = field(default_factory=list)
    ktls_supported: bool | None = None
    fips: dict[str, Any] = field(default_factory=dict)
    openssl: dict[str, Any] = field(default_factory=dict)
    tpm_pqc: dict[str, Any] = field(default_factory=dict)
    memory_bandwidth_gb_s: float | None = None
    memory_bandwidth_method: str = ""
    ssh_pqc: dict[str, Any] = field(default_factory=dict)
    ipsec_pqc: dict[str, Any] = field(default_factory=dict)
    nss: dict[str, Any] = field(default_factory=dict)
    kernel_info: dict[str, Any] = field(default_factory=dict)
    fips_pqc_conflict: dict[str, Any] = field(default_factory=dict)
    cnsa_2_0: dict[str, Any] = field(default_factory=dict)
    trust_store: dict[str, Any] = field(default_factory=dict)
    runtime_environment: dict[str, Any] = field(default_factory=dict)
    # Per-detection `unavailable_in_container` flags for host-fs-dependent
    # probes (PCI accel, kernel crypto, ktls, FIPS, TPM, kernel info, OS
    # release, PKCS#11 modules).  Populated only when the report was
    # produced inside a container without --host-mount; empty otherwise.
    # The fleet aggregator counts hosts per key under
    # host_fs_detections_unavailable_host_count.
    host_fs_detections_unavailable: dict[str, dict[str, Any]] = field(
        default_factory=dict
    )
    packages: dict[str, Any] = field(default_factory=dict)
    replace_required: bool = False
    os_release: dict[str, Any] = field(default_factory=dict)
    benchmark: dict[str, Any] = field(default_factory=dict)
    benchmark_tls_handshake: dict[str, Any] = field(default_factory=dict)
    pqc_sizes: dict[str, dict[str, Any]] = field(default_factory=lambda: PQC_SIZES)
    per_algo: dict[str, dict[str, Any]] = field(default_factory=dict)
    production_estimate: dict[str, Any] = field(default_factory=dict)
    verdict: str = ""
    verdict_reason: str = ""
    verdict_caveat: str = ""
    exit_code: int = 0


# ---------------------------------------------------------------------------
# Platform shims
# ---------------------------------------------------------------------------


def _run(cmd: list[str], timeout: int = 10) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except (subprocess.TimeoutExpired, OSError) as e:
        return 127, str(e)


def _sysctl(key: str) -> str:
    if not shutil.which("sysctl"):
        return ""
    rc, out = _run(["sysctl", "-n", key], timeout=3)
    return out.strip() if rc == 0 else ""


def is_linux() -> bool:
    return sys.platform.startswith("linux")


def is_macos() -> bool:
    return sys.platform == "darwin"


# ---------------------------------------------------------------------------
# CPU / memory inventory
# ---------------------------------------------------------------------------


def parse_cpuinfo_flags(text: str) -> set[str]:
    """Pure helper: extract the union of feature tokens from any
    /proc/cpuinfo-style text.  Handles all four label variants seen in
    the wild (`flags` on x86, `Features` on aarch64, `facilities` on
    s390x, lower-case `features` on some embedded kernels)."""
    flags: set[str] = set()
    for line in text.splitlines():
        if line.startswith(("flags", "Features", "features", "facilities")):
            _, _, vals = line.partition(":")
            flags.update(vals.split())
    return flags


def linux_cpu_flags() -> set[str]:
    try:
        return parse_cpuinfo_flags(host_path("/proc/cpuinfo").read_text())
    except OSError:
        return set()


def macos_cpu_flags(arch: str) -> set[str]:
    flags: set[str] = set()
    if arch in ("x86_64", "amd64"):
        for key, _ in MACOS_X86_SYSCTL.items():
            tokens = _sysctl(key).split()
            for tok in tokens:
                norm = MACOS_X86_TO_LINUX.get(tok.upper())
                if norm:
                    flags.add(norm)
    elif arch in ("arm64", "aarch64"):
        for key, norm in MACOS_ARM_SYSCTLS.items():
            if _sysctl(key) == "1":
                flags.add(norm)
    return flags


def cpu_flags(arch: str) -> set[str]:
    if is_linux():
        return linux_cpu_flags()
    if is_macos():
        return macos_cpu_flags(arch)
    return set()


def cpu_model() -> str:
    if is_linux():
        try:
            for line in host_path("/proc/cpuinfo").read_text().splitlines():
                if line.startswith(("model name", "Hardware", "cpu model", "machine")):
                    return line.split(":", 1)[1].strip()
        except OSError:
            pass
    if is_macos():
        m = _sysctl("machdep.cpu.brand_string")
        if m:
            return m
    return platform.processor() or platform.machine()


def cpu_freq_mhz() -> float:
    if is_linux():
        for path in (
            "/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq",
            "/sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq",
        ):
            try:
                return int(Path(path).read_text().strip()) / 1000.0
            except (OSError, ValueError):
                continue
        try:
            for line in host_path("/proc/cpuinfo").read_text().splitlines():
                if "cpu MHz" in line:
                    return float(line.split(":", 1)[1].strip())
        except OSError:
            pass
    if is_macos():
        v = _sysctl("hw.cpufrequency_max")
        try:
            return float(v) / 1_000_000 if v else 0.0
        except ValueError:
            pass
    return 0.0


def core_counts() -> tuple[int, int]:
    logical = os.cpu_count() or 0
    physical = 0
    if is_linux():
        try:
            text = host_path("/proc/cpuinfo").read_text()
            seen: set[tuple[str, str]] = set()
            cur_phys = cur_core = None
            for line in text.splitlines():
                if line.startswith("physical id"):
                    cur_phys = line.split(":", 1)[1].strip()
                elif line.startswith("core id"):
                    cur_core = line.split(":", 1)[1].strip()
                elif not line.strip() and cur_phys is not None and cur_core is not None:
                    seen.add((cur_phys, cur_core))
                    cur_phys = cur_core = None
            physical = len(seen) or logical
        except OSError:
            physical = logical
    elif is_macos():
        try:
            physical = int(_sysctl("hw.physicalcpu") or "0") or logical
            logical = int(_sysctl("hw.logicalcpu") or str(logical))
        except ValueError:
            physical = logical
    return logical, physical


def memory_info() -> tuple[float, float]:
    total = avail = 0.0
    if is_linux():
        try:
            for line in host_path("/proc/meminfo").read_text().splitlines():
                k, _, v = line.partition(":")
                v = v.strip().split()[0] if v.strip() else "0"
                if k == "MemTotal":
                    total = int(v) / 1024 / 1024
                elif k == "MemAvailable":
                    avail = int(v) / 1024 / 1024
        except OSError:
            pass
    elif is_macos():
        try:
            total = int(_sysctl("hw.memsize") or "0") / (1024**3)
        except ValueError:
            pass
        rc, out = _run(["vm_stat"], timeout=3)
        if rc == 0:
            page = 16384
            free = inactive = 0
            for line in out.splitlines():
                if "page size of" in line:
                    m = re.search(r"page size of (\d+)", line)
                    if m:
                        page = int(m.group(1))
                if line.startswith("Pages free:"):
                    free = int(re.sub(r"\D", "", line))
                elif line.startswith("Pages inactive:"):
                    inactive = int(re.sub(r"\D", "", line))
            avail = (free + inactive) * page / (1024**3)
    return total, avail or total


# ---------------------------------------------------------------------------
# ISA classification
# ---------------------------------------------------------------------------


def detect_isa(arch: str, flags: set[str]) -> tuple[dict[str, dict[str, str]], int]:
    if arch in ("x86_64", "amd64", "i686", "i386"):
        catalog = X86_FEATURES
    elif arch in ("aarch64", "arm64"):
        catalog = ARM_FEATURES
    elif arch == "s390x":
        catalog = S390_FEATURES
    else:
        return {}, 0
    found: dict[str, dict[str, str]] = {}
    score = 0
    for flag, (label, why, weight) in catalog.items():
        if flag in flags:
            found[flag] = {"name": label, "purpose": why}
            score += weight
    return found, score


def isa_tier(arch: str, score: int, flags: set[str]) -> tuple[str, str]:
    if arch in ("x86_64", "amd64"):
        avx512_pqc = {"avx512f", "avx512vbmi", "avx512ifma"}.issubset(flags) or {
            "avx512f",
            "vaes",
            "vpclmulqdq",
        }.issubset(flags)
        if avx512_pqc and score >= 18:
            return (
                "excellent",
                "AVX-512 with VBMI/IFMA/VAES family - full SIMD PQC at line rate",
            )
        if "avx2" in flags and {"aes", "pclmulqdq"}.issubset(flags) and score >= 6:
            return (
                "good",
                "AVX2 + AES-NI + PCLMULQDQ - production-capable in software",
            )
        if "avx2" in flags:
            return ("marginal", "AVX2 only - workable but slower than peers")
        return ("poor", "Pre-AVX2 x86 - software PQC will be slow")
    if arch in ("aarch64", "arm64"):
        if {"sha3", "aes"}.issubset(flags) and ("sve2" in flags or score >= 8):
            return (
                "excellent",
                "ARMv8 with SHA-3 + SVE2 / wide crypto - strong PQC profile",
            )
        if {"sha3", "aes"}.issubset(flags):
            return (
                "good",
                "ARMv8 with SHA-3 + AES - production-capable (Apple M-series, Graviton 3)",
            )
        if {"aes", "sha2", "pmull"}.issubset(flags):
            return ("good", "ARMv8 crypto extensions - production-capable")
        return ("marginal", "Limited ARM crypto extensions")
    if arch == "s390x":
        if {"msa8", "msa9"}.issubset(flags):
            return (
                "excellent",
                "MSA8+MSA9 (z15+/z16) - on-chip SHA-3 / EdDSA, PQC accel possible",
            )
        if "msa" in flags:
            return ("marginal", "Older z hardware without SHA-3 on-chip")
        return ("poor", "No CPACF detected")
    return ("unknown", f"Architecture {arch} not classified")


def memory_tier(gb: float) -> tuple[str, str]:
    if gb >= 64:
        return (
            "excellent",
            f"{gb:.1f} GiB - comfortable for high-throughput TLS/PQC at scale",
        )
    if gb >= 16:
        return ("good", f"{gb:.1f} GiB - adequate for medium production load")
    if gb >= 4:
        return ("marginal", f"{gb:.1f} GiB - OK for low-volume or edge deployments")
    return ("poor", f"{gb:.1f} GiB - insufficient for production PQC services")


# ---------------------------------------------------------------------------
# Accelerator detection
# ---------------------------------------------------------------------------


def detect_accelerators() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if shutil.which("lspci"):
        rc, data = _run(["lspci", "-nn"], timeout=10)
        if rc == 0:
            for line in data.splitlines():
                for pat, label, kind in ACCEL_PCI_HINTS:
                    if re.search(pat, line, re.IGNORECASE):
                        out.append(
                            {"kind": kind, "name": label, "detail": line.strip()}
                        )
    for path, label, kind in DEVICE_HINTS:
        if host_path(path).exists():
            out.append({"kind": kind, "name": label, "detail": path})
    # IBM z: enumerate Crypto Express adapters via lszcrypt.  Only CEX8 in
    # EP11 mode is flagged pqc_capable; CEX5/6/7 surface but do not count
    # toward dedicated PQC silicon.
    if platform.machine().lower() == "s390x":
        out.extend(detect_s390x_crypto())
    return out


def detect_pci_accelerators() -> dict[str, Any]:
    """Dict-returning sibling of detect_accelerators().  Returns the same
    list of detected accelerators under key `items`, plus an
    `unavailable_in_container` annotation when the result depends on
    `lspci` / /dev probing inside a container without --host-mount.
    Use this when callers need to surface "we couldn't see the host's
    PCI bus from in here" rather than silently emit an empty list."""
    items = detect_accelerators()
    out: dict[str, Any] = {"items": items}
    note = host_fs_unavailable_note(
        "PCI accelerator detection",
        "lspci output and /dev hints (/dev/kfd, /dev/nvidia*, etc.)",
    )
    if note:
        out.update(note)
    return out


def detect_pkcs11_modules(family: str = "unknown") -> list[str]:
    """Walk the family-appropriate PKCS#11 directories plus the always-
    on vendor paths.  Returns a sorted, de-duplicated list of *.so and
    *.dylib module file paths."""
    found: set[str] = set()
    for d in _pkcs11_search_paths(family):
        p = host_path(d)
        if not p.is_dir():
            continue
        for sub in p.rglob("*.so"):
            found.add(str(sub))
        for sub in p.rglob("*.dylib"):
            found.add(str(sub))
    return sorted(found)


def detect_tpm_pqc() -> dict[str, Any]:
    note = host_fs_unavailable_note(
        "TPM PQC detection", "/dev/tpmrm0, /dev/tpm0 and tpm2_getcap"
    )
    if not shutil.which("tpm2_getcap"):
        out: dict[str, Any] = {
            "present": host_path("/dev/tpmrm0").exists()
            or host_path("/dev/tpm0").exists(),
            "tools": False,
            "note": "tpm2-tools not installed; TPM 2.0 chips today do not implement NIST PQC",
        }
        if note:
            out.update(note)
        return out
    rc, out_text = _run(["tpm2_getcap", "algorithms"], timeout=5)
    if rc != 0:
        out = {
            "present": True,
            "tools": True,
            "note": "tpm2_getcap failed",
            "raw": out_text[:200],
        }
        if note:
            out.update(note)
        return out
    has_pqc = bool(
        re.search(
            r"ml[-_ ]?kem|ml[-_ ]?dsa|kyber|dilithium|sphincs", out_text, re.IGNORECASE
        )
    )
    out = {
        "present": True,
        "tools": True,
        "pqc_advertised": has_pqc,
        "note": "TPM 2.0 specs do not yet mandate PQC; almost all shipped TPMs answer 'no'",
    }
    if note:
        out.update(note)
    return out


def detect_kernel_crypto_hw() -> list[str]:
    """Linux /proc/crypto driver column - hardware-accelerated drivers usually
    end in -ni / -ce / -ssse3 / -avx2 / -avx512 / -arm64-ce / -aesni."""
    if not is_linux():
        return []
    try:
        text = host_path("/proc/crypto").read_text()
    except OSError:
        return []
    hw_suffixes = (
        "-ni",
        "-ce",
        "-ssse3",
        "-avx2",
        "-avx512",
        "-arm64-ce",
        "-aesni",
        "-pclmul",
        "-sha-ce",
        "-sha-ni",
        "_asm",
        "-paes",
    )
    out: set[str] = set()
    for line in text.splitlines():
        if line.startswith("driver"):
            drv = line.split(":", 1)[1].strip()
            if any(drv.endswith(s) or s in drv for s in hw_suffixes):
                out.add(drv)
    return sorted(out)


def detect_ktls() -> bool | None:
    if not is_linux():
        return None
    try:
        mods = host_path("/proc/modules").read_text()
        if "tls " in mods:
            return True
    except OSError:
        pass
    if host_path("/sys/module/tls").exists():
        return True
    rc, out = _run(["modinfo", "tls"], timeout=3)
    return rc == 0 and "filename" in out


def detect_fips_mode_from_providers_text(text: str) -> bool:
    """Parse `openssl list -providers -verbose` output as records and
    return True iff a provider named exactly 'fips' has 'status: active'.

    Provider records are introduced by a 2-space-indented line containing
    just the provider name; field lines under that record are indented
    4+ spaces and look like `    status: active`.  A FIPS provider that
    is loaded but inactive (status anything other than 'active') must NOT
    register as enabled — earlier regex-based detection conflated the two.
    """
    records: dict[str, dict[str, str]] = {}
    current: str | None = None
    for line in text.splitlines():
        m = re.match(r"^  (\S+)\s*$", line)
        if m:
            current = m.group(1).strip()
            records.setdefault(current, {})
            continue
        if current is None:
            continue
        f = re.match(r"^    (\S+):\s*(.*)$", line)
        if f:
            records[current][f.group(1).strip()] = f.group(2).strip()
    fips = records.get("fips") or {}
    return fips.get("status", "").lower() == "active"


def detect_fips_mode() -> dict[str, Any]:
    info: dict[str, Any] = {"kernel": False, "openssl_provider": False}
    try:
        info["kernel"] = (
            host_path("/proc/sys/crypto/fips_enabled").read_text().strip() == "1"
        )
    except OSError:
        pass
    if shutil.which("openssl"):
        rc, out = _run(["openssl", "list", "-providers", "-verbose"], timeout=5)
        if rc == 0:
            info["openssl_provider"] = detect_fips_mode_from_providers_text(out)
    note = host_fs_unavailable_note(
        "FIPS mode detection",
        "/proc/sys/crypto/fips_enabled and the in-container openssl binary",
    )
    if note:
        info.update(note)
    return info


def parse_lszcrypt(text: str) -> list[dict[str, Any]]:
    """Parse `lszcrypt -V` output into per-adapter records.

    Output format (IBM z, kernel zcrypt module):

        CARD.DOMAIN TYPE  MODE             STATUS  REQUEST_CNT ...
        00          CEX8C CCA-Coproc       online           0
        00.0026     CEX8C CCA-Coproc       online           0
        01          CEX8P EP11-Coproc      online           0
        02          CEX8A Accelerator      online           0

    Returns adapter dicts with: card, domain (None for card-level rows),
    type_str (e.g. "CEX8P"), level (int 5/6/7/8), mode (CCA/EP11/
    Accelerator), status, pqc_eligible.

    pqc_eligible is set True only for CEX8 in EP11 mode, the only
    generally-available IBM hardware that exposes ML-KEM/ML-DSA today.
    CEX5/6/7 in any mode and CEX8 in CCA or Accelerator modes do NOT
    qualify regardless of MSA8/MSA9 CPACF facility bits.
    """
    out: list[dict[str, Any]] = []
    pat = re.compile(r"^\s*(\S+)\s+(CEX(\d+)([CPA]))\s+(\S+)\s+(\S+)")
    for line in text.splitlines():
        if "CARD" in line.upper() and "TYPE" in line.upper():
            continue
        if not line.strip() or set(line.strip()) <= set("-"):
            continue
        m = pat.match(line)
        if not m:
            continue
        card_dom = m.group(1)
        if "." in card_dom:
            card, domain = card_dom.split(".", 1)
        else:
            card, domain = card_dom, None
        type_str = m.group(2)
        level = int(m.group(3))
        suffix = m.group(4)
        mode_token = m.group(5)
        status = m.group(6)
        mode = {"C": "CCA", "P": "EP11", "A": "Accelerator"}.get(suffix, mode_token)
        out.append(
            {
                "card": card,
                "domain": domain,
                "type_str": type_str,
                "level": level,
                "mode": mode,
                "status": status,
                "pqc_eligible": (level >= 8 and mode == "EP11"),
            }
        )
    return out


def detect_s390x_crypto() -> list[dict[str, Any]]:
    """Run `lszcrypt -V` and convert each adapter to an accelerators-list
    entry.  Only invoked on s390x; safe to call on other arches (returns
    empty list when the tool isn't installed)."""
    if not shutil.which("lszcrypt"):
        return []
    rc, out = _run(["lszcrypt", "-V"], timeout=5)
    if rc != 0:
        return []
    accels: list[dict[str, Any]] = []
    for adapter in parse_lszcrypt(out):
        accels.append(
            {
                "kind": "hsm",
                "name": f"IBM Crypto Express {adapter['level']} ({adapter['mode']})",
                "detail": (
                    f"card={adapter['card']}"
                    + (f" domain={adapter['domain']}" if adapter["domain"] else "")
                    + f" mode={adapter['mode']} status={adapter['status']}"
                ),
                "pqc_capable": adapter["pqc_eligible"],
                "cex_level": adapter["level"],
                "cex_mode": adapter["mode"],
            }
        )
    return accels


# Explicit allow-list of HSM/accelerator models confirmed to expose NIST
# PQC primitives on-chip in their currently-shipping firmware.  Anything
# not on this list is reported as an HSM but does NOT count as dedicated
# PQC silicon for fleet-readiness purposes.  Keep this list audited; the
# customer assessment depends on it being accurate.
#
# Confirmed today (2026):
#   - IBM Crypto Express 8 (CEX8) in EP11 mode on z15+/z16. Detected via
#     parse_lszcrypt; the card-level entry has pqc_capable=True.
#
# TODO — track for future inclusion (require model + firmware verification):
#   - Marvell LiquidSecurity 2/3 with PQC firmware bundle
#   - Thales Luna Network/PCIe 7+ with PQC FM (Functionality Module)
#   - Utimaco SecurityServer Se-Series with PQC algorithm pack
#   - AWS CloudHSM (currently not PQC-capable as of last verification)
def has_dedicated_pqc_silicon(
    arch: str, flags: set[str], accels: list[dict[str, Any]]
) -> bool:
    """Return True iff at least one detected accelerator is on the
    explicit PQC allow-list.  The detector that adds the device sets
    `pqc_capable=True` only when it has affirmative evidence (e.g.
    parse_lszcrypt sets it for CEX8 EP11 adapters).  Generic HSMs
    without confirmed PQC firmware return False even when present."""
    return any(a.get("pqc_capable") is True for a in accels)


# ---------------------------------------------------------------------------
# Network HSM detection (config-file based; not visible via lspci)
# ---------------------------------------------------------------------------

NETWORK_HSM_HINTS: list[tuple[str, str]] = [
    # (path, label) — path may be a file or a directory.  We only report
    # presence; we do NOT read or surface the contents of these files
    # (Chrystoki.conf especially can contain server hostnames / partition
    # IDs that customers may consider sensitive).
    ("/etc/Chrystoki.conf", "Thales Luna Network/PCIe (Chrystoki client config)"),
    ("/opt/nfast/kmdata", "Entrust nShield Connect (kmdata directory)"),
    ("/opt/nfast/sbin", "Entrust nShield (sbin tools)"),
    ("/opt/cloudhsm/etc", "AWS CloudHSM client"),
    ("/opt/cloudhsm/bin", "AWS CloudHSM client tools"),
    ("/opt/utimaco/Software/cs", "Utimaco CryptoServer client"),
]


def detect_network_hsms() -> list[dict[str, Any]]:
    """Detect network-attached HSMs by client-config presence.

    Network HSMs are reached over IP and never appear in lspci.  Their
    client tooling installs into well-known paths; we treat the existence
    of those paths as evidence the customer has client integration in
    place.  No file contents are read or reported.  All entries are
    flagged pqc_capable=False; firmware/version verification on the
    appliance side is out of scope for a host-level probe."""
    out: list[dict[str, Any]] = []
    seen_labels: set[str] = set()
    for path, label in NETWORK_HSM_HINTS:
        p = host_path(path)
        if not p.exists():
            continue
        if label in seen_labels:
            continue
        seen_labels.add(label)
        out.append(
            {
                "kind": "network_hsm",
                "name": label,
                "detail": f"client config present: {path}",
                "pqc_capable": False,
            }
        )
    return out


# ---------------------------------------------------------------------------
# OpenSSH / strongSwan / NSS PQC capability
# ---------------------------------------------------------------------------

# OpenSSH PQC kex names embed both a PQC token (mlkem*, kyber*, sntrup*)
# and — so far, always — a classical token (nistp*, x25519, x448).  Pure
# PQC SSH kex is not yet in OpenSSH as of 2026; the pure_pqc bucket below
# is reserved for the day a `mlkem768-sha256`-style name ships.
# No word-boundary anchors here — OpenSSH concatenates the PQC and
# classical tokens with no separator (e.g. `mlkem768x25519-sha256`),
# and `\b` on the leading side would suppress the classical match
# because the boundary between two word characters does not exist.
_PQC_SSH_TOKEN_RE = re.compile(r"(?:mlkem\d+|kyber\d+|sntrup\d+)", re.IGNORECASE)
_CLASSICAL_SSH_TOKEN_RE = re.compile(
    r"(?:nistp\d+|x25519|x448|secp\d+r1)",
    re.IGNORECASE,
)


def classify_ssh_kex(pqc_kex: list[str]) -> dict[str, list[str]]:
    """Split detected PQC-relevant SSH kex algorithms into pure-PQC and
    hybrid buckets.  A name that contains both a PQC and a classical
    token is hybrid; PQC-token-only names are pure PQC.  As of 2026 every
    shipped OpenSSH PQC kex is hybrid, but the pure_pqc bucket exists so
    future RFC-adopted pure-PQC kex are surfaced the day they arrive."""
    pure: set[str] = set()
    hybrid: set[str] = set()
    for k in pqc_kex:
        if not _PQC_SSH_TOKEN_RE.search(k):
            continue
        if _CLASSICAL_SSH_TOKEN_RE.search(k):
            hybrid.add(k)
        else:
            pure.add(k)
    return {"pure_pqc": sorted(pure), "hybrid": sorted(hybrid)}


def parse_ssh_kex(text: str) -> dict[str, Any]:
    """Parse `ssh -Q kex` output.  Returns a dict with the full kex
    count, the flat PQC subset (ML-KEM hybrids and the older sntrup761
    NTRU Prime hybrid), and a `kex_groups` split into pure_pqc / hybrid.

    The flat `pqc_kex` list is preserved for back-compat with consumers
    that already key off it; new consumers should prefer `kex_groups`."""
    kexes = [line.strip() for line in text.splitlines() if line.strip()]
    pqc = sorted({k for k in kexes if _PQC_SSH_TOKEN_RE.search(k)})
    return {
        "available": True,
        "kex_count": len(kexes),
        "pqc_kex": pqc,
        "kex_groups": classify_ssh_kex(pqc),
    }


def parse_ssh_version(text: str) -> str | None:
    """Parse `ssh -V` (printed to stderr).  Format:
    OpenSSH_9.9p1, OpenSSL 3.5.5 27 Jan 2026"""
    m = re.search(r"OpenSSH_([^\s,]+)", text)
    return m.group(1) if m else None


def detect_ssh_pqc(family: str = "unknown") -> dict[str, Any]:
    if not shutil.which("ssh"):
        return {
            "available": False,
            "reason": f"ssh not on PATH ({_install_hint('ssh', family)})",
        }
    # ssh -V writes to stderr, captured via _run's stderr merge.
    _, ver_out = _run(["ssh", "-V"], timeout=3)
    version = parse_ssh_version(ver_out)
    rc, out = _run(["ssh", "-Q", "kex"], timeout=5)
    if rc != 0:
        return {
            "available": False,
            "version": version,
            "reason": f"ssh -Q kex failed (rc={rc})",
        }
    parsed = parse_ssh_kex(out)
    parsed["version"] = version
    return parsed


def parse_libreswan_version(text: str) -> str | None:
    """Parse `ipsec --version` for the Libreswan release string.  Format:
    Linux Libreswan 4.15 (netkey) on 5.14.0-..."""
    m = re.search(r"Libreswan\s+(\S+)", text)
    return m.group(1) if m else None


def detect_ipsec_pqc(family: str = "unknown") -> dict[str, Any]:
    """Detect IPsec PQC support across the two major implementations.

    strongSwan exposes algorithms via `swanctl --list-algs`; Libreswan
    (more common on RHEL) does not have a single equivalent — it
    advertises supported KE methods through the `ipsec` command's
    config-validation output, but PQC support there is still
    pre-release as of early 2026.  We report both implementations
    when present so customers know which stack the host runs."""
    out: dict[str, Any] = {"available": False}
    if shutil.which("swanctl"):
        rc, sw_out = _run(["swanctl", "--list-algs"], timeout=10)
        if rc == 0:
            pqc_match = re.search(
                r"\b(ML[-_ ]?KEM|kyber|mlkem)\b", sw_out, re.IGNORECASE
            )
            out.update(
                {
                    "available": True,
                    "implementation": "strongswan",
                    "pqc": bool(pqc_match),
                    "evidence": pqc_match.group(0) if pqc_match else None,
                }
            )
            return out
        out["reason"] = f"swanctl --list-algs failed (rc={rc})"
    if shutil.which("ipsec"):
        rc, ip_out = _run(["ipsec", "--version"], timeout=5)
        if rc == 0 and "Libreswan" in ip_out:
            out.update(
                {
                    "available": True,
                    "implementation": "libreswan",
                    "version": parse_libreswan_version(ip_out),
                    "pqc": False,
                    "note": "Libreswan PQC support is pre-release as of 2026; "
                    "verify against upstream release notes.",
                }
            )
            return out
    if not out.get("reason"):
        out["reason"] = (
            f"neither swanctl nor ipsec on PATH ({_install_hint('swanctl', family)})"
        )
    return out


# Mozilla NSS 3.108 (Aug 2025) added hybrid PQC TLS support; earlier
# versions cannot negotiate the hybrid groups even when OpenSSL can.
NSS_PQC_MIN_VERSION = (3, 108)


def parse_nss_version(text: str) -> tuple[int, int, int] | None:
    m = re.search(r"\b(\d+)\.(\d+)(?:\.(\d+))?\b", text)
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or "0"))


def detect_nss() -> dict[str, Any]:
    """Probe NSS version via certutil --version (preferred) or
    `rpm -q nss` as a fallback.  PQC capability is inferred from version
    >= NSS_PQC_MIN_VERSION (3.108)."""
    if shutil.which("certutil"):
        rc, out = _run(["certutil", "--version"], timeout=5)
        if rc == 0:
            ver = parse_nss_version(out)
            return {
                "available": True,
                "tool": "certutil --version",
                "version": "%d.%d.%d" % ver if ver else "unknown",
                "pqc_capable": ver is not None and ver >= NSS_PQC_MIN_VERSION,
            }
    if shutil.which("rpm"):
        rc, out = _run(["rpm", "-q", "--qf", "%{VERSION}\\n", "nss"], timeout=5)
        if rc == 0 and out.strip():
            # rpm -q can return multiple lines when the package is installed
            # for several arches (i686 + x86_64); take the first version line.
            first = out.strip().splitlines()[0].strip()
            ver = parse_nss_version(first)
            return {
                "available": True,
                "tool": "rpm -q nss",
                "version": ("%d.%d.%d" % ver) if ver else first,
                "pqc_capable": ver is not None and ver >= NSS_PQC_MIN_VERSION,
                "note": "rpm-only check; NSS version reflects RHEL/Fedora package, not necessarily upstream",
            }
    return {
        "available": False,
        "reason": "neither certutil nor a package manager that can query nss is on PATH",
    }


# ---------------------------------------------------------------------------
# OS identity (single source of truth for distro family / package manager)
# ---------------------------------------------------------------------------
#
# Linux distros vary in tool names, package layout, and FIPS posture.  Rather
# than peppering checks throughout the codebase (`if "rhel" in ... else if
# "ubuntu" in ...`), every distro-conditional path resolves through the dict
# returned by detect_os().  /etc/os-release is the freedesktop standard and
# is present on every modern Linux distro; we fall back to legacy distro
# files only when it's missing.

OS_FAMILY_BY_ID: dict[str, str] = {
    # rhel family
    "rhel": "rhel",
    "fedora": "rhel",
    "centos": "rhel",
    "rocky": "rhel",
    "almalinux": "rhel",
    "ol": "rhel",
    "amzn": "rhel",
    # debian family
    "debian": "debian",
    "ubuntu": "debian",
    "linuxmint": "debian",
    "pop": "debian",
    "kali": "debian",
    "raspbian": "debian",
    "neon": "debian",
    "elementary": "debian",
    # suse family
    "sles": "suse",
    "opensuse-leap": "suse",
    "opensuse-tumbleweed": "suse",
    "sled": "suse",
    # arch family
    "arch": "arch",
    "manjaro": "arch",
    "endeavouros": "arch",
    "garuda": "arch",
    # alpine
    "alpine": "alpine",
}

# When `ID` is not in the table above, fall back to checking each token in
# `ID_LIKE` against the same map.  Ubuntu derivatives, for instance, may
# self-identify as `ID=foo ID_LIKE="ubuntu debian"` — we resolve to debian.

PKG_MANAGER_ORDER: dict[str, list[str]] = {
    # First entry that is on PATH wins.  apt-get is preferred over apt for
    # scripting (apt's CLI is explicitly not stable for scripts per the
    # apt(8) manpage).  microdnf only when dnf is absent (UBI minimal).
    "rhel": ["dnf", "microdnf", "yum"],
    "debian": ["apt-get", "apt"],
    "suse": ["zypper"],
    "arch": ["pacman"],
    "alpine": ["apk"],
}


def parse_os_release(text: str) -> dict[str, Any]:
    """Parse /etc/os-release content into the canonical os_release dict.

    /etc/os-release is `KEY=value` per line, values optionally wrapped in
    single or double quotes.  We extract ID, ID_LIKE, VERSION_ID,
    VERSION_CODENAME, PRETTY_NAME, then resolve family from ID first and
    fall back to ID_LIKE tokens.  Returns a dict with package_manager=None
    — the caller (`detect_os`) fills that in by probing PATH because we
    cannot do I/O from a pure parser used in unit tests.
    """
    raw: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        v = v.strip()
        if (v.startswith('"') and v.endswith('"')) or (
            v.startswith("'") and v.endswith("'")
        ):
            v = v[1:-1]
        raw[k.strip()] = v
    id_ = raw.get("ID", "").lower().strip()
    id_like = [t.lower() for t in raw.get("ID_LIKE", "").split() if t]
    family = OS_FAMILY_BY_ID.get(id_, "")
    if not family:
        for tok in id_like:
            if tok in OS_FAMILY_BY_ID:
                family = OS_FAMILY_BY_ID[tok]
                break
    return {
        "family": family or "unknown",
        "id": id_ or "unknown",
        "version_id": raw.get("VERSION_ID") or None,
        "version_codename": raw.get("VERSION_CODENAME") or None,
        "pretty_name": raw.get("PRETTY_NAME") or None,
        "package_manager": None,
    }


def _resolve_package_manager(family: str) -> str | None:
    for tool in PKG_MANAGER_ORDER.get(family, []):
        if shutil.which(tool):
            return tool
    return None


def detect_os() -> dict[str, Any]:
    """Single source of truth for distro identity.  Returns:

    family            rhel / debian / suse / arch / alpine / macos / unknown
    id                rhel / fedora / ubuntu / debian / sles / ... / macos
    version_id        e.g. "9.6", "24.04", "44"
    version_codename  e.g. "jammy", "bookworm", or None
    pretty_name       full string from os-release / sysctl
    package_manager   first tool on PATH for this family, or None

    When running inside a container without --host-mount, the result
    additionally carries `unavailable_in_container: True` and a `reason`
    string — /etc/os-release inside a container is the container image's
    OS, not the host's, so consumers can warn rather than misreport."""
    out = _detect_os_impl()
    note = host_fs_unavailable_note(
        "OS release detection",
        "/etc/os-release, /usr/lib/os-release, /etc/redhat-release, /etc/debian_version",
    )
    if note:
        out.update(note)
    return out


def _detect_os_impl() -> dict[str, Any]:
    if is_macos():
        ver = _sysctl("kern.osproductversion") or platform.mac_ver()[0]
        return {
            "family": "macos",
            "id": "macos",
            "version_id": ver or None,
            "version_codename": None,
            "pretty_name": f"macOS {ver}".rstrip() if ver else "macOS",
            "package_manager": "brew" if shutil.which("brew") else None,
        }
    # /etc/os-release is the freedesktop standard.  On most modern
    # distros it's a symlink to /usr/lib/os-release; in containerised
    # invocations the symlink can dangle when /usr/lib is not host-
    # mounted, so we try both paths explicitly.
    for candidate in ("/etc/os-release", "/usr/lib/os-release"):
        p = host_path(candidate)
        try:
            text = p.read_text()
        except OSError:
            continue
        out = parse_os_release(text)
        out["package_manager"] = _resolve_package_manager(out["family"])
        return out
    # Legacy fallbacks — only triggered when /etc/os-release is missing.
    if host_path("/etc/redhat-release").exists():
        rh = parse_redhat_release(host_path("/etc/redhat-release").read_text())
        return {
            "family": "rhel",
            "id": rh.get("distro", "").lower().split()[0] or "rhel",
            "version_id": rh.get("version"),
            "version_codename": None,
            "pretty_name": rh.get("raw"),
            "package_manager": _resolve_package_manager("rhel"),
        }
    if host_path("/etc/debian_version").exists():
        try:
            deb_ver: str | None = host_path("/etc/debian_version").read_text().strip()
        except OSError:
            deb_ver = None
        return {
            "family": "debian",
            "id": "debian",
            "version_id": deb_ver,
            "version_codename": None,
            "pretty_name": f"Debian {deb_ver}" if deb_ver else "Debian",
            "package_manager": _resolve_package_manager("debian"),
        }
    if host_path("/etc/SuSE-release").exists():
        return {
            "family": "suse",
            "id": "suse",
            "version_id": None,
            "version_codename": None,
            "pretty_name": "SUSE Linux (legacy /etc/SuSE-release)",
            "package_manager": _resolve_package_manager("suse"),
        }
    return {
        "family": "unknown",
        "id": "unknown",
        "version_id": None,
        "version_codename": None,
        "pretty_name": f"{platform.system()} {platform.release()}".strip(),
        "package_manager": None,
    }


# Per-family install-hint table for missing tools.  Used in error
# messages so a Debian customer doesn't see `dnf install pciutils` and a
# RHEL customer doesn't see `apt-get install pciutils`.  Keys are the
# *binary* name, not the package name — the packages all happen to
# match the binary on these distros.
_INSTALL_HINT_BY_FAMILY: dict[str, dict[str, str]] = {
    "rhel": {
        "lspci": "dnf install pciutils",
        "tpm2_getcap": "dnf install tpm2-tools",
        "swanctl": "dnf install strongswan",
        "ssh": "dnf install openssh-clients",
        "certutil": "dnf install nss-tools",
        "rpm": "(should already be present on RHEL/Fedora)",
        "dpkg-query": "n/a — RHEL uses rpm",
    },
    "debian": {
        "lspci": "apt-get install pciutils",
        "tpm2_getcap": "apt-get install tpm2-tools",
        "swanctl": "apt-get install strongswan-swanctl",
        "ssh": "apt-get install openssh-client",
        "certutil": "apt-get install libnss3-tools",
        "dpkg-query": "(should already be present on Debian/Ubuntu)",
        "rpm": "n/a — Debian uses dpkg",
    },
    "suse": {
        "lspci": "zypper install pciutils",
        "tpm2_getcap": "zypper install tpm2.0-tools",
        "swanctl": "zypper install strongswan",
        "ssh": "zypper install openssh-clients",
        "certutil": "zypper install mozilla-nss-tools",
        "rpm": "(should already be present on SLES/openSUSE)",
    },
    "arch": {
        "lspci": "pacman -S pciutils",
        "tpm2_getcap": "pacman -S tpm2-tools",
        "swanctl": "pacman -S strongswan",
        "ssh": "pacman -S openssh",
        "certutil": "pacman -S nss",
        "pacman": "(should already be present on Arch)",
    },
    "alpine": {
        "lspci": "apk add pciutils",
        "tpm2_getcap": "apk add tpm2-tools",
        "swanctl": "apk add strongswan",
        "ssh": "apk add openssh-client",
        "certutil": "apk add nss-tools",
        "apk": "(should already be present on Alpine)",
    },
}


def _install_hint(binary: str, family: str) -> str:
    """Return a family-correct 'how to install <binary>' fragment for
    inclusion in error messages.  Falls back to a generic instruction
    when the family or binary is not in the table."""
    table = _INSTALL_HINT_BY_FAMILY.get(family, {})
    return table.get(binary, f"install the package providing {binary}")


# ---------------------------------------------------------------------------
# Kernel + RHEL minor + /proc/crypto PQC awareness
# ---------------------------------------------------------------------------


def parse_redhat_release(text: str) -> dict[str, Any]:
    """Parse /etc/redhat-release one-liner.  Examples:

    Red Hat Enterprise Linux release 9.4 (Plow)
    CentOS Stream release 9
    Fedora release 44 (Forty Four)
    """
    s = text.strip()
    out: dict[str, Any] = {"raw": s}
    m = re.search(r"^(.+?)\s+release\s+(\d+(?:\.\d+)?)", s)
    if m:
        out["distro"] = m.group(1).strip()
        out["version"] = m.group(2)
        if m.group(2).count(".") == 1:
            out["minor"] = m.group(2).split(".", 1)[1]
    return out


def parse_proc_crypto_pqc(text: str) -> list[str]:
    """Return /proc/crypto driver names whose `name` line mentions a PQC
    primitive (ML-KEM, ML-DSA, SLH-DSA, Kyber, Dilithium, SPHINCS).  As
    of 2026 this almost always returns an empty list — kernel-side PQC
    primitives are not yet in mainline."""
    out: list[str] = []
    pqc_re = re.compile(
        r"ml[-_ ]?kem|ml[-_ ]?dsa|slh[-_ ]?dsa|kyber|dilithium|sphincs", re.IGNORECASE
    )
    block: list[str] = []
    for line in text.splitlines() + [""]:
        if line.strip():
            block.append(line)
            continue
        if not block:
            continue
        joined = "\n".join(block)
        if pqc_re.search(joined):
            for ln in block:
                if ln.startswith("driver"):
                    out.append(ln.split(":", 1)[1].strip())
                    break
        block = []
    return out


def detect_kernel_info(os_release: dict[str, Any] | None = None) -> dict[str, Any]:
    """Kernel-specific facts.  Distro identity (ID, VERSION_ID, pretty
    name) lives in detect_os() / Report.os_release; this function used to
    duplicate that and now consumes the precomputed dict for backward
    compatibility — `os_release_id` and `os_release_version_id` are kept
    on the kernel_info dict so existing aggregator/CSV consumers don't
    break when they read either location.

    When running inside a container without --host-mount, the dict
    additionally carries `unavailable_in_container: True` and a `reason`
    string — /etc/redhat-release reflects the container image, and
    /proc/crypto is shared with the host kernel but PQC awareness still
    needs explicit acknowledgement that the container is in play."""
    info: dict[str, Any] = {
        "release": platform.release(),
        "system": platform.system(),
    }
    if not is_linux():
        return info
    if os_release:
        if os_release.get("id") and os_release["id"] != "unknown":
            info["os_release_id"] = os_release["id"]
        if os_release.get("version_id"):
            info["os_release_version_id"] = os_release["version_id"]
    # /etc/redhat-release is retained as a legacy hint — modern distros
    # are sourced via os_release above.
    rh = host_path("/etc/redhat-release")
    if rh.exists():
        try:
            info["redhat_release"] = parse_redhat_release(rh.read_text())
        except OSError:
            pass
    try:
        info["proc_crypto_pqc"] = parse_proc_crypto_pqc(
            host_path("/proc/crypto").read_text()
        )
    except OSError:
        info["proc_crypto_pqc"] = []
    note = host_fs_unavailable_note(
        "Kernel info detection",
        "/etc/redhat-release and /proc/crypto",
    )
    if note:
        info.update(note)
    return info


# ---------------------------------------------------------------------------
# FIPS / PQC interaction warning
# ---------------------------------------------------------------------------

# Family-specific notes appended to fips dict by interpret_fips().  The
# strings deliberately stop short of declaring the host FIPS-compliant —
# the script can detect what is enabled, but only the customer's
# compliance team can declare the certification valid for their use.
_FIPS_NOTES_BY_FAMILY: dict[str, str] = {
    "rhel": (
        "RHEL ships a Red Hat-validated FIPS provider.  ML-KEM/ML-DSA "
        "are not yet in the FIPS-validated set as of RHEL 10.0 — verify "
        "against the latest Red Hat FIPS bulletin before relying on PQC "
        "in FIPS-mandated workflows."
    ),
    "debian": (
        "Debian main does not ship a FIPS-certified OpenSSL provider.  "
        "If fips_enabled=1 here, a third-party module is in use — verify "
        "its certification status independently."
    ),
    "suse": (
        "SUSE ships a separately-validated FIPS module via SUSE Linux "
        "Enterprise.  ML-KEM/ML-DSA are not yet covered as of SLES 15 "
        "SP6; verify against the latest SUSE FIPS bulletin."
    ),
    "arch": "Arch does not provide a FIPS-validated OpenSSL build.",
    "alpine": "Alpine does not provide a FIPS-validated OpenSSL build.",
    "macos": "macOS does not expose Linux-style FIPS mode; this field reflects OpenSSL provider state only.",
    "unknown": "Cannot determine distribution-specific FIPS posture.",
}

# Distribution-vendor-certified FIPS provider sources, keyed by os_release.
# When the kernel reports fips_enabled=1 AND OpenSSL has an active fips
# provider AND the os_release matches one of these signatures, we set
# fips.distribution_certified=True with the vendor source attribution.
_DISTRO_CERTIFIED_FIPS: list[tuple[str, str | None, str]] = [
    # (family, id_match_or_None, vendor_source_label)
    ("rhel", None, "Red Hat-validated FIPS provider"),
    ("suse", None, "SUSE Linux Enterprise FIPS module"),
    # Ubuntu Pro ships a Canonical-built FIPS provider.  We can't
    # distinguish Ubuntu Pro from regular Ubuntu purely from os_release,
    # but the presence of an active FIPS provider on Ubuntu strongly
    # implies Pro (Universe/Main do not ship one).
    ("debian", "ubuntu", "Ubuntu Pro FIPS (Canonical) — assumed from active provider"),
]


def interpret_fips(
    fips: dict[str, Any], openssl: dict[str, Any], os_release: dict[str, Any]
) -> dict[str, Any]:
    """Augment the fips dict with family-aware certification context.

    distribution_certified is True only when the script has affirmative
    evidence of a vendor-certified FIPS provider being active: kernel
    fips_enabled=1 AND an active OpenSSL FIPS provider AND the
    os_release matches a known certified family.  Unknown / Debian /
    Arch / Alpine never claim certification — the script cannot verify
    a third-party FIPS module.
    """
    out = dict(fips)
    family = os_release.get("family", "unknown")
    id_ = os_release.get("id", "unknown")
    has_provider = bool(fips.get("openssl_provider"))
    kernel_on = bool(fips.get("kernel"))

    out["distribution_certified"] = False
    out["distribution_certified_source"] = None
    if has_provider and kernel_on:
        for fam, id_match, source in _DISTRO_CERTIFIED_FIPS:
            if family == fam and (id_match is None or id_ == id_match):
                out["distribution_certified"] = True
                out["distribution_certified_source"] = source
                break

    out["notes"] = _FIPS_NOTES_BY_FAMILY.get(family, _FIPS_NOTES_BY_FAMILY["unknown"])
    return out


def fips_pqc_conflict_check(
    fips: dict[str, Any], openssl: dict[str, Any]
) -> dict[str, Any]:
    """Detect the case where a host is in kernel FIPS mode AND OpenSSL is
    advertising PQC algorithms via the non-FIPS default provider.  In this
    state ML-KEM/ML-DSA appear listed but are NOT usable in a FIPS-validated
    workflow (RHEL 9 / 10 FIPS provider does not yet include PQC)."""
    if not fips.get("kernel"):
        return {"in_conflict": False, "explanation": "Kernel FIPS mode not enabled."}
    has_pqc = bool(
        (openssl.get("kem_algorithms") or []) or (openssl.get("sig_algorithms") or [])
    )
    if not has_pqc:
        return {
            "in_conflict": False,
            "explanation": "FIPS mode active and no PQC algorithms exposed.",
        }
    if fips.get("openssl_provider"):
        return {
            "in_conflict": False,
            "explanation": (
                "FIPS provider is active and PQC algorithms are exposed.  "
                "Verify they are coming from a FIPS-validated provider before "
                "relying on them in regulated workflows."
            ),
        }
    return {
        "in_conflict": True,
        "explanation": (
            "Kernel FIPS mode is enabled but OpenSSL is exposing PQC algorithms via "
            "the default (non-FIPS) provider.  These algorithms are listed but would "
            "not be usable in a FIPS-validated workflow — RHEL 9/10 FIPS provider "
            "does not include ML-KEM/ML-DSA as of this writing.  Audit provider "
            "configuration before claiming PQC support in a FIPS-mandated environment."
        ),
    }


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
            except ValueError:
                pass
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
        "notes": notes,
        "requirements": {k: list(v) for k, v in CNSA_2_0_REQUIREMENTS.items()},
    }


# ---------------------------------------------------------------------------
# Trust store certificate inventory (--scan-trust-store)
# ---------------------------------------------------------------------------

TRUST_STORE_DIRS: list[str] = [
    "/etc/pki/tls/certs",
    "/etc/ssl/certs",
    "/etc/pki/ca-trust/extracted/pem",
]
# NIST PQC OID range 2.16.840.1.101.3.4.3.17 .. .31 covers ML-DSA-44/65/87
# and the SLH-DSA-SHA2 / SLH-DSA-SHAKE family.
PQC_OID_RE = re.compile(r"\b2\.16\.840\.1\.101\.3\.4\.3\.(1[7-9]|2\d|3[01])\b")
HYBRID_OID_RES: list[re.Pattern[str]] = [
    re.compile(r"\b1\.3\.6\.1\.4\.1\.42235\.1\.7\.\d+\b"),  # Mozilla draft
    re.compile(r"\b1\.3\.9999\.\d+\.\d+\.\d+\b"),  # liboqs experimental
]
# IETF composite signature OIDs (draft-ietf-lamps-pq-composite-sigs).
# IANA early-allocated 2025-10-20 under the SMI Security PKIX Algorithms arc
# 1.3.6.1.5.5.7.6.{37..54} — covers all 18 Composite-ML-DSA variants pairing
# ML-DSA-44/65/87 with RSA, ECDSA, or EdDSA classical components.  These
# certs use a single composite signature algorithm OID and form the
# "hybrid_composite" category in trust_store.cert_categories.
COMPOSITE_SIG_OID_RE = re.compile(r"\b1\.3\.6\.1\.5\.5\.7\.6\.(3[7-9]|4\d|5[0-4])\b")


def categorise_cert_dump(dump: str) -> str:
    """Categorise an openssl x509 -text dump as 'classical',
    'hybrid_composite', or 'pure_pqc'.

    Composite is checked before pure PQC because a composite-signature cert
    typically advertises both the composite OID and the embedded ML-DSA OID
    — the IETF composite category is the more specific (and accurate) label
    for those certs."""
    if COMPOSITE_SIG_OID_RE.search(dump):
        return "hybrid_composite"
    if PQC_OID_RE.search(dump):
        return "pure_pqc"
    return "classical"


def scan_trust_store(dirs: list[str] | None = None) -> dict[str, Any]:
    if not shutil.which("openssl"):
        return {"available": False, "reason": "openssl not on PATH"}
    target_dirs = dirs if dirs is not None else TRUST_STORE_DIRS
    total = 0
    pqc_certs = 0
    hybrid_certs = 0
    cert_categories: dict[str, int] = {
        "classical": 0,
        "hybrid_composite": 0,
        "pure_pqc": 0,
    }
    seen: set[str] = set()
    for d in target_dirs:
        p = Path(d)
        if not p.is_dir():
            continue
        for cert in list(p.rglob("*.pem")) + list(p.rglob("*.crt")):
            try:
                key = str(cert.resolve())
            except OSError:
                continue
            if key in seen:
                continue
            seen.add(key)
            rc, dump = _run(
                [
                    "openssl",
                    "x509",
                    "-in",
                    str(cert),
                    "-noout",
                    "-text",
                    "-certopt",
                    "no_validity,no_serial,no_pubkey,no_sigdump",
                ],
                timeout=3,
            )
            if rc != 0:
                continue
            total += 1
            if PQC_OID_RE.search(dump):
                pqc_certs += 1
            if any(p.search(dump) for p in HYBRID_OID_RES):
                hybrid_certs += 1
            cert_categories[categorise_cert_dump(dump)] += 1
    return {
        "available": True,
        "scanned_dirs": [d for d in target_dirs if Path(d).is_dir()],
        "total_certs": total,
        "pqc_certs": pqc_certs,
        "hybrid_certs": hybrid_certs,
        "cert_categories": cert_categories,
    }


# ---------------------------------------------------------------------------
# Runtime environment detection (container vs host)
# ---------------------------------------------------------------------------


def parse_cgroup_for_container(text: str) -> str | None:
    """Inspect /proc/1/cgroup content for container-runtime hierarchy
    markers.  Returns a marker string when one is found, else None."""
    for marker in (
        "kubepods",
        "/docker/",
        "/containerd/",
        "/podman-",
        "/crio-",
        "/system.slice/docker-",
        "/lxc/",
    ):
        if marker in text:
            return marker
    return None


# Catalogue of detection probes whose results depend on host filesystem
# paths or host-only commands (lspci / dmidecode).  Used by
# build_host_fs_detections_unavailable() to compute one annotation per
# probe when running inside a container without --host-mount.  The keys
# match Report field names so the aggregator can correlate counts back
# to the field they describe.
_HOST_FS_DEPENDENT_DETECTIONS: tuple[tuple[str, str, str], ...] = (
    (
        "accelerators",
        "PCI accelerator detection",
        "lspci output and /dev hints (/dev/kfd, /dev/nvidia*, etc.)",
    ),
    ("kernel_crypto_hw", "Kernel crypto hardware detection", "/proc/crypto"),
    ("ktls", "kTLS module detection", "/proc/modules and /sys/module/tls"),
    ("fips", "FIPS mode detection", "/proc/sys/crypto/fips_enabled"),
    ("tpm_pqc", "TPM PQC detection", "/dev/tpmrm0, /dev/tpm0 and tpm2_getcap"),
    ("kernel_info", "Kernel info detection", "/etc/redhat-release and /proc/crypto"),
    (
        "os_release",
        "OS release detection",
        "/etc/os-release, /usr/lib/os-release, /etc/redhat-release, /etc/debian_version",
    ),
    (
        "pkcs11_modules",
        "PKCS#11 module scan",
        "/usr/lib*/<arch>/ and /usr/lib*/pkcs11/ under host /usr",
    ),
)


def build_host_fs_detections_unavailable() -> dict[str, dict[str, Any]]:
    """Compute the `host_fs_detections_unavailable` map for the current
    invocation.  Returns an empty dict on bare metal or when --host-mount
    is in effect; otherwise returns one annotation per host-fs-dependent
    probe in `_HOST_FS_DEPENDENT_DETECTIONS`.  The aggregator preserves
    these keys so fleet rollups can report "X hosts had detection Y
    unavailable in container" without re-running detection."""
    out: dict[str, dict[str, Any]] = {}
    for key, label, host_resources in _HOST_FS_DEPENDENT_DETECTIONS:
        note = host_fs_unavailable_note(label, host_resources)
        if note:
            out[key] = note
    return out


def detect_runtime_environment() -> dict[str, Any]:
    """Identify whether we're executing inside a container.  Used by
    every detection function that may need a `unavailable_in_container`
    note appended to its result.  Detection is heuristic; combined with
    --host-mount /host the report still produces accurate host data."""
    if host_path("/.dockerenv").exists():
        return {"environment": "container", "evidence": "/.dockerenv present"}
    if host_path("/run/.containerenv").exists():
        return {"environment": "container", "evidence": "/run/.containerenv present"}
    try:
        cg = Path("/proc/1/cgroup").read_text()
    except OSError:
        cg = ""
    marker = parse_cgroup_for_container(cg)
    if marker:
        return {"environment": "container", "evidence": f"cgroup marker {marker}"}
    return {"environment": "host", "evidence": "no container markers"}


# ---------------------------------------------------------------------------
# Bundled-crypto package inventory (--scan-packages)
# ---------------------------------------------------------------------------

# Per-family regex catalogues for runtimes and applications that bundle
# their own crypto implementation rather than relying solely on system
# OpenSSL.  Each entry: (compiled regex matched against the package
# name, hint string surfaced in the report).  Per-family because package
# names diverge sharply: RHEL `java-21-openjdk` vs Debian `openjdk-21-jdk`
# vs SUSE `java-21-openjdk` vs Arch `jdk-openjdk` vs Alpine `openjdk21`.
BUNDLED_CRYPTO_BY_FAMILY: dict[str, list[tuple[str, str]]] = {
    "rhel": [
        (
            r"^java-\d+(\.\d+\.\d+)?-openjdk(-headless|-devel)?$",
            "Java JCE provider (SunJCE / Bouncy Castle)",
        ),
        (r"^bouncycastle", "Bouncy Castle (separate provider)"),
        (
            r"^(golang|go)(-bin)?$",
            "Go runtime (crypto/tls embedded; GODEBUG=fips140=on for FIPS)",
        ),
        (
            r"^nodejs$",
            "Node.js (bundled OpenSSL build; --openssl-config controls FIPS)",
        ),
        (r"^(rust|cargo|rustc)$", "Rust toolchain (rustls embeds ring or openssl-sys)"),
        (r"^firefox$", "Firefox (embeds NSS — separate PQC roadmap)"),
        (r"^thunderbird$", "Thunderbird (embeds NSS)"),
        (r"^chromium$", "Chromium (embeds BoringSSL)"),
        (r"^python3$", "Python ssl module (links system OpenSSL)"),
    ],
    "debian": [
        (
            r"^openjdk-\d+-(jdk|jre)(-headless)?$",
            "Java JCE provider (SunJCE / Bouncy Castle)",
        ),
        (r"^libbcprov-java$", "Bouncy Castle Java library"),
        (r"^golang-(go|\d+(\.\d+)?-go)$", "Go runtime (crypto/tls embedded)"),
        (r"^nodejs$", "Node.js (bundled OpenSSL build)"),
        (r"^(rustc|cargo)$", "Rust toolchain (rustls embeds ring or openssl-sys)"),
        (r"^firefox(-esr)?$", "Firefox (embeds NSS)"),
        (r"^thunderbird$", "Thunderbird (embeds NSS)"),
        (r"^chromium$", "Chromium (embeds BoringSSL)"),
        (r"^python3$", "Python ssl module (links system OpenSSL)"),
    ],
    "suse": [
        (r"^java-\d+(\.\d+\.\d+)?-openjdk(-headless|-devel)?$", "Java JCE provider"),
        (r"^go(1\.\d+)?$", "Go runtime"),
        (r"^nodejs(\d+)?$", "Node.js"),
        (r"^(rust|cargo)$", "Rust toolchain"),
        (r"^MozillaFirefox$", "Firefox (embeds NSS)"),
        (r"^MozillaThunderbird$", "Thunderbird (embeds NSS)"),
        (r"^chromium$", "Chromium (embeds BoringSSL)"),
        (r"^python3$", "Python ssl module"),
    ],
    "arch": [
        (r"^jdk\d+-openjdk$", "Java JCE provider"),
        (r"^go$", "Go runtime"),
        (r"^nodejs$", "Node.js"),
        (r"^rust$", "Rust toolchain"),
        (r"^firefox$", "Firefox (embeds NSS)"),
        (r"^thunderbird$", "Thunderbird"),
        (r"^chromium$", "Chromium"),
        (r"^python$", "Python"),
    ],
    "alpine": [
        (r"^openjdk\d+(-jdk|-jre)?$", "Java JCE provider"),
        (r"^go$", "Go runtime"),
        (r"^nodejs$", "Node.js"),
        (r"^rust$", "Rust toolchain"),
        (r"^firefox$", "Firefox"),
        (r"^chromium$", "Chromium"),
        (r"^python3$", "Python"),
    ],
}


def parse_rpm_packages(text: str) -> list[dict[str, str]]:
    """Parse `rpm -qa --queryformat '%{NAME} %{VERSION}\\n'` output into
    [{"name", "version"}, ...]."""
    out: list[dict[str, str]] = []
    for line in text.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2:
            out.append({"name": parts[0], "version": parts[1]})
    return out


def parse_dpkg_packages(text: str) -> list[dict[str, str]]:
    """Parse `dpkg-query -W -f='${Package} ${Version}\\n'` output."""
    out: list[dict[str, str]] = []
    for line in text.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2:
            out.append({"name": parts[0], "version": parts[1]})
    return out


def parse_pacman_packages(text: str) -> list[dict[str, str]]:
    """Parse `pacman -Q` output (`name version` per line)."""
    out: list[dict[str, str]] = []
    for line in text.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2:
            out.append({"name": parts[0], "version": parts[1]})
    return out


def parse_apk_packages(text: str) -> list[dict[str, str]]:
    """Parse `apk info -v` output.  Each line is `name-VERSION-rRELEASE`
    (e.g. `openssl-3.5.5-r0`).  We split on the LAST hyphen-followed-by-
    digits which is robustly the version boundary."""
    out: list[dict[str, str]] = []
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        # Walk back from the end: the version+release suffix is two
        # hyphen-separated segments at the tail (`<ver>-r<rel>`).
        m = re.match(r"^(.+)-(\d[^-]*-r\d+)$", s)
        if not m:
            # Fallback: single trailing version segment.
            m = re.match(r"^(.+)-(\d[^-]*)$", s)
            if not m:
                continue
        out.append({"name": m.group(1), "version": m.group(2)})
    return out


def classify_bundled_crypto(
    pkgs: list[dict[str, str]], family: str
) -> list[dict[str, str]]:
    """Match each installed package against the family's bundled-crypto
    regex catalogue.  First-match wins per package (so a package can
    appear in only one row even if multiple regexes match).  De-dupes on
    package name across multi-arch installs (i686 + x86_64)."""
    patterns = [
        (re.compile(p), hint) for p, hint in BUNDLED_CRYPTO_BY_FAMILY.get(family, [])
    ]
    seen: set[str] = set()
    out: list[dict[str, str]] = []
    for entry in pkgs:
        name = entry["name"]
        if name in seen:
            continue
        for pat, hint in patterns:
            if pat.match(name):
                seen.add(name)
                out.append({"package": name, "version": entry["version"], "note": hint})
                break
    return out


# Per-family commands for --scan-packages.  The first tuple element is the
# argv to invoke; the second is the parser to apply.  When the family has
# no entry (or the tool is missing on PATH), scan_packages reports
# unavailable rather than guessing.
PACKAGE_QUERY_BY_FAMILY: dict[
    str, tuple[list[str], Callable[[str], list[dict[str, str]]]]
] = {
    "rhel": (
        ["rpm", "-qa", "--queryformat", "%{NAME} %{VERSION}\\n"],
        parse_rpm_packages,
    ),
    "suse": (
        ["rpm", "-qa", "--queryformat", "%{NAME} %{VERSION}\\n"],
        parse_rpm_packages,
    ),
    "debian": (
        ["dpkg-query", "-W", "-f=${Package} ${Version}\\n"],
        parse_dpkg_packages,
    ),
    "arch": (["pacman", "-Q"], parse_pacman_packages),
    "alpine": (["apk", "info", "-v"], parse_apk_packages),
}


def scan_packages(os_release: dict[str, Any] | None = None) -> dict[str, Any]:
    """Family-aware package inventory.  Returns the same shape regardless
    of which tool produced it: {available, total_packages, bundled_crypto},
    so consumers don't have to special-case rpm/dpkg/pacman/apk output."""
    family = (os_release or {}).get("family", "unknown")
    plan = PACKAGE_QUERY_BY_FAMILY.get(family)
    if plan is None:
        return {
            "available": False,
            "reason": f"no package-query tool registered for family={family}",
        }
    argv, parser = plan
    if not shutil.which(argv[0]):
        return {
            "available": False,
            "reason": f"{argv[0]} not on PATH ({_install_hint(argv[0], family)})",
        }
    rc, out = _run(argv, timeout=30)
    if rc != 0:
        return {"available": False, "reason": f"{argv[0]} failed (rc={rc})"}
    pkgs = parser(out)
    return {
        "available": True,
        "package_manager": argv[0],
        "total_packages": len(pkgs),
        "bundled_crypto": classify_bundled_crypto(pkgs, family),
    }


# ---------------------------------------------------------------------------
# Fleet aggregation (--aggregate DIR)
# ---------------------------------------------------------------------------


def aggregate_reports(reports: list[dict[str, Any]]) -> dict[str, Any]:
    """Roll up many per-host reports into a single fleet view.

    Accepts only reports with matching schema_version; other entries are
    counted as `skipped_schema_mismatch` and listed by file (caller
    populates that field externally — pure version below operates on
    already-validated dicts).

    Output:
      total_hosts, by_arch, by_os_release_id, by_isa_tier, by_verdict,
      by_runtime_environment, accelerator_kinds (count of hosts with
      each kind), unique_cpu_models, replace_required_count,
      host_fs_detections_unavailable_host_count (count of hosts where
      each host-fs-dependent probe was flagged unavailable in container).
    """
    from collections import Counter

    out: dict[str, Any] = {
        "total_hosts": len(reports),
        "schema_version": SCHEMA_VERSION,
    }
    by_arch: Counter[str] = Counter()
    by_os: Counter[str] = Counter()
    by_isa: Counter[str] = Counter()
    by_verdict: Counter[str] = Counter()
    by_env: Counter[str] = Counter()
    cpu_models: set[str] = set()
    accel_kinds: Counter[str] = Counter()
    detections_unavailable: Counter[str] = Counter()
    replace_required = 0
    for r in reports:
        by_arch[r.get("arch", "?")] += 1
        kinfo = r.get("kernel_info") or {}
        by_os[kinfo.get("os_release_id") or "?"] += 1
        by_isa[r.get("isa_tier", "?")] += 1
        # Strip the trailing "- ..." commentary from the verdict for grouping.
        verdict = (r.get("verdict") or "?").split(" - ", 1)[0].strip()
        by_verdict[verdict] += 1
        runtime = (r.get("runtime_environment") or {}).get("environment", "?")
        by_env[runtime] += 1
        cpu_models.add(r.get("cpu_model") or "?")
        seen_kinds: set[str] = set()
        for a in r.get("accelerators") or []:
            k = a.get("kind", "?")
            if k not in seen_kinds:
                accel_kinds[k] += 1
                seen_kinds.add(k)
        # A detection key is counted at most once per host: the aggregator
        # only cares whether *any* host had probe Y flagged unavailable,
        # not how many duplicate annotations a single host carried.
        for det_key, det_info in (r.get("host_fs_detections_unavailable") or {}).items():
            if isinstance(det_info, dict) and det_info.get("unavailable_in_container"):
                detections_unavailable[det_key] += 1
        if r.get("replace_required"):
            replace_required += 1
    out["by_arch"] = dict(by_arch)
    out["by_os_release_id"] = dict(by_os)
    out["by_isa_tier"] = dict(by_isa)
    out["by_verdict"] = dict(by_verdict)
    out["by_runtime_environment"] = dict(by_env)
    out["accelerator_kinds_host_count"] = dict(accel_kinds)
    out["host_fs_detections_unavailable_host_count"] = dict(detections_unavailable)
    out["unique_cpu_models"] = sorted(cpu_models)
    out["replace_required_count"] = replace_required
    return out


def aggregate_to_csv(rollup: dict[str, Any]) -> str:
    """Render the rollup to a flat CSV view for ingestion by ops tools.
    One row per (group, key, count) tuple — easy to load in pandas /
    spreadsheet without nested-JSON gymnastics."""
    import io
    import csv

    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["group", "key", "count"])
    w.writerow(["total_hosts", "", rollup.get("total_hosts", 0)])
    w.writerow(["replace_required_count", "", rollup.get("replace_required_count", 0)])
    for group in (
        "by_arch",
        "by_os_release_id",
        "by_isa_tier",
        "by_verdict",
        "by_runtime_environment",
        "accelerator_kinds_host_count",
        "host_fs_detections_unavailable_host_count",
    ):
        for k, v in (rollup.get(group) or {}).items():
            w.writerow([group, k, v])
    for cpu in rollup.get("unique_cpu_models", []):
        w.writerow(["unique_cpu_models", cpu, 1])
    return buf.getvalue()


def run_aggregator(dir_path: Path, output: str = "json") -> tuple[str, int]:
    """Read every *.json under DIR, validate schema, return (output, exit_code).
    Output format: 'json' (rollup as JSON) or 'csv' (flat CSV view)."""
    reports: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []
    for fp in sorted(dir_path.glob("**/*.json")):
        try:
            data = json.loads(fp.read_text())
        except (OSError, json.JSONDecodeError) as e:
            skipped.append({"file": str(fp), "reason": f"unreadable: {e}"})
            continue
        sv = data.get("schema_version")
        if sv != SCHEMA_VERSION:
            skipped.append(
                {
                    "file": str(fp),
                    "reason": f"schema mismatch: file={sv!r} expected={SCHEMA_VERSION!r}",
                }
            )
            continue
        reports.append(data)
    rollup = aggregate_reports(reports)
    rollup["skipped"] = skipped
    if output == "csv":
        return aggregate_to_csv(rollup), 0
    return json.dumps(rollup, indent=2), 0


# ---------------------------------------------------------------------------
# OpenSSL capability inspection
# ---------------------------------------------------------------------------


def openssl_upgrade_path(
    version_tuple: list[int] | None, os_release: dict[str, Any] | None
) -> str | None:
    """Family-aware hint for getting a PQC-capable OpenSSL on this host.

    Empty when OpenSSL is already 3.5+ (nothing to upgrade) or when we
    cannot resolve the distro.  Strings deliberately stop at fact —
    the field architect plans the upgrade, the script just inventories.
    """
    if version_tuple and tuple(version_tuple[:2]) >= (3, 5):
        return None
    if not os_release:
        return None
    family = os_release.get("family", "unknown")
    id_ = os_release.get("id", "unknown")
    ver = (os_release.get("version_id") or "").split(".")
    major = ver[0] if ver and ver[0] else None

    if family == "rhel":
        # RHEL 8 / Rocky 8 / AlmaLinux 8 ship OpenSSL 1.1.1, which has no
        # PQC primitives at all — distinct from EL9's 3.0/3.2 path.  The
        # RHEL 8 customer also has to opt into the AppStream python3.9+
        # module just to invoke this script (default Python is 3.6, which
        # cannot parse modern type-hint syntax used here), so the hint
        # carries both facts.  The wrapper shell launcher at the repo
        # root does the runtime fallback to a usable interpreter.
        if id_ == "rhel" and major == "8":
            return (
                "RHEL 8 base channel ships OpenSSL 1.1.1; PQC requires "
                "OpenSSL 3.5+, available in RHEL 10 or a Red Hat-supported "
                "channel with newer crypto.  The script itself requires "
                "Python 3.9+ — enable the `python39` (or higher) AppStream "
                "module: `dnf module install python39`."
            )
        if id_ in {"rocky", "almalinux", "centos", "ol"} and major == "8":
            return (
                "EL8-class distributions ship OpenSSL 1.1.1; PQC requires "
                "OpenSSL 3.5+, available in the EL10 release of this "
                "distribution or a backport channel.  The script itself "
                "requires Python 3.9+ via the `python39` (or higher) "
                "AppStream module: `dnf module install python39`."
            )
        if id_ == "rhel" and major and int(major) <= 9:
            return (
                "RHEL 9 base channel ships OpenSSL 3.0/3.2; PQC requires "
                "RHEL 10 or a Red Hat-supported channel with newer crypto."
            )
        if id_ == "fedora" and major and int(major) < 41:
            return (
                f"Fedora {major} predates OpenSSL 3.5; upgrade to Fedora 41 or newer."
            )
        if id_ in {"rocky", "almalinux", "centos", "ol"} and major and int(major) <= 9:
            return (
                "EL9-class distributions ship OpenSSL 3.0/3.2; PQC requires "
                "the EL10 release of this distribution or a backport channel."
            )
    elif family == "debian":
        if id_ == "debian":
            if major == "12":
                return (
                    "Debian 12 (bookworm) ships OpenSSL 3.0; OpenSSL 3.5 is "
                    "available in trixie or bookworm-backports."
                )
            if major and int(major) < 12:
                return (
                    "Pre-bookworm Debian ships OpenSSL 1.1.x; upgrade to "
                    "Debian 12 + backports or newer."
                )
        elif id_ == "ubuntu":
            if major == "24":
                return (
                    "Ubuntu 24.04 LTS main ships OpenSSL 3.0; OpenSSL 3.5 is "
                    "available in universe — `apt install libssl3` from a "
                    "newer channel — or upgrade to 25.10."
                )
            if major and int(major) < 24:
                return (
                    "Ubuntu pre-24.04 LTS predates OpenSSL 3.5; upgrade to "
                    "24.04 LTS (universe) or 25.10."
                )
    elif family == "suse":
        return (
            "SLES 15 SP6 ships OpenSSL 3.0; OpenSSL 3.5 is available via "
            "SUSE Package Hub.  Verify FIPS validation status before swapping."
        )
    elif family == "alpine":
        return (
            "Alpine ships OpenSSL via the apk repository.  Edge channel "
            "carries 3.5+; verify against the host's apk repo configuration."
        )
    elif family == "arch":
        return "Arch rolls forward; `pacman -Syu` should bring OpenSSL 3.5+."
    return None


# TLS group classification.
#
# Pure PQC groups expose a single PQC KEM with no classical fallback;
# hybrid groups concatenate a classical group with a PQC KEM (the IETF
# transitional design — draft-ietf-tls-hybrid-design).  OpenSSL 3.5
# ships X25519MLKEM768 as the default and clients/servers negotiating
# PQC today are almost always using a hybrid; the distinction matters
# for compliance reporting and for transitional-deployment guidance.
#
# Anything that matches a recognised classical group name (named EC
# curves, FFDHE groups, brainpool) is bucketed as "classical".  Names
# that match no catalog are dropped rather than silently miscategorised.
_PURE_PQC_TLS_GROUP_RE = re.compile(r"^MLKEM\d+$")
_HYBRID_TLS_GROUP_RE = re.compile(r"^(?:X(?:25519|448)MLKEM\d+|SecP\d+r1MLKEM\d+)$")
_CLASSICAL_TLS_GROUP_RE = re.compile(
    r"^(?:secp\d+[kr]\d+|prime\d+v\d+|x25519|x448|ffdhe\d+|"
    r"brainpoolP\d+r\d+(?:tls13)?|sect\d+\w+)$",
    re.IGNORECASE,
)


def parse_openssl_tls_groups(text: str) -> list[str]:
    """Extract canonical group identifiers from `openssl list -tls-groups`.

    OpenSSL emits this list in two formats depending on flags / version:

      Colon-separated (current `-tls1_3` form, single line):
          secp256r1:secp384r1:x25519:MLKEM768:X25519MLKEM768

      One-per-line with optional alias info in parens (older form):
          secp256r1 (P-256, prime256v1)
          MLKEM768
          X25519MLKEM768

    We accept both.  Header lines like `TLS 1.3 group support:` end with
    `:` and contain whitespace — those are dropped before tokenisation.
    Ordering is preserved so callers can surface OpenSSL's preference
    order if desired.
    """
    out: list[str] = []
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        # Header rows: end with `:` AND have inner whitespace (e.g.
        # "TLS 1.3 group support:").  Group rows in either format do
        # not match this shape.
        if s.endswith(":") and " " in s:
            continue
        for tok in s.split(":"):
            tok = tok.strip()
            if not tok:
                continue
            # Alias-form rows include trailing parenthesised info; take
            # the leading whitespace-delimited token only.
            head = tok.split()[0]
            if re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]+", head):
                out.append(head)
    return out


def classify_tls_groups(group_names: list[str]) -> dict[str, list[str]]:
    """Split a flat list of TLS group names into pure_pqc / hybrid /
    classical buckets.  Names that match no catalog are dropped (rather
    than lumped into classical) so the report stays honest about what
    we don't recognise yet.  Each bucket is returned sorted and deduped."""
    pure: set[str] = set()
    hybrid: set[str] = set()
    classical: set[str] = set()
    for name in group_names:
        if _HYBRID_TLS_GROUP_RE.match(name):
            hybrid.add(name)
        elif _PURE_PQC_TLS_GROUP_RE.match(name):
            pure.add(name)
        elif _CLASSICAL_TLS_GROUP_RE.match(name):
            classical.add(name)
    return {
        "pure_pqc": sorted(pure),
        "hybrid": sorted(hybrid),
        "classical": sorted(classical),
    }


def openssl_capability(os_release: dict[str, Any] | None = None) -> dict[str, Any]:
    if not shutil.which("openssl"):
        return {"available": False, "reason": "openssl not on PATH"}
    out: dict[str, Any] = {"available": True}
    rc, ver = _run(["openssl", "version"], timeout=5)
    out["version"] = ver.strip() if rc == 0 else "unknown"
    m = re.search(r"OpenSSL\s+(\d+)\.(\d+)\.(\d+)", out["version"])
    out["version_tuple"] = (
        [int(m.group(1)), int(m.group(2)), int(m.group(3))] if m else None
    )
    out["pqc_native"] = bool(out["version_tuple"]) and tuple(
        out["version_tuple"][:2]
    ) >= (3, 5)
    rc, kems = _run(["openssl", "list", "-kem-algorithms"], timeout=5)
    out["kem_algorithms"] = (
        sorted({a for a in re.findall(r"ML-KEM-\d+", kems)}) if rc == 0 else []
    )
    rc, sigs = _run(["openssl", "list", "-signature-algorithms"], timeout=5)
    out["sig_algorithms"] = (
        sorted({a for a in re.findall(r"ML-DSA-\d+|SLH-DSA-[A-Za-z0-9-]+", sigs)})
        if rc == 0
        else []
    )
    rc, groups = _run(["openssl", "list", "-tls-groups", "-tls1_3"], timeout=5)
    if rc != 0:
        rc, groups = _run(["openssl", "list", "-tls-groups"], timeout=5)
    all_group_names = parse_openssl_tls_groups(groups) if rc == 0 else []
    classified = classify_tls_groups(all_group_names)
    out["tls_groups"] = classified
    # Back-compat: tls_pqc_groups was historically the pure-PQC + hybrid
    # union.  Aggregator/JSON consumers may key off it; new consumers
    # should prefer the explicit tls_groups split above.
    out["tls_pqc_groups"] = sorted(
        set(classified["pure_pqc"]) | set(classified["hybrid"])
    )
    rc, providers = _run(["openssl", "list", "-providers"], timeout=5)
    out["providers"] = (
        sorted(
            {m.group(1) for m in re.finditer(r"^\s*(\w+)\s*$", providers, re.MULTILINE)}
        )
        if rc == 0
        else []
    )
    out["upgrade_path"] = openssl_upgrade_path(out["version_tuple"], os_release)
    return out


# ---------------------------------------------------------------------------
# Benchmarking
# ---------------------------------------------------------------------------


def parse_speed_row(
    text: str, algo: str, labels: tuple[str, ...]
) -> dict[str, float] | None:
    """Parse the per-algorithm summary row from `openssl speed` output.

    The summary row looks like:
        ML-KEM-768 0.000027s 0.000017s 0.000026s   37542.4   59259.0   38383.0
    The first len(labels) columns are seconds-per-op; the last len(labels)
    columns are ops/sec.  We take the trailing rates.

    Bug fixes:
      - Use `\\d+(?:\\.\\d+)?` so integer rates (slow algorithms like
        SLH-DSA, where ops/sec may print as a bare integer in some builds)
        are not silently dropped.
      - Match the algo name anywhere on the line via word boundaries, not
        just at column zero, since some OpenSSL builds prefix the row with
        parameter strings.
    """
    needle = re.escape(algo)
    pat = re.compile(rf"\b{needle}\b")
    for line in text.splitlines():
        if not pat.search(line):
            continue
        nums = re.findall(r"\d+(?:\.\d+)?", line)
        if len(nums) >= len(labels) * 2:
            tail = nums[-len(labels) :]
            return {labels[i]: float(tail[i]) for i in range(len(labels))}
    return None


def parse_classical_speed(text: str) -> dict[str, dict[str, float]]:
    """Parse classical asymmetric `openssl speed` output.

    Headers vary by algorithm: RSA emits `sign/s verify/s encr./s decr./s`,
    ECDH emits `op/s`, EdDSA emits `sign/s verify/s`, and PQC-style entries
    (rsa-as-KEM) emit `keygens/s encaps/s decaps/s` or `keygens/s sign/s
    verify/s`.  A header is followed by a single data row whose trailing
    columns hold the per-second rates.

    Detection rule: a line is a header iff it contains 1+ tokens ending in
    `/s` and no numeric leading content.  Earlier code required the
    literal substring `op/s`, which silently skipped RSA/EdDSA/PQC headers.
    """
    out: dict[str, dict[str, float]] = {}
    pending: list[str] = []
    # Algorithm names can appear at column 0 (`rsa  2048 bits ...`,
    # `rsa2048 ...`) or mid-line wrapped in a description
    # (` 253 bits ecdh (X25519)`, ` 253 bits EdDSA (Ed25519)`).
    name_re = re.compile(
        r"\b(rsa\s*\d+|ed25519|ed448|ecdh|ecdsa|eddsa|x25519|x448)\b",
        re.IGNORECASE,
    )
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        per_s_tokens = re.findall(r"\S+?/s\b", s)
        # A header line: contains one or more `*/s` tokens and does not
        # start with a digit (data rows like ` 253 bits ...` start with
        # numeric content).
        if per_s_tokens and not re.match(r"^\s*\d", line):
            pending = per_s_tokens
            continue
        if not pending:
            continue
        m = name_re.search(line)
        if not m:
            continue
        name = re.sub(r"\s+", "", m.group(1).lower())
        nums = re.findall(r"\d+(?:\.\d+)?", line)
        if len(nums) < len(pending):
            continue
        rates = [float(x) for x in nums[-len(pending) :]]
        # The same algorithm appears under several header sections in
        # `openssl speed` (e.g., RSA shows up under the legacy block, the
        # KEM block, and the signature block).  Keep the first reading.
        out.setdefault(name, dict(zip(pending, rates)))
        pending = []
    return out


def run_pqc_bench(seconds: int, threads: int) -> dict[str, Any]:
    plan: list[tuple[str, str, tuple[str, ...]]] = [
        ("ML-KEM-768", "-kem-algorithms", ("keygen/s", "encaps/s", "decaps/s")),
        ("ML-DSA-65", "-signature-algorithms", ("keygen/s", "sign/s", "verify/s")),
        (
            "SLH-DSA-SHA2-128s",
            "-signature-algorithms",
            ("keygen/s", "sign/s", "verify/s"),
        ),
    ]
    results: dict[str, Any] = {}
    for algo, flag, labels in plan:
        cmd = ["openssl", "speed", "-seconds", str(seconds), flag, algo]
        rc, out = _run(cmd, timeout=seconds * 8 + 30)
        if rc != 0:
            results[algo] = {
                "error": out.strip().splitlines()[-1][:200] if out else f"rc={rc}"
            }
            continue
        rates = parse_speed_row(out, algo, labels)
        if rates is None:
            results[algo] = {"raw": out.strip().splitlines()[-1][:200]}
        else:
            results[algo] = rates
        if threads > 1:
            cmd_m = [
                "openssl",
                "speed",
                "-multi",
                str(threads),
                "-seconds",
                str(seconds),
                flag,
                algo,
            ]
            rc2, out2 = _run(cmd_m, timeout=seconds * 8 + 60)
            if rc2 == 0:
                m_rates = parse_speed_row(out2, algo, labels)
                if m_rates:
                    results[algo][f"x{threads}_aggregate"] = m_rates
    return results


def run_classical_baseline(seconds: int) -> dict[str, dict[str, float]]:
    rc, out = _run(
        [
            "openssl",
            "speed",
            "-seconds",
            str(seconds),
            "rsa2048",
            "ed25519",
            "ecdhx25519",
        ],
        timeout=seconds * 6 + 30,
    )
    if rc != 0:
        return {}
    return parse_classical_speed(out)


def run_benchmarks(seconds: int = 1, threads: int = 1) -> dict[str, Any]:
    if not shutil.which("openssl"):
        return {"available": False, "reason": "openssl not on PATH"}
    rc, ver = _run(["openssl", "version"], timeout=5)
    m = re.search(r"OpenSSL\s+(\d+)\.(\d+)", ver)
    if not m or (int(m.group(1)), int(m.group(2))) < (3, 5):
        return {"available": False, "reason": f"OpenSSL pre-3.5 (got {ver.strip()})"}
    return {
        "available": True,
        "engine": "openssl speed",
        "seconds_per_test": seconds,
        "threads": threads,
        "pqc": run_pqc_bench(seconds, threads),
        "classical": run_classical_baseline(seconds),
    }


# ---------------------------------------------------------------------------
# TLS-handshake benchmark
#
# `openssl speed` measures algorithm operations in isolation; it does not
# capture the network-side cost of larger PQC keys and signatures (cert
# chain inflation, initcwnd overflow) that only shows up at the handshake
# layer specified in RFC 8446.  This benchmark drives `openssl s_server`
# and `openssl s_client` over loopback so the wire-side bandwidth impact
# becomes visible alongside the algorithm-level numbers.
# ---------------------------------------------------------------------------


def _tls_pick_classical_group(classical: list[str]) -> str | None:
    """Pick a sensible classical TLS 1.3 group for the baseline.

    Prefer x25519 (modern default); fall back to secp256r1 if x25519 is
    not exposed by the local OpenSSL.  Older curves (secp384r1, etc.)
    are accepted only as a last resort so the comparison stays apples
    to apples with the PQC suites.
    """
    lowered = {g.lower(): g for g in classical}
    for pref in ("x25519", "secp256r1", "secp384r1"):
        if pref in lowered:
            return lowered[pref]
    return classical[0] if classical else None


def _tls_find_composite_signature_alg(sig_algs: list[str]) -> str | None:
    """Detect a composite signature scheme exposed by the local OpenSSL.

    Composite signatures (draft-ietf-lamps-pq-composite-sigs) bind a PQC
    signature with a classical signature in a single key, providing a
    hybrid hedge during PQC migration.  Only stock OpenSSL builds with
    a provider exposing such names will return a non-None value.
    Returns the OpenSSL algorithm name (suitable as `-newkey` arg) or
    None if no composite scheme is available.
    """
    pat = re.compile(
        r"^(?:id-)?(?:ml-?dsa)[-_]?\d+[-_]?"
        r"(?:rsa\d*|p\d{3}|ecdsa[-_]?p\d{3}|ed25519|ed448)",
        re.IGNORECASE,
    )
    for name in sig_algs:
        if pat.match(name):
            return name
    return None


def _tls_build_suites(osinfo: dict[str, Any]) -> list[dict[str, str]]:
    """Pick the set of TLS group/cert configurations to benchmark.

    Returns a list of suite descriptors with `label`, `role`, `group`,
    and (optionally) `cert_signature_algorithm` keys.  Suites that are
    not supported by the local OpenSSL are silently omitted.
    """
    groups = osinfo.get("tls_groups") or {}
    suites: list[dict[str, str]] = []
    classical = _tls_pick_classical_group(list(groups.get("classical") or []))
    if classical:
        suites.append(
            {
                "label": f"classical ({classical})",
                "role": "classical",
                "group": classical,
            }
        )
    hybrid = list(groups.get("hybrid") or [])
    pref_hybrid = next(
        (g for g in hybrid if g.lower() in ("x25519mlkem768",)),
        hybrid[0] if hybrid else None,
    )
    if pref_hybrid:
        suites.append(
            {"label": f"hybrid ({pref_hybrid})", "role": "hybrid", "group": pref_hybrid}
        )
    pure = list(groups.get("pure_pqc") or [])
    pref_pure = next(
        (g for g in pure if g.lower() in ("mlkem768",)),
        pure[0] if pure else None,
    )
    if pref_pure:
        suites.append(
            {"label": f"pure-pqc ({pref_pure})", "role": "pure_pqc", "group": pref_pure}
        )
    return suites


def _tls_get_free_port() -> int:
    """Return a TCP port that is currently free on 127.0.0.1.

    We close the probe socket before returning, so there is a small
    race where another process could grab the port before s_server
    binds.  In practice loopback contention on a CI runner is low
    enough that this is not a problem in practice; we accept the race
    rather than maintain a long-lived parent socket.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _tls_wait_for_port(port: int, timeout: float) -> bool:
    """Poll-connect to 127.0.0.1:port until it accepts or timeout expires."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.05)
    return False


def _tls_byte_counting_proxy(
    listen_port: int,
    target_port: int,
    expected_connections: int,
    accumulator: dict[str, int],
    timeout: float,
    ready_event: threading.Event,
) -> None:
    """Forward TCP between listen_port and target_port, counting bytes.

    Runs in its own thread.  Accepts up to `expected_connections`
    inbound connections (one per s_client invocation), forwards each to
    target_port, and accumulates the total byte count in
    accumulator['total'] with the connection count in accumulator['n'].
    Sets ready_event once it is listening.
    """
    deadline = time.monotonic() + timeout
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(("127.0.0.1", listen_port))
        srv.listen(max(expected_connections, 1))
    except OSError:
        ready_event.set()
        srv.close()
        return
    ready_event.set()
    accepted = 0
    try:
        while accepted < expected_connections and time.monotonic() < deadline:
            srv.settimeout(max(0.1, deadline - time.monotonic()))
            try:
                client, _ = srv.accept()
            except (socket.timeout, TimeoutError):
                break
            accepted += 1
            try:
                upstream = socket.create_connection(
                    ("127.0.0.1", target_port), timeout=2.0
                )
            except OSError:
                client.close()
                continue
            client.settimeout(None)
            upstream.settimeout(None)
            socks: list[socket.socket] = [client, upstream]
            conn_bytes = 0
            try:
                while socks:
                    rlist, _, _ = select.select(socks, [], [], 5.0)
                    if not rlist:
                        break
                    closed = False
                    for s in rlist:
                        try:
                            data = s.recv(8192)
                        except OSError:
                            data = b""
                        if not data:
                            closed = True
                            break
                        conn_bytes += len(data)
                        peer = upstream if s is client else client
                        try:
                            peer.sendall(data)
                        except OSError:
                            closed = True
                            break
                    if closed:
                        break
            finally:
                try:
                    client.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    upstream.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                client.close()
                upstream.close()
            accumulator["total"] += conn_bytes
            accumulator["n"] += 1
    finally:
        srv.close()


def _tls_generate_test_cert(
    cert: Path, key: Path, key_alg: str = "RSA:2048"
) -> tuple[bool, str]:
    """Create a self-signed loopback test cert.

    Uses RSA-2048 by default since it is universally supported by
    OpenSSL 3.x without requiring the EC subsystem.  Returns
    (True, "") on success, (False, reason) on failure.
    """
    cmd = [
        "openssl",
        "req",
        "-x509",
        "-newkey",
        key_alg,
        "-keyout",
        str(key),
        "-out",
        str(cert),
        "-noenc",
        "-subj",
        "/CN=localhost",
        "-addext",
        "subjectAltName=DNS:localhost,IP:127.0.0.1",
        "-days",
        "1",
    ]
    rc, out = _run(cmd, timeout=20)
    if rc != 0 or not cert.exists() or not key.exists():
        return False, (out.strip().splitlines() or [f"rc={rc}"])[-1][:200]
    return True, ""


def _tls_run_one_handshake(
    cert: Path, group: str, port: int, timeout: float = 10.0
) -> float | None:
    """Run a single full TLS handshake against 127.0.0.1:port via s_client.

    Returns elapsed wall-clock seconds for the s_client invocation, or
    None if the handshake failed.  Note: this measurement includes the
    cost of spawning the openssl process; the relative comparison
    between groups remains valid because spawn cost is constant.
    """
    cmd = [
        "openssl",
        "s_client",
        "-connect",
        f"127.0.0.1:{port}",
        "-groups",
        group,
        "-CAfile",
        str(cert),
        "-verify_return_error",
        "-quiet",
        "-no_ign_eof",
    ]
    start = time.perf_counter()
    try:
        p = subprocess.run(
            cmd,
            input=b"GET / HTTP/1.0\r\n\r\n",
            capture_output=True,
            timeout=timeout,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None
    elapsed = time.perf_counter() - start
    # `s_server -www` returns an HTTP 200 page and closes; s_client exits 0.
    # Some OpenSSL builds exit non-zero on the server-side close even when
    # the handshake succeeded, so we accept any exit code as long as the
    # response payload is present.
    if p.returncode != 0 and b"s_server" not in p.stdout:
        return None
    return elapsed


def _tls_bench_one_suite(
    cert: Path,
    key: Path,
    suite: dict[str, str],
    iterations: int,
    handshake_timeout: float = 10.0,
) -> dict[str, Any]:
    """Run `iterations` handshakes for one TLS suite and report metrics."""
    server_port = _tls_get_free_port()
    proxy_port = _tls_get_free_port()
    while proxy_port == server_port:
        proxy_port = _tls_get_free_port()
    server_cmd = [
        "openssl",
        "s_server",
        "-accept",
        str(server_port),
        "-cert",
        str(cert),
        "-key",
        str(key),
        "-groups",
        suite["group"],
        "-www",
        "-no_ticket",
        "-naccept",
        str(iterations + 4),
        "-quiet",
    ]
    try:
        server = subprocess.Popen(
            server_cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
    except OSError as exc:
        return {"error": f"failed to spawn s_server: {exc}"}
    try:
        if not _tls_wait_for_port(server_port, timeout=5.0):
            stderr = b""
            try:
                stderr = server.stderr.read() if server.stderr else b""
            except OSError:
                stderr = b""
            return {
                "error": "s_server failed to listen",
                "detail": stderr.decode("utf-8", "replace").strip()[:200],
            }
        accumulator: dict[str, int] = {"total": 0, "n": 0}
        ready = threading.Event()
        proxy = threading.Thread(
            target=_tls_byte_counting_proxy,
            args=(
                proxy_port,
                server_port,
                iterations,
                accumulator,
                handshake_timeout * iterations + 30.0,
                ready,
            ),
            daemon=True,
        )
        proxy.start()
        ready.wait(timeout=5.0)
        if not _tls_wait_for_port(proxy_port, timeout=5.0):
            return {"error": "byte-counting proxy failed to listen"}
        times: list[float] = []
        for _ in range(iterations):
            t = _tls_run_one_handshake(
                cert, suite["group"], proxy_port, timeout=handshake_timeout
            )
            if t is not None:
                times.append(t)
        proxy.join(timeout=10.0)
    finally:
        try:
            server.terminate()
            server.wait(timeout=3)
        except subprocess.TimeoutExpired:
            try:
                server.kill()
                server.wait(timeout=2)
            except OSError:
                pass
        except OSError:
            pass
        if server.stderr:
            try:
                server.stderr.close()
            except OSError:
                pass
    if not times:
        return {"error": "no successful handshakes"}
    total = sum(times)
    bytes_per = (
        round(accumulator["total"] / accumulator["n"]) if accumulator["n"] > 0 else None
    )
    return {
        "iterations": len(times),
        "handshakes_per_sec": round(len(times) / total, 2) if total > 0 else 0.0,
        "ttfb_ms_mean": round(statistics.mean(times) * 1000.0, 3),
        "ttfb_ms_median": round(statistics.median(times) * 1000.0, 3),
        "bytes_on_wire_per_handshake": bytes_per,
        "bytes_observed_connections": accumulator["n"],
    }


def _tls_bench_composite_signature(
    tmpdir: Path,
    osinfo: dict[str, Any],
    iterations: int,
) -> dict[str, Any] | None:
    """Run the composite-signature variant of the suite, if available.

    Composite signatures bind a PQC scheme with a classical scheme in a
    single signing key (per draft-ietf-lamps-pq-composite-sigs).  Only
    OpenSSL builds with a provider exposing such names can generate a
    cert with a composite key; the function returns None when no such
    algorithm is exposed or when cert generation fails.
    """
    sig_algs = list(osinfo.get("sig_algorithms") or [])
    composite = _tls_find_composite_signature_alg(sig_algs)
    if not composite:
        return None
    classical_group = _tls_pick_classical_group(
        list((osinfo.get("tls_groups") or {}).get("classical") or [])
    )
    if not classical_group:
        return None
    cert = tmpdir / "cert-composite.pem"
    key = tmpdir / "key-composite.pem"
    ok, reason = _tls_generate_test_cert(cert, key, key_alg=composite)
    if not ok:
        return {
            "label": f"composite-sig ({composite})",
            "role": "composite_sig",
            "group": classical_group,
            "cert_signature_algorithm": composite,
            "skipped": True,
            "reason": f"cert generation failed: {reason}",
        }
    suite: dict[str, str] = {
        "label": f"composite-sig ({composite})",
        "role": "composite_sig",
        "group": classical_group,
        "cert_signature_algorithm": composite,
    }
    metrics = _tls_bench_one_suite(cert, key, suite, iterations)
    return {**suite, **metrics}


def run_tls_handshake_bench(
    seconds: int, osinfo: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Loopback TLS handshake benchmark across classical / hybrid / PQC.

    Drives `openssl s_server` and `openssl s_client` over a Python
    byte-counting proxy on 127.0.0.1.  Reports handshakes/sec, mean and
    median time-to-first-byte (in milliseconds, including s_client
    process startup), and bytes-on-wire per handshake for each
    available TLS group selection plus an optional composite-signature
    cert variant.
    """
    if not shutil.which("openssl"):
        return {"available": False, "reason": "openssl not on PATH"}
    rc, ver = _run(["openssl", "version"], timeout=5)
    m = re.search(r"OpenSSL\s+(\d+)\.(\d+)", ver)
    if not m or (int(m.group(1)), int(m.group(2))) < (3, 5):
        return {
            "available": False,
            "reason": f"OpenSSL pre-3.5 lacks ML-KEM groups (got {ver.strip()})",
        }
    if osinfo is None:
        osinfo = openssl_capability()
    if not osinfo.get("available"):
        return {"available": False, "reason": "openssl_capability probe failed"}
    suites = _tls_build_suites(osinfo)
    if not suites:
        return {
            "available": False,
            "reason": "no TLS groups recognised by the local OpenSSL",
        }
    iterations = max(20, min(200, seconds * 30))
    with tempfile.TemporaryDirectory(prefix="pqc-readiness-tls-") as td_str:
        td = Path(td_str)
        cert = td / "cert.pem"
        key = td / "key.pem"
        ok, reason = _tls_generate_test_cert(cert, key)
        if not ok:
            return {
                "available": False,
                "reason": f"failed to generate test cert: {reason}",
            }
        results: list[dict[str, Any]] = []
        for s in suites:
            metrics = _tls_bench_one_suite(cert, key, s, iterations)
            results.append({**s, **metrics})
        composite = _tls_bench_composite_signature(td, osinfo, iterations)
        if composite is not None:
            results.append(composite)
    return {
        "available": True,
        "engine": "tls-handshake",
        "transport": "loopback",
        "openssl_version": (osinfo.get("version") or "").strip(),
        "iterations_per_suite": iterations,
        "seconds_budget": seconds,
        "note": (
            "ttfb measurements include the s_client process startup cost; "
            "comparisons across groups are still meaningful because that "
            "cost is constant"
        ),
        "suites": results,
    }


def memory_bandwidth_probe() -> tuple[float | None, str]:
    """STREAM-triad-style memory bandwidth probe (a = b * scalar + c).

    Returns (gb_per_sec, method).  When numpy is unavailable, returns
    (None, "unavailable: numpy not installed") rather than producing a
    misleading number.

    The previous bytes(bytearray) implementation measured a combination
    of allocator throughput and intra-process memcpy and was not
    representative of sustained memory bandwidth — it is removed.
    Section 3's SLH-DSA tier downgrade gates on this probe; if it
    returned None, no downgrade is applied.
    """
    try:
        import numpy as np
    except ImportError:
        return None, "unavailable: numpy not installed"
    try:
        n = 16 * 1024 * 1024  # 128 MiB per array (3 arrays = 384 MiB working set)
        a = np.zeros(n, dtype=np.float64)
        b = np.ones(n, dtype=np.float64)
        c = np.full(n, 2.0, dtype=np.float64)
        # Warm caches.
        np.add(np.multiply(b, 3.0), c, out=a)
        iters = 5
        t0 = time.perf_counter()
        for _ in range(iters):
            np.add(np.multiply(b, 3.0), c, out=a)
        elapsed = time.perf_counter() - t0
        if elapsed <= 0:
            return None, "probe failed: zero elapsed time"
        # Conservative: 3 reads (b, c, intermediate) + 1 write (a) per
        # element per iteration.  numpy may fuse this to 3 ops; we
        # under-report rather than over-report.
        bytes_moved = 4 * 8 * n * iters
        gb_per_s = bytes_moved / elapsed / (1024**3)
        return round(gb_per_s, 1), "STREAM-triad (numpy)"
    except (MemoryError, OSError) as e:
        return None, f"probe failed: {e}"


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
    for key, (op, thresholds) in ALGO_THRESHOLDS.items():
        algo = key.split("/", 1)[0]
        bench_algo = (pqc or {}).get(algo)
        notes = list(ALGO_NOTES.get(algo, []))
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
                "reason": "no benchmark data",
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
            and mem_bw_gb_s < SLH_DSA_MEM_BANDWIDTH_FLOOR_GB_S
        ):
            old_tier = tier
            idx = max(0, _TIER_ORDER.index(tier) - 1)
            tier = _TIER_ORDER[idx]
            notes.append(
                f"Tier downgraded from '{old_tier}' to '{tier}': measured "
                f"memory bandwidth {mem_bw_gb_s:.1f} GB/s is below the "
                f"{SLH_DSA_MEM_BANDWIDTH_FLOOR_GB_S:.0f} GB/s floor for "
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


# ---------------------------------------------------------------------------
# Algorithm recommendation engine
# ---------------------------------------------------------------------------
#
# `recommend()` is a pure function over (Report, policy, role).  It does
# NOT consult network or disk; everything it needs is already on the
# Report.  The policy-to-preference mapping is a single declarative dict
# (POLICY_PREFERENCES) so that authority position changes can be made
# without touching the engine.  The authoritative document for each
# policy is cited in `docs/recommendation-policies.md`.
#
# Five policy modes, four full and one composite:
#   cnsa-2.0      US National Security Systems / NSA-aligned.  Pure PQC
#                 preferred; hybrid permitted only where a protocol
#                 mandates it (IKEv2).
#   nist-civilian US federal civilian / FCEB.  ML-KEM, ML-DSA, SLH-DSA
#                 per FIPS 203/204/205.  Hybrid permitted, not required.
#   eu-anssi-bsi  EU public sector under ANSSI / BSI.  Hybrid actively
#                 recommended throughout the migration period.
#   commercial    No specific compliance regime.  Both pure and hybrid
#                 acceptable; hybrid suggested for long-confidentiality
#                 (HNDL-relevant) data.
#   auto          Side-by-side recommendation under all four real
#                 policies, with no single "preferred" answer.
#
# Roles:
#   tls-server        fully implemented
#   tls-client        stub: returns {"implemented": False, ...}
#   signing-service   stub: returns {"implemented": False, ...}
#   firmware-signing  stub: returns {"implemented": False, ...}
#
# The non-tls-server roles are intentionally stubs — see issue #13
# acceptance criteria, which scope the first cut to tls-server.

POLICY_PREFERENCES: dict[str, dict[str, Any]] = {
    "cnsa-2.0": {
        "name": "CNSA 2.0",
        "authority": "NSA / CNSA 2.0 (US National Security Systems)",
        "hybrid_policy": "discouraged",
        "hybrid_allowed_for": ["ikev2"],
        "kem_primary": "ML-KEM-1024",
        "sig_primary": "ML-DSA-87",
        "hash_primary": "SHA-384",
        "requires_fips": True,
        "citation": (
            "CNSA 2.0 specifies ML-KEM-1024 and ML-DSA-87 for National "
            "Security Systems.  Pure PQC is preferred; hybrid is "
            "permitted only where a protocol mandates it (e.g., IKEv2)."
        ),
        "source": (
            "NSA CSA / CSI on Commercial National Security Algorithm "
            "Suite 2.0 (CNSA 2.0 advisory and FAQ)"
        ),
    },
    "nist-civilian": {
        "name": "NIST civilian / FCEB",
        "authority": "NIST FIPS 203 / 204 / 205 (US federal civilian)",
        "hybrid_policy": "permitted",
        "hybrid_allowed_for": ["tls-server", "tls-client", "ikev2"],
        "kem_primary": "ML-KEM-768",
        "sig_primary": "ML-DSA-65",
        "hash_primary": "SHA-256",
        "requires_fips": True,
        "citation": (
            "NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), and FIPS 205 "
            "(SLH-DSA) standardize the civilian PQC suite.  Hybrid is "
            "permitted under SP 800-56C Rev. 2; it is not required."
        ),
        "source": (
            "NIST FIPS 203 / 204 / 205, NIST IR 8547, "
            "NIST SP 800-56C Rev. 2, NIST SP 800-227"
        ),
    },
    "eu-anssi-bsi": {
        "name": "ANSSI / BSI hybrid",
        "authority": "ANSSI (FR) and BSI (DE) PQC migration guidance",
        "hybrid_policy": "recommended",
        "hybrid_allowed_for": [
            "tls-server",
            "tls-client",
            "ikev2",
            "signing-service",
        ],
        "kem_primary": "ML-KEM-768",
        "sig_primary": "ML-DSA-65",
        "hash_primary": "SHA-256",
        "requires_fips": False,
        "citation": (
            "ANSSI and BSI both recommend deploying PQC alongside a "
            "classical primitive (hybrid) during the migration period.  "
            "Pure-PQC deployments are discouraged until confidence in "
            "the new primitives matures."
        ),
        "source": "ANSSI position on PQC migration; BSI guidance on PQC",
    },
    "commercial": {
        "name": "Commercial / no specific regime",
        "authority": "no specific compliance regime",
        "hybrid_policy": "either",
        "hybrid_allowed_for": [
            "tls-server",
            "tls-client",
            "ikev2",
            "signing-service",
        ],
        "kem_primary": "ML-KEM-768",
        "sig_primary": "ML-DSA-65",
        "hash_primary": "SHA-256",
        "requires_fips": False,
        "citation": (
            "Outside a specific compliance regime, both pure-PQC and "
            "hybrid deployments are acceptable.  Hybrid is suggested "
            "for data with long-confidentiality requirements (HNDL)."
        ),
        "source": "no single source — see policy guidance documentation",
    },
}

VALID_POLICIES = ("cnsa-2.0", "nist-civilian", "eu-anssi-bsi", "commercial")
VALID_ROLES = ("tls-server", "tls-client", "signing-service", "firmware-signing")


def _accel_pqc_capable(accelerators: list[dict[str, Any]]) -> bool:
    return any(a.get("pqc_capable") for a in (accelerators or []))


def _isa_supports_large_params(isa_tier_str: str, has_pqc_accel: bool) -> bool:
    """ISA tier 'excellent', or any tier with a PQC-capable accelerator,
    can carry the larger parameter sets (ML-KEM-1024 / ML-DSA-87) at
    typical service SLOs."""
    return isa_tier_str == "excellent" or has_pqc_accel


def _recommend_tls_server(r: Report, policy: str) -> dict[str, Any]:
    pref = POLICY_PREFERENCES[policy]
    isa = (r.isa_tier or "unknown").lower()
    accel_pqc = _accel_pqc_capable(r.accelerators)
    fips_kernel = bool((r.fips or {}).get("kernel"))
    openssl = r.openssl or {}
    tls_groups = openssl.get("tls_groups") or {}
    hybrid_groups = list(tls_groups.get("hybrid") or [])
    pure_groups = list(tls_groups.get("pure_pqc") or [])
    openssl_version = openssl.get("version") or ""
    kernel_release = (r.kernel_info or {}).get("release") or ""

    caveats: list[str] = []

    # KEM choice -----------------------------------------------------------
    if policy == "cnsa-2.0":
        kem_chosen = "ML-KEM-1024"
        if _isa_supports_large_params(isa, accel_pqc):
            kem_reason = (
                "ML-KEM-1024 per CNSA 2.0; ISA tier and/or PQC accelerator "
                "supports the larger parameter set"
            )
        else:
            kem_reason = "ML-KEM-1024 mandated by CNSA 2.0"
            caveats.append(
                f"Policy mandates ML-KEM-1024 but host ISA tier is '{isa}' "
                "and no PQC-capable accelerator is present; encapsulation "
                "throughput will be lower than ML-KEM-768.  Add a PQC "
                "accelerator or accept the slower path."
            )
    elif policy == "eu-anssi-bsi":
        kem_chosen = "ML-KEM-768"
        kem_reason = (
            "ML-KEM-768 deployed in hybrid; ANSSI and BSI both recommend "
            "hybrid during the migration period"
        )
    elif policy == "nist-civilian":
        kem_chosen = "ML-KEM-768"
        if _isa_supports_large_params(isa, accel_pqc):
            kem_reason = (
                "ML-KEM-768 per FIPS 203; ISA tier could support ML-KEM-1024 "
                "if compliance scope demands it"
            )
        else:
            kem_reason = "ML-KEM-768 per FIPS 203; balanced for civilian deployments"
    else:  # commercial
        kem_chosen = "ML-KEM-768"
        kem_reason = (
            "ML-KEM-768 — broadly interoperable default for commercial "
            "deployments; consider hybrid for long-confidentiality data"
        )

    # Hybrid vs pure for the KEM ------------------------------------------
    if pref["hybrid_policy"] == "recommended":
        kem_mode = "hybrid"
    elif pref["hybrid_policy"] == "discouraged":
        # CNSA 2.0: pure preferred.  Hybrid is permitted only where the
        # protocol mandates it (IKEv2).  TLS server is not IKEv2.
        kem_mode = "pure"
    else:
        # nist-civilian / commercial: pure default; hybrid is permitted.
        kem_mode = "pure"

    # Capability check on advertised TLS 1.3 groups -----------------------
    if openssl.get("available"):
        if kem_mode == "hybrid" and not hybrid_groups:
            caveats.append(
                "No TLS 1.3 hybrid groups are advertised by this OpenSSL "
                "build.  Upgrade OpenSSL or load the relevant provider "
                "before deploying a hybrid TLS server."
            )
        elif kem_mode == "pure" and not pure_groups:
            caveats.append(
                "No TLS 1.3 pure-PQC groups are advertised by this "
                "OpenSSL build.  Upgrade OpenSSL or load the relevant "
                "provider before deploying pure-PQC TLS."
            )
    else:
        caveats.append(
            "OpenSSL was not detected on this host; the recommended "
            "algorithms cannot be served via TLS until an OpenSSL build "
            "with TLS 1.3 PQC group support is installed."
        )

    # Signature choice ----------------------------------------------------
    if policy == "cnsa-2.0":
        sig_chosen = "ML-DSA-87"
        if _isa_supports_large_params(isa, accel_pqc):
            sig_reason = (
                "ML-DSA-87 per CNSA 2.0; ISA tier supports the signing "
                "latency at typical service SLOs"
            )
        else:
            sig_reason = "ML-DSA-87 mandated by CNSA 2.0"
            caveats.append(
                f"Policy mandates ML-DSA-87 but host ISA tier is '{isa}' "
                "without a PQC accelerator; ML-DSA-87 sign p99 latency "
                "may exceed typical service SLOs.  Consider a hardware "
                "accelerator or accept the slower path."
            )
    else:
        sig_chosen = "ML-DSA-65"
        if isa == "good":
            sig_reason = (
                "ML-DSA-65 over ML-DSA-87 because ISA tier is 'good' not "
                "'excellent'; ML-DSA-87 sign p99 latency will likely "
                "exceed typical service SLOs"
            )
        elif isa in ("poor", "marginal"):
            sig_reason = (
                f"ML-DSA-65 because ISA tier is '{isa}' without a PQC "
                "accelerator; ML-DSA-87 sign p99 latency would likely "
                "exceed typical SLOs"
            )
        elif isa == "excellent":
            sig_reason = (
                "ML-DSA-65 — balanced default for civilian/commercial "
                "deployments; ISA tier could support ML-DSA-87 if "
                "compliance scope demands it"
            )
        else:
            sig_reason = (
                "ML-DSA-65 — balanced default for civilian/commercial deployments"
            )

    # Hash ----------------------------------------------------------------
    hash_chosen = pref["hash_primary"]
    hash_reason = f"{hash_chosen} aligned with {pref['name']} guidance"

    # FIPS state caveats --------------------------------------------------
    if pref["requires_fips"] and not fips_kernel:
        caveats.append(
            f"Kernel FIPS mode is not enabled.  {pref['name']} requires "
            "use of FIPS-validated cryptographic modules; enable kernel "
            "FIPS mode and load a FIPS-validated provider before going "
            "to production."
        )

    # Build the recommendation record ------------------------------------
    return {
        "role": "tls-server",
        "policy": policy,
        "policy_authority": pref["authority"],
        "policy_basis": pref["citation"],
        "policy_source": pref["source"],
        "implemented": True,
        "kem": {
            "algorithm": kem_chosen,
            "mode": kem_mode,
            "reason": kem_reason,
        },
        "signature": {
            "algorithm": sig_chosen,
            "reason": sig_reason,
        },
        "hash": {
            "algorithm": hash_chosen,
            "reason": hash_reason,
        },
        "host_capability_inputs": {
            "isa_tier": isa,
            "pqc_accelerator_present": accel_pqc,
            "fips_kernel": fips_kernel,
            "openssl_version": openssl_version,
            "kernel_release": kernel_release,
        },
        "caveats": caveats,
    }


def _recommend_stub(r: Report, policy: str, role: str) -> dict[str, Any]:
    """Placeholder for roles not yet fully implemented.  Returns the
    policy basis so the JSON shape is consistent across roles, but
    leaves the algorithm fields empty.

    TODO(#13): expand to fully implement tls-client, signing-service,
    and firmware-signing.  Each has its own SLO profile (e.g.,
    firmware-signing tolerates SLH-DSA; tls-client cares about
    handshake size more than throughput)."""
    pref = POLICY_PREFERENCES[policy]
    return {
        "role": role,
        "policy": policy,
        "policy_authority": pref["authority"],
        "policy_basis": pref["citation"],
        "policy_source": pref["source"],
        "implemented": False,
        "note": (
            f"Recommendations for role={role!r} are not yet implemented.  "
            "Only role='tls-server' is supported in this revision."
        ),
        "host_capability_inputs": {
            "isa_tier": (r.isa_tier or "unknown").lower(),
            "pqc_accelerator_present": _accel_pqc_capable(r.accelerators),
        },
        "caveats": [],
    }


def _recommend_one(r: Report, policy: str, role: str) -> dict[str, Any]:
    if role == "tls-server":
        return _recommend_tls_server(r, policy)
    return _recommend_stub(r, policy, role)


def recommend(
    r: Report,
    policy: str = "auto",
    role: str = "tls-server",
) -> dict[str, Any]:
    """Produce a host-specific PQC algorithm recommendation.

    Pure function over (Report, policy, role).  Returns a record that
    contains the recommendation AND the policy basis as separate fields,
    so downstream tooling can audit the chain of reasoning without
    re-deriving it.

    policy='auto' emits one recommendation per real policy in
    POLICY_PREFERENCES, side by side, with no single 'preferred' answer.
    """
    if role not in VALID_ROLES:
        raise ValueError(
            f"unknown role {role!r}; valid roles: {', '.join(VALID_ROLES)}"
        )
    if policy == "auto":
        return {
            "role": role,
            "mode": "auto",
            "hostname": r.hostname,
            "generated_at": r.generated_at,
            "recommendations": {p: _recommend_one(r, p, role) for p in VALID_POLICIES},
        }
    if policy not in POLICY_PREFERENCES:
        raise ValueError(
            f"unknown policy {policy!r}; valid policies: "
            f"{', '.join(VALID_POLICIES)} (or 'auto')"
        )
    return {
        "role": role,
        "mode": "single",
        "policy": policy,
        "hostname": r.hostname,
        "generated_at": r.generated_at,
        "recommendations": {policy: _recommend_one(r, policy, role)},
    }


def _render_recommendation_block(rec: dict[str, Any]) -> list[str]:
    """Render a single per-policy recommendation as plain-text lines."""
    L: list[str] = []
    L.append(f"Policy: {rec['policy']} ({rec['policy_authority']})")
    if not rec.get("implemented", False):
        L.append(f"  {rec.get('note', 'not implemented')}")
        return L
    kem = rec["kem"]
    sig = rec["signature"]
    h = rec["hash"]
    L.append(f"  KEM:        {kem['algorithm']} ({kem['mode']})")
    L.append(f"              Reason: {kem['reason']}")
    L.append(f"  Signature:  {sig['algorithm']}")
    L.append(f"              Reason: {sig['reason']}")
    L.append(f"  Hash:       {h['algorithm']}")
    L.append(f"              Reason: {h['reason']}")
    L.append(f"  Policy basis: {rec['policy_basis']}")
    L.append(f"  Source:       {rec['policy_source']}")
    if rec["caveats"]:
        L.append("  Caveats:")
        for c in rec["caveats"]:
            L.append(f"    - {c}")
    return L


def render_recommendation_text(report: Report, rec: dict[str, Any]) -> str:
    L: list[str] = []
    L.append(f"PQC algorithm recommendation — {report.hostname or 'unknown'}")
    L.append(f"Role: {rec['role']}")
    L.append(f"Mode: {rec['mode']}")
    L.append("")
    for _, sub in rec["recommendations"].items():
        L.extend(_render_recommendation_block(sub))
        L.append("")
    return "\n".join(L).rstrip() + "\n"


def render_recommendation_markdown(report: Report, rec: dict[str, Any]) -> str:
    L: list[str] = []
    L.append(f"# PQC algorithm recommendation — {report.hostname or 'unknown'}")
    L.append("")
    L.append(f"_Generated {report.generated_at}_")
    L.append("")
    L.append(f"**Role:** `{rec['role']}` &nbsp;·&nbsp; **Mode:** `{rec['mode']}`")
    L.append("")
    for _, sub in rec["recommendations"].items():
        L.append(f"## Policy: `{sub['policy']}` — {sub['policy_authority']}")
        L.append("")
        if not sub.get("implemented", False):
            L.append(f"> {sub.get('note', 'not implemented')}")
            L.append("")
            continue
        kem = sub["kem"]
        sig = sub["signature"]
        h = sub["hash"]
        L.append("| Primitive | Algorithm | Reason |")
        L.append("|-----------|-----------|--------|")
        L.append(f"| KEM ({kem['mode']}) | `{kem['algorithm']}` | {kem['reason']} |")
        L.append(f"| Signature | `{sig['algorithm']}` | {sig['reason']} |")
        L.append(f"| Hash | `{h['algorithm']}` | {h['reason']} |")
        L.append("")
        L.append(f"**Policy basis:** {sub['policy_basis']}")
        L.append("")
        L.append(f"**Source:** {sub['policy_source']}")
        L.append("")
        if sub["caveats"]:
            L.append("**Caveats:**")
            L.append("")
            for c in sub["caveats"]:
                L.append(f"- {c}")
            L.append("")
    return "\n".join(L).rstrip() + "\n"


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------


def _tier_label(tier: str) -> str:
    return C.wrap(TIER_COLOR.get(tier, ""), tier.upper())


# Canonical cryptographic-asset model ----------------------------------------
#
# Both --cbom (CycloneDX 1.6) and --spdx (SPDX 3.0 JSON-LD) project from
# the same canonical CryptoAsset list, so detection logic lives in one
# place and the renderers are pure projections.  A single source of
# truth means a new detection rule shows up in every output format
# without a renderer-side patch.
#
# Refs:
#   https://cyclonedx.org/docs/1.6/json/  (specVersion 1.6)
#   https://csrc.nist.gov/pubs/ir/8547/final  (NIST IR 8547)
#   https://spdx.github.io/spdx-spec/v3.0.1/  (SPDX 3.0.1)

# Implementation platform mapping for CycloneDX algorithmProperties.
# CycloneDX enumerates a fixed set of `implementationPlatform` values;
# anything outside the set must collapse to `other` or `unknown`.
_CBOM_PLATFORM: dict[str, str] = {
    "x86_64": "x86_64",
    "amd64": "x86_64",
    "i386": "x86_32",
    "i686": "x86_32",
    "aarch64": "armv8-a",
    "arm64": "armv8-a",
    "armv7l": "armv7-a",
    "s390x": "s390x",
    "ppc64": "ppc64",
    "ppc64le": "ppc64le",
}


def _cbom_platform(arch: str) -> str:
    return _CBOM_PLATFORM.get(arch.lower(), "unknown")


# NIST PQC parameter sets — security category lookup.  Categories follow
# the NIST PQC evaluation criteria (1=AES128-equivalent, 3=AES192-equiv,
# 5=AES256-equiv); SLH-DSA `s` and `f` variants share the category of the
# underlying parameter set.  Source: FIPS 203 / 204 / 205.
_PQC_NIST_CATEGORY: dict[str, int] = {
    "ML-KEM-512": 1,
    "ML-KEM-768": 3,
    "ML-KEM-1024": 5,
    "ML-DSA-44": 2,
    "ML-DSA-65": 3,
    "ML-DSA-87": 5,
    "SLH-DSA-SHA2-128s": 1,
    "SLH-DSA-SHA2-128f": 1,
    "SLH-DSA-SHA2-192s": 3,
    "SLH-DSA-SHA2-192f": 3,
    "SLH-DSA-SHA2-256s": 5,
    "SLH-DSA-SHA2-256f": 5,
    "SLH-DSA-SHAKE-128s": 1,
    "SLH-DSA-SHAKE-128f": 1,
    "SLH-DSA-SHAKE-192s": 3,
    "SLH-DSA-SHAKE-192f": 3,
    "SLH-DSA-SHAKE-256s": 5,
    "SLH-DSA-SHAKE-256f": 5,
}


def _pqc_parameter_set(name: str) -> str:
    """Extract the parameter-set identifier from a NIST PQC algorithm name.
    For ML-KEM-768 → '768'; for SLH-DSA-SHA2-128s → 'SHA2-128s'."""
    for prefix in ("ML-KEM-", "ML-DSA-"):
        if name.startswith(prefix):
            return name[len(prefix) :]
    if name.startswith("SLH-DSA-"):
        return name[len("SLH-DSA-") :]
    return name


@dataclass(frozen=True)
class CryptoAsset:
    """Canonical cryptographic asset detected on the host.

    Both --cbom (CycloneDX 1.6 cryptographic-asset components) and
    --spdx (SPDX 3.0 software_Package elements) project from this list,
    so each detection rule appears in exactly one place.

    The `category` is the detection-source bucket (e.g. "openssl_kem",
    "ssh_kex_hybrid") — used to label per-format properties so consumers
    can correlate findings across CBOM and SPDX outputs.

    `asset_type` matches the CycloneDX 1.6 cryptographic-asset enum:
    "algorithm" | "protocol" | "related-crypto-material".  Renderers
    omit fields whose values are empty / None."""

    key: str
    name: str
    category: str
    asset_type: str
    primitive: str = ""
    execution_environment: str = ""
    implementation_platform: str = ""
    protocol_type: str = ""
    related_material_type: str = ""
    parameter_set: str = ""
    nist_category: int | None = None
    source: str = ""
    properties: tuple[tuple[str, str], ...] = ()


def _pqc_algorithm_asset(
    key: str,
    name: str,
    category: str,
    primitive: str,
    source: str,
) -> CryptoAsset:
    """A NIST PQC algorithm exposed by a library.  Carries a derived
    parameterSetIdentifier and nistQuantumSecurityLevel where the
    algorithm name is in the published FIPS lookup."""
    pset = _pqc_parameter_set(name)
    return CryptoAsset(
        key=key,
        name=name,
        category=category,
        asset_type="algorithm",
        primitive=primitive,
        execution_environment="software-plain-ram",
        parameter_set=pset if pset != name else "",
        nist_category=_PQC_NIST_CATEGORY.get(name),
        source=source,
    )


def _canonical_isa_assets(r: Report) -> list[CryptoAsset]:
    """Each detected ISA feature is a hardware-execution algorithm asset.
    Primitive is `other` because an ISA feature accelerates many primitives
    (Keccak, lattice mul, AES round) rather than implementing one — the
    human-readable purpose lives in the `purpose` property."""
    platform_id = _cbom_platform(r.arch)
    out: list[CryptoAsset] = []
    for flag, info in sorted(r.isa_features.items()):
        out.append(
            CryptoAsset(
                key=f"isa/{flag}",
                name=info.get("name", flag),
                category="isa",
                asset_type="algorithm",
                primitive="other",
                execution_environment="hardware",
                implementation_platform=platform_id,
                properties=(
                    ("isa:flag", flag),
                    ("isa:purpose", info.get("purpose", "")),
                ),
            )
        )
    return out


def _canonical_accelerator_assets(r: Report) -> list[CryptoAsset]:
    """HSMs, TPMs, accelerators, DPUs and network HSMs each become a
    hardware-execution algorithm asset.  The detection layer already
    classifies kind/name/detail/pqc_capable; we surface those verbatim
    in extra properties so consumers can filter on them."""
    platform_id = _cbom_platform(r.arch)
    out: list[CryptoAsset] = []
    for idx, a in enumerate(r.accelerators):
        kind = a.get("kind", "accelerator")
        name = a.get("name", "")
        props: list[tuple[str, str]] = [("accelerator:kind", str(kind))]
        detail = a.get("detail")
        if detail:
            props.append(("accelerator:detail", str(detail)))
        if a.get("pqc_capable"):
            props.append(("accelerator:pqc_capable", "true"))
        out.append(
            CryptoAsset(
                key=f"accel/{idx}/{kind}",
                name=name or kind,
                category="accelerator",
                asset_type="algorithm",
                primitive="other",
                execution_environment="hardware",
                implementation_platform=platform_id,
                properties=tuple(props),
            )
        )
    return out


def _canonical_tpm_assets(r: Report) -> list[CryptoAsset]:
    tpm = r.tpm_pqc or {}
    if not tpm.get("present"):
        return []
    return [
        CryptoAsset(
            key="tpm/pqc",
            name="TPM PQC capability",
            category="tpm",
            asset_type="algorithm",
            primitive="other",
            execution_environment="hardware",
            implementation_platform=_cbom_platform(r.arch),
            properties=(
                (
                    "tpm:pqc_advertised",
                    "true" if tpm.get("pqc_advertised") else "false",
                ),
                ("tpm:note", str(tpm.get("note", ""))),
            ),
        )
    ]


def _canonical_pkcs11_assets(r: Report) -> list[CryptoAsset]:
    """PKCS#11 is a cryptographic-token API; each loadable module is
    emitted as a protocol asset with the module path captured in a
    property so an aggregator can deduplicate identical modules across
    a fleet."""
    out: list[CryptoAsset] = []
    for idx, mod in enumerate(r.pkcs11_modules or []):
        out.append(
            CryptoAsset(
                key=f"pkcs11/{idx}",
                name=Path(mod).name or f"pkcs11-module-{idx}",
                category="pkcs11",
                asset_type="protocol",
                protocol_type="other",
                properties=(("pkcs11:module_path", mod),),
            )
        )
    return out


def _canonical_openssl_assets(r: Report) -> list[CryptoAsset]:
    osinfo = r.openssl or {}
    if not osinfo.get("available"):
        return []
    out: list[CryptoAsset] = []
    version = osinfo.get("version") or "unknown"
    src = f"openssl@{version}"
    for kem in osinfo.get("kem_algorithms") or []:
        out.append(
            _pqc_algorithm_asset(
                f"openssl/kem/{kem}",
                kem,
                "openssl_kem",
                "kem",
                src,
            )
        )
    for sig in osinfo.get("sig_algorithms") or []:
        out.append(
            _pqc_algorithm_asset(
                f"openssl/sig/{sig}",
                sig,
                "openssl_sig",
                "signature",
                src,
            )
        )
    tls_groups = osinfo.get("tls_groups") or {}
    for grp in tls_groups.get("hybrid") or []:
        out.append(
            CryptoAsset(
                key=f"openssl/tls-hybrid/{grp}",
                name=grp,
                category="openssl_tls_hybrid",
                asset_type="algorithm",
                primitive="combiner",
                execution_environment="software-plain-ram",
                source=src,
                properties=(("tls:role", "hybrid-group"),),
            )
        )
    for grp in tls_groups.get("pure_pqc") or []:
        out.append(
            CryptoAsset(
                key=f"openssl/tls-pure-pqc/{grp}",
                name=grp,
                category="openssl_tls_pqc",
                asset_type="algorithm",
                primitive="kem",
                execution_environment="software-plain-ram",
                source=src,
                properties=(("tls:role", "pure-pqc-group"),),
            )
        )
    return out


def _canonical_ssh_assets(r: Report) -> list[CryptoAsset]:
    """SSH KEX algorithms surface as key-agreement assets.  We only emit
    the PQC subset detected by `ssh -Q kex` — the classical kex set is
    out of scope for a PQC inventory."""
    ssh_info = r.ssh_pqc or {}
    if not ssh_info.get("available"):
        return []
    out: list[CryptoAsset] = []
    version = ssh_info.get("version") or "unknown"
    src = f"openssh@{version}"
    kex_groups = ssh_info.get("kex_groups") or {}
    for kex in kex_groups.get("hybrid") or []:
        out.append(
            CryptoAsset(
                key=f"ssh/kex/hybrid/{kex}",
                name=kex,
                category="ssh_kex_hybrid",
                asset_type="algorithm",
                primitive="key-agree",
                execution_environment="software-plain-ram",
                source=src,
                properties=(("ssh:role", "hybrid-kex"),),
            )
        )
    for kex in kex_groups.get("pure_pqc") or []:
        out.append(
            CryptoAsset(
                key=f"ssh/kex/pure-pqc/{kex}",
                name=kex,
                category="ssh_kex_pqc",
                asset_type="algorithm",
                primitive="kem",
                execution_environment="software-plain-ram",
                source=src,
                properties=(("ssh:role", "pure-pqc-kex"),),
            )
        )
    return out


def _canonical_ipsec_assets(r: Report) -> list[CryptoAsset]:
    """IPsec stacks expose PQC support as a single boolean today; emit
    one protocol asset describing the implementation found and whether
    it advertises any PQC KE.  When a future strongSwan release ships
    per-algorithm PQC names, this can split into algorithm assets."""
    ipsec = r.ipsec_pqc or {}
    if not ipsec.get("available"):
        return []
    impl = str(ipsec.get("implementation") or "ipsec")
    props: list[tuple[str, str]] = [("ipsec:implementation", impl)]
    if ipsec.get("evidence"):
        props.append(("ipsec:evidence", str(ipsec["evidence"])))
    if ipsec.get("version"):
        props.append(("ipsec:version", str(ipsec["version"])))
    props.append(
        (
            "ipsec:pqc_advertised",
            "true" if ipsec.get("pqc") else "false",
        )
    )
    return [
        CryptoAsset(
            key=f"ipsec/{impl}",
            name=f"IPsec ({impl})",
            category="ipsec",
            asset_type="protocol",
            protocol_type="ipsec",
            properties=tuple(props),
        )
    ]


def _canonical_trust_store_assets(r: Report) -> list[CryptoAsset]:
    """Trust-store scan is summary-only (counts by category) — there is
    no per-cert detail in the Report, so we emit a single related-crypto-
    material asset whose properties carry the totals.  When a richer
    per-cert scan ships, this can fan out to one certificate asset per
    file."""
    ts = r.trust_store or {}
    if not ts.get("available"):
        return []
    props: list[tuple[str, str]] = [
        ("trust_store:total_certs", str(ts.get("total_certs", 0))),
        ("trust_store:pqc_certs", str(ts.get("pqc_certs", 0))),
        ("trust_store:hybrid_certs", str(ts.get("hybrid_certs", 0))),
    ]
    cats = ts.get("cert_categories") or {}
    for cat in ("classical", "hybrid_composite", "pure_pqc"):
        props.append(
            (
                f"trust_store:cert_categories:{cat}",
                str(cats.get(cat, 0)),
            )
        )
    for d in ts.get("scanned_dirs") or []:
        props.append(("trust_store:scanned_dir", d))
    return [
        CryptoAsset(
            key="trust-store/summary",
            name="Trust store certificate inventory",
            category="trust_store",
            asset_type="related-crypto-material",
            related_material_type="other",
            properties=tuple(props),
        )
    ]


def canonical_assets(r: Report) -> list[CryptoAsset]:
    """Walk the Report and return the canonical CryptoAsset list.

    Order is deterministic so that downstream diffs across runs on the
    same host stay stable: ISA → accelerators → TPM → PKCS#11 →
    OpenSSL → SSH → IPsec → trust-store summary."""
    out: list[CryptoAsset] = []
    out.extend(_canonical_isa_assets(r))
    out.extend(_canonical_accelerator_assets(r))
    out.extend(_canonical_tpm_assets(r))
    out.extend(_canonical_pkcs11_assets(r))
    out.extend(_canonical_openssl_assets(r))
    out.extend(_canonical_ssh_assets(r))
    out.extend(_canonical_ipsec_assets(r))
    out.extend(_canonical_trust_store_assets(r))
    return out


# CycloneDX 1.6 CBOM rendering ----------------------------------------------
#
# A CBOM (Cryptographic Bill of Materials) is a CycloneDX BOM whose
# `components` are populated with `cryptographic-asset` entries.  NIST IR
# 8547 references CycloneDX 1.6 as the standard for cryptographic inventory
# exchange, so emitting this shape lets downstream PQC-migration tooling
# ingest pqc-readiness output without writing a bespoke translator.

# Provenance tag stamped onto every emitted CBOM asset so downstream
# aggregators can tell which tool detected the entry.
def _cbom_provenance() -> list[dict[str, str]]:
    return [{"name": "detectedBy", "value": f"pqc-readiness@{SCRIPT_VERSION}"}]


def _cbom_crypto_properties(asset: CryptoAsset) -> dict[str, Any]:
    """Project a canonical asset's crypto properties into the CycloneDX
    1.6 cryptographic-asset shape."""
    if asset.asset_type == "algorithm":
        algo: dict[str, Any] = {"primitive": asset.primitive or "other"}
        if asset.execution_environment:
            algo["executionEnvironment"] = asset.execution_environment
        if asset.implementation_platform:
            algo["implementationPlatform"] = asset.implementation_platform
        if asset.parameter_set:
            algo["parameterSetIdentifier"] = asset.parameter_set
        if asset.nist_category is not None:
            algo["nistQuantumSecurityLevel"] = asset.nist_category
        return {"assetType": "algorithm", "algorithmProperties": algo}
    if asset.asset_type == "protocol":
        return {
            "assetType": "protocol",
            "protocolProperties": {"type": asset.protocol_type or "other"},
        }
    if asset.asset_type == "related-crypto-material":
        return {
            "assetType": "related-crypto-material",
            "relatedCryptoMaterialProperties": {
                "type": asset.related_material_type or "other"
            },
        }
    raise ValueError(f"unsupported CryptoAsset.asset_type: {asset.asset_type!r}")


def _cbom_component(asset: CryptoAsset) -> dict[str, Any]:
    """Project a canonical asset into a CycloneDX 1.6 cryptographic-asset
    component.  Every emitted asset carries the `detectedBy` provenance
    tag plus any free-form (k, v) properties from the canonical record."""
    props = _cbom_provenance()
    if asset.source:
        props.append({"name": "source", "value": asset.source})
    for k, v in asset.properties:
        props.append({"name": k, "value": v})
    return {
        "type": "cryptographic-asset",
        "bom-ref": asset.key,
        "name": asset.name,
        "cryptoProperties": _cbom_crypto_properties(asset),
        "properties": props,
    }


def render_cbom(r: Report) -> str:
    """Render the report as a CycloneDX 1.6 CBOM (JSON).  The output is
    schema-conformant — see tests/test_cbom.py for the schema check."""
    components = [_cbom_component(a) for a in canonical_assets(r)]

    timestamp = r.generated_at or datetime.now(timezone.utc).isoformat(
        timespec="seconds"
    )
    # CycloneDX metadata.timestamp must be RFC 3339 / ISO-8601 with a
    # timezone designator.  Report.generated_at already has +00:00; if a
    # caller stamped a naive value we leave it alone — the schema accepts
    # bare date-time but downstream consumers should treat it as UTC.
    host_bom_ref = f"host/{r.hostname or 'unknown'}"
    host_props: list[dict[str, str]] = []
    if r.os:
        host_props.append({"name": "host:os", "value": r.os})
    if r.arch:
        host_props.append({"name": "host:arch", "value": r.arch})
    if r.cpu_model:
        host_props.append({"name": "host:cpu_model", "value": r.cpu_model})
    host_component: dict[str, Any] = {
        "type": "device",
        "bom-ref": host_bom_ref,
        "name": r.hostname or "unknown-host",
    }
    if host_props:
        host_component["properties"] = host_props

    bom: dict[str, Any] = {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "bom-ref": f"tool/pqc-readiness@{SCRIPT_VERSION}",
                        "name": "pqc-readiness",
                        "version": SCRIPT_VERSION,
                    }
                ],
            },
            "component": host_component,
        },
        "components": components,
    }
    return json.dumps(bom, indent=2)


# ---------------------------------------------------------------------------
# SARIF 2.1.0 finding output (--sarif)
# ---------------------------------------------------------------------------
# SARIF (Static Analysis Results Interchange Format, OASIS) is the standard
# exchange format for code-scanning and security tooling.  Emitting SARIF
# lets readiness output drop into existing security pipelines (CodeQL,
# GitHub code scanning, IDE integrations) without per-tool adapters.
#
# This is host-level analysis, not file-level — every result attaches the
# scanned host's identity (hostname, OS, arch, the values that triggered
# the rule) under `result.properties` rather than file locations.  Per
# SARIF 2.1.0 the only required result field is `message`; `locations` is
# recommended but optional.
#
# Adding a new rule means appending one entry to RULE_SPECS plus a small
# predicate in build_findings().

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_HELP_BASE = "https://github.com/aclater/pqc-readiness/blob/main/docs/rules"


@dataclass(frozen=True)
class RuleSpec:
    """Static metadata for one SARIF rule.

    `default_level` is the SARIF severity enum value: one of
    ``error``, ``warning``, ``note``."""

    id: str
    short_description: str
    full_description: str
    default_level: str
    help_uri: str


@dataclass(frozen=True)
class Finding:
    """One detected condition projected from Report state.

    `properties` carries host-level context — the specific values that
    triggered the rule — since SARIF results have no file location for
    host-scope analysis."""

    rule_id: str
    level: str
    message: str
    properties: dict[str, Any]


RULE_SPECS: tuple[RuleSpec, ...] = (
    RuleSpec(
        id="pqc-001-openssl-pre-3.5",
        short_description="OpenSSL is older than 3.5 (no native PQC).",
        full_description=(
            "The host's OpenSSL is older than 3.5.0, which is the first "
            "release with native ML-KEM and ML-DSA support.  Pre-3.5 "
            "OpenSSL cannot expose PQC algorithms or hybrid TLS groups "
            "to applications without a third-party provider."
        ),
        default_level="warning",
        help_uri=f"{SARIF_HELP_BASE}/pqc-001-openssl-pre-3.5.md",
    ),
    RuleSpec(
        id="pqc-002-fips-pqc-conflict",
        short_description=(
            "Kernel FIPS mode active but PQC exposed via non-FIPS provider."
        ),
        full_description=(
            "Kernel FIPS mode is enabled and OpenSSL is exposing PQC "
            "algorithms, but the FIPS provider does not yet include "
            "ML-KEM or ML-DSA.  The algorithms appear listed yet would "
            "not be usable in a FIPS-validated workflow."
        ),
        default_level="error",
        help_uri=f"{SARIF_HELP_BASE}/pqc-002-fips-pqc-conflict.md",
    ),
    RuleSpec(
        id="pqc-003-no-pqc-isa-support",
        short_description=(
            "ISA tier is poor and no PQC accelerator is present."
        ),
        full_description=(
            "The host's ISA feature score is below the threshold for "
            "software PQC, and no PQC-capable accelerator (HSM, network "
            "HSM, or dedicated silicon) was detected.  The host cannot "
            "be made PQC-ready in software alone."
        ),
        default_level="warning",
        help_uri=f"{SARIF_HELP_BASE}/pqc-003-no-pqc-isa-support.md",
    ),
    RuleSpec(
        id="pqc-004-classical-only-trust-store",
        short_description=(
            "Trust store contains zero PQC and zero hybrid certificates."
        ),
        full_description=(
            "The system trust store was scanned and every certificate "
            "uses classical signature algorithms.  Trust-store rotation "
            "to PQC roots will be required before pure-PQC chains "
            "validate against this host."
        ),
        default_level="note",
        help_uri=f"{SARIF_HELP_BASE}/pqc-004-classical-only-trust-store.md",
    ),
    RuleSpec(
        id="pqc-005-slh-dsa-in-tls-context",
        short_description=(
            "SLH-DSA exposed for TLS use; signatures are large for handshakes."
        ),
        full_description=(
            "OpenSSL is exposing SLH-DSA (SPHINCS+) signature "
            "algorithms.  SLH-DSA signatures are an order of magnitude "
            "larger than ML-DSA and substantially slow TLS handshakes; "
            "ML-DSA is the recommended TLS signature primitive in NIST "
            "PQC migration guidance."
        ),
        default_level="warning",
        help_uri=f"{SARIF_HELP_BASE}/pqc-005-slh-dsa-in-tls-context.md",
    ),
    RuleSpec(
        id="pqc-006-no-network-hsm-pqc-firmware",
        short_description=(
            "Network HSM client present but appliance is not PQC-capable."
        ),
        full_description=(
            "A network-attached HSM client integration is installed "
            "on the host, but the appliance has not been flagged as "
            "PQC-capable.  Confirm the appliance firmware version "
            "supports ML-KEM / ML-DSA before depending on the HSM "
            "for PQC operations."
        ),
        default_level="warning",
        help_uri=f"{SARIF_HELP_BASE}/pqc-006-no-network-hsm-pqc-firmware.md",
    ),
)


def _sarif_host_properties(r: Report) -> dict[str, Any]:
    """Run-level host-context property bag.

    SARIF 2.1.0 lets us attach an arbitrary `properties` bag at the
    `run` level so consumers (Splunk dashboards, custom scripts) can
    correlate findings to a specific host without scraping `message`."""
    return {
        "host:hostname": r.hostname,
        "host:os": r.os,
        "host:arch": r.arch,
        "tool:schema_version": r.schema_version,
        "tool:version": SCRIPT_VERSION,
        "report:generated_at": r.generated_at,
    }


def build_findings(r: Report) -> list[Finding]:
    """Project a Report into typed Finding records.

    Each rule is a small predicate over Report state.  Order is
    deterministic — RULE_SPECS order is preserved so SARIF result
    indexing is stable across runs on the same host."""
    findings: list[Finding] = []

    osinfo = r.openssl
    if osinfo.get("available") and not osinfo.get("pqc_native", False):
        findings.append(
            Finding(
                rule_id="pqc-001-openssl-pre-3.5",
                level="warning",
                message=(
                    f"OpenSSL {osinfo.get('version', 'unknown')} is older "
                    "than 3.5.0 — native ML-KEM / ML-DSA are not available."
                ),
                properties={
                    "openssl:version": osinfo.get("version"),
                    "openssl:upgrade_path": osinfo.get("upgrade_path"),
                },
            )
        )

    fc = r.fips_pqc_conflict
    if fc.get("in_conflict"):
        findings.append(
            Finding(
                rule_id="pqc-002-fips-pqc-conflict",
                level="error",
                message=str(
                    fc.get("explanation") or "FIPS / PQC provider conflict."
                ),
                properties={
                    "fips:kernel": r.fips.get("kernel"),
                    "fips:openssl_provider": r.fips.get("openssl_provider"),
                    "openssl:kem_algorithms": list(
                        osinfo.get("kem_algorithms") or []
                    ),
                    "openssl:sig_algorithms": list(
                        osinfo.get("sig_algorithms") or []
                    ),
                },
            )
        )

    if r.replace_required:
        findings.append(
            Finding(
                rule_id="pqc-003-no-pqc-isa-support",
                level="warning",
                message=(
                    f"ISA tier '{r.isa_tier}' and no PQC-capable accelerator "
                    "detected; software-only PQC is not viable on this host."
                ),
                properties={
                    "isa:tier": r.isa_tier,
                    "isa:score": r.isa_score,
                    "isa:reason": r.isa_reason,
                },
            )
        )

    ts = r.trust_store
    if (
        ts.get("available")
        and ts.get("total_certs", 0) > 0
        and ts.get("pqc_certs", 0) == 0
        and ts.get("hybrid_certs", 0) == 0
    ):
        findings.append(
            Finding(
                rule_id="pqc-004-classical-only-trust-store",
                level="note",
                message=(
                    f"Scanned {ts.get('total_certs', 0)} certificates across "
                    f"{len(ts.get('scanned_dirs') or [])} trust-store "
                    "directories; every cert uses classical signatures."
                ),
                properties={
                    "trust_store:total_certs": ts.get("total_certs"),
                    "trust_store:pqc_certs": ts.get("pqc_certs"),
                    "trust_store:hybrid_certs": ts.get("hybrid_certs"),
                    "trust_store:scanned_dirs": list(
                        ts.get("scanned_dirs") or []
                    ),
                },
            )
        )

    sigs = list(osinfo.get("sig_algorithms") or [])
    slh_dsa = sorted(
        s for s in sigs if isinstance(s, str) and s.startswith("SLH-DSA")
    )
    if slh_dsa:
        findings.append(
            Finding(
                rule_id="pqc-005-slh-dsa-in-tls-context",
                level="warning",
                message=(
                    "OpenSSL exposes SLH-DSA signature algorithms "
                    f"({', '.join(slh_dsa)}); prefer ML-DSA for TLS handshakes."
                ),
                properties={"openssl:slh_dsa_algorithms": slh_dsa},
            )
        )

    network_hsms_no_pqc = [
        a
        for a in r.accelerators
        if a.get("kind") == "network_hsm" and not a.get("pqc_capable")
    ]
    if network_hsms_no_pqc:
        names = sorted(
            {str(a.get("name") or "unknown") for a in network_hsms_no_pqc}
        )
        findings.append(
            Finding(
                rule_id="pqc-006-no-network-hsm-pqc-firmware",
                level="warning",
                message=(
                    f"Network HSM client present ({', '.join(names)}) but "
                    "the appliance is not flagged as PQC-capable.  Verify "
                    "appliance firmware before relying on it for PQC."
                ),
                properties={"hsm:network_hsm_names": names},
            )
        )

    return findings


def _sarif_rule_descriptor(spec: RuleSpec) -> dict[str, Any]:
    return {
        "id": spec.id,
        "name": spec.id,
        "shortDescription": {"text": spec.short_description},
        "fullDescription": {"text": spec.full_description},
        "helpUri": spec.help_uri,
        "defaultConfiguration": {"level": spec.default_level},
    }


def _sarif_result(finding: Finding, rule_index: int) -> dict[str, Any]:
    return {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index,
        "level": finding.level,
        "message": {"text": finding.message},
        "properties": finding.properties,
    }


def render_sarif(r: Report) -> str:
    """Render the report as a SARIF 2.1.0 log document.

    Every rule from RULE_SPECS is emitted in the run's tool-driver
    descriptor — tooling can render rule metadata even when no result
    references the rule.  Only matched rules become results."""
    rules = [_sarif_rule_descriptor(s) for s in RULE_SPECS]
    rule_index_by_id = {s.id: i for i, s in enumerate(RULE_SPECS)}
    findings = build_findings(r)
    results = [
        _sarif_result(f, rule_index_by_id[f.rule_id])
        for f in findings
        if f.rule_id in rule_index_by_id
    ]
    log: dict[str, Any] = {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "pqc-readiness",
                        "version": SCRIPT_VERSION,
                        "informationUri": (
                            "https://github.com/aclater/pqc-readiness"
                        ),
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": _sarif_host_properties(r),
            }
        ],
    }
    return json.dumps(log, indent=2)


# ---------------------------------------------------------------------------
# SPDX 3.0 JSON-LD output (--spdx)
# ---------------------------------------------------------------------------
# SPDX 3.0 added a Security profile that overlaps with CBOM use cases.
# Some procurement contexts (notably US federal) standardise on SPDX
# rather than CycloneDX, so emitting both broadens compatibility without
# forcing customers to convert formats.
#
# Same source data as --cbom — both renderers project from the
# canonical_assets() pipeline above.  Findings (the same set of rule
# predicates that drive --sarif) are emitted here as
# security_Vulnerability elements with VEX "affects" relationships
# linking each finding to the host package.
#
# Validation: SPDX 3.0.1 does not publish a JSON Schema; the canonical
# validation surface is the OWL/SHACL ontology.  tests/test_spdx.py
# bundles the official JSON-LD context file and runs a structural
# validator that mirrors the spec's required-shape constraints
# (top-level @context + @graph, every Element carries creationInfo,
# every type/property is a known term in the SPDX 3.0.1 context).
#
# Refs:
#   https://spdx.github.io/spdx-spec/v3.0.1/  (SPDX 3.0.1 spec)
#   https://spdx.org/rdf/3.0.1/spdx-context.jsonld  (canonical context)

SPDX_VERSION = "3.0.1"
SPDX_CONTEXT_URL = "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"
SPDX_DATA_LICENSE = "https://spdx.org/licenses/CC0-1.0"

# URN namespace prefix for spdxIds emitted by this tool.  URNs are valid
# IRIs and avoid implying a resolvable HTTP endpoint.
SPDX_URN_PREFIX = "urn:pqc-readiness"


def _spdx_safe(s: str) -> str:
    """Sanitise a string for inclusion in a URN segment.  SPDX 3.0
    spdxIds are IRIs; we conservatively keep alphanumerics plus
    [.-_] and replace runs of anything else with a single dash."""
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", s).strip("-")
    return cleaned or "unknown"


def _spdx_software_purpose(asset: CryptoAsset) -> str:
    """Map a canonical asset onto the SPDX 3.0 SoftwarePurpose enum.

    The enum is fixed (see /Software/SoftwarePurpose) so we collapse
    crypto-asset categories to the closest enum entry: hardware-execution
    assets surface as `device`, software algorithms / protocols as
    `library`, and the trust-store summary as `data`."""
    if asset.execution_environment == "hardware":
        return "device"
    if asset.asset_type == "related-crypto-material":
        return "data"
    return "library"


def _spdx_creation_info(creator_id: str) -> dict[str, Any]:
    """SPDX 3.0 inlines CreationInfo on every Element.  Every element in
    a single document shares the same created-time + creator agent."""
    return {
        "type": "CreationInfo",
        "specVersion": SPDX_VERSION,
        "created": _CURRENT_RUN_TIME[0],
        "createdBy": [creator_id],
    }


# Module-level slot so _spdx_creation_info renders a stable timestamp
# across all elements in one document; render_spdx() updates it once.
_CURRENT_RUN_TIME: list[str] = ["1970-01-01T00:00:00Z"]


def _spdx_element_base(
    spdx_id: str,
    type_name: str,
    name: str,
    creator_id: str,
) -> dict[str, Any]:
    return {
        "type": type_name,
        "spdxId": spdx_id,
        "creationInfo": _spdx_creation_info(creator_id),
        "name": name,
    }


def _spdx_creator_agent(spdx_id: str) -> dict[str, Any]:
    """The pqc-readiness tool itself, modelled as a SoftwareAgent.

    SoftwareAgent is the SPDX 3.0 class for software acting on a system.
    The agent is its own creator (self-reference is permitted by the
    spec and is the standard bootstrap pattern) so the document does
    not require an external Agent registry."""
    return {
        "type": "SoftwareAgent",
        "spdxId": spdx_id,
        "creationInfo": _spdx_creation_info(spdx_id),
        "name": "pqc-readiness",
        "description": (
            "Open-source PQC readiness scanner — see "
            "https://github.com/aclater/pqc-readiness"
        ),
    }


def _spdx_host_package(
    spdx_id: str,
    creator_id: str,
    r: Report,
) -> dict[str, Any]:
    """The scanned host as a software_Package.

    The host is the package whose cryptographic inventory this document
    describes.  Findings (Vulnerability elements) attach to it via VEX
    relationships."""
    pkg = _spdx_element_base(
        spdx_id,
        "software_Package",
        r.hostname or "unknown-host",
        creator_id,
    )
    summary_bits: list[str] = []
    if r.os:
        summary_bits.append(r.os)
    if r.arch:
        summary_bits.append(r.arch)
    if summary_bits:
        pkg["summary"] = " / ".join(summary_bits)
    pkg["software_primaryPurpose"] = "platform"
    if r.cpu_model:
        pkg["description"] = f"CPU: {r.cpu_model}"
    return pkg


def _spdx_asset_package(
    asset: CryptoAsset,
    namespace: str,
    creator_id: str,
) -> dict[str, Any]:
    """Project a canonical CryptoAsset into an SPDX 3.0 software_Package.

    SPDX 3.0 doesn't ship a native cryptographic-asset element type, so
    we model each asset as a software_Package with `software_primaryPurpose`
    set per the asset's execution environment.  Crypto metadata that has
    no native SPDX field (primitive, parameter set, NIST category, source,
    free-form properties) goes into `description` as a stable, parseable
    `key=value` block — the same data CBOM emits as `properties`."""
    spdx_id = f"{namespace}:asset:{_spdx_safe(asset.key)}"
    elem = _spdx_element_base(
        spdx_id,
        "software_Package",
        asset.name,
        creator_id,
    )
    elem["summary"] = f"Cryptographic asset (category={asset.category})"
    elem["software_primaryPurpose"] = _spdx_software_purpose(asset)

    desc_lines: list[str] = [f"category={asset.category}"]
    desc_lines.append(f"assetType={asset.asset_type}")
    if asset.primitive:
        desc_lines.append(f"primitive={asset.primitive}")
    if asset.execution_environment:
        desc_lines.append(f"executionEnvironment={asset.execution_environment}")
    if asset.implementation_platform:
        desc_lines.append(f"implementationPlatform={asset.implementation_platform}")
    if asset.protocol_type:
        desc_lines.append(f"protocolType={asset.protocol_type}")
    if asset.related_material_type:
        desc_lines.append(f"relatedMaterialType={asset.related_material_type}")
    if asset.source:
        desc_lines.append(f"source={asset.source}")
    for k, v in asset.properties:
        desc_lines.append(f"{k}={v}")
    elem["description"] = "\n".join(desc_lines)

    if asset.parameter_set:
        elem["software_packageVersion"] = asset.parameter_set
    if asset.nist_category is not None:
        elem["externalIdentifier"] = [
            {
                "type": "ExternalIdentifier",
                "externalIdentifierType": "other",
                "identifier": f"nist-pqc-category-{asset.nist_category}",
            }
        ]
    return elem


# Help-URL base for security_Vulnerability elements emitted to SPDX —
# reuses the SARIF rule docs so each finding type has one canonical
# explanation page across formats.
SPDX_FINDING_HELP_BASE = SARIF_HELP_BASE
SPDX_FINDING_LEVEL_TO_NOTE = {
    "error": "severity: error",
    "warning": "severity: warning",
    "note": "severity: note",
}


def _spdx_vulnerability(
    finding: Finding,
    rule_spec: RuleSpec,
    namespace: str,
    creator_id: str,
    idx: int,
) -> dict[str, Any]:
    """Each Finding becomes a security_Vulnerability whose summary is
    the rule's short description and whose full description is the
    rule body plus the rule-fired message.

    Keeping the SARIF rule_id as the externalIdentifier lets tooling
    correlate the same finding across SARIF and SPDX outputs."""
    spdx_id = f"{namespace}:finding:{idx:04d}:{_spdx_safe(rule_spec.id)}"
    elem = _spdx_element_base(
        spdx_id,
        "security_Vulnerability",
        rule_spec.id,
        creator_id,
    )
    elem["summary"] = rule_spec.short_description
    elem["description"] = (
        f"{rule_spec.full_description}\n\nDetected: {finding.message}"
    )
    elem["comment"] = SPDX_FINDING_LEVEL_TO_NOTE.get(
        finding.level, f"severity: {finding.level}"
    )
    elem["security_publishedTime"] = _CURRENT_RUN_TIME[0]
    elem["externalIdentifier"] = [
        {
            "type": "ExternalIdentifier",
            "externalIdentifierType": "other",
            "identifier": rule_spec.id,
        }
    ]
    elem["externalRef"] = [
        {
            "type": "ExternalRef",
            "externalRefType": "securityAdvisory",
            "locator": [rule_spec.help_uri],
        }
    ]
    return elem


def _spdx_vex_affects(
    vuln_id: str,
    target_id: str,
    namespace: str,
    creator_id: str,
    idx: int,
    action_statement: str,
) -> dict[str, Any]:
    """Link a security_Vulnerability to the host package via a VEX
    `affects` relationship.

    VexAffectedVulnAssessmentRelationship is the SPDX 3.0 way to declare
    "vulnerability V affects element E" — in this document E is always
    the scanned host package."""
    return {
        "type": "security_VexAffectedVulnAssessmentRelationship",
        "spdxId": f"{namespace}:vex:{idx:04d}",
        "creationInfo": _spdx_creation_info(creator_id),
        "relationshipType": "affects",
        "from": vuln_id,
        "to": [target_id],
        "security_assessedElement": target_id,
        "security_actionStatement": action_statement,
        "security_publishedTime": _CURRENT_RUN_TIME[0],
    }


def render_spdx(r: Report) -> str:
    """Render the report as an SPDX 3.0 JSON-LD document.

    The document profileConformance includes core, software, and
    security: cryptographic assets are software_Package elements and
    findings are security_Vulnerability elements with VEX `affects`
    relationships to the scanned host."""
    timestamp = r.generated_at or datetime.now(timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    # The official spec wants an `xsd:dateTimeStamp`; that means a
    # mandatory timezone designator.  Report.generated_at carries
    # +00:00; SPDX examples use the trailing-Z form.  We accept either.
    _CURRENT_RUN_TIME[0] = timestamp

    host_safe = _spdx_safe(r.hostname or "unknown-host")
    namespace = f"{SPDX_URN_PREFIX}:{host_safe}"
    creator_id = f"{SPDX_URN_PREFIX}:tool:{_spdx_safe(SCRIPT_VERSION)}"
    host_id = f"{namespace}:host"
    sbom_id = f"{namespace}:sbom"
    doc_id = f"{namespace}:document:{uuid.uuid4()}"

    creator = _spdx_creator_agent(creator_id)
    host_pkg = _spdx_host_package(host_id, creator_id, r)
    asset_pkgs = [
        _spdx_asset_package(a, namespace, creator_id) for a in canonical_assets(r)
    ]

    findings = build_findings(r)
    rule_specs_by_id = {s.id: s for s in RULE_SPECS}
    vulns: list[dict[str, Any]] = []
    vex_rels: list[dict[str, Any]] = []
    for idx, f in enumerate(findings):
        spec = rule_specs_by_id.get(f.rule_id)
        if spec is None:
            continue
        vuln = _spdx_vulnerability(f, spec, namespace, creator_id, idx)
        vulns.append(vuln)
        vex_rels.append(
            _spdx_vex_affects(
                vuln["spdxId"],
                host_id,
                namespace,
                creator_id,
                idx,
                action_statement=f.message,
            )
        )

    member_ids: list[str] = (
        [host_id]
        + [pkg["spdxId"] for pkg in asset_pkgs]
        + [v["spdxId"] for v in vulns]
        + [rel["spdxId"] for rel in vex_rels]
    )

    sbom: dict[str, Any] = {
        "type": "software_Sbom",
        "spdxId": sbom_id,
        "creationInfo": _spdx_creation_info(creator_id),
        "name": f"pqc-readiness inventory for {r.hostname or 'unknown-host'}",
        "profileConformance": ["core", "software", "security"],
        "rootElement": [host_id],
        "element": member_ids,
        "software_sbomType": ["analyzed"],
    }

    document: dict[str, Any] = {
        "type": "SpdxDocument",
        "spdxId": doc_id,
        "creationInfo": _spdx_creation_info(creator_id),
        "name": f"pqc-readiness {SCRIPT_VERSION} report",
        "profileConformance": ["core", "software", "security"],
        "dataLicense": SPDX_DATA_LICENSE,
        "rootElement": [sbom_id],
        "element": [sbom_id, *member_ids, creator_id],
    }

    graph: list[dict[str, Any]] = [
        creator,
        document,
        sbom,
        host_pkg,
        *asset_pkgs,
        *vulns,
        *vex_rels,
    ]

    out = {"@context": SPDX_CONTEXT_URL, "@graph": graph}
    return json.dumps(out, indent=2)


def render_text(r: Report) -> str:
    L: list[str] = []
    bar = "=" * 76
    sub = "-" * 76
    L.append(C.wrap(C.BOLD, bar))
    L.append(C.wrap(C.BOLD, "  Post-Quantum Cryptography Readiness Report"))
    L.append(C.wrap(C.BOLD, bar))
    L.append(f"  Host:          {r.hostname}  ({r.os}, {r.arch})")
    L.append(f"  CPU:           {r.cpu_model}")
    if r.cpu_freq_mhz:
        L.append(f"  Max freq:      {r.cpu_freq_mhz / 1000:.2f} GHz")
    L.append(
        f"  Cores:         {r.cores_physical} physical / {r.cores_logical} logical"
    )
    L.append(
        f"  Memory:        {r.mem_total_gb:.1f} GiB total / {r.mem_avail_gb:.1f} GiB available"
    )
    if r.memory_bandwidth_gb_s is not None:
        L.append(
            f"  Mem bandwidth: ~{r.memory_bandwidth_gb_s} GB/s ({r.memory_bandwidth_method})"
        )
    elif r.memory_bandwidth_method:
        L.append(f"  Mem bandwidth: {r.memory_bandwidth_method}")
    L.append(f"  Generated:     {r.generated_at}")
    L.append("")

    L.append(C.wrap(C.BOLD, "1. CPU instruction-set support for PQC"))
    L.append(f"   Tier: {_tier_label(r.isa_tier)}  (score {r.isa_score})")
    L.append(f"   {r.isa_reason}")
    if r.isa_features:
        for _, info in sorted(r.isa_features.items()):
            L.append(f"     + {info['name']:<22} {info['purpose']}")
    else:
        L.append("     (no PQC-relevant ISA features detected)")
    L.append("")

    L.append(C.wrap(C.BOLD, "2. Cryptographic accelerators / HSMs / TPMs"))
    if r.accelerators:
        for a in r.accelerators:
            pqc_mark = " [PQC-capable]" if a.get("pqc_capable") else ""
            L.append(f"     [{a['kind']:>11}] {a['name']}{pqc_mark}  ({a['detail']})")
    else:
        L.append("     none detected - host would do all PQC in CPU/memory")
    if r.hsm_present_but_not_pqc:
        L.append(
            C.wrap(
                C.YELLOW,
                "     NOTE: HSM(s) detected but none currently confirmed PQC-capable.",
            )
        )
        L.append(
            "           Verify firmware version against vendor's PQC release notes."
        )
    if r.tpm_pqc.get("present"):
        marker = "yes" if r.tpm_pqc.get("pqc_advertised") else "no"
        L.append(
            f"     TPM PQC algorithms advertised: {marker}  ({r.tpm_pqc.get('note', '')})"
        )
    if r.pkcs11_modules:
        L.append(f"     PKCS#11 modules installed: {len(r.pkcs11_modules)}")
        for p in r.pkcs11_modules[:5]:
            L.append(f"       - {p}")
        if len(r.pkcs11_modules) > 5:
            L.append(f"       ... and {len(r.pkcs11_modules) - 5} more")
    L.append("")

    L.append(C.wrap(C.BOLD, "3. Operating-system crypto plumbing"))
    if r.kernel_info:
        rh = r.kernel_info.get("redhat_release") or {}
        if rh.get("raw"):
            L.append(f"   Distribution:  {rh.get('raw')}")
        L.append(f"   Kernel:        {r.kernel_info.get('release', '?')}")
        pqc_drivers = r.kernel_info.get("proc_crypto_pqc") or []
        if pqc_drivers:
            L.append(f"   /proc/crypto PQC drivers: {', '.join(pqc_drivers)}")
        else:
            L.append(
                "   /proc/crypto PQC drivers: none (kernel-side PQC not in mainline)"
            )
    if r.kernel_crypto_hw:
        L.append(f"   /proc/crypto hw-accel: {len(r.kernel_crypto_hw)} drivers")
        for d in r.kernel_crypto_hw[:6]:
            L.append(f"     - {d}")
        if len(r.kernel_crypto_hw) > 6:
            L.append(f"     ... and {len(r.kernel_crypto_hw) - 6} more")
    if r.ktls_supported is not None:
        L.append(f"   Kernel TLS:    {'yes' if r.ktls_supported else 'no'}")
    if r.fips:
        L.append(
            f"   FIPS mode:     kernel={r.fips.get('kernel')}, openssl-provider={r.fips.get('openssl_provider')}"
        )
    if r.fips_pqc_conflict.get("in_conflict"):
        L.append(
            C.wrap(
                C.RED,
                f"   ⚠  FIPS/PQC conflict: {r.fips_pqc_conflict.get('explanation')}",
            )
        )
    if r.ssh_pqc.get("available"):
        pqc = r.ssh_pqc.get("pqc_kex") or []
        L.append(
            f"   OpenSSH kex:   {len(pqc)} PQC algorithm(s)"
            + (f": {', '.join(pqc)}" if pqc else "")
        )
        kg = r.ssh_pqc.get("kex_groups") or {}
        hyb = kg.get("hybrid") or []
        pure = kg.get("pure_pqc") or []
        if hyb:
            L.append(f"     hybrid:    {', '.join(hyb)}")
        if pure:
            L.append(f"     pure PQC:  {', '.join(pure)}")
    if r.ipsec_pqc.get("available"):
        L.append(
            f"   strongSwan:    PQC support {'yes' if r.ipsec_pqc.get('pqc') else 'no'}"
        )
    if r.nss.get("available"):
        L.append(
            f"   NSS:           {r.nss.get('version')}  (PQC-capable: {r.nss.get('pqc_capable')})"
        )
    L.append("")

    L.append(C.wrap(C.BOLD, "4. PQC library capability (OpenSSL)"))
    if not r.openssl.get("available"):
        L.append(f"   {r.openssl.get('reason', 'unknown')}")
    else:
        L.append(f"   Version:       {r.openssl.get('version')}")
        L.append(
            f"   PQC native:    {'yes (>=3.5)' if r.openssl.get('pqc_native') else 'no'}"
        )
        kems = r.openssl.get("kem_algorithms") or []
        sigs = r.openssl.get("sig_algorithms") or []
        L.append(f"   ML-KEM:        {', '.join(kems) if kems else 'not exposed'}")
        L.append(f"   PQC sigs:      {', '.join(sigs) if sigs else 'not exposed'}")
        tg = r.openssl.get("tls_groups") or {}
        hybrid = tg.get("hybrid") or []
        pure = tg.get("pure_pqc") or []
        classical = tg.get("classical") or []
        if not (hybrid or pure):
            L.append("   TLS PQC groups: not exposed")
        else:
            L.append(
                f"   TLS PQC groups (hybrid): {', '.join(hybrid) if hybrid else 'none'}"
            )
            L.append(
                f"   TLS PQC groups (pure):   {', '.join(pure) if pure else 'none'}"
            )
        if classical:
            L.append(f"   TLS classical groups:    {len(classical)} detected")
    L.append("")

    L.append(C.wrap(C.BOLD, "5. NIST PQC parameter sizes (bytes)"))
    for name, sz in r.pqc_sizes.items():
        role = sz.get("role", "")
        nums = " ".join(f"{k}={v}" for k, v in sz.items() if k != "role")
        L.append(f"   {name:<20} {role:<18} {nums}")
    L.append("")

    if r.benchmark:
        L.append(C.wrap(C.BOLD, "6. Microbenchmark"))
        if not r.benchmark.get("available"):
            L.append(f"   unavailable: {r.benchmark.get('reason')}")
        else:
            L.append(
                f"   engine: {r.benchmark['engine']}, {r.benchmark['seconds_per_test']}s per test, "
                f"{r.benchmark.get('threads', 1)} thread(s)"
            )
            for algo, data in (r.benchmark.get("pqc") or {}).items():
                L.append(f"   {algo}:")
                for k, v in data.items():
                    if isinstance(v, dict):
                        agg = ", ".join(f"{kk}={vv:.1f}" for kk, vv in v.items())
                        L.append(f"     {k}: {agg}")
                    elif isinstance(v, (int, float)):
                        L.append(f"     {k:<12} {v:>12.1f}")
                    else:
                        L.append(f"     {k}: {v}")
            classical = r.benchmark.get("classical") or {}
            if classical:
                L.append("   Classical baseline (per-core):")
                for name, rates in classical.items():
                    s = ", ".join(f"{k}={v:.1f}" for k, v in rates.items())
                    L.append(f"     {name:<10} {s}")
        L.append("")

    if r.benchmark_tls_handshake:
        L.append(C.wrap(C.BOLD, "6b. TLS handshake benchmark (loopback)"))
        b = r.benchmark_tls_handshake
        if not b.get("available"):
            L.append(f"   unavailable: {b.get('reason')}")
        else:
            L.append(
                f"   engine: {b.get('engine')}, transport: {b.get('transport')}, "
                f"{b.get('iterations_per_suite')} handshakes/suite"
            )
            for s in b.get("suites") or []:
                if "error" in s:
                    L.append(
                        f"   {s.get('label', s.get('role', '?')):<32} error: {s['error']}"
                    )
                    continue
                if s.get("skipped"):
                    L.append(
                        f"   {s.get('label', '?'):<32} skipped: {s.get('reason', '')}"
                    )
                    continue
                hps = s.get("handshakes_per_sec")
                ttfb = s.get("ttfb_ms_median")
                bw = s.get("bytes_on_wire_per_handshake")
                L.append(
                    f"   {s.get('label', '?'):<32} "
                    f"{hps:>7.1f} hs/s  "
                    f"ttfb={ttfb:>6.2f} ms  "
                    f"wire={bw if bw is not None else '?'} B"
                )
        L.append("")

    if r.per_algo:
        L.append(C.wrap(C.BOLD, "7. Per-algorithm production verdict"))
        for key, v in r.per_algo.items():
            tier_s = _tier_label(v["tier"])
            extra = ""
            if "rate_per_core" in v:
                extra = f" - {v['rate_per_core']:.1f} {v['metric']}/core, ~{v['rate_host_estimate']:.0f} host"
            L.append(f"   {key:<22} {tier_s:<14}{extra}")
            L.append(f"     {v.get('reason', '')}")
            for note in v.get("notes", []):
                L.append(C.wrap(C.YELLOW, f"     note: {note}"))
        L.append("")

    if r.production_estimate:
        L.append(C.wrap(C.BOLD, "8. Production capacity estimate (60% CPU headroom)"))
        e = r.production_estimate
        if "tls_pqc_handshakes_per_sec" in e:
            L.append(
                f"   TLS-PQC handshakes/sec:           ~{e['tls_pqc_handshakes_per_sec']:,}"
            )
        if "ml_dsa_signatures_per_sec" in e:
            L.append(
                f"   ML-DSA-65 signatures/sec:         ~{e['ml_dsa_signatures_per_sec']:,}"
            )
        if "slh_dsa_sha2_128s_signatures_per_sec" in e:
            L.append(
                f"   SLH-DSA-SHA2-128s signatures/sec: ~{e['slh_dsa_sha2_128s_signatures_per_sec']}"
            )
        if "concurrent_connections_realistic" in e:
            L.append(
                f"   Concurrent conns (realistic):     ~{e['concurrent_connections_realistic']:,}  (192 KB/conn)"
            )
        if "concurrent_connections_theoretical_max" in e:
            L.append(
                f"   Concurrent conns (theoretical):   ~{e['concurrent_connections_theoretical_max']:,}  (32 KB/conn)"
            )
        if "assumptions" in e:
            L.append(f"   ({e['assumptions']})")
        L.append("")

    if r.trust_store.get("available"):
        L.append(C.wrap(C.BOLD, "9. Trust store inventory"))
        L.append(
            f"   Scanned dirs:     {', '.join(r.trust_store.get('scanned_dirs', []))}"
        )
        L.append(f"   Total certs:      {r.trust_store.get('total_certs', 0)}")
        L.append(f"   PQC certs:        {r.trust_store.get('pqc_certs', 0)}")
        L.append(f"   Hybrid certs:     {r.trust_store.get('hybrid_certs', 0)}")
        cats = r.trust_store.get("cert_categories") or {}
        if cats:
            L.append(
                "   Categories:       "
                f"classical={cats.get('classical', 0)}, "
                f"hybrid_composite={cats.get('hybrid_composite', 0)}, "
                f"pure_pqc={cats.get('pure_pqc', 0)}"
            )
        L.append("")

    if r.cnsa_2_0:
        L.append(
            C.wrap(C.BOLD, "10. CNSA 2.0 compliance (NSA national security suite)")
        )
        status = r.cnsa_2_0.get("status", "unknown")
        status_color = {
            "compliant": C.GREEN,
            "partial": C.YELLOW,
            "non_compliant": C.RED,
            "unknown": C.DIM,
        }.get(status, C.DIM)
        L.append(f"   Status:                 {C.wrap(status_color, status.upper())}")
        L.append(
            f"   ML-KEM-1024 (KEM):      {'yes' if r.cnsa_2_0.get('kem_compliant') else 'no'}"
        )
        L.append(
            f"   ML-DSA-87  (signature): {'yes' if r.cnsa_2_0.get('signature_compliant') else 'no'}"
        )
        L.append(
            f"   AES-256    (symmetric): {'yes' if r.cnsa_2_0.get('symmetric_compliant') else 'no'}"
        )
        L.append(
            f"   SHA-384/512 (hash, hw): {'yes' if r.cnsa_2_0.get('hash_compliant') else 'no'}"
        )
        for note in r.cnsa_2_0.get("notes") or []:
            L.append(C.wrap(C.YELLOW, f"   note: {note}"))
        L.append("")

    L.append(sub)
    L.append(f"  VERDICT: {C.wrap(C.BOLD, r.verdict)}")
    L.append(f"           {r.verdict_reason}")
    if r.verdict_caveat:
        L.append(C.wrap(C.YELLOW, f"  CAVEAT:  {r.verdict_caveat}"))
    L.append(sub)
    return "\n".join(L)


def render_markdown(r: Report) -> str:
    L: list[str] = []
    L.append(f"# PQC Readiness — {r.hostname}")
    L.append("")
    L.append(f"_Generated {r.generated_at}_")
    L.append("")
    L.append(f"**Verdict:** {r.verdict}")
    L.append("")
    L.append(f"> {r.verdict_reason}")
    L.append("")
    L.append("## Host")
    L.append(f"- OS / arch: `{r.os}` / `{r.arch}`")
    L.append(f"- CPU: {r.cpu_model}")
    L.append(f"- Cores: {r.cores_physical} physical / {r.cores_logical} logical")
    L.append(f"- Memory: {r.mem_total_gb:.1f} GiB total")
    if r.memory_bandwidth_gb_s is not None:
        L.append(f"- Memory bandwidth (rough probe): ~{r.memory_bandwidth_gb_s} GB/s")
    L.append("")
    L.append(f"## ISA tier: **{r.isa_tier.upper()}** (score {r.isa_score})")
    L.append(f"_{r.isa_reason}_")
    L.append("")
    if r.isa_features:
        L.append("| Flag | Purpose |")
        L.append("|------|---------|")
        for _, info in sorted(r.isa_features.items()):
            L.append(f"| `{info['name']}` | {info['purpose']} |")
        L.append("")
    L.append("## Accelerators")
    if r.accelerators:
        for a in r.accelerators:
            L.append(f"- **[{a['kind']}]** {a['name']} — `{a['detail']}`")
    else:
        L.append("- _none detected_")
    L.append("")
    if r.openssl.get("available"):
        L.append("## OpenSSL PQC capability")
        L.append(f"- Version: `{r.openssl.get('version')}`")
        L.append(
            f"- KEM algorithms: {', '.join(r.openssl.get('kem_algorithms') or []) or '_none_'}"
        )
        L.append(
            f"- Signature algorithms: {', '.join(r.openssl.get('sig_algorithms') or []) or '_none_'}"
        )
        tg_md = r.openssl.get("tls_groups") or {}
        hybrid_md = tg_md.get("hybrid") or []
        pure_md = tg_md.get("pure_pqc") or []
        L.append(f"- TLS 1.3 hybrid groups: {', '.join(hybrid_md) or '_none_'}")
        L.append(f"- TLS 1.3 pure PQC groups: {', '.join(pure_md) or '_none_'}")
        L.append("")
    if r.per_algo:
        L.append("## Per-algorithm verdict")
        L.append("| Algorithm | Tier | Per-core | Host estimate | Metric |")
        L.append("|-----------|------|----------|---------------|--------|")
        for algo, v in r.per_algo.items():
            rc = f"{v.get('rate_per_core', '-')}"
            rh = f"{v.get('rate_host_estimate', '-')}"
            L.append(
                f"| {algo} | **{v['tier']}** | {rc} | {rh} | {v.get('metric', '-')} |"
            )
        L.append("")
    if r.production_estimate:
        e = r.production_estimate
        L.append("## Production capacity (60% headroom)")
        for k, v in e.items():
            L.append(f"- {k}: {v}")
        L.append("")
    if r.benchmark_tls_handshake.get("available"):
        b = r.benchmark_tls_handshake
        L.append("## TLS handshake benchmark (loopback)")
        L.append(
            f"_{b.get('iterations_per_suite')} handshakes per suite via "
            f"`{b.get('openssl_version', 'openssl')}`. "
            "ttfb includes s_client process startup._"
        )
        L.append("")
        L.append(
            "| Suite | Role | Handshakes/sec | TTFB median (ms) | Bytes on wire / handshake |"
        )
        L.append(
            "|-------|------|---------------:|-----------------:|--------------------------:|"
        )
        for s in b.get("suites") or []:
            if "error" in s:
                L.append(
                    f"| {s.get('label', '?')} | {s.get('role', '?')} | error | error | error |"
                )
                continue
            if s.get("skipped"):
                L.append(
                    f"| {s.get('label', '?')} | {s.get('role', '?')} | skipped | skipped | skipped |"
                )
                continue
            L.append(
                f"| {s.get('label', '?')} | {s.get('role', '?')} | "
                f"{s.get('handshakes_per_sec', '-')} | "
                f"{s.get('ttfb_ms_median', '-')} | "
                f"{s.get('bytes_on_wire_per_handshake', '-')} |"
            )
        L.append("")
    return "\n".join(L)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--json", action="store_true", help="emit JSON")
    ap.add_argument("--markdown", action="store_true", help="emit markdown")
    ap.add_argument(
        "--cbom",
        action="store_true",
        help="emit CycloneDX 1.6 CBOM JSON (NIST IR 8547)",
    )
    ap.add_argument(
        "--spdx",
        action="store_true",
        help="emit SPDX 3.0 JSON-LD (Security profile) for SPDX-native pipelines",
    )
    ap.add_argument(
        "--sarif",
        action="store_true",
        help="emit SARIF 2.1.0 findings (OASIS) for security pipelines",
    )
    ap.add_argument(
        "--bench", action="store_true", help="run PQC + classical microbench"
    )
    ap.add_argument(
        "--bench-tls",
        action="store_true",
        help="run loopback TLS 1.3 handshake benchmark (classical/hybrid/PQC)",
    )
    ap.add_argument("--threads", type=int, default=1, help="add an N-way scaling test")
    ap.add_argument("--seconds", type=int, default=1, help="seconds per benchmark op")
    ap.add_argument(
        "--check",
        choices=["excellent", "good", "marginal", "poor", "cnsa-2.0"],
        help="exit 4 if verdict is below TIER, or if cnsa-2.0 status != compliant",
    )
    ap.add_argument(
        "--save", action="store_true", help="save JSON to ~/.cache/pqc-readiness/"
    )
    ap.add_argument("--quiet", action="store_true", help="print only verdict line")
    ap.add_argument("--no-color", action="store_true", help="disable ANSI color")
    ap.add_argument(
        "--scan-trust-store",
        action="store_true",
        help="walk system trust store dirs and count PQC / hybrid certs (slow)",
    )
    ap.add_argument(
        "--scan-packages",
        action="store_true",
        help="enumerate installed packages with bundled crypto (RHEL/Fedora)",
    )
    ap.add_argument(
        "--host-mount",
        metavar="PATH",
        default="",
        help="prefix for /proc /sys /dev /etc reads (DaemonSet pattern)",
    )
    ap.add_argument(
        "--ansible",
        action="store_true",
        help="emit {ansible_facts: {pqc_readiness: ...}} JSON, exit 0",
    )
    ap.add_argument(
        "--recommend",
        action="store_true",
        help=(
            "emit a host-specific PQC algorithm recommendation under the "
            "selected policy and role, instead of the readiness report"
        ),
    )
    ap.add_argument(
        "--policy",
        choices=[*VALID_POLICIES, "auto"],
        default="auto",
        help=(
            "compliance context for --recommend; 'auto' (default) emits "
            "all policies side by side"
        ),
    )
    ap.add_argument(
        "--role",
        choices=list(VALID_ROLES),
        default="tls-server",
        help=(
            "role for --recommend (only 'tls-server' is fully implemented; "
            "other roles return a stub response)"
        ),
    )
    ap.add_argument(
        "--aggregate",
        metavar="DIR",
        help="aggregate every *.json in DIR into a fleet rollup; exits when done",
    )
    ap.add_argument(
        "--aggregate-format",
        choices=["json", "csv"],
        default="json",
        help="output format for --aggregate (default: json)",
    )
    ap.add_argument(
        "--version",
        action="version",
        version=f"pqc-readiness {SCRIPT_VERSION} (schema {SCHEMA_VERSION})",
    )
    args = ap.parse_args()

    # --aggregate is a top-level alternate mode; bail before per-host probing.
    if args.aggregate:
        d = Path(args.aggregate)
        if not d.is_dir():
            print(f"--aggregate: {d} is not a directory", file=sys.stderr)
            return 2
        body, code = run_aggregator(d, output=args.aggregate_format)
        print(body)
        return code

    global HOST_PREFIX
    if args.host_mount:
        HOST_PREFIX = args.host_mount.rstrip("/")

    C.configure(
        sys.stdout.isatty()
        and not args.no_color
        and not args.json
        and not args.markdown
        and not args.cbom
        and not args.spdx
        and not args.sarif
    )

    arch = platform.machine().lower()
    flags = cpu_flags(arch)
    total_gb, avail_gb = memory_info()
    logical, physical = core_counts()
    isa_feat, isa_score = detect_isa(arch, flags)
    isa_t, isa_reason = isa_tier(arch, isa_score, flags)
    mem_t, mem_reason = memory_tier(total_gb)
    runtime_env = detect_runtime_environment()
    host_fs_detections_unavailable = build_host_fs_detections_unavailable()
    accels = detect_accelerators()
    accels.extend(detect_network_hsms())
    os_release = detect_os()
    pkcs11 = detect_pkcs11_modules(os_release.get("family", "unknown"))
    kcrypto = detect_kernel_crypto_hw()
    ktls = detect_ktls()
    fips = detect_fips_mode()
    tpm = detect_tpm_pqc()
    family = os_release.get("family", "unknown")
    osinfo = openssl_capability(os_release)
    ssh_info = detect_ssh_pqc(family)
    ipsec_info = detect_ipsec_pqc(family)
    nss_info = detect_nss()
    kernel_info = detect_kernel_info(os_release)
    fips = interpret_fips(fips, osinfo, os_release)
    fips_conflict = fips_pqc_conflict_check(fips, osinfo)
    proc_crypto_text: str | None = None
    if is_linux():
        try:
            proc_crypto_text = host_path("/proc/crypto").read_text()
        except OSError:
            proc_crypto_text = None
    cnsa_2_0 = evaluate_cnsa_2_0(osinfo, proc_crypto_text)
    trust_store_info: dict[str, Any] = {}
    if getattr(args, "scan_trust_store", False):
        trust_store_info = scan_trust_store()
    packages_info: dict[str, Any] = {}
    if getattr(args, "scan_packages", False):
        packages_info = scan_packages(os_release)
    dedicated = has_dedicated_pqc_silicon(arch, flags, accels)
    hsm_present = any(a.get("kind") in ("hsm", "network_hsm") for a in accels)
    hsm_pqc_capable = any(
        a.get("kind") in ("hsm", "network_hsm") and a.get("pqc_capable") for a in accels
    )
    hsm_present_but_not_pqc = hsm_present and not hsm_pqc_capable

    bench: dict[str, Any] = {}
    bench_tls: dict[str, Any] = {}
    membw: float | None = None
    membw_method = ""
    if args.bench:
        bench = run_benchmarks(seconds=args.seconds, threads=max(args.threads, 1))
        membw, membw_method = memory_bandwidth_probe()
    if args.bench_tls:
        bench_tls = run_tls_handshake_bench(seconds=args.seconds, osinfo=osinfo)

    cores_for_estimate = physical or logical or 1
    tls_hybrid_avail = bool((osinfo.get("tls_groups") or {}).get("hybrid"))
    palg = (
        per_algo_verdict(
            bench,
            cores_for_estimate,
            mem_bw_gb_s=membw,
            tls_hybrid_available=tls_hybrid_avail,
        )
        if bench
        else {}
    )
    pest = production_estimate(palg, total_gb) if palg else {}
    verdict, why, code, caveat = overall_verdict(isa_t, mem_t, dedicated, palg)
    why = f"{why} ISA: {isa_reason}. Memory: {mem_reason}."

    # replace_required: poor ISA tier AND no PQC silicon AND no PQC-capable
    # accelerator.  Used by fleet planners to count hosts that cannot be
    # made PQC-ready in software regardless of OpenSSL version.
    accel_pqc_present = any(a.get("pqc_capable") for a in accels)
    replace_required = (isa_t == "poor") and not dedicated and not accel_pqc_present

    r = Report(
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        hostname=socket.gethostname(),
        os=os_release.get("pretty_name") or f"{platform.system()} {platform.release()}",
        arch=arch,
        cpu_model=cpu_model(),
        cpu_freq_mhz=round(cpu_freq_mhz(), 1),
        cores_logical=logical,
        cores_physical=physical or logical,
        mem_total_gb=round(total_gb, 2),
        mem_avail_gb=round(avail_gb, 2),
        isa_features=isa_feat,
        isa_score=isa_score,
        isa_tier=isa_t,
        isa_reason=isa_reason,
        accelerators=accels,
        hsm_present_but_not_pqc=hsm_present_but_not_pqc,
        pkcs11_modules=pkcs11,
        kernel_crypto_hw=kcrypto,
        ktls_supported=ktls,
        fips=fips,
        openssl=osinfo,
        tpm_pqc=tpm,
        memory_bandwidth_gb_s=membw,
        memory_bandwidth_method=membw_method,
        ssh_pqc=ssh_info,
        ipsec_pqc=ipsec_info,
        nss=nss_info,
        kernel_info=kernel_info,
        fips_pqc_conflict=fips_conflict,
        cnsa_2_0=cnsa_2_0,
        trust_store=trust_store_info,
        runtime_environment=runtime_env,
        host_fs_detections_unavailable=host_fs_detections_unavailable,
        packages=packages_info,
        replace_required=replace_required,
        os_release=os_release,
        benchmark=bench,
        benchmark_tls_handshake=bench_tls,
        per_algo=palg,
        production_estimate=pest,
        verdict=verdict,
        verdict_reason=why,
        verdict_caveat=caveat,
        exit_code=code,
    )

    if args.save:
        d = Path.home() / ".cache" / "pqc-readiness"
        d.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        fp = d / f"{r.hostname}-{ts}.json"
        fp.write_text(json.dumps(asdict(r), indent=2))

    if args.ansible:
        # Ansible's set_fact / register patterns expect a top-level
        # ansible_facts wrapper.  The task must always exit 0 or Ansible
        # will mark the play as failed regardless of the report content.
        print(json.dumps({"ansible_facts": {"pqc_readiness": asdict(r)}}, indent=2))
        return 0
    if args.recommend:
        rec = recommend(r, policy=args.policy, role=args.role)
        if args.json:
            print(json.dumps(rec, indent=2))
        elif args.markdown:
            print(render_recommendation_markdown(r, rec))
        else:
            print(render_recommendation_text(r, rec))
        return 0
    if args.json:
        print(json.dumps(asdict(r), indent=2))
    elif args.cbom:
        print(render_cbom(r))
    elif args.spdx:
        print(render_spdx(r))
    elif args.sarif:
        print(render_sarif(r))
    elif args.markdown:
        print(render_markdown(r))
    elif args.quiet:
        print(r.verdict)
    else:
        print(render_text(r))

    if args.check == "cnsa-2.0":
        if r.cnsa_2_0.get("status") != "compliant":
            return 4
    elif args.check:
        rank = {"poor": 0, "marginal": 1, "good": 2, "excellent": 3}
        cur = (
            "excellent"
            if r.exit_code == 0
            else "good"
            if r.exit_code == 1
            else "marginal"
            if r.exit_code == 2
            else "poor"
        )
        if rank[cur] < rank[args.check]:
            return 4
    return r.exit_code


if __name__ == "__main__":
    sys.exit(main())
