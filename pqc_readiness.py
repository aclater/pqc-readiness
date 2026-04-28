#!/usr/bin/env python3
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
    pqc-readiness --markdown                markdown report (for tickets)
    pqc-readiness --bench                   run PQC + classical microbench
    pqc-readiness --threads N               include N-way scaling test
    pqc-readiness --check TIER              exit nonzero if verdict < TIER
    pqc-readiness --save                    write JSON to ~/.cache/pqc-readiness/
    pqc-readiness --quiet                   print only the verdict line
    pqc-readiness --no-color                disable ANSI color

TIER values: excellent | good | marginal | poor

Exit codes:
    0  Excellent  - dedicated PQC silicon OR optimized SIMD + ample RAM
    1  Good       - software PQC fast enough for production
    2  Marginal   - works, but plan for an accelerator at scale
    3  Poor       - software-only and too slow for production
    4  --check TIER threshold not met
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "1.0"

# ---------------------------------------------------------------------------
# ISA feature catalogs
# Per-flag tuple = (display name, purpose, weight in tier scoring)
# Weight rationale: 3 = enables a major fast path; 2 = clear speedup;
# 1 = useful but not by itself decisive.
# Refs: Intel Crypto Acceleration whitepapers; liboqs SIMD backends;
# pq-crystals reference impl notes; Cloudflare CIRCL benchmarks.
# ---------------------------------------------------------------------------

X86_FEATURES: dict[str, tuple[str, str, int]] = {
    "avx2":             ("AVX2",              "256-bit SIMD; baseline for optimized PQC", 2),
    "avx512f":          ("AVX-512 F",         "Vector polynomial arithmetic",             3),
    "avx512bw":         ("AVX-512 BW",        "Byte/word ops for Keccak/SHAKE",           2),
    "avx512vl":         ("AVX-512 VL",        "VL-aware AVX-512",                         1),
    "avx512vbmi":       ("AVX-512 VBMI",      "Permute-bytes; major Keccak speedup",      3),
    "avx512vbmi2":      ("AVX-512 VBMI2",     "Compress/expand; SHAKE/Keccak",            2),
    "avx512ifma":       ("AVX-512 IFMA",      "52-bit FMA; lattice multiplication",       3),
    "avx512_vpopcntdq": ("AVX-512 VPOPCNTDQ", "Bitcount; SLH-DSA hash trees",             1),
    "avx512_bitalg":    ("AVX-512 BITALG",    "Bit algorithms",                           1),
    "vaes":             ("VAES",              "Vector AES-NI; AES-CTR DRBG",              2),
    "vpclmulqdq":       ("VPCLMULQDQ",        "Vector carry-less multiply",               2),
    "gfni":             ("GFNI",              "Galois field; Keccak speedup",             2),
    "sha_ni":           ("SHA-NI",            "SHA-256 hardware (hybrid TLS)",            2),
    "aes":              ("AES-NI",            "AES hardware (DRBG, hybrid)",              1),
    "pclmulqdq":        ("PCLMULQDQ",         "Carry-less multiply",                      1),
}

ARM_FEATURES: dict[str, tuple[str, str, int]] = {
    "aes":    ("AES",     "ARMv8 AES instructions",                1),
    "sha2":   ("SHA-2",   "SHA-256 hardware",                      1),
    "sha3":   ("SHA-3",   "Keccak/SHAKE hardware - major PQC win", 3),
    "sha512": ("SHA-512", "SHA-512 hardware",                      1),
    "pmull":  ("PMULL",   "Polynomial multiply long",              1),
    "sve":    ("SVE",     "Scalable Vector Extension",             2),
    "sve2":   ("SVE2",    "SVE2; lattice arithmetic",              3),
    "i8mm":   ("I8MM",    "Int8 matrix multiply",                  1),
}

# IBM z facilities. MSA8 added SHA-3/SHAKE on-chip; MSA9 added EdDSA.
# IBM z16 (CEX8) is the first widely-deployed system with on-chip
# acceleration of NIST PQC algorithms in hardware.
S390_FEATURES: dict[str, tuple[str, str, int]] = {
    "msa":  ("MSA",  "Message Security Assist baseline (CPACF)", 1),
    "msa3": ("MSA3", "SHA-256/512",                              1),
    "msa4": ("MSA4", "AES-192/256, GHASH",                       1),
    "msa5": ("MSA5", "PRNG/PPNO",                                1),
    "msa8": ("MSA8", "AES-GCM, SHA-3, SHAKE - PQC hashing",      3),
    "msa9": ("MSA9", "EdDSA on-chip; precursor to PQC accel",    2),
    "vx":   ("VX",   "Vector facility",                          1),
    "vxe":  ("VXE",  "Vector enhancements",                      1),
    "vxe2": ("VXE2", "Vector enhancements 2",                    1),
}

# macOS sysctl flag prefixes -> normalized flag names matching the catalogs.
MACOS_X86_SYSCTL = {
    "machdep.cpu.features":        ["AVX1.0", "AES", "PCLMULQDQ", "SSE4.2"],
    "machdep.cpu.leaf7_features":  ["AVX2", "AVX512F", "AVX512BW", "AVX512VL",
                                    "AVX512VBMI", "AVX512VBMI2", "AVX512IFMA",
                                    "AVX512_VPOPCNTDQ", "AVX512_BITALG",
                                    "VAES", "VPCLMULQDQ", "GFNI", "SHA"],
}
MACOS_X86_TO_LINUX = {
    "AVX2": "avx2", "AVX512F": "avx512f", "AVX512BW": "avx512bw",
    "AVX512VL": "avx512vl", "AVX512VBMI": "avx512vbmi",
    "AVX512VBMI2": "avx512vbmi2", "AVX512IFMA": "avx512ifma",
    "AVX512_VPOPCNTDQ": "avx512_vpopcntdq", "AVX512_BITALG": "avx512_bitalg",
    "VAES": "vaes", "VPCLMULQDQ": "vpclmulqdq", "GFNI": "gfni",
    "SHA": "sha_ni", "AES": "aes", "PCLMULQDQ": "pclmulqdq",
}
MACOS_ARM_SYSCTLS = {
    "hw.optional.arm.FEAT_AES":    "aes",
    "hw.optional.arm.FEAT_SHA1":   "sha1",
    "hw.optional.arm.FEAT_SHA256": "sha2",
    "hw.optional.arm.FEAT_SHA512": "sha512",
    "hw.optional.arm.FEAT_SHA3":   "sha3",
    "hw.optional.arm.FEAT_PMULL":  "pmull",
    "hw.optional.arm.FEAT_SVE":    "sve",
    "hw.optional.arm.FEAT_I8MM":   "i8mm",
}

# ---------------------------------------------------------------------------
# Accelerator catalogs
# ---------------------------------------------------------------------------

ACCEL_PCI_HINTS: list[tuple[str, str, str]] = [
    (r"Marvell.*LiquidSecurity",                       "Marvell LiquidSecurity HSM",      "hsm"),
    (r"Cavium.*Nitrox|Marvell.*Nitrox",                "Marvell/Cavium Nitrox",           "hsm"),
    (r"Thales.*Luna|SafeNet.*Luna",                    "Thales Luna PCIe HSM",            "hsm"),
    (r"Utimaco",                                       "Utimaco SecurityServer",          "hsm"),
    (r"Atos.*Trustway|Bull.*Trustway|Proteccio",       "Atos Trustway Proteccio",         "hsm"),
    (r"Yubico",                                        "YubiHSM",                         "hsm"),
    (r"IBM.*Crypto Express|IBM.*47[67][09]",           "IBM Crypto Express (CEX)",        "hsm"),
    (r"Intel.*QuickAssist|Intel.*QAT",                 "Intel QuickAssist (QAT)",         "accel"),
    (r"AMD.*Secure Processor|AMD.*PSP",                "AMD Platform Security Processor", "accel"),
    (r"ARM.*CryptoCell",                               "ARM CryptoCell",                  "accel"),
    (r"Amazon\.com.*Nitro|Amazon Web Services.*Nitro", "AWS Nitro Security Chip",        "accel"),
    (r"Microchip.*CryptoAuth",                         "Microchip CryptoAuthentication",  "accel"),
    # SmartNICs / DPUs.  These are not PQC silicon today but customers
    # want them inventoried as part of the broader accelerator picture.
    (r"Mellanox.*BlueField|NVIDIA.*BlueField",         "NVIDIA BlueField DPU",            "dpu"),
    (r"Intel.*IPU(\s+E2000)?|Intel.*Mount Evans",      "Intel IPU E2000",                 "dpu"),
    (r"Pensando|AMD.*Pensando|DSC2|DSC-25",            "AMD Pensando DSC",                "dpu"),
]

DEVICE_HINTS: list[tuple[str, str, str]] = [
    ("/dev/tpm0",           "TPM 2.0 device",            "tpm"),
    ("/dev/tpmrm0",         "TPM 2.0 resource manager",  "tpm"),
    ("/dev/qat_adf_ctl",    "Intel QAT control",         "accel"),
    ("/dev/z90crypt",       "IBM Z crypto express",      "hsm"),
    ("/dev/nitro_enclaves", "AWS Nitro Enclaves",        "accel"),
    ("/dev/kfd",            "AMD ROCm compute (general-purpose)", "gpu"),
    ("/dev/nvidia0",        "NVIDIA GPU (general-purpose)",       "gpu"),
]

PKCS11_SEARCH: list[str] = [
    "/usr/lib64/pkcs11", "/usr/lib/pkcs11",
    "/usr/lib/x86_64-linux-gnu/pkcs11", "/usr/lib/aarch64-linux-gnu/pkcs11",
    "/usr/local/lib/pkcs11", "/opt/cloudhsm/lib", "/opt/Thales/PKCS11",
    "/opt/utimaco/Software/PKCS11",
]

# ---------------------------------------------------------------------------
# NIST PQC parameter sizes (bytes) and per-algorithm production thresholds
# ---------------------------------------------------------------------------

PQC_SIZES = {
    "ML-KEM-768":        {"role": "TLS KEM",        "pk": 1184, "sk": 2400, "ct": 1088, "shared": 32},
    "ML-DSA-65":         {"role": "general sig",    "pk": 1952, "sk": 4032, "sig":  3309},
    "ML-DSA-87":         {"role": "high-sec sig",   "pk": 2592, "sk": 4896, "sig":  4627},
    "SLH-DSA-SHA2-128s": {"role": "small/slow sig", "pk":   32, "sk":   64, "sig":  7856},
    "SLH-DSA-SHA2-128f": {"role": "fast/large sig", "pk":   32, "sk":   64, "sig": 17088},
    "SLH-DSA-SHA2-256f": {"role": "high-sec sig",   "pk":   64, "sk":  128, "sig": 49856},
}

# Per-core ops/sec thresholds for the bottleneck operation of each algorithm.
# ML-KEM bottleneck = decaps (server-side TLS); ML-DSA = sign (cert/JWT issuance);
# SLH-DSA = sign (catastrophically slow without an accelerator).
# Calibrated against published Intel SPR / Zen 4 / Graviton 3 numbers.
ALGO_THRESHOLDS: dict[str, tuple[str, dict[str, float]]] = {
    "ML-KEM-768":        ("decaps/s", {"excellent": 20000, "good":  8000, "marginal": 2000}),
    "ML-DSA-65":         ("sign/s",   {"excellent":  1500, "good":   600, "marginal":  150}),
    "SLH-DSA-SHA2-128s": ("sign/s",   {"excellent":     5, "good":     2, "marginal":  0.5}),
}

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

class C:
    BOLD = "\033[1m"; DIM = "\033[2m"; RESET = "\033[0m"
    GREEN = "\033[32m"; YELLOW = "\033[33m"; RED = "\033[31m"
    CYAN = "\033[36m"; MAGENTA = "\033[35m"
    enabled = False

    @classmethod
    def configure(cls, on: bool) -> None:
        cls.enabled = on

    @classmethod
    def wrap(cls, color: str, text: str) -> str:
        return f"{color}{text}{cls.RESET}" if cls.enabled else text


TIER_COLOR = {
    "excellent": C.GREEN,
    "good":      C.GREEN,
    "adequate":  C.YELLOW,
    "marginal":  C.YELLOW,
    "poor":      C.RED,
    "unknown":   C.DIM,
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
    trust_store: dict[str, Any] = field(default_factory=dict)
    benchmark: dict[str, Any] = field(default_factory=dict)
    pqc_sizes: dict[str, dict[str, Any]] = field(default_factory=lambda: PQC_SIZES)
    per_algo: dict[str, dict[str, Any]] = field(default_factory=dict)
    production_estimate: dict[str, Any] = field(default_factory=dict)
    verdict: str = ""
    verdict_reason: str = ""
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

def linux_cpu_flags() -> set[str]:
    flags: set[str] = set()
    try:
        text = Path("/proc/cpuinfo").read_text()
    except OSError:
        return flags
    for line in text.splitlines():
        if line.startswith(("flags", "Features", "features", "facilities")):
            _, _, vals = line.partition(":")
            flags.update(vals.split())
    return flags


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
            for line in Path("/proc/cpuinfo").read_text().splitlines():
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
            for line in Path("/proc/cpuinfo").read_text().splitlines():
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
            text = Path("/proc/cpuinfo").read_text()
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
            for line in Path("/proc/meminfo").read_text().splitlines():
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
        avx512_pqc = (
            {"avx512f", "avx512vbmi", "avx512ifma"}.issubset(flags)
            or {"avx512f", "vaes", "vpclmulqdq"}.issubset(flags)
        )
        if avx512_pqc and score >= 18:
            return ("excellent", "AVX-512 with VBMI/IFMA/VAES family - full SIMD PQC at line rate")
        if "avx2" in flags and {"aes", "pclmulqdq"}.issubset(flags) and score >= 6:
            return ("good", "AVX2 + AES-NI + PCLMULQDQ - production-capable in software")
        if "avx2" in flags:
            return ("adequate", "AVX2 only - workable but slower than peers")
        return ("poor", "Pre-AVX2 x86 - software PQC will be slow")
    if arch in ("aarch64", "arm64"):
        if {"sha3", "aes"}.issubset(flags) and ("sve2" in flags or score >= 8):
            return ("excellent", "ARMv8 with SHA-3 + SVE2 / wide crypto - strong PQC profile")
        if {"sha3", "aes"}.issubset(flags):
            return ("good", "ARMv8 with SHA-3 + AES - production-capable (Apple M-series, Graviton 3)")
        if {"aes", "sha2", "pmull"}.issubset(flags):
            return ("good", "ARMv8 crypto extensions - production-capable")
        return ("adequate", "Limited ARM crypto extensions")
    if arch == "s390x":
        if {"msa8", "msa9"}.issubset(flags):
            return ("excellent", "MSA8+MSA9 (z15+/z16) - on-chip SHA-3 / EdDSA, PQC accel possible")
        if "msa" in flags:
            return ("adequate", "Older z hardware without SHA-3 on-chip")
        return ("poor", "No CPACF detected")
    return ("unknown", f"Architecture {arch} not classified")


def memory_tier(gb: float) -> tuple[str, str]:
    if gb >= 64:
        return ("excellent", f"{gb:.1f} GiB - comfortable for high-throughput TLS/PQC at scale")
    if gb >= 16:
        return ("good", f"{gb:.1f} GiB - adequate for medium production load")
    if gb >= 4:
        return ("adequate", f"{gb:.1f} GiB - OK for low-volume or edge deployments")
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
                        out.append({"kind": kind, "name": label, "detail": line.strip()})
    for path, label, kind in DEVICE_HINTS:
        if Path(path).exists():
            out.append({"kind": kind, "name": label, "detail": path})
    # IBM z: enumerate Crypto Express adapters via lszcrypt.  Only CEX8 in
    # EP11 mode is flagged pqc_capable; CEX5/6/7 surface but do not count
    # toward dedicated PQC silicon.
    if platform.machine().lower() == "s390x":
        out.extend(detect_s390x_crypto())
    return out


def detect_pkcs11_modules() -> list[str]:
    found: set[str] = set()
    for d in PKCS11_SEARCH:
        p = Path(d)
        if not p.is_dir():
            continue
        for sub in p.rglob("*.so"):
            found.add(str(sub))
        for sub in p.rglob("*.dylib"):
            found.add(str(sub))
    return sorted(found)


def detect_tpm_pqc() -> dict[str, Any]:
    if not shutil.which("tpm2_getcap"):
        return {"present": Path("/dev/tpmrm0").exists() or Path("/dev/tpm0").exists(),
                "tools": False, "note": "tpm2-tools not installed; TPM 2.0 chips today do not implement NIST PQC"}
    rc, out = _run(["tpm2_getcap", "algorithms"], timeout=5)
    if rc != 0:
        return {"present": True, "tools": True, "note": "tpm2_getcap failed", "raw": out[:200]}
    has_pqc = bool(re.search(r"ml[-_ ]?kem|ml[-_ ]?dsa|kyber|dilithium|sphincs", out, re.IGNORECASE))
    return {"present": True, "tools": True, "pqc_advertised": has_pqc,
            "note": "TPM 2.0 specs do not yet mandate PQC; almost all shipped TPMs answer 'no'"}


def detect_kernel_crypto_hw() -> list[str]:
    """Linux /proc/crypto driver column - hardware-accelerated drivers usually
    end in -ni / -ce / -ssse3 / -avx2 / -avx512 / -arm64-ce / -aesni."""
    if not is_linux():
        return []
    try:
        text = Path("/proc/crypto").read_text()
    except OSError:
        return []
    hw_suffixes = ("-ni", "-ce", "-ssse3", "-avx2", "-avx512", "-arm64-ce",
                   "-aesni", "-pclmul", "-sha-ce", "-sha-ni", "_asm", "-paes")
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
        mods = Path("/proc/modules").read_text()
        if "tls " in mods:
            return True
    except OSError:
        pass
    if Path("/sys/module/tls").exists():
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
        info["kernel"] = Path("/proc/sys/crypto/fips_enabled").read_text().strip() == "1"
    except OSError:
        pass
    if shutil.which("openssl"):
        rc, out = _run(["openssl", "list", "-providers", "-verbose"], timeout=5)
        if rc == 0:
            info["openssl_provider"] = detect_fips_mode_from_providers_text(out)
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
    pat = re.compile(
        r"^\s*(\S+)\s+(CEX(\d+)([CPA]))\s+(\S+)\s+(\S+)"
    )
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
        out.append({
            "card": card,
            "domain": domain,
            "type_str": type_str,
            "level": level,
            "mode": mode,
            "status": status,
            "pqc_eligible": (level >= 8 and mode == "EP11"),
        })
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
        accels.append({
            "kind": "hsm",
            "name": f"IBM Crypto Express {adapter['level']} ({adapter['mode']})",
            "detail": (f"card={adapter['card']}"
                       + (f" domain={adapter['domain']}" if adapter["domain"] else "")
                       + f" mode={adapter['mode']} status={adapter['status']}"),
            "pqc_capable": adapter["pqc_eligible"],
            "cex_level": adapter["level"],
            "cex_mode": adapter["mode"],
        })
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
def has_dedicated_pqc_silicon(arch: str, flags: set[str], accels: list[dict[str, Any]]) -> bool:
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
    ("/etc/Chrystoki.conf",  "Thales Luna Network/PCIe (Chrystoki client config)"),
    ("/opt/nfast/kmdata",    "Entrust nShield Connect (kmdata directory)"),
    ("/opt/nfast/sbin",      "Entrust nShield (sbin tools)"),
    ("/opt/cloudhsm/etc",    "AWS CloudHSM client"),
    ("/opt/cloudhsm/bin",    "AWS CloudHSM client tools"),
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
        p = Path(path)
        if not p.exists():
            continue
        if label in seen_labels:
            continue
        seen_labels.add(label)
        out.append({
            "kind": "network_hsm",
            "name": label,
            "detail": f"client config present: {path}",
            "pqc_capable": False,
        })
    return out


# ---------------------------------------------------------------------------
# OpenSSH / strongSwan / NSS PQC capability
# ---------------------------------------------------------------------------

def parse_ssh_kex(text: str) -> dict[str, Any]:
    """Parse `ssh -Q kex` output.  Returns a dict with the full count and
    the subset of PQC-relevant kex algorithms (ML-KEM hybrids and the
    older sntrup761 NTRU Prime hybrid)."""
    kexes = [line.strip() for line in text.splitlines() if line.strip()]
    pqc = sorted({k for k in kexes if re.search(r"\b(?:mlkem|sntrup)", k, re.IGNORECASE)})
    return {"available": True, "kex_count": len(kexes), "pqc_kex": pqc}


def detect_ssh_pqc() -> dict[str, Any]:
    if not shutil.which("ssh"):
        return {"available": False, "reason": "ssh not on PATH"}
    rc, out = _run(["ssh", "-Q", "kex"], timeout=5)
    if rc != 0:
        return {"available": False, "reason": f"ssh -Q kex failed (rc={rc})"}
    return parse_ssh_kex(out)


def detect_ipsec_pqc() -> dict[str, Any]:
    """Look for ML-KEM / Kyber tokens in `swanctl --list-algs`."""
    if not shutil.which("swanctl"):
        return {"available": False, "reason": "swanctl not on PATH"}
    rc, out = _run(["swanctl", "--list-algs"], timeout=10)
    if rc != 0:
        return {"available": False, "reason": f"swanctl --list-algs failed (rc={rc})"}
    pqc_match = re.search(r"\b(ML[-_ ]?KEM|kyber|mlkem)\b", out, re.IGNORECASE)
    return {
        "available": True,
        "pqc": bool(pqc_match),
        "evidence": pqc_match.group(0) if pqc_match else None,
    }


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
    return {"available": False, "reason": "neither certutil nor rpm available"}


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
    pqc_re = re.compile(r"ml[-_ ]?kem|ml[-_ ]?dsa|slh[-_ ]?dsa|kyber|dilithium|sphincs",
                        re.IGNORECASE)
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


def detect_kernel_info() -> dict[str, Any]:
    info: dict[str, Any] = {
        "release": platform.release(),
        "system": platform.system(),
    }
    if not is_linux():
        return info
    rh = Path("/etc/redhat-release")
    if rh.exists():
        try:
            info["redhat_release"] = parse_redhat_release(rh.read_text())
        except OSError:
            pass
    osr = Path("/etc/os-release")
    if osr.exists():
        try:
            text = osr.read_text()
            for line in text.splitlines():
                if line.startswith("ID="):
                    info["os_release_id"] = line.split("=", 1)[1].strip().strip('"')
                elif line.startswith("VERSION_ID="):
                    info["os_release_version_id"] = line.split("=", 1)[1].strip().strip('"')
        except OSError:
            pass
    try:
        info["proc_crypto_pqc"] = parse_proc_crypto_pqc(Path("/proc/crypto").read_text())
    except OSError:
        info["proc_crypto_pqc"] = []
    return info


# ---------------------------------------------------------------------------
# FIPS / PQC interaction warning
# ---------------------------------------------------------------------------

def fips_pqc_conflict_check(fips: dict[str, Any], openssl: dict[str, Any]) -> dict[str, Any]:
    """Detect the case where a host is in kernel FIPS mode AND OpenSSL is
    advertising PQC algorithms via the non-FIPS default provider.  In this
    state ML-KEM/ML-DSA appear listed but are NOT usable in a FIPS-validated
    workflow (RHEL 9 / 10 FIPS provider does not yet include PQC)."""
    if not fips.get("kernel"):
        return {"in_conflict": False, "explanation": "Kernel FIPS mode not enabled."}
    has_pqc = bool((openssl.get("kem_algorithms") or []) or
                   (openssl.get("sig_algorithms") or []))
    if not has_pqc:
        return {"in_conflict": False, "explanation": "FIPS mode active and no PQC algorithms exposed."}
    if fips.get("openssl_provider"):
        return {
            "in_conflict": False,
            "explanation": ("FIPS provider is active and PQC algorithms are exposed.  "
                            "Verify they are coming from a FIPS-validated provider before "
                            "relying on them in regulated workflows."),
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
    re.compile(r"\b1\.3\.9999\.\d+\.\d+\.\d+\b"),            # liboqs experimental
]


def scan_trust_store(dirs: list[str] | None = None) -> dict[str, Any]:
    if not shutil.which("openssl"):
        return {"available": False, "reason": "openssl not on PATH"}
    target_dirs = dirs if dirs is not None else TRUST_STORE_DIRS
    total = 0
    pqc_certs = 0
    hybrid_certs = 0
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
                ["openssl", "x509", "-in", str(cert), "-noout", "-text",
                 "-certopt", "no_validity,no_serial,no_pubkey,no_sigdump"],
                timeout=3,
            )
            if rc != 0:
                continue
            total += 1
            if PQC_OID_RE.search(dump):
                pqc_certs += 1
            if any(p.search(dump) for p in HYBRID_OID_RES):
                hybrid_certs += 1
    return {
        "available": True,
        "scanned_dirs": [d for d in target_dirs if Path(d).is_dir()],
        "total_certs": total,
        "pqc_certs": pqc_certs,
        "hybrid_certs": hybrid_certs,
    }


# ---------------------------------------------------------------------------
# OpenSSL capability inspection
# ---------------------------------------------------------------------------

def openssl_capability() -> dict[str, Any]:
    if not shutil.which("openssl"):
        return {"available": False, "reason": "openssl not on PATH"}
    out: dict[str, Any] = {"available": True}
    rc, ver = _run(["openssl", "version"], timeout=5)
    out["version"] = ver.strip() if rc == 0 else "unknown"
    m = re.search(r"OpenSSL\s+(\d+)\.(\d+)\.(\d+)", out["version"])
    out["version_tuple"] = [int(m.group(1)), int(m.group(2)), int(m.group(3))] if m else None
    out["pqc_native"] = bool(out["version_tuple"]) and tuple(out["version_tuple"][:2]) >= (3, 5)
    rc, kems = _run(["openssl", "list", "-kem-algorithms"], timeout=5)
    out["kem_algorithms"] = sorted({a for a in re.findall(r"ML-KEM-\d+", kems)}) if rc == 0 else []
    rc, sigs = _run(["openssl", "list", "-signature-algorithms"], timeout=5)
    out["sig_algorithms"] = sorted({a for a in re.findall(r"ML-DSA-\d+|SLH-DSA-[A-Za-z0-9-]+", sigs)}) if rc == 0 else []
    rc, groups = _run(["openssl", "list", "-tls-groups", "-tls1_3"], timeout=5)
    if rc != 0:
        rc, groups = _run(["openssl", "list", "-tls-groups"], timeout=5)
    out["tls_pqc_groups"] = sorted({g for g in re.findall(r"\b(?:X25519MLKEM\d+|MLKEM\d+|SecP\d+r1MLKEM\d+|X448MLKEM\d+)\b", groups)}) if rc == 0 else []
    rc, providers = _run(["openssl", "list", "-providers"], timeout=5)
    out["providers"] = sorted({m.group(1) for m in re.finditer(r"^\s*(\w+)\s*$", providers, re.MULTILINE)}) if rc == 0 else []
    return out


# ---------------------------------------------------------------------------
# Benchmarking
# ---------------------------------------------------------------------------

def parse_speed_row(text: str, algo: str, labels: tuple[str, ...]) -> dict[str, float] | None:
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
            tail = nums[-len(labels):]
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
        rates = [float(x) for x in nums[-len(pending):]]
        # The same algorithm appears under several header sections in
        # `openssl speed` (e.g., RSA shows up under the legacy block, the
        # KEM block, and the signature block).  Keep the first reading.
        out.setdefault(name, dict(zip(pending, rates)))
        pending = []
    return out


def run_pqc_bench(seconds: int, threads: int) -> dict[str, Any]:
    plan: list[tuple[str, str, tuple[str, ...]]] = [
        ("ML-KEM-768",         "-kem-algorithms",       ("keygen/s", "encaps/s", "decaps/s")),
        ("ML-DSA-65",          "-signature-algorithms", ("keygen/s", "sign/s",   "verify/s")),
        ("SLH-DSA-SHA2-128s",  "-signature-algorithms", ("keygen/s", "sign/s",   "verify/s")),
    ]
    results: dict[str, Any] = {}
    for algo, flag, labels in plan:
        cmd = ["openssl", "speed", "-seconds", str(seconds), flag, algo]
        rc, out = _run(cmd, timeout=seconds * 8 + 30)
        if rc != 0:
            results[algo] = {"error": out.strip().splitlines()[-1][:200] if out else f"rc={rc}"}
            continue
        rates = parse_speed_row(out, algo, labels)
        if rates is None:
            results[algo] = {"raw": out.strip().splitlines()[-1][:200]}
        else:
            results[algo] = rates
        if threads > 1:
            cmd_m = ["openssl", "speed", "-multi", str(threads), "-seconds", str(seconds), flag, algo]
            rc2, out2 = _run(cmd_m, timeout=seconds * 8 + 60)
            if rc2 == 0:
                m_rates = parse_speed_row(out2, algo, labels)
                if m_rates:
                    results[algo][f"x{threads}_aggregate"] = m_rates
    return results


def run_classical_baseline(seconds: int) -> dict[str, dict[str, float]]:
    rc, out = _run(
        ["openssl", "speed", "-seconds", str(seconds), "rsa2048", "ed25519", "ecdhx25519"],
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
        gb_per_s = bytes_moved / elapsed / (1024 ** 3)
        return round(gb_per_s, 1), "STREAM-triad (numpy)"
    except (MemoryError, OSError) as e:
        return None, f"probe failed: {e}"


# ---------------------------------------------------------------------------
# Per-algorithm and overall verdicts
# ---------------------------------------------------------------------------

def per_algo_verdict(bench: dict[str, Any], cores: int) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    pqc = bench.get("pqc") if bench.get("available") else None
    for algo, (op, thresholds) in ALGO_THRESHOLDS.items():
        bench_algo = (pqc or {}).get(algo)
        if not bench_algo or op not in bench_algo:
            out[algo] = {"tier": "unknown", "reason": "no benchmark data", "metric": op}
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
        host_rate = rate * cores
        out[algo] = {
            "tier": tier, "metric": op,
            "rate_per_core": round(rate, 2),
            "rate_host_estimate": round(host_rate, 2),
            "thresholds": thresholds,
            "reason": f"{rate:.1f} {op}/core - threshold for '{tier}' is {thresholds.get(tier, '-')}",
        }
    return out


def production_estimate(per_algo: dict[str, dict[str, Any]], mem_gb: float) -> dict[str, Any]:
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
        out["slh_dsa_sha2_128s_signatures_per_sec"] = round(slh["rate_host_estimate"] * headroom, 1)
    # Per-connection memory accounting.  The earlier 32 KB figure ignored
    # default Linux socket buffers, ML-KEM ciphertext (1088 B), the
    # ML-DSA cert chain (typically 8-12 KB across 2-3 certs), TLS state,
    # and userspace buffers.  192 KB is a realistic floor for a TLS
    # server doing PQC; 32 KB is the lower theoretical bound for
    # comparison.  50% of RAM is reserved for non-connection use
    # (binary, kernel, working memory headroom).
    if mem_gb > 0:
        usable_bytes = mem_gb * (1024 ** 3) * 0.5
        out["concurrent_connections_realistic"] = int(usable_bytes / (192 * 1024))
        out["concurrent_connections_theoretical_max"] = int(usable_bytes / (32 * 1024))
        out["assumptions"] = (
            "realistic: 192 KB/conn (TCP buffers + ML-KEM ct + ML-DSA cert "
            "chain + TLS state + userspace); theoretical max: 32 KB/conn "
            "(minimal PQC handshake state only); 50% RAM reserved"
        )
    return out


def overall_verdict(
    isa: str, mem: str, dedicated: bool, per_algo: dict[str, dict[str, Any]],
) -> tuple[str, str, int]:
    if dedicated:
        return ("EXCELLENT - dedicated PQC silicon present",
                "Use the accelerator for keygen/sign/decap; software path covers the rest.",
                0)
    rank = {"excellent": 4, "good": 3, "adequate": 2, "marginal": 2, "poor": 1, "unknown": 2}
    bench_tiers = [v["tier"] for v in per_algo.values() if v.get("tier") not in (None, "unknown")]
    bench_min = min((rank[t] for t in bench_tiers), default=0)
    isa_score = rank.get(isa, 2)
    mem_score = rank.get(mem, 2)
    composite = min(s for s in (isa_score, mem_score, bench_min or 99) if s)
    if composite >= 4:
        return ("EXCELLENT - software PQC at production speed",
                "On-chip SIMD covers ML-KEM/ML-DSA easily; SLH-DSA acceptable for non-hot paths.", 0)
    if composite == 3:
        return ("GOOD - production-capable in software",
                "Fine for TLS termination at moderate QPS; benchmark before committing to SLH-DSA.", 1)
    if composite == 2:
        return ("MARGINAL - works, but plan for an accelerator",
                "Software PQC will be a hot spot under load; consider HSM/QAT offload.", 2)
    return ("POOR - not suitable for production PQC",
            "Add a dedicated accelerator or upgrade the host.", 3)


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------

def _tier_label(tier: str) -> str:
    return C.wrap(TIER_COLOR.get(tier, ""), tier.upper())


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
        L.append(f"  Max freq:      {r.cpu_freq_mhz/1000:.2f} GHz")
    L.append(f"  Cores:         {r.cores_physical} physical / {r.cores_logical} logical")
    L.append(f"  Memory:        {r.mem_total_gb:.1f} GiB total / {r.mem_avail_gb:.1f} GiB available")
    if r.memory_bandwidth_gb_s is not None:
        L.append(f"  Mem bandwidth: ~{r.memory_bandwidth_gb_s} GB/s ({r.memory_bandwidth_method})")
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
        L.append(C.wrap(C.YELLOW,
            "     NOTE: HSM(s) detected but none currently confirmed PQC-capable."))
        L.append("           Verify firmware version against vendor's PQC release notes.")
    if r.tpm_pqc.get("present"):
        marker = "yes" if r.tpm_pqc.get("pqc_advertised") else "no"
        L.append(f"     TPM PQC algorithms advertised: {marker}  ({r.tpm_pqc.get('note', '')})")
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
            L.append("   /proc/crypto PQC drivers: none (kernel-side PQC not in mainline)")
    if r.kernel_crypto_hw:
        L.append(f"   /proc/crypto hw-accel: {len(r.kernel_crypto_hw)} drivers")
        for d in r.kernel_crypto_hw[:6]:
            L.append(f"     - {d}")
        if len(r.kernel_crypto_hw) > 6:
            L.append(f"     ... and {len(r.kernel_crypto_hw) - 6} more")
    if r.ktls_supported is not None:
        L.append(f"   Kernel TLS:    {'yes' if r.ktls_supported else 'no'}")
    if r.fips:
        L.append(f"   FIPS mode:     kernel={r.fips.get('kernel')}, openssl-provider={r.fips.get('openssl_provider')}")
    if r.fips_pqc_conflict.get("in_conflict"):
        L.append(C.wrap(C.RED, f"   ⚠  FIPS/PQC conflict: {r.fips_pqc_conflict.get('explanation')}"))
    if r.ssh_pqc.get("available"):
        pqc = r.ssh_pqc.get("pqc_kex") or []
        L.append(f"   OpenSSH kex:   {len(pqc)} PQC algorithm(s)" + (f": {', '.join(pqc)}" if pqc else ""))
    if r.ipsec_pqc.get("available"):
        L.append(f"   strongSwan:    PQC support {'yes' if r.ipsec_pqc.get('pqc') else 'no'}")
    if r.nss.get("available"):
        L.append(f"   NSS:           {r.nss.get('version')}  (PQC-capable: {r.nss.get('pqc_capable')})")
    L.append("")

    L.append(C.wrap(C.BOLD, "4. PQC library capability (OpenSSL)"))
    if not r.openssl.get("available"):
        L.append(f"   {r.openssl.get('reason', 'unknown')}")
    else:
        L.append(f"   Version:       {r.openssl.get('version')}")
        L.append(f"   PQC native:    {'yes (>=3.5)' if r.openssl.get('pqc_native') else 'no'}")
        kems = r.openssl.get("kem_algorithms") or []
        sigs = r.openssl.get("sig_algorithms") or []
        groups = r.openssl.get("tls_pqc_groups") or []
        L.append(f"   ML-KEM:        {', '.join(kems) if kems else 'not exposed'}")
        L.append(f"   PQC sigs:      {', '.join(sigs) if sigs else 'not exposed'}")
        L.append(f"   TLS PQC groups:{(' ' + ', '.join(groups)) if groups else ' not exposed'}")
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
            L.append(f"   engine: {r.benchmark['engine']}, {r.benchmark['seconds_per_test']}s per test, "
                     f"{r.benchmark.get('threads', 1)} thread(s)")
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

    if r.per_algo:
        L.append(C.wrap(C.BOLD, "7. Per-algorithm production verdict"))
        for algo, v in r.per_algo.items():
            tier_s = _tier_label(v["tier"])
            extra = ""
            if "rate_per_core" in v:
                extra = f" - {v['rate_per_core']:.1f} {v['metric']}/core, ~{v['rate_host_estimate']:.0f} host"
            L.append(f"   {algo:<20} {tier_s:<14}{extra}")
            L.append(f"     {v.get('reason','')}")
        L.append("")

    if r.production_estimate:
        L.append(C.wrap(C.BOLD, "8. Production capacity estimate (60% CPU headroom)"))
        e = r.production_estimate
        if "tls_pqc_handshakes_per_sec" in e:
            L.append(f"   TLS-PQC handshakes/sec:           ~{e['tls_pqc_handshakes_per_sec']:,}")
        if "ml_dsa_signatures_per_sec" in e:
            L.append(f"   ML-DSA-65 signatures/sec:         ~{e['ml_dsa_signatures_per_sec']:,}")
        if "slh_dsa_sha2_128s_signatures_per_sec" in e:
            L.append(f"   SLH-DSA-SHA2-128s signatures/sec: ~{e['slh_dsa_sha2_128s_signatures_per_sec']}")
        if "concurrent_connections_realistic" in e:
            L.append(f"   Concurrent conns (realistic):     ~{e['concurrent_connections_realistic']:,}  (192 KB/conn)")
        if "concurrent_connections_theoretical_max" in e:
            L.append(f"   Concurrent conns (theoretical):   ~{e['concurrent_connections_theoretical_max']:,}  (32 KB/conn)")
        if "assumptions" in e:
            L.append(f"   ({e['assumptions']})")
        L.append("")

    if r.trust_store.get("available"):
        L.append(C.wrap(C.BOLD, "9. Trust store inventory"))
        L.append(f"   Scanned dirs:     {', '.join(r.trust_store.get('scanned_dirs', []))}")
        L.append(f"   Total certs:      {r.trust_store.get('total_certs', 0)}")
        L.append(f"   PQC certs:        {r.trust_store.get('pqc_certs', 0)}")
        L.append(f"   Hybrid certs:     {r.trust_store.get('hybrid_certs', 0)}")
        L.append("")

    L.append(sub)
    L.append(f"  VERDICT: {C.wrap(C.BOLD, r.verdict)}")
    L.append(f"           {r.verdict_reason}")
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
        L.append(f"- KEM algorithms: {', '.join(r.openssl.get('kem_algorithms') or []) or '_none_'}")
        L.append(f"- Signature algorithms: {', '.join(r.openssl.get('sig_algorithms') or []) or '_none_'}")
        L.append(f"- TLS 1.3 PQC groups: {', '.join(r.openssl.get('tls_pqc_groups') or []) or '_none_'}")
        L.append("")
    if r.per_algo:
        L.append("## Per-algorithm verdict")
        L.append("| Algorithm | Tier | Per-core | Host estimate | Metric |")
        L.append("|-----------|------|----------|---------------|--------|")
        for algo, v in r.per_algo.items():
            rc = f"{v.get('rate_per_core', '-')}"
            rh = f"{v.get('rate_host_estimate', '-')}"
            L.append(f"| {algo} | **{v['tier']}** | {rc} | {rh} | {v.get('metric', '-')} |")
        L.append("")
    if r.production_estimate:
        e = r.production_estimate
        L.append("## Production capacity (60% headroom)")
        for k, v in e.items():
            L.append(f"- {k}: {v}")
        L.append("")
    return "\n".join(L)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--json", action="store_true", help="emit JSON")
    ap.add_argument("--markdown", action="store_true", help="emit markdown")
    ap.add_argument("--bench", action="store_true", help="run PQC + classical microbench")
    ap.add_argument("--threads", type=int, default=1, help="add an N-way scaling test")
    ap.add_argument("--seconds", type=int, default=1, help="seconds per benchmark op")
    ap.add_argument("--check", choices=["excellent", "good", "marginal", "poor"],
                    help="exit nonzero if verdict is below TIER")
    ap.add_argument("--save", action="store_true", help="save JSON to ~/.cache/pqc-readiness/")
    ap.add_argument("--quiet", action="store_true", help="print only verdict line")
    ap.add_argument("--no-color", action="store_true", help="disable ANSI color")
    ap.add_argument("--scan-trust-store", action="store_true",
                    help="walk system trust store dirs and count PQC / hybrid certs (slow)")
    args = ap.parse_args()

    C.configure(sys.stdout.isatty() and not args.no_color and not args.json and not args.markdown)

    arch = platform.machine().lower()
    flags = cpu_flags(arch)
    total_gb, avail_gb = memory_info()
    logical, physical = core_counts()
    isa_feat, isa_score = detect_isa(arch, flags)
    isa_t, isa_reason = isa_tier(arch, isa_score, flags)
    mem_t, mem_reason = memory_tier(total_gb)
    accels = detect_accelerators()
    accels.extend(detect_network_hsms())
    pkcs11 = detect_pkcs11_modules()
    kcrypto = detect_kernel_crypto_hw()
    ktls = detect_ktls()
    fips = detect_fips_mode()
    tpm = detect_tpm_pqc()
    osinfo = openssl_capability()
    ssh_info = detect_ssh_pqc()
    ipsec_info = detect_ipsec_pqc()
    nss_info = detect_nss()
    kernel_info = detect_kernel_info()
    fips_conflict = fips_pqc_conflict_check(fips, osinfo)
    trust_store_info: dict[str, Any] = {}
    if getattr(args, "scan_trust_store", False):
        trust_store_info = scan_trust_store()
    dedicated = has_dedicated_pqc_silicon(arch, flags, accels)
    hsm_present = any(a.get("kind") in ("hsm", "network_hsm") for a in accels)
    hsm_pqc_capable = any(a.get("kind") in ("hsm", "network_hsm") and a.get("pqc_capable") for a in accels)
    hsm_present_but_not_pqc = hsm_present and not hsm_pqc_capable

    bench: dict[str, Any] = {}
    membw: float | None = None
    membw_method = ""
    if args.bench:
        bench = run_benchmarks(seconds=args.seconds, threads=max(args.threads, 1))
        membw, membw_method = memory_bandwidth_probe()

    cores_for_estimate = physical or logical or 1
    palg = per_algo_verdict(bench, cores_for_estimate) if bench else {}
    pest = production_estimate(palg, total_gb) if palg else {}
    verdict, why, code = overall_verdict(isa_t, mem_t, dedicated, palg)
    why = f"{why} ISA: {isa_reason}. Memory: {mem_reason}."

    r = Report(
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        hostname=socket.gethostname(),
        os=f"{platform.system()} {platform.release()}",
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
        trust_store=trust_store_info,
        benchmark=bench,
        per_algo=palg,
        production_estimate=pest,
        verdict=verdict,
        verdict_reason=why,
        exit_code=code,
    )

    if args.save:
        d = Path.home() / ".cache" / "pqc-readiness"
        d.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        fp = d / f"{r.hostname}-{ts}.json"
        fp.write_text(json.dumps(asdict(r), indent=2))

    if args.json:
        print(json.dumps(asdict(r), indent=2))
    elif args.markdown:
        print(render_markdown(r))
    elif args.quiet:
        print(r.verdict)
    else:
        print(render_text(r))

    if args.check:
        rank = {"poor": 0, "marginal": 1, "good": 2, "excellent": 3}
        cur = "excellent" if r.exit_code == 0 else "good" if r.exit_code == 1 else "marginal" if r.exit_code == 2 else "poor"
        if rank[cur] < rank[args.check]:
            return 4
    return r.exit_code


if __name__ == "__main__":
    sys.exit(main())
