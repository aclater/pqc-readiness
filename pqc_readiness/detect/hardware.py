"""CPU, memory, ISA tiers, accelerators, TPM, kernel crypto drivers and kTLS."""

from __future__ import annotations

import functools
import logging
import os
import platform
import re
import shutil
from pathlib import Path
from typing import Any

from .. import _platform as _platform
from ..detect import runtime as _runtime

log = logging.getLogger("pqc-readiness")


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
        return parse_cpuinfo_flags(_platform.host_path("/proc/cpuinfo").read_text())
    except OSError as e:
        log.debug("linux_cpu_flags: cannot read /proc/cpuinfo: %s", e)
        return set()


def macos_cpu_flags(arch: str) -> set[str]:
    flags: set[str] = set()
    if arch in ("x86_64", "amd64"):
        for key, _ in MACOS_X86_SYSCTL.items():
            tokens = _platform._sysctl(key).split()
            for tok in tokens:
                norm = MACOS_X86_TO_LINUX.get(tok.upper())
                if norm:
                    flags.add(norm)
    elif arch in ("arm64", "aarch64"):
        for key, norm in MACOS_ARM_SYSCTLS.items():
            if _platform._sysctl(key) == "1":
                flags.add(norm)
    return flags


def cpu_flags(arch: str) -> set[str]:
    if _platform.is_linux():
        return linux_cpu_flags()
    if _platform.is_macos():
        return macos_cpu_flags(arch)
    return set()


def cpu_model() -> str:
    if _platform.is_linux():
        try:
            for line in _platform.host_path("/proc/cpuinfo").read_text().splitlines():
                if line.startswith(("model name", "Hardware", "cpu model", "machine")):
                    return line.split(":", 1)[1].strip()
        except OSError as e:
            log.debug("cpu_model: cannot read /proc/cpuinfo: %s", e)
    if _platform.is_macos():
        m = _platform._sysctl("machdep.cpu.brand_string")
        if m:
            return m
    return platform.processor() or platform.machine()


def cpu_freq_mhz() -> float:
    if _platform.is_linux():
        for path in (
            "/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq",
            "/sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq",
        ):
            try:
                return int(Path(path).read_text().strip()) / 1000.0
            except (OSError, ValueError) as e:
                log.debug("cpu_freq_mhz: cannot read %s: %s", path, e)
                continue
        try:
            for line in _platform.host_path("/proc/cpuinfo").read_text().splitlines():
                if "cpu MHz" in line:
                    return float(line.split(":", 1)[1].strip())
        except OSError as e:
            log.debug("cpu_freq_mhz: cannot read /proc/cpuinfo: %s", e)
    if _platform.is_macos():
        v = _platform._sysctl("hw.cpufrequency_max")
        try:
            return float(v) / 1_000_000 if v else 0.0
        except ValueError as e:
            log.debug("cpu_freq_mhz: unparseable hw.cpufrequency_max %r: %s", v, e)
    return 0.0


def core_counts() -> tuple[int, int]:
    logical = os.cpu_count() or 0
    physical = 0
    if _platform.is_linux():
        try:
            text = _platform.host_path("/proc/cpuinfo").read_text()
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
        except OSError as e:
            log.debug("core_counts: cannot read /proc/cpuinfo: %s", e)
            physical = logical
    elif _platform.is_macos():
        try:
            physical = int(_platform._sysctl("hw.physicalcpu") or "0") or logical
            logical = int(_platform._sysctl("hw.logicalcpu") or str(logical))
        except ValueError as e:
            log.debug("core_counts: unparseable hw.physicalcpu/hw.logicalcpu: %s", e)
            physical = logical
    return logical, physical


def memory_info() -> tuple[float, float]:
    total = avail = 0.0
    if _platform.is_linux():
        try:
            for line in _platform.host_path("/proc/meminfo").read_text().splitlines():
                k, _, v = line.partition(":")
                v = v.strip().split()[0] if v.strip() else "0"
                if k == "MemTotal":
                    total = int(v) / 1024 / 1024
                elif k == "MemAvailable":
                    avail = int(v) / 1024 / 1024
        except OSError as e:
            log.debug("memory_info: cannot read /proc/meminfo: %s", e)
    elif _platform.is_macos():
        try:
            total = int(_platform._sysctl("hw.memsize") or "0") / (1024**3)
        except ValueError as e:
            log.debug("memory_info: unparseable hw.memsize: %s", e)
        rc, out = _platform._run(["vm_stat"], timeout=3)
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


# Per-role memory thresholds in GiB for the "good" tier.  Driven by
# per-connection memory math: TLS terminator at ~192 KB realistic per
# PQC TLS connection × concurrent-connection target gives 16 GiB; a
# signing service with ML-DSA-87 working memory of ~120 KB × concurrent
# signing target gives 8 GiB; firmware signing has low concurrency and
# large signatures (2 GiB is enough); a TLS client only originates a
# small number of connections (4 GiB).  "generic" preserves the prior
# single-threshold behavior (16 GiB) for back-compat with reports that
# pre-date role-aware tiering.
MEMORY_TIER_GOOD_THRESHOLD_BY_ROLE: dict[str, float] = {
    "tls-server": 16.0,
    "tls-client": 4.0,
    "signing-service": 8.0,
    "firmware-signing": 2.0,
    "generic": 16.0,
}


def memory_tier(gb: float, role: str = "generic") -> tuple[str, str]:
    """Classify total memory into a tier for a given workload role.

    The "excellent" and "poor" thresholds are role-independent — only the
    boundary between "marginal" and "good" varies by role, since that's
    the boundary driven by per-connection / per-operation working memory
    math.  Roles other than the five enumerated in
    `MEMORY_TIER_GOOD_THRESHOLD_BY_ROLE` fall back to the generic tier.
    """
    threshold_good = MEMORY_TIER_GOOD_THRESHOLD_BY_ROLE.get(
        role, MEMORY_TIER_GOOD_THRESHOLD_BY_ROLE["generic"]
    )
    if gb >= 64:
        return (
            "excellent",
            f"{gb:.1f} GiB - comfortable for high-throughput TLS/PQC at scale",
        )
    if gb >= threshold_good:
        return (
            "good",
            f"{gb:.1f} GiB >= {threshold_good:.0f} GiB threshold for role={role}",
        )
    if gb >= 4:
        return (
            "marginal",
            f"{gb:.1f} GiB below {threshold_good:.0f} GiB threshold for role={role} - OK for low-volume or edge",
        )
    return ("poor", f"{gb:.1f} GiB - insufficient for production PQC services")


def memory_tier_all_roles(gb: float) -> dict[str, dict[str, Any]]:
    """Return tier evaluations for every known role keyed by role name."""
    out: dict[str, dict[str, Any]] = {}
    for role, threshold in MEMORY_TIER_GOOD_THRESHOLD_BY_ROLE.items():
        tier, reason = memory_tier(gb, role)
        out[role] = {
            "tier": tier,
            "reason": reason,
            "threshold_gib_good": threshold,
        }
    return out


# ---------------------------------------------------------------------------
# Accelerator detection
# ---------------------------------------------------------------------------


def detect_accelerators() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if shutil.which("lspci"):
        rc, data = _platform._run(["lspci", "-nn"], timeout=10)
        if rc == 0:
            for line in data.splitlines():
                for pat, label, kind in ACCEL_PCI_HINTS:
                    if re.search(pat, line, re.IGNORECASE):
                        out.append(
                            {"kind": kind, "name": label, "detail": line.strip()}
                        )
    for path, label, kind in DEVICE_HINTS:
        if _platform.safe_exists(_platform.host_path(path)):
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
    note = _platform.host_fs_unavailable_note(
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
        p = _platform.host_path(d)
        if not _platform.safe_is_dir(p):
            continue
        for sub in p.rglob("*.so"):
            found.add(str(sub))
        for sub in p.rglob("*.dylib"):
            found.add(str(sub))
    return sorted(found)


def detect_tpm_pqc() -> dict[str, Any]:
    note = _platform.host_fs_unavailable_note(
        "TPM PQC detection", "/dev/tpmrm0, /dev/tpm0 and tpm2_getcap"
    )
    if not shutil.which("tpm2_getcap"):
        out: dict[str, Any] = {
            "present": _platform.safe_exists(_platform.host_path("/dev/tpmrm0"))
            or _platform.safe_exists(_platform.host_path("/dev/tpm0")),
            "tools": False,
            "note": "tpm2-tools not installed; TPM 2.0 chips today do not implement NIST PQC",
        }
        if note:
            out.update(note)
        return out
    rc, out_text = _platform._run(["tpm2_getcap", "algorithms"], timeout=5)
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
    if not _platform.is_linux():
        return []
    try:
        text = _platform.host_path("/proc/crypto").read_text()
    except OSError as e:
        log.debug("detect_kernel_crypto_hw: cannot read /proc/crypto: %s", e)
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
    if not _platform.is_linux():
        return None
    try:
        mods = _platform.host_path("/proc/modules").read_text()
        if "tls " in mods:
            return True
    except OSError as e:
        log.debug("detect_ktls: cannot read /proc/modules: %s", e)
    if _platform.safe_exists(_platform.host_path("/sys/module/tls")):
        return True
    rc, out = _platform._run(["modinfo", "tls"], timeout=3)
    return rc == 0 and "filename" in out


def detect_kernel_crypto_hw_annotated() -> dict[str, Any]:
    """Dict-returning sibling of detect_kernel_crypto_hw(), mirroring
    detect_pci_accelerators().  Returns the driver list under `items`
    plus an `unavailable_in_container` annotation when /proc/crypto is
    the container's view rather than the host's.  The Report field
    `kernel_crypto_hw` keeps its list type; the annotation reaches JSON
    via `host_fs_detections_unavailable`."""
    out: dict[str, Any] = {"items": detect_kernel_crypto_hw()}
    note = _runtime._host_fs_note_for("kernel_crypto_hw")
    if note:
        out.update(note)
    return out


def detect_ktls_annotated() -> dict[str, Any]:
    """Dict-returning sibling of detect_ktls().  Returns the tri-state
    result under `supported` plus an `unavailable_in_container`
    annotation when /proc/modules and /sys/module/tls reflect the
    container rather than the host."""
    out: dict[str, Any] = {"supported": detect_ktls()}
    note = _runtime._host_fs_note_for("ktls")
    if note:
        out.update(note)
    return out


# `openssl list -providers -verbose` is constant for the process lifetime
# and serves both FIPS detection and the provider list in
# openssl_capability(); one cached call replaces two subprocesses (#117).
@functools.lru_cache(maxsize=None)
def _openssl_providers_verbose_text() -> tuple[int, str]:
    """Return cached (rc, text) from `openssl list -providers -verbose`.
    Tests requiring a fresh subprocess call must invoke .cache_clear()."""
    return _platform._run(["openssl", "list", "-providers", "-verbose"], timeout=5)


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
    rc, out = _platform._run(["lszcrypt", "-V"], timeout=5)
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
        p = _platform.host_path(path)
        if not _platform.safe_exists(p):
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
