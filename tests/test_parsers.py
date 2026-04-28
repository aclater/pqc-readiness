# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the pure parsing functions in pqc_readiness."""
from __future__ import annotations

from pathlib import Path

import pytest

from conftest import FIXTURES
import pqc_readiness as pr


# ---------------------------------------------------------------------------
# parse_speed_row — OpenSSL PQC speed output
# ---------------------------------------------------------------------------

def _read(p: Path) -> str:
    return p.read_text()


def test_parse_speed_row_ml_kem_768() -> None:
    text = _read(FIXTURES / "openssl-speed" / "ml-kem-768.txt")
    rates = pr.parse_speed_row(text, "ML-KEM-768",
                               ("keygen/s", "encaps/s", "decaps/s"))
    assert rates is not None
    assert rates["keygen/s"] > 1000
    assert rates["encaps/s"] > 1000
    assert rates["decaps/s"] > 1000


def test_parse_speed_row_ml_dsa_65() -> None:
    text = _read(FIXTURES / "openssl-speed" / "ml-dsa-65.txt")
    rates = pr.parse_speed_row(text, "ML-DSA-65",
                               ("keygen/s", "sign/s", "verify/s"))
    assert rates is not None
    assert rates["sign/s"] > 100
    assert rates["verify/s"] > 1000


def test_parse_speed_row_slh_dsa() -> None:
    text = _read(FIXTURES / "openssl-speed" / "slh-dsa-sha2-128s.txt")
    rates = pr.parse_speed_row(text, "SLH-DSA-SHA2-128s",
                               ("keygen/s", "sign/s", "verify/s"))
    assert rates is not None
    # SLH-DSA-128s is intentionally slow; verify the parser still pulls
    # the integer-or-float rate row instead of bailing on integer values.
    assert rates["sign/s"] > 0


def test_parse_speed_row_handles_integer_rates() -> None:
    """Regression: previous regex \\d+\\.\\d+ missed integer-only ops/sec
    columns that appear in some OpenSSL builds for very slow algorithms."""
    text = ("                  keygen     signs    verify keygens/s    sign/s  verify/s\n"
            "        ALGO 1.000000s 0.500000s 0.001000s        1         2      1000\n")
    rates = pr.parse_speed_row(text, "ALGO", ("keygen/s", "sign/s", "verify/s"))
    assert rates == {"keygen/s": 1.0, "sign/s": 2.0, "verify/s": 1000.0}


def test_parse_speed_row_handles_prefix_lines() -> None:
    """Some OpenSSL builds prefix the row with parameter strings."""
    text = ("                              keygen    encaps    decaps keygens/s  encaps/s  decaps/s\n"
            "[someparam=foo]   ML-KEM-768 0.000027s 0.000017s 0.000026s   37542.4   59259.0   38383.0\n")
    rates = pr.parse_speed_row(text, "ML-KEM-768",
                               ("keygen/s", "encaps/s", "decaps/s"))
    assert rates is not None
    assert rates["decaps/s"] == 38383.0


def test_parse_speed_row_missing_algo_returns_none() -> None:
    text = "no relevant content here"
    assert pr.parse_speed_row(text, "ML-KEM-768",
                              ("keygen/s", "encaps/s", "decaps/s")) is None


# ---------------------------------------------------------------------------
# parse_classical_speed — RSA / EdDSA / ECDH baseline
# ---------------------------------------------------------------------------

def test_parse_classical_speed_finds_rsa_eddsa_ecdh() -> None:
    text = _read(FIXTURES / "openssl-speed" / "classical.txt")
    out = pr.parse_classical_speed(text)
    # RSA-2048 has sign/verify/encr/decr columns
    assert "rsa" in out or any("rsa" in k for k in out), f"no rsa in {list(out)}"
    # Ed25519 has sign/verify
    eddsa_keys = [k for k in out if "ed25519" in k.lower() or "eddsa" in k.lower()]
    assert eddsa_keys, f"no Ed25519 row in {list(out)}"
    # ECDH X25519 has op/s
    ecdh_keys = [k for k in out if "ecdh" in k.lower() or "x25519" in k.lower()]
    assert ecdh_keys, f"no ECDH/X25519 row in {list(out)}"


# ---------------------------------------------------------------------------
# detect_fips_mode_from_providers_text — record-based provider parser
# ---------------------------------------------------------------------------

def test_fips_provider_not_loaded() -> None:
    text = _read(FIXTURES / "openssl-providers.txt")
    assert pr.detect_fips_mode_from_providers_text(text) is False


def test_fips_provider_loaded_and_active() -> None:
    text = (
        "Providers:\n"
        "  default\n"
        "    name: OpenSSL Default Provider\n"
        "    status: active\n"
        "  fips\n"
        "    name: Red Hat FIPS Provider\n"
        "    version: 3.5.5\n"
        "    status: active\n"
    )
    assert pr.detect_fips_mode_from_providers_text(text) is True


def test_fips_provider_loaded_but_inactive() -> None:
    """A loaded-but-inactive FIPS provider must NOT register as enabled."""
    text = (
        "Providers:\n"
        "  default\n"
        "    status: active\n"
        "  fips\n"
        "    name: FIPS Provider\n"
        "    status: inactive\n"
    )
    assert pr.detect_fips_mode_from_providers_text(text) is False


# ---------------------------------------------------------------------------
# parse_lszcrypt — IBM Z Crypto Express enumeration
# ---------------------------------------------------------------------------

def test_parse_lszcrypt_cex8_mixed_finds_ep11() -> None:
    text = _read(FIXTURES / "lszcrypt" / "cex8-mixed.txt")
    adapters = pr.parse_lszcrypt(text)
    cards = [a for a in adapters if a["domain"] is None]  # card rows, not queue rows
    assert len(cards) >= 3
    levels = sorted({a["level"] for a in cards})
    assert 8 in levels
    modes = {a["mode"] for a in cards}
    assert "EP11" in modes
    assert "CCA" in modes
    assert "Accelerator" in modes
    # PQC-eligible: CEX8 + EP11
    pqc = [a for a in adapters if a["pqc_eligible"]]
    assert pqc, "expected at least one CEX8 EP11 adapter to be PQC-eligible"


def test_parse_lszcrypt_cex5_only_no_pqc() -> None:
    text = _read(FIXTURES / "lszcrypt" / "cex5-cca-only.txt")
    adapters = pr.parse_lszcrypt(text)
    pqc = [a for a in adapters if a["pqc_eligible"]]
    assert not pqc, "CEX5 must never qualify as PQC silicon"


# ---------------------------------------------------------------------------
# has_dedicated_pqc_silicon — explicit allowlist behavior
# ---------------------------------------------------------------------------

def test_has_dedicated_pqc_silicon_rejects_generic_hsm() -> None:
    """Regression: previous implementation returned True for any kind=='hsm'.
    Generic Marvell/Thales/Utimaco HSMs without confirmed PQC firmware MUST
    not register as dedicated PQC silicon."""
    accels = [{"kind": "hsm", "name": "Marvell/Cavium Nitrox", "detail": "01:00.0 ..."}]
    assert pr.has_dedicated_pqc_silicon("x86_64", set(), accels) is False


def test_has_dedicated_pqc_silicon_accepts_cex8_ep11() -> None:
    """IBM CEX8 in EP11 mode is the only generally-available PQC silicon today."""
    accels = [{
        "kind": "hsm",
        "name": "IBM Crypto Express 8 (EP11)",
        "detail": "card=01 mode=EP11 status=online",
        "pqc_capable": True,
    }]
    assert pr.has_dedicated_pqc_silicon("s390x", {"msa8", "msa9"}, accels) is True


# ---------------------------------------------------------------------------
# Section 2: detection coverage parsers
# ---------------------------------------------------------------------------

def test_parse_ssh_kex_finds_pqc() -> None:
    text = _read(FIXTURES / "ssh-kex-rhel10.txt")
    out = pr.parse_ssh_kex(text)
    assert out["available"]
    assert out["kex_count"] > 5
    pqc = out["pqc_kex"]
    assert any("mlkem" in k for k in pqc)
    assert any("sntrup" in k for k in pqc)


def test_parse_ssh_kex_no_pqc() -> None:
    text = "diffie-hellman-group14-sha256\necdh-sha2-nistp256\ncurve25519-sha256\n"
    out = pr.parse_ssh_kex(text)
    assert out["available"]
    assert out["kex_count"] == 3
    assert out["pqc_kex"] == []


# ---------------------------------------------------------------------------
# parse_redhat_release
# ---------------------------------------------------------------------------

def test_parse_redhat_release_rhel() -> None:
    out = pr.parse_redhat_release("Red Hat Enterprise Linux release 9.4 (Plow)")
    assert out["distro"] == "Red Hat Enterprise Linux"
    assert out["version"] == "9.4"
    assert out["minor"] == "4"


def test_parse_redhat_release_rhel10() -> None:
    out = pr.parse_redhat_release("Red Hat Enterprise Linux release 10.0 (Coughlan)")
    assert out["distro"] == "Red Hat Enterprise Linux"
    assert out["version"] == "10.0"
    assert out["minor"] == "0"


def test_parse_redhat_release_centos_no_minor() -> None:
    out = pr.parse_redhat_release("CentOS Stream release 9")
    assert out["distro"] == "CentOS Stream"
    assert out["version"] == "9"
    assert "minor" not in out


# ---------------------------------------------------------------------------
# parse_proc_crypto_pqc
# ---------------------------------------------------------------------------

def test_parse_proc_crypto_pqc_finds_kyber() -> None:
    text = (
        "name         : kyber768\n"
        "driver       : kyber768-generic\n"
        "module       : kernel\n"
        "priority     : 0\n"
        "\n"
        "name         : sha256\n"
        "driver       : sha256-ssse3\n"
        "module       : kernel\n"
        "priority     : 200\n"
        "\n"
    )
    drivers = pr.parse_proc_crypto_pqc(text)
    assert drivers == ["kyber768-generic"]


def test_parse_proc_crypto_pqc_no_pqc() -> None:
    text = (
        "name         : sha256\n"
        "driver       : sha256-ssse3\n"
        "module       : kernel\n"
        "priority     : 200\n"
        "\n"
    )
    assert pr.parse_proc_crypto_pqc(text) == []


# ---------------------------------------------------------------------------
# parse_nss_version
# ---------------------------------------------------------------------------

def test_parse_nss_version_pqc_capable() -> None:
    assert pr.parse_nss_version("3.108.0") == (3, 108, 0)


def test_parse_nss_version_predates_pqc() -> None:
    assert pr.parse_nss_version("3.79.4") == (3, 79, 4)


def test_parse_nss_version_unparseable() -> None:
    assert pr.parse_nss_version("garbage") is None


# ---------------------------------------------------------------------------
# fips_pqc_conflict_check
# ---------------------------------------------------------------------------

def test_fips_pqc_conflict_no_fips() -> None:
    fips = {"kernel": False, "openssl_provider": False}
    openssl = {"kem_algorithms": ["ML-KEM-768"]}
    out = pr.fips_pqc_conflict_check(fips, openssl)
    assert out["in_conflict"] is False


def test_fips_pqc_conflict_fips_no_pqc() -> None:
    fips = {"kernel": True, "openssl_provider": True}
    openssl = {"kem_algorithms": [], "sig_algorithms": []}
    out = pr.fips_pqc_conflict_check(fips, openssl)
    assert out["in_conflict"] is False


def test_fips_pqc_conflict_real_conflict() -> None:
    """Kernel FIPS on, OpenSSL exposing PQC via default provider — the
    case the spec calls out as the meaningful conflict."""
    fips = {"kernel": True, "openssl_provider": False}
    openssl = {"kem_algorithms": ["ML-KEM-768"], "sig_algorithms": ["ML-DSA-65"]}
    out = pr.fips_pqc_conflict_check(fips, openssl)
    assert out["in_conflict"] is True
    assert "FIPS" in out["explanation"]


# ---------------------------------------------------------------------------
# parse_lszcrypt edge case: malformed line
# ---------------------------------------------------------------------------

def test_parse_lszcrypt_skips_malformed_lines() -> None:
    text = "garbage line\n00 CEX9X CCA-Coproc online 0\n"
    # CEX9 + suffix X is not in the allowed mode set; pattern won't match (only C/P/A)
    assert pr.parse_lszcrypt(text) == []


# ---------------------------------------------------------------------------
# Section 3: ISA detection / tier across reference CPUs
# ---------------------------------------------------------------------------

def _isa_for(arch: str, fixture: str) -> tuple[set[str], dict[str, dict[str, str]], int, str]:
    text = (FIXTURES / "cpuinfo" / fixture).read_text()
    flags = pr.parse_cpuinfo_flags(text)
    feats, score = pr.detect_isa(arch, flags)
    tier, _reason = pr.isa_tier(arch, score, flags)
    return flags, feats, score, tier


def test_isa_skylake_x_is_good_not_excellent() -> None:
    """Skylake-X has AVX-512F but lacks AVX-512 VBMI/IFMA and VAES;
    the AVX-512 PQC fast paths are not available, so the host must
    score 'good', not 'excellent'."""
    flags, feats, score, tier = _isa_for("x86_64", "skylake-x-flags.txt")
    assert "avx512f" in flags
    assert "avx512vbmi" not in flags
    assert "avx512ifma" not in flags
    assert "vaes" not in flags
    assert tier == "good"


def test_isa_sapphire_rapids_is_excellent() -> None:
    flags, feats, score, tier = _isa_for("x86_64", "sapphire-rapids-flags.txt")
    assert {"avx512vbmi", "avx512ifma", "vaes", "vpclmulqdq", "gfni"}.issubset(flags)
    assert tier == "excellent"


def test_isa_zen4_is_excellent() -> None:
    flags, feats, score, tier = _isa_for("x86_64", "zen4-flags.txt")
    assert {"avx512vbmi", "avx512ifma", "vaes", "gfni"}.issubset(flags)
    assert tier == "excellent"


def test_isa_graviton3_is_excellent_due_to_sve2_plus_sha3() -> None:
    """Graviton 3 (Neoverse V1) ships SHA-3 + SVE2 + I8MM; per the spec
    revision the I8MM weight bump should help push the score over the
    excellent threshold."""
    flags, feats, score, tier = _isa_for("aarch64", "graviton3-flags.txt")
    assert "sha3" in flags and "sve2" in flags and "i8mm" in flags
    assert tier == "excellent"


def test_isa_arm_i8mm_weight_is_two() -> None:
    """Regression: I8MM was weight 1 in v1; bumped to 2 for Section 3."""
    assert pr.ARM_FEATURES["i8mm"][2] == 2


# ---------------------------------------------------------------------------
# Section 3: per-algorithm verdict notes + memory-bandwidth gating +
# overall-verdict caveat for missing benchmark
# ---------------------------------------------------------------------------

def test_per_algo_verdict_emits_slh_dsa_note() -> None:
    bench = {"available": True, "pqc": {"SLH-DSA-SHA2-128s": {"sign/s": 6.0}}}
    out = pr.per_algo_verdict(bench, cores=8)
    slh = out["SLH-DSA-SHA2-128s"]
    assert slh["tier"] == "excellent"
    assert any("hot-path" in n for n in slh["notes"])


def test_per_algo_verdict_downgrades_slh_dsa_on_low_memory_bandwidth() -> None:
    bench = {"available": True, "pqc": {"SLH-DSA-SHA2-128s": {"sign/s": 6.0}}}
    out = pr.per_algo_verdict(bench, cores=8, mem_bw_gb_s=4.0)
    slh = out["SLH-DSA-SHA2-128s"]
    assert slh["tier"] == "good", "tier should drop excellent -> good"
    assert any("downgraded" in n.lower() for n in slh["notes"])


def test_per_algo_verdict_no_downgrade_when_bandwidth_unmeasured() -> None:
    bench = {"available": True, "pqc": {"SLH-DSA-SHA2-128s": {"sign/s": 6.0}}}
    out = pr.per_algo_verdict(bench, cores=8, mem_bw_gb_s=None)
    slh = out["SLH-DSA-SHA2-128s"]
    assert slh["tier"] == "excellent"
    assert not any("downgraded" in n.lower() for n in slh["notes"])


def test_per_algo_verdict_includes_ml_dsa_verify_threshold() -> None:
    bench = {"available": True, "pqc": {"ML-DSA-65": {"sign/s": 1700, "verify/s": 9000}}}
    out = pr.per_algo_verdict(bench, cores=8)
    assert "ML-DSA-65/verify" in out
    assert out["ML-DSA-65/verify"]["tier"] == "excellent"


def test_overall_verdict_no_caveat_when_bench_present() -> None:
    palg = {
        "ML-KEM-768": {"tier": "excellent"},
        "ML-DSA-65":  {"tier": "excellent"},
    }
    verdict, why, code, caveat = pr.overall_verdict("excellent", "excellent", False, palg)
    assert code == 0
    assert caveat == ""


def test_overall_verdict_adds_caveat_when_bench_unavailable() -> None:
    """No benchmark data must NOT drag a high-ISA / high-mem host to POOR."""
    palg: dict[str, dict[str, str]] = {}
    verdict, why, code, caveat = pr.overall_verdict("excellent", "excellent", False, palg)
    assert code == 0
    assert "no PQC microbenchmark" in caveat


def test_overall_verdict_caveat_with_unknown_only_per_algo() -> None:
    palg = {
        "ML-KEM-768": {"tier": "unknown"},
        "ML-DSA-65":  {"tier": "unknown"},
    }
    verdict, why, code, caveat = pr.overall_verdict("excellent", "excellent", False, palg)
    assert code == 0
    assert caveat != ""


# ---------------------------------------------------------------------------
# Section 4: container / package / aggregator parsers
# ---------------------------------------------------------------------------

def test_parse_cgroup_for_container_kubepods() -> None:
    cg = "12:cpu,cpuacct:/kubepods.slice/kubepods-pod1234.slice/cri-containerd-abcd.scope\n"
    assert pr.parse_cgroup_for_container(cg) == "kubepods"


def test_parse_cgroup_for_container_docker() -> None:
    cg = "11:devices:/docker/0123456789ab\n"
    assert pr.parse_cgroup_for_container(cg) == "/docker/"


def test_parse_cgroup_for_container_bare_metal() -> None:
    cg = "11:devices:/init.scope\n0::/user.slice/user-1000.slice/session-2.scope\n"
    assert pr.parse_cgroup_for_container(cg) is None


def test_parse_rpm_packages() -> None:
    text = "openssl 3.5.5\nnss 3.122.1\nnss 3.122.1\njava-21-openjdk 21.0.5\n"
    out = pr.parse_rpm_packages(text)
    assert ("openssl", "3.5.5") in out
    assert ("java-21-openjdk", "21.0.5") in out
    assert len(out) == 4


def test_classify_bundled_crypto_finds_jdk_and_node_dedupes() -> None:
    pkgs = [
        ("openssl", "3.5.5"),
        ("java-21-openjdk", "21.0.5"),
        ("java-21-openjdk-headless", "21.0.5"),
        ("nodejs", "22.10.0"),
        ("python3", "3.13.5"),
        ("nss", "3.122.1"),
    ]
    out = pr.classify_bundled_crypto(pkgs)
    names = sorted(p["package"] for p in out)
    # java-21-openjdk-headless matches via prefix; both jdk packages dedupe by exact name
    assert "java-21-openjdk" in names
    assert "java-21-openjdk-headless" in names
    assert "nodejs" in names
    assert "python3" in names
    # openssl + nss are not in the bundled-crypto allowlist (they ARE the
    # system crypto, not a bundled override)
    assert "openssl" not in names
    assert "nss" not in names


def test_aggregate_reports_basic_counts() -> None:
    reports = [
        {"schema_version": "1.0", "arch": "x86_64", "isa_tier": "excellent",
         "verdict": "EXCELLENT - software PQC at production speed",
         "cpu_model": "AMD EPYC", "kernel_info": {"os_release_id": "rhel"},
         "runtime_environment": {"environment": "host"},
         "accelerators": [{"kind": "tpm"}],
         "replace_required": False},
        {"schema_version": "1.0", "arch": "x86_64", "isa_tier": "good",
         "verdict": "GOOD - production-capable in software",
         "cpu_model": "Intel Xeon", "kernel_info": {"os_release_id": "rhel"},
         "runtime_environment": {"environment": "container"},
         "accelerators": [{"kind": "hsm"}, {"kind": "tpm"}],
         "replace_required": False},
        {"schema_version": "1.0", "arch": "aarch64", "isa_tier": "poor",
         "verdict": "POOR - not suitable for production PQC",
         "cpu_model": "Old ARM", "kernel_info": {"os_release_id": "fedora"},
         "runtime_environment": {"environment": "host"},
         "accelerators": [],
         "replace_required": True},
    ]
    out = pr.aggregate_reports(reports)
    assert out["total_hosts"] == 3
    assert out["by_arch"] == {"x86_64": 2, "aarch64": 1}
    assert out["by_isa_tier"] == {"excellent": 1, "good": 1, "poor": 1}
    assert out["by_runtime_environment"] == {"host": 2, "container": 1}
    assert out["replace_required_count"] == 1
    assert out["accelerator_kinds_host_count"] == {"tpm": 2, "hsm": 1}
    assert "AMD EPYC" in out["unique_cpu_models"]


def test_aggregate_to_csv_renders_groups() -> None:
    rollup = {
        "total_hosts": 2,
        "replace_required_count": 0,
        "by_arch": {"x86_64": 2},
        "by_isa_tier": {"excellent": 2},
        "unique_cpu_models": ["AMD EPYC"],
    }
    csv_text = pr.aggregate_to_csv(rollup)
    assert "group,key,count" in csv_text
    assert "total_hosts,,2" in csv_text
    assert "by_arch,x86_64,2" in csv_text
    assert "unique_cpu_models,AMD EPYC,1" in csv_text


# ---------------------------------------------------------------------------
# Section 4: host_path prefixing
# ---------------------------------------------------------------------------

def test_host_path_no_prefix_leaves_path_unchanged() -> None:
    # HOST_PREFIX is "" by default; host_path returns Path(p) verbatim.
    assert str(pr.host_path("/proc/cpuinfo")) == "/proc/cpuinfo"


def test_host_path_prefix_redirects_kernel_namespaces() -> None:
    saved = pr.HOST_PREFIX
    try:
        pr.HOST_PREFIX = "/host"
        assert str(pr.host_path("/proc/cpuinfo")) == "/host/proc/cpuinfo"
        assert str(pr.host_path("/sys/module/tls")) == "/host/sys/module/tls"
        assert str(pr.host_path("/etc/redhat-release")) == "/host/etc/redhat-release"
        assert str(pr.host_path("/dev/tpm0")) == "/host/dev/tpm0"
        # User-space paths are not redirected
        assert str(pr.host_path("/opt/Chrystoki")) == "/opt/Chrystoki"
        assert str(pr.host_path("/tmp/foo")) == "/tmp/foo"
    finally:
        pr.HOST_PREFIX = saved
