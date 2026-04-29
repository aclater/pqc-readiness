# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the pure parsing functions in pqc_readiness."""
from __future__ import annotations

from pathlib import Path

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


# ISA tier vocabulary must match what `--check` accepts.  isa_tier()
# previously returned "adequate" for AVX2-only x86, ARM without SHA-3,
# and pre-MSA8 s390x — values that argparse rejected with an error.  See
# audit issue #39.  The same vocabulary must hold for memory_tier(),
# which contributes to the same overall verdict that --check gates on.
_TIER_CHECK_CHOICES = {"excellent", "good", "marginal", "poor"}


def test_isa_tier_avx2_only_x86_is_marginal_not_adequate() -> None:
    """Regression for #39: AVX2-only x86 returned "adequate", which is
    not a value `--check` accepts.  Must be "marginal"."""
    flags = {"avx2"}
    tier, _reason = pr.isa_tier("x86_64", score=4, flags=flags)
    assert tier == "marginal"


def test_isa_tier_arm_without_sha3_is_marginal() -> None:
    """Regression for #39: ARM without SHA-3 / AES extensions returned
    "adequate"; must be "marginal"."""
    tier, _reason = pr.isa_tier("aarch64", score=0, flags=set())
    assert tier == "marginal"


def test_isa_tier_s390x_pre_msa8_is_marginal() -> None:
    """Regression for #39: s390x with MSA but pre-MSA8 returned
    "adequate"; must be "marginal"."""
    tier, _reason = pr.isa_tier("s390x", score=0, flags={"msa"})
    assert tier == "marginal"


def test_memory_tier_mid_range_is_marginal() -> None:
    """Regression for #39: 4-16 GiB memory returned "adequate"; must be
    "marginal" so it lines up with the isa_tier vocabulary and the
    `--check` choices."""
    tier, _reason = pr.memory_tier(8.0)
    assert tier == "marginal"


def test_isa_tier_return_values_are_subset_of_check_choices() -> None:
    """Every value isa_tier() can return for a classified architecture
    must be accepted by `--check`.  Walk every branch of the function
    and assert the tier is in the documented vocabulary."""
    cases: list[tuple[str, int, set[str]]] = [
        # x86_64
        ("x86_64", 20, {"avx512f", "avx512vbmi", "avx512ifma"}),  # excellent
        ("x86_64", 8, {"avx2", "aes", "pclmulqdq"}),              # good
        ("x86_64", 4, {"avx2"}),                                  # marginal
        ("x86_64", 0, set()),                                     # poor
        # aarch64
        ("aarch64", 10, {"sha3", "aes", "sve2"}),                 # excellent
        ("aarch64", 4, {"sha3", "aes"}),                          # good
        ("aarch64", 0, set()),                                    # marginal
        # s390x
        ("s390x", 0, {"msa", "msa8", "msa9"}),                    # excellent
        ("s390x", 0, {"msa"}),                                    # marginal
        ("s390x", 0, set()),                                      # poor
    ]
    for arch, score, flags in cases:
        tier, _ = pr.isa_tier(arch, score, flags)
        assert tier in _TIER_CHECK_CHOICES, (
            f"isa_tier({arch!r}, {score}, {flags!r}) returned "
            f"{tier!r}, which `--check` does not accept"
        )


def test_memory_tier_return_values_are_subset_of_check_choices() -> None:
    """Every memory_tier() return value must also be in the `--check`
    vocabulary, since it feeds the same overall verdict."""
    for gb in (128.0, 32.0, 8.0, 1.0):
        tier, _ = pr.memory_tier(gb)
        assert tier in _TIER_CHECK_CHOICES, (
            f"memory_tier({gb}) returned {tier!r}, which `--check` "
            "does not accept"
        )


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
    assert {"name": "openssl", "version": "3.5.5"} in out
    assert {"name": "java-21-openjdk", "version": "21.0.5"} in out
    assert len(out) == 4


def test_classify_bundled_crypto_rhel_finds_jdk_and_node_dedupes() -> None:
    pkgs = [
        {"name": "openssl",                  "version": "3.5.5"},
        {"name": "java-21-openjdk",          "version": "21.0.5"},
        {"name": "java-21-openjdk-headless", "version": "21.0.5"},
        {"name": "nodejs",                   "version": "22.10.0"},
        {"name": "python3",                  "version": "3.13.5"},
        {"name": "nss",                      "version": "3.122.1"},
    ]
    out = pr.classify_bundled_crypto(pkgs, family="rhel")
    names = sorted(p["package"] for p in out)
    assert "java-21-openjdk" in names
    assert "java-21-openjdk-headless" in names
    assert "nodejs" in names
    assert "python3" in names
    # openssl + nss are not in the bundled-crypto allowlist (they ARE the
    # system crypto, not a bundled override).
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


# ---------------------------------------------------------------------------
# parse_proc_crypto_cnsa — symmetric/hash detection for CNSA 2.0
# ---------------------------------------------------------------------------

# Realistic /proc/crypto fragment: AES-NI cipher with 256-bit max keysize,
# SHA-384/SHA-512 with hardware-accel drivers (-avx2 / -ssse3), plus a
# software-only sha256 to confirm the hardware-suffix gate works.
_PROC_CRYPTO_CNSA_HW = (
    "name         : aes\n"
    "driver       : aes-aesni\n"
    "module       : aesni_intel\n"
    "priority     : 300\n"
    "refcnt       : 1\n"
    "selftest     : passed\n"
    "internal     : no\n"
    "type         : cipher\n"
    "blocksize    : 16\n"
    "min keysize  : 16\n"
    "max keysize  : 32\n"
    "\n"
    "name         : sha384\n"
    "driver       : sha384-avx2\n"
    "module       : sha512_ssse3\n"
    "priority     : 170\n"
    "type         : shash\n"
    "blocksize    : 128\n"
    "digestsize   : 48\n"
    "\n"
    "name         : sha512\n"
    "driver       : sha512-avx2\n"
    "module       : sha512_ssse3\n"
    "priority     : 170\n"
    "type         : shash\n"
    "blocksize    : 128\n"
    "digestsize   : 64\n"
    "\n"
    "name         : sha256\n"
    "driver       : sha256-generic\n"
    "module       : kernel\n"
    "priority     : 100\n"
    "type         : shash\n"
    "blocksize    : 64\n"
    "digestsize   : 32\n"
    "\n"
)


def test_parse_proc_crypto_cnsa_finds_aes_256_and_hw_hashes() -> None:
    out = pr.parse_proc_crypto_cnsa(_PROC_CRYPTO_CNSA_HW)
    assert out["aes_256"] is True
    assert out["sha_384_hw_driver"] == "sha384-avx2"
    assert out["sha_512_hw_driver"] == "sha512-avx2"


def test_parse_proc_crypto_cnsa_rejects_software_only_hashes() -> None:
    """SHA-384/512 with a generic / software driver must NOT count as
    hardware-accelerated for CNSA purposes — that's the whole point of
    the hash check."""
    text = (
        "name         : aes\n"
        "driver       : aes-generic\n"
        "max keysize  : 32\n"
        "\n"
        "name         : sha384\n"
        "driver       : sha384-generic\n"
        "\n"
        "name         : sha512\n"
        "driver       : sha512-generic\n"
        "\n"
    )
    out = pr.parse_proc_crypto_cnsa(text)
    assert out["aes_256"] is True
    assert out["sha_384_hw_driver"] is None
    assert out["sha_512_hw_driver"] is None


def test_parse_proc_crypto_cnsa_aes_below_256_not_compliant() -> None:
    """A hypothetical AES driver capped at 192-bit keys must not register
    as AES-256.  Not common in practice, but the parser should not
    silently round up."""
    text = (
        "name         : aes\n"
        "driver       : aes-weird\n"
        "min keysize  : 16\n"
        "max keysize  : 24\n"
        "\n"
    )
    out = pr.parse_proc_crypto_cnsa(text)
    assert out["aes_256"] is False


# ---------------------------------------------------------------------------
# evaluate_cnsa_2_0 — overall compliance classifier
# ---------------------------------------------------------------------------

def test_evaluate_cnsa_2_0_fully_compliant() -> None:
    openssl = {
        "available": True,
        "kem_algorithms": ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"],
        "sig_algorithms": ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"],
    }
    out = pr.evaluate_cnsa_2_0(openssl, _PROC_CRYPTO_CNSA_HW)
    assert out["status"] == "compliant"
    assert out["kem_compliant"] is True
    assert out["signature_compliant"] is True
    assert out["symmetric_compliant"] is True
    assert out["hash_compliant"] is True
    # No gap notes when fully compliant.
    assert out["notes"] == []
    # Requirements echoed back so consumers can verify the version of
    # CNSA 2.0 the report was scored against.
    assert out["requirements"]["kem"] == ["ML-KEM-1024"]
    assert out["requirements"]["signature"] == ["ML-DSA-87"]


def test_evaluate_cnsa_2_0_partial_when_only_ml_kem_768_present() -> None:
    """A host with ML-KEM-768/ML-DSA-65 (the popular defaults) is
    explicitly NOT CNSA 2.0 compliant — the suite mandates the larger
    parameter sets."""
    openssl = {
        "available": True,
        "kem_algorithms": ["ML-KEM-768"],
        "sig_algorithms": ["ML-DSA-65"],
    }
    out = pr.evaluate_cnsa_2_0(openssl, _PROC_CRYPTO_CNSA_HW)
    assert out["status"] == "partial"
    assert out["kem_compliant"] is False
    assert out["signature_compliant"] is False
    assert out["symmetric_compliant"] is True
    assert out["hash_compliant"] is True
    notes_joined = " ".join(out["notes"])
    assert "ML-KEM-1024" in notes_joined
    assert "ML-DSA-87" in notes_joined


def test_evaluate_cnsa_2_0_non_compliant_when_nothing_present() -> None:
    """Old OpenSSL with no PQC, kernel without hardware SHA — every
    field is checked and every field is False → non_compliant."""
    openssl = {
        "available": True,
        "kem_algorithms": [],
        "sig_algorithms": [],
    }
    proc_crypto = (
        "name         : sha384\n"
        "driver       : sha384-generic\n"
        "\n"
        "name         : sha512\n"
        "driver       : sha512-generic\n"
        "\n"
    )
    out = pr.evaluate_cnsa_2_0(openssl, proc_crypto)
    assert out["status"] == "non_compliant"
    assert out["kem_compliant"] is False
    assert out["signature_compliant"] is False
    assert out["symmetric_compliant"] is False
    assert out["hash_compliant"] is False


def test_evaluate_cnsa_2_0_unknown_when_no_detection_inputs() -> None:
    """openssl absent AND /proc/crypto absent — there is no evidence
    either way, so the verdict must be 'unknown', NOT 'non_compliant'.
    A vacuous False on every field is exactly the failure mode the
    status field must distinguish from a real audit."""
    out = pr.evaluate_cnsa_2_0({"available": False, "reason": "openssl missing"}, None)
    assert out["status"] == "unknown"
    notes_joined = " ".join(out["notes"])
    assert "OpenSSL not available" in notes_joined
    assert "/proc/crypto not available" in notes_joined


def test_evaluate_cnsa_2_0_partial_when_only_one_input_available() -> None:
    """openssl says yes to ML-KEM-1024/ML-DSA-87 but /proc/crypto is
    unavailable.  Status must reflect that some evidence exists — partial,
    not unknown — and notes must explain why sym/hash read as False."""
    openssl = {
        "available": True,
        "kem_algorithms": ["ML-KEM-1024"],
        "sig_algorithms": ["ML-DSA-87"],
    }
    out = pr.evaluate_cnsa_2_0(openssl, None)
    assert out["status"] == "partial"
    assert out["kem_compliant"] is True
    assert out["signature_compliant"] is True
    assert out["symmetric_compliant"] is False
    assert out["hash_compliant"] is False
    assert any("/proc/crypto not available" in n for n in out["notes"])


# ---------------------------------------------------------------------------
# Cross-distro §1: parse_os_release across the supported family matrix
# ---------------------------------------------------------------------------

import pytest  # noqa: E402  (placed after the existing tests for diff locality)


@pytest.mark.parametrize("fixture, expected_family, expected_id, has_codename", [
    ("rhel-8.txt",       "rhel",   "rhel",      False),
    ("rhel-9.txt",       "rhel",   "rhel",      False),
    ("rhel-10.txt",      "rhel",   "rhel",      False),
    ("fedora-41.txt",    "rhel",   "fedora",    False),
    ("rocky-8.txt",      "rhel",   "rocky",     False),
    ("rocky-9.txt",      "rhel",   "rocky",     False),
    ("almalinux-8.txt",  "rhel",   "almalinux", False),
    ("ubuntu-2404.txt",  "debian", "ubuntu",    True),
    ("ubuntu-2510.txt",  "debian", "ubuntu",    True),
    ("debian-12.txt",    "debian", "debian",    True),
    ("debian-13.txt",    "debian", "debian",    True),
    ("sles-15sp6.txt",   "suse",   "sles",      False),
    ("arch.txt",         "arch",   "arch",      False),
    ("alpine-321.txt",   "alpine", "alpine",    False),
])
def test_parse_os_release_matrix(fixture: str, expected_family: str,
                                 expected_id: str, has_codename: bool) -> None:
    text = (FIXTURES / "os-release" / fixture).read_text()
    parsed = pr.parse_os_release(text)
    assert parsed["family"] == expected_family, parsed
    assert parsed["id"] == expected_id, parsed
    assert parsed["pretty_name"], "pretty_name should be populated"
    if has_codename:
        assert parsed["version_codename"], "expected codename for this distro"
    # package_manager is always None from the pure parser; resolved by detect_os().
    assert parsed["package_manager"] is None


def test_parse_os_release_resolves_family_via_id_like() -> None:
    """Unknown ID, but ID_LIKE points at a known family — Rocky/Alma-style
    derivatives that haven't been added to OS_FAMILY_BY_ID still resolve
    correctly via ID_LIKE fallback."""
    text = 'ID=somenewdistro\nID_LIKE="rhel fedora"\nPRETTY_NAME="Some New Distro"\n'
    parsed = pr.parse_os_release(text)
    assert parsed["family"] == "rhel"
    assert parsed["id"] == "somenewdistro"


def test_parse_os_release_unknown_distro() -> None:
    text = 'ID=alienos\nVERSION_ID=1.0\nPRETTY_NAME="AlienOS 1.0"\n'
    parsed = pr.parse_os_release(text)
    assert parsed["family"] == "unknown"
    assert parsed["id"] == "alienos"


def test_parse_os_release_strips_quotes_and_comments() -> None:
    text = (
        "# this is a comment\n"
        'ID="rhel"\n'
        "VERSION_ID='9.6'\n"
        "PRETTY_NAME=\"Red Hat Enterprise Linux 9.6 (Plow)\"\n"
        "\n"
    )
    parsed = pr.parse_os_release(text)
    assert parsed["id"] == "rhel"
    assert parsed["version_id"] == "9.6"
    assert parsed["pretty_name"] == "Red Hat Enterprise Linux 9.6 (Plow)"


# ---------------------------------------------------------------------------
# Cross-distro §2: per-family package parsers + classification
# ---------------------------------------------------------------------------

def test_parse_dpkg_packages_normalises_to_dicts() -> None:
    text = (FIXTURES / "packages" / "dpkg-query-sample.txt").read_text()
    out = pr.parse_dpkg_packages(text)
    names = {e["name"] for e in out}
    assert "openjdk-21-jdk" in names
    assert "libbcprov-java" in names
    assert "nodejs" in names
    # Same shape as rpm/pacman/apk parsers — dicts, not tuples.
    assert all({"name", "version"} <= set(e.keys()) for e in out)


def test_parse_pacman_packages() -> None:
    text = (FIXTURES / "packages" / "pacman-q-sample.txt").read_text()
    out = pr.parse_pacman_packages(text)
    by_name = {e["name"]: e["version"] for e in out}
    assert by_name["jdk21-openjdk"] == "21.0.5.u11-1"
    assert by_name["nodejs"] == "22.11.0-1"


def test_parse_apk_packages_handles_release_suffix() -> None:
    text = (FIXTURES / "packages" / "apk-info-sample.txt").read_text()
    out = pr.parse_apk_packages(text)
    by_name = {e["name"]: e["version"] for e in out}
    # `openjdk21-jdk-21.0.5_p11-r0` — name ends at jdk-21.0.5 boundary.
    assert "openjdk21-jdk" in by_name
    assert by_name["openjdk21-jdk"].endswith("-r0")
    assert by_name["nodejs"].endswith("-r0")
    assert "openssl" in by_name


def test_classify_bundled_crypto_debian_finds_distinct_names() -> None:
    text = (FIXTURES / "packages" / "dpkg-query-sample.txt").read_text()
    pkgs = pr.parse_dpkg_packages(text)
    out = pr.classify_bundled_crypto(pkgs, family="debian")
    names = {p["package"] for p in out}
    # Debian uses openjdk-XX-jdk / openjdk-XX-jre; the regex catches all four.
    assert "openjdk-21-jdk" in names
    assert "openjdk-21-jre" in names
    assert "libbcprov-java" in names
    # nodejs without -ng suffix
    assert "nodejs" in names
    assert "rustc" in names
    assert "firefox-esr" in names
    # Not bundled crypto:
    assert "openssl" not in names
    assert "libssl3" not in names
    assert "libnss3" not in names


def test_classify_bundled_crypto_arch_uses_arch_naming() -> None:
    text = (FIXTURES / "packages" / "pacman-q-sample.txt").read_text()
    pkgs = pr.parse_pacman_packages(text)
    out = pr.classify_bundled_crypto(pkgs, family="arch")
    names = {p["package"] for p in out}
    # Arch ships `jdk21-openjdk` (vs. RHEL `java-21-openjdk`, Debian
    # `openjdk-21-jdk`).  The family-specific regex must match it.
    assert "jdk21-openjdk" in names
    assert "go" in names
    assert "nodejs" in names
    assert "rust" in names
    assert "firefox" in names
    # `python` (Arch) — not `python3`.  The Arch regex anchors to `^python$`.
    assert "python" in names


def test_classify_bundled_crypto_alpine_uses_alpine_naming() -> None:
    text = (FIXTURES / "packages" / "apk-info-sample.txt").read_text()
    pkgs = pr.parse_apk_packages(text)
    out = pr.classify_bundled_crypto(pkgs, family="alpine")
    names = {p["package"] for p in out}
    assert "openjdk21-jdk" in names
    assert "go" in names
    assert "python3" in names


def test_classify_bundled_crypto_unknown_family_is_empty() -> None:
    pkgs = [{"name": "openjdk-21-jdk", "version": "21.0.5"}]
    assert pr.classify_bundled_crypto(pkgs, family="unknown") == []


# ---------------------------------------------------------------------------
# Cross-distro §2: install hints
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("binary, family, expected_substring", [
    ("lspci",       "rhel",   "dnf install"),
    ("lspci",       "debian", "apt-get install"),
    ("lspci",       "suse",   "zypper install"),
    ("lspci",       "arch",   "pacman -S"),
    ("lspci",       "alpine", "apk add"),
    ("tpm2_getcap", "rhel",   "tpm2-tools"),
    ("tpm2_getcap", "debian", "tpm2-tools"),
    ("tpm2_getcap", "suse",   "tpm2.0-tools"),  # SUSE name
    ("certutil",    "debian", "libnss3-tools"),  # Debian name differs
    ("certutil",    "rhel",   "nss-tools"),
])
def test_install_hint_per_family(binary: str, family: str, expected_substring: str) -> None:
    hint = pr._install_hint(binary, family)
    assert expected_substring in hint


def test_install_hint_unknown_family_falls_back() -> None:
    assert "openssl" in pr._install_hint("openssl", "unknown")


# ---------------------------------------------------------------------------
# Cross-distro §2: FIPS interpretation
# ---------------------------------------------------------------------------

def test_interpret_fips_rhel_active_provider_certified() -> None:
    fips = {"kernel": True, "openssl_provider": True}
    osr = {"family": "rhel", "id": "rhel"}
    out = pr.interpret_fips(fips, {}, osr)
    assert out["distribution_certified"] is True
    assert "Red Hat" in out["distribution_certified_source"]
    assert "RHEL" in out["notes"]


def test_interpret_fips_debian_no_certification_claim() -> None:
    """Debian main has no certified provider — even with fips_enabled=1
    we must not claim certification."""
    fips = {"kernel": True, "openssl_provider": False}
    osr = {"family": "debian", "id": "debian"}
    out = pr.interpret_fips(fips, {}, osr)
    assert out["distribution_certified"] is False
    assert out["distribution_certified_source"] is None
    assert "third-party" in out["notes"]


def test_interpret_fips_ubuntu_pro_with_active_provider() -> None:
    """Ubuntu + active provider implies Ubuntu Pro (Universe doesn't ship one).
    distribution_certified is True with an explicit assumption note."""
    fips = {"kernel": True, "openssl_provider": True}
    osr = {"family": "debian", "id": "ubuntu"}
    out = pr.interpret_fips(fips, {}, osr)
    assert out["distribution_certified"] is True
    assert "Ubuntu Pro" in out["distribution_certified_source"]


def test_interpret_fips_kernel_off_no_certification() -> None:
    """fips_enabled=0 must never produce distribution_certified=True."""
    fips = {"kernel": False, "openssl_provider": True}
    osr = {"family": "rhel", "id": "rhel"}
    out = pr.interpret_fips(fips, {}, osr)
    assert out["distribution_certified"] is False


def test_interpret_fips_arch_alpine_explicitly_uncertified() -> None:
    for fam in ("arch", "alpine"):
        out = pr.interpret_fips(
            {"kernel": True, "openssl_provider": True},
            {},
            {"family": fam, "id": fam},
        )
        assert out["distribution_certified"] is False
        assert "FIPS-validated" in out["notes"]


# ---------------------------------------------------------------------------
# Cross-distro §4: PKCS#11 search paths per family
# ---------------------------------------------------------------------------

def test_pkcs11_search_paths_debian_includes_multiarch() -> None:
    paths = pr._pkcs11_search_paths("debian")
    assert "/usr/lib/x86_64-linux-gnu/pkcs11" in paths
    assert "/usr/lib/softhsm" in paths


def test_pkcs11_search_paths_rhel_excludes_debian_specific() -> None:
    paths = pr._pkcs11_search_paths("rhel")
    assert "/usr/lib64/pkcs11" in paths
    assert "/usr/lib/x86_64-linux-gnu/pkcs11" not in paths


def test_pkcs11_search_paths_always_include_vendor() -> None:
    """Vendor HSM client paths (/opt/cloudhsm, /opt/Thales, /opt/utimaco)
    are searched on every family."""
    for fam in ("rhel", "debian", "suse", "arch", "alpine"):
        paths = pr._pkcs11_search_paths(fam)
        assert "/opt/cloudhsm/lib" in paths
        assert "/opt/Thales/PKCS11" in paths
        assert "/opt/utimaco/Software/PKCS11" in paths


# ---------------------------------------------------------------------------
# Cross-distro §6: OpenSSL upgrade-path hints per family
# ---------------------------------------------------------------------------

def test_openssl_upgrade_path_already_pqc_capable_returns_none() -> None:
    osr = {"family": "rhel", "id": "rhel", "version_id": "10.0"}
    assert pr.openssl_upgrade_path([3, 5, 5], osr) is None


def test_openssl_upgrade_path_rhel9() -> None:
    osr = {"family": "rhel", "id": "rhel", "version_id": "9.6"}
    msg = pr.openssl_upgrade_path([3, 2, 0], osr)
    assert msg is not None
    assert "RHEL 10" in msg


@pytest.mark.parametrize("id_, version_id, expected_distro_token", [
    ("rhel",      "8.10", "RHEL 8"),
    ("rocky",     "8.10", "EL8"),
    ("almalinux", "8.10", "EL8"),
])
def test_openssl_upgrade_path_rhel8_family(
    id_: str, version_id: str, expected_distro_token: str
) -> None:
    """RHEL 8 / Rocky 8 / AlmaLinux 8 ship OpenSSL 1.1.1 — the upgrade
    hint must call out the OpenSSL 3.5+ requirement and the AppStream
    Python prerequisite for the script itself.  Distinct branch from the
    EL9 catch-all so the customer sees an EL8-correct message."""
    osr = {"family": "rhel", "id": id_, "version_id": version_id}
    msg = pr.openssl_upgrade_path([1, 1, 1], osr)
    assert msg is not None
    assert expected_distro_token in msg, msg
    assert "1.1.1" in msg, "should name the shipped OpenSSL series"
    assert "3.5" in msg, "should name the OpenSSL version PQC requires"
    assert "AppStream" in msg, "should mention the AppStream Python prerequisite"
    assert "python3" in msg.lower(), "should name the python3.9+ AppStream module"


def test_openssl_upgrade_path_rhel9_unchanged_after_rhel8_branch() -> None:
    """Regression guard: adding the RHEL 8 branch must not change the
    existing RHEL 9 string."""
    osr = {"family": "rhel", "id": "rhel", "version_id": "9.6"}
    msg = pr.openssl_upgrade_path([3, 2, 0], osr)
    assert msg is not None
    assert "RHEL 10" in msg
    assert "AppStream" not in msg, "RHEL 9 hint should not mention AppStream Python"


def test_openssl_upgrade_path_rocky9_unchanged_after_rhel8_branch() -> None:
    """Regression guard: Rocky/Alma 9 keeps the EL9-class hint."""
    osr = {"family": "rhel", "id": "rocky", "version_id": "9.6"}
    msg = pr.openssl_upgrade_path([3, 2, 0], osr)
    assert msg is not None
    assert "EL10" in msg or "backport" in msg
    assert "AppStream" not in msg


def test_openssl_upgrade_path_debian12() -> None:
    osr = {"family": "debian", "id": "debian", "version_id": "12"}
    msg = pr.openssl_upgrade_path([3, 0, 0], osr)
    assert msg is not None
    assert "trixie" in msg or "backports" in msg


def test_openssl_upgrade_path_ubuntu_2404() -> None:
    osr = {"family": "debian", "id": "ubuntu", "version_id": "24.04"}
    msg = pr.openssl_upgrade_path([3, 0, 0], osr)
    assert msg is not None
    assert "universe" in msg or "25.10" in msg


def test_openssl_upgrade_path_no_os_release() -> None:
    assert pr.openssl_upgrade_path([3, 0, 0], None) is None


# ---------------------------------------------------------------------------
# Cross-distro §7: SSH version + Libreswan parsing
# ---------------------------------------------------------------------------

def test_parse_ssh_version_standard_format() -> None:
    text = "OpenSSH_9.9p1, OpenSSL 3.5.5 27 Jan 2026\n"
    assert pr.parse_ssh_version(text) == "9.9p1"


def test_parse_ssh_version_no_match() -> None:
    assert pr.parse_ssh_version("garbage output") is None


def test_parse_libreswan_version() -> None:
    text = "Linux Libreswan 4.15 (netkey) on 5.14.0-503.21.1.el9_5.x86_64\n"
    assert pr.parse_libreswan_version(text) == "4.15"


def test_parse_libreswan_version_no_match() -> None:
    assert pr.parse_libreswan_version("strongSwan 5.9.13 swanctl") is None


# ---------------------------------------------------------------------------
# detect_os() I/O wrapper coverage — exercises HOST_PREFIX redirection
# and the legacy fallback paths (/etc/redhat-release, /etc/debian_version,
# /etc/SuSE-release) so the cross-distro contract is exercised end-to-end
# without requiring a real distro switch.
# ---------------------------------------------------------------------------

def _stub_host(tmp_path, monkeypatch, files):
    """Helper: populate tmp_path with the given {relpath: content} dict
    and point pr.HOST_PREFIX at it for the duration of one test."""
    for rel, content in files.items():
        target = tmp_path / rel.lstrip("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
    monkeypatch.setattr(pr, "HOST_PREFIX", str(tmp_path))


def test_detect_os_reads_etc_os_release(tmp_path, monkeypatch) -> None:
    text = (FIXTURES / "os-release" / "rhel-9.txt").read_text()
    _stub_host(tmp_path, monkeypatch, {"/etc/os-release": text})
    out = pr.detect_os()
    assert out["family"] == "rhel"
    assert out["id"] == "rhel"
    assert out["version_id"] == "9.6"


def test_detect_os_falls_back_to_usr_lib_os_release(tmp_path, monkeypatch) -> None:
    """When /etc/os-release is missing, /usr/lib/os-release is the
    secondary path (Fedora/Debian-style symlink target)."""
    text = (FIXTURES / "os-release" / "ubuntu-2404.txt").read_text()
    _stub_host(tmp_path, monkeypatch, {"/usr/lib/os-release": text})
    out = pr.detect_os()
    assert out["family"] == "debian"
    assert out["id"] == "ubuntu"


def test_detect_os_falls_back_to_redhat_release(tmp_path, monkeypatch) -> None:
    """Pre-os-release RHEL-derivatives still have /etc/redhat-release."""
    _stub_host(tmp_path, monkeypatch, {
        "/etc/redhat-release": "Red Hat Enterprise Linux release 7.9 (Maipo)\n",
    })
    out = pr.detect_os()
    assert out["family"] == "rhel"
    assert out["version_id"] == "7.9"


def test_detect_os_falls_back_to_debian_version(tmp_path, monkeypatch) -> None:
    _stub_host(tmp_path, monkeypatch, {"/etc/debian_version": "11.7\n"})
    out = pr.detect_os()
    assert out["family"] == "debian"
    assert out["version_id"] == "11.7"


def test_detect_os_unknown_when_nothing_present(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(pr, "HOST_PREFIX", str(tmp_path))
    out = pr.detect_os()
    assert out["family"] == "unknown"
    # pretty_name still populated from platform.system() + release().
    assert out["pretty_name"]


# ---------------------------------------------------------------------------
# TLS group classification — hybrid vs pure PQC vs classical
# ---------------------------------------------------------------------------

# Realistic OpenSSL 3.5 `openssl list -tls-groups -tls1_3` output:
# classical EC and FFDHE groups, pure-PQC ML-KEM-{512,768,1024}, and the
# IETF hybrid groups (X25519+ML-KEM-768, P-256+ML-KEM-768, P-384+ML-KEM-
# 1024).  Includes a couple of trailing alias lines and an unrecognised
# experimental group to verify the classifier drops unknowns rather
# than miscategorising them.
_TLS_GROUPS_OUTPUT = (
    "  TLS 1.3 group support:\n"
    "secp256r1 (P-256, prime256v1)\n"
    "secp384r1\n"
    "secp521r1\n"
    "x25519\n"
    "x448\n"
    "ffdhe2048\n"
    "ffdhe3072\n"
    "brainpoolP256r1tls13\n"
    "MLKEM512\n"
    "MLKEM768\n"
    "MLKEM1024\n"
    "X25519MLKEM768\n"
    "SecP256r1MLKEM768\n"
    "SecP384r1MLKEM1024\n"
    "X448MLKEM1024\n"
    "experimental-not-a-real-group\n"
)


def test_parse_openssl_tls_groups_extracts_first_token() -> None:
    names = pr.parse_openssl_tls_groups(_TLS_GROUPS_OUTPUT)
    # Header line "TLS 1.3 group support:" should not be a group name.
    assert "TLS" not in names
    assert "secp256r1" in names
    assert "MLKEM768" in names
    assert "X25519MLKEM768" in names


def test_parse_openssl_tls_groups_colon_separated_form() -> None:
    """OpenSSL 3.5's `list -tls-groups -tls1_3` emits a single colon-
    separated line.  That's what runs in production today; the parser
    must accept this form (regression — the first cut only handled the
    one-per-line alias form)."""
    text = ("secp256r1:secp384r1:x25519:ffdhe2048:MLKEM512:MLKEM768:"
            "MLKEM1024:SecP256r1MLKEM768:X25519MLKEM768:SecP384r1MLKEM1024\n")
    names = pr.parse_openssl_tls_groups(text)
    assert "secp256r1" in names
    assert "MLKEM768" in names
    assert "X25519MLKEM768" in names
    out = pr.classify_tls_groups(names)
    assert "X25519MLKEM768" in out["hybrid"]
    assert "MLKEM768" in out["pure_pqc"]
    assert "secp256r1" in out["classical"]


def test_classify_tls_groups_splits_hybrid_pure_classical() -> None:
    names = pr.parse_openssl_tls_groups(_TLS_GROUPS_OUTPUT)
    out = pr.classify_tls_groups(names)
    assert out["pure_pqc"] == ["MLKEM1024", "MLKEM512", "MLKEM768"]
    assert out["hybrid"] == [
        "SecP256r1MLKEM768", "SecP384r1MLKEM1024",
        "X25519MLKEM768", "X448MLKEM1024",
    ]
    # Classical bucket: named EC curves + FFDHE + brainpool.
    assert "secp256r1" in out["classical"]
    assert "x25519" in out["classical"]
    assert "ffdhe2048" in out["classical"]
    assert "brainpoolP256r1tls13" in out["classical"]
    # Unrecognised experimental name MUST be dropped, not lumped into
    # classical — keeps the report honest about what we don't know.
    flat = out["pure_pqc"] + out["hybrid"] + out["classical"]
    assert "experimental-not-a-real-group" not in flat


def test_classify_tls_groups_pure_mlkem_not_misclassified_as_hybrid() -> None:
    """Regression: the old single regex matched `MLKEM768` and
    `X25519MLKEM768` together.  The new classifier must put MLKEM768
    in pure_pqc only."""
    out = pr.classify_tls_groups(["MLKEM768", "X25519MLKEM768"])
    assert out["pure_pqc"] == ["MLKEM768"]
    assert out["hybrid"] == ["X25519MLKEM768"]


def test_classify_tls_groups_empty_input_returns_empty_buckets() -> None:
    out = pr.classify_tls_groups([])
    assert out == {"pure_pqc": [], "hybrid": [], "classical": []}


# ---------------------------------------------------------------------------
# SSH KEX classification
# ---------------------------------------------------------------------------

def test_classify_ssh_kex_marks_mlkem_x25519_as_hybrid() -> None:
    """OpenSSH 9.x ships mlkem768x25519-sha256 and mlkem768nistp256-
    sha256 as the PQC kex options; both embed a classical group token
    and must classify as hybrid, not pure_pqc."""
    out = pr.classify_ssh_kex([
        "mlkem768x25519-sha256",
        "mlkem768nistp256-sha256",
        "mlkem1024nistp384-sha384",
        "sntrup761x25519-sha512",
    ])
    assert out["hybrid"] == [
        "mlkem1024nistp384-sha384",
        "mlkem768nistp256-sha256",
        "mlkem768x25519-sha256",
        "sntrup761x25519-sha512",
    ]
    assert out["pure_pqc"] == []


def test_classify_ssh_kex_recognises_pure_pqc_when_no_classical_token() -> None:
    """If a future OpenSSH ships a pure-PQC kex (no classical token),
    it must surface in pure_pqc rather than being silently dropped or
    miscategorised."""
    out = pr.classify_ssh_kex(["mlkem768-sha256", "kyber768-sha256"])
    assert out["pure_pqc"] == ["kyber768-sha256", "mlkem768-sha256"]
    assert out["hybrid"] == []


def test_parse_ssh_kex_emits_kex_groups_and_back_compat_pqc_kex() -> None:
    """parse_ssh_kex must populate the new `kex_groups` split AND keep
    the flat `pqc_kex` list so downstream consumers that already key
    off it don't break."""
    text = (
        "curve25519-sha256\n"
        "ecdh-sha2-nistp256\n"
        "mlkem768x25519-sha256\n"
        "sntrup761x25519-sha512\n"
        "diffie-hellman-group14-sha256\n"
    )
    out = pr.parse_ssh_kex(text)
    assert out["available"] is True
    assert out["kex_count"] == 5
    assert out["pqc_kex"] == [
        "mlkem768x25519-sha256", "sntrup761x25519-sha512",
    ]
    assert out["kex_groups"]["hybrid"] == [
        "mlkem768x25519-sha256", "sntrup761x25519-sha512",
    ]
    assert out["kex_groups"]["pure_pqc"] == []
    # Issue #40: classical SSH kex must surface in its own bucket so
    # downstream tooling can inventory classical-only SSH posture from a
    # single field, the way it already can for tls_groups.
    assert out["kex_groups"]["classical"] == [
        "curve25519-sha256",
        "diffie-hellman-group14-sha256",
        "ecdh-sha2-nistp256",
    ]


def test_classify_ssh_kex_buckets_rhel10_fixture_into_three_groups() -> None:
    """Regression for issue #40: every kex name from the rhel10 ssh -Q
    kex fixture must land in exactly one of pure_pqc / hybrid / classical
    (the same three-bucket contract issue #9 introduced for TLS).  The
    classical bucket must be non-empty — historical behaviour silently
    dropped curve25519-sha256, ecdh-sha2-nistp*, and the diffie-hellman
    group kex set, which left consumers unable to inventory classical
    SSH posture from kex_groups alone."""
    text = (FIXTURES / "ssh-kex-rhel10.txt").read_text()
    out = pr.parse_ssh_kex(text)
    kg = out["kex_groups"]
    assert set(kg) == {"pure_pqc", "hybrid", "classical"}
    classified = set(kg["pure_pqc"]) | set(kg["hybrid"]) | set(kg["classical"])
    fixture_kexes = {ln.strip() for ln in text.splitlines() if ln.strip()}
    # Every fixture entry must be classified; no kex is dropped.
    assert classified == fixture_kexes
    # No kex appears in more than one bucket.
    assert len(classified) == (
        len(kg["pure_pqc"]) + len(kg["hybrid"]) + len(kg["classical"])
    )
    # Sanity: classical bucket carries the expected baseline kex set.
    assert "curve25519-sha256" in kg["classical"]
    assert "ecdh-sha2-nistp256" in kg["classical"]
    assert "diffie-hellman-group14-sha256" in kg["classical"]
    # And the PQC pair still bucket as hybrid (no regression).
    assert "mlkem768x25519-sha256" in kg["hybrid"]
    assert "sntrup761x25519-sha512" in kg["hybrid"]


def test_classify_ssh_kex_drops_unrecognised_names() -> None:
    """Names that match no PQC and no classical pattern are dropped, the
    same way classify_tls_groups treats unknown TLS groups.  This keeps
    the report honest about what we don't yet catalogue."""
    out = pr.classify_ssh_kex([
        "unknown-future-kex-sha512",
        "gss-group14-sha256-",  # GSS-API kex; out of scope for PQC inventory
    ])
    assert out == {"pure_pqc": [], "hybrid": [], "classical": []}


# ---------------------------------------------------------------------------
# per_algo_verdict — hybrid availability surfaces in ML-KEM notes
# ---------------------------------------------------------------------------

def test_per_algo_verdict_emits_hybrid_note_for_ml_kem_when_available() -> None:
    """When OpenSSL exposes hybrid TLS groups, the ML-KEM verdict notes
    must point at hybrid as the preferred transitional path — that's
    the operational guidance #9 calls out."""
    bench = {
        "available": True,
        "pqc": {"ML-KEM-768": {"decaps/s": 30000.0}},
    }
    out = pr.per_algo_verdict(
        bench, cores=8, mem_bw_gb_s=80.0, tls_hybrid_available=True,
    )
    notes_joined = " ".join(out["ML-KEM-768"]["notes"])
    assert "hybrid" in notes_joined.lower()
    assert "transitional" in notes_joined.lower()


def test_per_algo_verdict_no_hybrid_note_when_unavailable() -> None:
    """A host without hybrid TLS groups must NOT get the hybrid note —
    surfacing it would imply availability and mislead the operator."""
    bench = {
        "available": True,
        "pqc": {"ML-KEM-768": {"decaps/s": 30000.0}},
    }
    out = pr.per_algo_verdict(
        bench, cores=8, mem_bw_gb_s=80.0, tls_hybrid_available=False,
    )
    notes_joined = " ".join(out["ML-KEM-768"]["notes"])
    assert "hybrid" not in notes_joined.lower()


def test_per_algo_verdict_hybrid_note_does_not_attach_to_signatures() -> None:
    """The hybrid note is a TLS KEM concern, not a signature concern.
    It must not appear on ML-DSA / SLH-DSA verdicts."""
    bench = {
        "available": True,
        "pqc": {
            "ML-DSA-65": {"sign/s": 1000.0, "verify/s": 5000.0},
            "SLH-DSA-SHA2-128s": {"sign/s": 3.0},
        },
    }
    out = pr.per_algo_verdict(
        bench, cores=8, mem_bw_gb_s=80.0, tls_hybrid_available=True,
    )
    for key in ("ML-DSA-65", "SLH-DSA-SHA2-128s"):
        notes = " ".join(out[key]["notes"])
        assert "hybrid" not in notes.lower(), f"hybrid note leaked into {key}"
