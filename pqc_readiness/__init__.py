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
    pqc-readiness --cbom                    CycloneDX 1.7 CBOM JSON (--cbom-version 1.6)
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

# Public API re-exports.  Private helpers stay in their modules, e.g.
# ``pqc_readiness.detect.certs._certs_in_file``.  Tests patch the defining
# module, never this package root (tests/conftest.py enforces that).
# Mutable state (HOST_PREFIX) is deliberately not re-exported: read
# ``pqc_readiness._platform.HOST_PREFIX``.

from ._platform import (  # noqa: F401
    host_fs_unavailable_note,
    host_path,
    is_linux,
    is_macos,
    set_host_prefix,
)
from .report import (  # noqa: F401
    Report,
    SCHEMA_VERSION,
    SCRIPT_VERSION,
)
from .algorithms import (  # noqa: F401
    ALGO_NOTES,
    ALGO_THRESHOLDS,
    PQC_SIZES,
    SLH_DSA_MEM_BANDWIDTH_FLOOR_GB_S,
)
from .detect.runtime import (  # noqa: F401
    build_host_fs_detections_unavailable,
    detect_runtime_environment,
    parse_cgroup_for_container,
)
from .detect.osinfo import (  # noqa: F401
    OS_FAMILY_BY_ID,
    PKG_MANAGER_ORDER,
    detect_kernel_info,
    detect_os,
    parse_os_release,
    parse_proc_crypto_pqc,
    parse_redhat_release,
)
from .detect.hardware import (  # noqa: F401
    ACCEL_PCI_HINTS,
    ARM_FEATURES,
    DEVICE_HINTS,
    MACOS_ARM_SYSCTLS,
    MACOS_X86_SYSCTL,
    MACOS_X86_TO_LINUX,
    MEMORY_TIER_GOOD_THRESHOLD_BY_ROLE,
    NETWORK_HSM_HINTS,
    S390_FEATURES,
    X86_FEATURES,
    core_counts,
    cpu_flags,
    cpu_freq_mhz,
    cpu_model,
    detect_accelerators,
    detect_isa,
    detect_kernel_crypto_hw,
    detect_kernel_crypto_hw_annotated,
    detect_ktls,
    detect_ktls_annotated,
    detect_network_hsms,
    detect_pci_accelerators,
    detect_pkcs11_modules,
    detect_s390x_crypto,
    detect_tpm_pqc,
    has_dedicated_pqc_silicon,
    isa_tier,
    linux_cpu_flags,
    macos_cpu_flags,
    memory_info,
    memory_tier,
    memory_tier_all_roles,
    parse_cpuinfo_flags,
    parse_lszcrypt,
)
from .detect.config import (  # noqa: F401
    classify_tls_groups,
    detect_fips_mode,
    detect_fips_mode_from_providers_text,
    fips_fence_check,
    fips_pqc_conflict_check,
    interpret_fips,
    openssl_capability,
    openssl_upgrade_path,
    parse_openssl_provider_records,
    parse_openssl_tls_groups,
)
from .detect.packages import (  # noqa: F401
    BUNDLED_CRYPTO_BY_FAMILY,
    PACKAGE_QUERY_BY_FAMILY,
    RPMDB_DIRS,
    RpmdbError,
    classify_bundled_crypto,
    locate_rpmdb,
    parse_apk_packages,
    parse_rpm_header,
    parse_rpm_qa_nvra,
    parse_whitespace_pkg_lines,
    query_rpm_named,
    query_rpm_named_from_inventory,
    query_rpm_packages,
    read_rpmdb_blobs,
    read_rpmdb_sqlite,
    read_rpmdb_sqlite_named,
    resolve_under_prefix,
    rpmdb_backend_by_magic,
    scan_packages,
)
from .detect.protocols import (  # noqa: F401
    NSS_PQC_MIN_VERSION,
    NSS_RPM_PACKAGE_NAMES,
    classify_ssh_kex,
    detect_ipsec_pqc,
    detect_nss,
    detect_ssh_pqc,
    parse_libreswan_version,
    parse_nss_version,
    parse_ssh_kex,
    parse_ssh_version,
)
from .detect.certs import (  # noqa: F401
    COMPOSITE_SIG_OID_RE,
    DERError,
    HYBRID_OID_RES,
    PQC_OID_RE,
    TRUST_STORE_DIRS,
    TRUST_STORE_MAX_CERTS_DEFAULT,
    TRUST_STORE_MAX_FILE_BYTES,
    categorise_cert_oids,
    cert_algorithm_oids,
    scan_trust_store,
)
from .verdict import (  # noqa: F401
    CNSA_2_0_REQUIREMENTS,
    evaluate_cnsa_2_0,
    overall_verdict,
    parse_proc_crypto_cnsa,
    per_algo_verdict,
    production_estimate,
)
from .bench import (  # noqa: F401
    BENCH_SKIPPED_NOT_PROVIDED,
    memory_bandwidth_probe,
    parse_classical_speed,
    parse_speed_row,
    run_benchmarks,
    run_classical_baseline,
    run_pqc_bench,
    run_tls_handshake_bench,
)
from .aggregate import (  # noqa: F401
    aggregate_reports,
    aggregate_to_csv,
    run_aggregator,
)
from .recommendation import (  # noqa: F401
    CLIENT_HELLO_MIDDLEBOX_BYTES,
    ML_KEM_ENCAPS_KEY_BYTES,
    POLICY_PREFERENCES,
    VALID_POLICIES,
    VALID_ROLES,
    X25519_SHARE_BYTES,
    recommend,
    render_recommendation_markdown,
    render_recommendation_text,
)
from .render.text import (  # noqa: F401
    C,
    TIER_COLOR,
    render_markdown,
    render_text,
)
from .render.cbom import (  # noqa: F401
    CryptoAsset,
    canonical_assets,
    render_cbom,
)
from .render.sarif import (  # noqa: F401
    Finding,
    RULE_SPECS,
    RuleSpec,
    SARIF_HELP_BASE,
    SARIF_SCHEMA_URI,
    SARIF_VERSION,
    build_findings,
    render_sarif,
)
from .render.spdx import (  # noqa: F401
    SPDX_CONTEXT_URL,
    SPDX_DATA_LICENSE,
    SPDX_FINDING_HELP_BASE,
    SPDX_FINDING_LEVEL_TO_NOTE,
    SPDX_URN_PREFIX,
    SPDX_VERSION,
    render_spdx,
)
from .render.prom import render_prometheus  # noqa: F401
from .cli import (  # noqa: F401
    EXIT_OUTPUT_WRITE_FAILED,
    ansible_ignored_flag_warnings,
    build_parser,
    collect_report,
    exit_code_for,
    main,
    render_output,
)
from . import detect, render  # noqa: F401
from .render import json_report  # noqa: F401  (registers --json)
from . import inventory_metadata  # noqa: F401  (registers --inventory-metadata)

__all__ = [
    "ACCEL_PCI_HINTS",
    "ALGO_NOTES",
    "ALGO_THRESHOLDS",
    "ARM_FEATURES",
    "BENCH_SKIPPED_NOT_PROVIDED",
    "BUNDLED_CRYPTO_BY_FAMILY",
    "C",
    "CLIENT_HELLO_MIDDLEBOX_BYTES",
    "CNSA_2_0_REQUIREMENTS",
    "COMPOSITE_SIG_OID_RE",
    "CryptoAsset",
    "DERError",
    "DEVICE_HINTS",
    "EXIT_OUTPUT_WRITE_FAILED",
    "Finding",
    "HYBRID_OID_RES",
    "MACOS_ARM_SYSCTLS",
    "MACOS_X86_SYSCTL",
    "MACOS_X86_TO_LINUX",
    "MEMORY_TIER_GOOD_THRESHOLD_BY_ROLE",
    "ML_KEM_ENCAPS_KEY_BYTES",
    "NETWORK_HSM_HINTS",
    "NSS_PQC_MIN_VERSION",
    "NSS_RPM_PACKAGE_NAMES",
    "OS_FAMILY_BY_ID",
    "PACKAGE_QUERY_BY_FAMILY",
    "PKG_MANAGER_ORDER",
    "POLICY_PREFERENCES",
    "PQC_OID_RE",
    "PQC_SIZES",
    "RPMDB_DIRS",
    "RULE_SPECS",
    "Report",
    "RpmdbError",
    "RuleSpec",
    "S390_FEATURES",
    "SARIF_HELP_BASE",
    "SARIF_SCHEMA_URI",
    "SARIF_VERSION",
    "SCHEMA_VERSION",
    "SCRIPT_VERSION",
    "SLH_DSA_MEM_BANDWIDTH_FLOOR_GB_S",
    "SPDX_CONTEXT_URL",
    "SPDX_DATA_LICENSE",
    "SPDX_FINDING_HELP_BASE",
    "SPDX_FINDING_LEVEL_TO_NOTE",
    "SPDX_URN_PREFIX",
    "SPDX_VERSION",
    "TIER_COLOR",
    "TRUST_STORE_DIRS",
    "TRUST_STORE_MAX_CERTS_DEFAULT",
    "TRUST_STORE_MAX_FILE_BYTES",
    "VALID_POLICIES",
    "VALID_ROLES",
    "X25519_SHARE_BYTES",
    "X86_FEATURES",
    "aggregate_reports",
    "aggregate_to_csv",
    "ansible_ignored_flag_warnings",
    "build_findings",
    "build_host_fs_detections_unavailable",
    "build_parser",
    "canonical_assets",
    "categorise_cert_oids",
    "cert_algorithm_oids",
    "classify_bundled_crypto",
    "classify_ssh_kex",
    "classify_tls_groups",
    "collect_report",
    "core_counts",
    "cpu_flags",
    "cpu_freq_mhz",
    "cpu_model",
    "detect_accelerators",
    "detect_fips_mode",
    "detect_fips_mode_from_providers_text",
    "detect_ipsec_pqc",
    "detect_isa",
    "detect_kernel_crypto_hw",
    "detect_kernel_crypto_hw_annotated",
    "detect_kernel_info",
    "detect_ktls",
    "detect_ktls_annotated",
    "detect_network_hsms",
    "detect_nss",
    "detect_os",
    "detect_pci_accelerators",
    "detect_pkcs11_modules",
    "detect_runtime_environment",
    "detect_s390x_crypto",
    "detect_ssh_pqc",
    "detect_tpm_pqc",
    "evaluate_cnsa_2_0",
    "exit_code_for",
    "fips_fence_check",
    "fips_pqc_conflict_check",
    "has_dedicated_pqc_silicon",
    "host_fs_unavailable_note",
    "host_path",
    "interpret_fips",
    "is_linux",
    "is_macos",
    "isa_tier",
    "linux_cpu_flags",
    "locate_rpmdb",
    "macos_cpu_flags",
    "main",
    "memory_bandwidth_probe",
    "memory_info",
    "memory_tier",
    "memory_tier_all_roles",
    "openssl_capability",
    "openssl_upgrade_path",
    "overall_verdict",
    "parse_apk_packages",
    "parse_cgroup_for_container",
    "parse_classical_speed",
    "parse_cpuinfo_flags",
    "parse_libreswan_version",
    "parse_lszcrypt",
    "parse_nss_version",
    "parse_openssl_provider_records",
    "parse_openssl_tls_groups",
    "parse_os_release",
    "parse_proc_crypto_cnsa",
    "parse_proc_crypto_pqc",
    "parse_redhat_release",
    "parse_rpm_header",
    "parse_rpm_qa_nvra",
    "parse_speed_row",
    "parse_ssh_kex",
    "parse_ssh_version",
    "parse_whitespace_pkg_lines",
    "per_algo_verdict",
    "production_estimate",
    "query_rpm_named",
    "query_rpm_named_from_inventory",
    "query_rpm_packages",
    "read_rpmdb_blobs",
    "read_rpmdb_sqlite",
    "read_rpmdb_sqlite_named",
    "recommend",
    "render_cbom",
    "render_markdown",
    "render_output",
    "render_recommendation_markdown",
    "render_recommendation_text",
    "render_sarif",
    "render_spdx",
    "render_text",
    "resolve_under_prefix",
    "rpmdb_backend_by_magic",
    "run_aggregator",
    "run_benchmarks",
    "run_classical_baseline",
    "run_pqc_bench",
    "run_tls_handshake_bench",
    "scan_packages",
    "scan_trust_store",
    "set_host_prefix",
]
