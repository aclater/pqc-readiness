"""The Report dataclass and the script / schema version constants."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from . import algorithms as _algorithms


SCRIPT_VERSION = "2.0.0"


SCHEMA_VERSION = "1.4"


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
    # Role-aware memory tiering.  When --role is supplied, `memory.tier`
    # reflects that role and `memory.tier_basis.role` records which
    # threshold was applied.  When --role is not supplied, `memory.tier`
    # is the generic role's tier (back-compat with schema 1.0 reports
    # that pre-date role-aware tiering) and `memory.tier_by_role` carries
    # per-role evaluations side-by-side.
    memory: dict[str, Any] = field(default_factory=dict)
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
    # None when --bench was not run (no probe attempted).  When the probe
    # runs but cannot measure, this carries the reason string and
    # memory_bandwidth_gb_s stays None.
    memory_bandwidth_method: str | None = None
    ssh_pqc: dict[str, Any] = field(default_factory=dict)
    ipsec_pqc: dict[str, Any] = field(default_factory=dict)
    nss: dict[str, Any] = field(default_factory=dict)
    # System-wide crypto policy and what it lets PQC do (#104).
    crypto_policy: dict[str, Any] = field(default_factory=dict)
    kernel_info: dict[str, Any] = field(default_factory=dict)
    fips_pqc_conflict: dict[str, Any] = field(default_factory=dict)
    cnsa_2_0: dict[str, Any] = field(default_factory=dict)
    trust_store: dict[str, Any] = field(default_factory=dict)
    crypto_material: dict[str, Any] = field(default_factory=dict)
    runtime_environment: dict[str, Any] = field(default_factory=dict)
    # --scan-services (#111): listening sockets -> owning process -> the
    # crypto library it maps (or Go toolchain).  {} when not requested.
    service_crypto_linkage: dict[str, Any] = field(default_factory=dict)
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
    # Package-signing trust anchors (--scan-signing-keys, #153); {} when
    # not requested, like trust_store and packages.
    signing_keys: dict[str, Any] = field(default_factory=dict)
    replace_required: bool = False
    os_release: dict[str, Any] = field(default_factory=dict)
    # None when --bench / --bench-tls was not requested, so "not run" is
    # a single JSON value (null) rather than {} vs null vs "" (#82).
    benchmark: dict[str, Any] | None = None
    benchmark_tls_handshake: dict[str, Any] | None = None
    pqc_sizes: dict[str, dict[str, Any]] = field(
        default_factory=lambda: _algorithms.PQC_SIZES
    )
    per_algo: dict[str, dict[str, Any]] = field(default_factory=dict)
    production_estimate: dict[str, Any] = field(default_factory=dict)
    verdict: str = ""
    verdict_reason: str = ""
    verdict_caveat: str = ""
    exit_code: int = 0
    # Operator-supplied facts from --inventory-metadata FILE (OMB M-23-02
    # items the host can't know); None when the flag isn't given (#144).
    inventory_metadata: dict[str, Any] | None = None
