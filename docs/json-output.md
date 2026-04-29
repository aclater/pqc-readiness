# JSON output reference

`./pqc_readiness.py --json` emits a stable, schema-versioned document.
The `schema_version` key changes only when fields are renamed or
removed; additive changes keep the same version. The fleet aggregator
refuses to merge files whose `schema_version` does not match.

This document is the field-by-field reference for the schema. For the
narrative description of when to use `--json` vs. the other output
formats, see the [Output formats](../README.md#output-formats) section
of the README.

## Top-level keys

| Top-level key | Description |
| --- | --- |
| `schema_version` | Stable schema version string. Bumped on rename/remove, not on additive changes. |
| `generated_at` | ISO 8601 UTC timestamp of the probe run. |
| `hostname` | Host's reported hostname. |
| `os` | OS family token (`linux`, `darwin`). |
| `arch` | CPU architecture (`x86_64`, `aarch64`, `s390x`, …). |
| `cpu_model` | CPU model string from `/proc/cpuinfo` or `sysctl`. |
| `cpu_freq_mhz` | Reported CPU base frequency. |
| `cores_logical` | Logical core count (SMT siblings included). |
| `cores_physical` | Physical core count. |
| `mem_total_gb` | Total system memory in GiB. |
| `mem_avail_gb` | Available memory in GiB at probe time. |
| `isa_features` | Map of ISA feature flags relevant to PQC (AVX-512 family, ARMv8 crypto, CPACF MSA, …). |
| `isa_score` | Numeric ISA score backing the tier classification. |
| `isa_tier` | Coarse ISA tier (`excellent` / `good` / `marginal` / `poor`). |
| `isa_reason` | Human-readable explanation for the ISA tier. |
| `accelerators` | List of detected accelerators (HSMs, DPUs, TPMs, QAT, Nitro, …). |
| `hsm_present_but_not_pqc` | True when an HSM is detected but it does not advertise PQC primitives. |
| `pkcs11_modules` | PKCS#11 modules discoverable on the host. |
| `kernel_crypto_hw` | `/proc/crypto` entries backed by hardware drivers. |
| `ktls_supported` | Whether kernel TLS is available. |
| `fips` | Kernel FIPS mode and provider state. |
| `openssl` | Detected OpenSSL version, PQC algorithm exposure, hybrid TLS group list, and `upgrade_path` suggestion. |
| `tpm_pqc` | TPM presence and any PQC capability advertised. |
| `memory_bandwidth_gb_s` | Memory bandwidth measurement (null if not measured). |
| `memory_bandwidth_method` | How the bandwidth value was obtained, or `not-measured`. |
| `ssh_pqc` | OpenSSH `ssh -Q kex` availability. `kex_groups` splits the detected kex names into `pure_pqc` / `hybrid` / `classical` buckets, mirroring `openssl.tls_groups`. |
| `ipsec_pqc` | strongSwan / Libreswan PQC and hybrid IKE state. |
| `nss` | NSS PQC algorithm exposure. |
| `kernel_info` | Kernel version, build flags relevant to crypto, and module list. |
| `fips_pqc_conflict` | Detected when kernel FIPS is on but PQC is exposed only via a non-FIPS provider. |
| `cnsa_2_0` | CNSA 2.0 compliance summary (algorithm coverage, hash, FIPS state). |
| `trust_store` | Trust-store summary (count, PQC-capable count, hybrid count). Populated only when `--scan-trust-store` is set. |
| `runtime_environment` | How the probe is running (bare metal, container, DaemonSet, …). |
| `host_fs_detections_unavailable` | Per-probe annotations emitted when running inside a container without `--host-mount`. One entry per host-fs-dependent detection (lspci, dmidecode, `/proc /sys` reads). Empty on bare metal or when `--host-mount` is in effect. The aggregator surfaces a `host_fs_detections_unavailable_host_count` rollup. |
| `packages` | Installed crypto-bearing packages. Populated only when `--scan-packages` is set. |
| `replace_required` | Top-level boolean for fleet planning: true when the host cannot run NIST PQC at production speed without an accelerator. |
| `os_release` | Parsed `/etc/os-release` (id, version, like-chain). |
| `benchmark` | Microbenchmark results from `--bench`. Empty when `--bench` is not set. |
| `benchmark_tls_handshake` | TLS 1.3 handshake bench results from `--bench-tls`. Empty when `--bench-tls` is not set. |
| `pqc_sizes` | Wire-size and key-size constants for the PQC primitives, used by the recommendation engine and by sizing notes in the human report. |
| `per_algo` | Per-algorithm tier and reasoning (ML-KEM-512/768/1024, ML-DSA-44/65/87, SLH-DSA variants). |
| `production_estimate` | Estimated handshakes-per-second / sign-per-second per algorithm given the measured benchmark numbers. |
| `verdict` | Coarse verdict (`excellent` / `good` / `marginal` / `poor`). |
| `verdict_reason` | One-line explanation for the verdict. |
| `verdict_caveat` | Caveat string (e.g. `no-bench`) when the verdict was determined without running OpenSSL primitives. |
| `exit_code` | Numeric exit code the program will return. Mirrors the [Exit codes](../README.md#exit-codes) table in the README. |

## `--ansible` variant

`--ansible` returns a single top-level key `ansible_facts`, whose value
is `{pqc_readiness: {…the schema above…}}`. The wrapper exists so an
Ansible play can `register` or `set_fact` on the result without
custom parsing. `--ansible` always exits 0 so a host's PQC verdict
never marks the play as failed; downstream tasks read the verdict
from the fact body. See [docs/ansible.md](ansible.md) for runnable
playbooks, the `become` / privilege model, and downstream `set_fact`
patterns.

## `--recommend --json` variant

`--recommend --json` returns a different document scoped to the
recommendation rather than the readiness report:

| Top-level key | Description |
| --- | --- |
| `role` | Role for the recommendation (`tls-server`, `tls-client`, …). |
| `mode` | `single` for a one-policy recommendation; `auto` when emitting all four side by side. |
| `hostname` | Host the recommendation is for. |
| `generated_at` | ISO 8601 UTC timestamp. |
| `recommendations` | List of per-policy recommendation records. Each record contains `policy`, `authority`, `kem`, `signature`, `hash`, `policy_basis`, `source`, and `caveats`. |

The policy-to-preference mapping, the issuing authority for each
policy, and the source documents are catalogued in
[docs/recommendation-policies.md](recommendation-policies.md).

## Schema alignment with CycloneDX 1.6

[docs/schema-alignment.md](schema-alignment.md) is a field-by-field
mapping of the `--json` schema against the field-name conventions in
CycloneDX 1.6's `cryptoProperties` schema. The mapping concludes that
`--json` is a host-level inventory schema and CycloneDX is an
asset-level schema — the asset-level projection is already provided by
`--cbom`. No `--json` field renames are recommended at this time and
`SCHEMA_VERSION` stays at `"1.0"`.
