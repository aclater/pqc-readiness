# JSON output reference

`./pqc_readiness.py --json` emits a stable, schema-versioned document.
The current `schema_version` is `"1.2"`. It follows the bump rules in
[docs/schema-alignment.md](schema-alignment.md#versioning-recommendation):
a rename, removal, or re-type is a major bump; an additive change
(including normalising an "absent" value to `null`) is a minor bump.
The fleet aggregator refuses to merge files whose `schema_version`
does not match, so mixed-version fleets show up under `skipped`.

| Version | Change |
| --- | --- |
| `1.0` | Initial stable schema. |
| `1.1` | Added the role-aware `memory` object. |
| `1.2` | `benchmark`, `benchmark_tls_handshake`, `memory_bandwidth_method` are `null` (was `{}` / `""`) when not run; `trust_store` gained `total_found` / `scanned_count` / `max_certs` / `truncated`; `host_fs_detections_unavailable` documented for `kernel_crypto_hw` / `ktls`. |

This document is the field-by-field reference for the schema. For the
narrative description of when to use `--json` vs. the other output
formats, see the [Output formats](../README.md#output-formats) section
of the README.

## Top-level keys

Convention: the benchmark-derived fields (`benchmark`,
`benchmark_tls_handshake`, `memory_bandwidth_gb_s`,
`memory_bandwidth_method`) are `null` when the corresponding `--bench*`
flag was not set. Opt-in scan fields (`trust_store`, `packages`) are
`{}` when their flag was not set. List-valued fields are `[]` when
nothing was found.

| Top-level key | Description |
| --- | --- |
| `schema_version` | Schema version string, currently `"1.2"`. Major bump on rename/remove/re-type, minor bump on additive changes. |
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
| `kernel_crypto_hw` | List of `/proc/crypto` driver names backed by hardware. Inside a container without `--host-mount` this is the container's view; `host_fs_detections_unavailable.kernel_crypto_hw` is then set. |
| `ktls_supported` | `true` / `false`, or `null` on non-Linux. Inside a container without `--host-mount` this reflects the container's `/proc/modules` and `/sys/module/tls`; `host_fs_detections_unavailable.ktls` is then set. |
| `fips` | Kernel FIPS mode and provider state. |
| `openssl` | Detected OpenSSL version, PQC algorithm exposure, hybrid TLS group list, and `upgrade_path` suggestion. |
| `tpm_pqc` | TPM presence and any PQC capability advertised. |
| `memory_bandwidth_gb_s` | Memory bandwidth measurement in GB/s. `null` when `--bench` was not set or the probe could not measure. |
| `memory_bandwidth_method` | How the bandwidth value was obtained (e.g. `STREAM-triad (numpy)`), or the reason it could not be measured (e.g. `unavailable: numpy not installed`). `null` when `--bench` was not set. |
| `ssh_pqc` | OpenSSH `ssh -Q kex` availability. `kex_groups` splits the detected kex names into `pure_pqc` / `hybrid` / `classical` buckets, mirroring `openssl.tls_groups`. |
| `ipsec_pqc` | strongSwan / Libreswan PQC and hybrid IKE state. |
| `nss` | NSS PQC algorithm exposure. |
| `kernel_info` | Kernel version, build flags relevant to crypto, and module list. |
| `fips_pqc_conflict` | Detected when kernel FIPS is on but PQC is exposed only via a non-FIPS provider. |
| `cnsa_2_0` | CNSA 2.0 compliance summary (algorithm coverage, hash, FIPS state). |
| `trust_store` | Trust-store summary. Populated only when `--scan-trust-store` is set (`{}` otherwise). Keys: `available`, `scanned_dirs`, `total_certs` (certs openssl parsed successfully), `pqc_certs`, `hybrid_certs`, `cert_categories` (`classical` / `hybrid_composite` / `pure_pqc` counts), `total_found` (candidate `*.pem` / `*.crt` files after symlink de-duplication), `scanned_count` (files handed to openssl, ≤ `max_certs`), `max_certs` (cap in effect, default 500, set by `--trust-store-max-certs`), and `truncated` (true when `total_found > max_certs`, i.e. some files were not inspected; files are scanned in sorted path order so a capped scan is deterministic). |
| `runtime_environment` | How the probe is running (bare metal, container, DaemonSet, …). |
| `host_fs_detections_unavailable` | Object keyed by detection (`accelerators`, `kernel_crypto_hw`, `ktls`, `fips`, `tpm_pqc`, `kernel_info`, `os_release`, `pkcs11_modules`). Each value is `{"unavailable_in_container": true, "reason": "<detection> reads <host paths>; …"}`. Populated only when running inside a container without `--host-mount`; `{}` on bare metal or when `--host-mount` is in effect. Detections whose own field is an object (`fips`, `tpm_pqc`, `kernel_info`, `os_release`) also carry the same two keys inline; list/boolean fields (`accelerators`, `kernel_crypto_hw`, `ktls_supported`, `pkcs11_modules`) are annotated only here so their types stay stable. The aggregator surfaces a `host_fs_detections_unavailable_host_count` rollup. |
| `packages` | Installed crypto-bearing packages. Populated only when `--scan-packages` is set. |
| `replace_required` | Top-level boolean for fleet planning: true when the host cannot run NIST PQC at production speed without an accelerator. |
| `os_release` | Parsed `/etc/os-release` (id, version, like-chain). |
| `benchmark` | Microbenchmark results object from `--bench`. `null` when `--bench` is not set. When the bench ran but could not execute, an object with `available: false` and `reason`. |
| `benchmark_tls_handshake` | TLS 1.3 handshake bench results object from `--bench-tls`. `null` when `--bench-tls` is not set. When the bench ran but could not execute, an object with `available: false` and `reason`. |
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
`--cbom`. No `--json` field renames are recommended at this time, so
no major (`2.0`) bump is planned; the current `SCHEMA_VERSION` is
`"1.2"` from additive changes only.
