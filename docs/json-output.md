# JSON output reference

`pqc-readiness --json` emits a stable, schema-versioned document.
The current `schema_version` is `"1.4"`. It follows the bump rules in
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
| `1.3` | `benchmark.pqc.<algo>.skipped` (algorithm not provided by the local OpenSSL; never benchmarked); `benchmark.classical.rsa2048_kem` and `benchmark.classical.rsa2048_signature` rows. `trust_store` counts are per unique certificate, every certificate in bundle files is inspected, and PQC certificates are classified by DER OID (#116). |
| `1.4` | `packages.source` (`rpmdb-sqlite` \| `rpm-cli`) and `packages.db_root` on RPM hosts; the rpm database is read in-process and, under `--host-mount`, from the **host** (earlier releases inventoried the scanner image). `nss.tool` may be `rpmdb (sqlite)` or `rpm -qa`. `host_fs_detections_unavailable` gained `packages` and `nss` keys (#125). |

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
| `schema_version` | Schema version string, currently `"1.4"`. Major bump on rename/remove/re-type, minor bump on additive changes. |
| `generated_at` | ISO 8601 UTC timestamp of the probe run. |
| `hostname` | Host's reported hostname. |
| `os` | Human-readable OS name: `os_release.pretty_name`, or `<system> <kernel release>` (e.g. `Linux 6.12.0`) when `/etc/os-release` gave none. |
| `arch` | CPU architecture (`x86_64`, `aarch64`, `s390x`, …). |
| `cpu_model` | CPU model string from `/proc/cpuinfo` or `sysctl`. |
| `cpu_freq_mhz` | Maximum CPU frequency in MHz (`cpuinfo_max_freq`, else `scaling_max_freq`, else `cpu MHz` from `/proc/cpuinfo`; `hw.cpufrequency_max` on macOS), rounded to 0.1. `0.0` when no source is readable. |
| `cores_logical` | Logical core count (SMT siblings included). |
| `cores_physical` | Physical core count. |
| `mem_total_gb` | Total system memory in GiB. |
| `mem_avail_gb` | Available memory in GiB at probe time. |
| `memory` | Role-aware memory tier (added in schema `1.1`). `tier` (`excellent` / `good` / `marginal` / `poor`) and `reason` evaluate `mem_total_gb` against the threshold for `tier_basis.role` — the `--role` value, or `generic` when none is given. `tier_basis` = `{role, threshold_gib_good, role_supplied}`. When `--role` is not supplied, `tier_by_role` maps every role (`tls-server`, `tls-client`, `signing-service`, `firmware-signing`, `generic`) to `{tier, reason, threshold_gib_good}`. |
| `isa_features` | Map of the PQC-relevant CPU flags present on this host, keyed by the kernel flag name (e.g. `avx512vbmi`, `sha3`, `msa9`). See [`isa_features`](#isa_features). |
| `isa_score` | Numeric ISA score backing the tier classification. |
| `isa_tier` | ISA tier: `excellent` / `good` / `marginal` / `poor`. |
| `isa_reason` | Human-readable explanation for the ISA tier. |
| `accelerators` | List of detected accelerators. See [`accelerators[]`](#accelerators). |
| `hsm_present_but_not_pqc` | True when an HSM is detected but it does not advertise PQC primitives. |
| `pkcs11_modules` | Sorted list of PKCS#11 module file paths (`*.so`, `*.dylib`) found in the family-appropriate PKCS#11 directories. Under a container without `--host-mount`, `host_fs_detections_unavailable.pkcs11_modules` is set. |
| `kernel_crypto_hw` | List of `/proc/crypto` driver names backed by hardware. Inside a container without `--host-mount` this is the container's view; `host_fs_detections_unavailable.kernel_crypto_hw` is then set. |
| `ktls_supported` | `true` / `false`, or `null` on non-Linux. Inside a container without `--host-mount` this reflects the container's `/proc/modules` and `/sys/module/tls`; `host_fs_detections_unavailable.ktls` is then set. |
| `fips` | Kernel FIPS mode, OpenSSL FIPS provider state, distribution certification context and the FIPS algorithm-fence check. See [`fips`](#fips). |
| `openssl` | OpenSSL version, PQC KEM / signature algorithms, TLS groups split into pure-PQC / hybrid / classical, providers and an upgrade hint. See [`openssl`](#openssl). |
| `tpm_pqc` | TPM presence and whether `tpm2_getcap` advertises PQC algorithms. See [`tpm_pqc`](#tpm_pqc). |
| `memory_bandwidth_gb_s` | Memory bandwidth measurement in GB/s. `null` when `--bench` was not set or the probe could not measure. |
| `memory_bandwidth_method` | How the bandwidth value was obtained (e.g. `STREAM-triad (numpy)`), or the reason it could not be measured (e.g. `unavailable: numpy not installed`). `null` when `--bench` was not set. |
| `ssh_pqc` | OpenSSH `ssh -Q kex` availability. `kex_groups` splits the detected kex names into `pure_pqc` / `hybrid` / `classical` buckets, mirroring `openssl.tls_groups`. |
| `ipsec_pqc` | strongSwan / Libreswan presence and PQC (ML-KEM) key-exchange support. See [`ipsec_pqc`](#ipsec_pqc). |
| `nss` | NSS PQC algorithm exposure: `{available, tool, version, pqc_capable, note?}`. `tool` is `certutil --version`, `rpmdb (sqlite)` / `rpmdb (bdb)` / `rpmdb (ndb)` (package `nss` / `mozilla-nss` read from the rpm database in-process; the suffix is the database format) or `rpm -q` (CLI fallback when the database cannot be read directly). Under `--host-mount` the host rpm database is consulted before `certutil`, because `certutil` belongs to the scanner image. |
| `kernel_info` | Kernel release, OS identity copies kept for back-compat, `/etc/redhat-release` and PQC-named `/proc/crypto` drivers. See [`kernel_info`](#kernel_info). |
| `fips_pqc_conflict` | `{in_conflict, explanation}`: `in_conflict` is true when kernel FIPS mode is on but PQC algorithms are exposed only through the non-FIPS default provider. See [`fips_pqc_conflict`](#fips_pqc_conflict). |
| `cnsa_2_0` | CNSA 2.0 evaluation: overall `status` plus per-category compliance booleans and gap notes. See [`cnsa_2_0`](#cnsa_2_0). |
| `trust_store` | Trust-store summary. Populated only when `--scan-trust-store` is set (`{}` otherwise). Certificates are classified from the signature-algorithm and SubjectPublicKeyInfo OIDs in their DER encoding (independent of the installed OpenSSL), every certificate in multi-certificate bundle files is inspected, and counts are per **unique certificate** (SHA-256 of the DER; a `TRUSTED CERTIFICATE` block counts as its embedded certificate). Keys: `available`, `scanned_dirs`, `total_certs` (unique certificates whose DER parsed), `pqc_certs` (signature or key algorithm is ML-DSA / SLH-DSA), `hybrid_certs` (pre-standard hybrid OIDs), `cert_categories` (`classical` / `hybrid_composite` / `pure_pqc` counts), `total_found` (unique certificates found across all `*.pem` / `*.crt` files after symlink de-duplication), `scanned_count` (certificates classified, ≤ `max_certs`), `max_certs` (cap in effect, default 500, set by `--trust-store-max-certs`), and `truncated` (true when `total_found > max_certs`; certificates are taken in sorted file order, then file order, so a capped scan is deterministic). Earlier releases counted *files*, read only the first certificate in each, and missed PQC certificates on OpenSSL ≥ 3.5 (#116); the field shapes are unchanged, but the count semantics changed in schema `1.3`, so counts from older reports are not comparable (the fleet aggregator already refuses to mix versions). |
| `runtime_environment` | `{environment, evidence}`: `environment` is `container` or `host`; `evidence` is the marker that decided it. See [`runtime_environment`](#runtime_environment). |
| `service_crypto_linkage` | Listening sockets mapped to the process that owns each one and the crypto library it actually uses. Populated only when `--scan-services` is set (`{}` otherwise). Pure `/proc` inspection, no network connections. See [`service_crypto_linkage`](#service_crypto_linkage). |
| `host_fs_detections_unavailable` | Object keyed by detection (`accelerators`, `kernel_crypto_hw`, `ktls`, `fips`, `tpm_pqc`, `kernel_info`, `os_release`, `pkcs11_modules`, `packages`, `nss`). Each value is `{"unavailable_in_container": true, "reason": "<detection> reads <host paths>; …"}`. Populated only when running inside a container without `--host-mount`; `{}` on bare metal or when `--host-mount` is in effect. Detections whose own field is an object (`fips`, `tpm_pqc`, `kernel_info`, `os_release`) also carry the same two keys inline; list/boolean fields (`accelerators`, `kernel_crypto_hw`, `ktls_supported`, `pkcs11_modules`) are annotated only here so their types stay stable. The aggregator surfaces a `host_fs_detections_unavailable_host_count` rollup. |
| `packages` | Installed crypto-bearing packages. Populated only when `--scan-packages` is set. Keys: `available`, `package_manager`, `total_packages`, `bundled_crypto`. On RPM families also `source` — `rpmdb-sqlite` (EL9+, Fedora, CentOS Stream, Amazon Linux 2023, Oracle Linux 9+), `rpmdb-bdb` (Berkeley DB: EL8, openSUSE Leap 15 cloud images) or `rpmdb-ndb` (SLES 15, Leap 16, Tumbleweed), each read in-process without the `rpm` binary, or `rpm-cli` (only when the database cannot be read directly: unrecognised or corrupt file, or no `sqlite3` module) — and `db_root`, the host-relative database directory (`/var/lib/rpm`, `/usr/lib/sysimage/rpm` or `/usr/share/rpm`; `null` when rpm located it itself). The backend is identified by file magic. Under `--host-mount` the host database is read (the CLI fallback runs `rpm --root <mount> --dbpath <db_root>`), and the scan reports unavailable rather than inventorying the scanner image when no host database is mounted. |
| `replace_required` | Top-level boolean for fleet planning: true when the host cannot run NIST PQC at production speed without an accelerator. |
| `os_release` | Parsed `/etc/os-release` plus the derived distro `family` and `package_manager`. See [`os_release`](#os_release). |
| `benchmark` | Microbenchmark results object from `--bench`. `null` when `--bench` is not set. When the bench ran but could not execute, an object with `available: false` and `reason`. `pqc` maps each planned algorithm (`ML-KEM-768`, `ML-DSA-65`, `SLH-DSA-SHA2-128s`) to its per-second rates, or to `{"skipped": "algorithm not provided by this OpenSSL"}` when the local OpenSSL does not expose it (the benchmark is never attempted, since `openssl speed` given an unknown name runs every algorithm in that class), or to `{"error": ...}` / `{"raw": ...}` when it ran but failed or could not be parsed. `classical` holds the baseline rows: `rsa2048` (legacy block: `sign/s`, `verify/s`, `encr./s`, `decr./s`), `ecdh` (`op/s`), `eddsa` (`sign/s`, `verify/s`), plus `rsa2048_kem` (`keygens/s`, `encaps/s`, `decaps/s`) and `rsa2048_signature` (`keygens/s`, `sign/s`, `verify/s`) on OpenSSL builds that also run RSA as a KEM and signature scheme. |
| `benchmark_tls_handshake` | TLS 1.3 handshake bench results object from `--bench-tls`. `null` when `--bench-tls` is not set. When the bench ran but could not execute, an object with `available: false` and `reason`. |
| `pqc_sizes` | Byte sizes of PQC keys, ciphertexts and signatures, keyed by algorithm (constants, not measured). See [`pqc_sizes`](#pqc_sizes). |
| `per_algo` | Per-algorithm tier from the `--bench` rates, keyed `ML-KEM-768`, `ML-DSA-65`, `ML-DSA-65/verify`, `ML-DSA-87`, `ML-DSA-87/verify`, `SLH-DSA-SHA2-128s`. `{}` without `--bench`. See [`per_algo`](#per_algo). |
| `production_estimate` | Sustainable throughput and connection estimates derived from `per_algo` and `mem_total_gb`. `{}` without `--bench`. See [`production_estimate`](#production_estimate). |
| `verdict` | Overall verdict sentence, one of `EXCELLENT - dedicated PQC silicon present`, `EXCELLENT - software PQC at production speed`, `GOOD - production-capable in software`, `MARGINAL - works, but plan for an accelerator`, `POOR - not suitable for production PQC`. The text before ` - ` is the tier (the fleet aggregator groups on it). |
| `verdict_reason` | One-line explanation for the verdict. |
| `verdict_caveat` | `""` when `--bench` measured the PQC primitives; otherwise an explanation that the verdict reflects CPU instruction set and memory only. |
| `exit_code` | Numeric exit code the program will return. Mirrors the [Exit codes](../README.md#exit-codes) table in the README. |

## Nested fields

One subsection per object-valued field. Conventions used throughout:

- A detection that could not run returns `{"available": false, "reason": "<why>"}` in place of its normal keys (e.g. `openssl` when the binary is missing, `ssh_pqc` when `ssh` is absent).
- Object-valued detections that read host files (`fips`, `tpm_pqc`, `kernel_info`, `os_release`, `nss`, `packages`) also carry `unavailable_in_container: true` and a `reason` inline when running in a container without `--host-mount`; see [`host_fs_detections_unavailable`](#host_fs_detections_unavailable).
- Rates are operations per second; sizes are bytes; memory is GiB unless stated.

### `memory`

| Key | Type | Meaning |
| --- | --- | --- |
| `tier` | string | `excellent` / `good` / `marginal` / `poor` for `mem_total_gb` under the role in `tier_basis`. |
| `reason` | string | Human-readable basis for `tier`. |
| `tier_basis` | object | `{role, threshold_gib_good, role_supplied}`. |
| `role` | string | Role whose threshold was applied: the `--role` value, or `generic`. |
| `threshold_gib_good` | number | GiB needed for `good` under that role: `tls-server` 16, `tls-client` 4, `signing-service` 8, `firmware-signing` 2, `generic` 16. |
| `role_supplied` | bool | Whether `--role` was given. |
| `tier_by_role` | object | Present only when `--role` was **not** given. Keys are every role (`tls-server`, `tls-client`, `signing-service`, `firmware-signing`, `generic`); each value is `{tier, reason, threshold_gib_good}`. |

### `isa_features`

Keyed by kernel CPU flag name (only flags present on the host appear; the catalogue differs per architecture: x86_64 AVX-512 family / AES / PCLMULQDQ / SHA-NI / GFNI / VAES, aarch64 ARMv8 crypto / SHA-3 / SVE2 / I8MM, s390x CPACF MSA levels). Each value:

| Key | Type | Meaning |
| --- | --- | --- |
| `name` | string | Display name of the feature. |
| `purpose` | string | Why the feature matters for PQC. |

### `accelerators[]`

Each list item describes one detected device or HSM client configuration:

| Key | Type | Meaning |
| --- | --- | --- |
| `kind` | string | `hsm`, `accel`, `dpu`, `gpu`, `tpm` (from `lspci -nn` / device-node hints) or `network_hsm` (client configuration file present). |
| `name` | string | Product family label, e.g. `Intel QuickAssist (QAT)`. |
| `detail` | string | Evidence: the matching `lspci` line, the device path, the client config path, or on s390x `card=… domain=… mode=… status=…`. |
| `pqc_capable` | bool | Present for s390x Crypto Express adapters (true only for CEX8 in EP11 mode) and network HSMs (always false: the client config cannot prove PQC firmware). Absent for `lspci` / device-node hints. |
| `cex_level` | string | s390x only: Crypto Express level, e.g. `CEX8`. |
| `cex_mode` | string | s390x only: adapter mode, e.g. `EP11`, `CCA`, `Accel`. |

### `fips`

| Key | Type | Meaning |
| --- | --- | --- |
| `kernel` | bool | `/proc/sys/crypto/fips_enabled` reads `1`. |
| `openssl_provider` | bool | An OpenSSL FIPS provider is listed **and active** (`openssl list -providers -verbose`). |
| `distribution_certified` | bool | True only when `kernel` and `openssl_provider` are both true **and** the distro matches a known vendor-certified family. Never claimed for Debian, Arch, Alpine or unknown distros. |
| `distribution_certified_source` | string \| null | Which certification the claim rests on; `null` when `distribution_certified` is false. |
| `notes` | string | Family-specific guidance on PQC under FIPS (does not assert compliance). |
| `fence_check_active` | bool | Whether the FIPS algorithm-fence check ran (it needs kernel FIPS and a FIPS provider). |
| `fence_check_skip_reason` | string | Present only when `fence_check_active` is false: why it was skipped. |
| `algorithm_fence_engaged` | bool | True when the default provider exposes no PQC algorithm outside the FIPS provider's set. `--fips-strict` exits 4 when the check is active and this is false. See [docs/findings/fips-algorithm-fence.md](findings/fips-algorithm-fence.md). |
| `algorithms_reachable_outside_fence` | object | `{kems, signatures, tls_groups}`: lists of PQC names reachable through a non-FIPS provider while FIPS mode is on. |

### `fips_pqc_conflict`

| Key | Type | Meaning |
| --- | --- | --- |
| `in_conflict` | bool | Kernel FIPS is on, OpenSSL exposes PQC algorithms, and no FIPS provider is active, so the PQC algorithms are not usable in a FIPS-validated workflow. |
| `explanation` | string | Which of the four states applies and what to check. |

### `openssl`

| Key | Type | Meaning |
| --- | --- | --- |
| `available` | bool | `openssl` binary found. When false only `reason` follows. |
| `version` | string | `openssl version` output, or `unknown`. |
| `version_tuple` | list[int] \| null | `[major, minor, patch]`, or `null` when unparseable. |
| `pqc_native` | bool | Version ≥ 3.5 (native ML-KEM / ML-DSA / SLH-DSA). |
| `kem_algorithms` | list[string] | `ML-KEM-*` names from `openssl list -kem-algorithms`. |
| `sig_algorithms` | list[string] | `ML-DSA-*` / `SLH-DSA-*` names from `openssl list -signature-algorithms`. |
| `tls_groups` | object | TLS 1.3 groups split into `pure_pqc` (e.g. `MLKEM768`), `hybrid` (e.g. `X25519MLKEM768`, `SecP256r1MLKEM768`) and `classical`; each a list. |
| `tls_pqc_groups` | list[string] | Back-compat union of `tls_groups.pure_pqc` and `tls_groups.hybrid`; prefer `tls_groups`. |
| `tls_group_references` | object | Present when OpenSSL was probed. One entry per known PQC group in `tls_groups.pure_pqc` / `hybrid`, keyed by name: `codepoint` (IANA TLS Supported Groups value, e.g. `0x11EC`), `kem`, `classical` (`null` for pure groups), `recommended` (IANA "Recommended" column), `cnsa_2_0` (true only for an ML-KEM-1024 component), `reference` (`RFC 10024` or `draft-ietf-tls-mlkem`), `status` (`final` or `draft`), `url`, and `obsolete: true` for the pre-standard Kyber groups. Unknown names are omitted. |
| `providers` | list[string] | Active provider names. |
| `upgrade_path` | string \| null | Family-aware advice for reaching OpenSSL ≥ 3.5; `null` when already there or no advice applies. |
| `reason` | string | Present only when `available` is false. |

### `tpm_pqc`

| Key | Type | Meaning |
| --- | --- | --- |
| `present` | bool | `/dev/tpmrm0` or `/dev/tpm0` exists (always true once `tpm2_getcap` ran). |
| `tools` | bool | `tpm2_getcap` (tpm2-tools) is installed. |
| `pqc_advertised` | bool | Present only when `tpm2_getcap algorithms` succeeded: whether it lists any ML-KEM / ML-DSA / Kyber / Dilithium / SPHINCS algorithm. |
| `note` | string | Context (tools missing, query failed, or that TPM 2.0 does not yet mandate PQC). |
| `raw` | string | Present only when `tpm2_getcap` failed: first 200 characters of its output. |

### `ssh_pqc`

| Key | Type | Meaning |
| --- | --- | --- |
| `available` | bool | `ssh -Q kex` ran. When false, `reason` (and `version` if `ssh -V` worked) follow. |
| `version` | string \| null | OpenSSH version from `ssh -V`. |
| `kex_count` | int | Number of key-exchange methods the client binary supports. |
| `pqc_kex` | list[string] | Back-compat flat list of PQC / hybrid methods (ML-KEM hybrids, `sntrup761`); prefer `kex_groups`. |
| `kex_groups` | object | `pure_pqc` / `hybrid` / `classical` lists, mirroring `openssl.tls_groups`. |
| `kex_references` | object | Present when `ssh -Q kex` ran. One entry per known PQC kex in `kex_groups.pure_pqc` / `hybrid`: `kem`, `classical`, `cnsa_2_0`, `reference` (`RFC 10042` or `RFC 9941`), `status`, `url`, and `alias_of` for the pre-RFC `sntrup761x25519-sha512@openssh.com` name. |
| `reason` | string | Present only when `available` is false. |

### `ipsec_pqc`

| Key | Type | Meaning |
| --- | --- | --- |
| `available` | bool | A strongSwan (`swanctl`) or Libreswan (`ipsec`) installation answered. |
| `implementation` | string | `strongswan` or `libreswan`. |
| `pqc` | bool | strongSwan: `swanctl --list-algs` lists ML-KEM / Kyber. Libreswan: always false (PQC is pre-release there). |
| `evidence` | string \| null | strongSwan only: the matching algorithm token. |
| `version` | string \| null | Libreswan only: version from `ipsec --version`. |
| `note` | string | Libreswan only: pre-release caveat. |
| `reason` | string | Why `swanctl --list-algs` failed (kept even if Libreswan then answered), or that neither tool is on PATH. |

### `nss`

| Key | Type | Meaning |
| --- | --- | --- |
| `available` | bool | An NSS version was found. When false only `reason` follows. |
| `tool` | string | `certutil --version`; `rpmdb (sqlite)`, `rpmdb (bdb)` or `rpmdb (ndb)` (package `nss` / `mozilla-nss` read from the rpm database in-process: the sqlite `Name` index, or a full read of Berkeley DB / ndb when `rpm` is unavailable); or `rpm -q` (looked up through the rpm CLI, the first choice on Berkeley DB / ndb because it uses rpm's own index). |
| `version` | string | `major.minor.patch`, the raw string if unparseable, or `unknown`. With several installs (i686 + x86_64) the highest. |
| `pqc_capable` | bool | Version ≥ 3.108. |
| `note` | string | Present for rpm-sourced versions (distro package version, not necessarily upstream), and under `--host-mount` when only the image's `certutil` was available. |
| `reason` | string | Present only when `available` is false. |

### `kernel_info`

| Key | Type | Meaning |
| --- | --- | --- |
| `release` | string | Kernel release (`uname -r`). |
| `system` | string | Kernel name (`Linux`, `Darwin`). Non-Linux reports stop here. |
| `os_release_id` | string | Copy of `os_release.id`, kept for aggregator / CSV back-compat. Absent when unknown. |
| `os_release_version_id` | string | Copy of `os_release.version_id`. Absent when unknown. |
| `redhat_release` | object | Present when `/etc/redhat-release` exists: `raw` (the line), plus `distro` and `version` when it matches `<distro> release <version>`, and `minor` when the version has one. |
| `proc_crypto_pqc` | list[string] | `/proc/crypto` driver names whose algorithm mentions a PQC primitive; normally `[]` (kernel PQC is not in mainline). |

### `cnsa_2_0`

| Key | Type | Meaning |
| --- | --- | --- |
| `status` | string | `compliant` (all four true), `partial`, `non_compliant` (none true) or `unknown` (neither OpenSSL nor `/proc/crypto` could be inspected). |
| `kem_compliant` | bool | `ML-KEM-1024` exposed by OpenSSL. |
| `signature_compliant` | bool | `ML-DSA-87` exposed by OpenSSL. |
| `symmetric_compliant` | bool | An AES driver with a ≥ 32-byte key in `/proc/crypto`. |
| `hash_compliant` | bool | Hardware-accelerated SHA-384 **and** SHA-512 drivers in `/proc/crypto`. |
| `tls_key_exchange` | object | Informational split of the PQC TLS groups OpenSSL offers: `compliant_groups` (ML-KEM-1024 component: `SecP384r1MLKEM1024`, `MLKEM1024`) and `non_compliant_pqc_groups` (e.g. `X25519MLKEM768`). Does not change `status`; a note is added when PQC groups are offered but none is compliant. |
| `notes` | list[string] | One entry per gap or per input that could not be checked; a false boolean means "missing or not checkable", and `notes` says which. |
| `requirements` | object | The suite as evaluated: `{kem: ["ML-KEM-1024"], signature: ["ML-DSA-87"], symmetric: ["AES-256"], hash: ["SHA-384", "SHA-512"]}`. |

### `trust_store`

`{}` unless `--scan-trust-store`. When the scan ran: `available`, `scanned_dirs`, `total_certs`, `pqc_certs`, `hybrid_certs`, `cert_categories` (`classical` / `hybrid_composite` / `pure_pqc` counts), `total_found`, `scanned_count`, `max_certs`, `truncated`, as described in the [top-level table](#top-level-keys).

### `runtime_environment`

| Key | Type | Meaning |
| --- | --- | --- |
| `environment` | string | `container` or `host`. |
| `evidence` | string | The marker that decided it: `/.dockerenv present`, `/run/.containerenv present`, `cgroup marker <m>`, or `no container markers`. |

### `service_crypto_linkage`

`{}` unless `--scan-services`. Built from `/proc/<pid>/net/{tcp,tcp6,udp,udp6}` (read once per network namespace), `/proc/<pid>/fd`, `/proc/<pid>/maps`, and the executable and libraries as the process itself sees them (`/proc/<pid>/root`, or `/proc/<pid>/map_files` for a deleted library). Without root, or CAP_SYS_PTRACE and CAP_DAC_READ_SEARCH, other users' processes can't be read. They are counted in `unreadable_pids`, never guessed.

| Key | Type | Meaning |
| --- | --- | --- |
| `available` | bool | Scan ran. When false only `reason` follows (not Linux, or `/proc` unreadable). |
| `listeners` | list[object] | One entry per listening TCP socket or bound, unconnected UDP socket; see the listener table below. |
| `summary` | object | `listeners` (count), `unattributed_listeners` (no readable owning process), `listeners_by_crypto_family` (`openssl` / `libressl` / `boringssl` / `aws-lc` / `gnutls` / `nss` / `wolfssl` / `go` / `none` → count), `listeners_with_deleted_crypto_library` (the service still maps a library that an upgrade replaced: restart it to pick up the new one). |
| `scanned_pids` | int | Processes inspected. |
| `unreadable_pids` | int | Processes whose file-descriptor table could not be read (permissions). |
| `truncated` | bool | The scan stopped at `limits.max_pids` or `limits.time_budget_s`, so later processes were not inspected. |
| `limits` | object | `max_pids` (default 4096) and `time_budget_s` (default 15). |
| `note` | string | Present when `unreadable_pids` > 0: how to get complete attribution. |
| `reason` | string | Present when `available` is false, or with `unavailable_in_container` (running in a container without `--host-mount` / hostPID: the scan only sees the container's own processes). |

Listener entries. `protocol`, `address`, `port` and `bind_scope` are the join keys that endpoint-observation ingestion (#149) matches against what a network scan saw on this host's addresses:

| Key | Type | Meaning |
| --- | --- | --- |
| `protocol` | string | `tcp` or `udp` (UDP covers QUIC, DTLS and IKE listeners). |
| `family` | string | `ipv4` or `ipv6`. |
| `address` | string | Bound address as the kernel reports it (IPv4-mapped IPv6 kept as written). |
| `port` | int | Bound port. |
| `bind_scope` | string | `any` (wildcard), `loopback`, `multicast`, `link-local` or `specific`. A remote observation can only match `any` or `specific`. |
| `network_namespace` | string | `host` (same namespace as PID 1) or `other` (e.g. a container with its own network: reachable from outside only through port mapping). |
| `pid` | int \| null | Lowest owning PID; `null` when no readable process holds the socket. |
| `pids` | list[int] | Every readable process holding the socket (e.g. a server's master and workers). |
| `process` | string \| null | `comm` of `pid`. |
| `exe` | string \| null | Executable path of `pid`, in its own mount namespace. |
| `systemd_unit` | string \| null | Unit (`*.service` / `*.scope`) from the process's cgroup, when it has one. |
| `cgroup` | string \| null | The process's cgroup path (last 200 characters). |
| `crypto_libraries` | list[object] | Crypto libraries the process maps: `{family, path, version, version_source, deleted, library_pqc_capable}`. `family` is `openssl`, `libressl`, `boringssl`, `aws-lc`, `gnutls`, `nss` or `wolfssl` (OpenSSL forks share sonames and are told apart by their embedded strings). `version_source` is `embedded` (version string inside the library), `filename` (e.g. `libssl.so.3.5.9`), `sibling-libcrypto` (libssl takes the version of the libcrypto beside it) or `null`. `deleted` is true when the mapped file was replaced on disk. `library_pqc_capable` is whether that library *version* ships ML-KEM hybrid TLS key exchange (OpenSSL ≥ 3.5, NSS ≥ 3.108); `null` where no verified threshold is encoded yet. Whether the service turns it on is configuration (#106 / #107). |
| `static_binary` | bool \| null | The executable has no ELF interpreter (statically linked); `null` when it could not be read. |
| `go` | object \| null | For Go binaries: `go_version` (e.g. `go1.24.4`, from the embedded build info; `null` for pre-1.18 binaries), `main_module`, `cgo_enabled`, `default_hybrid_kex` and `godebug_reverts`. `default_hybrid_kex` is the hybrid key exchange crypto/tls offers when the program leaves `CurvePreferences` unset: `X25519MLKEM768` from Go 1.24 (which also removed the Kyber draft), `X25519Kyber768Draft00` on Go 1.23, else `null`. `godebug_reverts` lists `tlsmlkem` / `tlskyber` / `tlssecpmlkem` set to `0` by the binary's `DefaultGODEBUG` or the process's `GODEBUG` environment variable, which turn those defaults off. Only `GODEBUG` is read from the environment; nothing else is kept. |

### `host_fs_detections_unavailable`

Keyed by detection: `accelerators`, `kernel_crypto_hw`, `ktls`, `fips`, `tpm_pqc`, `kernel_info`, `os_release`, `pkcs11_modules`, `packages`, `nss`. Each value:

| Key | Type | Meaning |
| --- | --- | --- |
| `unavailable_in_container` | bool | Always true when present. |
| `reason` | string | Which host paths the detection reads and that the result reflects the container. |

### `packages`

`{}` unless `--scan-packages`.

| Key | Type | Meaning |
| --- | --- | --- |
| `available` | bool | Inventory succeeded. When false only `reason` follows. |
| `package_manager` | string | `rpm`, `dpkg-query`, `pacman` or `apk`. |
| `source` | string | RPM families only: `rpmdb-sqlite`, `rpmdb-bdb` or `rpmdb-ndb` (database read in-process; the suffix is its format) or `rpm-cli` (fallback when it cannot be read directly). |
| `db_root` | string \| null | RPM families only: host-relative rpm database directory. |
| `total_packages` | int | Installed packages counted (on RPM hosts this includes `gpg-pubkey` entries, as `rpm -qa` does). |
| `bundled_crypto` | list[object] | Packages that embed their own crypto stack, each `{package, version, note}` where `note` names the stack (e.g. `Go runtime (crypto/tls embedded)`). |
| `reason` | string | Present when `available` is false, or with `unavailable_in_container`. |

### `os_release`

| Key | Type | Meaning |
| --- | --- | --- |
| `id` | string | `ID` from `/etc/os-release` (`unknown` when absent). |
| `version_id` | string | `VERSION_ID`. |
| `version_codename` | string \| null | `VERSION_CODENAME`; `null` when unset. |
| `pretty_name` | string | `PRETTY_NAME`. |
| `family` | string | Derived distro family (from `ID`, then `ID_LIKE`): `rhel`, `debian`, `suse`, `arch`, `alpine`, `macos` or `unknown`. |
| `package_manager` | string \| null | Package tool for the family (`rpm`, `dpkg-query`, `pacman`, `apk`). |

### `pqc_sizes`

Keyed by algorithm: `ML-KEM-768`, `ML-DSA-65`, `ML-DSA-87`, `SLH-DSA-SHA2-128s`, `SLH-DSA-SHA2-128f`, `SLH-DSA-SHA2-256f`. Values in bytes:

| Key | Meaning |
| --- | --- |
| `role` | Typical use (e.g. `TLS KEM`, `general sig`). |
| `pk` | Public key size. |
| `sk` | Secret key size. |
| `ct` | KEM ciphertext size (KEMs only). |
| `shared` | KEM shared-secret size (KEMs only). |
| `sig` | Signature size (signature schemes only). |

### `benchmark`

`null` unless `--bench`.

| Key | Type | Meaning |
| --- | --- | --- |
| `available` | bool | False when OpenSSL is missing or older than 3.5; then only `reason` follows. |
| `engine` | string | `openssl speed`. |
| `seconds_per_test` | int | `--seconds`. |
| `threads` | int | `--threads`. |
| `pqc` | object | Keyed `ML-KEM-768`, `ML-DSA-65`, `SLH-DSA-SHA2-128s`. Each value is a rate map (`keygen/s`, `encaps/s`, `decaps/s` for KEMs; `keygen/s`, `sign/s`, `verify/s` for signatures), plus `x<N>_aggregate` (same rate keys, all threads) when `--threads N` > 1; or `{skipped}` (algorithm not provided by this OpenSSL, never run), `{error}` (run failed) or `{raw}` (output not parseable). |
| `classical` | object | Baseline rows keyed by `openssl speed` name: `rsa2048` (`sign/s`, `verify/s`, `encr./s`, `decr./s`), `rsa2048_kem` (`keygens/s`, `encaps/s`, `decaps/s`), `rsa2048_signature` (`keygens/s`, `sign/s`, `verify/s`), `eddsa` (`sign/s`, `verify/s`), `ecdh` (`op/s`). Rows appear only when OpenSSL printed them. |
| `reason` | string | Present only when `available` is false. |

### `benchmark_tls_handshake`

`null` unless `--bench-tls`.

| Key | Type | Meaning |
| --- | --- | --- |
| `available` | bool | False when OpenSSL is missing, older than 3.5, its capability probe failed, or it recognises no TLS groups; then only `reason` follows. |
| `engine` | string | `tls-handshake`. |
| `transport` | string | `loopback`. |
| `openssl_version` | string | OpenSSL used for `s_server` / `s_client`. |
| `iterations_per_suite` | int | Handshakes attempted per suite. |
| `seconds_budget` | int | `--seconds` value the iteration count was derived from. |
| `note` | string | Measurement caveat (TTFB includes `s_client` start-up, constant across suites). |
| `suites` | list[object] | One entry per suite; see below. |

Each `suites[]` entry:

| Key | Type | Meaning |
| --- | --- | --- |
| `label` | string | E.g. `hybrid (X25519MLKEM768)`. |
| `role` | string | `classical`, `hybrid`, `pure_pqc` or `composite_sig`. |
| `group` | string | TLS group negotiated. |
| `cert_signature_algorithm` | string | `composite_sig` suites only: the composite signature algorithm of the server certificate. |
| `iterations` | int | Successful handshakes. |
| `handshakes_per_sec` | number | Successful handshakes per second of handshake time. |
| `ttfb_ms_mean` | number | Mean time to first byte, ms. |
| `ttfb_ms_median` | number | Median time to first byte, ms. |
| `bytes_on_wire_per_handshake` | int \| null | Mean bytes through the counting proxy per connection. |
| `bytes_observed_connections` | int | Connections the proxy measured. |
| `error` | string | Present instead of the metrics when the suite could not run (server did not listen, proxy failed, no successful handshake). |
| `detail` | string | With `error`, the first 200 characters of `s_server` stderr when available. |
| `skipped` | bool | `composite_sig` only: certificate generation failed; `reason` says why. |
| `reason` | string | With `skipped`. |

### `per_algo`

`{}` unless `--bench`. Keyed `ML-KEM-768`, `ML-DSA-65`, `ML-DSA-65/verify`, `ML-DSA-87`, `ML-DSA-87/verify`, `SLH-DSA-SHA2-128s` (the suffix names the operation scored when one algorithm has several thresholds).

| Key | Type | Meaning |
| --- | --- | --- |
| `algorithm` | string | Algorithm benchmarked. |
| `metric` | string | Operation scored, e.g. `encaps/s`, `sign/s`, `verify/s`. |
| `tier` | string | `excellent` / `good` / `marginal` / `poor`, or `unknown` when there was no rate. SLH-DSA drops one tier when measured memory bandwidth is under 10 GB/s. |
| `reason` | string | Rate vs. threshold, the benchmark's `skipped` reason, or `no benchmark data`. |
| `rate_per_core` | number | Measured rate (single thread). Absent when `tier` is `unknown`. |
| `rate_host_estimate` | number | `rate_per_core` × physical cores (logical cores when the physical count is unknown). Absent when `tier` is `unknown`. |
| `thresholds` | object | `{excellent, good, marginal}` per-core rates for this metric. Absent when `tier` is `unknown`. |
| `notes` | list[string] | Algorithm guidance (e.g. SLH-DSA not for hot paths, hybrid TLS preferred during transition, bandwidth downgrade). |

### `production_estimate`

`{}` unless `--bench`. Assumes 60 % of CPU is available for crypto and 50 % of RAM for connection state.

| Key | Type | Meaning |
| --- | --- | --- |
| `tls_pqc_handshakes_per_sec` | int | From `per_algo.ML-KEM-768`. |
| `ml_dsa_signatures_per_sec` | int | From `per_algo.ML-DSA-65`. |
| `slh_dsa_sha2_128s_signatures_per_sec` | number | From `per_algo.SLH-DSA-SHA2-128s`. |
| `concurrent_connections_realistic` | int | At 192 KiB per connection. |
| `concurrent_connections_theoretical_max` | int | At 32 KiB per connection. |
| `assumptions` | string | The per-connection and RAM assumptions above. |

Each rate key appears only when the matching `per_algo` entry has a measured rate.

## `--ansible` variant

`--ansible` returns a single top-level key `ansible_facts`, whose value
is `{pqc_readiness: {…the schema above…}}`. The wrapper exists so an
Ansible play can `register` or `set_fact` on the result without
custom parsing. `--ansible` always exits 0 so a host's PQC verdict
never marks the play as failed; downstream tasks read the verdict
from the fact body. See [docs/ansible.md](ansible.md) for runnable
playbooks, the `become` / privilege model, and downstream `set_fact`
patterns.

## `--recommend --json` document

`--recommend --json` returns a document scoped to the recommendation
instead of the readiness report.

| Key | Type | Meaning |
| --- | --- | --- |
| `role` | string | `--role` (default `tls-server`): `tls-server`, `tls-client`, `signing-service`, `firmware-signing` or `generic`. |
| `mode` | string | `auto` (`--policy auto`, the default: every policy side by side) or `single`. |
| `policy` | string | `single` mode only: the requested policy. |
| `hostname` | string | Host the recommendation is for. |
| `generated_at` | string | ISO 8601 UTC timestamp of the underlying probe. |
| `recommendations` | object | Keyed by policy (`cnsa-2.0`, `nist-civilian`, `eu-anssi-bsi`, `commercial`; only the requested one in `single` mode). Each value is a recommendation record. |
| `policy_sources` | object | The migration timelines and their sources, keyed by jurisdiction: `us-nss-cnsa-2.0`, `us-nist`, `eu`, `de-bsi`, `fr-anssi`, `uk-ncsc`, `ca-cccs`, `au-asd`. Always the full set, so national timelines that are not engine policies are still reported. See *Policy sources* below. |

### Policy sources

Each value in `policy_sources`:

| Key | Type | Meaning |
| --- | --- | --- |
| `authority` | string | Issuing body. |
| `documents` | list[object] | `{title, date, status, url}` per source document. `status` is `final` or `draft` (e.g. NIST IR 8547 is `draft`); `date` is `null` when the document carries none. |
| `title` | string | Inside `documents[]`: document title, with version where it has one. |
| `date` | string \| null | Inside `documents[]`: publication date (`YYYY`, `YYYY-MM` or `YYYY-MM-DD`). |
| `status` | string | Inside `documents[]`: `final` or `draft`. |
| `url` | string | Inside `documents[]`: the publisher's URL. |
| `milestones` | list[object] | `{by, event}` deadlines from the documents; empty when the source states a position rather than dates (BSI, ANSSI). |
| `by` | string | Inside `milestones[]`: the deadline (`YYYY`, `YYYY-MM` or `YYYY-MM-DD`). |
| `event` | string | Inside `milestones[]`: what is due. Draft-sourced milestones say "(draft)". |
| `categories` | object | `us-nss-cnsa-2.0` only: per CNSA 2.0 category (`software-firmware-signing`, `web-browsers-servers-cloud`, `traditional-networking`, `operating-systems`, `niche-equipment`, `custom-legacy`), `{support_and_prefer, exclusive_use}` years from the 2022 advisory. `support_and_prefer` is `null` for `custom-legacy`. |
| `support_and_prefer` | string \| null | Inside `categories`: year by which CNSA 2.0 must be supported and preferred. |
| `exclusive_use` | string | Inside `categories`: year by which CNSA 2.0 must be used exclusively (`custom-legacy`: update or replace by). |
| `notes` | list[string] | Positions without dates (e.g. hybrid requirements, approved algorithms). |
| `verified` | string | When the entry was checked against the publisher's own document, and how if not fetched directly. |

### Recommendation record

| Key | Type | Meaning |
| --- | --- | --- |
| `role` | string | Role the record was computed for. |
| `policy` | string | Policy key. |
| `policy_authority` | string | Issuing authority for the policy. |
| `policy_basis` | string | Citation for the policy's algorithm preferences. |
| `policy_source` | string | Source document URL. |
| `implemented` | bool | False only for `generic`, which has no workload profile; that record carries `note` and no algorithm fields. |
| `note` | string | `generic` only: which roles are implemented. |
| `kem` | object | `{algorithm, mode, reason, tls_groups}` (`tls_groups` for the TLS roles only). `mode` is `hybrid` or `pure` for the TLS roles; for `signing-service` and `firmware-signing` the KEM is not applicable: `algorithm` is `null` and `mode` is `n/a`. |
| `signature` | object | `{algorithm, reason}`. |
| `hash` | object | `{algorithm, reason}` from the policy's primary hash. |
| `algorithm` | string \| null | Inside `kem`, `signature`, `hash`: the selected algorithm. |
| `mode` | string | Inside `kem`: see above. |
| `tls_groups` | list[string] | Inside `kem`, TLS roles only: advertised groups that carry the chosen KEM in the chosen mode (e.g. `MLKEM1024` for CNSA 2.0). Empty means the host cannot serve the recommendation yet, and `caveats` says why. |
| `reason` | string | Inside `kem`, `signature`, `hash`: why that algorithm was chosen for this host and policy. |
| `host_capability_inputs` | object | The host facts the choice used: `isa_tier`, `pqc_accelerator_present`, and for implemented roles `fips_kernel`, `openssl_version`, `kernel_release`. |
| `isa_tier` | string | Inside `host_capability_inputs`: lower-cased `isa_tier`. |
| `pqc_accelerator_present` | bool | Inside `host_capability_inputs`: any accelerator with `pqc_capable: true`. |
| `fips_kernel` | bool | Inside `host_capability_inputs`: `fips.kernel`. |
| `openssl_version` | string | Inside `host_capability_inputs`: `openssl.version` (`""` when unknown). |
| `kernel_release` | string | Inside `host_capability_inputs`: `kernel_info.release` (`""` when unknown). |
| `timeline` | object | `{sources, cnsa_2_0_category?}`. `sources` lists the `policy_sources` keys behind this policy (empty for `commercial`). `cnsa_2_0_category` appears for `cnsa-2.0` on implemented roles: `{category, support_and_prefer, exclusive_use}`; TLS roles map to `web-browsers-servers-cloud` (exclusive use 2033), signing roles to `software-firmware-signing` (2030). |
| `sources` | list[string] | Inside `timeline`: keys into the document's `policy_sources`. |
| `cnsa_2_0_category` | object | Inside `timeline`: the CNSA 2.0 deadline category for the role. |
| `category` | string | Inside `cnsa_2_0_category`: category id, as in `policy_sources.us-nss-cnsa-2.0.categories`. |
| `caveats` | list[string] | Host- and policy-specific warnings (missing TLS groups, FIPS mode required, middlebox ClientHello size, HSM considerations, …). |

The policy-to-preference mapping, issuing authorities and sources are
catalogued in [docs/recommendation-policies.md](recommendation-policies.md).

## `--aggregate` rollup

`--aggregate DIR` reads every `*.json` report under `DIR` and emits a
fleet rollup (JSON by default, or one `group,key,count` row per value
with `--aggregate-format csv`). Reports whose `schema_version` differs
from the scanner's are not merged.

| Key | Type | Meaning |
| --- | --- | --- |
| `total_hosts` | int | Reports merged. |
| `schema_version` | string | Schema the rollup was built for. |
| `by_arch` | object | Host count per `arch`. |
| `by_os_release_id` | object | Host count per `kernel_info.os_release_id` (`?` when absent). |
| `by_isa_tier` | object | Host count per `isa_tier`. |
| `by_verdict` | object | Host count per verdict tier (the text of `verdict` before ` - `). |
| `by_runtime_environment` | object | Host count per `runtime_environment.environment`. |
| `accelerator_kinds_host_count` | object | Hosts with at least one accelerator of each `kind`. |
| `host_fs_detections_unavailable_host_count` | object | Hosts on which each detection was flagged `unavailable_in_container`. |
| `unique_cpu_models` | list[string] | Sorted distinct `cpu_model` values. |
| `replace_required_count` | int | Hosts with `replace_required: true`. |
| `skipped` | list[object] | Files not merged, each `{file, reason}` (unreadable, not a JSON object, or schema mismatch). |

## Schema alignment with CycloneDX 1.6

[docs/schema-alignment.md](schema-alignment.md) is a field-by-field
mapping of the `--json` schema against the field-name conventions in
CycloneDX 1.6's `cryptoProperties` schema. The mapping concludes that
`--json` is a host-level inventory schema and CycloneDX is an
asset-level schema — the asset-level projection is already provided by
`--cbom`. No `--json` field renames are recommended at this time, so
no major (`2.0`) bump is planned; the current `SCHEMA_VERSION` is
`"1.4"` from additive changes only.
