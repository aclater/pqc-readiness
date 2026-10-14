# JSON output reference

`pqc-readiness --json` emits a stable, schema-versioned document.
The current `schema_version` is `"1.6"`. It follows the bump rules in
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
| `1.5` | Additive only. New top-level objects: `crypto_policy` (system crypto policy and whether it lets PQC through, #104), `crypto_material` (`--scan-crypto-material` filesystem certificate / key / keystore discovery, #108), `service_crypto_linkage` (`--scan-services` listening service → crypto library, #111), `signing_keys` (`--scan-signing-keys` package-manager signing trust anchors, #153) and `inventory_metadata` (`--inventory-metadata FILE`, #144). New nested fields: `openssl.config` (effective OpenSSL configuration and providers, #106), `openssl.tls_group_references` and `ssh_pqc.kex_references` (RFC codepoints and status, #139), `cnsa_2_0.tls_key_exchange` (#139), `trust_store.certificates` (per-certificate CycloneDX 1.7 fields, #108), and `ipsec_pqc.configured` / `ipsec_pqc.note` (configured IKEv2 proposals classified for ML-KEM and RFC 9370, #154). `packages.source` also takes `rpmdb-bdb` / `rpmdb-ndb` (#134). The `--recommend` document gained `policy_sources` and per-record `timeline` (#141). |
| `1.6` | Additive only. New top-level objects: `sshd` (effective sshd key exchange and host keys, #105), `crypto_libraries` (`--scan-crypto-libraries`: GnuTLS, libgcrypt, libssh, wolfSSL, AWS-LC, JDK and Go PQC capability, #110), `process_crypto_linkage` (`--scan-processes`: every process, including outbound-only TLS clients, attributed to its crypto library, #155), `scan_mode` (live host vs offline `--root PATH` tree, #152), `boot_chain` (`--scan-boot-chain`: Secure Boot, module signing, IMA/EVM, TPM 2.0 v1.85 PQC, #112), `kerberos` (`--scan-kerberos`: enctypes, keytabs, PKINIT, #109), `tunnels` and `dnssec` (WireGuard pre-shared keys, OpenVPN key exchange, DNSSEC algorithms, #113), and `pqc_deployment_gap` (capable / configured / observed verdict per protocol, listening service and outbound client group, #107, #202). `crypto_policy` gained `framework` (`crypto-policies` or Ubuntu's `crypto-config`, with that framework's keys, #170). Nothing was renamed, removed or re-typed. |

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
| `schema_version` | Schema version string, currently `"1.6"`. Major bump on rename/remove/re-type, minor bump on additive changes. |
| `generated_at` | ISO 8601 UTC timestamp of the probe run. |
| `hostname` | Host's reported hostname. `--host-name NAME` sets it for any scan mode; otherwise `PQC_HOSTNAME` in the environment overrides it (the OpenShift DaemonSets set it to `spec.nodeName`); under `--host-mount` the host's `/etc/hostname` is used, because the container's own hostname is the pod name. |
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
| `ssh_pqc` | OpenSSH key-exchange support, from `ssh -Q kex` or, under `--host-mount` / `--root`, the host's own package and binary (`version_source`, `kex_source`). `kex_groups` splits the detected kex names into `pure_pqc` / `hybrid` / `classical` buckets, mirroring `openssl.tls_groups`. |
| `ipsec_pqc` | strongSwan / Libreswan presence and PQC (ML-KEM) key-exchange support. See [`ipsec_pqc`](#ipsec_pqc). |
| `nss` | NSS PQC algorithm exposure: `{available, tool, version, pqc_capable, note?}`. `tool` is `certutil --version`, `rpmdb (sqlite)` / `rpmdb (bdb)` / `rpmdb (ndb)` (package `nss` / `mozilla-nss` read from the rpm database in-process; the suffix is the database format) or `rpm -q` (CLI fallback when the database cannot be read directly). Under `--host-mount` the host rpm database is consulted before `certutil`, because `certutil` belongs to the scanner image. |
| `crypto_policy` | System-wide crypto policy and what it lets PQC do. `framework` is `crypto-policies` (RHEL family, Fedora, SUSE) or `crypto-config` (Ubuntu's optional package, #170). For crypto-policies: active / configured policy, subpolicies, per-protocol `pqc_enabled`, and the parsed OpenSSL / GnuTLS / NSS / OpenSSH / libreswan back-ends. Read from files, so it works under `--host-mount` and on SUSE releases that ship the policy data without `update-crypto-policies`. For crypto-config: the active profile, its OpenSSL snippet settings and which applications it configures. `{available: false, reason}` where neither `/etc/crypto-policies` nor `/var/lib/crypto-config` exists. See [Nested fields](#crypto_policy). |
| `sshd` | Effective sshd key exchange and host keys: the `KexAlgorithms` sshd actually offers (from `sshd -T` as root on a live host, otherwise by following `sshd_config` and its `Include` chain into the crypto-policies back-end), whether a PQC method is offered and first, and each HostKey's type, size and SHA-256 fingerprint read from its `.pub` file only. `{available: false, reason}` when no `sshd_config` exists. See [Nested fields](#sshd). |
| `kernel_info` | Kernel release, OS identity copies kept for back-compat, `/etc/redhat-release` and PQC-named `/proc/crypto` drivers. See [`kernel_info`](#kernel_info). |
| `fips_pqc_conflict` | `{in_conflict, explanation}`: `in_conflict` is true when kernel FIPS mode is on but PQC algorithms are exposed only through the non-FIPS default provider. See [`fips_pqc_conflict`](#fips_pqc_conflict). |
| `cnsa_2_0` | CNSA 2.0 evaluation: overall `status` plus per-category compliance booleans and gap notes. See [`cnsa_2_0`](#cnsa_2_0). |
| `trust_store` | Trust-store summary. Populated only when `--scan-trust-store` is set (`{}` otherwise). Certificates are classified from the signature-algorithm and SubjectPublicKeyInfo OIDs in their DER encoding (independent of the installed OpenSSL), every certificate in multi-certificate bundle files is inspected, and counts are per **unique certificate** (SHA-256 of the DER; a `TRUSTED CERTIFICATE` block counts as its embedded certificate). Keys: `available`, `scanned_dirs`, `total_certs` (unique certificates whose DER parsed), `pqc_certs` (signature or key algorithm is ML-DSA / SLH-DSA), `hybrid_certs` (pre-standard hybrid OIDs), `cert_categories` (`classical` / `hybrid_composite` / `pure_pqc` counts), `total_found` (unique certificates found across all `*.pem` / `*.crt` files after symlink de-duplication), `scanned_count` (certificates classified, ≤ `max_certs`), `max_certs` (cap in effect, default 500, set by `--trust-store-max-certs`), and `truncated` (true when `total_found > max_certs`; certificates are taken in sorted file order, then file order, so a capped scan is deterministic). Earlier releases counted *files*, read only the first certificate in each, and missed PQC certificates on OpenSSL ≥ 3.5 (#116); the field shapes are unchanged, but the count semantics changed in schema `1.3`, so counts from older reports are not comparable (the fleet aggregator already refuses to mix versions). |
| `crypto_material` | Filesystem discovery of certificates, private keys and Java keystores (#108). Populated only when `--scan-crypto-material` is set (`{}` otherwise); see [`crypto_material`](#crypto_material). Private keys are reported as metadata only — their content is never read into the report. |
| `runtime_environment` | `{environment, evidence}`: `environment` is `container` or `host`; `evidence` is the marker that decided it. See [`runtime_environment`](#runtime_environment). |
| `service_crypto_linkage` | Listening sockets mapped to the process that owns each one and the crypto library it actually uses. Populated only when `--scan-services` is set (`{}` otherwise). Pure `/proc` inspection, no network connections. See [`service_crypto_linkage`](#service_crypto_linkage). |
| `service_tls_config` | Each server daemon's own TLS settings per endpoint (groups, their source, protocol range, whether hybrid ML-KEM is offered). Populated only with `--scan-service-configs` or `--scan-services` (`{}` otherwise); file reads only, also with `--root`. See [`service_tls_config`](#service_tls_config). |
| `process_crypto_linkage` | Every running process (servers and outbound-only TLS clients) mapped to the crypto library or Go runtime it has loaded, grouped by executable and library version. Populated only when `--scan-processes` is set (`{}` otherwise). Pure `/proc` reads; see [`process_crypto_linkage`](#process_crypto_linkage). |
| `host_fs_detections_unavailable` | Object keyed by detection (`accelerators`, `kernel_crypto_hw`, `ktls`, `fips`, `tpm_pqc`, `kernel_info`, `os_release`, `pkcs11_modules`, `packages`, `openssl_config`, `crypto_policy`, `sshd`, `nss`). Each value is `{"unavailable_in_container": true, "reason": "<detection> reads <host paths>; …"}`. Populated only when running inside a container without `--host-mount`; `{}` on bare metal or when `--host-mount` is in effect. Detections whose own field is an object also carry the same two keys inline (see [Nested fields](#nested-fields)); list/boolean fields (`accelerators`, `kernel_crypto_hw`, `ktls_supported`, `pkcs11_modules`) are annotated only here so their types stay stable. The aggregator surfaces a `host_fs_detections_unavailable_host_count` rollup. |
| `packages` | Installed crypto-bearing packages. Populated only when `--scan-packages` is set. Keys: `available`, `package_manager`, `total_packages`, `bundled_crypto`. On RPM families also `source` — `rpmdb-sqlite` (EL9+, Fedora, CentOS Stream, Amazon Linux 2023, Oracle Linux 9+), `rpmdb-bdb` (Berkeley DB: EL8, openSUSE Leap 15 cloud images) or `rpmdb-ndb` (SLES 15, Leap 16, Tumbleweed), each read in-process without the `rpm` binary, or `rpm-cli` (only when the database cannot be read directly: unrecognised or corrupt file, or no `sqlite3` module) — and `db_root`, the host-relative database directory (`/var/lib/rpm`, `/usr/lib/sysimage/rpm` or `/usr/share/rpm`; `null` when rpm located it itself). The backend is identified by file magic. Under `--host-mount` the host database is read (the CLI fallback runs `rpm --root <mount> --dbpath <db_root>`), and the scan reports unavailable rather than inventorying the scanner image when no host database is mounted. |
| `signing_keys` | Package-manager signing trust anchors. Populated only when `--scan-signing-keys` is set (`{}` otherwise). Keys: `available`, `family`, `sources`, `keys`, `summary` (see [Nested fields](#signing_keys)). Public keys only: algorithm, size or curve, fingerprint, key ID, creation time and user ID; never key material. |
| `crypto_libraries` | PQC capability of crypto libraries other than OpenSSL / NSS: GnuTLS, libgcrypt, libssh, wolfSSL, AWS-LC, Mbed TLS, installed JDKs and Go toolchains. Populated only when `--scan-crypto-libraries` is set (`{}` otherwise). Keys: `available`, `libraries`, `summary` (see [Nested fields](#crypto_libraries)). No subprocess is run. |
| `pqc_deployment_gap` | Capability vs configuration verdict (#107): for TLS, SSH and IPsec, and for every listening service when `--scan-services` ran, whether PQC is `deployed`, `capable_not_configured`, `configured_not_capable`, `not_capable`, `unknown` or `not_present`, with JSON paths to the fields that decided it. Computed from the other fields; no probe of its own. See [`pqc_deployment_gap`](#pqc_deployment_gap). |
| `boot_chain` | Boot chain trust anchors and their algorithms: UEFI Secure Boot state and the PK / KEK / db / dbx / MOK signature lists, kernel module signing, IMA / EVM, kernel lockdown and TPM 2.0 post-quantum support. Populated only when `--scan-boot-chain` is set (`{}` otherwise). Keys: `available`, `secure_boot`, `module_signing`, `ima_evm`, `lockdown`, `tpm`, `summary` (see [Nested fields](#boot_chain)). |
| `kerberos` | Kerberos encryption types and PKINIT: the client / KDC enctype lists (`krb5.conf` with includes, `kdc.conf`), keytab entries (principal, kvno, enctype; never keys) and PKINIT settings. Populated only when `--scan-kerberos` is set (`{}` otherwise). Keys: `available`, `config_files`, `config`, `kdc`, `keytabs`, `summary` (see [Nested fields](#kerberos)). |
| `tunnels` | WireGuard and OpenVPN post-quantum posture: WireGuard peers' pre-shared-key presence (never the key) from wg-quick, systemd-networkd, NetworkManager and, as root on a live host, `wg show`; OpenVPN control-channel key exchange from each config's `tls-groups` / `tls-version-max`. Populated only when `--scan-tunnels` is set (`{}` otherwise). Keys: `available`, `wireguard`, `openvpn` (see [Nested fields](#tunnels)). |
| `dnssec` | DNSSEC signing algorithms of authoritative servers on the host (BIND `dnssec-policy` and key files, Knot, PowerDNS) and validation settings (Unbound, systemd-resolved, BIND `dnssec-validation`). Populated only when `--scan-dnssec` is set (`{}` otherwise). Keys: `available`, `bind`, `knot`, `powerdns`, `validators`, `summary` (see [Nested fields](#dnssec)). |
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
| `inventory_metadata` | Operator-supplied inventory facts from `--inventory-metadata FILE` (OMB M-23-02 items the host can't know), validated and normalised; `null` when the flag isn't given. See [`inventory_metadata`](#inventory_metadata). |
| `scan_mode` | `null` for live scans. For an offline `--root PATH` scan of a filesystem tree, `{mode, root, not_applicable, partial, reason}`: which fields cannot be answered from a tree and are marked not applicable. See [`scan_mode`](#scan_mode). |

## Nested fields

One subsection per object-valued field. Conventions used throughout:

- A detection that could not run returns `{"available": false, "reason": "<why>"}` in place of its normal keys (e.g. `openssl` when the binary is missing, `ssh_pqc` when `ssh` is absent).
- Object-valued detections that read host files (`fips`, `tpm_pqc`, `kernel_info`, `os_release`, `nss`, `packages`, `openssl.config`, `crypto_policy`, `sshd`, and the opt-in scans `signing_keys`, `crypto_libraries`, `service_crypto_linkage`, `service_tls_config`, `process_crypto_linkage`, `boot_chain`, `kerberos`, `tunnels`, `dnssec`) also carry `unavailable_in_container: true` and a `reason` inline when running in a container without `--host-mount`; see [`host_fs_detections_unavailable`](#host_fs_detections_unavailable).
- In an offline `--root` scan, object-valued sections that need a live host carry `{"available": false, "not_applicable": true, "reason": "<why>"}`; see [`scan_mode`](#scan_mode). `not_applicable` never appears in live scans.
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
| `available` | bool | The host's OpenSSL was found: the `openssl` CLI on a bare-metal or VM scan, else its package or libcrypto file (see `version_source`). When false only `reason` follows (plus `scanner_cli_version` under `--host-mount`). |
| `version` | string | `openssl version` output; `OpenSSL <version>` from the host package or libcrypto when the CLI can't describe the host; or `unknown`. |
| `version_tuple` | list[int] \| null | `[major, minor, patch]`, or `null` when unparseable. |
| `pqc_native` | bool \| null | Version ≥ 3.5 (native ML-KEM / ML-DSA / SLH-DSA). `null` when the host's libcrypto carries no version string. |
| `version_source` | string \| null | Where the version came from: `cli` (the `openssl` binary on a bare-metal or VM scan), `package` (the host's OpenSSL library package from its package database) or `library` (the "OpenSSL x.y.z" string the host's libcrypto embeds). The CLI is not used under `--host-mount`, where it is the scanner image's (#228), or when the host has none, e.g. OpenWrt and minimal images (#225). Offline `--root` scans use `package` / `library` too. |
| `cli_probe` | object | Present when the CLI can't describe the host: `{available: false, reason}`. The CLI-only fields (`kem_algorithms`, `sig_algorithms`, `tls_groups`, `tls_pqc_groups`, `providers`, `third_party_providers`, `third_party_algorithms`) are then `null`, meaning unknown rather than empty. Capability judgements fall back to `pqc_native`: the gap verdict's TLS `capable`, pqc-001, pqc-008 and the FIPS / PQC conflict. CNSA 2.0 notes that the lists weren't probed. |
| `scanner_cli_version` | string | `--host-mount` only: `openssl version` of the scanner image's CLI, for reference. It is not the host's. |
| `kem_algorithms` | list[string] | `ML-KEM-*` names from `openssl list -kem-algorithms`. |
| `sig_algorithms` | list[string] | `ML-DSA-*` / `SLH-DSA-*` names from `openssl list -signature-algorithms`. |
| `tls_groups` | object | TLS 1.3 groups split into `pure_pqc` (e.g. `MLKEM768`), `hybrid` (e.g. `X25519MLKEM768`, `SecP256r1MLKEM768`) and `classical`; each a list. |
| `tls_pqc_groups` | list[string] | Back-compat union of `tls_groups.pure_pqc` and `tls_groups.hybrid`; prefer `tls_groups`. |
| `tls_group_references` | object | Present when OpenSSL was probed. One entry per known PQC group in `tls_groups.pure_pqc` / `hybrid`, keyed by name: `codepoint` (IANA TLS Supported Groups value, e.g. `0x11EC`), `kem`, `classical` (`null` for pure groups), `recommended` (IANA "Recommended" column), `cnsa_2_0` (true only for an ML-KEM-1024 component), `reference` (`RFC 10024` or `draft-ietf-tls-mlkem`), `status` (`final` or `draft`), `url`, and `obsolete: true` for the pre-standard Kyber groups. Unknown names are omitted. |
| `providers` | list[string] | Active provider names. |
| `third_party_providers` | list[object] | Loaded providers that don't ship with OpenSSL (not `default` / `base` / `fips` / `legacy` / `null`), e.g. a source-built OQS provider: `{name, display_name, version, build_info, status}` from `openssl list -providers -verbose`. `null` under `--host-mount` (see `cli_probe`). |
| `third_party_algorithms` | object | `kem` / `signature`: lists of `{name, provider}` from `openssl list -kem-algorithms` / `-signature-algorithms` lines tagged `@ <provider>` for a non-built-in provider (e.g. `p256_mldsa44 @ oqsprovider`). |
| `config` | object | What the host's OpenSSL configuration sets by default (#106); see below. Read from files through the host prefix, so it describes the host under `--host-mount`. |
| `upgrade_path` | string \| null | Family-aware advice for reaching OpenSSL ≥ 3.5; `null` when already there or no advice applies. |
| `not_applicable` | bool | Offline `--root` scan only: the capability probes (which run the scanner's own `openssl`) did not run; `available` is false and `reason` explains. `package`, `version_tuple`, `pqc_native_expected` and `config` describe the tree. |
| `package` | object \| null | When `version_source` is `package` or `library` (offline `--root`, `--host-mount`, or a host without the CLI): the host's or tree's OpenSSL library package `{name, version}` from its package database (e.g. `openssl-libs`, `libssl3t64`, Yocto's `libcrypto3`, OpenWrt's `libopenssl3`), or `null` when none is installed. Trees whose family has no registered package tool are looked up in whichever database the tree has (#217). |
| `library` | object \| null | Same scans as `package`, when no package was found (e.g. a Buildroot or minimal Yocto image with no package database; #217): the tree's libcrypto file `{path, version}`, with `version` read from the "OpenSSL x.y.z" string the library embeds (`null` when it carries none). Forks that embed an OpenSSL compatibility string (AWS-LC, BoringSSL, LibreSSL) are not counted. `null` when a package was found or no libcrypto exists. |
| `installed` | bool | Offline `--root` scan only: `false` when the tree has neither an OpenSSL package nor a libcrypto file (e.g. OpenWrt, which ships Mbed TLS); no OpenSSL finding is raised then. |
| `pqc_native_expected` | bool \| null | Offline `--root` scan only: the packaged (or, without a package, the library's) version is ≥ 3.5; `null` when no version is known. |
| `reason` | string | Present only when `available` is false. |

#### `openssl.config`

| Key | Type | Meaning |
| --- | --- | --- |
| `available` | bool | An `openssl.cnf` was found. When false only `reason` follows. |
| `path` | string | Main config file (host path). |
| `path_source` | string | `OPENSSL_CONF`, `OPENSSLDIR` (from `openssl version -d`) or `distribution default` (always under `--host-mount`, where the environment and binary belong to the image). Defaults: `/etc/pki/tls/openssl.cnf` (RHEL family), `/etc/ssl/openssl.cnf` (Debian / Ubuntu / SUSE). |
| `files` | list[string] | Every file read, in order, following `.include` (a directory include reads its `*.cnf` / `*.conf` files in sorted order). |
| `include_errors` | list[string] | Includes that could not be read: missing, unreadable, or a cycle / depth limit. Stock Ubuntu 26.04 lists two here: directories that exist only once its optional `crypto-config` package is installed. |
| `unreadable` | list[object] | Present when a config file or include directory exists but this user can't read it (#232). An unprivileged scan of a host whose files are `0600 root` gets this instead of a "not found" reason; run as root or with `CAP_DAC_READ_SEARCH` to read them. Each item is `{path, reason}`; the path is also in `include_errors`. When `available` is false, `reason` names the first unreadable candidate. |
| `init_section` | string \| null | Section named by `openssl_conf`. |
| `system_default_section` | string \| null | Section named by `ssl_conf` → `system_default` (RHEL-family / SUSE: `crypto_policy`, which includes the crypto-policies back-end). |
| `providers_configured` | list[object] | Entries of the `providers` section: `{name, section, activate, module, third_party}`. `activate` is null when the section doesn't set it. Commented-out snippets (Fedora's `pkcs11-provider.conf`) don't appear. |
| `min_protocol` | string \| null | `MinProtocol` in the `system_default` section. |
| `groups_configured` | list[string] \| null | `Groups` (or `Curves`) set in the `system_default` section, in order; null when unset. |
| `signature_algorithms_configured` | list[string] \| null | `SignatureAlgorithms` set there; null when unset. |
| `default_groups` | list[string] | Effective default groups: `groups_configured`, else OpenSSL's built-in list. |
| `default_groups_source` | string | `config`, `openssl built-in default (3.5+)` (`?*X25519MLKEM768 / ?*X25519:?secp256r1 / ?X448:?secp384r1:?secp521r1 / ?ffdhe2048:?ffdhe3072`, per OpenSSL CHANGES.md for 3.5.0, 8 Apr 2025) or `openssl built-in default (pre-3.5: no PQC groups)`. |
| `default_pqc_groups` | object | `hybrid` / `pure_pqc` split of `default_groups`. |
| `pqc_key_exchange_by_default` | bool | A PQC key-exchange group is in `default_groups`. |
| `third_party_providers_configured` | list[string] | Names of activated providers in the config that don't ship with OpenSSL. |
| `reason` | string | Present only when `available` is false. |
| `unavailable_in_container` | bool | Present when running in a container without `--host-mount`. |

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
| `available` | bool | `ssh -Q kex` ran, or (under `--host-mount`, `--root`, or with no `ssh` client) the host's OpenSSH package or binary was found. When false, `reason` (and `version` if `ssh -V` worked) follow. |
| `version` | string \| null | OpenSSH version, in `ssh -V`'s form (`9.9p1`): from `ssh -V`, else the host's package or binary (see `version_source`). |
| `version_source` | string \| null | Where `version` came from: `cli` (`ssh -V`), `binary` (the `OpenSSH_x.ypz` string in the host's binary, which is what `ssh -V` prints there) or `package` (the host's OpenSSH package with the epoch and distribution revision stripped, used only when no binary is readable; it can differ, e.g. Debian 13's `1:10.0p1-7+deb13u4` prints `10.0p2`). Under `--host-mount` and `--root` the `ssh` on PATH is the scanner's own, so it is never `cli` there (#256). |
| `kex_source` | string \| null | Where the kex lists came from: `cli` (`ssh -Q kex`) or `binary` (the names the kex table in the host's `sshd-session` / `sshd` / `ssh` points at, which equal `ssh -Q kex` on every build checked). Null, with `kex_count`, `pqc_kex` and `kex_groups` null too, when the package was found but no binary was readable. |
| `package` | object \| null | File-based reads only: the host's OpenSSH package `{name, version}`, as its package database records it. |
| `binaries` | list[string] | File-based reads only: host paths of the OpenSSH binaries the kex names (and the version) were read from; empty when none was readable. |
| `source` | string | File-based reads with a kex list only: `binary`, the same marker `sshd.openssh_kex_evidence` carries. |
| `default_kex` | object | File-based reads only, when the server binary holds exactly one kex list: sshd's compiled-in default `{kex, binary}`, used by `sshd` when nothing sets KexAlgorithms (as offline, #247). |
| `cli_probe` | object | File-based reads only: `{available: false, reason}`, why `ssh -V` / `ssh -Q kex` weren't used. |
| `scanner_cli_version` | string | Under `--host-mount` / `--root` when the scanner has an `ssh`: that client's version, for comparison. |
| `kex_count` | int \| null | Number of key-exchange methods the OpenSSH build supports. |
| `pqc_kex` | list[string] | Back-compat flat list of PQC / hybrid methods (ML-KEM hybrids, `sntrup761`); prefer `kex_groups`. |
| `kex_groups` | object | `pure_pqc` / `hybrid` / `classical` lists, mirroring `openssl.tls_groups`. |
| `kex_references` | object | Present when `ssh -Q kex` ran. One entry per known PQC kex in `kex_groups.pure_pqc` / `hybrid`: `kem`, `classical`, `cnsa_2_0`, `reference` (`RFC 10042` or `RFC 9941`), `status`, `url`, and `alias_of` for the pre-RFC `sntrup761x25519-sha512@openssh.com` name. |
| `reason` | string | Present only when `available` is false. |

### `ipsec_pqc`

| Key | Type | Meaning |
| --- | --- | --- |
| `available` | bool | A strongSwan (`swanctl`) or Libreswan (`ipsec`) installation answered. |
| `implementation` | string | `strongswan` or `libreswan`. |
| `pqc` | bool | strongSwan: `swanctl --list-algs` lists ML-KEM / Kyber. Libreswan: version ≥ 5.4, the upstream release that added ML-KEM-768 (RFC 9370 additional key exchanges); distribution builds may backport. |
| `evidence` | string \| null | strongSwan only: the matching algorithm token. |
| `version` | string \| null | Libreswan only: version from `ipsec --version`. |
| `note` | string | Libreswan only: the version basis of `pqc`. |
| `reason` | string | Why `swanctl --list-algs` failed (kept even if Libreswan then answered), or that neither tool is on PATH. |
| `configured` | object | What the IPsec configuration asks IKEv2 to negotiate (#154), read whether or not a daemon is installed. See below. |

`configured` classifies every IKE and child-SA proposal in strongSwan `swanctl.conf` (`/etc/swanctl/` or `/etc/strongswan/swanctl/`, with `include`s) and `ipsec.conf` (`/etc/ipsec.conf`, `/etc/strongswan/ipsec.conf`, with Libreswan `include /etc/ipsec.d/*.conf`). Both dialects are understood: strongSwan `-` separated keywords with `keX_<method>` additional key exchanges (`keX_none` = optional), and Libreswan `;` separated `ke=` / `addkeN=` with `+` alternatives.

| Key | Type | Meaning |
| --- | --- | --- |
| `files` | list[string] | Top-level config files found (host paths). |
| `proposals` | list[object] | One entry per configured proposal (fields below). |
| `summary` | object | `{ike_proposals, classical, hybrid, pure_pqc, unclassified, connections, connections_offering_pqc, connections_requiring_pqc}` over IKE (not child) proposals. A connection *offers* PQC when any of its IKE proposals can negotiate ML-KEM, and *requires* it when one has `pqc_mandatory`. |
| `capability_mismatch` | object | Present when an installed stack answered with no ML-KEM support (`pqc` false) but connections configure ML-KEM: `{connections, reason}`. Such connections fail to load rather than falling back (Libreswan 5.3.2 rejects `ke=ml_kem_768` and `addke1=`). `%default` templates are not counted as connections. |
| `standards` | list[object] | `{mechanism, reference, status, note?}`: RFC 9370 (`final`) and ML-KEM in IKEv2, `draft-ietf-ipsecme-ikev2-mlkem-09` (`draft`: IESG-approved, in the RFC Editor queue; IANA Transform Type 4 IDs 35/36/37). |

Each `proposals[]` entry:

| Key | Type | Meaning |
| --- | --- | --- |
| `proposal` | string | The proposal as configured (trailing `!` removed). |
| `connection` | string \| null | Connection name (`connections.<name>` / `conn <name>`). |
| `child` | string \| null | strongSwan child SA name for `esp_proposals`. |
| `kind` | string | `ike` (IKE SA) or `child` (`esp_proposals`, `esp=`, `phase2alg=`, `ah`: the key exchange there is PFS). |
| `source` | string | Host path of the file the proposal came from. |
| `primary` | list[string] | Key-exchange methods offered for the main exchange (alternatives), e.g. `Curve25519`, `ECP-384`, `MODP-3072`, `ML-KEM-768`. Empty when none is named. |
| `additional` | object | RFC 9370 Additional Key Exchange slots: `{"1": [...], ...}`; `none` marks a slot as optional. |
| `category` | string \| null | `classical`, `hybrid` or `pure_pqc` for the most post-quantum combination the proposal can negotiate; `null` when no key exchange is named. |
| `pqc_mandatory` | bool | Every acceptable negotiation includes ML-KEM. False when a classical alternative or an optional slot lets a peer avoid it. |
| `note` | string | Present when `category` is null: the implementation default applies. |

### `nss`

| Key | Type | Meaning |
| --- | --- | --- |
| `available` | bool | An NSS version was found. When false only `reason` follows. |
| `tool` | string | `certutil --version`; `rpmdb (sqlite)`, `rpmdb (bdb)` or `rpmdb (ndb)` (package `nss` / `mozilla-nss` read from the rpm database in-process: the sqlite `Name` index, or a full read of Berkeley DB / ndb when `rpm` is unavailable); or `rpm -q` (looked up through the rpm CLI, the first choice on Berkeley DB / ndb because it uses rpm's own index). |
| `version` | string | `major.minor.patch`, the raw string if unparseable, or `unknown`. With several installs (i686 + x86_64) the highest. |
| `pqc_capable` | bool | Version ≥ 3.108. |
| `note` | string | Present for rpm-sourced versions (distro package version, not necessarily upstream), and under `--host-mount` when only the image's `certutil` was available. |
| `reason` | string | Present only when `available` is false. |

### `crypto_policy`

The system-wide crypto policy is the master switch for which algorithms
OpenSSL, GnuTLS, NSS, OpenSSH and libreswan negotiate by default, so a
PQC-capable library can still be held back by policy. Measured on cloud
images (2026-10-13):

| Release | DEFAULT enables PQC? | PQ-enabling subpolicy | Other |
| --- | --- | --- | --- |
| RHEL-family 9.8 (Rocky, Alma, Stream, Oracle) | No: no ML-KEM / ML-DSA in any back-end | `PQ` | |
| RHEL-family 10.2, Fedora 43 / 44 | Yes: hybrid ML-KEM groups, ML-DSA signatures, hybrid ML-KEM SSH kex | `TEST-PQ` adds pure ML-KEM groups and composite signatures | `NO-PQ` removes PQC |
| openSUSE Leap 16.0, Tumbleweed | Yes (as Fedora) | `TEST-PQ` (module shipped) | Policy files present but no `update-crypto-policies` tool |

Field names follow the RHEL `crypto_policies` system role's facts where
they overlap (`crypto_policies_active`, `crypto_policies_available_subpolicies`,
`crypto_policies_reboot_required`).

| Key | Type | Meaning |
| --- | --- | --- |
| `available` | bool | A framework was found: `/etc/crypto-policies/state/current` or `/etc/crypto-policies/config` was readable, or `/var/lib/crypto-config/profiles/current` exists. When false only `reason` (and any container note) follows. |
| `framework` | string | `crypto-policies` or `crypto-config`. The crypto-config fields are described after this table. |
| `active` | string \| null | Applied policy from `state/current`, e.g. `DEFAULT:TEST-PQ` (role: `crypto_policies_active`). |
| `base_policy` | string \| null | Part before the first `:` (`DEFAULT`, `FUTURE`, `FIPS`, `LEGACY`, …). |
| `subpolicies` | list[string] | Modules after the base, in order. |
| `configured` | string \| null | Policy requested in `/etc/crypto-policies/config`. |
| `applied` | bool \| null | `configured` equals `active` (what `update-crypto-policies --is-applied` checks); null when either file is missing. |
| `available_subpolicies` | list[string] | `*.pmod` modules installed under `/usr/share/crypto-policies/policies/modules` and `/etc/crypto-policies/policies/modules` (role: `crypto_policies_available_subpolicies`). |
| `pq_subpolicies_active` | list[string] | Active subpolicies that switch PQC on (`PQ` on EL9, `TEST-PQ` on EL10 / Fedora / SUSE). |
| `pq_disabled_by_subpolicy` | list[string] | Active subpolicies that switch PQC off (`NO-PQ`). |
| `reboot_required` | bool \| null | The FIPS policy and kernel FIPS mode disagree (`base_policy == "FIPS"` vs `/proc/sys/crypto/fips_enabled`); they only change together across a reboot (role: `crypto_policies_reboot_required`). Null when either is unknown. |
| `pqc_enabled` | object | Per protocol, does the policy let PQC through: `tls_key_exchange`, `tls_signatures` (OpenSSL back-end), `ssh_key_exchange_client`, `ssh_key_exchange_server`, `ike_key_exchange` (libreswan). `null` when the deciding back-end is missing or unreadable. |
| `backends` | object | Parsed back-ends keyed `opensslcnf`, `gnutls`, `nss`, `openssh`, `opensshserver`, `libreswan`. Each has `readable` (bool); readable ones add the fields below. Back-ends are absolute symlinks into `/usr/share/crypto-policies/<POLICY>/`, resolved inside the `--host-mount` prefix (mount `/usr/share/crypto-policies` read-only as well as `/etc`). |
| `unreadable` | list[object] | Present when a policy file (`state/current`, `config`, a back-end) exists but this user can't read it (#232). An unprivileged scan of a host whose files are `0600 root` gets this instead of a "not found" reason; run as root or with `CAP_DAC_READ_SEARCH` to read them. Items are `{path, reason}`. When neither `state/current` nor `config` can be read, `available` is false and `reason` says so. |
| `readable` | bool | The back-end file (after symlink resolution inside the host prefix) could be read. When it exists but can't be read, `reason` says why (e.g. `permission denied; run as root or with CAP_DAC_READ_SEARCH`); an absent back-end has no `reason`. |
| `groups` | list[string] | `opensslcnf` / `gnutls`: TLS groups in preference order (`*`, `?` markers and `GROUP-` prefixes stripped). |
| `pqc_groups` | object | `hybrid` / `pure_pqc` lists of PQC key-exchange names (OpenSSL canonical names, oqs-provider aliases such as `p256_mlkem768`, GnuTLS and NSS spellings). |
| `signature_algorithms` | list[string] | `opensslcnf` / `gnutls`: signature algorithms in preference order. |
| `pqc_signature_algorithms` | object | `hybrid` (composite, e.g. `p256_mldsa44`) / `pure_pqc` (e.g. `mldsa65`, `ML-DSA-65`) lists. |
| `allowed` | list[string] | `nss`: the policy module's `allow=` list. |
| `kex` | list[string] | `openssh` / `opensshserver`: `KexAlgorithms` in order. |
| `kex_groups` | object | `openssh` / `opensshserver`: `pure_pqc` / `hybrid` / `classical`, same classifier as `ssh_pqc.kex_groups`. |
| `ike_proposals` | list[string] | `libreswan`: `ike=` proposals. |
| `pqc_key_exchange` | list[string] | `libreswan`: PQC tokens found in the proposals (none in any measured policy). |
| `reason` | string | Present only when `available` is false. |
| `unavailable_in_container` | bool | Present when running in a container without `--host-mount` (see `host_fs_detections_unavailable`). |

SARIF rule `pqc-008-crypto-policy-blocks-pqc` fires when `openssl.tls_groups`
lists hybrid or pure PQC groups but `pqc_enabled.tls_key_exchange` is false.


**Ubuntu `crypto-config` (`framework: "crypto-config"`).** Ubuntu 26.04's
optional `crypto-config` package switches per-application snippets via the
symlink `/var/lib/crypto-config/profiles/current`; `/etc/ssl/openssl.cnf`
includes the active profile's `openssl.conf.d`. Measured on a booted Ubuntu
26.04.1 cloud image with crypto-config 0.7.4-0ubuntu2 (2026-10-13): the
package isn't installed by default; its profiles set no TLS groups and don't
configure OpenSSH, so `openssl list -tls-groups` and sshd's KexAlgorithms
were identical under `default`, `future` and `legacy`. These keys replace
the crypto-policies ones:

| Key | Type | Meaning |
| --- | --- | --- |
| `active` | string | Active profile, e.g. `default`, `future`, `legacy`, or a namespaced `debian/test1`. |
| `available_profiles` | list of strings | Profiles with a `metadata.json` under `/var/lib/crypto-config/profiles`. |
| `profile` | object | `summary` and `parent` from the active profile's `metadata.json` (null when unreadable). |
| `applications` | list of strings | What the active profile configures: `openssl.conf.d`, `gnutls.conf`, `nginx.conf.d`, `apt.conf.d`, `exim`. |
| `openssl` | object | The active profile's OpenSSL snippet: `settings` (`MinProtocol`, `MaxProtocol`, `CipherString`, `Ciphersuites`, `Groups`, `Curves`, `SignatureAlgorithms` where set), `seclevel` (from `@SECLEVEL=N`), `groups_configured` (null when the profile sets no groups), `pqc_groups` (`hybrid` / `pure_pqc`, null without groups), `files` read. |
| `pqc_enabled` | object | Same keys as for crypto-policies. `tls_key_exchange` is null when the profile sets no TLS groups (OpenSSL's default applies; OpenSSL 3.5 prefers hybrid ML-KEM), otherwise whether a PQC group is listed. The SSH and IKE keys are always null: crypto-config doesn't configure them. |

### `sshd`

`ssh_pqc` reports what the OpenSSH *client binary* supports (`ssh -Q kex`);
`sshd` reports what the *server* offers. On every measured distro sshd reaches
`KexAlgorithms` through an `Include` chain into
`/etc/crypto-policies/back-ends/opensshserver.config`. Measured on cloud
images (2026-10-13): Fedora 44, Rocky 10.2, AlmaLinux 10.2 and CentOS Stream
10 offer `mlkem768x25519-sha256` first; openSUSE Leap 16.0 offers
`sntrup761x25519-sha512` first; Rocky 9.8 (DEFAULT policy) offers no PQC key
exchange although its OpenSSH 9.9 supports `mlkem768x25519-sha256`
(SARIF `pqc-010`). The file-parsing path reproduced each host's `sshd -T`
list exactly.

| Key | Type | Meaning |
| --- | --- | --- |
| `available` | bool | `false` when no `sshd_config` exists in `/etc/ssh` or `/usr/etc/ssh` (SUSE vendor config). |
| `reason` | string | Why `available` is false. |
| `source` | string | `sshd -T` (root, no `--host-mount`) or `config files`. Offline `--root` scans are always `config files`: the tree's `sshd_config` and its `Include` chain are parsed inside the root, and `sshd -T` never runs (#247). |
| `config_files` | list of strings | Files read, in order, when `source` is `config files` (`Include` globs expanded lexically; parsing stops at the first `Match` block). |
| `unreadable` | list[object] | `{path, reason}` for config files or Include directories that exist but this user can't read (#232). An unprivileged scan of a host whose files are `0600 root` gets this instead of a "not found" reason; run as root or with `CAP_DAC_READ_SEARCH` to read them. When `/etc/ssh/sshd_config` itself is unreadable, `available` is false, `reason` names it, and the SSH gap row is `unknown` (not `not_present`) with a `note`. |
| `kex_offered` | list or null | Effective `KexAlgorithms`, in preference order. `null` when nothing sets it (OpenSSH's compiled-in default applies) or when it is set relative to that default; offline, the compiled-in default is filled in when it can be read from the tree's server binary (see `kex_default_source`). |
| `kex_source` | string | `configured`; `openssh-compiled-default` when nothing sets KexAlgorithms; or `unreadable-config` when a file or Include directory that exists couldn't be read before any KexAlgorithms line, so the value sshd uses is unknown (`kex_offered`, `pqc_offered` and `pqc_first` are null). |
| `kex_default_source` | object | Offline only: `{source: "binary", binary}` when nothing sets KexAlgorithms and `kex_offered` is the compiled-in default read from that `sshd-session` / `sshd` binary. Read only when the binary holds exactly one kex list; EL-family builds carry several (FIPS, ML-KEM-only) and stay `null`. |
| `kex_modifier` | object | Present when `KexAlgorithms` starts with `+`, `-` or `^`: `{operator, algorithms}`. |
| `kex_groups` | object | `pure_pqc` / `hybrid` / `classical` split of `kex_offered`, same classifier as `ssh_pqc.kex_groups`. |
| `kex_references` | object | Registry facts (RFC 10042 / RFC 9941, draft/final status, CNSA 2.0 eligibility) for each offered PQC method, as `ssh_pqc.kex_references`. |
| `first_kex` | string | The most-preferred offered method. |
| `pqc_offered` | bool or null | Any PQC (hybrid or pure) method offered; null when unknown. |
| `pqc_first` | bool or null | The most-preferred method is PQC; null when unknown. |
| `host_key_algorithms` | list of strings | Effective `HostKeyAlgorithms` when set explicitly. |
| `host_keys` | list | One entry per `HostKey` (OpenSSH's default three when none is configured). Read from `<path>.pub`; the private key file is never opened. |
| `host_keys_pqc` | bool | Any host key is post-quantum. |
| `openssh_supports_pqc_kex` | bool or null | Whether `ssh -Q kex` lists a PQC method (client and server ship in the same OpenSSH build); null when the client probe did not run. Offline, from the kex methods compiled into the tree's OpenSSH binaries (`openssh_kex_evidence`); null when the tree has none. |
| `openssh_kex_evidence` | object | Offline only (#247): `{source: "binary", binaries, pqc_kex}`: the binaries read and the PQC methods their kex name table holds. Reading the build, not its version, keeps distro backports right: Rocky 9's OpenSSH 8.7 build offered `mlkem768x25519-sha256`, which upstream added in 9.9. |
| `unavailable_in_container` | bool | Set, with `reason`, inside a container without `--host-mount`: the values describe the image, not the host. |

Each `host_keys` entry:

| Key | Type | Meaning |
| --- | --- | --- |
| `path` | string | The `HostKey` path as configured. |
| `readable` | bool | Whether `<path>.pub` was found and parsed. |
| `reason` | string | Why a readable `.pub` could not be parsed. |
| `type` | string | Public key type, e.g. `ssh-ed25519`, `ecdsa-sha2-nistp256`, `ssh-rsa`. |
| `bits` | int | Key size (RSA modulus bits; curve size for ECDSA / Ed25519 / Ed448). |
| `fingerprint_sha256` | string | `SHA256:...` fingerprint, identical to `ssh-keygen -lf`. The key comment is not reported. |
| `pqc` | bool | Whether the key type is a post-quantum signature (none shipped in OpenSSH as of 2026). |
| `type_mismatch` | string | Present when the key blob's embedded type differs from the line's type field. |
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

`certificates` lists every classified certificate (≤ `max_certs`), one object per unique certificate. It is the per-certificate contract the CycloneDX 1.7 emitter projects into `certificate` assets (#138):

| Key | Type | Meaning |
| --- | --- | --- |
| `sha256` | string | SHA-256 of the certificate DER, lowercase hex. The join key (CycloneDX 1.7 `fingerprint`). |
| `serial` | string | Serial number as hex of the DER INTEGER content. |
| `subject` / `issuer` | string | RFC 4514 names, most specific RDN first. |
| `not_before` / `not_after` | string | Validity window, ISO 8601 UTC. |
| `category` | string | `classical`, `hybrid_composite` or `pure_pqc`, from the signature and key algorithm OIDs. |
| `role` | string | `ca` (basicConstraints cA=TRUE, or a self-signed certificate without basicConstraints, i.e. a v1 root) or `leaf`. |
| `key_algorithm` | string | Subject public key algorithm: `RSA`, `RSASSA-PSS`, `EC <curve>` (e.g. `EC P-256`), `DSA`, `Ed25519`, `Ed448`, `X25519`, `X448`, `ML-DSA-44/65/87`, `SLH-DSA-*`, `ML-KEM-512/768/1024`, or the dotted OID when unknown. |
| `key_size` | int \| null | Key size in bits for RSA (modulus) and EC/EdDSA/X25519 curves; null for PQC parameter sets, whose strength is in the name. |

### `crypto_material`

`{}` unless `--scan-crypto-material`. Walks `--crypto-material-path` (repeatable; default: common service locations such as `/etc/pki`, `/etc/ssl`, `/etc/httpd`, `/etc/nginx`, `/etc/letsencrypt`, `/etc/kubernetes/pki`, `/usr/lib/jvm`) under `--host-mount` when set. Symlinked directories are not followed; symlinked files resolve inside the host tree and are de-duplicated. SSH host keys are left to the sshd detection (#105).

| Key | Type | Meaning |
| --- | --- | --- |
| `available` | bool | Always true when the scan ran. |
| `scanned_paths` | list[string] | Requested paths that exist on the host. |
| `files_examined` | int | Candidate files (by suffix: certificates, keys, keystores) examined. |
| `max_files` | int | Cap in effect (`--crypto-material-max-files`, default 5000). |
| `truncated` | bool | The cap stopped the walk; files are visited in sorted order so a capped scan is deterministic. |
| `malformed_certificates` | int | Certificate blocks that failed to parse (logged under `--debug`). |
| `summary` | object | Counts: `certificates`, `leaf_certificates`, `ca_certificates`, `cert_categories` (`classical` / `hybrid_composite` / `pure_pqc`), `expired`, `valid_past_2030_classical` (classical certificates still valid after 2030-12-31), `private_keys`, `private_keys_world_readable`, `keystores`. |
| `certificates` | list[object] | One object per unique certificate, with every key of [`trust_store.certificates`](#trust_store) plus `expiry_bucket` (`expired`, `lt_30d`, `lt_90d`, `lt_1y`, `gt_1y`), `valid_past_2030` / `valid_past_2035` (still valid after the NIST IR 8547 draft's deprecation / disallow years and OMB M-26-15's 2030-12-31 key-establishment date), and `paths` (host paths where it was found). |
| `private_keys` | list[object] | One object per private-key file. **Metadata only**: `path`, `sha256` (of the whole file), `key_type` from the PEM header label (`RSA`, `EC`, `DSA`, `PKCS#8`, `PKCS#8 (encrypted)`, `OpenSSH`), `encrypted`, `mode` (octal permission bits), `group_readable`, `world_readable`, and `public_half` — `{certificate_sha256, key_algorithm, key_size, source}` taken from a certificate in the same file (`source`: `certificate in the same file`) or a certificate whose file has the same stem (`certificate with the same file stem (heuristic)`). Any certificate qualifies — `openssl req -x509` marks self-signed service certificates CA:TRUE — with a single leaf preferred; null when there is none or the match is ambiguous. |
| `keystores` | list[object] | One object per Java keystore: `path`, `size_bytes`, `sha256`, `store_type` (`jks`, `jceks`, `pkcs12`, `unknown`), `listed` (its certificates were read), `method` (`in-process` for JKS — trusted-certificate entries and the public chains of key entries are stored unencrypted; `keytool (default cacerts password)` for a JDK `cacerts` in PKCS#12), `private_key_entries` (JKS), `certificates_found`, and `reason` when not listed (e.g. `password-protected; not opened`). |

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
| `container` | object \| null | For a process in a container (#233): `{runtime, id, pod_uid, pod_name, pod_namespace, container_name}`, from the cgroup path. `runtime` is `cri-o`, `containerd`, `docker` or `podman` (from the `crio-` / `cri-containerd-` / `docker-` / `libpod-<id>.scope` unit), or `null` for the cgroupfs driver's `/kubepods/<qos>/pod<uid>/<id>` layout; `id` is the 64-hex container ID; `pod_uid` is the Kubernetes pod UID when the path has one. The three names come from the kubelet's `/var/log/containers/<pod>_<namespace>_<container>-<id>.log` entries (a directory listing; no log is opened) and are `null` when that directory isn't readable, e.g. a DaemonSet that doesn't mount it. The runtime's container config is not read: it holds the container's environment. `null` for processes outside containers. |
| `crypto_libraries` | list[object] | Crypto libraries the process maps: `{family, path, version, version_source, deleted, library_pqc_capable, pqc_evidence}`. `family` is `openssl`, `libressl`, `boringssl`, `aws-lc`, `gnutls`, `nss` or `wolfssl` (OpenSSL forks share sonames and are told apart by their embedded strings). `version_source` is `embedded` (version string inside the library), `filename` (e.g. `libssl.so.3.5.9`), `sibling-libcrypto` (libssl takes the version of the libcrypto beside it) or `null`. `deleted` is true when the mapped file was replaced on disk. `library_pqc_capable` is whether that library ships ML-KEM hybrid TLS key exchange: decided by the library binary itself when it contains the hybrid TLS group names (`pqc_evidence: "binary"`, GnuTLS / wolfSSL / AWS-LC, using the markers from `crypto_libraries`), otherwise by version (`pqc_evidence: "version"`: OpenSSL ≥ 3.5, NSS ≥ 3.108); `null` with `pqc_evidence: null` when neither applies. A library a sandboxed process can't open through its own root is identified by the device and inode in `/proc/<pid>/maps` when another process mapped the same file. Whether the service turns it on is configuration (#106 / #107). |
| `crypto_libraries_from` | object | Present only when the owning process maps no crypto library itself and `crypto_libraries` was taken from the daemon's workers instead (#240): master/worker daemons such as Postfix accept connections in a master that never loads the TLS library, and hand each connection to a worker that does. `source` says where the libraries came from: `socket-holder` (another process holding the same listening socket, e.g. an `smtpd` that inherited it; with `pid`, `process`, `exe`), `descendant` (a child of the owner that maps a crypto library; same keys), or `worker-binary` (the libraries an executable in the workers' directory links, read from its ELF `DT_NEEDED` entries through RUNPATH/RPATH and the system library directories; with `binary`). Evidence of a TLS library (libssl, GnuTLS, NSS, wolfSSL) is preferred, in that order of sources; a worker that maps only libcrypto (often for hashing, or through Kerberos/SASL) is used only when nothing else is found. Executables in shared directories (`/usr/bin`, `/usr/sbin`, ...) and daemons with no workers are never used. |
| `static_binary` | bool \| null | The executable has no ELF interpreter (statically linked); `null` when it could not be read. |
| `go` | object \| null | For Go binaries: `go_version` (e.g. `go1.24.4`, from the embedded build info; `null` for pre-1.18 binaries), `main_module`, `cgo_enabled`, `default_hybrid_kex` and `godebug_reverts`. `default_hybrid_kex` is the hybrid key exchange crypto/tls offers when the program leaves `CurvePreferences` unset: `X25519MLKEM768` from Go 1.24 (which also removed the Kyber draft), `X25519Kyber768Draft00` on Go 1.23, else `null`. `godebug_reverts` lists `tlsmlkem` / `tlskyber` / `tlssecpmlkem` set to `0` by the binary's `DefaultGODEBUG` or the process's `GODEBUG` environment variable, which turn those defaults off. Only `GODEBUG` is read from the environment; nothing else is kept. |

### `service_tls_config`

`{}` unless `--scan-service-configs` or `--scan-services` (#216). A server
daemon's own TLS settings decide its key exchange before the system crypto
policy does: a group list without ML-KEM keeps a service classical after
the policy enables PQC, and one with ML-KEM turns it on under a policy that
doesn't (measured on Rocky Linux 9.8 with nginx). Configuration files are
read through their includes; nothing is executed. `{available: false,
reason}` when none of the supported services has a configuration.

| Key | Type | Meaning |
| --- | --- | --- |
| `available` | bool | At least one supported service has configuration on the host. |
| `services` | list[object] | One entry per service configuration found (several for PostgreSQL clusters or Redis/Valkey instances). |
| `summary` | object | `services` and `services_with_tls` (names), `endpoints`, `pqc_configured`, `pqc_blocked` and `follow_library_default` (endpoint counts by `pqc_key_exchange`), `unreadable` (paths). |

Each `services[]` entry:

| Key | Type | Meaning |
| --- | --- | --- |
| `service` | string | `nginx`, `apache`, `haproxy`, `stunnel`, `squid`, `postfix`, `dovecot`, `postgresql`, `mysql` (MariaDB / MySQL), `redis` (Redis / Valkey), `openldap`, `389-ds` or `tomcat`. |
| `version` | string \| null | Present for services whose built-in default depends on it: Postfix (package version), PostgreSQL (major version from `PG_VERSION`, the Debian cluster path or the package). |
| `default_groups_from` | string \| null | stunnel only: the binary its compiled default group list was read from. |
| `config_from_command_line` | list[string] | haproxy and stunnel, live scans with `--scan-services` only: config files read because a running daemon that owns a listening socket was started with them (`haproxy -f <file\|dir>`, `stunnel <file>`) outside the standard paths. Absent when none. |
| `files` | list[string] | Configuration files read, includes expanded. |
| `unreadable` | list[object] | `{path, reason}` for files or directories that exist but couldn't be read (PostgreSQL data directories and slapd.d are root / service-user only, and an unprivileged scan can't read `0600` configs: `permission denied; run as root or with CAP_DAC_READ_SEARCH`), or that are larger than 1 MiB. |
| `missing` | list[string] | Present when the configuration names a file that doesn't exist (e.g. an include of an absent file). Until #232 these were listed under `unreadable`. |
| `endpoints` | list[object] | TLS endpoints; see below. |
| `error` | string | Present only if the parser failed on this service. |

Each `endpoints[]` entry is one TLS listener (a server block, virtual host,
bind line, service section or port), or the whole daemon for services that
configure TLS once (Dovecot, PostgreSQL, MariaDB, Redis, OpenLDAP):

| Key | Type | Meaning |
| --- | --- | --- |
| `file`, `line` | string, int \| null | Where the endpoint is configured. |
| `context` | string \| null | E.g. `http server`, `VirtualHost *:443`, `frontend web`, `[https]`, `smtpd submission`. |
| `role` | string | `server`, or `client` for stunnel client sections. |
| `ports` | list[int] | Ports this endpoint serves (standard ports for Dovecot's enabled protocols). |
| `groups` | list[string] \| null | The effective key-exchange group list, `null` when the TLS library default applies. |
| `groups_setting` | string \| null | The directive that set it (`ssl_ecdh_curve`, `SSLOpenSSLConfCmd Groups`, `curves`, `tls_eecdh_auto_curves`, `ssl_groups`, `TLSECName`, ...). |
| `groups_source` | string | `config`; `service default` (a list compiled into the service: Postfix before 3.11 `X25519 X448 prime256v1 secp384r1 secp521r1`, PostgreSQL before 18 `prime256v1`, PostgreSQL 18+ `X25519:prime256v1`, stunnel's build default read from its binary); or `library default`. |
| `pqc_groups` | object \| null | `{hybrid, pure_pqc}` ML-KEM groups in `groups`. |
| `protocols`, `min_protocol`, `max_protocol` | list[string] \| null, string \| null | The configured protocol range. |
| `tls13_allowed` | bool \| null | False when the range excludes TLS 1.3 (hybrid ML-KEM groups are TLS 1.3 only); null when nothing restricts it. |
| `ciphers`, `ciphersuites` | string \| null | Cipher settings, recorded as configured. |
| `certificates` | list[string] | Certificate paths (join keys into `crypto_material`); key files are never read. |
| `service_supports_pqc_groups` | bool \| null | False for PostgreSQL before 18, which sets one elliptic curve and can never use ML-KEM. |
| `follows_library_default` | bool | `pqc_key_exchange` is null. |
| `pqc_key_exchange` | bool \| null | True when the endpoint's own configuration (or built-in default) offers hybrid ML-KEM; false when it keeps it out; null when it follows the TLS library default (crypto policy / `openssl.cnf`). |
| `reason` | string | Why, in words. |
| `note` | string | Optional (e.g. NSS-based or JSSE endpoints, PostgreSQL before 18). |

Measured 2026-10-14 on five booted images (Rocky 9.8, CentOS Stream 10,
Fedora 44, Ubuntu 26.04, Leap 16.0) by probing each configured daemon with
a client offering `X25519MLKEM768`: every endpoint with `pqc_key_exchange`
false negotiated a classical group, every true one ML-KEM, and every null
one followed the host (ML-KEM except under Rocky 9.8's DEFAULT policy).
The per-distribution results are in `tests/fixtures/service_tls/README.md`.

### `process_crypto_linkage`

`{}` unless `--scan-processes`. The same `/proc` inspection as [`service_crypto_linkage`](#service_crypto_linkage), applied to **every** process rather than only socket owners, so TLS *clients* (package managers, agents, backup and monitoring daemons that only connect out) are covered: their PQC readiness is client-side readiness, and a process with no listening socket never appears in a service scan. Processes are grouped by executable, the crypto libraries they map (family, version, path, deleted) and, for Go binaries, the toolchain version and TLS default, so output size follows the number of distinct binaries rather than the number of processes. Groups that cannot do PQC sort first.

| Key | Type | Meaning |
| --- | --- | --- |
| `available` | bool | Scan ran. When false only `reason` follows (not Linux, or `/proc` unreadable). |
| `groups` | list[object] | One entry per (executable, libraries, Go default); see the group table below. Capped at `limits.max_groups`. |
| `summary` | object | `groups` (all groups, including omitted ones), `processes_with_crypto`, `processes_without_crypto` (user-space processes mapping no crypto library and not Go), `processes_by_crypto_family` (family → process count; a process mapping several families counts once in each), `processes_not_pqc_capable` (processes in groups with `pqc_capable: false`), `client_processes_not_pqc_capable` (of those, processes in the `client` role), `processes_with_deleted_crypto_library`. |
| `scanned_pids` | int | Processes whose `maps` was read. |
| `unreadable_pids` | int | Processes whose `/proc/<pid>/maps` could not be read (permissions); counted, never guessed. |
| `kernel_threads` | int | Processes with no address space and no executable link. |
| `truncated` | bool | The scan stopped at `limits.max_pids` or `limits.time_budget_s`. |
| `omitted_groups` | int | Groups beyond `limits.max_groups` (left out of `groups`, still counted in `summary`). |
| `limits` | object | `max_pids` (default 16384), `time_budget_s` (default 30), `max_groups` (default 500). |
| `note` | string | Present when `unreadable_pids` > 0: how to get complete attribution. |
| `reason` | string | Present when `available` is false, or with `unavailable_in_container`. |

Each `groups[]` entry:

| Key | Type | Meaning |
| --- | --- | --- |
| `exe` | string \| null | Executable path, in the process's own mount namespace. |
| `process` | string \| null | `comm` of the first process in the group. |
| `crypto_libraries` | list[object] | As in `service_crypto_linkage`: `{family, path, version, version_source, deleted, library_pqc_capable, pqc_evidence}`. |
| `static_binary` | bool \| null | No ELF interpreter (statically linked). |
| `go` | object \| null | As in `service_crypto_linkage`. |
| `pqc_capable` | bool \| null | `false` when any mapped crypto library is known not to ship hybrid ML-KEM TLS (it may be the one the process uses) or a Go binary has no hybrid default; `true` when every library / the Go runtime is known capable; `null` when unknown. Capability only: configuration decides whether it is used. |
| `process_count` | int | Processes in the group. |
| `sample_pids` | list[int] | Up to five PIDs. |
| `systemd_units` | list[string] | Units (`*.service` / `*.scope`) of the group's processes, at most ten. |
| `systemd_units_omitted` | int | Present when more than ten units were seen. |
| `containers` | list[object] | Containers the group's processes run in (#262), at most ten, sorted by namespace, pod and container: the `container` object of `service_crypto_linkage.listeners[]` (`{runtime, id, pod_uid, pod_name, pod_namespace, container_name}`, same sources and limits). Empty when no process is in a container. |
| `containers_omitted` | int | Present when more than ten containers were seen. |
| `container_processes` | int | Processes in the group that run in a container. |
| `network_namespaces` | list[string] | `host` and/or `other`, as in `service_crypto_linkage`. |
| `roles` | object | Process counts by role: `server` (holds a listening TCP or bound UDP socket), `client` (holds established TCP connections and no listening socket: outbound-only), `idle` (neither). "Established TCP" says nothing about TLS on the connection. |
| `established_tcp_connections` | int | Established TCP sockets held by the group's processes. |
| `fd_unreadable_processes` | int | Processes whose file-descriptor table could not be read, so their role is `idle` by default. |

### `host_fs_detections_unavailable`

Keyed by detection: `accelerators`, `kernel_crypto_hw`, `ktls`, `fips`, `tpm_pqc`, `kernel_info`, `os_release`, `pkcs11_modules`, `packages`, `openssl_config`, `crypto_policy`, `sshd`, `nss`. Each value:

| Key | Type | Meaning |
| --- | --- | --- |
| `unavailable_in_container` | bool | Always true when present. |
| `reason` | string | Which host paths the detection reads and that the result reflects the container. |

### `packages`

`{}` unless `--scan-packages`.

| Key | Type | Meaning |
| --- | --- | --- |
| `available` | bool | Inventory succeeded. When false only `reason` follows. |
| `package_manager` | string | `rpm`, `dpkg-query`, `pacman` or `apk` for live scans; `dpkg`, `pacman` or `apk` when the database was read in-process under `--host-mount` / `--root`; `opkg` for opkg databases. Families with no registered package tool (OpenWrt, Yocto, Buildroot, `unknown`) are inventoried from whichever database exists, probed in the order rpm, dpkg, apk, opkg, pacman and always read in-process (#217); when none exists (Buildroot keeps no package database) `available` is false and `reason` lists what was looked for. |
| `source` | string | RPM families: `rpmdb-sqlite`, `rpmdb-bdb` or `rpmdb-ndb` (database read in-process; the suffix is its format) or `rpm-cli` (fallback when it cannot be read directly). Debian / Alpine / Arch under `--host-mount` or `--root`: `dpkg-status`, `apk-installed-db` or `pacman-local-db`, read in-process because their CLIs would read the scanner's own database. `opkg-status` for an opkg `status` file (`/usr/lib/opkg/status` on OpenWrt, `/var/lib/opkg/status` on Yocto), counting the packages `opkg list-installed` lists (state `installed` or `unpacked`). Absent for live scans that ran a family tool. |
| `db_root` | string \| null | Host-relative database location: the rpm database directory, or the dpkg `status` file, apk `installed` file, opkg `status` file or pacman `local` directory when `source` names one of those. |
| `total_packages` | int | Installed packages counted (on RPM hosts this includes `gpg-pubkey` entries, as `rpm -qa` does). |
| `bundled_crypto` | list[object] | Packages that embed their own crypto stack, each `{package, version, note}` where `note` names the stack (e.g. `Go runtime (crypto/tls embedded)`), plus `release`, `epoch` and `arch` when the package database records them (the rpm readers do). With them the CBOM emits the same exact purl as `--sbom` (#222). |
| `reason` | string | Present when `available` is false, or with `unavailable_in_container`. |

### `signing_keys`

`{}` unless `--scan-signing-keys`. The keys a package manager trusts to verify package signatures: on RPM families the keys imported into the rpm database (`gpg-pubkey`, read in-process from sqlite / Berkeley DB / ndb, with `rpm -q gpg-pubkey` as the fallback) plus the local files enabled repositories reference with `gpgkey=file://`; on Debian/Ubuntu `/etc/apt/trusted.gpg`, `/etc/apt/trusted.gpg.d/*` and every `signed-by` / `Signed-By` keyring (including inline deb822 keys); on Arch the keys in `/usr/share/pacman/keyrings` listed as trusted; on Alpine `/etc/apk/keys/*.pub`. OpenPGP keys are parsed per RFC 9580 (v4 and v6); post-quantum algorithm IDs 30–36 are the RFC 9980 assignments.

| Key | Type | Meaning |
| --- | --- | --- |
| `available` | bool | A trust store for the family was found. When false only `family` and `reason` follow. |
| `family` | string | `os_release.family` the scan used. |
| `reason` | string | Why the scan is unavailable, or with `unavailable_in_container`. |
| `sources` | list[object] | One entry per place keys were read from: `{origin, source, keys, error?}`. `origin` is `rpmdb`, `repo-gpgkey`, `apt-trusted`, `apt-signed-by`, `pacman-keyring` or `apk-keys`; `source` is the host path (for `rpmdb`, the database directory plus `(rpmdb-<format>)` or `(rpm-cli)`); `keys` is how many keys it held; `error` is set when it could not be read, including an enabled repo whose `gpgkey` file is missing. |
| `keys` | list[object] | Unique keys, de-duplicated by fingerprint and sorted by it. |
| `summary` | object | `{total, classical, hybrid, pure_pqc, all_classical}`. `all_classical` is true when at least one key was found and none can make a post-quantum signature; it drives SARIF rule `pqc-009-classical-package-signing-keys`. |

Each `keys[]` entry:

| Key | Type | Meaning |
| --- | --- | --- |
| `fingerprint` | string \| null | Upper-case hex: SHA-1 for v4 OpenPGP keys, SHA-256 for v6 (and v5); SHA-256 of the DER SubjectPublicKeyInfo for apk keys; `null` for v3 keys. |
| `key_id` | string \| null | OpenPGP key ID (last 16 hex of a v4 fingerprint, first 16 of a v6 one); `null` for apk keys. rpm names imported keys `gpg-pubkey-<last 8 hex>`. |
| `version` | int \| null | OpenPGP key version (3, 4, 5 or 6); `null` for apk keys. |
| `algorithm` | string | e.g. `RSA`, `EdDSALegacy`, `Ed25519`, `ML-DSA-87+Ed448`, `SLH-DSA-SHAKE-128s`, `ML-DSA-65` (apk). |
| `algorithm_id` | int | OpenPGP public-key algorithm ID (IANA registry). OpenPGP keys only. |
| `algorithm_oid` | string | apk keys only: SubjectPublicKeyInfo algorithm OID. |
| `bits` | int | RSA / DSA / Elgamal modulus size. |
| `curve` | string | ECC curve for ECDSA / ECDH / EdDSALegacy (OpenPGP) or ECDSA (apk). |
| `capability` | string | `sign`, `encrypt`, `both` or `unknown`, from the algorithm. |
| `pqc_category` | string | `classical`, `hybrid` (RFC 9980 composites: ML-DSA+EdDSA, ML-KEM+X25519/X448) or `pure_pqc` (SLH-DSA, ML-DSA) for the primary key's own algorithm. |
| `signing_pqc_category` | string | The most post-quantum category among the primary key and any signing-capable subkey; what a package signature can actually be made with. An ML-KEM encryption subkey does not count. Summary counts use this. |
| `created` | string | Key creation time, ISO 8601 UTC. OpenPGP keys only. |
| `uid` | string | First User ID packet, e.g. `Red Hat, Inc. (release key 4) <security@redhat.com>`. |
| `subkeys` | list[object] | Subkeys, each with `fingerprint`, `key_id`, `version`, `algorithm`, `algorithm_id`, `capability`, `pqc_category`, `created` and `bits` / `curve` where they apply. |
| `origins` | list[object] | Every `{origin, source}` that carries this key. |

### `crypto_libraries`

`{}` unless `--scan-crypto-libraries`. For each library the primary evidence is the installed shared library itself: the probe reads the file (at most 64 MiB) and looks for the algorithm and TLS / SSH group names that library embeds when it implements them, so a distribution backport or a build without a PQC backend is reported correctly. When no library file can be read, the package or embedded version is compared with the upstream thresholds, cited in the source code from each project's release notes. AWS-LC is found by the `AWS-LC x.y.z` string in a `libcrypto` file, because some distributions install it under OpenSSL's file names; its `libssl` is only the exact sibling of that file.

| Key | Type | Meaning |
| --- | --- | --- |
| `available` | bool | False off Linux; then only `reason` follows. |
| `reason` | string | Why the probes did not run, or with `unavailable_in_container`. |
| `libraries` | object | One entry per probe: `gnutls`, `libgcrypt`, `libssh`, `wolfssl`, `aws-lc`, `mbedtls`, `java`, `go`. A library that is not installed is `{installed: false}`. |
| `summary` | object | `{installed, pqc_capable, classical_only, unknown}`: lists of library names. `unknown` holds libraries whose capability could not be decided (no readable file and a build-dependent library above its version threshold, or no version). |

Each native library entry (`gnutls`, `libgcrypt`, `libssh`, `wolfssl`, `aws-lc`, `mbedtls`). `mbedtls` covers Mbed TLS 2.x / 3.x (`libmbedtls`, `libmbedcrypto`) and 4.x with TF-PSA-Crypto (`libtfpsacrypto`), the TLS stack of most embedded images (OpenWrt's default):

| Key | Type | Meaning |
| --- | --- | --- |
| `installed` | bool | A package or library file was found. |
| `version` | string \| null | Package version, else the version the library embeds (`GnuTLS x.y.z`, `Libgcrypt x.y.z`, libssh's banner `SSH-2.0-libssh_x.y.z`, `Mbed TLS x.y.z`, `AWS-LC x.y.z`; wolfSSL embeds no matchable version string), else, for Mbed TLS only, the version in the library's file name (`libmbedtls.so.3.6.6`; Mbed TLS names its libraries after the release, so builds that strip the version string, such as OpenWrt's, are still versioned). Package-less trees such as Buildroot images get their version this way (#217). |
| `version_source` | string \| null | `package`, `library` (embedded version string) or `library-filename` (Mbed TLS file name). |
| `packages` | list[object] | Matching installed packages, `{name, version}` (plus `release`, `epoch` and `arch` from the rpm database, so the CBOM purl matches `--sbom`; #222), from the rpm database (in-process or `rpm -q`), `/var/lib/dpkg/status`, `/lib/apk/db/installed` or `/var/lib/pacman/local`; for families without a registered package tool (OpenWrt, Yocto, `unknown`), from whichever database the tree has, including opkg (e.g. OpenWrt's `libmbedtls21`, Yocto's `libgnutls30`; #217). |
| `files` | list[string] | Host paths of the library files read. |
| `evidence` | string | `binary` (capability read from the library file), `version` (threshold comparison only) or `none`. |
| `pqc_capable` | bool \| null | Binary evidence: any PQC name found. Version evidence: any threshold met, except `null` for a build-dependent library (GnuTLS, wolfSSL), which may be built without PQC. |
| `algorithms` | object | Names found in the binary, by kind: `tls_hybrid_groups` (e.g. `X25519MLKEM768`, `SecP256r1MLKEM768`, `SecP384r1MLKEM1024`), `kem` (e.g. `ML-KEM-768`, `sntrup761`), `signatures` (e.g. `ML-DSA-65`), `ssh_kex` (libssh: `mlkem768x25519-sha256`, `mlkem768nistp256-sha256`, `mlkem1024nistp384-sha384`, `sntrup761x25519-sha512`). Empty when no file was read. |
| `version_thresholds` | object | Capability → `{minimum_version, met, note}`; `met` is `null` without a version. GnuTLS: `tls_hybrid_mlkem768` 3.8.8, `tls_hybrid_mlkem1024` and `ml_dsa` 3.8.9, `ml_dsa_tls` 3.8.10. libgcrypt: `ml_kem_draft` 1.11.0, `ml_kem` 1.11.1, `ml_dsa` 1.12.0. libssh: `ssh_pqc_kex` 0.12.0. wolfSSL: `ml_kem_final` 5.7.4, `ml_kem_default` 5.9.1. AWS-LC: `ml_kem` 1.35.0, `tls_hybrid_mlkem768` 1.35.1, `ml_dsa` 1.41.0, `tls_hybrid_mlkem1024` 1.50.0. Mbed TLS: none, because no released Mbed TLS (through 4.2.0) or TF-PSA-Crypto (through 1.2.0) offers ML-KEM or ML-DSA to applications; an installed Mbed TLS is therefore `pqc_capable: false` unless its binary carries ML-KEM TLS group names. |
| `build_dependent` | bool | PQC support depends on build options (GnuTLS needs a PQC backend; wolfSSL before 5.9.1 needs `--enable-mlkem`). |
| `caveats` | list[string] | Set when the version is known to be below a release that changed the algorithm to its final standard while the binary still carries PQC names: libgcrypt before 1.11.1 (FIPS 203 initial public draft Kyber), wolfSSL before 5.7.4 (pre-final Kyber / Dilithium). Distribution builds may carry the final-standard patch. Mbed TLS always carries a note that no release offers ML-KEM / ML-DSA (LMS verification only). |
| `reference` | string | The release notes the thresholds come from. |

`java` and `go` entries (toolchains, from files: each JDK's `release` file under `/usr/lib/jvm`, `/usr/lib64/jvm`, `/usr/java`, `/opt/java`; each Go root's `VERSION` file):

| Key | Type | Meaning |
| --- | --- | --- |
| `installed` | bool | At least one install was found. |
| `installs` | list[object] | `java`: `{path, version, implementor, jca_ml_kem_ml_dsa, tls_hybrid_default}`; `go`: `{path, version, tls_mlkem_default}`. `jca_ml_kem_ml_dsa` is JDK ≥ 24 (JEP 496 / 497, JCA APIs only); `tls_hybrid_default` is JDK ≥ 27 (JEP 527, X25519MLKEM768 on by default in TLS 1.3); `tls_mlkem_default` is Go ≥ 1.24 (X25519MLKEM768 on by default in `crypto/tls`; `GODEBUG=tlsmlkem=0` reverts it). |
| `evidence` | string | Always `version`. |
| `pqc_capable` | bool | Any install meets the first threshold. |
| `version_thresholds` | object | As above, `{minimum_version, note}` per capability. |
| `reference` | string | JEP / Go release-note URLs. |

### `pqc_deployment_gap`

Joins what the host *can* do with what it is *set up* to do, per protocol
and per listening service (#107). Every value is derived from fields already
in the report, so a live scan, an offline `--root` scan and the aggregator
re-reading an older report give the same answer. The fleet aggregator adds
the third state, what an endpoint was *observed* to negotiate, when
`--observations` is supplied (see [`--aggregate` observations
join](#--aggregate-observations-join)).

| Key | Type | Meaning |
| --- | --- | --- |
| `protocols` | object | `tls`, `ssh` and `ipsec`, each a verdict (below). |
| `services` | object | Per-service verdicts; `{available: false}` without `--scan-services`. |
| `clients` | object | Per outbound-client process group verdicts (#202); `{available: false}` without `--scan-processes`. |
| `gaps` | list[string] | Every protocol (`tls:capable_not_configured`) in `capable_not_configured` or `configured_not_capable`, plus every service in those states whose verdict *differs* from its host's (`service:<process>/<protocol>/<port>:<state>`; see `follows_host_default`), and every such client group (`client:<exe>:<state>`). Empty when there is nothing to fix. |

A verdict (each `protocols.*` entry, and each service item):

| Key | Type | Meaning |
| --- | --- | --- |
| `state` | string | `deployed` (capable and configured), `capable_not_configured` (a configuration change closes the gap), `configured_not_capable` (configured for PQC the software can't do: connections fail or fall back), `not_capable` (an upgrade is needed), `unknown` (the evidence doesn't decide), `not_present` (the protocol's software isn't on the host, e.g. no IPsec stack). |
| `capable` | bool \| null | TLS: the system OpenSSL offers a hybrid or pure ML-KEM TLS group (`openssl.tls_groups`), else `openssl.pqc_native`, else, offline, `openssl.pqc_native_expected`. SSH: `sshd.openssh_supports_pqc_kex`, else `ssh_pqc.kex_groups`. IPsec: `ipsec_pqc.pqc`. Services: the library the process maps (`library_pqc_capable`) or its Go default. |
| `configured` | bool \| null | TLS: `crypto_policy.pqc_enabled.tls_key_exchange`, else `openssl.config.pqc_key_exchange_by_default`. SSH: `sshd.pqc_offered` (sshd's effective `KexAlgorithms`), else the policy's server setting. IPsec: a configured connection offers ML-KEM, else the policy's IKE setting. Go services: their own crypto/tls default, which ignores the system policy. |
| `evidence` | object | `{capable, configured}`: lists of JSON paths into this report for the fields that decided each value. Empty for `not_present`. |
| `note` | string | Optional. SSH: PQC is offered but a classical method is preferred first. IPsec: connections the installed stack can't load (`ipsec_pqc.configured.capability_mismatch`). |

`services`:

| Key | Type | Meaning |
| --- | --- | --- |
| `available` | bool | `--scan-services` ran (`service_crypto_linkage.available`). |
| `items` | list[object] | One verdict per process / transport / port / state; instances that share all four (IPv4 and IPv6 sockets, or one daemon per systemd scope) are collapsed. |
| `by_state` | object | Item count per `state`. |
| `differing_from_host` | int | Items with `follows_host_default: false`. |
| `listeners_without_crypto_library` | int | Attributed listeners whose process maps no crypto library and isn't a Go binary (no verdict). |
| `listeners_unattributed` | int | Listeners whose owning process couldn't be read (no verdict). |

Each `services.items[]` entry adds to the verdict keys:

| Key | Type | Meaning |
| --- | --- | --- |
| `process` | string | Process name (`service_crypto_linkage.listeners[].process`). |
| `systemd_units` | list[string] | Units of the collapsed instances. |
| `protocol` | string | Transport: `tcp` or `udp`. |
| `port` | int | Listening port. |
| `kind` | string | `ssh` for sshd, which takes the host's SSH verdict; otherwise `tls`, meaning the process maps a TLS library (or is a Go binary). The port itself may not speak TLS (for example mDNS on `udp/5353` in a process that links a TLS library). |
| `crypto_families` | list[string] | Library families the process maps, plus `go`. |
| `follows_host_default` | bool | The item reached the same state as the host's protocol verdict through the host default, so it adds nothing to it. Measured on Rocky Linux 9.8 and Fedora 44: `httpd` on port 80, `rpcbind` and `systemd-resolved` map a TLS library without speaking TLS on those ports. False for a service whose library differs from the system one, a Go binary using its own default, or a service whose own TLS configuration decides (`service_config`); only those count in `gaps` and `pqc-020`. |
| `listeners` | list[string] | JSON paths of the `service_crypto_linkage.listeners[]` entries behind this item. |
| `service_config` | string | Present when the service's own TLS configuration (`service_tls_config`, #216) has an endpoint on this port: its JSON path. When that endpoint's `pqc_key_exchange` is true or false it decides `configured` (and `follows_host_default` is false); PostgreSQL before 18 is also not `capable`. When it is null, the host default decides and the path is added to `evidence.configured`. |

`clients` (#202): one verdict per `process_crypto_linkage.groups[]` entry
with at least one process in the `client` role (outbound-only TLS clients a
service scan can't see). Listening servers are covered by `services`; idle
processes negotiate nothing. A Go binary is judged on its own crypto/tls
default: Go 1.24+ is capable, and `GODEBUG tlsmlkem=0` (environment, or
`DefaultGODEBUG` from an old `go` line in go.mod) makes it
`capable_not_configured`; older Go is `not_capable`. Otherwise the group
negotiates with the libraries it maps under the host's TLS configuration and
is not capable when any of them is known not to be, the same judgement the
`pqc-011` / `pqc-013` failure findings use (`library_capable`).

| Key | Type | Meaning |
| --- | --- | --- |
| `available` | bool | `--scan-processes` ran (`process_crypto_linkage.available`). |
| `items` | list[object] | One verdict per client process group, ordered by state (`deployed` first) then client process count. |
| `by_state` | object | Client group count per `state`. |
| `client_processes_by_state` | object | Client process count per `state`. |
| `differing_from_host` | int | Items with `follows_host_default: false`. |
| `groups_omitted_by_scan` | int | Optional. Process groups the scan dropped at its group cap (`process_crypto_linkage.omitted_groups`); they have no verdict. |

Each `clients.items[]` entry adds to the verdict keys:

| Key | Type | Meaning |
| --- | --- | --- |
| `exe` | string | Executable path of the group. |
| `process` | string | Process name. |
| `systemd_units` | list[string] | Units of the group's processes. |
| `containers` | list[object] | The group's `containers` (#262). |
| `containers_omitted` | int | The group's `containers_omitted`, or 0. |
| `client_processes` | int | Processes in the group in the `client` role. |
| `crypto_families` | list[string] | Library families the group maps, plus `go`. |
| `follows_host_default` | bool | The group reached the host's TLS verdict through the host default; false for a Go binary (its own default) or a group whose libraries give a different state. Only groups with `false` count in `gaps` and `pqc-020`. |
| `group` | string | JSON path of the `process_crypto_linkage.groups[]` entry. |

SARIF / NDJSON: rule `pqc-020-pqc-capable-not-configured` reports one
host-level result listing every protocol, and every service and client
group that differs from its host's verdict, in `capable_not_configured` (a warning when it covers IPsec or services, a note
when it only restates the TLS / SSH gaps of `pqc-008` / `pqc-010`). A client
group in one container is named by container and pod, e.g.
`proxy (pod shop/web-0)`; a group spread over several is named by
executable with a count, e.g. `/usr/bin/sidecar (3 containers)` (#262).
### `boot_chain`

`{}` unless `--scan-boot-chain`. Linux only; read in-process, no subprocess. Live hosts only: `--root` rejects the flag. Under `--host-mount` the kernel config and modules are read from the host's `/usr/lib/modules/<release>/` (reachable through the deployments' read-only `/usr` mount; Fedora / RHEL ship the config there), never from the container's `/boot` or `/lib/modules`.

| Key | Type | Meaning |
| --- | --- | --- |
| `available` | bool | False off Linux; then only `reason` follows. |
| `reason` | string | Why the inventory did not run, or with `unavailable_in_container`. |
| `unavailable_in_container` | bool | Set, with `reason`, inside a container without `--host-mount`. |
| `secure_boot` | object | UEFI Secure Boot (below). |
| `module_signing` | object | Kernel module signing (below). |
| `ima_evm` | object | IMA / EVM state (below). |
| `lockdown` | string \| null | Active kernel lockdown mode from `/sys/kernel/security/lockdown` (`none`, `integrity`, `confidentiality`); null when unreadable. |
| `tpm` | object | TPM 2.0 revision and post-quantum algorithms (below). |
| `summary` | object | `{secure_boot_certificates, secure_boot_certificate_categories, secure_boot_all_classical, secure_boot_algorithms, module_signing_pqc, classical_layers}`. Certificates are counted across the databases that authorise boot code (`PK`, `KEK`, `db`, `MokList`); `secure_boot_certificate_categories` uses the trust-store buckets (`classical`, `hybrid_composite`, `pure_pqc`); `secure_boot_algorithms` lists e.g. `RSA-2048`, `EC P-384`. `classical_layers` lists every layer with no post-quantum key: `secure_boot`, `module_signing`, `ima`, `tpm` (SARIF `pqc-030`). |

`secure_boot` (efivarfs; UEFI 2.10 EFI_SIGNATURE_LIST; GUIDs from edk2 and shim):

| Key | Type | Meaning |
| --- | --- | --- |
| `available` | bool | False on legacy BIOS boot or without efivarfs. |
| `firmware` | string | `uefi` or `bios`. |
| `reason` | string | Why `available` is false: legacy BIOS, efivarfs not mounted, or efivarfs not readable (measured: rootless podman with default SELinux labels is denied efivarfs; the quadlet's `SecurityLabelDisable` lifts that). |
| `enabled` | bool \| null | The `SecureBoot` variable. |
| `setup_mode` | bool \| null | The `SetupMode` variable (true: no PK enrolled, keys can be changed freely). |
| `shim_validation_disabled` | bool | shim's `MokSBStateRT` says signature validation is disabled. |
| `databases` | object | `PK`, `KEK`, `db`, `dbx`, `MokList` (shim `MokListRT`), `MokListX` (shim `MokListXRT`). Each is `{present: false}` when absent, otherwise `{present, source, certificates, sha256_hashes, rsa2048_keys, other_entries, errors}`: `source` is `efivars` or `mok-variables` (the kernel's complete copy of the MOK lists); `certificates` holds `{subject, issuer, sha256, not_after, key_algorithm, key_size, category}` for each X.509 entry; `sha256_hashes` and `rsa2048_keys` count those entry types; `other_entries` maps other signature-type GUIDs to counts; `errors` lists malformed lists or entries. `dbx` and `MokListX` revoke, so they don't count towards `summary`. |

`module_signing`:

| Key | Type | Meaning |
| --- | --- | --- |
| `kernel_release` | string | Running kernel release (`/proc/sys/kernel/osrelease`). |
| `kernel_config_source` | string \| null | Where the kernel config was read: `/boot/config-<release>` (bare metal only), `/lib/modules/<release>/config`, `/usr/lib/modules/<release>/config` or `/proc/config.gz`. |
| `module_sig` | bool \| null | `CONFIG_MODULE_SIG`. |
| `module_sig_force` | bool \| null | `CONFIG_MODULE_SIG_FORCE`. |
| `module_sig_hash` | string \| null | `CONFIG_MODULE_SIG_HASH`, e.g. `sha512`. |
| `key_types_configured` | list[string] | `CONFIG_MODULE_SIG_KEY_TYPE_*` set to `y`: `RSA`, `ECDSA`, `MLDSA_44`, `MLDSA_65`, `MLDSA_87` (the ML-DSA options exist from Linux 7.0). |
| `sig_enforce` | bool \| null | `/sys/module/module/parameters/sig_enforce`. |
| `sample_module` | object \| null | The first module from `modules.dep` whose signature could be read: `{module, signed}`, plus for signed modules `{format, parsed}` and, when the PKCS#7 signature parsed, `{signer, digest_algorithm, signature_algorithm, signature_algorithm_oid, key_size, category}` (`key_size` is the RSA modulus size implied by the signature length; `category` is `classical` or `pure_pqc`), or `reason` when it did not. `.ko.zst` modules need Python 3.14 (`compression.zstd`). |
| `pqc` | bool \| null | The sample module, else the configured key type, is ML-DSA. |

`ima_evm`:

| Key | Type | Meaning |
| --- | --- | --- |
| `ima_securityfs` | bool | `/sys/kernel/security/ima` exists. |
| `cmdline` | object | IMA / EVM kernel parameters present on `/proc/cmdline`: `ima_policy`, `ima_appraise`, `ima_hash`, `ima_template`, `evm`. |
| `policy` | object | `{readable: false}` unless the IMA policy is readable (root, `CONFIG_IMA_READ_POLICY`); then `{readable, rules, measure_rules, appraise_rules, signature_required_rules}` (`signature_required_rules` counts `appraise_type=imasig`). |
| `evm_mode` | int \| null | Value of the EVM securityfs file (a bitmask; 0 means EVM is not initialised). |
| `certificates` | list[object] | IMA code-signing certificates under `/etc/keys/ima` (Fedora ships them), same fields as the Secure Boot certificates plus `path`. |

`tpm` (one read-only `TPM2_GetCapability` on `/dev/tpmrm0`; needs root or the `tss` group):

| Key | Type | Meaning |
| --- | --- | --- |
| `present` | bool | `/sys/class/tpm/tpm0` exists. |
| `version_major` | int \| null | `tpm_version_major` from sysfs (1 or 2). |
| `queried` | bool | The capability query ran. |
| `reason` | string | Why it did not. |
| `family` | string \| null | `TPM_PT_FAMILY_INDICATOR`, e.g. `2.0`. |
| `spec_revision` | string \| null | `TPM_PT_REVISION` / 100, e.g. `1.59`, `1.85`. |
| `spec_year` | int \| null | `TPM_PT_YEAR`. |
| `manufacturer` | string \| null | `TPM_PT_MANUFACTURER` as ASCII, e.g. `IBM`, `INTC`. |
| `pqc_algorithms` | list[string] | Post-quantum algorithms the TPM implements: `ML-KEM`, `ML-DSA`, `HashML-DSA` (TPM 2.0 Library v1.85 IDs 0x00A0-0x00A2). |
| `pqc_capable` | bool | Any of them. |
| `spec_note` | string | Where the v1.85 algorithm IDs come from (a release candidate, per wolfTPM's implementation). |

### `kerberos`

`{}` unless `--scan-kerberos`. Read in-process (no `klist`): `/etc/krb5.conf` and everything it pulls in with `include` / `includedir` (symlinks resolved under the host prefix, so the RHEL crypto-policies back-end in `/etc/krb5.conf.d` is the host's), `kdc.conf`, and keytabs. Keytabs are parsed from MIT's FILE keytab format; key contents are skipped by length and never stored or emitted. Enctype names and status follow the IANA Kerberos Encryption Type Numbers registry. Works with `--root`.

| Key | Type | Meaning |
| --- | --- | --- |
| `available` | bool | False when neither `/etc/krb5.conf` nor a `kdc.conf` exists. |
| `reason` | string | Why `available` is false, or with `unavailable_in_container`. |
| `unavailable_in_container` | bool | Set, with `reason`, inside a container without `--host-mount`. |
| `config_files` | list[string] | Configuration files read, in order. |
| `config` | object | `{allow_weak_crypto, default_keytab_name, enctype_lists, pkinit}` from `[libdefaults]` (below). |
| `kdc` | object \| null | `{path, realms}` from `/var/kerberos/krb5kdc/kdc.conf` or `/etc/krb5kdc/kdc.conf`; `realms` maps each realm to `{supported_enctypes, master_key_type}` (salt types dropped). Null without a `kdc.conf`. |
| `keytabs` | list[object] | One per keytab found (`/etc/krb5.keytab`, `default_keytab_name`, `*.keytab` up to three levels under `/etc`): `{path, readable, reason}` when unreadable (keytabs are root-only), otherwise `{path, readable, parsed, format_version, entries, enctypes}` (`parsed: false` with `reason` for a malformed file). Each `entries` item is `{principal, kvno, enctype, enctype_number, status}`; `enctypes` maps enctype name to key count. |
| `summary` | object | `{enctypes_allowed, enctypes_in_keytabs, deprecated_enctypes, aes128_enctypes, keytab_keys_128_bit_only, pkinit_classical}`. `enctypes_allowed` is the union of every expanded list, the KDC `supported_enctypes` and the keytab enctypes. `pkinit_classical` is true when a PKINIT identity is configured with classical certificates, null when the identity store can't be read (e.g. a PKCS#11 token), false when PKINIT isn't used. Drives SARIF `pqc-031`. |

`config.enctype_lists` has one entry per `permitted_enctypes`, `default_tkt_enctypes` and `default_tgs_enctypes`: `{raw, source, enctypes}`. `raw` is the configured string; `source` is `configured`, `permitted_enctypes` (unset, so `permitted_enctypes` applies, as in krb5 1.18 and later) or `mit_default` (unset everywhere: MIT's built-in default, which still includes the deprecated `des3-cbc-sha1` and `arcfour-hmac`); `enctypes` is the list expanded with MIT's rules (aliases, the `aes` / `des3` / `rc4` / `camellia` families, `DEFAULT`, `-x` removal), with MIT's "weak" types dropped unless `allow_weak_crypto` is true.

Enctype `status`: `deprecated` (DES, 3DES, RC4: RFC 6649 / RFC 8429), `aes128` (128-bit AES / Camellia: about 64-bit security against Grover's algorithm; CNSA 2.0 requires AES-256), `ok` (256-bit), `unknown`.

`config.pkinit`:

| Key | Type | Meaning |
| --- | --- | --- |
| `settings` | list[string] | Every `pkinit_*` tag found in `[libdefaults]`, `[realms]` or `[kdcdefaults]`. |
| `anchors` | object \| null | `pkinit_anchors`. For a `FILE:` value `{path, exists, certificates, categories, key_algorithms}` (`exists: false` when the file is missing, as with Fedora's stock `ca-bundle.crt` path); otherwise `{value}` naming only the store type. |
| `identity_configured` | bool | `pkinit_identity` / `pkinit_identities` is set: PKINIT is in use. Anchors alone don't count. |
| `identity` | object \| null | For a `FILE:` identity, the same fields as `anchors` (certificates only; the key half is never read); for other stores `{store}` (e.g. `PKCS11`). |

### `tunnels`

`{}` unless `--scan-tunnels`. Read in-process from configuration files; on a live host as root, `wg show all preshared-keys` adds the running interfaces (only whether each peer's pre-shared-key column is `(none)` is kept; the value is never stored or emitted). WireGuard's handshake is Curve25519 (Noise_IK); its only post-quantum mitigation is the optional per-peer pre-shared key (WireGuard protocol documentation). OpenVPN's control channel is TLS: `tls-groups` is handed to OpenSSL only when configured, and hybrid ML-KEM groups are TLS 1.3 only. Works with `--root` (configs only).

| Key | Type | Meaning |
| --- | --- | --- |
| `available` | bool | False when no WireGuard or OpenVPN configuration was found. |
| `reason` | string | Why `available` is false, or with `unavailable_in_container`. |
| `unavailable_in_container` | bool | Set, with `reason`, inside a container without `--host-mount`. |
| `wireguard` | object | `{configs, running, summary}` (below). |
| `openvpn` | object | `{configs, version, summary}` (below). |

`wireguard`:

| Key | Type | Meaning |
| --- | --- | --- |
| `configs` | list[object] | One per WireGuard config: `{path, source, readable, peers}`, or `{path, source, readable: false, reason}` when unreadable (wg-quick configs are root-only; an `/etc/wireguard` directory that can't be listed appears as one unreadable entry with the directory as `path`). `source` is `wg-quick` (`/etc/wireguard/*.conf`), `systemd-networkd` (`.netdev` with `Kind=wireguard`) or `networkmanager` (keyfile with `type=wireguard`). Each `peers` item is `{preshared_key}` (bool; a NetworkManager PSK held by an agent counts as present). |
| `running` | object | `{queried, interfaces}` when `wg show` ran (`interfaces` maps each interface to `{peers, with_psk}`), otherwise `{queried: false, reason}` (not root, `wg` missing, or not a live host namespace). |
| `summary` | object | `{configured, peers, peers_without_psk, unreadable_configs}`. `peers` / `peers_without_psk` are the larger of the config and running counts. Drives SARIF `pqc-032`; each unreadable wg-quick config or directory raises `pqc-018` (undetermined), as does each unreadable OpenVPN config. |

`openvpn`:

| Key | Type | Meaning |
| --- | --- | --- |
| `configs` | list[object] | One per config under `/etc/openvpn` (`*.conf`, `server/`, `client/`, `*.ovpn`): `{path, readable: false, reason}` when unreadable (also for a directory that exists but can't be listed: Fedora ships `server/` and `client/` 0750), otherwise the fields below. |
| `version` | string \| null | Installed OpenVPN version from the rpm database; null elsewhere. |
| `summary` | object | `{configured, without_pqc, follows_openssl_default}`: config paths whose key exchange can't be PQC, and those that inherit OpenSSL's defaults. Drives SARIF `pqc-033`. |

Each readable `openvpn.configs` item: `path`, `readable`, `role` (`client` / `server` / null), `tls_groups` (list or null when unset), `tls_version_min`, `tls_version_max`, `control_channel_psk` (`tls-crypt-v2` / `tls-crypt` / `tls-auth` / null: a pre-shared symmetric key wrapped around the handshake), `static_key_mode` (`secret`: no public-key exchange at all), `data_ciphers`, `key_exchange` (`configured`, `openssl-default` or `static-key`) and `pqc_key_exchange` (true / false; null when it follows OpenSSL's defaults, see `openssl` and `crypto_policy`, or in static-key mode). `tls-version-max` 1.2 or lower forces `pqc_key_exchange: false`.

### `dnssec`

`{}` unless `--scan-dnssec`. Read in-process from configuration and key file names. Algorithm numbers, names and status follow the IANA DNS Security Algorithm Numbers registry: `pqc` (ML-DSA-44, algorithm 18, registered from an Internet-Draft), `deprecated` (MUST NOT for signing: RSAMD5, DSA, RSASHA1 and their NSEC3 variants, ECC-GOST), `classical`, `unknown`. Works with `--root`.

| Key | Type | Meaning |
| --- | --- | --- |
| `available` | bool | False when no BIND, Knot, PowerDNS, Unbound or systemd-resolved configuration exists. |
| `reason` | string | Why `available` is false, or with `unavailable_in_container`. |
| `unavailable_in_container` | bool | Set, with `reason`, inside a container without `--host-mount`. |
| `bind` | object \| null | `{config_files, dnssec_validation, policies, signed_zones, key_directory, key_files}` from `/etc/named.conf` or `/etc/bind/named.conf` with `include`s. `policies` maps each `dnssec-policy` to its key algorithms (the built-in `default` policy is one ECDSAP256SHA256 CSK); `signed_zones` lists `{zone, policy}` for zones with a policy other than `none`; `key_files` are the `K<zone>+<alg>+<id>.key` files found in the key directory (algorithm from the file name). |
| `knot` | object \| null | `{config_files, policy_algorithms, signing_zones}` from `/etc/knot/knot.conf`; `signing_zones` counts `dnssec-signing: on`. |
| `powerdns` | object \| null | `{config_files, default_algorithms}`: `default-ksk-algorithm` / `default-zsk-algorithm` from `pdns.conf`. |
| `validators` | object | `unbound: {validating, trust_anchor_configured}` (validator module or trust anchor configured) and `systemd_resolved: {dnssec}` (the effective `DNSSEC=` value after drop-ins; null when unset), each present only when its config exists. |
| `summary` | object | `{signing_algorithms, signing_configured, signing_pqc, deprecated_signing, unreadable_configs}`: the distinct algorithms used to sign zones (BIND policies in use and key files, Knot when signing, PowerDNS defaults), and `{path, reason}` for each server config that exists but couldn't be read (`named.conf` is root:named 0640 on RHEL / Fedora). Drives SARIF `pqc-034`; each unreadable config raises `pqc-018` (undetermined). |

Each algorithm record (in `policies`, `key_files`, `policy_algorithms`, `default_algorithms`, `signing_algorithms`) is `{number, name, status}`; BIND policy entries add `role` (`ksk` / `zsk` / `csk`), key files add `zone` and `directory`.

### `os_release`

| Key | Type | Meaning |
| --- | --- | --- |
| `id` | string | `ID` from `/etc/os-release` (`unknown` when absent). |
| `version_id` | string | `VERSION_ID`. |
| `version_codename` | string \| null | `VERSION_CODENAME`; `null` when unset. |
| `pretty_name` | string \| null | `PRETTY_NAME`.  Under `--root`, `null` when the tree has no release file at all (see `reason`); it is never filled from the scanning machine's kernel. |
| `family` | string | Derived distro family (from `ID`, then `ID_LIKE`): `rhel`, `debian`, `suse`, `arch`, `alpine`, `openwrt`, `macos` or `unknown`. Yocto and Buildroot images usually resolve to `unknown`; their package database, if any, is found by probing. |
| `package_manager` | string \| null | The family's package-manager command (`dnf` / `microdnf` / `yum`, `apt-get` / `apt`, `zypper`, `pacman`, `apk`, `opkg`): the first one on `PATH`, or under `--root` the first one the tree itself ships in `/usr/bin`, `/bin`, `/usr/sbin` or `/sbin`. |
| `source` | string | Present only when the identity came from a distro release file other than `os-release`: `/etc/openwrt_release` (OpenWrt) or `/etc/buildinfo` (Yocto `image-buildinfo`: `id` is `DISTRO`, e.g. `poky`, and `version_id` is `DISTRO_VERSION`). |
| `reason` | string | Present only under `--root` when the tree has no `os-release`, `openwrt_release`, `buildinfo` or legacy release file, so its OS is not identified. |

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

### `inventory_metadata`

`null` unless `--inventory-metadata FILE` is given. Every key is optional;
the file is rejected (exit 2, before any probing) if it contains unknown
keys or invalid values. Values are echoed as supplied, so the file must
hold **identifiers only**: OMB M-23-02 footnote 13 forbids names that
reveal a system's function or location.

| Key | Type | Meaning |
| --- | --- | --- |
| `fisma_system_id` | string | FISMA system identifier (M-23-02 item 1). |
| `fips199_categorization` | string | `Low`, `Moderate` or `High` (item 2); input is case-insensitive. |
| `hva_id` | string | High Value Asset identifier, if the system is an HVA (item 3). |
| `hosting` | object | Hosting model (item 7): `{model, provider?}`. |
| `hosting.model` | string | `on-premises`, `commercial-csp`, `government-csp` or `hybrid`. |
| `hosting.provider` | string | Provider name(s); required for every model except `on-premises`. |
| `data_lifecycle` | object | Data lifecycle (item 8): `{records_categories?, time_to_live_years?}`. |
| `data_lifecycle.records_categories` | list of string | Records-management categories of the data. |
| `data_lifecycle.time_to_live_years` | number | How long the data and metadata need protection. |
| `notes` | string | Free text (item 9). |

The same facts appear in `--cbom` as `inventory:*` properties on the host
component. With `--cbom-profile federal-draft` the CBOM also reports, per
item, whether it was `provided`, `collected`, `partial` or
`not-provided`; see [docs/inventory-methodology.md](inventory-methodology.md).

### `scan_mode`

`null` unless `--root PATH` is given. An offline scan reads a filesystem tree (a
mounted disk image or an extracted container rootfs) instead of a live host:
packages, certificates, keys, crypto policies, `openssl.cnf` and package-signing
keys come from the tree; nothing about the scanning machine (its CPU, kernel,
processes or binaries on `PATH`) is reported. `verdict` is
`NOT APPLICABLE - offline filesystem scan`, `isa_tier` is `not_applicable`,
`exit_code` is 0, and `hostname` is `--host-name` when given, else the tree's
`/etc/hostname` (empty when it has none). `arch` is read from the ELF header of the tree's
`/usr/bin/env`, `/bin/sh` or `/usr/bin/sh`.

| Key | Type | Meaning |
| --- | --- | --- |
| `mode` | string | Always `offline_root`. |
| `root` | string | Absolute path of the scanned tree. |
| `not_applicable` | list[string] | Report fields that cannot be answered from a tree. Object-valued ones hold the `{available: false, not_applicable: true, reason}` marker; scalar and list ones keep their empty defaults and are listed here so consumers don't read them as "probed, nothing found". |
| `partial` | object | Sections that are partly answered: `openssl` (packaged version and `openssl.cnf`, no capability probes), `ipsec_pqc` (configured proposals, no capability), `nss` (version from the tree's rpm database when present) and `ssh_pqc` (version from the tree's OpenSSH package, kex names from its binary; #256). Values are human-readable explanations. |
| `reason` | string | One-sentence summary; also used as `verdict_reason`. |

`--root` cannot be combined with `--host-mount`, `--bench`, `--bench-tls`,
`--scan-services`, `--scan-processes`, `--scan-boot-chain`, `--check`,
`--fips-strict` or `--recommend` (usage error, exit 2): each needs a live host
or a readiness tier.

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
| `policy_source` | string | Source documents the policy rests on, by name (e.g. `NSA CSA Announcing CNSA 2.0 (Sept 2022) and CNSA 2.0 FAQ ver. 2.1 (Dec 2024)`); URLs are in `policy_sources`. |
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
| `pqc_deployment_gap` | object | Capability vs configuration across the fleet (#107): `hosts_by_protocol_state` (for `tls`, `ssh`, `ipsec`: host count per state), `services_by_state` (service count per state across all hosts), `client_groups_by_state` / `client_processes_by_state` (outbound-client process groups from `--scan-processes`, and their client process counts, per state; #202), and `hosts_with_gap` (hosts with at least one protocol, service or client group in `capable_not_configured` / `configured_not_capable`). Reports without their own `pqc_deployment_gap` are evaluated from their fields. CSV rows: `pqc_deployment_gap_<protocol>`, `pqc_deployment_gap_services`, `pqc_deployment_gap_client_groups`, `pqc_deployment_gap_client_processes`, `pqc_deployment_gap_hosts_with`. |
| `skipped` | list[object] | Files not merged, each `{file, reason}` (unreadable, not a JSON object, or schema mismatch). |
| `observations` | object | Present only with `--observations FILE`: endpoint observations joined to the hosts and listening services in the reports (#149). See [`--aggregate` observations join](#--aggregate-observations-join). |

### `--aggregate` observations join

`--aggregate DIR --observations FILE` adds an `observations` object. The
record format and the matching rules are in
[endpoint-observations.md](endpoint-observations.md).

| Key | Type | Meaning |
| --- | --- | --- |
| `observation_schema_version` | string | Observation schema this scanner validates against (`1.0`). |
| `file_format` | string | `envelope` (one JSON object) or `jsonl` (one record per line). |
| `total` | int | Records read, valid or not. |
| `valid` | int | Records that passed validation and were joined. |
| `invalid` | list[object] | Rejected records, each `{record, reason}`: `record` is the 1-based position in the envelope list, or the line number in JSON Lines. |
| `max_age_days` | number | `--observations-max-age-days` in effect (default 7). |
| `stale` | int | Matched records made more than `max_age_days` before or after their host's report. |
| `by_status` | object | Record count per `status` (see `matches[]`). |
| `by_observed_class` | object | Record count per observed class: `pure_pqc`, `hybrid`, `classical`, `unknown`. |
| `states` | list[object] | One entry per combination seen on endpoints attributed to a host (`matched` or `no_service_scan`): `{capable, configured, observed, endpoints}`. `capable` and `configured` are `yes`, `no` or `unknown`; `observed` is the class. This is the input to the three-state verdict (#107). |
| `by_gap_state` | list[object] | One entry per `{protocol, state, observed}` seen on attributed endpoints, with `endpoints`: the three-state view (#107). `state` is the endpoint's deployment-gap state (see [`pqc_deployment_gap`](#pqc_deployment_gap)); `observed` is the observed class. For example `state: deployed, observed: classical` is a capable, configured endpoint that a client still reached with classical key exchange. CSV rows: `observations_by_gap_state`. |
| `per_host` | object | Keyed by `hostname`: `{endpoints, by_observed_class, capable_but_observed_classical, configured_but_observed_classical, stale}` over that host's attributed endpoints. |
| `matches` | list[object] | One entry per valid record, in file order (fields below). |

`matches[]` entries:

| Key | Type | Meaning |
| --- | --- | --- |
| `record` | int | Position of the record in the file (as in `invalid`). |
| `id` | string \| null | The record's own `id`. |
| `protocol` / `port` / `fqdn` / `ip` / `sni` | | Copied from the record. |
| `observed_group` | string \| null | `negotiated_group` normalised: codepoints and spelling variants mapped to the IANA name (e.g. `0x11EC` → `X25519MLKEM768`); for IKEv2, initial and additional key exchanges joined with `+`. |
| `observed_class` | string | `pure_pqc`, `hybrid`, `classical` or `unknown`. |
| `source_category` | string | The record's `source.category`. |
| `status` | string | `matched` (host and listener found), `no_service_scan` (host found; its report has no `service_crypto_linkage`), `unmatched_listener` (host found; nothing reachable listening on that transport and port), `ambiguous` (more than one host fits; see `candidates`), `unmatched_host`. |
| `match_basis` | string \| null | Key that identified the host: `fqdn`, `sni`, `ip`, `short-name`, `certificate`, or one of the first four with `+certificate` when the fingerprint broke a tie. |
| `host` | string \| null | Matched report's `hostname`. |
| `candidates` | list[string] | `ambiguous` only: hostnames of the hosts that fit. |
| `listener` | object \| null | The matched listener: `protocol`, `address`, `port`, `bind_scope`, `network_namespace`, `process`, `systemd_unit`, `crypto_families`, `library_pqc_capable`, `go_default_hybrid` (a Go binary whose default offers hybrid ML-KEM), `matching_listeners` (how many listeners fit; the first in the host namespace is used). |
| `capable` | bool \| null | TLS, QUIC, DTLS: the listener's library version ships hybrid ML-KEM, or its Go default offers it. SSH: the host's OpenSSH lists an ML-KEM kex. IKEv2: the IPsec stack supports ML-KEM. |
| `configured` | bool \| null | TLS, QUIC, DTLS: the system crypto policy, else OpenSSL's default groups, allow a PQC group; Go listeners use their own default. SSH: sshd's effective `KexAlgorithms` (`sshd.pqc_offered`), else the policy's server key-exchange setting. IKEv2: a configured connection offers ML-KEM, else the policy. Host defaults, not per-service settings. |
| `state` | string \| null | `classify(capable, configured)`, as in [`pqc_deployment_gap`](#pqc_deployment_gap); null when no host was attributed. |
| `certificate_on_host` | bool \| null | When the record has `certificate_sha256` and a host matched: whether that certificate was found on the host. |
| `stale` | bool \| null | The record is older or newer than the host's report by more than `max_age_days`; null when no host matched. |
| `note` | string \| null | E.g. the listener is in another network namespace, reachable only through port mapping. |

## `--ndjson` events

`--ndjson` writes newline-delimited JSON for SIEMs (#146): one compact
JSON object per line, shaped after [OCSF](https://schema.ocsf.io) 1.9.0.
Every event validates against the OCSF 1.9.0 JSON Schema for its class
(base class, no profiles), which CI checks. The first line is one
**Device Inventory Info** event (class 5001) for the host. Each following
line is one **Compliance Finding** event (class 2003) per matched rule:
the same rules, in the same order, as `--sarif`. OCSF has no
crypto-inventory class, so scanner-specific detail goes under
`unmapped.pqc_readiness`. Integration recipes are in
[docs/siem-ndjson.md](siem-ndjson.md).

Fields common to both event types:

| Field | Type | Meaning |
|---|---|---|
| `class_uid` / `class_name` | int / string | `5001` Device Inventory Info, or `2003` Compliance Finding. |
| `category_uid` / `category_name` | int / string | `5` Discovery, or `2` Findings. |
| `activity_id` / `activity_name` | int / string | `1`: `Log` for 5001, `Create` for 2003. Each run is a snapshot; deduplicate on `finding_info.uid`. |
| `type_uid` / `type_name` | int / string | `class_uid × 100 + activity_id`: `500101` or `200301`. |
| `severity_id` / `severity` | int / string | 5001 is always `1` Informational. For 2003, the rule's `security-severity` on the CVSS v3.1 bands: `2` Low (< 4.0), `3` Medium (< 7.0), `4` High. |
| `time` | int | `generated_at` in milliseconds since the Unix epoch (OCSF `timestamp_t`). |
| `message` | string | 5001: `PQC readiness: <verdict>`. 2003: the finding message. |
| `metadata` | object | `version` (OCSF version, `1.9.0`); `uid` (this event: hash of the finding identity and `generated_at`); `log_name` (`pqc_readiness`); `original_time` (`generated_at` as emitted); `product` = `{name, vendor_name, version, url_string}`. |
| `device` | object | `hostname`; `type_id`/`type` (`0` Unknown, because the scanner does not classify the host); `os` = `{name, type_id, type}`, with `type_id` `200` Linux when `/etc/os-release` was read. |

Compliance Finding (2003) only:

| Field | Type | Meaning |
|---|---|---|
| `status_id` / `status` | int / string | `1` New. Lifecycle is left to the SIEM. |
| `finding_info` | object | `uid`: stable identity of host + rule, identical to the `--sarif-anchor` fingerprint. `title` / `desc`: the rule's short and full description. `types`: `["Post-Quantum Cryptography Readiness"]`. `src_url`: the rule help page. `analytic` = `{uid, name, type_id, type}`, the rule ID, with `type_id` `1` Rule. |
| `compliance` | object | `control` (rule ID), `standards` (`["pqc-readiness"]`), `status` / `status_id` (`Fail` / `3`). |

`unmapped.pqc_readiness`, the scanner-specific detail:

| Field | Event | Meaning |
|---|---|---|
| `schema_version`, `verdict`, `exit_code`, `isa_tier`, `replace_required` | 5001 | As in the `--json` report. |
| `cnsa_2_0_status` | 5001 | `cnsa_2_0.status`. |
| `openssl_version`, `openssl_pqc_native` | 5001 | `openssl.version`, `openssl.pqc_native`. |
| `tls_hybrid_groups`, `tls_pure_pqc_groups` | 5001 | `openssl.tls_groups.hybrid` / `.pure_pqc`. |
| `findings_count` | 5001 | Number of 2003 events that follow. |
| `scan_mode` | 5001 | Offline `--root` scans only: the report's [`scan_mode`](#scan_mode) object (the event describes a filesystem tree, not a live host). |
| `rule_id`, `level`, `security_severity` | 2003 | Rule ID, SARIF level, and score. |
| `properties` | 2003 | The SARIF result `properties` bag for the finding: the values that triggered the rule. |
| `subject` | 2003 | Rules that fire once per service, library, install, IPsec connection or package (`pqc-011` to `pqc-018`, #193): what this finding is about, e.g. `service:tcp/ipv4/443:/usr/sbin/httpd`, `library:gnutls`, `ipsec:site-a`. Part of `finding_info.uid`, so each subject keeps its own stable ID. Absent for host-level rules. |

## Schema alignment with CycloneDX 1.6

[docs/schema-alignment.md](schema-alignment.md) is a field-by-field
mapping of the `--json` schema against the field-name conventions in
CycloneDX 1.6's `cryptoProperties` schema. The mapping concludes that
`--json` is a host-level inventory schema and CycloneDX is an
asset-level schema — the asset-level projection is already provided by
`--cbom`. No `--json` field renames are recommended at this time, so
no major (`2.0`) bump is planned; the current `SCHEMA_VERSION` is
`"1.6"` from additive changes only.
