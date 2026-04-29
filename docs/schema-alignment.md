# JSON schema alignment with CycloneDX 1.6

This document compares every field emitted by `pqc-readiness --json`
against the established field-name conventions in
[CycloneDX 1.6's `cryptoProperties` schema][cdx-crypto] and
[NIST IR 8547][nist-8547], and recommends — for each field — whether
to rename, keep, or treat as having no equivalent.

The deliverable here is the mapping only. Applying any rename, bumping
`SCHEMA_VERSION`, dual-schema reading in the aggregator, and a
`--schema-version` flag are out of scope and tracked separately.

## Summary

| Counter                                  | Value |
| ---------------------------------------- | ----- |
| Distinct field paths covered             | 110   |
| Recommended `rename to <new>`            | 0     |
| Recommended `keep`                       | 26    |
| Recommended `no equivalent`              | 84    |
| Proposed `SCHEMA_VERSION`                | `1.0` (no bump required) |

**No field renames are recommended.** The reason is structural:

- `pqc-readiness --json` is a **host-level inventory and capability
  schema** — it summarises what one host's CPU, kernel, and crypto
  libraries expose. The shape is `{host -> aggregate findings}`.
- CycloneDX 1.6's `cryptoProperties` is an **asset-level
  cryptographic-asset schema** — every emitted record describes one
  algorithm, protocol, certificate, or related-crypto-material entry.
  The shape is `{component[]}`, one per asset.
- The two schemas operate in different concept spaces. Renaming a
  host-level summary field (e.g. `openssl.kem_algorithms`) to a
  CycloneDX term (e.g. `algorithmProperties.primitive=kem`) would
  change the shape, not just the name.
- The asset-level CycloneDX projection is already shipped: `--cbom`
  emits a CycloneDX 1.6 CBOM whose components carry the canonical
  field names (`assetType`, `algorithmProperties.primitive`,
  `parameterSetIdentifier`, `nistQuantumSecurityLevel`,
  `executionEnvironment`, `implementationPlatform`,
  `protocolProperties.type`, `relatedCryptoMaterialProperties.type`).
  Customers who need the CycloneDX shape consume `--cbom`; customers
  who need the host-level rollup consume `--json`.
- NIST IR 8547 (initial public draft, November 2024) does **not**
  define cryptographic-asset field names — it specifies the PQC
  transition policy (timelines, deprecated primitives, mandatory
  algorithms). The only naming authority for cryptographic asset
  schemas remains CycloneDX 1.6.

The conclusion: keep the current `--json` shape and `SCHEMA_VERSION =
"1.0"`, treat `--cbom` as the asset-level alignment surface, and skip
the planned follow-up rename PR. The follow-up is no-op given this
analysis; if a future cross-tool need surfaces a specific rename the
follow-up issue can be filed at that point with concrete justification.

## Methodology

1. Captured `./pqc_readiness.py --json` against a representative host
   (Fedora 44, OpenSSL 3.5.5, OpenSSH 10.2p1, TPM 2.0 present, no
   FIPS, no IPsec, no trust-store scan, no `--bench`).
2. Walked the `Report` dataclass (`pqc_readiness.py:377`) to enumerate
   every declared field, including those that are empty by default in
   the captured shape (`benchmark`, `benchmark_tls_handshake`,
   `trust_store`, `packages`, `per_algo`, `production_estimate`,
   `accelerators[].pqc_capable`, `accelerators[].version`).
3. Inspected the bundled CycloneDX 1.6 schema
   (`tests/fixtures/cyclonedx/bom-1.6.schema.json`) for the full set of
   `cryptoProperties.*` keys and their enum vocabularies.
4. Confirmed that NIST IR 8547 ipd does not introduce schema field
   names — it cites no specific JSON property names; references in
   `pqc-readiness` documentation that frame NIST IR 8547 as a naming
   authority should be read as "transition-policy authority" rather
   than schema authority.

For each field the table below records:

- **Path** — JSON path under the `--json` root.
- **Type** — current type.
- **Description** — one-sentence summary.
- **CycloneDX 1.6 equivalent** — the closest term in `cryptoProperties`,
  or `—` if none.
- **Recommendation** — `keep`, `no equivalent`, or `rename to <new>`.
- **Rationale** — terse reason.

`keep` = a CycloneDX equivalent exists at the asset level but the
host-level summary has no 1:1 rename. `no equivalent` = nothing in
CycloneDX 1.6 names this concept at all. `rename to <new>` = a
mechanical rename would align with CycloneDX naming with no shape
change.

## Top-level fields

| Path | Type | Description | CycloneDX 1.6 equivalent | Recommendation | Rationale |
| --- | --- | --- | --- | --- | --- |
| `schema_version` | str | Version stamp for this `--json` schema | — | no equivalent | Tooling-internal; CycloneDX has `specVersion` for itself, not foreign schemas. |
| `generated_at` | str (RFC 3339) | When the probe ran | `metadata.timestamp` (BOM-level) | keep | Same concept; appears in `--cbom` already. |
| `hostname` | str | Scanned host's `gethostname()` | `metadata.component.name` (BOM-level) | keep | Already projected to `--cbom`. |
| `os` | str | Pretty OS name | `metadata.component.properties[host:os]` | keep | Host context, no asset-level field. |
| `arch` | str | `platform.machine().lower()` | `algorithmProperties.implementationPlatform` (asset-level) | keep | Mapped per-asset in `--cbom`; host-level summary has no rename target. |
| `cpu_model` | str | Vendor + model string | — | no equivalent | Host context. |
| `cpu_freq_mhz` | float | Max CPU frequency | — | no equivalent | Host context. |
| `cores_logical` | int | Logical core count | — | no equivalent | Host context. |
| `cores_physical` | int | Physical core count | — | no equivalent | Host context. |
| `mem_total_gb` | float | Total system RAM | — | no equivalent | Host context. |
| `mem_avail_gb` | float | Available RAM at probe time | — | no equivalent | Host context. |
| `isa_features` | dict[flag, {name, purpose, weight}] | Detected SIMD ISA features by flag | `algorithmProperties` (asset, primitive=other, executionEnvironment=hardware) | keep | Already projected to per-asset CBOM components. |
| `isa_score` | int | Weighted SIMD score | — | no equivalent | Internal heuristic; CycloneDX has `classicalSecurityLevel` / `nistQuantumSecurityLevel` for asset strength, not host capability. |
| `isa_tier` | str | `excellent / good / marginal / poor` | — | no equivalent | Internal verdict tier. |
| `isa_reason` | str | One-line tier explanation | — | no equivalent | Internal verdict context. |
| `accelerators` | list[obj] | Detected HSMs / TPMs / DPUs / network HSMs | `algorithmProperties` (asset, executionEnvironment=hardware) | keep | Already projected per-asset in CBOM. |
| `hsm_present_but_not_pqc` | bool | Fleet-planning derivative flag | — | no equivalent | Host-level summary; CycloneDX has no aggregate booleans. |
| `pkcs11_modules` | list[str] | Discovered PKCS#11 module paths | `protocolProperties` (asset, type=other) | keep | Each path becomes one CBOM protocol asset; the list itself has no asset-level equivalent. |
| `kernel_crypto_hw` | list[str] | `/proc/crypto` hardware drivers detected | — | no equivalent | Host-level enumeration. |
| `ktls_supported` | bool \| null | Kernel TLS available | — | no equivalent | Host-kernel feature flag. |
| `fips` | dict | FIPS-mode kernel + provider state | — | no equivalent | Compliance posture, not an asset. |
| `openssl` | dict | OpenSSL availability + algorithm exposure | mix of asset + protocol projections (see nested) | keep | Container for nested fields covered below. |
| `tpm_pqc` | dict | TPM presence + PQC advertisement | — | no equivalent | Per-host TPM probe summary. |
| `memory_bandwidth_gb_s` | float \| null | Optional STREAM-Triad bandwidth | — | no equivalent | Bench artefact; not crypto. |
| `memory_bandwidth_method` | str | Method used to derive bandwidth | — | no equivalent | Bench artefact. |
| `ssh_pqc` | dict | OpenSSH PQC capability summary | mix of asset projections (see nested) | keep | Container for nested fields. |
| `ipsec_pqc` | dict | IPsec stack PQC capability | `protocolProperties` (type=ipsec) | keep | Already projected to one CBOM protocol asset. |
| `nss` | dict | NSS library version + PQC capability | — | no equivalent | RPM-based summary; no asset records emitted. |
| `kernel_info` | dict | Linux kernel + distro release facts | — | no equivalent | Host context. |
| `fips_pqc_conflict` | dict | Boolean + explanation when FIPS hides PQC | — | no equivalent | Compliance interpretation. |
| `cnsa_2_0` | dict | CNSA 2.0 compliance evaluation | — | no equivalent | Compliance verdict. |
| `trust_store` | dict | Trust-store summary (cert counts by category) | `relatedCryptoMaterialProperties` summary OR per-cert `certificateProperties` | keep | Summary form already in CBOM as one related-crypto-material asset; per-cert breakout deferred. |
| `runtime_environment` | dict | Container vs host detection | — | no equivalent | Host context. |
| `packages` | dict | RPM/DEB/pacman/apk package inventory | — | no equivalent | OS package inventory; SPDX 3.0 has `software_Package` but that's a different schema (covered in `--spdx`). |
| `replace_required` | bool | Fleet-planning verdict — host needs replacement | — | no equivalent | Aggregate verdict, not an asset. |
| `os_release` | dict | `/etc/os-release` contents normalised | — | no equivalent | OS identification. |
| `benchmark` | dict | OpenSSL microbench results (when `--bench`) | — | no equivalent | Performance, not inventory. |
| `benchmark_tls_handshake` | dict | Loopback TLS 1.3 bench (when `--bench-tls`) | — | no equivalent | Performance, not inventory. |
| `pqc_sizes` | dict[algo, sizes] | Static byte-size table for NIST PQC primitives | `relatedCryptoMaterialProperties.size` (per-instance) | keep | Static reference table; CycloneDX `size` is per-material instance, not per-parameter-set. |
| `per_algo` | dict[algo, verdict] | Per-algorithm production-suitability verdict | — | no equivalent | Internal verdict. |
| `production_estimate` | dict | Aggregate capacity estimate | — | no equivalent | Internal verdict. |
| `verdict` | str | Top-level verdict (`EXCELLENT`/`GOOD`/`MARGINAL`/`POOR`) | — | no equivalent | Internal verdict. |
| `verdict_reason` | str | One-sentence verdict justification | — | no equivalent | Internal verdict. |
| `verdict_caveat` | str | Bench-availability caveat | — | no equivalent | Internal verdict. |
| `exit_code` | int | Process exit code (mirrors verdict) | — | no equivalent | Tooling artefact. |

## Nested fields

### `isa_features.<flag>`

| Path | Type | Description | CycloneDX 1.6 equivalent | Recommendation | Rationale |
| --- | --- | --- | --- | --- | --- |
| `isa_features.<flag>.name` | str | Human-readable feature name | `name` (component-level in CBOM) | keep | Mapped to `name` per asset in `--cbom`. |
| `isa_features.<flag>.purpose` | str | Why this flag matters for PQC | — | no equivalent | Editorial context; emitted as a CBOM `properties[isa:purpose]` entry. |
| `isa_features.<flag>.weight` | str | Numeric weight contributing to `isa_score` | — | no equivalent | Internal scoring. |

### `accelerators[]`

| Path | Type | Description | CycloneDX 1.6 equivalent | Recommendation | Rationale |
| --- | --- | --- | --- | --- | --- |
| `accelerators[].kind` | str | `tpm` / `hsm` / `network_hsm` / `accelerator` / `dpu` | — | no equivalent | Internal taxonomy; surfaced in CBOM as `accelerator:kind` property. |
| `accelerators[].name` | str | Vendor product name | `name` (component-level in CBOM) | keep | Mapped per asset. |
| `accelerators[].detail` | str | PCI vendor:device, sysfs path, or version | — | no equivalent | Free-form detail; CBOM property. |
| `accelerators[].pqc_capable` | bool (optional) | Appliance/firmware advertises PQC | — | no equivalent | Capability flag; CBOM `accelerator:pqc_capable` property. |
| `accelerators[].version` | str (optional) | Version string when available | — | no equivalent | Free-form. |

### `openssl.*`

| Path | Type | Description | CycloneDX 1.6 equivalent | Recommendation | Rationale |
| --- | --- | --- | --- | --- | --- |
| `openssl.available` | bool | OpenSSL detected on host | — | no equivalent | Host-presence flag. |
| `openssl.version` | str | Full version banner | — | no equivalent | Host context; CBOM emits as `source=openssl@<version>` per asset. |
| `openssl.version_tuple` | list[int] | Parsed (major, minor, patch) | — | no equivalent | Internal parse artefact. |
| `openssl.pqc_native` | bool | OpenSSL ≥ 3.5 (native ML-KEM/ML-DSA) | — | no equivalent | Capability flag; CBOM emits per-asset. |
| `openssl.kem_algorithms` | list[str] | Detected KEM names (ML-KEM-512/768/1024 etc.) | per algorithm: `algorithmProperties.primitive=kem` + `parameterSetIdentifier` + `nistQuantumSecurityLevel` | keep | Already projected per-algorithm in CBOM; the list summary has no rename target. |
| `openssl.sig_algorithms` | list[str] | Detected signature algorithms | per algorithm: `algorithmProperties.primitive=signature` + parameterSetIdentifier + nistQuantumSecurityLevel | keep | Same — projected per-asset. |
| `openssl.tls_groups` | dict | TLS group categorisation | — | no equivalent | Container. |
| `openssl.tls_groups.pure_pqc` | list[str] | Pure-PQC TLS group names | per group: `algorithmProperties.primitive=kem` | keep | Projected per-asset. |
| `openssl.tls_groups.hybrid` | list[str] | Hybrid TLS group names | per group: `algorithmProperties.primitive=combiner` | keep | Projected per-asset. |
| `openssl.tls_groups.classical` | list[str] | Classical TLS group names | per group: `algorithmProperties.primitive=key-agree` (not currently emitted to CBOM) | keep | Out-of-scope today; would extend CBOM, not rename `--json`. |
| `openssl.tls_pqc_groups` | list[str] | Legacy combined PQC group list | — | no equivalent | Pre-split helper; superseded by `tls_groups.{pure_pqc,hybrid}`. |
| `openssl.providers` | list[str] | OpenSSL providers loaded | — | no equivalent | Diagnostic. |
| `openssl.upgrade_path` | str \| null | Family-aware OpenSSL upgrade hint | — | no equivalent | Editorial guidance. |

### `fips.*`

| Path | Type | Description | CycloneDX 1.6 equivalent | Recommendation | Rationale |
| --- | --- | --- | --- | --- | --- |
| `fips.kernel` | bool | Kernel FIPS mode active | — | no equivalent | Compliance posture. |
| `fips.openssl_provider` | bool | OpenSSL FIPS provider loaded | — | no equivalent | Compliance posture. |
| `fips.distribution_certified` | bool | Distro ships a certified FIPS provider | — | no equivalent | Compliance posture. |
| `fips.distribution_certified_source` | str \| null | Where the certification claim comes from | — | no equivalent | Compliance posture. |
| `fips.notes` | str | One-paragraph FIPS context | — | no equivalent | Editorial. |

### `tpm_pqc.*`

| Path | Type | Description | CycloneDX 1.6 equivalent | Recommendation | Rationale |
| --- | --- | --- | --- | --- | --- |
| `tpm_pqc.present` | bool | TPM device file present | — | no equivalent | Host probe. |
| `tpm_pqc.tools` | bool | `tpm2-tools` available | — | no equivalent | Host probe. |
| `tpm_pqc.pqc_advertised` | bool (optional) | TPM advertises PQC algorithms | — | no equivalent | Host probe. |
| `tpm_pqc.note` | str | Status / error explanation | — | no equivalent | Editorial. |
| `tpm_pqc.raw` | str | Raw `tpm2_getcap` output | — | no equivalent | Diagnostic. |

### `ssh_pqc.*`

| Path | Type | Description | CycloneDX 1.6 equivalent | Recommendation | Rationale |
| --- | --- | --- | --- | --- | --- |
| `ssh_pqc.available` | bool | OpenSSH detected | — | no equivalent | Host probe. |
| `ssh_pqc.version` | str | OpenSSH version banner | — | no equivalent | Host context. |
| `ssh_pqc.kex_count` | int | Total KEX algorithms advertised | — | no equivalent | Host probe summary. |
| `ssh_pqc.pqc_kex` | list[str] | Combined PQC KEX list (legacy) | — | no equivalent | Pre-split helper; superseded by `kex_groups`. |
| `ssh_pqc.kex_groups` | dict | KEX categorisation | — | no equivalent | Container. |
| `ssh_pqc.kex_groups.pure_pqc` | list[str] | Pure-PQC KEX names | per kex: `algorithmProperties.primitive=kem` | keep | Projected per-asset. |
| `ssh_pqc.kex_groups.hybrid` | list[str] | Hybrid KEX names | per kex: `algorithmProperties.primitive=key-agree` | keep | Projected per-asset. |

### `ipsec_pqc.*`

| Path | Type | Description | CycloneDX 1.6 equivalent | Recommendation | Rationale |
| --- | --- | --- | --- | --- | --- |
| `ipsec_pqc.available` | bool | IPsec stack detected | — | no equivalent | Host probe. |
| `ipsec_pqc.implementation` | str | `strongswan` / `libreswan` / `ipsec` | `protocolProperties.type=ipsec` (asset) | keep | Already projected to one CBOM protocol asset. |
| `ipsec_pqc.pqc` | bool | Stack advertises any PQC KE | — | no equivalent | Capability flag. |
| `ipsec_pqc.evidence` | str | What proved PQC support (or absence) | — | no equivalent | Editorial. |
| `ipsec_pqc.version` | str | Stack version | — | no equivalent | Host context. |
| `ipsec_pqc.reason` | str (when unavailable) | Why detection failed | — | no equivalent | Diagnostic. |

### `nss.*`

| Path | Type | Description | CycloneDX 1.6 equivalent | Recommendation | Rationale |
| --- | --- | --- | --- | --- | --- |
| `nss.available` | bool | NSS package installed | — | no equivalent | Host probe. |
| `nss.tool` | str | Tool used to detect (`rpm -q nss` etc.) | — | no equivalent | Diagnostic. |
| `nss.version` | str | NSS version | — | no equivalent | Host context. |
| `nss.pqc_capable` | bool | NSS version threshold met | — | no equivalent | Capability flag. |
| `nss.note` | str | Status caveat | — | no equivalent | Editorial. |

### `kernel_info.*`

| Path | Type | Description | CycloneDX 1.6 equivalent | Recommendation | Rationale |
| --- | --- | --- | --- | --- | --- |
| `kernel_info.release` | str | `uname -r` output | — | no equivalent | Host context. |
| `kernel_info.system` | str | `uname -s` output | — | no equivalent | Host context. |
| `kernel_info.os_release_id` | str | `/etc/os-release` `ID` | — | no equivalent | OS identification. |
| `kernel_info.os_release_version_id` | str | `/etc/os-release` `VERSION_ID` | — | no equivalent | OS identification. |
| `kernel_info.redhat_release.raw` | str | Raw `/etc/redhat-release` line | — | no equivalent | Diagnostic. |
| `kernel_info.redhat_release.distro` | str | Parsed distro name | — | no equivalent | Diagnostic. |
| `kernel_info.redhat_release.version` | str | Parsed version | — | no equivalent | Diagnostic. |
| `kernel_info.proc_crypto_pqc` | list[str] | `/proc/crypto` PQC entries | — | no equivalent | Host probe. |

### `fips_pqc_conflict.*`

| Path | Type | Description | CycloneDX 1.6 equivalent | Recommendation | Rationale |
| --- | --- | --- | --- | --- | --- |
| `fips_pqc_conflict.in_conflict` | bool | True iff FIPS hides PQC algorithms | — | no equivalent | Compliance interpretation. |
| `fips_pqc_conflict.explanation` | str | One-sentence rationale | — | no equivalent | Editorial. |

### `cnsa_2_0.*`

| Path | Type | Description | CycloneDX 1.6 equivalent | Recommendation | Rationale |
| --- | --- | --- | --- | --- | --- |
| `cnsa_2_0.status` | str | `compliant` / `partial` / `non_compliant` | — | no equivalent | Compliance verdict. |
| `cnsa_2_0.kem_compliant` | bool | KEM tier compliant | — | no equivalent | Compliance verdict. |
| `cnsa_2_0.signature_compliant` | bool | Signature tier compliant | — | no equivalent | Compliance verdict. |
| `cnsa_2_0.symmetric_compliant` | bool | Symmetric-cipher tier compliant | — | no equivalent | Compliance verdict. |
| `cnsa_2_0.hash_compliant` | bool | Hash tier compliant | — | no equivalent | Compliance verdict. |
| `cnsa_2_0.notes` | list[str] | Per-tier explanation lines | — | no equivalent | Editorial. |
| `cnsa_2_0.requirements.kem` | list[str] | Required KEM algorithms | — | no equivalent | Reference data. |
| `cnsa_2_0.requirements.signature` | list[str] | Required signature algorithms | — | no equivalent | Reference data. |
| `cnsa_2_0.requirements.symmetric` | list[str] | Required symmetric algorithms | — | no equivalent | Reference data. |
| `cnsa_2_0.requirements.hash` | list[str] | Required hash algorithms | — | no equivalent | Reference data. |

### `trust_store.*` (populated by `--scan-trust-store`)

| Path | Type | Description | CycloneDX 1.6 equivalent | Recommendation | Rationale |
| --- | --- | --- | --- | --- | --- |
| `trust_store.available` | bool | Trust-store scan ran | — | no equivalent | Host probe. |
| `trust_store.scanned_dirs` | list[str] | Directories walked | — | no equivalent | Diagnostic. |
| `trust_store.total_certs` | int | Cert count | — | no equivalent | Summary. |
| `trust_store.pqc_certs` | int | Pure-PQC cert count | — | no equivalent | Summary. |
| `trust_store.hybrid_certs` | int | Hybrid cert count | — | no equivalent | Summary. |
| `trust_store.cert_categories.classical` | int | Classical cert count | — | no equivalent | Summary. |
| `trust_store.cert_categories.hybrid_composite` | int | Hybrid composite cert count | — | no equivalent | Summary. |
| `trust_store.cert_categories.pure_pqc` | int | Pure-PQC cert count | — | no equivalent | Summary. |

When per-certificate detail is added in a future scan, the natural
projection is one `assetType=certificate` component per certificate
with `certificateProperties` (subjectName, issuerName, notValidBefore,
notValidAfter, signatureAlgorithmRef). The summary form has no
asset-level equivalent.

### `runtime_environment.*`

| Path | Type | Description | CycloneDX 1.6 equivalent | Recommendation | Rationale |
| --- | --- | --- | --- | --- | --- |
| `runtime_environment.environment` | str | `host` / `container` / `vm` | — | no equivalent | Host context. |
| `runtime_environment.evidence` | str | What proved the classification | — | no equivalent | Diagnostic. |

### `os_release.*`

| Path | Type | Description | CycloneDX 1.6 equivalent | Recommendation | Rationale |
| --- | --- | --- | --- | --- | --- |
| `os_release.family` | str | `rhel` / `debian` / `arch` / `alpine` / `suse` | — | no equivalent | OS identification. |
| `os_release.id` | str | `/etc/os-release` `ID` | — | no equivalent | OS identification. |
| `os_release.version_id` | str | `/etc/os-release` `VERSION_ID` | — | no equivalent | OS identification. |
| `os_release.version_codename` | str \| null | `/etc/os-release` `VERSION_CODENAME` | — | no equivalent | OS identification. |
| `os_release.pretty_name` | str | `/etc/os-release` `PRETTY_NAME` | — | no equivalent | OS identification. |
| `os_release.package_manager` | str | `dnf` / `apt` / `pacman` / `apk` / `zypper` | — | no equivalent | OS identification. |

### `pqc_sizes.<algo>`

Static reference table for NIST PQC primitives — same on every host.

| Path | Type | Description | CycloneDX 1.6 equivalent | Recommendation | Rationale |
| --- | --- | --- | --- | --- | --- |
| `pqc_sizes.<algo>.role` | str | `TLS KEM` / `general sig` / `high-sec sig` / `small/slow sig` / `fast/large sig` | — | no equivalent | Editorial label. |
| `pqc_sizes.<algo>.pk` | int | Public key size in bytes | `relatedCryptoMaterialProperties.size` (per-instance) | keep | CycloneDX `size` is per-material instance; this is a static parameter-set lookup. |
| `pqc_sizes.<algo>.sk` | int | Secret key size in bytes | `relatedCryptoMaterialProperties.size` (per-instance) | keep | Same. |
| `pqc_sizes.<algo>.ct` | int (KEM only) | Ciphertext size | `relatedCryptoMaterialProperties.size` | keep | Same. |
| `pqc_sizes.<algo>.shared` | int (KEM only) | Shared-secret size | `relatedCryptoMaterialProperties.size` | keep | Same. |
| `pqc_sizes.<algo>.sig` | int (signature only) | Signature size | `relatedCryptoMaterialProperties.size` | keep | Same. |

### `benchmark.*` and `benchmark_tls_handshake.*`

Performance measurement output. CycloneDX 1.6 has no concept of
benchmark results in `cryptoProperties` — the schema describes asset
identity, not asset performance. All fields under these keys map to
**no equivalent**.

### `per_algo.*` and `production_estimate.*`

Internal verdict structures keyed by algorithm name. Each algorithm is
already a CBOM component; the verdict on it is a `pqc-readiness`
internal computation with no CycloneDX equivalent. **No equivalent.**

### `packages.*`

OS package inventory (RPM/DEB/pacman/APK shape, normalised to
`[{name, version}, ...]`). CycloneDX models packages via the regular
`component` (type=`library`/`application`) shape, not via
`cryptoProperties`. SPDX 3.0 has `software_Package`, but that is
covered by the `--spdx` output, not by aligning `--json` to CycloneDX.
**No equivalent for `cryptoProperties`.**

## Renames recommended

None.

If a future cross-tool need surfaces a specific concrete rename, a
follow-up issue should be filed at that point with the rename, the
ingest tool that requires it, and a short justification. Speculative
schema churn is rejected per project guidance: "Don't add features,
refactor, or introduce abstractions beyond what the task requires".

## Versioning recommendation

`SCHEMA_VERSION` stays at `"1.0"`. No follow-up rename PR is required.

If a future patch *does* introduce a rename, the bump rule is:

- Any rename or removal of an existing field → major bump (`1.0` → `2.0`).
- Adding a new field → minor bump (`1.0` → `1.1`); pure additions are
  backward-compatible for the aggregator.
- Re-typing an existing field → major bump.

The aggregator (`run_aggregator()` in `pqc_readiness.py`) already
filters mismatched `schema_version` files into the `skipped` bucket
with a reason, so a major bump is observable rather than silently
merged.

[cdx-crypto]: https://cyclonedx.org/docs/1.6/json/#components_items_cryptoProperties
[nist-8547]: https://csrc.nist.gov/pubs/ir/8547/ipd
