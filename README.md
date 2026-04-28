# pqc-readiness

Host-level Post-Quantum Cryptography readiness assessment.

`pqc-readiness` inspects a host and reports whether it can run NIST PQC
primitives (ML-KEM, ML-DSA, SLH-DSA) at production speed in software, or
whether it requires a dedicated cryptographic accelerator. Output is a
stable JSON schema designed for fleet inventory aggregation.

## Scope

`pqc-readiness` is a host-level capability and inventory scanner. It
sits alongside — not in place of — network-level TLS analyzers,
source-code cryptographic scanners, dependency-scoped scanners, and
TLS-handshake benchmarking harnesses. See [`docs/scope.md`](docs/scope.md)
for how each category composes with this project's CBOM, SARIF, and
SPDX output.

## Audience

Field architects and customer infrastructure teams. The tool is intended
for use during regulated-environment PQC migration engagements. It runs
on bare metal Linux, in containers (podman/quadlet), and as a privileged
DaemonSet on OpenShift.

## What it detects

1. **CPU instruction-set support for PQC** — AVX-512 family (VBMI/IFMA/
   VAES/GFNI) on x86_64; ARMv8 crypto extensions (SHA-3, SVE2, I8MM) on
   aarch64; CPACF MSA8/MSA9 and Crypto Express level on s390x.
2. **Cryptographic accelerators** — PCI HSMs (Marvell, Thales Luna,
   Utimaco, IBM CEX), DPUs (BlueField, IPU, Pensando), TPMs, network
   HSMs detected by client config, AWS Nitro, Intel QAT.
3. **OS / library plumbing** — `/proc/crypto` hardware drivers, kernel
   TLS, kernel FIPS mode, OpenSSL ≥ 3.5 PQC algorithms and TLS 1.3
   hybrid groups, OpenSSH `ssh -Q kex`, strongSwan / Libreswan, NSS.
4. **Production suitability** — per-algorithm tier with measured
   throughput, host capacity estimate, and a top-level `replace_required`
   flag for fleet planning.

## Quick start

```bash
./pqc_readiness.py                    # human-readable report
./pqc_readiness.py --bench            # include OpenSSL microbench
./pqc_readiness.py --json             # stable JSON for aggregation
./pqc_readiness.py --cbom             # CycloneDX 1.6 CBOM JSON (NIST IR 8547)
./pqc_readiness.py --sarif            # SARIF 2.1.0 findings (OASIS)
./pqc_readiness.py --markdown         # markdown for tickets
./pqc_readiness.py --recommend        # policy-aware algorithm recommendation
./pqc_readiness.py --ansible          # ansible_facts wrapper
./pqc_readiness.py --aggregate ./out  # roll up many --save outputs
./pqc_readiness.py --version          # script + JSON schema versions
```

## Flags

Every flag listed by `./pqc_readiness.py --help` is documented below.
The list is grouped by purpose; the `--help` text remains the
authoritative one-line summary.

### Output format

| Flag | Purpose |
| --- | --- |
| `--json` | Emit the stable JSON schema (see [JSON output](#json-output---json)). |
| `--markdown` | Emit a markdown report suitable for pasting into a ticket. |
| `--cbom` | Emit a CycloneDX 1.6 Cryptographic Bill of Materials (see [CBOM output](#cbom-output---cbom)). |
| `--sarif` | Emit SARIF 2.1.0 findings for security pipelines (see [SARIF output](#sarif-output---sarif)). |
| `--ansible` | Wrap the JSON schema in `{ansible_facts: {pqc_readiness: ...}}` and exit 0. Intended for `ansible.builtin.set_fact`. |

`--json`, `--cbom`, and `--sarif` are mutually exclusive views over the
same probe run. The default (no flag) is the human-readable text
report.

### Benchmarking

| Flag | Purpose |
| --- | --- |
| `--bench` | Run the PQC + classical OpenSSL microbenchmark and include results in the output. |
| `--bench-tls` | Run a loopback TLS 1.3 handshake benchmark covering classical, hybrid, and pure-PQC groups. |
| `--threads N` | Add an N-way scaling test alongside the single-thread benchmark. |
| `--seconds N` | Override the per-operation benchmark duration. Larger values reduce variance at the cost of run time. |

Benchmark results land under the `benchmark` and
`benchmark_tls_handshake` top-level JSON keys. Without `--bench` /
`--bench-tls`, those keys are still present but empty.

### Recommendation engine

| Flag | Purpose |
| --- | --- |
| `--recommend` | Emit a host-specific PQC algorithm recommendation under the selected policy and role, instead of the readiness report. |
| `--policy {cnsa-2.0,nist-civilian,eu-anssi-bsi,commercial,auto}` | Compliance context for `--recommend`. `auto` (default) emits all policies side by side. |
| `--role {tls-server,tls-client,signing-service,firmware-signing}` | Role for `--recommend`. Only `tls-server` is fully implemented; other roles return a stub response. |

The full policy-to-preference mapping, the issuing authority for each
policy, and the source documents are catalogued in
[`docs/recommendation-policies.md`](docs/recommendation-policies.md).
Updating a policy is a single-place edit in the `POLICY_PREFERENCES`
table inside `pqc_readiness.py`; the engine itself does not change.

`--recommend` combines with `--json` to produce a machine-readable
recommendation document with top-level keys `role`, `mode`, `hostname`,
`generated_at`, and `recommendations`. This is a different schema from
the readiness `--json`; see [JSON output](#json-output---json).

### Inventory and host probes

| Flag | Purpose |
| --- | --- |
| `--scan-trust-store` | Walk system trust-store directories and count PQC / hybrid certificates. Slower than the default probe; opt in when an inventory of the trust anchors is needed. |
| `--scan-packages` | Enumerate installed packages with bundled crypto. Branches on family: `rpm -qa` (rhel/suse), `dpkg-query -W` (debian), `pacman -Q` (arch), `apk info -v` (alpine). All four parsers normalise to the same `[{name, version}, ...]` shape. |
| `--host-mount PATH` | Prefix for `/proc /sys /dev /etc` reads. Used by the OpenShift DaemonSet pattern: the host filesystem is mounted at `/host` inside the container, and `--host-mount /host` makes the probe inspect the node, not the container. |

Without these flags the probe stays in the fast path and skips the
trust-store walk and the package enumeration.

### Verbosity, gating, and persistence

| Flag | Purpose |
| --- | --- |
| `--check {excellent,good,marginal,poor,cnsa-2.0}` | Exit 4 if the verdict is below the named tier, or if `cnsa-2.0` is selected and the host is not CNSA 2.0 compliant. Designed for CI gating. |
| `--save` | Write JSON to `~/.cache/pqc-readiness/`. The fleet aggregation path reads exactly this directory layout. |
| `--quiet` | Print only the verdict line (e.g. `EXCELLENT - software PQC at production speed`). |
| `--no-color` | Disable ANSI colour in human-readable output. Auto-disabled when stdout is not a TTY. |

### Aggregation

| Flag | Purpose |
| --- | --- |
| `--aggregate DIR` | Aggregate every `*.json` in `DIR` into a fleet rollup; the program exits when done and ignores all other flags. |
| `--aggregate-format {json,csv}` | Output format for `--aggregate` (default `json`). |

See the [Aggregation](#aggregation-1) section for the rollup schema.

### Miscellaneous

| Flag | Purpose |
| --- | --- |
| `--version` | Print the script version and the JSON schema version, then exit. |
| `-h`, `--help` | Print the help text and exit. |

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Excellent — dedicated PQC silicon OR optimized SIMD + ample RAM. |
| 1 | Good — software PQC fast enough for production. |
| 2 | Marginal — works, but plan for an accelerator at scale. |
| 3 | Poor — software-only and too slow for production. |
| 4 | `--check` threshold not met (TIER below floor, or `cnsa-2.0` not compliant). |

## JSON output (`--json`)

`--json` emits a stable, schema-versioned document. The `schema_version`
key changes only when fields are renamed or removed; additive changes
keep the same version. Aggregation refuses to merge files whose
`schema_version` does not match the rollup version.

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
| `ssh_pqc` | OpenSSH `ssh -Q kex` PQC / hybrid kex availability. |
| `ipsec_pqc` | strongSwan / Libreswan PQC and hybrid IKE state. |
| `nss` | NSS PQC algorithm exposure. |
| `kernel_info` | Kernel version, build flags relevant to crypto, and module list. |
| `fips_pqc_conflict` | Detected when kernel FIPS is on but PQC is exposed only via a non-FIPS provider. |
| `cnsa_2_0` | CNSA 2.0 compliance summary (algorithm coverage, hash, FIPS state). |
| `trust_store` | Trust-store summary (count, PQC-capable count, hybrid count). Populated only when `--scan-trust-store` is set. |
| `runtime_environment` | How the probe is running (bare metal, container, DaemonSet, …). |
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
| `exit_code` | Numeric exit code the program will return. Mirrors the [Exit codes](#exit-codes) table. |

`--ansible` returns a single top-level key `ansible_facts`, whose value
is `{pqc_readiness: {…the schema above…}}`.

`--recommend --json` returns a different document with top-level keys
`role`, `mode`, `hostname`, `generated_at`, and `recommendations`. The
`recommendations` list contains one object per evaluated policy with
`policy`, `authority`, `kem`, `signature`, `hash`, `policy_basis`,
`source`, and `caveats`.

## CBOM output (`--cbom`)

`--cbom` emits a [CycloneDX 1.6](https://cyclonedx.org/docs/1.6/json/)
Cryptographic Bill of Materials. Each detected source — ISA features,
accelerators / HSMs / TPMs, OpenSSL KEM and signature algorithms,
OpenSSL TLS hybrid and pure-PQC groups, OpenSSH PQC kex, IPsec
implementation, PKCS#11 modules, and the trust-store summary — becomes
a `cryptographic-asset` component with the appropriate `assetType`,
`algorithmProperties` (or `protocolProperties` /
`relatedCryptoMaterialProperties`) where applicable, and a `detectedBy:
pqc-readiness@<version>` provenance property.

The output validates against the official CycloneDX 1.6 JSON schema and
is suitable for ingest by any CBOM-aware tooling. NIST IR 8547
([final](https://csrc.nist.gov/pubs/ir/8547/final)) references CycloneDX
1.6 as the standard exchange format for cryptographic inventory.

The existing `--json` output is unchanged; the two formats can be
emitted side by side from the same probe run.

## SARIF output (`--sarif`)

`--sarif` emits [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
findings (OASIS standard) so the readiness signal can be consumed by
the same security pipelines that already ingest SARIF from other
scanners. Each finding is a rule with a stable id (`pqc-001-…`,
`pqc-002-…`, …), a short and full description, a `helpUri` pointing at
`docs/rules/<rule-id>.md`, and a default severity level
(`warning` / `error`).

Findings cover, among others:

- OpenSSL older than 3.5 (no native PQC).
- Kernel FIPS mode active but PQC is exposed via a non-FIPS provider.
- Hybrid TLS groups missing from the OpenSSL build.
- HSM present but not advertising PQC primitives.

The SARIF document validates against the official SARIF 2.1.0 JSON
schema. As with `--cbom`, the `--json` schema is unchanged; SARIF is a
projection over the same probe run.

## Distribution support

The script targets one JSON schema across every Linux it runs on. Tiers
below describe **what is validated**, not what carries a support
contract — “validated on” here means the script runs cleanly and the
schema matches in CI or in maintainer testing.

| Tier | Distros | Validation cadence |
| --- | --- | --- |
| **1** | RHEL 9, RHEL 10, Ubuntu 24.04 LTS, Debian 12 | Every change (CI) |
| **2** | Fedora (latest), Rocky / AlmaLinux 9 and 10, Ubuntu 25.10, Debian 13, SLES 15 SP6+ | Periodic (weekly) — fixes accepted |
| **3** | Arch, Alpine, others | Best-effort, community-supported |

`detect_os()` resolves `family` from `/etc/os-release` `ID` and falls
back through `ID_LIKE`, so derivatives the explicit table doesn’t name
(Linux Mint → debian, Manjaro → arch, etc.) still classify correctly.
The `--scan-packages` path branches on family: `rpm -qa` (rhel/suse),
`dpkg-query -W` (debian), `pacman -Q` (arch), `apk info -v` (alpine).
All four parsers normalise to the same `[{name, version}, ...]` shape.

PQC primitives require OpenSSL **≥ 3.5**. The tool runs on older
OpenSSL builds — it just reports `openssl.pqc_native: false` and the
verdict gains a “no-bench” caveat. `openssl.upgrade_path` is a
family-aware string suggesting how to get a PQC-capable OpenSSL on the
specific host.

Out of scope for this tool: Windows / WSL, BSD, musl-specific behaviour
beyond Alpine. macOS support is best-effort and limited to the paths
already in the script.

## Container / OpenShift

Two Containerfiles are provided:

- `Containerfile.ubi10` — Red Hat UBI 10 minimal base. Default for
  RHEL/Fedora fleets and the image referenced by the systemd quadlet.
- `Containerfile.debian` — `debian:12-slim` base. Functionally
  identical (same script, flags, JSON schema, UID 1001, healthcheck).
  Use for Debian/Ubuntu fleets.
- `Containerfile.ubuntu-fips` — stub. Pending an Ubuntu Pro FIPS
  customer ask.

```bash
make container-ubi10     # build the UBI image
make container-debian    # build the Debian image
make container           # build both
```

`deploy/quadlet/pqc-readiness.container` is a systemd quadlet that runs
the probe daily against the host. `deploy/openshift/daemonset.yaml` is
the fleet DaemonSet — non-root UID 1001, hostPID, custom SCC dropping
all capabilities, read-only host bind mounts of `/proc /sys /dev /etc
/usr/lib/os-release`. Inside the DaemonSet the host root is mounted at
`/host`, and the probe is invoked with `--host-mount /host` so its
reads target the node, not the container image.

## Aggregation

`--aggregate DIR` reads every `*.json` produced by `--save` (or by the
DaemonSet output volume) and emits a fleet rollup: counts by arch, OS,
ISA tier, verdict, runtime environment, and accelerator kind, plus the
list of unique CPU models and a `replace_required_count`.

```bash
pqc_readiness.py --aggregate /var/lib/pqc-readiness                       # JSON
pqc_readiness.py --aggregate /var/lib/pqc-readiness --aggregate-format csv  # CSV
```

Files with mismatched `schema_version` are listed under `skipped` with
a reason rather than silently merged.

## Documentation map

- [`docs/scope.md`](docs/scope.md) — where this project fits in the
  wider PQC tooling ecosystem; how host-level scanning composes with
  network, source-code, dependency, and TLS-handshake categories.
- [`docs/recommendation-policies.md`](docs/recommendation-policies.md) —
  authority, source documents, and engine-encoded position for every
  policy reachable through `--policy`.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — third-party product reference
  policy and the rule that keeps this README in sync with `--help`.

## License

Apache-2.0. See `LICENSE`.
