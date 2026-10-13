# Inventory methodology

This document describes how `pqc-readiness` builds a cryptographic
inventory of a Linux host, how that inventory maps to the US federal
inventory data items, and what it does **not** collect. It is written so
that an agency or operator can cite it as "the methodology and automated
tools used for the cryptographic inventory", which OMB M-26-15 Appendix B
requires migration plans to describe.

Every standard and mandate cited here is labelled **final** or **draft**
with its source. Where a fact comes from secondary reporting rather than
the primary document, that is stated.

## Contents

- [What kind of tool this is](#what-kind-of-tool-this-is)
- [What is collected and how](#what-is-collected-and-how)
- [Capability versus in-use](#capability-versus-in-use)
- [Cadence and deployment](#cadence-and-deployment)
- [Fleet aggregation](#fleet-aggregation)
- [Mapping to OMB M-23-02 inventory items](#mapping-to-omb-m-23-02-inventory-items)
- [Mapping to OMB M-26-15 and EO 14412](#mapping-to-omb-m-26-15-and-eo-14412)
- [Standards status](#standards-status)
- [Known limitations](#known-limitations)

## What kind of tool this is

`pqc-readiness` is a **host-level capability and inventory scanner**. It
runs on the host, or in a container with the host's filesystem mounted.
It reads local state: CPU features, devices, kernel and library
configuration, the package database and the trust store. It does not
probe the network, read application source code, or parse build
manifests. Those are separate tool categories, described in
[scope.md](scope.md). A complete inventory under M-26-15 §6 combines this
tool's host view with network scanners, software composition analysis
and source-code scanning.

The tool is a single stdlib-only Python file. It needs no agent,
service account or outbound network access, and makes no changes to the
host.

## What is collected and how

Each JSON field is documented in [json-output.md](json-output.md). The
table groups them by what is being inventoried.

| Category | JSON fields | How it is collected |
|---|---|---|
| Host identity | `hostname`, `os`, `os_release`, `arch`, `kernel_info`, `runtime_environment` | `/etc/os-release` (family-aware), `uname`, `/proc` markers that distinguish bare metal, VM and container |
| CPU and memory | `cpu_model`, `cpu_freq_mhz`, `cores_*`, `isa_features`, `isa_score`, `isa_tier`, `mem_*`, `memory` | `/proc/cpuinfo` flags (x86 AVX-512 family, ARMv8 crypto extensions, s390x CPACF), `/proc/meminfo` |
| Crypto hardware | `accelerators`, `pkcs11_modules`, `tpm_pqc`, `hsm_present_but_not_pqc`, `kernel_crypto_hw` | PCI device catalogue, PKCS#11 module paths, TPM tooling, network HSM client configuration files, s390x Crypto Express listing, `/proc/crypto` drivers |
| Crypto libraries and protocols | `openssl`, `ssh_pqc`, `ipsec_pqc`, `nss`, `ktls_supported` | The OpenSSL CLI's algorithm, TLS group and provider lists; the SSH client's key-exchange list; IPsec stack versions; the NSS version; the kernel TLS module |
| FIPS posture | `fips`, `fips_pqc_conflict` | Kernel FIPS flag, OpenSSL FIPS provider state, and the [algorithm-fence check](findings/fips-algorithm-fence.md) |
| Policy evaluation | `cnsa_2_0` | The collected algorithm lists evaluated against NSA CNSA 2.0 |
| Trust store (`--scan-trust-store`) | `trust_store` | Every certificate in the system trust-store directories, bundle files included, de-duplicated by SHA-256 of the DER encoding and classified as classical, PQC or composite from the signature and public-key algorithm OIDs |
| Packages (`--scan-packages`) | `packages` | The package database read in-process (rpm SQLite, Berkeley DB and ndb formats; dpkg), with crypto-bearing packages flagged from a per-family catalogue; `rpm`/`dpkg-query` as a fallback |
| Performance (`--bench`, `--bench-tls`) | `benchmark`, `benchmark_tls_handshake`, `memory_bandwidth_*`, `per_algo`, `production_estimate` | OpenSSL primitive microbenchmarks and a loopback TLS 1.3 handshake benchmark (classical, hybrid and PQC groups) |
| Verdict | `verdict`, `verdict_reason`, `verdict_caveat`, `replace_required`, `exit_code` | Derived from the fields above |

Container deployments read the host through `--host-mount`.
`host_fs_detections_unavailable` lists every detection that could not
see the host, so a container's own state is never reported as the
host's.

No private key material is read or emitted. The trust-store scan reads
certificates only.

## Capability versus in-use

The inventory answers **what this host can do**: which PQC algorithms and
TLS groups its libraries provide, whether its hardware can run them at
production speed, and whether FIPS mode would block them. It does **not**
yet report what each service on the host is configured to negotiate, or
what it actually negotiates on the wire.

This matters for M-23-02 item 4, which asks for cryptographic systems
"actively used", including legacy fallback. A host whose OpenSSL offers
X25519MLKEM768 may still run a service that is configured for classical
key exchange only. Until the configuration detections land (system crypto
policy #104, sshd #105, OpenSSL configuration #106) together with the
capability-versus-configuration verdict (#107), treat this tool's output
as the **capability** half of the inventory. The in-use half comes from
network scanning and configuration review.

## Cadence and deployment

| Mode | Cadence | Output |
|---|---|---|
| CLI | On demand | stdout, or `--output FILE` |
| Podman quadlet (`deploy/quadlet/`) | Daily systemd timer (`OnCalendar=daily`, 5-minute randomized delay) | `--save` JSON to the cache directory |
| OpenShift DaemonSet (`deploy/openshift/`) | Every `PQC_PROBE_INTERVAL` seconds (default 3600) on every node | `--save` JSON to a host path or PVC for aggregation |
| Ansible (`deploy/ansible/`) | Per play run | `--ansible` facts under `ansible_facts.pqc_readiness`, plus a fleet aggregation playbook |

Reports are timestamped (`generated_at`) and versioned
(`schema_version`), so a series of runs forms the continuously updated
inventory that M-26-15 §6 describes.

## Fleet aggregation

`--aggregate DIR` reads every per-host JSON report in a directory and
produces a fleet rollup as JSON or CSV. Reports with a different
`schema_version` are listed under `skipped` and never merged, so a
rollup never mixes results from different scanner versions. The same
per-host data can be emitted as a CycloneDX CBOM (`--cbom`), SPDX 3.0
(`--spdx`) or SARIF findings (`--sarif`) for downstream inventory,
software-bill-of-materials and findings pipelines.

## Mapping to OMB M-23-02 inventory items

OMB M-23-02 (18 Nov 2022, **in force**; not rescinded by M-26-15) lists
nine data items per system
([M-23-02](https://bidenwhitehouse.archives.gov/wp-content/uploads/2022/11/M-23-02-M-Memo-on-Migrating-to-Post-Quantum-Cryptography.pdf)).
CISA's *Strategy for Migrating to Automated PQC Discovery and Inventory
Tools* (15 Aug 2024) states that only items 4, 5 and 6 can be collected
automatically
([CISA strategy](https://cisa.gov/sites/default/files/2024-09/Strategy-for-Migrating-to-Automated-PQC-Discovery-and-Inventory-Tools.pdf)).
The other six are organisational facts that no host scanner can see.

| # | M-23-02 item | Collected? | Where | Notes |
|---|---|---|---|---|
| 1 | FISMA system ID | **No** | — | Organisational; not visible on the host. An operator metadata file is planned (#144). |
| 2 | FIPS 199 categorisation | **No** | — | Organisational. Planned in #144. |
| 3 | High Value Asset ID | **No** | — | Organisational. Planned in #144. |
| 4 | Each CRQC-vulnerable cryptographic system actively used: algorithm, service provided, key or module length | **Partly** | `openssl`, `ssh_pqc`, `ipsec_pqc`, `nss`, `trust_store`, `cnsa_2_0`; CBOM algorithm assets | Algorithms and key sizes the host's libraries **provide**, and the algorithms of trusted certificates. Not yet which service **uses** which algorithm, or any legacy fallback in use; see [Capability versus in-use](#capability-versus-in-use). Classifying each asset as key establishment or signature is planned (#144). |
| 5 | COTS / GOTS / other, with vendor | **Partly** | `packages.bundled_crypto` (with `--scan-packages`) | Crypto-bearing distribution packages, with name and version. No COTS/GOTS/custom classification, and no software installed outside the package manager. |
| 6 | Operating system with major/minor version | **Yes** | `os_release` (`id`, `version_id`, `pretty_name`), `kernel_info` | |
| 7 | Hosting: on-premises, commercial CSP, government CSP, hybrid | **No** | — | `runtime_environment` says bare metal, VM or container, but not who hosts it. Planned in #144. |
| 8 | Data lifecycle: records category and time to live | **No** | — | Organisational. Planned in #144. |
| 9 | Notes | — | `verdict_reason`, `verdict_caveat` | Free-text context for the verdict. |

## Mapping to OMB M-26-15 and EO 14412

**Executive Order 14412**, *Securing the Nation Against Advanced
Cryptographic Attacks* (22 Jun 2026; Federal Register doc 2026-12909),
**in force**
([White House](https://www.whitehouse.gov/presidential-actions/2026/06/securing-the-nation-against-advanced-cryptographic-attacks/),
[Federal Register](https://public-inspection.federalregister.gov/2026-12909.pdf)).
Some sources number it 14409; the Federal Register numbers it 14412.
§5(d) directs CISA and NIST to publish **minimum elements for a
cryptographic bill of materials** within 270 days, around March 2027.
That guidance had not been published when this document was written.
The CBOM output will be mapped to it when it is (#150). Until then,
`--cbom` follows the CycloneDX cryptographic-asset model.

**OMB M-26-15**, *Execution of the Migration to Post-Quantum
Cryptography* (24 Jun 2026), **in force**
([M-26-15](https://www.whitehouse.gov/wp-content/uploads/2026/06/M-26-15-Execution-of-the-Migration-to-Post-Quantum-Cryptography.pdf)):

| M-26-15 requirement | How this tool contributes |
|---|---|
| §6: a continuously updated, automated inventory feeding a central CBOM | Scheduled runs (quadlet, DaemonSet, Ansible), schema-versioned JSON, `--cbom` output, fleet aggregation |
| PQC key establishment for high-value and high-impact systems by 31 Dec 2030 | Reports whether each host **can** do PQC key establishment (OpenSSL KEMs and hybrid TLS groups, SSH key exchange) and at what speed |
| PQC signatures by 31 Dec 2031 | Reports PQC signature availability and benchmark rates, and PQC or composite certificates in the trust store |
| TLS 1.3 by 2 Jan 2030 | Not yet reported as a dedicated finding; planned in #144 |
| Appendix A: treat unknown asymmetric algorithms as vulnerable | The trust-store scan classifies any certificate without a recognised PQC or composite OID as classical |
| Appendix B: describe the inventory methodology and tools | This document |
| Align with NIST IR 8547 "or successor document" | IR 8547 is still a **draft**; see below |

M-26-15 does not apply to National Security Systems. For those systems,
`cnsa_2_0` evaluates the host against NSA CNSA 2.0.

## Standards status

| Document | Status | Source |
|---|---|---|
| FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA) | **Final** (Aug 2024) | [NIST CSRC](https://csrc.nist.gov/projects/post-quantum-cryptography) |
| FIPS 206 (FN-DSA) | **Draft**, not yet final | Secondary reporting; no final NIST page found |
| NIST SP 800-227, Recommendations for KEMs | **Final** (18 Sep 2025) | [NIST](https://csrc.nist.gov/News/2025/nist-publishes-sp-800-227) |
| NIST IR 8547, Transition to PQC Standards | **Initial public draft** (12 Nov 2024) | [NIST CSRC](https://csrc.nist.gov/pubs/ir/8547/ipd) |
| HQC (additional KEM) | Selected 11 Mar 2025; **no published FIPS** | [NIST PQC news](https://csrc.nist.gov/projects/post-quantum-cryptography/news) |
| OMB M-23-02 | **In force** (18 Nov 2022) | [M-23-02](https://bidenwhitehouse.archives.gov/wp-content/uploads/2022/11/M-23-02-M-Memo-on-Migrating-to-Post-Quantum-Cryptography.pdf) |
| OMB M-26-15 | **In force** (24 Jun 2026) | [M-26-15](https://www.whitehouse.gov/wp-content/uploads/2026/06/M-26-15-Execution-of-the-Migration-to-Post-Quantum-Cryptography.pdf) |
| EO 14412 | **In force** (22 Jun 2026); CBOM minimum elements **not yet published** | [White House](https://www.whitehouse.gov/presidential-actions/2026/06/securing-the-nation-against-advanced-cryptographic-attacks/) |
| CISA automated discovery strategy | **Published** (15 Aug 2024) | [CISA](https://cisa.gov/sites/default/files/2024-09/Strategy-for-Migrating-to-Automated-PQC-Discovery-and-Inventory-Tools.pdf) |
| NSA CNSA 2.0 | **In force**; latest FAQ found is v2.1 (Dec 2024) | [NSA CNSA 2.0 FAQ](https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/1/CSI_CNSA_2.0_FAQ_.PDF) |
| CycloneDX cryptographic assets (CBOM) | 1.6 emitted today; 1.7 **final** (Oct 2025) and planned (#138) | [CycloneDX](https://cyclonedx.org/capabilities/cbom/) |

Statuses are as of October 2026. Check the sources before relying on
them, since drafts in this list are expected to change.

## Known limitations

- **Capability, not use.** See [above](#capability-versus-in-use). Service
  configuration and observed negotiation are planned (#104–#107).
- **Organisational items.** M-23-02 items 1, 2, 3, 7 and 8 need operator
  input (#144).
- **Python prerequisite.** The scanner needs Python 3.9 or newer. Stock
  RHEL/Rocky/AlmaLinux 8 cloud images and stock SLES/openSUSE Leap 15
  images ship only Python 3.6, so the scanner exits 127 until a newer
  interpreter is installed. See the README's distribution notes and #127.
- **Validated platforms.** The README's
  [What's new](../README.md#whats-new) section lists the cloud images on
  which the scanner and its package-database reader were validated by
  booting them under KVM.
- **Host scope only.** Network endpoints, source code, build
  dependencies and cloud key-management services are out of scope for
  this tool; see [scope.md](scope.md) for the adjacent tool categories.
- **Keys and certificates outside the trust store** (service certificates,
  key files, Java keystores) are not yet inventoried (#108).
