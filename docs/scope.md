# Scope

This document explains where `pqc-readiness` fits in the wider Post-Quantum
Cryptography (PQC) tooling ecosystem. It describes the categories of PQC
tooling by what they inspect — not by product — and notes how this
project's output composes with each category through standard schemas
(CycloneDX CBOM, OASIS SARIF, SPDX).

The categories below are defined by their inspection target: the host,
the network, the source tree, the dependency manifest, or the TLS
handshake. A complete migration programme typically draws on more than
one of these; they are complementary, not competing.

## Where this project fits

`pqc-readiness` is a **host-level capability and inventory scanner**. It
runs on a Linux host and answers a single question: *can this host run
NIST PQC primitives at production speed in software, or does it need a
dedicated cryptographic accelerator?* It inspects CPU instruction-set
support (AVX-512 family on x86_64, ARMv8 crypto extensions on aarch64,
CPACF / Crypto Express on s390x), attached cryptographic accelerators
(HSMs, DPUs, TPMs, CPU offload engines), kernel and OS crypto plumbing
(`/proc/crypto`, kernel TLS, FIPS mode), and library versions
(OpenSSL ≥ 3.5 PQC algorithms, OpenSSH `ssh -Q kex`, IPsec stacks, NSS,
GnuTLS, libgcrypt, libssh, wolfSSL, AWS-LC, Mbed TLS, JDKs and Go toolchains).

With the opt-in `--scan-*` flags it also inventories the host's
cryptographic material and trust anchors: installed packages, trust-store
and on-disk certificates, private-key metadata, package-signing keys, the
boot chain (Secure Boot, module signing, IMA, TPM), Kerberos encryption
types, WireGuard and OpenVPN configuration, DNSSEC signing algorithms,
and which crypto library each listening service and running process
actually maps.

It also answers a second question at host level: *is that capability
actually configured?* For TLS, SSH and IPsec, and for every listening
service it can attribute, it reports whether PQC is deployed, capable but
not configured, configured but not capable, or not capable at all
(`pqc_deployment_gap`, #107). That verdict comes from what the host
already exposes (library capability, the system crypto policy, OpenSSL's
default groups, sshd's effective configuration, configured IKE
proposals), with no network traffic. Anything found that will fail or
stay classical in a PQC migration is reported as a SARIF / NDJSON finding
under a stable rule ID ([rules index](rules/README.md)).

It does not probe network endpoints, parse application source code, or
read dependency manifests, and its TLS benchmark is a loopback
measurement rather than an end-to-end one. Those are separate categories
with separate tools, described below.

## Categories of PQC tooling

### 1. Host-level capability and inventory scanners

**Inspects:** the host — CPU ISA, cryptographic accelerators (HSMs,
DPUs, TPMs, on-package offload engines), OS crypto plumbing, installed
library versions and the algorithms they expose.

**Typical output formats:** structured JSON inventory, CycloneDX
cryptographic-assets CBOM (1.7, or 1.6), SPDX 3.0, SARIF findings, OCSF
NDJSON events, Prometheus metrics, Ansible facts, fleet rollups (CSV / JSON).

**How this project's output composes:** this is the category
`pqc-readiness` occupies. Per-host JSON aggregates into a fleet rollup
and emits a CBOM describing the cryptographic capability of
each host. That CBOM is the canonical input the other categories below
combine with.

### 2. Network-level TLS analyzers

**Inspects:** running TLS endpoints over the wire — the cipher suites,
key-exchange groups (including hybrid PQC groups), and certificate
chains a server actually negotiates.

**Typical output formats:** per-endpoint JSON or CSV reports, sometimes
SARIF for findings-style consumption, occasionally CBOM entries for
endpoint-observed algorithms.

**How this project's output composes:** complementary, not overlapping.
A host-level scan tells you which PQC algorithms a server *can*
negotiate given its CPU, accelerators, and library versions; a
network-level scan tells you which algorithms it *does* negotiate on a
given listener. The capable and configured half of that comparison is
now computed on the host itself (`pqc_deployment_gap`). The third state,
what an endpoint was *observed* to negotiate, still needs the network
view: the fleet aggregator joins endpoint-observation records produced by
tools in this category, keyed by FQDN, port and SNI, to each host's
listeners and verdict (`--aggregate DIR --observations FILE`; record
format in [endpoint-observations.md](endpoint-observations.md)). A
`deployed` endpoint observed negotiating classical key exchange, for
example, points at a client or an intermediary rather than the host.

### 3. Source-code cryptographic scanners

**Inspects:** application and library source code for direct use of
cryptographic APIs — calls to `EVP_*`, `RSA_*`, `ECDSA_*`, key
generation, signing and verification, hardcoded curve and key-size
constants.

**Typical output formats:** SARIF (the OASIS standard exchange format
for code-scanning findings) is the dominant interchange format, plus
tool-specific JSON.

**How this project's output composes:** complementary. Source scanners
produce findings against a code repository; this project produces
inventory against a deployment host. The two intersect at runtime: a
SARIF finding "RSA-2048 used in `auth/sign.go:142`" is more or less
actionable depending on whether the host that runs it can negotiate a
PQC replacement (host CBOM) and whether its TLS endpoint already does
(network analyzer). `pqc-readiness --sarif` emits its host findings in
the same SARIF format, so both kinds of finding can land in one
code-scanning or vulnerability-management pipeline
([recipe](sarif-code-scanning.md)).

### 4. Dependency-scoped scanners

**Inspects:** package manifests and lockfiles — `requirements.txt`,
`go.mod`, `Cargo.lock`, `package-lock.json`, RPM / Deb / Wheel
manifests — to identify cryptographic libraries and their versions
declared as build- or runtime dependencies.

**Typical output formats:** CycloneDX SBOM (with cryptographic-asset
extensions in 1.6), SPDX 3.0 (including the new Security profile),
tool-specific JSON.

**How this project's output composes:** complementary. A dependency
scanner answers *what crypto library version is declared in this
build*; `pqc-readiness` answers *what crypto library version is
installed on this host and what algorithms it actually exposes*. Build-
time dependency declarations and runtime host inventory diverge
routinely — a build may declare OpenSSL 3.0 while the host has
OpenSSL 3.5 available — and reconciling the two is a common migration
task. The CBOM and SPDX 3.0 Security profile outputs
from this project share an algorithm-naming vocabulary with
dependency-scoped CBOMs / SBOMs, so the two artefacts merge cleanly.

### 5. TLS-handshake benchmarking harnesses

**Inspects:** the cost of a full TLS handshake using PQC or hybrid PQC
key-exchange groups under controlled conditions — handshake duration,
bytes on the wire, CPU cycles, throughput at saturation.

**Typical output formats:** time-series CSV / JSON of measurement runs,
occasionally CBOM entries annotated with measured cost figures, and
narrative reports with statistical summaries.

**How this project's output composes:** complementary. `pqc-readiness`
includes an OpenSSL microbench (`--bench`) for primitive-level
throughput per host, which drives the *capability tier* verdict, and a
loopback TLS 1.3 handshake benchmark (`--bench-tls`) that compares
classical, hybrid and pure-PQC groups on the same host. Neither
measures handshake cost across a real network path, with real
certificate chains and intermediaries. A dedicated harness measures that
and can be parameterised by the host capability profile this project
produces, so that handshake measurements are attributable to known host
hardware and library configurations.

## Field-level interoperability

The category descriptions above explain how artefacts compose at the
*tool* level — CBOM out of one tool flows into the input of another,
SARIF out of one is consumed by another. Field-level interoperability
— matching algorithm names, key-size encodings, and risk-level
vocabularies across CycloneDX cryptographic-assets and NIST IR 8547
— is documented field by field in [schema-alignment.md](schema-alignment.md).

## References

- NIST IR 8547 (IPD) — Transition to Post-Quantum Cryptography Standards: <https://csrc.nist.gov/pubs/ir/8547/ipd>
- CycloneDX 1.7 and 1.6 JSON schemas (cryptographic assets): <https://cyclonedx.org/docs/1.7/json/>, <https://cyclonedx.org/docs/1.6/json/>
- OASIS SARIF 2.1.0: <https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html>
- SPDX 3.0.1 specification: <https://spdx.github.io/spdx-spec/v3.0.1/>
- NIST FIPS 203 / 204 / 205 (ML-KEM, ML-DSA, SLH-DSA)
- IETF TLS hybrid key-exchange drafts and related RFCs
