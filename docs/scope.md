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
(OpenSSL ≥ 3.5 PQC algorithms, OpenSSH `ssh -Q kex`, IPsec stacks, NSS).

It does not probe network endpoints, parse application source code, read
dependency manifests, or measure TLS handshake cost end-to-end. Those
are separate categories with separate tools, described below.

## Categories of PQC tooling

### 1. Host-level capability and inventory scanners

**Inspects:** the host — CPU ISA, cryptographic accelerators (HSMs,
DPUs, TPMs, on-package offload engines), OS crypto plumbing, installed
library versions and the algorithms they expose.

**Typical output formats:** structured JSON inventory, CycloneDX 1.6
cryptographic-assets CBOM, Ansible facts, fleet rollups (CSV / JSON).

**How this project's output composes:** this is the category
`pqc-readiness` occupies. Per-host JSON aggregates into a fleet rollup
and emits a CBOM (issue #5) describing the cryptographic capability of
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
given listener. Joining the two — host CBOM keyed by host, endpoint
report keyed by `(host, port)` — produces a capability-vs.-deployment
gap analysis (capable but not configured, configured but not capable,
both, neither).

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
(network analyzer). SARIF output for `pqc-readiness` is tracked in
issue #7 to make this composition direct.

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
task. CBOM (issue #5) and SPDX 3.0 Security profile (issue #6) outputs
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
throughput per host, which is sufficient for a *capability tier*
verdict but does not measure end-to-end handshake cost. A dedicated
TLS-level benchmark harness (issue #12) measures the latter and can be
parameterised by the host capability profile this project produces, so
that handshake measurements are attributable to known host hardware
and library configurations.

## Field-level interoperability

The category descriptions above explain how artefacts compose at the
*tool* level — CBOM out of one tool flows into the input of another,
SARIF out of one is consumed by another. Field-level interoperability
— matching algorithm names, key-size encodings, and risk-level
vocabularies across CycloneDX 1.6 cryptographic-assets and NIST IR 8547
— is tracked separately in issue #8 (`docs/schema-alignment.md`).

## References

- NIST IR 8547 (IPD) — Transition to Post-Quantum Cryptography Standards: <https://csrc.nist.gov/pubs/ir/8547/ipd>
- CycloneDX 1.6 cryptographic-assets schema: <https://cyclonedx.org/docs/1.6/json/>
- OASIS SARIF 2.1.0: <https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html>
- SPDX 3.0 specification: <https://spdx.github.io/spdx-spec/v3.0/>
- NIST FIPS 203 / 204 / 205 (ML-KEM, ML-DSA, SLH-DSA)
- IETF TLS hybrid key-exchange drafts and related RFCs
