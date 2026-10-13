# pqc-readiness

Host-level Post-Quantum Cryptography readiness assessment.

`pqc-readiness` inspects a Linux host and reports whether it can run
NIST PQC primitives (ML-KEM, ML-DSA, SLH-DSA) at production speed in
software, or whether it requires a dedicated cryptographic accelerator.
Output is a stable JSON schema designed for fleet inventory aggregation,
with first-class support for CycloneDX 1.7 CBOM (1.6 on request), SPDX 3.0, and SARIF
2.1.0 so results drop into existing security pipelines.

The tool is intended for field architects and customer infrastructure
teams during regulated-environment PQC migration engagements. It runs
on bare-metal Linux, in containers (podman / quadlet), and as a
privileged DaemonSet on OpenShift.

## Table of contents

- [What's new](#whats-new)
- [What it detects](#what-it-detects)
- [Quick start](#quick-start)
- [Output formats](#output-formats)
- [CLI flags](#cli-flags)
- [Exit codes](#exit-codes)
- [Distribution support](#distribution-support)
- [Containers and OpenShift](#containers-and-openshift)
- [Fleet aggregation](#fleet-aggregation)
- [Scope and adjacent tooling](docs/scope.md)
- [Findings](#findings)
- [Documentation](#documentation)
- [License](#license)

## What's new

### 2026-10-13: accuracy fixes, faster scans, schema 1.4

This release fixes results that were wrong on current platforms, so
**re-scan your fleet**. Older reports can't be aggregated with new ones,
because the fleet aggregator only merges reports with the same
`schema_version`. It moves through schema versions 1.1 → 1.4; see
[Upgrade notes](#upgrade-notes-for-json-consumers).

#### Results that were wrong, now fixed

- **PQC certificates were reported as classical on OpenSSL ≥ 3.5**
  (#116). OpenSSL 3.5 prints ML-DSA / SLH-DSA *names* rather than OIDs, so
  `--scan-trust-store` never recognised them. Certificates are now
  classified from the OIDs in their DER encoding, independent of the
  installed OpenSSL.
- **Only the first certificate in each trust-store file was read**
  (#116). Bundle files hold hundreds of certificates. Every certificate
  is now inspected and de-duplicated by SHA-256. On a Fedora 44 host
  that is 396 unique certificates instead of 125 files, including the
  whole code-signing CA bundle that was previously invisible.
- **Container deployments described the scanner image, not the host**
  (#125). Under `--host-mount` (DaemonSet, quadlet), `--scan-packages`
  and the NSS version came from the *container image's* rpm database.
  They now read the host's rpm database, and the deployment manifests
  mount it read-only.
- **A missing algorithm benchmarked every algorithm** (#117). Asking
  `openssl speed` for an algorithm the local OpenSSL lacks makes it run
  the whole class instead. Such algorithms are now skipped with a reason.
- **Ubuntu upgrade advice pointed at an end-of-life release** (#121).
  Hosts on 24.04 or older are now pointed at 26.04 LTS, which ships
  OpenSSL 3.5. The old advice also wrongly said 24.04 offers OpenSSL 3.5.
- **Fleet rollups no longer abort on one bad file** (#76, #88). A
  non-UTF-8 file or a JSON value that isn't an object is listed under
  `skipped` instead of crashing the aggregation.

#### New

- **Three more recommendation roles** for `--recommend --role`:
  `tls-client`, `signing-service` and `firmware-signing`, under all four
  policies (#90–#92). Firmware signing recommends SLH-DSA (hash-based)
  except under CNSA 2.0, which mandates ML-DSA-87 and names LMS/XMSS
  (SP 800-208) for firmware. See
  [docs/recommendation-policies.md](docs/recommendation-policies.md).
- **`--output FILE`** writes any format to a path, including
  `--aggregate`, `--recommend` and `--ansible` (#89). Exit code 5 means
  the file could not be written.
- **`--debug`** logs every probe's diagnostics and subprocess exit codes
  to stderr; stdout is unchanged (#81).
- **`--trust-store-max-certs N`** bounds `--scan-trust-store` (default
  500 certificates); `trust_store.truncated` reports when the cap is hit
  (#87).
- **`--ansible` with `--check` / `--fips-strict` warns on stderr** that
  the gate is ignored, instead of silently exiting 0 (#95).
- Kernel crypto and kTLS detections now report when they can't see the
  host from inside a container (#70). The classical benchmark baseline
  now keeps OpenSSL's RSA KEM and signature rows, including key
  generation rates (#117).

#### Faster

Measured on Fedora 44 (24 cores); median of 11 runs, alternating between
versions.

| Run | Before | Now | Change |
|---|---|---|---|
| Default scan | 0.38 s | 0.38 s | unchanged |
| `--scan-packages` | 0.79 s | 0.36 s | 2.2× faster |
| `--scan-trust-store --scan-packages` | 1.61 s | 0.38 s | 4.2× faster |
| Trust-store classification alone | 0.70 s, one `openssl` per file | 0.04 s, no subprocesses | ~17× faster |

The rpm database is read in-process, without the `rpm` binary, in all
three formats rpm uses:
- **SQLite:** EL9, EL10, Fedora, CentOS Stream, Oracle Linux 9 and
  Amazon Linux 2023. Single lookups such as the NSS version use rpm's own
  `Name` index.
- **Berkeley DB:** EL8 and openSUSE Leap 15.6 cloud images (#134).
- **ndb:** SLES 15, Leap 16 and Tumbleweed (#134).

Measured inside booted cloud-image VMs (median of 7 alternating runs,
fresh process each), a full inventory read in-process against `rpm -qa`:

| Host | Format | `rpm -qa` | In-process |
|---|---|---|---|
| AlmaLinux 8.10 (440 pkgs) | Berkeley DB | 218 ms | 63 ms |
| Rocky Linux 8.10 (461 pkgs) | Berkeley DB | 212 ms | 54 ms |
| Oracle Linux 8.10 (373 pkgs) | Berkeley DB | 124 ms | 31 ms |
| openSUSE Leap 16.0 (378 pkgs) | ndb | 127 ms | 17 ms |
| openSUSE Tumbleweed (372 pkgs) | ndb | 78 ms | 10 ms |

Every in-process inventory matched `rpm -qa` exactly. Single-package
lookups (the NSS version in every default scan) are different: Berkeley
DB and ndb have no index the scanner reads, so a direct lookup walks the
whole database (10–60 ms), while `rpm -q` uses rpm's own index (~4 ms).
On those formats `rpm -q` is used first, pointed at the host with
`--root` under `--host-mount`, and the in-process read is the fallback
when `rpm` is missing or fails. A full inventory never needs the `rpm`
binary, so a container no longer depends on its own `rpm` being able to
read the host's format. The database format is detected from the
file contents, never assumed from the distro version, because hosts
upgraded in place can keep an older format.

#### Validated on real hosts

Official cloud images were booted under KVM. Each one checked the
in-process rpm reader against `rpm -qa` and ran the scanner end to end
with `--scan-packages`:

- **SQLite, reader output identical to `rpm -qa`, scanner OK:** AlmaLinux
  9.8 and 10.2, Rocky Linux 9.8 and 10.2, CentOS Stream 10, Fedora 43 and
  44.
- **ndb, served by the `rpm` fallback, scanner OK:** openSUSE Leap 16.0
  and Tumbleweed.
- **Database format detected correctly, but the scanner can't run on the
  stock image (Python 3.6 only):** AlmaLinux 8.10 (Berkeley DB) and
  openSUSE Leap 15.6 (Berkeley DB). See *Known limitations*.

Container images of RHEL 8/9/10 (UBI), Rocky, Alma, Stream, Oracle Linux
9, Amazon Linux 2023 and SLES 15 SP6/SP7 were also checked.

#### Upgrade notes for JSON consumers

| Schema | Change |
|---|---|
| `1.2` | `benchmark`, `benchmark_tls_handshake`, `memory_bandwidth_method` are `null` when not run (previously `{}` / `""`). `trust_store` gained `total_found`, `scanned_count`, `max_certs`, `truncated`. |
| `1.3` | Benchmark entries can carry `skipped`; RSA KEM/signature baseline rows added. **`trust_store` counts are now unique certificates, not files**, so they aren't comparable with older reports. |
| `1.4` | `packages.source` (`rpmdb-sqlite` or `rpm-cli`) and `packages.db_root` show which database was read. |

Nothing was renamed or removed. The full field reference is in
[docs/json-output.md](docs/json-output.md).

#### Known limitations

- **Stock SLES 15 / openSUSE Leap 15** ship only Python 3.6, so the
  scanner exits 127 until a newer interpreter is installed (#127).
  [RHEL 8 / Rocky 8 / AlmaLinux 8](#distribution-support) need the same
  kind of prerequisite.
- RHEL cloud images need a Red Hat login to download, so they were checked as UBI containers.
  Rocky and AlmaLinux stood in for booted RHEL 8 hosts.

#### Under the hood

- CI pins `ruff` / `mypy` so tool upgrades can't break unchanged code
  (#97). `detect-secrets` runs in CI (#94).
- The full test suite runs inside the UBI 8, UBI 10 and Debian images
  on every PR (#84). A weekly workflow covers Fedora, Rocky/AlmaLinux 9
  and 10, Debian 13, Ubuntu 26.04 LTS and SLES (#83, #115).
- `main()` was split into parser, collection, rendering and exit-code
  steps, guarded by a golden-output test (#80, first step towards the
  package split).
- Tests went from 351 to 688.

## What it detects

1. **CPU instruction-set support for PQC** — AVX-512 family (VBMI / IFMA
   / VAES / GFNI) on x86_64; ARMv8 crypto extensions (SHA-3, SVE2, I8MM)
   on aarch64; CPACF MSA8 / MSA9 and Crypto Express level on s390x.
2. **Cryptographic accelerators** — PCI HSMs, DPUs (BlueField, IPU,
   Pensando), TPMs, network HSMs detected by client config, AWS Nitro,
   Intel QAT.
3. **OS / library plumbing** — `/proc/crypto` hardware drivers, kernel
   TLS, kernel FIPS mode, OpenSSL ≥ 3.5 PQC algorithms and TLS 1.3
   hybrid groups, OpenSSH `ssh -Q kex`, strongSwan / Libreswan, NSS.
4. **Production suitability** — per-algorithm tier with measured
   throughput, host capacity estimate, and a top-level
   `replace_required` flag for fleet planning.

## Quick start

```bash
./pqc-readiness                       # human-readable text report
./pqc-readiness --bench               # add OpenSSL microbench
./pqc-readiness --json                # stable JSON for aggregation
./pqc-readiness --recommend           # policy-aware algorithm recommendation
./pqc-readiness --check excellent     # exit 4 if below tier (CI gating)
./pqc-readiness --save                # save JSON to ~/.cache/pqc-readiness/
./pqc-readiness --json --output /var/lib/pqc/report.json  # write to a chosen path
./pqc-readiness --version             # script + JSON schema versions
./pqc-readiness --help                # full flag reference
```

`pqc-readiness` is a shell wrapper that picks a usable Python 3.9+ from
`PATH` (`python3.13` … `python3.9`, then `python3` / `python`) and runs
the single-file zipapp `pqc-readiness.pyz` next to it. In a git checkout
it runs the `pqc_readiness/` package instead (`python -m pqc_readiness`).
On hosts whose default `python3` is too old (RHEL 8 / Rocky 8 /
AlmaLinux 8 ship 3.6, and some stock EL8 cloud images have no `python3`
at all) it prints AppStream guidance and exits 127 instead of failing
with a `SyntaxError` or an `env` error. Hosts with Python ≥ 3.9 can also
run `./pqc-readiness.pyz` or `python3 -m pqc_readiness` directly; they
are interchangeable. See [Distribution support](#distribution-support)
for per-distro notes.

### Single-file deployment

The tool is a stdlib-only Python package. `make dist` (or
`python3 scripts/build_zipapp.py`) builds `dist/pqc-readiness.pyz`, one
executable file with no dependencies. Copy it, with or without the
`pqc-readiness` wrapper, to any host with Python 3.9+ and run it:

```bash
make dist
scp dist/pqc-readiness.pyz pqc-readiness host:/usr/local/bin/
ssh host /usr/local/bin/pqc-readiness --json
```

Debugging on a target host: `python3 -m zipfile -l pqc-readiness.pyz`
lists the modules, and `python3 -m zipfile -e pqc-readiness.pyz /tmp/pqc`
extracts them for reading or `grep`.

**Migrating from `pqc_readiness.py`.** Releases before the package split
(#80) shipped one script, `pqc_readiness.py`. It is gone. Replace
`pqc_readiness.py` with `pqc-readiness.pyz`, the `pqc-readiness` wrapper,
or `python3 -m pqc_readiness` in scripts, cron jobs and playbooks. Flags,
output and exit codes are unchanged. The container images and the
example Ansible playbooks already use the zipapp.

## Output formats

| Flag | Format | Use case |
| --- | --- | --- |
| (default) | Coloured text report | Operator console |
| `--markdown` | Markdown | Pasting into tickets |
| `--json` | Stable JSON schema | Fleet aggregation, automation |
| `--cbom` | CycloneDX 1.7 CBOM (`--cbom-version 1.6` for 1.6) | Cryptographic inventory pipelines |
| `--spdx` | SPDX 3.0 JSON-LD | SPDX-native tooling |
| `--sarif` | SARIF 2.1.0 findings | Code-scanning / security pipelines |
| `--ansible` | `ansible_facts` wrapper | Ansible `set_fact` |
| `--recommend` | Policy-aware recommendation | Algorithm selection per host |

`--json`, `--cbom`, `--spdx`, `--sarif`, and `--ansible` are mutually
exclusive views of the same probe run. Detection logic is shared — a
new detection rule shows up in every output format without per-renderer
changes.

**JSON.** Stable, schema-versioned host inventory. The full top-level
field reference, the `--ansible` wrapper shape, and the
`--recommend --json` variant are documented in
[docs/json-output.md](docs/json-output.md). For schema interoperation
with CycloneDX, see [docs/schema-alignment.md](docs/schema-alignment.md).

**CBOM.** `--cbom` emits a [CycloneDX 1.7](https://cyclonedx.org/docs/1.7/json/)
Cryptographic Bill of Materials; `--cbom-version 1.6` emits
[CycloneDX 1.6](https://cyclonedx.org/docs/1.6/json/) exactly as earlier
releases did. Each detected source — ISA features, accelerators, OpenSSL
primitives, OpenSSH KEX, IPsec, PKCS#11 modules, trust-store summary —
becomes a `cryptographic-asset` component with `assetType`,
`algorithmProperties` where applicable, and a
`detectedBy: pqc-readiness@<version>` provenance property. 1.7 output
adds:

- `algorithmFamily` from the CycloneDX 1.7 algorithm registry (ML-KEM,
  ML-DSA, SLH-DSA, LMS, XMSS). Families the registry doesn't define yet
  (HQC, FN-DSA, FrodoKEM, Classic McEliece, BIKE) are reported in a
  `pqc-readiness:algorithmFamily` property marked
  `not-in-cyclonedx-1.7-registry`. Hybrid groups such as
  X25519MLKEM768 have no single family.
- TLS and SSH `protocol` components that link the key-exchange groups
  they can negotiate through `relatedCryptographicAssets`.
- `certificate` assets keyed by SHA-256 fingerprint once the
  per-certificate inventory (#108) is available.

Both versions validate against the official schemas bundled under
`tests/fixtures/cyclonedx/`. NIST IR 8547, the US transition guidance,
is still an [initial public draft](https://csrc.nist.gov/pubs/ir/8547/ipd).

**SPDX.** `--spdx` emits an [SPDX 3.0.1](https://spdx.github.io/spdx-spec/v3.0.1/)
JSON-LD document with `core` + `software` + `security` profile
conformance. The shared canonical asset list is projected as
`software_Package` / `security_Vulnerability` elements wrapped in a
`software_Sbom`. JSON-LD is fully type-checked: every `type` and
property is a term in the canonical SPDX 3.0.1 context, and every
reference resolves within the document.

**SARIF.** `--sarif` emits [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
findings under stable rule IDs (`pqc-001-…` through `pqc-006-…`),
each with `helpUri`, severity (`warning` / `error`), and short / full
descriptions. Findings cover OpenSSL pre-3.5, kernel-FIPS / PQC
provider conflicts, missing hybrid TLS groups, and HSMs without PQC
firmware. Validates against the official SARIF 2.1.0 schema.

**Recommendations.** `--recommend` produces a host-specific PQC
algorithm recommendation under one of four policies (`cnsa-2.0`,
`nist-civilian`, `eu-anssi-bsi`, `commercial`); `--policy auto`
(default) emits all four side by side. The authority, source
document, and engine-encoded position for each policy are catalogued
in [docs/recommendation-policies.md](docs/recommendation-policies.md).
The `--recommend --json` document shape is in
[docs/json-output.md](docs/json-output.md#recommend-json-variant).

**Ansible.** `--ansible` wraps the JSON schema in
`{ansible_facts: {pqc_readiness: …}}` and always exits 0 so a play
never marks a host as failed on the verdict. Because of that,
`--ansible` takes precedence over `--check` and `--fips-strict`: they
can be combined with it, but their exit-code gates are ignored and a
warning is printed on stderr. Gate in the play on the JSON instead
(e.g. `pqc_readiness.cnsa_2_0.status`). Runnable playbooks
(`set_fact`, fleet aggregation), the `become` / privilege model, and
the fact shape downstream tasks rely on are in
[docs/ansible.md](docs/ansible.md); the playbooks themselves live
under [`deploy/ansible/`](deploy/ansible/).

## CLI flags

`pqc-readiness --help` is the authoritative one-liner reference.
Flags below are grouped by purpose.

### Probes and benchmarks

| Flag | Purpose |
| --- | --- |
| `--bench` | OpenSSL microbenchmark (PQC + classical). |
| `--bench-tls` | Loopback TLS 1.3 handshake bench (classical / hybrid / pure-PQC). |
| `--threads N` | Add an N-way scaling test alongside the single-thread bench. |
| `--seconds N` | Override per-operation benchmark duration. Larger values reduce variance at the cost of run time. |
| `--scan-trust-store` | Walk system trust-store directories and classify every certificate (bundles included) as PQC, hybrid composite, or classical by reading its algorithm OIDs directly; no `openssl` binary needed. |
| `--trust-store-max-certs N` | Cap on unique certificates classified by `--scan-trust-store` (default 500). When the cap is hit, `trust_store.truncated` is `true` and the text, CBOM, and SARIF outputs say how many certificates were not inspected. |
| `--scan-packages` | Enumerate installed packages with bundled crypto. Branches on family: the rpm database (rhel / suse; SQLite, Berkeley DB and ndb databases are all read in-process for the inventory, with `rpm -qa` only as the fallback for an unreadable database), `dpkg-query -W` (debian), `pacman -Q` (arch), `apk info -v` (alpine). Normalises to `[{name, version}, ...]`. Under `--host-mount` the host's rpm database is read; the DaemonSet and quadlet mount `/var/lib/rpm` read-only for this. |
| `--host-mount PATH` | Path where the host root is mounted. Host reads of `/proc /sys /dev /etc`, `os-release` and the rpm / dpkg package databases go through it. DaemonSet pattern: host root mounted at `/host`, probe invoked with `--host-mount /host` so reads target the node, not the container image. |

### Recommendation engine

| Flag | Purpose |
| --- | --- |
| `--recommend` | Emit a host-specific PQC recommendation instead of the readiness report. |
| `--policy {cnsa-2.0,nist-civilian,eu-anssi-bsi,commercial,auto}` | Compliance context for `--recommend`. `auto` (default) emits all four policies side by side. |
| `--role {tls-server,tls-client,signing-service,firmware-signing}` | Role for `--recommend`. All four workload roles are implemented; `generic` returns a stub response. See [docs/recommendation-policies.md](docs/recommendation-policies.md#roles). |

### Output

| Flag | Purpose |
| --- | --- |
| `--json` / `--markdown` / `--cbom` / `--spdx` / `--sarif` / `--ansible` | See [Output formats](#output-formats). |
| `--cbom-version {1.7,1.6}` | CycloneDX specVersion for `--cbom` (default `1.7`). `1.6` reproduces earlier releases' output exactly. |
| `--check {excellent,good,marginal,poor,cnsa-2.0}` | Exit 4 if the verdict is below the named tier, or if `cnsa-2.0` is selected and the host is not CNSA 2.0 compliant. CI gating. |
| `--save` | Write JSON to `~/.cache/pqc-readiness/`. The fleet aggregator reads exactly this directory layout. |
| `--output FILE` | Write the report to `FILE` instead of stdout. Works with every format, including `--aggregate`, `--recommend` and `--ansible`. The parent directory must already exist (it is never created). Mutually exclusive with `--save`. Useful for volume mounts in quadlet / DaemonSet / Ansible `command:` tasks, where shell redirection is fragile. |
| `--quiet` | Print only the verdict line. |
| `--no-color` | Disable ANSI colour. Auto-disabled when stdout is not a TTY. |

### Aggregation

| Flag | Purpose |
| --- | --- |
| `--aggregate DIR` | Roll every `*.json` in `DIR` into a fleet rollup. The program exits when done and ignores all other flags. |
| `--aggregate-format {json,csv}` | Output format for `--aggregate` (default `json`). |

### Misc

| Flag | Purpose |
| --- | --- |
| `--debug` | Log detection diagnostics (failed file reads, subprocess exit codes) to stderr. Report output on stdout is unchanged. Use it to tell "tool absent" from "tool present but read/parse failed" on a customer host. |
| `--version` | Print the script version and the JSON schema version, then exit. |
| `-h`, `--help` | Print help and exit. |

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Excellent — dedicated PQC silicon OR optimised SIMD + ample RAM. |
| 1 | Good — software PQC fast enough for production. |
| 2 | Marginal — works, plan for an accelerator at scale. |
| 3 | Poor — software-only and too slow for production. |
| 4 | `--check` threshold not met (tier below floor, or `cnsa-2.0` not compliant). |
| 5 | `--output FILE` could not be written after the probe ran (e.g. disk full). An unusable path detected up front (missing parent directory, path is a directory) is a usage error and exits 2 before probing. |

`--ansible` always exits 0 and overrides `--check` / `--fips-strict`
(with a stderr warning); the verdict is in the JSON body.

## Distribution support

The script targets one JSON schema across every Linux it runs on.
"Validated on" means the script runs cleanly and the schema matches in
CI or in maintainer testing — not a support contract.

| Tier | Distros | Validation cadence |
| --- | --- | --- |
| **1** | RHEL 9, RHEL 10, Ubuntu 24.04 LTS, Debian 12 | Every PR runs `pytest` + `ruff` + `mypy --strict` on the GitHub-hosted `ubuntu-latest` runner under CPython 3.11 / 3.12 / 3.13 (`.github/workflows/ci.yml`); per-OS validation against the actual Tier 1 images runs out-of-band — see *"What 'every change' actually means"* below. |
| **2** | Fedora (latest), Rocky / AlmaLinux 9 and 10, Ubuntu 26.04 LTS, Debian 13, SLES 15 SP6+, RHEL 8, Rocky 8, AlmaLinux 8 | Weekly — `.github/workflows/ci-tier2-weekly.yml` runs the full `pytest` suite inside each distro's stock container image every Monday (non-blocking; fixes accepted). **EL8 (RHEL 8, Rocky 8, AlmaLinux 8) is the exception:** it is not in the weekly matrix but runs on every PR instead — `.github/workflows/ci-ubi8.yml` builds `Containerfile.ubi8` and runs the full `pytest` suite under the AppStream `python3.9` interpreter inside the UBI 8 image (a container image, not a booted EL8 host). EL8 stays Tier 2 because stock EL8 cloud images need a manual Python prerequisite (see *RHEL 8 / Rocky 8 / AlmaLinux 8 specifics*). |
| **3** | Arch, Alpine, others | Best-effort, community-supported |

Cross-distro probing uses a single `detect_os()` source of truth that
resolves family from `/etc/os-release` `ID` + `ID_LIKE`, so derivatives
the explicit table doesn't name (Linux Mint → debian, Manjaro → arch,
…) still classify correctly. PQC primitives require **OpenSSL ≥ 3.5**;
older builds report `openssl.pqc_native: false` and a no-bench caveat.
`openssl.upgrade_path` is a family-aware hint for getting a PQC-capable
OpenSSL on the specific host.

**What "every change" actually means.** Three workflows run on every PR:

- `.github/workflows/ci.yml` — `ruff check`, `mypy --strict`,
  `pytest tests/ -q`, and the `--help` ↔ README cross-check on the
  GitHub-hosted `ubuntu-latest` runner under CPython 3.11 / 3.12 /
  3.13. This catches schema and parser regressions on every push but
  does **not** boot the script under any Tier 1 vendor image.
- `.github/workflows/ci-ubi8.yml` — builds `Containerfile.ubi8` with
  Podman, smoke-tests the wrapper launcher, and runs `pytest` under
  AppStream `python3.9` inside the resulting image. The Red Hat
  UBI 8 entry point therefore *is* boot-tested on every PR.
- `.github/workflows/ci-containers.yml` — the same build + smoke +
  in-image `pytest` sequence for `Containerfile.ubi10` (RHEL 10
  userspace, OpenSSL 3.5) and `Containerfile.debian` (Debian 12).

Per-OS validation against stock cloud images for the remaining Tier 1
targets (RHEL 9, RHEL 10, Ubuntu 24.04 LTS, Debian 12) and the Tier 2
distros happens out-of-band via the
[`aclater/distro-matrix`](https://github.com/aclater/distro-matrix)
libvirt + KVM runner; surfacing those runs as a CI artefact is tracked
in [issue #41](https://github.com/aclater/pqc-readiness/issues/41).
Separately, `.github/workflows/ci-tier2-weekly.yml` runs the `pytest`
suite every Monday inside the stock *container* image of each Tier 2
distro (Fedora, Rocky / AlmaLinux 9 and 10, Debian 13, Ubuntu 26.04 LTS,
SLES via SUSE BCI). That exercises each distro's Python, OpenSSL and
OpenSSH userspace, but not a booted kernel; it can also be run on
demand from the Actions tab (`workflow_dispatch`).

**Ubuntu rotation in Tier 2.** The Tier 2 Ubuntu slot tracks the newest
*supported* Ubuntu release that is not already Tier 1. An interim release
(e.g. 26.10) enters the slot once it is generally available — not while
its image is still a pre-release — and leaves when it reaches end of life
(interim releases get nine months of support). When no supported interim
exists, the newest LTS not in Tier 1 fills the slot; today that is 26.04
LTS (Tier 1 stays on 24.04 LTS). Rotating means updating this table, the
`ci-tier2-weekly.yml` matrix entry, the `tests/fixtures/os-release/`
fixture and `tests/test_readme_distribution_support.py` together.
The phrase "Every change (CI)" in earlier revisions of this table
overstated what GitHub Actions exercises today — see
[issue #44](https://github.com/aclater/pqc-readiness/issues/44) for
the audit finding.

**RHEL 8 / Rocky 8 / AlmaLinux 8 specifics.** EL8 needs one manual
prerequisite: a Python 3.9+ interpreter from AppStream. Stock EL8 cloud
images (RHEL / Rocky / AlmaLinux 8.10 KVM qcow2s) ship no Python 3.9+.
Depending on the image build there is either no `python3` on `PATH` at
all (only `/usr/libexec/platform-python`, 3.6) or a `python3` that is
3.6. The AlmaLinux 8.10 image of 2026-10 ships `/usr/bin/python3` 3.6.8.
Neither can run the tool: `./pqc-readiness.pyz` fails with
`/usr/bin/env: 'python3': No such file or directory` or a syntax error,
and the `pqc-readiness` wrapper exits 127 with the guidance below. Install an interpreter once per host (or in your configuration-
management baseline), then invoke through the wrapper, which finds it
automatically:

```bash
sudo dnf module install -y python39   # AppStream module, provides python3.9
# or, on EL 8.8+:
sudo dnf install -y python3.11        # non-modular AppStream package
./pqc-readiness --json
```

Python 3.6 / `platform-python` is deliberately not supported: the
script relies on 3.7+ language and stdlib features (`from __future__
import annotations`, `dataclasses`), and back-porting would lock every
future change into 3.6 (see
[issue #36](https://github.com/aclater/pqc-readiness/issues/36)).
OpenSSL 1.1.1 on EL8 means `openssl.pqc_native: false` and a no-bench
caveat in the verdict; the inventory probe still works. A
ready-to-deploy image is shipped at
[`Containerfile.ubi8`](Containerfile.ubi8) (build via
`make container-ubi8`); the existing `--host-mount` DaemonSet pattern
is identical to the UBI 10 image. CI runs the full test suite inside the
UBI 8 image on every PR and push to `main` (`ci-ubi8.yml`).

**SLES 15 / openSUSE Leap 15 specifics.** SLES 15 and openSUSE Leap 15
ship Python 3.6 as `/usr/bin/python3`; the openSUSE Leap 15.6 cloud
image has nothing newer. On such a host the `pqc-readiness` wrapper
exits 127 and prints SUSE-specific guidance. The fix is a one-time
install of a newer interpreter alongside the system one. The wrapper
finds `python3.11` on its own, and the system `python3` is left
untouched:

```bash
sudo zypper --gpg-auto-import-keys ref   # refresh repo metadata (and import repo keys) first
sudo zypper -n in python311              # provides /usr/bin/python3.11
./pqc-readiness --json
```

These exact steps were tested on a booted openSUSE Leap 15.6 cloud image
(`python311` gives Python 3.11.15). The scanner then ran normally and
read the Berkeley DB rpm database in-process. openSUSE Leap 16.0 and Tumbleweed already ship Python 3.13 as
`python3` (checked by booting their cloud images). The wrapper picks its install hint from `ID` / `ID_LIKE`
in `/etc/os-release`. SUSE, RHEL-family and Debian/Ubuntu hosts each get
their own hint ([#127](https://github.com/aclater/pqc-readiness/issues/127)).

Out of scope for this tool: Windows / WSL, BSD, musl-specific behaviour
beyond Alpine. macOS support is best-effort and limited to the paths
already in the script.

## Containers and OpenShift

Containerfiles ship for each supported base image:

| File | Base | Use case |
| --- | --- | --- |
| `Containerfile.ubi10` | `registry.access.redhat.com/ubi10/ubi-minimal` | RHEL / Fedora fleets; default |
| `Containerfile.ubi8` | `registry.access.redhat.com/ubi8/ubi-minimal` | RHEL 8 / Rocky 8 / AlmaLinux 8 |
| `Containerfile.debian` | `docker.io/library/debian:12-slim` | Debian / Ubuntu fleets |
| `Containerfile.ubuntu-fips` | (stub) | Pending an Ubuntu Pro FIPS customer ask |

```bash
make container           # build all three real images
make container-ubi10     # UBI 10 only
make container-ubi8      # UBI 8 only
make container-debian    # Debian only
```

All images run as non-root UID 1001 with a Python-only HEALTHCHECK
(`ubi*-minimal` lacks `curl`).

`deploy/quadlet/pqc-readiness.container` is a systemd quadlet that
runs the probe daily against the host.

`deploy/openshift/daemonset.yaml` is the fleet DaemonSet — non-root,
hostPID, custom SCC dropping all capabilities, read-only host bind
mounts of `/proc /sys /dev /etc /usr/lib/os-release` and the rpm
database directory `/var/lib/rpm`. That one mount covers every layout,
because on EL10, Fedora and SUSE `/var/lib/rpm` is a symlink to
`/usr/lib/sysimage/rpm` and the bind mount follows it. The quadlet
mounts the same paths. Inside the pod
the host root is mounted at `/host` and the probe is invoked with
`--host-mount /host` so its reads target the node, not the container
image.

For Ansible-based deployments see [docs/ansible.md](docs/ansible.md)
and the runnable playbooks under [`deploy/ansible/`](deploy/ansible/).

## Fleet aggregation

`--aggregate DIR` reads every `*.json` produced by `--save` (or by the
DaemonSet output volume) and emits a fleet rollup: counts by arch,
OS, ISA tier, verdict, runtime environment, and accelerator kind, plus
unique CPU models and a `replace_required_count`.

```bash
pqc-readiness --aggregate /var/lib/pqc-readiness                       # JSON
pqc-readiness --aggregate /var/lib/pqc-readiness --aggregate-format csv  # CSV
```

Files with mismatched `schema_version` land under `skipped` with a
reason rather than being silently merged.

## Findings

Reproducible technical findings produced by `pqc-readiness`-driven testing. Reference documents — not blog posts — kept in-repo so the underlying claim, the data, and the reproduction steps stay together.

- [`docs/findings/fips-algorithm-fence.md`](docs/findings/fips-algorithm-fence.md) — kernel `fips=1` and a FIPS-preset crypto-policy do not, by themselves, gate which algorithms the public OpenSSL interface exposes; the gating comes from downstream patches in the OpenSSL build. Distros that rebuild from upstream sources without those patches expose ML-KEM, ML-DSA, and SLH-DSA via the default provider while FIPS is active. Use `--fips-strict` to flag the divergence.

## Documentation

- [`docs/scope.md`](docs/scope.md) — where this project fits in the wider PQC tooling ecosystem; how host-level scanning composes with network, source-code, dependency, and TLS-handshake categories.
- [`docs/json-output.md`](docs/json-output.md) — full `--json` top-level field reference, `--ansible` wrapper, and `--recommend --json` variant.
- [`docs/recommendation-policies.md`](docs/recommendation-policies.md) — authority, source document, and engine-encoded position for every `--policy`.
- [`docs/ansible.md`](docs/ansible.md) — Ansible playbooks (`set_fact`, fleet aggregation), privilege model, downstream fact shape.
- [`docs/schema-alignment.md`](docs/schema-alignment.md) — field-by-field mapping of `--json` against CycloneDX 1.6's `cryptoProperties` schema.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — third-party-product reference policy, the README ↔ `--help` rule.

## License

Apache-2.0. See [`LICENSE`](LICENSE).
