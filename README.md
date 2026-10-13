# pqc-readiness

Host-level Post-Quantum Cryptography readiness assessment.

`pqc-readiness` inspects a Linux host and reports whether it can run
NIST PQC primitives (ML-KEM, ML-DSA, SLH-DSA) at production speed in
software, or whether it requires a dedicated cryptographic accelerator.
Output is a stable JSON schema designed for fleet inventory aggregation,
with first-class support for CycloneDX 1.6 CBOM, SPDX 3.0, and SARIF
2.1.0 so results drop into existing security pipelines.

The tool is intended for field architects and customer infrastructure
teams during regulated-environment PQC migration engagements. It runs
on bare-metal Linux, in containers (podman / quadlet), and as a
privileged DaemonSet on OpenShift.

## Table of contents

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
`PATH` (`python3.13` … `python3.9`, then `python3` / `python`) and
`exec`s `pqc_readiness.py`. On hosts whose default `python3` is too old
(RHEL 8 / Rocky 8 / AlmaLinux 8 ship 3.6, and stock EL8 cloud images
have no `python3` at all) it prints AppStream guidance and exits 127
instead of failing with a `SyntaxError` or an `env` error. Hosts with Python ≥ 3.9 can invoke
`./pqc_readiness.py` directly; the two are interchangeable. See
[Distribution support](#distribution-support) for per-distro notes.

## Output formats

| Flag | Format | Use case |
| --- | --- | --- |
| (default) | Coloured text report | Operator console |
| `--markdown` | Markdown | Pasting into tickets |
| `--json` | Stable JSON schema | Fleet aggregation, automation |
| `--cbom` | CycloneDX 1.6 CBOM | NIST IR 8547 inventory pipelines |
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

**CBOM.** `--cbom` emits a [CycloneDX 1.6](https://cyclonedx.org/docs/1.6/json/)
Cryptographic Bill of Materials. Each detected source — ISA features,
accelerators, OpenSSL primitives, OpenSSH KEX, IPsec, PKCS#11 modules,
trust-store summary — becomes a `cryptographic-asset` component with
`assetType`, `algorithmProperties` where applicable, and a
`detectedBy: pqc-readiness@<version>` provenance property. Validates
against the official CycloneDX 1.6 JSON schema. NIST IR 8547
([final](https://csrc.nist.gov/pubs/ir/8547/final)) references
CycloneDX 1.6 as the standard exchange format for cryptographic
inventory.

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

`./pqc_readiness.py --help` is the authoritative one-liner reference.
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
| `--scan-packages` | Enumerate installed packages with bundled crypto. Branches on family: the rpm database (rhel / suse; `rpmdb.sqlite` is read in-process, with `rpm -qa` as the fallback for Berkeley DB / ndb databases), `dpkg-query -W` (debian), `pacman -Q` (arch), `apk info -v` (alpine). Normalises to `[{name, version}, ...]`. Under `--host-mount` the host's rpm database is read; the DaemonSet and quadlet mount `/var/lib/rpm` read-only for this. |
| `--host-mount PATH` | Prefix for `/proc /sys /dev /etc` reads. DaemonSet pattern: host root mounted at `/host`, probe invoked with `--host-mount /host` so reads target the node, not the container image. |

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
images (RHEL / Rocky / AlmaLinux 8.10 KVM qcow2s) ship **no** `python3`
on `PATH` at all — only `/usr/libexec/platform-python` (3.6), which
cannot parse the script — so out of the box `./pqc_readiness.py` fails
with `/usr/bin/env: 'python3': No such file or directory` (exit 127)
and the `pqc-readiness` wrapper exits 127 with the same guidance as
below. Install an interpreter once per host (or in your configuration-
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
mounts of `/proc /sys /dev /etc /usr/lib/os-release`. Inside the pod
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
pqc_readiness.py --aggregate /var/lib/pqc-readiness                       # JSON
pqc_readiness.py --aggregate /var/lib/pqc-readiness --aggregate-format csv  # CSV
```

Files with mismatched `schema_version` land under `skipped` with a
reason rather than being silently merged.

## Findings

Reproducible technical findings produced by `pqc_readiness.py`-driven testing. Reference documents — not blog posts — kept in-repo so the underlying claim, the data, and the reproduction steps stay together.

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
