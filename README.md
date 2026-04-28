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
./pqc_readiness.py --markdown         # markdown for tickets
./pqc_readiness.py --ansible          # ansible_facts wrapper
./pqc_readiness.py --aggregate ./out  # roll up many --save outputs
./pqc_readiness.py --version          # script + JSON schema versions
```

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
/usr/lib/os-release`.

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

## License

Apache-2.0. See `LICENSE`.
