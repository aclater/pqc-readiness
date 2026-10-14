# pqc-readiness

Find out which Linux hosts will break, or quietly stay classical, when you
move to post-quantum cryptography, before you start the migration.

`pqc-readiness` scans a Linux host and answers the questions a PQC migration
plan needs answered for every machine:

- **Can it do PQC?** OpenSSL, OpenSSH, GnuTLS, NSS, libgcrypt, Java, Go and the
  other crypto stacks installed, checked for ML-KEM, ML-DSA and SLH-DSA.
- **Is it actually configured to?** Capability isn't deployment. The system
  crypto policy, `openssl.cnf` and the running `sshd` configuration decide
  whether PQC is offered. Each protocol and listening service is rated
  *deployed*, *capable but not configured*, or *not capable*.
- **What will fail?** Services linked to crypto libraries that can't do PQC,
  Go binaries without hybrid ML-KEM, classical-only signing keys, boot chains,
  Kerberos, VPN and DNSSEC configurations. Each becomes a finding with a rule
  ID and a help page.
- **Is the hardware fast enough?** CPU instruction-set support, accelerators
  (HSMs, TPMs, DPUs, s390x Crypto Express) and measured ML-KEM / ML-DSA and
  TLS-handshake throughput.
- **What should it use?** Algorithm recommendations under CNSA 2.0, NIST,
  EU (ANSSI/BSI) or commercial policy.

Results come out as a text report, JSON, a CycloneDX CBOM, SPDX, SARIF,
OCSF events for SIEMs, Prometheus metrics or Ansible facts, and roll up
across a fleet.

What makes it easy to deploy and trust:

- **One file, no dependencies:** a single Python zipapp that runs on Python
  3.9 or newer.
- **Read only:** it never changes the host; the only file it writes is a
  report, when you ask it to.
- **Runs where your hosts are:** on a live host, in a container against the
  host's filesystem, as a DaemonSet on OpenShift, Kubernetes, RKE2 or K3s,
  or against an offline image, including OpenWrt and Yocto.
- **Reports the host, not the scanner:** in a container, OpenSSL and
  package facts come from the node, and findings name the pod and
  namespace.
- **Verifiable:** release images are signed and carry build provenance and
  a CycloneDX SBOM attestation.

## What it finds

A scan of 20 stock Linux images with v2.2.0 (the full results are in
[docs/examples/os-matrix-2026-10.md](docs/examples/os-matrix-2026-10.md)):

| Distributions | Out of the box |
| --- | --- |
| RHEL, Rocky, AlmaLinux and CentOS Stream 10; Fedora 43 and 44; Ubuntu 26.04; openSUSE Leap 16 and Tumbleweed | Hybrid ML-KEM on by default for TLS and SSH |
| RHEL, Rocky, AlmaLinux, Oracle Linux and CentOS Stream 9; Amazon Linux 2023 | OpenSSL can do PQC, but the default crypto policy keeps TLS and SSH classical: a configuration change, not an upgrade |
| RHEL, Rocky, AlmaLinux and Oracle Linux 8; openSUSE Leap 15.6 | OpenSSL can't do PQC in TLS; the host needs an upgrade |

Every host trusted only classical package-signing keys except RHEL 10, which
ships a hybrid ML-DSA-87+Ed448 key.

## Latest release

**v2.3.0** (2026-10-14, JSON schema 1.7) added:

- **per-service TLS configuration**: each daemon's own TLS settings decide
  its verdict, and rule `pqc-021` flags endpoints pinned to classical groups;
- **embedded and minimal systems**: OpenWrt, Yocto and Buildroot
  inventories, SBOMs and library versions, even without a package database;
- **host-accurate container scans**: OpenSSL facts from the node, not the
  scanner image, and findings named by pod and namespace;
- **offline sshd analysis** from the image's config and binaries;
- **Kubernetes, RKE2, K3s and Rancher** manifests, validated on a live
  cluster, and CBOMs and SBOMs that share canonical package identifiers.

**Upgrading:** package identifiers now encode `+` as `%2B`, container scans
can read CNSA 2.0 `partial` where they said `compliant`, and schema 1.7
reports don't merge with 1.6 ones, so re-scan. Full release notes:
[CHANGELOG.md](CHANGELOG.md).

## Quick start

Download the scanner from the
[latest release](https://github.com/aclater/pqc-readiness/releases/latest),
verify it, and run it. It needs Python 3.9 or newer.

```bash
curl -LO https://github.com/aclater/pqc-readiness/releases/latest/download/pqc-readiness.pyz
curl -LO https://github.com/aclater/pqc-readiness/releases/latest/download/pqc-readiness.pyz.sha256
sha256sum -c pqc-readiness.pyz.sha256
sudo python3 pqc-readiness.pyz            # human-readable report
```

Run as root to see every process, key and configuration file; without root
the scan still works but reports what it couldn't read. Common runs:

```bash
pqc-readiness --json --scan-packages --scan-services > host.json   # inventory for automation
pqc-readiness --sarif --scan-crypto-libraries --scan-services       # findings for a security pipeline
pqc-readiness --cbom --scan-trust-store --scan-crypto-material      # CycloneDX CBOM
pqc-readiness --bench --bench-tls                                  # measure PQC and TLS throughput
pqc-readiness --recommend --role tls-server                        # algorithm recommendations
pqc-readiness --check cnsa-2.0                                     # exit 4 if not CNSA 2.0 compliant
```

`pqc-readiness` here is the launcher script from a checkout, which picks a
suitable Python and runs the zipapp; `python3 pqc-readiness.pyz` and
`python3 -m pqc_readiness` are equivalent. To build the zipapp yourself, run
`python3 scripts/build_zipapp.py`.

## What it checks

Nothing is installed or reconfigured. The basic scan
always runs; the `--scan-*` flags add deeper inventories.

| Area | What it reports | Flag |
| --- | --- | --- |
| CPU and accelerators | AVX-512 / ARMv8 / s390x CPACF support for PQC; HSMs, TPMs (including TPM 2.0 v1.85 PQC), DPUs, QAT, Crypto Express, PKCS#11 modules | always |
| OpenSSL, OpenSSH, NSS, IPsec | PQC algorithms and TLS groups, SSH key exchanges, IKEv2 proposals; in a container, the host's OpenSSL version from its package or libcrypto | always |
| Configuration | System crypto policy, `openssl.cnf` defaults, effective `sshd` configuration (parsed from the tree and its binaries in offline scans), FIPS mode and its algorithm fence, CNSA 2.0 compliance; unreadable files are reported as unreadable, not missing | always |
| Deployment gap | Per-protocol and per-service verdict: deployed, capable but not configured, not capable | always |
| Crypto libraries | GnuTLS, libgcrypt, libssh, wolfSSL, AWS-LC, Mbed TLS, JDKs and Go toolchains; versions from the library itself in images with no package database | `--scan-crypto-libraries` |
| Services and processes | Which crypto library each listening service and running process actually uses, including master/worker daemons such as Postfix; containers named by pod and namespace | `--scan-services`, `--scan-processes` |
| Service TLS settings | Each server daemon's own TLS groups and protocol range (nginx, Apache, HAProxy, stunnel, Squid, Postfix, Dovecot, PostgreSQL, MariaDB/MySQL, Redis/Valkey, OpenLDAP, 389 DS, Tomcat), which override the system policy | `--scan-service-configs` (implied by `--scan-services`) |
| Certificates and keys | Trust store and service certificates by algorithm OID, private keys (metadata only), Java keystores | `--scan-trust-store`, `--scan-crypto-material` |
| Packages and signing keys | Installed packages with bundled crypto (rpm, dpkg, apk, opkg and pacman, read directly, including OpenWrt and Yocto images); package-manager signing keys | `--scan-packages`, `--scan-signing-keys` |
| Boot chain | Secure Boot certificates, kernel module signing, IMA/EVM, TPM | `--scan-boot-chain` |
| Kerberos, VPN, DNSSEC | Kerberos encryption types and PKINIT; WireGuard pre-shared keys and OpenVPN groups; DNSSEC signing algorithms | `--scan-kerberos`, `--scan-tunnels`, `--scan-dnssec` |
| Performance | ML-KEM, ML-DSA, SLH-DSA and classical throughput; loopback TLS 1.3 handshakes | `--bench`, `--bench-tls` |

The [SARIF rule pages](docs/rules/README.md) list every finding the scan can
raise. [docs/scope.md](docs/scope.md) explains where a host scanner fits next
to network, source-code and dependency scanners.

## Output formats

| Flag | Output | For |
| --- | --- | --- |
| (none) | Text report | People |
| `--markdown` | Markdown report | Tickets |
| `--json` | Versioned JSON ([field reference](docs/json-output.md)) | Automation, fleet aggregation |
| `--cbom` | CycloneDX 1.7 CBOM (`--cbom-version 1.6` for 1.6) | Cryptographic inventory |
| `--spdx` | SPDX 3.0.1 JSON-LD | SPDX tooling |
| `--sbom` | Plain CycloneDX 1.6 package SBOM | SBOM and supply-chain graph tools |
| `--sarif` | SARIF 2.1.0 findings | Security and code-scanning pipelines |
| `--ndjson` | OCSF 1.9.0 events, one per line | SIEMs |
| `--prometheus` | Prometheus text format | node_exporter, dashboards |
| `--ansible` | `ansible_facts` wrapper | Ansible `set_fact` |
| `--recommend` | Algorithm recommendation per policy and role | Migration planning |

Details of each format, including CBOM contents and SARIF rule groups:
[docs/output-formats.md](docs/output-formats.md).

## CLI flags

Every flag, by purpose. [docs/cli-reference.md](docs/cli-reference.md) has the
full description of each; `pqc-readiness --help` prints them too.

| Purpose | Flags |
| --- | --- |
| Deeper scans | `--scan-packages`, `--scan-trust-store` (`--trust-store-max-certs N`), `--scan-crypto-material` (`--crypto-material-path PATH`, `--crypto-material-max-files N`), `--scan-signing-keys`, `--scan-services`, `--scan-service-configs`, `--scan-processes`, `--scan-crypto-libraries`, `--scan-boot-chain`, `--scan-kerberos`, `--scan-tunnels`, `--scan-dnssec` |
| Benchmarks | `--bench`, `--bench-tls`, `--threads N`, `--seconds N` |
| What to scan | `--host-mount PATH` (a live host mounted into a container), `--root PATH` (an offline image or rootfs), `--host-name NAME` (the name to report, e.g. for an offline tree) |
| Output format | `--json`, `--markdown`, `--cbom`, `--spdx`, `--sbom`, `--sarif`, `--ndjson`, `--prometheus`, `--ansible` |
| Output shaping | `--cbom-version {1.7,1.6}`, `--cbom-profile {none,federal-draft}`, `--cbom-interop {none,dependency-track,sbom-only}`, `--cbom-namespaced-properties`, `--sarif-anchor PATH`, `--inventory-metadata FILE` |
| Recommendations | `--recommend`, `--policy {cnsa-2.0,nist-civilian,eu-anssi-bsi,commercial,auto}`, `--role {tls-server,tls-client,signing-service,firmware-signing,generic}` |
| Gates | `--check {excellent,good,marginal,poor,cnsa-2.0}`, `--fips-strict` |
| Where output goes | `--output FILE`, `--save`, `--quiet`, `--no-color` |
| Fleet | `--aggregate DIR`, `--aggregate-format {json,csv}`, `--observations FILE`, `--observations-max-age-days DAYS` |
| Other | `--debug`, `--version`, `-h` / `--help` |

## Distribution support

| Tier | Distros | Validation cadence |
| --- | --- | --- |
| **1** | RHEL 9, RHEL 10, Ubuntu 24.04 LTS, Debian 12 | Every PR runs the suite on the GitHub-hosted runner under CPython 3.11, 3.12 and 3.13 (`.github/workflows/ci.yml`) and inside the UBI 10 and Debian 12 images (`.github/workflows/ci-containers.yml`). Booted-image validation runs before probe changes merge ([testing](docs/testing.md#booted-vm-matrix)). |
| **2** | Fedora (latest), Rocky / AlmaLinux 9 and 10, Ubuntu 26.04 LTS, Debian 13, SLES 15 SP6+, RHEL 8, Rocky 8, AlmaLinux 8 | Weekly: `.github/workflows/ci-tier2-weekly.yml` runs the suite in each distro's stock container image every Monday. **EL8 runs on every PR instead:** `.github/workflows/ci-ubi8.yml` runs the suite under AppStream `python3.9` in the UBI 8 image (a container image, not a booted EL8 host). |
| **Embedded** | OpenWrt 24.10 and 25.12, Yocto (rpm and opkg images), Buildroot | Offline `--root` scans checked against the official OpenWrt 24.10.8 and 25.12.5 and Yocto 6.0.3 images and a Buildroot 2026.08 build: package inventories and SBOMs match each image's own package list, and library versions match the build's. OpenWrt also runs the scan live with the full `python3` package. |
| **3** | Arch, Alpine, others | Best effort, community supported |

Tiers describe how each distribution is tested, not a support contract.
PQC needs **OpenSSL 3.5 or newer**; on older OpenSSL the scan still
inventories the host and says how to get a PQC-capable OpenSSL for that
distribution. Windows, WSL and BSD are out of scope; macOS is best effort.

**RHEL 8, Rocky 8 and AlmaLinux 8** ship Python 3.6, which the scanner does
not support. Running the zipapp directly fails with
`/usr/bin/env: 'python3': No such file or directory` or a syntax error, and
the `pqc-readiness` launcher exits 127 with this fix:

```bash
sudo dnf module install -y python39   # or, on EL 8.8+: sudo dnf install -y python3.11
```

**SLES 15 and openSUSE Leap 15** also ship Python 3.6. Install a newer
interpreter alongside it; the launcher finds it:

```bash
sudo zypper --gpg-auto-import-keys ref
sudo zypper -n in python311
```

**OpenWrt** needs the full `python3` package. `python3-light` reports a
supported version but leaves out standard-library modules; the launcher
detects that and exits 127 with this fix:

```bash
opkg update && opkg install python3   # OpenWrt 24.10 and earlier
apk update && apk add python3         # OpenWrt 25.12 and later
```

## Deploying at scale

- **Single file:** copy `pqc-readiness.pyz` to each host, or run it from
  Ansible ([docs/ansible.md](docs/ansible.md),
  [playbooks](deploy/ansible/)).
- **Containers, OpenShift and Kubernetes:** UBI 10, UBI 8 and Debian
  images (`ghcr.io/aclater/pqc-readiness`) published with each release,
  signed and carrying build provenance and a CycloneDX SBOM attestation; a
  systemd quadlet for a daily scan, and a least-privilege DaemonSet (non-root,
  no added capabilities, read-only host mounts) for OpenShift and for
  Kubernetes, RKE2, K3s and Rancher-managed clusters, with opt-in overlays for
  the service scan and for per-node summaries.
- **Offline images:** `--root PATH` scans a container rootfs or mounted disk
  image without running anything from it.
- **Fleet rollup:** `--aggregate DIR` combines saved JSON reports, and
  `--observations FILE` joins what network-side tools saw endpoints negotiate.

All of these are described in [docs/deployment.md](docs/deployment.md).
Integration recipes for Dependency-Track, DefectDojo, ServiceNow, Event-Driven
Ansible, ACM and the Compliance Operator, SUSE Multi-Linux Manager and SBOM
graph tools are in [docs/integrations/](docs/integrations/README.md).
To feed cryptographic posture platforms, see
[docs/integrations/posture-platforms.md](docs/integrations/posture-platforms.md).

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Excellent: dedicated PQC silicon, or optimised SIMD and ample RAM |
| 1 | Good: software PQC fast enough for production |
| 2 | Marginal: works, but plan for an accelerator at scale |
| 3 | Poor: software only, and too slow for production |
| 4 | `--check` or `--fips-strict` threshold not met |
| 5 | `--output FILE` could not be written after the scan ran |

`--ansible` always exits 0. Usage errors exit 2 before scanning. See
[docs/cli-reference.md](docs/cli-reference.md#exit-codes).

## How it's tested

Probes are tested against data captured from real hosts, every output format
is validated against its official schema, CI runs the suite inside UBI 8,
UBI 10 and Debian images on every PR and inside each Tier 2 distribution
weekly, and probe changes are run on booted cloud images of every supported
distribution before they merge. Details: [docs/testing.md](docs/testing.md).

## Documentation

| Topic | Document |
| --- | --- |
| Every flag and exit code | [docs/cli-reference.md](docs/cli-reference.md) |
| Output formats | [docs/output-formats.md](docs/output-formats.md) |
| JSON field reference | [docs/json-output.md](docs/json-output.md) |
| SARIF rules | [docs/rules/](docs/rules/README.md) |
| Example output across 20 distributions | [docs/examples/os-matrix-2026-10.md](docs/examples/os-matrix-2026-10.md) |
| Example output from a live OpenShift 4.22 node | [docs/examples/openshift-4.22-live.md](docs/examples/openshift-4.22-live.md) |
| Example output from a live Rancher-managed RKE2 cluster | [docs/examples/rancher-rke2-live.md](docs/examples/rancher-rke2-live.md) |
| Deployment: containers, OpenShift, Kubernetes / RKE2 / K3s, offline images, fleet rollup | [docs/deployment.md](docs/deployment.md) |
| OpenShift service-scan overlay | [docs/openshift-services-overlay.md](docs/openshift-services-overlay.md) |
| Ansible | [docs/ansible.md](docs/ansible.md) |
| Integrations | [docs/integrations/](docs/integrations/README.md) |
| Posture platforms (CBOM import) | [docs/integrations/posture-platforms.md](docs/integrations/posture-platforms.md) |
| SIEM (OCSF NDJSON) | [docs/siem-ndjson.md](docs/siem-ndjson.md) |
| Prometheus and Grafana | [docs/prometheus.md](docs/prometheus.md) |
| SARIF in code scanning | [docs/sarif-code-scanning.md](docs/sarif-code-scanning.md) |
| Endpoint observations | [docs/endpoint-observations.md](docs/endpoint-observations.md) |
| Recommendation policies | [docs/recommendation-policies.md](docs/recommendation-policies.md) |
| Inventory methodology (OMB M-23-02) | [docs/inventory-methodology.md](docs/inventory-methodology.md) |
| CycloneDX schema alignment | [docs/schema-alignment.md](docs/schema-alignment.md) |
| Where this tool fits | [docs/scope.md](docs/scope.md) |
| Testing methodology | [docs/testing.md](docs/testing.md) |
| Technical findings: FIPS algorithm fence | [docs/findings/fips-algorithm-fence.md](docs/findings/fips-algorithm-fence.md) |
| Release notes | [CHANGELOG.md](CHANGELOG.md) |
| Contributing | [CONTRIBUTING.md](CONTRIBUTING.md) |

## License

Apache-2.0. See [LICENSE](LICENSE).
