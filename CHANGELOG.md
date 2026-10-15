# Changelog

Release notes for `pqc-readiness`, newest first. Each release says what
changed in the results, what's new, how to upgrade and what is still
limited. The [README](README.md#latest-release) carries a short summary
of the latest release.

Downloads (`pqc-readiness.pyz` and its `.sha256`) are on the
[GitHub releases page](https://github.com/aclater/pqc-readiness/releases).
JSON reports carry `schema_version`. The fleet aggregator only merges
reports with the same schema version, so re-scan after an upgrade that
changes it.

| Version | Date | JSON schema |
| --- | --- | --- |
| [2.3.0](#230---2026-10-14-host-accurate-results-embedded-systems-and-joinable-outputs-schema-17) | 2026-10-14 | 1.7 |
| [2.2.0](#220---2026-10-13-deployment-gap-verdict-and-pqc-failure-findings-schema-16) | 2026-10-13 | 1.6 |
| [2.1.0](#210---2026-10-13-one-package-configuration-aware-detection-schema-15) | 2026-10-13 | 1.5 |
| [Before 2.1.0](#before-210---2026-10-13-accuracy-fixes-faster-scans-schema-14) | 2026-10-13 | 1.4 |

## Unreleased

- **Under `--host-mount` and `--root`, IPsec facts describe the host**
  (#265). `ipsec_pqc` used to run the scanner image's `swanctl` / `ipsec`,
  which images don't ship, so a node running strongSwan or Libreswan was
  reported as having no IPsec stack; offline scans reported only the
  configured proposals. The implementation, version and ML-KEM capability
  now come from the host's package and binaries, with the same treatment
  for live hosts that have the daemon but no CLI. strongSwan counts as
  ML-KEM-capable from 6.0 with the `ml` plugin, or with the `openssl`
  plugin on OpenSSL 3.5+ (Fedora 44 and Ubuntu 26.04 list ML-KEM from the
  `openssl` plugin); Libreswan from 5.4, its version read from `pluto`.
  New nested fields: `ipsec_pqc.version_source`, `package`, `binaries`,
  `plugins` and `cli_probe`; live strongSwan scans now report `version`
  from `swanctl --version`.

## 2.3.0 - 2026-10-14: host-accurate results, embedded systems and joinable outputs, schema 1.7

Version **2.3.0**. All JSON changes are additive, so the schema goes to
**1.7**. The fleet aggregator only merges reports with the same
`schema_version`, so re-scan before mixing old and new reports.

### Upgrade notes

- **Package identifiers (purls) are canonical now** (#243). `+` is written
  `%2B` and a Debian epoch keeps its `:` (it was `%3A`), per ECMA-427
  clause 5.4, in both `--sbom` and `--cbom`. Tools that compare purls as
  strings will see these as new identifiers once; spec-conformant tools
  decode both forms to the same package. `deploy/cbom/cbom_tools.py
  join-packages` decodes before comparing, so it joins either form.
- **Under `--host-mount`, OpenSSL facts describe the host** (#228). Every
  DaemonSet and quadlet deployment uses `--host-mount`, and until now
  `openssl.version` and `pqc_native` were the scanner image's. They now come
  from the host's OpenSSL package or libcrypto (`openssl.version_source`).
  The CLI-only lists (algorithms, TLS groups, providers) are `null`, with
  the reason in `openssl.cli_probe`. As a result **CNSA 2.0 reads `partial`
  instead of `compliant`** in container scans: the old `compliant` came
  from the image's algorithm lists, not the host's. OpenSSH is read from
  the host the same way (#256): `ssh_pqc.version` and its kex list come
  from the host's binaries or package, so a node can lose an ML-KEM kex it
  was wrongly credited with (an Ubuntu 24.04 node has only sntrup761).
- **Re-scan your fleet** after upgrading: schema 1.7 reports won't merge
  with 1.6 ones.

### New detections

- **Per-service TLS configuration** (#216). `--scan-service-configs`
  (implied by `--scan-services`) reads the TLS settings of nginx, Apache
  httpd, HAProxy, stunnel, Squid, Postfix, Dovecot, PostgreSQL,
  MariaDB/MySQL, Redis/Valkey, OpenLDAP, 389 Directory Server and Tomcat,
  following includes, live, offline and under `--host-mount`. A daemon that
  pins classical groups decides its own deployment-gap verdict, and SARIF
  rule `pqc-021` reports each blocked endpoint with file and line. New
  top-level key `service_tls_config`; new Prometheus metric
  `pqc_readiness_service_tls_endpoints`. On booted Rocky 9, CentOS Stream
  10, Fedora 44 and Ubuntu 26.04, the verdict matched the group an ML-KEM
  client actually negotiated on all 50 endpoints compared.
- **Embedded and minimal systems** (#217). OpenWrt is its own OS family.
  Families without a package tool (OpenWrt, Yocto, Buildroot) are
  inventoried from whichever package database the tree has (rpm, dpkg, apk,
  opkg or pacman), and package-less trees take library versions from the
  strings the libraries embed. New Mbed TLS probe. OpenSSL-compatible forks
  are no longer mistaken for OpenSSL. Checked against OpenWrt 24.10.8 and
  25.12.5, Yocto 6.0.3 and a Buildroot 2026.08 image.
- **Offline `--root` scans report sshd's key exchange** (#247). The tree's
  `sshd_config` and its `Include` chain are parsed inside the root (never
  `sshd -T`), and OpenSSH's PQC capability comes from the kex methods
  compiled into the tree's binaries (`sshd.openssh_kex_evidence`), which
  keeps distro backports right. The SSH gap row and `pqc-010` now work
  offline. On booted Rocky 9, Fedora 44, Ubuntu 26.04, Leap 16 and
  Tumbleweed images, the parsed list equals `sshd -T` and the binary's PQC
  methods equal `ssh -Q kex`.
- **Findings name the container and pod** (#233). A listener in a
  Kubernetes container used to be named by its `crio-<64 hex>.scope` unit.
  `--scan-services` now reports each listener's `container` (runtime, ID,
  pod UID, and pod, namespace and container names from the kubelet's
  `/var/log/containers` entries, a directory listing only), and SARIF/NDJSON
  messages name the pod. Both DaemonSets mount `/var/log/containers`
  read-only.
- **Process groups name their containers and pods** (#262).
  `--scan-processes` groups carry `containers` (the same identity listeners
  got in #233, at most ten per group, plus `containers_omitted`) and
  `container_processes`. The text report and `pqc-020` client entries name
  a group in one container as e.g. `proxy (pod shop/web-0)`.
- **Postfix and other master/worker daemons get a verdict** (#240). A
  listener whose owner maps no TLS library takes its libraries from a worker
  holding the socket, a descendant process, or the libraries a worker
  executable links, and says which in
  `service_crypto_linkage.listeners[].crypto_libraries_from`.
- **Hosts with libcrypto but no `openssl` CLI** (OpenWrt, minimal images)
  report the library's version instead of "openssl not on PATH", so
  `pqc-001` fires for a pre-3.5 library (#225).

### Results that were wrong, now fixed

- **OpenSSL version and PQC capability in container scans** came from the
  scanner image (#228, see the upgrade notes). On OpenShift 4.22 the scan
  now reports the node's OpenSSL 3.5.5, which sshd and haproxy actually
  load, instead of the image's 3.5.8.
- **OpenSSH version and kex list in container scans** came from the
  scanner image (#256): every DaemonSet scan reported the image's OpenSSH
  9.9p1 and its ML-KEM kex, though a Leap 16 node runs 10.0p2 and an
  Ubuntu 24.04 node (9.6p1) has only the sntrup761 hybrid. They now come
  from the host's binaries, with its OpenSSH package as the version
  fallback (`ssh_pqc.version_source`, `kex_source`, `package`, `binaries`,
  `cli_probe`, `scanner_cli_version`). Offline `--root` scans now answer
  `ssh_pqc` from the tree, and a host with sshd but no `ssh` client is no
  longer reported as having no OpenSSH. Kex names read from binaries now
  count only when the binary's kex table points at them, which is exact
  on Alpine too: the list equals `ssh -Q kex` on Fedora 44, Rocky 9, Leap
  16, Ubuntu 24.04, Debian 13 and Alpine 3.22.
- **An unreadable path no longer aborts the scan** (#229). On Python
  3.9-3.12, one directory the scanner couldn't read ended the run with a
  traceback. Now only the detection that needed it is affected, and an
  opt-in scan that hits one reports `available: false` with the path.
- **Unreadable config files are no longer reported as missing** (#232). An
  unprivileged scan of a host whose `sshd_config` is `0600 root` said "no
  sshd_config found". sshd, crypto-policies, `openssl.cnf` and the service
  TLS readers now tell absent from unreadable, with the file named in
  `reason` and new `unreadable` and `missing` lists, and the SSH gap row is
  `unknown` with a note instead of `not_present`.
- **Offline `--root` scans never describe the scanning machine** (#258). A
  tree without `os-release` was reported as the scanner's own kernel; now
  its OS comes from `/etc/buildinfo` (Yocto) or `/etc/openwrt_release`, or
  is `null` with a reason (`os_release.source`, `os_release.reason`). The
  package manager and repository architecture come from the tree, and
  absolute symlinks inside a tree resolve inside it everywhere: an
  `/etc/os-release -> /usr/lib/os-release` link used to report the scanning
  machine's OS, and linked certificates, libraries, JDKs, the rpm database
  and config directories were read from the scanning machine.
- **Offline scans never write to the scanned tree** (#224). A WAL rpm
  database is opened read-only and immutable, so no `rpmdb.sqlite-shm` is
  created in the tree.
- **Reports from a DaemonSet name the node, not the pod** (#220), from
  `PQC_HOSTNAME` (set from `spec.nodeName`) or the host's `/etc/hostname`.

### Outputs

- **CBOMs and SBOMs name every package the same way** (#222, #257). CBOM
  library components carry the exact purl `--sbom` emits (full
  version-release, `arch`, `epoch`, the package database kind, Yocto
  recipes, OpenWrt opkg/apk types), so a purl join between a host's CBOM
  and SBOM matches on every family. `packages.bundled_crypto` and
  `crypto_libraries.libraries.<lib>.packages` gain `release`, `epoch` and
  `arch`.
- **`--sbom` covers OpenWrt and Yocto** (#227): 129 of 129, 136 of 136 and
  444 of 444 packages on the official OpenWrt 24.10.8, 25.12.5 and Yocto
  6.0.3 images, matching each image's own package list.
- **`--host-name NAME`** names the host in every output and every scan mode
  (#222); offline trees without `/etc/hostname` no longer come out as
  `host/unknown`.
- **`--cbom-namespaced-properties`** (opt-in) prefixes every CBOM property
  name with `pqc-readiness:` (#222).

### Deployment

- **Kubernetes, RKE2, K3s and Rancher** (#219). `kubectl apply -k
  deploy/kubernetes` runs the OpenShift DaemonSet with Pod Security
  Admission labels in place of the SCC; `deploy/kubernetes/services` is the
  opt-in service-scan variant. Live run on a Rancher-managed RKE2 cluster
  (Rocky Linux 10.2 and openSUSE Leap 16.0 nodes) in
  [docs/examples/rancher-rke2-live.md](docs/examples/rancher-rke2-live.md).
- **OpenShift manifests work on a fresh cluster** (#220): `oc apply -k
  deploy/openshift` creates the namespace, the SCC allows the
  `RuntimeDefault` seccomp profile the pod requests, and reports go to an
  `emptyDir`. Live run on OpenShift 4.22 with the Compliance Operator in
  [docs/examples/openshift-4.22-live.md](docs/examples/openshift-4.22-live.md).
- **The launcher spots a stripped Python** (#226). An interpreter that
  reports 3.9+ but lacks standard-library modules the scanner needs
  (OpenWrt's `python3-light`) is skipped, with an OpenWrt install hint
  (`opkg install python3` up to 24.10, `apk add python3` from 25.12).

### Supply chain

- **Every image carries an SBOM attestation** (#230). The services image
  now gets its CycloneDX SBOM attestation like the others, and the
  published 2.2.0 services image was backfilled without a rebuild through a
  new attest-only dispatch mode (#251).
- **CI runs independent static analysis** (#235): CodeQL (security-extended)
  and Semgrep community rules on every PR, and every workflow action is
  pinned to a commit SHA, kept current by Dependabot.
- **A second model reviews every PR** (#238), and its comments are answered
  before merging.

### Known limitations

- The federal CBOM profile waits on CISA/NIST's minimum CBOM elements,
  expected around March 2027 (#150).
- wolfSSL in package-less images embeds no matchable version string, so
  its version stays undetermined.
- Under `--host-mount`, IPsec tool versions still come from the scanner
  image (#265).

## 2.2.0 - 2026-10-13: deployment-gap verdict and PQC failure findings, schema 1.6

Version **2.2.0**. All JSON changes are additive, so the schema goes to
**1.6**. The fleet aggregator only merges reports with the same
`schema_version`, so re-scan before mixing old and new reports.

### The deployment-gap verdict

Each host now carries `pqc_deployment_gap` (#107). It rates TLS, SSH,
IPsec, each crypto-linked listening service (#107) and each outbound
client process group (#202) as one of:
- **deployed:** the software can do PQC and is configured to;
- **capable but not configured:** an upgrade isn't needed, a configuration
  change is;
- **configured but not capable;**
- **not capable;**
- **unknown** or **not present.**

Every state carries JSON paths to the fields that decided it, and it is
computed only from what the scan already collected. With `--aggregate
--observations`, the fleet rollup adds what endpoints were actually
observed negotiating (#149). SARIF/NDJSON rule `pqc-020` reports
"capable but not configured".

On booted VMs:
- **Rocky 9.8, DEFAULT policy:** TLS and SSH capable but not configured,
  observed classical.
- **Rocky 9.8 after `DEFAULT:PQ`:** deployed, observed hybrid.
- **Fedora 44:** deployed. A Go client run with `GODEBUG=tlsmlkem=0` is
  flagged as capable but not configured.

### Software that will fail at PQC is now flagged

Detections that find software unable to do PQC now raise a SARIF/NDJSON
finding, not just a JSON field (#193):

| Rule | Flags |
|---|---|
| `pqc-011` | A listening service on a crypto library without PQC |
| `pqc-012` | A Go service without hybrid ML-KEM (old Go, or `tlsmlkem=0`) |
| `pqc-013` | An installed crypto library, JDK or Go toolchain without PQC |
| `pqc-014` | A library with only pre-standard ML-KEM |
| `pqc-015` / `pqc-016` | IPsec proposals the stack can't run, or classical-only IKE |
| `pqc-017` | Packages bundling crypto without PQC |
| `pqc-018` | PQC capability that couldn't be determined (never reported as a failure) |
| `pqc-030` | A classical boot chain (#112) |
| `pqc-031` | Deprecated or 128-bit-only Kerberos enctypes, classical PKINIT (#109) |
| `pqc-032` | A WireGuard peer without a pre-shared key (#113) |
| `pqc-033` | An OpenVPN configuration that can't negotiate PQC (#113) |
| `pqc-034` | Classical-only DNSSEC signing (#113) |
| `pqc-010` | sshd not offering a PQC key exchange that OpenSSH supports (#105) |

On booted VMs this flagged sshd, rpcbind and chronyd on AlmaLinux 8.10;
libgcrypt, libssh and a JDK 17 install on Rocky 9.8; and on Fedora 44 a
Go 1.26 binary whose `go.mod` line `go 1.22` silently turns ML-KEM off
(#193). Every rule has a help page under [docs/rules/](docs/rules/)
(#179).

### New detections

- **sshd's effective configuration** (#105): the key exchanges the server
  actually offers, and host keys read from `.pub` files only. On six VM
  images the config-file path matched `sshd -T` exactly.
- **`--scan-crypto-libraries`** (#110): GnuTLS, libgcrypt, libssh,
  wolfSSL, AWS-LC, JDKs and Go, judged from the algorithm names inside the
  library file. Rocky 9.8's GnuTLS turned out to be PQC-capable, which a
  version check alone would miss.
- **`--scan-processes`** (#155): every process, including outbound-only
  TLS clients, attributed to the crypto library or Go runtime it has
  loaded. On Fedora 44 and Rocky 9.8 every process matched a
  `/proc/*/maps` ground truth.
- **`--root PATH`** (#152): scan a mounted disk image or an extracted
  container filesystem without running anything from it. On six container
  images the package list matched the image's own package manager
  exactly.
- **`--scan-boot-chain`** (#112): Secure Boot keys, kernel module signing,
  IMA/EVM, lockdown, and TPM 2.0 v1.85 ML-KEM / ML-DSA support.
- **`--scan-kerberos`** (#109): `krb5.conf` / `kdc.conf` enctypes, keytab
  entries (key bytes never read into the report) and PKINIT.
- **`--scan-tunnels` and `--scan-dnssec`** (#113): WireGuard pre-shared
  key presence (never key values), OpenVPN key exchange, DNSSEC signing
  algorithms in BIND, Knot and PowerDNS, and Unbound / systemd-resolved
  validation settings. Root-only configs scanned without root raise
  `pqc-018` instead of silently reporting nothing.
- **Ubuntu's `crypto-config`** (#170) is now read by `crypto_policy`. Its
  profiles set no TLS groups, so PQC key exchange is reported as the
  library default (`null`), not as blocked.

### Outputs and integrations

- **CBOM:** host certificates found by `--scan-crypto-material` (#178),
  crypto libraries with the algorithms they provide, and listening
  services linked to the library they load (#194).
- **`--cbom-interop dependency-track`** (#175): crypto details survive
  Dependency-Track 5.x, which otherwise keeps only the asset name. In a
  real 5.2.0 instance all 458 components and 3,047 mirrored properties
  survived a re-export. `sbom-only` is the one shape 4.14.5 ingests.
- **`--sbom`** (#157): a plain CycloneDX 1.6 package SBOM for SBOM graph
  tools that don't understand crypto assets.
- **Endpoint observations** (#149): `--aggregate DIR --observations FILE`
  joins what a network scanner saw an endpoint negotiate to the host and
  listening service, using a neutral, versioned record schema.
- **Recipes and samples** (#156, #157): ServiceNow Vulnerability Response
  import from the NDJSON findings; an Ansible playbook that fixes
  `pqc-008` through the RHEL `crypto_policies` system role; an
  Event-Driven Ansible rulebook; an ACM policy and Compliance Operator CEL
  rule fed by an opt-in per-node summary ConfigMap; a SUSE Multi-Linux
  Manager custom-info push.

### Deployment changes

- **Host `/usr` is mounted read-only** in the DaemonSet, the services
  overlay and the quadlet (#187). It replaces the narrower `os-release` and
  `crypto-policies` mounts, and lets SUSE's vendor sshd config in
  `/usr/etc/ssh` be read from the host.
- **Opt-in OpenShift services overlay** (#181), for fleet-wide
  `--scan-services` / `--scan-processes`. The base DaemonSet is unchanged
  and least-privilege. The overlay is a separate DaemonSet and SCC, still
  non-root, that drops all capabilities and adds back only
  `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH`. To make those effective for
  a non-root pod it sets **`allowPrivilegeEscalation: true`** and gives
  file capabilities to a dedicated interpreter copy (the system `python3`
  gets none). Only deploy it where that trade-off is acceptable.
- **Opt-in per-node summary overlay** (#157) writes one ConfigMap per
  node for ACM and the Compliance Operator. The base DaemonSet still has
  no API token or RBAC.

### Results that were wrong, now fixed

- **EL9/EL10 OpenSSL upgrade advice** (#184): EL9 hosts were told to move
  to RHEL 10. In fact EL 9.7 ships OpenSSL 3.5, while EL 10.0 only ships
  3.2.
- **Debian, Alpine and Arch package scans under `--host-mount`** read the
  scanner image's package database instead of the host's (#152).
- **SUSE sshd configuration in container mode** came from the scanner
  image, because SUSE keeps it under `/usr/etc` (#105, #187).

### Known limitations

- The federal CBOM profile waits on CISA/NIST's minimum CBOM elements,
  expected around March 2027 (#150).
- The OpenShift services and node-summary overlays are validated with
  strict schema checks and on VMs, but not yet on a live OpenShift
  cluster.
- The ServiceNow recipe and the SUSE Multi-Linux Manager push are tested
  against local harnesses, not live instances.

## 2.1.0 - 2026-10-13: one package, configuration-aware detection, schema 1.5

Version **2.1.0**. All JSON changes are additive, so the schema goes to
**1.5**. The fleet aggregator only merges reports with the same
`schema_version`, so re-scan before mixing old and new reports.

### Deployment changes: read first

- **`pqc_readiness.py` no longer exists** (#80). Run one of:
  - `pqc-readiness.pyz`, a single-file zipapp built with
    `python3 scripts/build_zipapp.py` (or `make dist`). It is stdlib only and
    needs Python 3.9 or newer.
  - The `pqc-readiness` wrapper, which prefers the `.pyz`.
  - `python3 -m pqc_readiness` from a checkout.

  Output and exit codes are unchanged: every output mode was compared
  byte for byte, including on booted Fedora 44, Rocky 9 and AlmaLinux 8
  VMs.
- **More read-only host mounts.** The DaemonSet and quadlet now also mount
  `/usr/share/crypto-policies`, because the crypto-policies back-end files
  are symlinks into it (#104).
- **Atomic file writes.** `--output` now writes every format atomically
  (#140).
- **Python install hints per distro.** When no Python 3.9+ is found, the
  wrapper's message now gives the right install command for SUSE, the
  RHEL 8 family or Debian/Ubuntu (#127).

### Results that were wrong, now fixed

- **Containers scanned the image, not the host.** With `--host-mount`,
  `--scan-trust-store` read the scanner image's own `/etc` (#108).
- **CNSA 2.0 recommendations passed hosts that don't qualify** (#139).
  - A host offering only ML-KEM-768 TLS groups used to pass the CNSA 2.0
    group check. It now gets a caveat.
  - X25519MLKEM768 and the other ML-KEM-768 groups are reported as not
    compliant in `cnsa_2_0.tls_key_exchange`. This is informational:
    `status` and `--check cnsa-2.0` exit codes are unchanged.
- **NIST IR 8547 was presented as final.** It is still a draft (#138,
  #139). The README also wrongly said IR 8547 references CycloneDX; the
  draft never mentions it (#139).
- **IPsec PQC support was misreported** (#154).
  - PQC-capable strongSwan showed `pqc: false`; the check never matched
    `ML_KEM_768`.
  - Libreswan was hard-coded to no PQC. It now reports PQC from version
    5.4.
- **Policy text corrected** (#141).
  - The ANSSI source linked to a quantum-key-distribution paper.
  - The CNSA 2.0 wording on hybrids now matches NSA's FAQ: permitted, not
    required.

### New: what the host is configured to do, not just what it can do

- **System crypto policy** (`crypto_policy`, #104). It is read from files,
  so it works under `--host-mount` and on SUSE. A new SARIF rule,
  `pqc-008`, fires when OpenSSL supports PQC but the policy blocks it.
  On booted VMs:
  - Rocky 9.8 and AlmaLinux 9.8 `DEFAULT` let no PQC through; `DEFAULT:PQ`
    enables it.
  - Rocky 10.2, Fedora 44 and Leap 16 `DEFAULT` already allow PQC.
- **OpenSSL effective configuration** (`openssl.config`, #106). It reports
  the config file and its includes, configured and third-party providers,
  and where the default TLS groups come from.
  - AlmaLinux 9.8 offers no PQC key exchange by default.
  - Rocky 10.2, Fedora 44 and Leap 16 do.
  - Debian 13 and Ubuntu 26.04 configs set no groups, so OpenSSL 3.5's
    built-in hybrid-first default applies.
- **Listening services and the crypto library each one loads**
  (`--scan-services`, #111). It covers the OpenSSL family, GnuTLS, NSS and
  wolfSSL, plus the Go version and default hybrid key exchange of static
  Go binaries. It only reads `/proc`. Every listener was attributed:
  16/16 on Fedora 44 and 12/12 on Rocky 9.8.
- **Certificates, private keys and Java keystores on disk**
  (`--scan-crypto-material`, #108).
  - Certificates: leaf or CA, key algorithm, PQC category, and whether they
    are valid past 2030 or 2035.
  - Private keys: metadata only. Key bytes never appear in any output
    format; this was checked on VMs across all 7 formats.
- **Package-signing trust anchors** (`--scan-signing-keys`, #153). It lists
  the public keys each package manager trusts (rpm, apt, pacman, apk) with
  their algorithm, including the PQC OpenPGP algorithms from RFC 9980. A
  new SARIF rule, `pqc-009`, fires when every trusted signing key is
  classical. RHEL 10.2 already trusts Red Hat's ML-DSA-87+Ed448 release
  key, while packages in the UBI 10 image were still RSA-signed.
- **Configured IKEv2 proposals** (`ipsec_pqc.configured`, #154). Each
  configured strongSwan and Libreswan proposal is classified for ML-KEM and
  RFC 9370 additional key exchanges. `capability_mismatch` flags ML-KEM
  connections the installed stack can't negotiate. RFC 9370 is final;
  ML-KEM in IKEv2 is still a draft.
- **RFC-assigned names and codepoints** for PQC TLS groups and SSH key
  exchanges (RFC 10024, RFC 10042), with draft/final status
  (`openssl.tls_group_references`, `ssh_pqc.kex_references`, #139).
- **Sourced migration timelines** in `--recommend`, as `policy_sources` plus
  a per-record `timeline` that includes the CNSA 2.0 deadline category
  (#141).

### New outputs and integrations

- **CycloneDX 1.7 is now the default CBOM** (#138). It adds algorithm
  families, TLS/SSH protocol components and certificate assets.
  `--cbom-version 1.6` is byte-identical to earlier releases.
- **Federal CBOM fields** (`--cbom-profile federal-draft` and
  `--inventory-metadata FILE`, #144). These cover EO 14412 / OMB M-26-15:
  key establishment vs signature, deadlines, TLS 1.3 status and OMB M-23-02
  item coverage. The profile is a data table, so it can be remapped when
  CISA/NIST publish the minimum CBOM elements (#150).
- **Prometheus output** (`--prometheus`, #140) for node_exporter's textfile
  collector, with an 8-panel Grafana dashboard. It was checked end to end
  with node_exporter and Prometheus. See [docs/prometheus.md](docs/prometheus.md).
- **SIEM events** (`--ndjson`, #146): OCSF 1.9.0 Device Inventory Info and
  Compliance Finding events, validated against the OCSF schema. Recipes for
  Splunk, Sentinel and Elastic are in
  [docs/siem-ndjson.md](docs/siem-ndjson.md).
- **Code-scanning SARIF** (`--sarif-anchor PATH`, #145) adds the locations,
  fingerprints and per-host categories that code-scanning upload needs.
  Without the flag, `--sarif` output is unchanged.
- **Tested integration recipes** for Dependency-Track and DefectDojo,
  written from real uploads (#147). See
  [docs/integrations/](docs/integrations/).
- **[Inventory methodology](docs/inventory-methodology.md)** that agencies
  can cite in M-26-15 migration plans (#142). It maps the scanner's output
  to the OMB M-23-02 inventory items.

### Upgrade notes for JSON consumers (schema 1.5)

- **New top-level objects:** `crypto_policy`, `crypto_material`,
  `service_crypto_linkage`, `signing_keys`, `inventory_metadata`.
- **New nested fields:** `openssl.config`, `openssl.tls_group_references`,
  `ssh_pqc.kex_references`, `cnsa_2_0.tls_key_exchange`,
  `trust_store.certificates`, `ipsec_pqc.configured`, `ipsec_pqc.note`.
- **New values:** `packages.source` can now also be `rpmdb-bdb` or
  `rpmdb-ndb`.

Nothing was renamed, removed or re-typed. See the
[version table](docs/json-output.md).

### Known limitations

- **Ubuntu 26.04's own crypto-policy framework isn't read yet** (#170).
- **Dependency-Track:**
  - 5.2.0 accepts the CBOM but drops the crypto details.
  - 4.14.5 accepts the upload and then fails silently (#175).
- **The CBOM lists trust-store certificates only.** Certificates found by
  `--scan-crypto-material` aren't included yet (#178).
- **SARIF help links point to rule pages that don't exist yet** (#179).
- **`--scan-services` can't see other users' processes** in the non-root
  DaemonSet without `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH`.
  Unreadable processes are counted, not guessed (#111). The default
  DaemonSet stays least-privilege. An opt-in DaemonSet variant with those
  two capabilities is tracked in #181 (shipped in 2.2.0).
- **The SIEM recipes haven't been run against live tenants** (#146).

### Under the hood

- **Package split** (#80): one module per area, with registries for
  output formats and per-module command-line flags. A test guard
  rejects patches on the package root. The `.pyz` runs the full test
  suite in CI, including inside the UBI 8/10 and Debian images.
- **Formatting enforced** (#122): repo-wide `ruff format`, and every
  pre-commit hook runs in CI.
- **Tests:** from 688 to 1,229.

## Before 2.1.0 - 2026-10-13: accuracy fixes, faster scans, schema 1.4

This release fixes results that were wrong on current platforms, so
**re-scan your fleet**. Older reports can't be aggregated with new ones,
because the fleet aggregator only merges reports with the same
`schema_version`. It moves through schema versions 1.1 → 1.4; see
[Upgrade notes](#upgrade-notes-for-json-consumers).

### Results that were wrong, now fixed

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

### New

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

### Faster

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

### Validated on real hosts

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

### Upgrade notes for JSON consumers

| Schema | Change |
|---|---|
| `1.2` | `benchmark`, `benchmark_tls_handshake`, `memory_bandwidth_method` are `null` when not run (previously `{}` / `""`). `trust_store` gained `total_found`, `scanned_count`, `max_certs`, `truncated`. |
| `1.3` | Benchmark entries can carry `skipped`; RSA KEM/signature baseline rows added. **`trust_store` counts are now unique certificates, not files**, so they aren't comparable with older reports. |
| `1.4` | `packages.source` (`rpmdb-sqlite` or `rpm-cli`) and `packages.db_root` show which database was read. |

Nothing was renamed or removed. The full field reference is in
[docs/json-output.md](docs/json-output.md).

### Known limitations

- **Stock SLES 15 / openSUSE Leap 15** ship only Python 3.6, so the
  scanner exits 127 until a newer interpreter is installed (#127). The
  prerequisite is now documented under [Distribution
  support](README.md#distribution-support), and the wrapper prints the SUSE
  install commands (resolved in 2.1.0).
- RHEL cloud images need a Red Hat login to download, so they were checked as UBI containers.
  Rocky and AlmaLinux stood in for booted RHEL 8 hosts.

### Under the hood

- CI pins `ruff` / `mypy` so tool upgrades can't break unchanged code
  (#97). `detect-secrets` runs in CI (#94).
- The full test suite runs inside the UBI 8, UBI 10 and Debian images
  on every PR (#84). A weekly workflow covers Fedora, Rocky/AlmaLinux 9
  and 10, Debian 13, Ubuntu 26.04 LTS and SLES (#83, #115).
- `main()` was split into parser, collection, rendering and exit-code
  steps, guarded by a golden-output test (#80, first step towards the
  package split).
- Tests went from 351 to 688.
