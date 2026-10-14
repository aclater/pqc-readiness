# CLI reference

Every flag `pqc-readiness` accepts, grouped by purpose. `pqc-readiness --help`
prints the same flags with one-line descriptions.

## Probes and benchmarks

| Flag | Purpose |
| --- | --- |
| `--bench` | OpenSSL microbenchmark (PQC + classical). |
| `--bench-tls` | Loopback TLS 1.3 handshake bench (classical / hybrid / pure-PQC). |
| `--threads N` | Add an N-way scaling test alongside the single-thread bench. |
| `--seconds N` | Override per-operation benchmark duration. Larger values reduce variance at the cost of run time. |
| `--scan-trust-store` | Walk system trust-store directories and classify every certificate (bundles included) as PQC, hybrid composite, or classical by reading its algorithm OIDs directly; no `openssl` binary needed. |
| `--trust-store-max-certs N` | Cap on unique certificates classified by `--scan-trust-store` (default 500). When the cap is hit, `trust_store.truncated` is `true` and the text, CBOM, and SARIF outputs say how many certificates were not inspected. |
| `--scan-crypto-material` | Discover certificates (leaf and CA, key algorithm and size, PQC category, expiry and 2030/2035 flags), private keys and Java keystores under common service paths. Private keys are reported as **metadata only** (PEM header type, file SHA-256, permission bits, and the key algorithm from a matching certificate); key content is never read into the report. See [`crypto_material`](json-output.md#crypto_material). |
| `--crypto-material-path PATH` | Host path to search with `--scan-crypto-material` (repeatable; replaces the default list). Honours `--host-mount`. |
| `--crypto-material-max-files N` | Cap on candidate files examined by `--scan-crypto-material` (default 5000); `crypto_material.truncated` is set when the cap is hit. |
| `--scan-packages` | Enumerate installed packages with bundled crypto. Branches on family: the rpm database (rhel / suse; SQLite, Berkeley DB and ndb databases are all read in-process for the inventory, with `rpm -qa` only as the fallback for an unreadable database), `dpkg-query -W` (debian), `pacman -Q` (arch), `apk info -v` (alpine). Families with no registered tool (OpenWrt, Yocto, Buildroot, unknown) are inventoried in-process from whichever database exists: rpm, dpkg, apk, opkg or pacman (opkg as `opkg list-installed` counts it). Normalises to `[{name, version}, ...]`. Under `--host-mount` the host's rpm database is read; the DaemonSet and quadlet mount `/var/lib/rpm` read-only for this. |
| `--scan-services` | Map each listening TCP socket and bound UDP socket to the process that owns it and the crypto library that process actually maps (OpenSSL and its forks, GnuTLS, NSS, wolfSSL), or for Go binaries the toolchain version and its default hybrid key exchange. Reads `/proc` only, with no network connections; bounded by a process cap and a time budget. Needs root, or CAP_SYS_PTRACE and CAP_DAC_READ_SEARCH, to see other users' processes, and hostPID plus `--host-mount` in a container. Output: `service_crypto_linkage` ([json-output.md](json-output.md#service_crypto_linkage)). Also runs `--scan-service-configs`, so each listening service is judged on its own TLS configuration. |
| `--scan-service-configs` | Read the TLS settings of common server daemons (nginx, Apache httpd, HAProxy, stunnel, Squid, Postfix, Dovecot, PostgreSQL, MariaDB/MySQL, Redis/Valkey, OpenLDAP, 389 Directory Server, Tomcat), following their includes: per endpoint, the key-exchange groups, where they come from (the config, a default compiled into the service, or the TLS library), the protocol range, ciphers and certificate paths, and whether hybrid ML-KEM is offered. A service's own group list overrides the system crypto policy. Built-in defaults that differ from OpenSSL's are applied by version (Postfix before 3.11, PostgreSQL) or read from the binary (stunnel). Files only, no subprocess; works with `--root` and `--host-mount`. With `--scan-services`, config files a running haproxy or stunnel was started with (`-f`, or stunnel's config argument) are read too, even outside the standard paths. Output: `service_tls_config` ([json-output.md](json-output.md#service_tls_config)); SARIF [`pqc-021`](rules/pqc-021-service-config-blocks-pqc.md). |
| `--scan-processes` | Map **every** running process, including outbound-only TLS clients a service scan never sees, to the crypto library or Go runtime it has loaded, grouped by executable and library version (`process_crypto_linkage`). Groups that cannot do PQC are listed first and counted in the summary. Reads `/proc` only; run as root for other users' processes (otherwise they're counted as unreadable). Not available with `--root`. |
| `--scan-signing-keys` | Inventory the package manager's trusted signing keys: rpm `gpg-pubkey` entries (read in-process from sqlite / Berkeley DB / ndb) and repo `gpgkey=file://` files, apt `trusted.gpg(.d)` and `signed-by` keyrings, pacman keyrings, apk keys. Reports algorithm, size or curve, fingerprint and RFC 9980 PQC category (`signing_keys` in JSON; SARIF `pqc-009` when every key is classical). Public keys only. |
| `--scan-crypto-libraries` | Report PQC support in GnuTLS, libgcrypt, libssh, wolfSSL, AWS-LC, Mbed TLS, installed JDKs and Go toolchains (`crypto_libraries` in JSON). Reads the algorithm and group names each installed library embeds, then falls back to upstream version thresholds; no subprocess. On trees with no package database (Buildroot), versions come from the library files themselves. |
| `--scan-boot-chain` | Inventory the boot chain's trust anchors (`boot_chain` in JSON): Secure Boot state and the PK / KEK / db / dbx / MOK certificate algorithms (read from efivarfs), the kernel module signing algorithm (kernel config plus one module's appended PKCS#7 signature), IMA / EVM state and certificates, kernel lockdown, and the TPM's specification revision and TPM 2.0 v1.85 ML-KEM / ML-DSA support (one read-only `TPM2_GetCapability`; needs root or the `tss` group). No subprocess. SARIF `pqc-030` flags a classical boot chain. Live hosts only. |
| `--scan-kerberos` | Inventory Kerberos encryption types (`kerberos` in JSON): `krb5.conf` (with includes and the crypto-policies back-end) and `kdc.conf` enctype lists expanded with MIT's rules, keytab entries parsed in-process (principal, kvno, enctype; key bytes are never read into the report), and PKINIT settings. SARIF `pqc-031` flags deprecated DES / 3DES / RC4 enctypes (warning) and 128-bit-only enctypes or classical PKINIT (note). Also works with `--root`. |
| `--scan-tunnels` | Inventory WireGuard and OpenVPN post-quantum posture (`tunnels` in JSON): WireGuard peers from wg-quick, systemd-networkd and NetworkManager configs (and, as root on a live host, `wg show`), recording only whether each peer has a pre-shared key, never the key; OpenVPN `tls-groups` / `tls-version-max` per config under `/etc/openvpn`. SARIF `pqc-032` flags peers without a pre-shared key, `pqc-033` OpenVPN configs whose key exchange can't be PQC. Also works with `--root` (configs only). |
| `--scan-dnssec` | Inventory DNSSEC signing algorithms (`dnssec` in JSON) of BIND (`dnssec-policy`, key files), Knot and PowerDNS, plus Unbound / systemd-resolved / BIND validation settings. SARIF `pqc-034` notes classical-only signing (warning when an algorithm IANA marks MUST NOT for signing is in use). Also works with `--root`. |
| `--host-mount PATH` | Path where the host root is mounted. Host reads of `/proc /sys /dev /etc`, `os-release` and the rpm / dpkg package databases go through it. DaemonSet pattern: host root mounted at `/host`, probe invoked with `--host-mount /host` so reads target the node, not the container image. |
| `--root PATH` | Scan a filesystem tree offline: a mounted disk image or an extracted container rootfs. Package, certificate, key, crypto-policy, `openssl.cnf`, sshd configuration, service TLS configuration and signing-key checks read `PATH`; CPU, kernel, device, process and benchmark sections are marked not applicable and no readiness tier is computed. Cannot be combined with `--host-mount`, `--bench`, `--bench-tls`, `--scan-services`, `--check`, `--fips-strict` or `--recommend`. See [Scanning images offline](deployment.md#scanning-images-offline). |
| `--host-name NAME` | Name to report for the scanned host in every output: JSON `hostname` and the `host/<name>` component that `--cbom` and `--sbom` share. Overrides `PQC_HOSTNAME` and the detected name. Use it with `--root`: a tree often has no `/etc/hostname`, and several unnamed offline CBOMs would all be `host/unknown` (#222). |

## Recommendation engine

| Flag | Purpose |
| --- | --- |
| `--recommend` | Emit a host-specific PQC recommendation instead of the readiness report. |
| `--policy {cnsa-2.0,nist-civilian,eu-anssi-bsi,commercial,auto}` | Compliance context for `--recommend`. `auto` (default) emits all four policies side by side. |
| `--role {tls-server,tls-client,signing-service,firmware-signing,generic}` | Workload role. Drives the recommendation engine (every workload role is implemented; `generic` returns a stub response) and the memory-tier threshold, which differs per role. See [recommendation-policies.md](recommendation-policies.md#roles). |

## Output

| Flag | Purpose |
| --- | --- |
| `--json` / `--markdown` / `--cbom` / `--spdx` / `--sbom` / `--sarif` / `--prometheus` / `--ndjson` / `--ansible` | See [output formats](output-formats.md). |
| `--cbom-version {1.7,1.6}` | CycloneDX specVersion for `--cbom` (default `1.7`). `1.6` reproduces earlier releases' output exactly. |
| `--sarif-anchor PATH` | Shape `--sarif` for code-scanning upload: every result is attached to `PATH` (relative to the repository root; `{hostname}` is substituted), with `partialFingerprints`, a per-host `automationDetails.id` category and rule `security-severity`. Without it, `--sarif` output is unchanged. See [sarif-code-scanning.md](sarif-code-scanning.md). |
| `--cbom-profile {none,federal-draft}` | Regime annotations for `--cbom` (default `none`, unchanged output). `federal-draft` adds OMB M-23-02 / M-26-15 / EO 14412 fields: key-establishment vs signature, quantum-vulnerable flag and deadline per asset, the classical groups a host offers, a TLS 1.3 status, and M-23-02 item coverage. Draft until CISA/NIST publish the minimum CBOM elements (~March 2027). |
| `--cbom-interop {none,dependency-track,sbom-only}` | Shape `--cbom` for SBOM-oriented tools (default `none`, unchanged output). `dependency-track` mirrors the crypto details into `pqc-readiness:crypto:*` component properties (they survive tools that drop `cryptoProperties`) and adds library components with purls linked to the assets they provide; `sbom-only` emits only those library components, for tools that reject cryptographic assets. See [integrations/dependency-track.md](integrations/dependency-track.md). |
| `--cbom-namespaced-properties` | Prefix every `--cbom` property name with `pqc-readiness:` (`detectedBy` becomes `pqc-readiness:detectedBy`, `certificate:role` becomes `pqc-readiness:certificate:role`; names already in `pqc-readiness:` or the CycloneDX `cdx:` taxonomy are left alone), so documents merged from several tools can't collide. Opt-in, because importers may key on the current names (#222). |
| `--fips-strict` | Exit 4 (like `--check`) when kernel FIPS mode is active but OpenSSL's default provider exposes algorithms the FIPS provider does not. Background: [findings/fips-algorithm-fence.md](findings/fips-algorithm-fence.md). |
| `--check {excellent,good,marginal,poor,cnsa-2.0}` | Exit 4 if the verdict is below the named tier, or if `cnsa-2.0` is selected and the host is not CNSA 2.0 compliant. CI gating. |
| `--save` | Write JSON to `~/.cache/pqc-readiness/`. The fleet aggregator reads exactly this directory layout. |
| `--output FILE` | Write the report to `FILE` instead of stdout. Works with every format, including `--aggregate`, `--recommend` and `--ansible`. The parent directory must already exist (it is never created). The file is replaced atomically (temp file in the same directory, then rename), so a reader such as node_exporter or the fleet aggregator never sees a partial report. Mutually exclusive with `--save`. Useful for volume mounts in quadlet / DaemonSet / Ansible `command:` tasks, where shell redirection is fragile. |
| `--inventory-metadata FILE` | JSON file of operator-supplied facts the host can't know (FISMA system ID, FIPS 199 level, HVA ID, hosting model and provider, data lifecycle, notes; OMB M-23-02 items 1–3 and 7–9). Validated before probing (exit 2 on error); carried into `--json` as `inventory_metadata` and into `--cbom` as `inventory:*` host properties. Identifiers only: see [json-output.md](json-output.md#inventory_metadata). |
| `--quiet` | Print only the verdict line. |
| `--no-color` | Disable ANSI colour. Auto-disabled when stdout is not a TTY. |

## Aggregation

| Flag | Purpose |
| --- | --- |
| `--aggregate DIR` | Roll every `*.json` in `DIR` into a fleet rollup. The program exits when done and ignores all other flags. |
| `--aggregate-format {json,csv}` | Output format for `--aggregate` (default `json`). |
| `--observations FILE` | With `--aggregate`: join endpoint-observation records (what a network-side tool saw an endpoint negotiate) to the hosts and listening services in the reports. Format and matching rules: [endpoint-observations.md](endpoint-observations.md). |
| `--observations-max-age-days DAYS` | Flag an observation as stale when it was made more than `DAYS` before or after its host's report (default 7). |

## Misc

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
