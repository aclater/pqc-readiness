# Example output: cross-OS scan matrix (v2.4.0)

> **Example output, not a support statement.** This page records what `pqc-readiness` v2.4.0 reported on 20 stock Linux images on 2026-10-15. It shows what the scanner produces across distributions and what each distribution ships out of the box. Results will change as distributions update their packages. Distribution support tiers are in the [README](../../README.md#distribution-support).

Every image was scanned **unmodified**, apart from installing a supported Python where the image lacked one. The [method](#how-this-was-run) section lists the exact flags and VM sizing. [What changed since the v2.2.0 run](#changes-since-the-v220-run) explains the differences from the previous version of this page.

## Summary

| Measure | Hosts |
| --- | ---: |
| Ship OpenSSL with native ML-KEM / ML-DSA | 15 / 20 |
| Offer hybrid PQC in TLS by default (`deployed`) | 9 / 20 |
| Offer PQC key exchange in SSH by default (`deployed`) | 10 / 20 |
| PQC-capable but configured to stay classical (`capable_not_configured`) | 10 / 20 |
| SARIF findings raised | 179 across 12 rules |

The hosts fall into three groups:

- **PQC on by default for TLS:** Red Hat Enterprise Linux 10.2 (UBI container), Rocky Linux 10.2 (Red Quartz), AlmaLinux 10.2 (Lavender Lion), CentOS Stream 10 (Coughlan), Fedora Linux 43 (Cloud Edition), Fedora Linux 44 (Cloud Edition), Ubuntu 26.04.1 LTS, openSUSE Leap 16.0, openSUSE Tumbleweed.
- **PQC-capable OpenSSL, but the default crypto policy keeps TLS classical** ([`pqc-008`](../rules/pqc-008-crypto-policy-blocks-pqc.md), [`pqc-020`](../rules/pqc-020-pqc-capable-not-configured.md)): Red Hat Enterprise Linux 9.8 (UBI container), Rocky Linux 9.8 (Blue Onyx), AlmaLinux 9.8 (Olive Jaguar), Oracle Linux Server 9.8, CentOS Stream 9, Amazon Linux 2023.12.20261012.
- **OpenSSL cannot do PQC in TLS** ([`pqc-001`](../rules/pqc-001-openssl-pre-3.5.md)): Red Hat Enterprise Linux 8.10 (UBI container), Rocky Linux 8.10 (Green Obsidian), AlmaLinux 8.10 (Cerulean Leopard), Oracle Linux Server 8.10, openSUSE Leap 15.6.

19 of 20 hosts trust only classical package-signing keys ([`pqc-009`](../rules/pqc-009-classical-package-signing-keys.md)); the exception is Red Hat Enterprise Linux 10.2 (UBI container), whose package-signing keys include a hybrid (PQC) key. Every VM boots through a classical chain ([`pqc-030`](../rules/pqc-030-classical-boot-chain.md)).

## Crypto stack and deployment gap

The TLS, SSH and IPsec columns are the per-protocol `pqc_deployment_gap.protocols.*.state` verdict ([JSON reference](../json-output.md)). `sshd kex` is the effective server configuration from `sshd -T`. Since v2.3.0 the OpenSSL and OpenSSH versions are read from the host's own packages or binaries (`version_source`), not from whatever command-line tool happens to be on `PATH`.

| OS | Firmware | OpenSSL | OpenSSH (PQC kex) | Crypto policy | Hybrid TLS default | TLS | SSH | IPsec | sshd kex |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **Red Hat Enterprise Linux 8.10 (UBI container)** | container | 1.1.1k (no PQC) | 8.0p1 (sntrup only) | DEFAULT | no | ❌ not capable | ⚠️ capable, off | — not present | classical |
| **Red Hat Enterprise Linux 9.8 (UBI container)** | container | 3.5.8 | 9.9p1 (ML-KEM) | DEFAULT | no | ⚠️ capable, off | ⚠️ capable, off | — not present | classical |
| **Red Hat Enterprise Linux 10.2 (UBI container)** | container | 3.5.8 | 9.9p1 (ML-KEM) | DEFAULT | yes | ✅ deployed | ✅ deployed | — not present | PQC first |
| **Rocky Linux 8.10 (Green Obsidian)** | BIOS | 1.1.1k (no PQC) | 8.0p1 (sntrup only) | DEFAULT | no | ❌ not capable | ⚠️ capable, off | — not present | classical |
| **Rocky Linux 9.8 (Blue Onyx)** | BIOS | 3.5.5 | 9.9p1 (ML-KEM) | DEFAULT | no | ⚠️ capable, off | ⚠️ capable, off | — not present | classical |
| **Rocky Linux 10.2 (Red Quartz)** | BIOS | 3.5.5 | 9.9p1 (ML-KEM) | DEFAULT | yes | ✅ deployed | ✅ deployed | — not present | PQC first |
| **AlmaLinux 8.10 (Cerulean Leopard)** | BIOS | 1.1.1k (no PQC) | 8.0p1 (sntrup only) | DEFAULT | no | ❌ not capable | ⚠️ capable, off | — not present | classical |
| **AlmaLinux 9.8 (Olive Jaguar)** | BIOS | 3.5.8 | 9.9p1 (ML-KEM) | DEFAULT | no | ⚠️ capable, off | ⚠️ capable, off | — not present | classical |
| **AlmaLinux 10.2 (Lavender Lion)** | BIOS | 3.5.8 | 9.9p1 (ML-KEM) | DEFAULT | yes | ✅ deployed | ✅ deployed | — not present | PQC first |
| **Oracle Linux Server 8.10** | BIOS | 1.1.1k (no PQC) | 8.0p1 (sntrup only) | DEFAULT | no | ❌ not capable | ⚠️ capable, off | — not present | classical |
| **Oracle Linux Server 9.8** | BIOS | 3.5.5 | 9.9p1 (ML-KEM) | DEFAULT | no | ⚠️ capable, off | ⚠️ capable, off | — not present | classical |
| **CentOS Stream 9** | BIOS | 3.5.8 | 9.9p1 (ML-KEM) | DEFAULT | no | ⚠️ capable, off | ⚠️ capable, off | — not present | classical |
| **CentOS Stream 10 (Coughlan)** | BIOS | 3.5.8 | 9.9p1 (ML-KEM) | DEFAULT | yes | ✅ deployed | ✅ deployed | — not present | PQC first |
| **Fedora Linux 43 (Cloud Edition)** | BIOS | 3.5.1 | 10.0p2 (ML-KEM) | DEFAULT | yes | ✅ deployed | ✅ deployed | — not present | PQC first |
| **Fedora Linux 44 (Cloud Edition)** | BIOS | 3.5.5 | 10.2p1 (ML-KEM) | DEFAULT | yes | ✅ deployed | ✅ deployed | — not present | PQC first |
| **Amazon Linux 2023.12.20261012** | BIOS | 3.5.8 | 9.9p1 (ML-KEM) | DEFAULT | no | ⚠️ capable, off | ⚠️ capable, off | — not present | classical |
| **Ubuntu 26.04.1 LTS** | BIOS | 3.5.5 | 10.2p1 (ML-KEM) | none | yes | ✅ deployed | ✅ deployed | — not present | PQC first |
| **openSUSE Leap 15.6** | BIOS | 3.1.4 (no PQC) | 9.6p1 (sntrup only) | DEFAULT | no | ❌ not capable | ✅ deployed | — not present | PQC first |
| **openSUSE Leap 16.0** | BIOS | 3.5.0 | 10.0p2 (ML-KEM) | DEFAULT | yes | ✅ deployed | ✅ deployed | — not present | PQC first |
| **openSUSE Tumbleweed** | BIOS | 3.5.3 | 10.5p1 (ML-KEM) | DEFAULT | yes | ✅ deployed | ✅ deployed | — not present | PQC first |

## Compliance and inventory

`PQC libs` is PQC-capable / installed crypto libraries. `Trust store` is total certificates / PQC or hybrid certificates. `Findings` is errors / warnings / notes.

| OS | PQC libs | CNSA 2.0 | FIPS kernel | Packages (source) | Trust store | Pkg signing keys | Secure Boot certs | Kerberos | Findings E/W/N |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **Red Hat Enterprise Linux 8.10 (UBI container)** | 0/3 (no PQC: gnutls, libgcrypt, libssh) | partial | off | 195 (rpmdb-bdb) | 390 / 0 | 2, all classical | none | AES-128 allowed | 0 / 5 / 4 |
| **Red Hat Enterprise Linux 9.8 (UBI container)** | 1/2 (no PQC: libgcrypt) | partial | off | 194 (rpmdb-sqlite) | 390 / 0 | 2, all classical | none | AES-128 allowed | 0 / 4 / 5 |
| **Red Hat Enterprise Linux 10.2 (UBI container)** | 1/1 | partial | off | 182 (rpmdb-sqlite) | 390 / 0 | 3, 1 hybrid, 0 PQC | none | AES-128 allowed | 0 / 1 / 3 |
| **Rocky Linux 8.10 (Green Obsidian)** | 0/3 (no PQC: gnutls, libgcrypt, libssh) | partial | off | 460 (rpmdb-bdb) | 356 / 0 | 1, all classical | n/a (BIOS boot) | AES-128 allowed | 0 / 13 / 5 |
| **Rocky Linux 9.8 (Blue Onyx)** | 1/3 (no PQC: libgcrypt, libssh) | compliant | off | 422 (rpmdb-sqlite) | 390 / 0 | 1, all classical | n/a (BIOS boot) | AES-128 allowed | 0 / 5 / 5 |
| **Rocky Linux 10.2 (Red Quartz)** | 3/3 | compliant | off | 443 (rpmdb-sqlite) | 390 / 0 | 1, all classical | n/a (BIOS boot) | AES-128 allowed | 0 / 1 / 5 |
| **AlmaLinux 8.10 (Cerulean Leopard)** | 0/3 (no PQC: gnutls, libgcrypt, libssh) | partial | off | 439 (rpmdb-bdb) | 390 / 0 | 2, all classical | n/a (BIOS boot) | AES-128 allowed | 0 / 13 / 5 |
| **AlmaLinux 9.8 (Olive Jaguar)** | 1/3 (no PQC: libgcrypt, libssh) | compliant | off | 387 (rpmdb-sqlite) | 390 / 0 | 1, all classical | n/a (BIOS boot) | AES-128 allowed | 0 / 5 / 5 |
| **AlmaLinux 10.2 (Lavender Lion)** | 3/3 | compliant | off | 380 (rpmdb-sqlite) | 390 / 0 | 1, all classical | n/a (BIOS boot) | AES-128 allowed | 0 / 1 / 5 |
| **Oracle Linux Server 8.10** | 0/3 (no PQC: gnutls, libgcrypt, libssh) | partial | off | 372 (rpmdb-bdb) | 390 / 0 | 1, all classical | n/a (BIOS boot) | AES-128 allowed | 0 / 9 / 5 |
| **Oracle Linux Server 9.8** | 1/3 (no PQC: libgcrypt, libssh) | compliant | off | 373 (rpmdb-sqlite) | 390 / 0 | 2, all classical | n/a (BIOS boot) | AES-128 allowed | 0 / 5 / 5 |
| **CentOS Stream 9** | 1/3 (no PQC: libgcrypt, libssh) | compliant | off | 473 (rpmdb-sqlite) | 396 / 0 | 2, all classical | n/a (BIOS boot) | AES-128 allowed | 0 / 5 / 5 |
| **CentOS Stream 10 (Coughlan)** | 3/3 | compliant | off | 512 (rpmdb-sqlite) | 396 / 0 | 2, all classical | n/a (BIOS boot) | AES-128 allowed | 0 / 1 / 5 |
| **Fedora Linux 43 (Cloud Edition)** | 2/3 (no PQC: libssh) | partial | off | 430 (rpmdb-sqlite) | 390 / 0 | 1, all classical | n/a (BIOS boot) | AES-128 allowed | 0 / 2 / 4 |
| **Fedora Linux 44 (Cloud Edition)** | 3/3 | partial | off | 427 (rpmdb-sqlite) | 388 / 0 | 1, all classical | n/a (BIOS boot) | AES-128 allowed | 0 / 1 / 4 |
| **Amazon Linux 2023.12.20261012** | 1/2 (no PQC: libgcrypt) | compliant | off | 471 (rpmdb-sqlite) | 310 / 0 | 1, all classical | n/a (BIOS boot) | AES-128 allowed | 0 / 4 / 5 |
| **Ubuntu 26.04.1 LTS** | 2/2 | partial | off | 678 (None) | 121 / 0 | 3, all classical | n/a (BIOS boot) | n/a | 0 / 3 / 3 |
| **openSUSE Leap 15.6** | 0/3 (no PQC: gnutls, libgcrypt, libssh) | partial | off | 375 (rpmdb-bdb) | 145 / 0 | 6, all classical | n/a (BIOS boot) | AES-128 allowed | 0 / 8 / 4 |
| **openSUSE Leap 16.0** | 2/3 (no PQC: libssh) | compliant | off | 378 (rpmdb-ndb) | 121 / 0 | 6, all classical | n/a (BIOS boot) | AES-128 allowed | 0 / 2 / 4 |
| **openSUSE Tumbleweed** | 2/3 (no PQC: libssh) | partial | off | 372 (rpmdb-ndb) | 121 / 0 | 5, all classical | n/a (BIOS boot) | n/a | 0 / 2 / 3 |

## Findings matrix

`E` error, `W` warning, `N` note, `·` not raised. Column keys are listed under the table. Each rule links to its help page.

| Rule | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 | 16 | 17 | 18 | 19 | 20 | Hosts |
| --- | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | ---: |
| [`pqc-001`](../rules/pqc-001-openssl-pre-3.5.md) OpenSSL is older than 3.5 (no native PQC). | W | · | · | W | · | · | W | · | · | W | · | · | · | · | · | · | · | W | · | · | 5 |
| [`pqc-004`](../rules/pqc-004-classical-only-trust-store.md) Trust store contains zero PQC and zero hybrid certificates. | N | N | N | N | N | N | N | N | N | N | N | N | N | N | N | N | N | N | N | N | 20 |
| [`pqc-005`](../rules/pqc-005-slh-dsa-in-tls-context.md) SLH-DSA exposed for TLS use; signatures are large for handshakes. | · | W | W | · | W | W | · | W | W | · | W | W | W | W | W | W | W | · | W | W | 15 |
| [`pqc-008`](../rules/pqc-008-crypto-policy-blocks-pqc.md) OpenSSL supports PQC TLS groups but the system crypto policy keeps them out. | · | W | · | · | W | · | · | W | · | · | W | W | · | · | · | W | · | · | · | · | 6 |
| [`pqc-009`](../rules/pqc-009-classical-package-signing-keys.md) Every package-signing key the package manager trusts is classical. | N | N | · | N | N | N | N | N | N | N | N | N | N | N | N | N | N | N | N | N | 19 |
| [`pqc-010`](../rules/pqc-010-sshd-pqc-kex-not-offered.md) OpenSSH supports a PQC key exchange but sshd does not offer it (or not first). | W | W | · | W | W | · | W | W | · | W | W | W | · | · | · | W | · | · | · | · | 10 |
| [`pqc-011`](../rules/pqc-011-service-crypto-library-without-pqc.md) A listening service uses a crypto library that cannot do PQC. | · | · | · | W | · | · | W | · | · | W | · | · | · | · | · | · | W | W | · | · | 5 |
| [`pqc-013`](../rules/pqc-013-crypto-library-without-pqc.md) An installed crypto library or toolchain cannot do PQC. | W | W | · | W | W | · | W | W | · | W | W | W | · | W | · | W | · | W | W | W | 14 |
| [`pqc-014`](../rules/pqc-014-crypto-library-pre-standard-mlkem.md) An installed crypto library only has pre-standard ML-KEM (Kyber). | · | · | · | · | · | N | · | · | N | · | · | · | N | · | · | · | · | · | · | · | 3 |
| [`pqc-020`](../rules/pqc-020-pqc-capable-not-configured.md) PQC-capable software on this host is configured to stay classical. | N | N | · | N | N | · | N | N | · | N | N | N | · | · | · | N | · | · | · | · | 10 |
| [`pqc-030`](../rules/pqc-030-classical-boot-chain.md) The boot chain's signing keys are all classical. | · | N | N | N | N | N | N | N | N | N | N | N | N | N | N | N | N | N | N | N | 19 |
| [`pqc-031`](../rules/pqc-031-kerberos-weak-enctypes.md) Kerberos allows deprecated or 128-bit encryption types, or uses classical PKINIT. | N | N | N | N | N | N | N | N | N | N | N | N | N | N | N | N | · | N | N | · | 18 |

Columns: **1** Red Hat Enterprise Linux 8.10 (UBI container); **2** Red Hat Enterprise Linux 9.8 (UBI container); **3** Red Hat Enterprise Linux 10.2 (UBI container); **4** Rocky Linux 8.10 (Green Obsidian); **5** Rocky Linux 9.8 (Blue Onyx); **6** Rocky Linux 10.2 (Red Quartz); **7** AlmaLinux 8.10 (Cerulean Leopard); **8** AlmaLinux 9.8 (Olive Jaguar); **9** AlmaLinux 10.2 (Lavender Lion); **10** Oracle Linux Server 8.10; **11** Oracle Linux Server 9.8; **12** CentOS Stream 9; **13** CentOS Stream 10 (Coughlan); **14** Fedora Linux 43 (Cloud Edition); **15** Fedora Linux 44 (Cloud Edition); **16** Amazon Linux 2023.12.20261012; **17** Ubuntu 26.04.1 LTS; **18** openSUSE Leap 15.6; **19** openSUSE Leap 16.0; **20** openSUSE Tumbleweed.

## Performance

Single-thread `openssl speed` (1 s per test) and the loopback TLS 1.3 handshake benchmark (`--bench --bench-tls`), in operations per second. Every host ran on the same CPU (AMD Ryzen AI 9 HX 370 w/ Radeon 890M), so the differences come from each distribution's OpenSSL build. Up to four VMs ran at once under the host's VM budget, which adds noise. The RHEL container rows ran without virtualization or that contention, so their numbers run higher and should not be compared with the VM rows. Hosts without native PQC in OpenSSL have no PQC numbers.

| OS | ML-KEM-768 encaps | ML-KEM-768 decaps | ML-DSA-65 sign | ML-DSA-65 verify | SLH-DSA-128s sign | RSA-2048 sign | ECDH | TLS x25519 | TLS X25519MLKEM768 | TLS MLKEM768 | Hybrid vs classical |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **Red Hat Enterprise Linux 8.10 (UBI container)** | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a |
| **Red Hat Enterprise Linux 9.8 (UBI container)** | 41,998 | 29,234 | 1,693 | 8,327 | 4.4 | 4,331 | 40,048 | 150 | 163 | 194 | +9% |
| **Red Hat Enterprise Linux 10.2 (UBI container)** | 49,399 | 35,064 | 1,662 | 8,305 | 4.6 | 5,058 | 33,532 | 206 | 210 | 180 | +2% |
| **Rocky Linux 8.10 (Green Obsidian)** | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a |
| **Rocky Linux 9.8 (Blue Onyx)** | 48,794 | 31,937 | 1,689 | 9,094 | 5.0 | 5,325 | 49,484 | 221 | 205 | 252 | -7% |
| **Rocky Linux 10.2 (Red Quartz)** | 50,855 | 33,435 | 1,643 | 8,611 | 5.0 | 5,065 | 47,243 | 208 | 208 | 228 | +0% |
| **AlmaLinux 8.10 (Cerulean Leopard)** | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a |
| **AlmaLinux 9.8 (Olive Jaguar)** | 43,204 | 32,124 | 1,544 | 8,826 | 4.5 | 5,060 | 46,826 | 218 | 196 | 148 | -10% |
| **AlmaLinux 10.2 (Lavender Lion)** | 46,455 | 35,076 | 1,445 | 7,673 | 5.0 | 4,973 | 47,286 | 215 | 226 | 216 | +5% |
| **Oracle Linux Server 8.10** | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a |
| **Oracle Linux Server 9.8** | 32,998 | 20,791 | 1,533 | 8,439 | 4.8 | 4,754 | 46,868 | 192 | 200 | 229 | +4% |
| **CentOS Stream 9** | 45,842 | 30,671 | 1,680 | 8,923 | 4.3 | 5,135 | 47,415 | 135 | 160 | 225 | +19% |
| **CentOS Stream 10 (Coughlan)** | 47,020 | 31,711 | 1,633 | 8,833 | 5.0 | 5,010 | 37,316 | 236 | 244 | 244 | +3% |
| **Fedora Linux 43 (Cloud Edition)** | 53,007 | 33,738 | 799 | 65 | 2.0 | 4,964 | 44,581 | 211 | 234 | 282 | +11% |
| **Fedora Linux 44 (Cloud Edition)** | 47,366 | 33,914 | 1,557 | 7,779 | 5.2 | 5,022 | 48,454 | 172 | 247 | 248 | +44% |
| **Amazon Linux 2023.12.20261012** | 61,088 | 39,639 | 1,214 | 6,150 | 3.4 | 3,812 | 33,484 | 133 | 146 | 132 | +9% |
| **Ubuntu 26.04.1 LTS** | 39,580 | 33,555 | 1,436 | 8,281 | 4.5 | 5,071 | 47,174 | 278 | 231 | 262 | -17% |
| **openSUSE Leap 15.6** | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a |
| **openSUSE Leap 16.0** | 54,356 | 35,258 | n/a | n/a | n/a | 4,476 | 48,213 | 29 | 27 | 28 | -9% |
| **openSUSE Tumbleweed** | 53,615 | 34,825 | 799 | 65 | 2.0 | 5,129 | 46,125 | 28 | 21 | 24 | -26% |

## Changes since the v2.2.0 run

The previous version of this page recorded v2.2.0 on 2026-10-14, on the same image builds. Cells that changed, excluding package counts (which move with every image update) and the firmware-dependent Firmware and Secure Boot certs columns (see below):

| OS | Field | v2.2.0 | v2.4.0 |
| --- | --- | --- | --- |
| (none) | | | |

**What this shows.** On booted, stock hosts nothing in the verdicts, versions, findings or summary changed between v2.2.0 and v2.4.0. Every host reported its OpenSSL and OpenSSH versions with `version_source: cli`, because on a booted host the `openssl` and `ssh` commands are the host's own. The accuracy fixes in 2.3.0 and 2.4.0 (versions from the host's packages and binaries, IPsec facts from the host, offline scans that never describe the scanning machine) change results where the tools and the host disagree: scans through `--host-mount` (the OpenShift and Kubernetes DaemonSets) and offline `--root` scans. [openshift-4.22-live.md](openshift-4.22-live.md) shows that case: OpenSSL 3.5.5 from the node's package where v2.2.0 reported the image's 3.5.8.

**Method differences from the v2.2.0 run:**

- **Firmware.** The VMs were booted by the [distro-matrix](https://github.com/aclater/distro-matrix) runner, whose qemu backend uses SeaBIOS, where the v2.2.0 run's hand-built harness used UEFI. Without UEFI there is no Secure Boot database to read, so the Secure Boot certs column is `n/a (BIOS boot)` for the VMs (it was 1 to 4 RSA certificates per distribution under UEFI; see the [v2.2.0 page in git history](https://github.com/aclater/pqc-readiness/blob/v2.2.0/docs/examples/os-matrix-2026-10.md)). UEFI support for the runner is [aclater/distro-matrix#57](https://github.com/aclater/distro-matrix/issues/57). `pqc-030` still fires on every VM from the kernel module-signing keys.
- **Python on EL8 and Leap 15.6.** Installed by the runner's `--prepare` step (python3.11), as the v2.2.0 run installed it by hand.

## Findings by OS

<details>
<summary><b>Red Hat Enterprise Linux 8.10 (UBI container)</b>: 9 findings</summary>

- **warning** `pqc-001-openssl-pre-3.5`: OpenSSL 1.1.1k  FIPS 25 Mar 2021 is older than 3.5.0 — native ML-KEM / ML-DSA are not available.
- **warning** `pqc-010-sshd-pqc-kex-not-offered`: sshd offers no post-quantum key exchange although the installed OpenSSH supports one; offered: curve25519-sha256, curve25519-sha256@libssh.org, ecdh-sha2-nistp256, ecdh-sha2-nistp384, ....
- **warning** `pqc-013-crypto-library-without-pqc`: gnutls 3.6.16 has no ML-KEM / ML-DSA (evidence: binary); software using it fails at PQC.
- **warning** `pqc-013-crypto-library-without-pqc`: libgcrypt 1.8.5 has no ML-KEM / ML-DSA (evidence: binary); software using it fails at PQC.
- **warning** `pqc-013-crypto-library-without-pqc`: libssh 0.9.6 has no ML-KEM / ML-DSA (evidence: binary); software using it fails at PQC.
- **note** `pqc-004-classical-only-trust-store`: Scanned 390 certificates across 3 trust-store directories; every cert uses classical signatures.
- **note** `pqc-009-classical-package-signing-keys`: All 2 trusted package-signing keys are classical (RSA); none uses ML-DSA or SLH-DSA (RFC 9980).
- **note** `pqc-020-pqc-capable-not-configured`: PQC-capable software is configured to stay classical (protocols: ssh); a configuration change closes the gap.
- **note** `pqc-031-kerberos-weak-enctypes`: Kerberos: 128-bit enctypes are permitted (aes128-cts-hmac-sha1-96, aes128-cts-hmac-sha256-128, camellia128-cts-cmac); Grover's algorithm leaves them ~64-bit security and CNSA 2.0 requires AES-256.

</details>

<details>
<summary><b>Red Hat Enterprise Linux 9.8 (UBI container)</b>: 9 findings</summary>

- **warning** `pqc-005-slh-dsa-in-tls-context`: OpenSSL exposes SLH-DSA signature algorithms (SLH-DSA-SHA2-128f, SLH-DSA-SHA2-128s, SLH-DSA-SHA2-192f, SLH-DSA-SHA2-192s, SLH-DSA-SHA2-256f, SLH-DSA-SHA2-256s, SLH-DSA-SHAKE-128f, SLH-DSA-SHAKE-128s, SLH-DSA-SHAKE-192f, SLH-DSA-SHAKE-192s, SLH-DSA-SHAKE-256f, SLH-DSA-SHAKE-256s); prefer ML-DSA for TLS handshakes.
- **warning** `pqc-008-crypto-policy-blocks-pqc`: Crypto policy DEFAULT allows no PQC TLS groups, although OpenSSL supports SecP256r1MLKEM768, SecP384r1MLKEM1024, X25519MLKEM768, MLKEM1024, MLKEM512, MLKEM768.
- **warning** `pqc-010-sshd-pqc-kex-not-offered`: sshd offers no post-quantum key exchange although the installed OpenSSH supports one; offered: curve25519-sha256, curve25519-sha256@libssh.org, ecdh-sha2-nistp256, ecdh-sha2-nistp384, ....
- **warning** `pqc-013-crypto-library-without-pqc`: libgcrypt 1.10.0 has no ML-KEM / ML-DSA (evidence: binary); software using it fails at PQC.
- **note** `pqc-004-classical-only-trust-store`: Scanned 390 certificates across 3 trust-store directories; every cert uses classical signatures.
- **note** `pqc-009-classical-package-signing-keys`: All 2 trusted package-signing keys are classical (RSA); none uses ML-DSA or SLH-DSA (RFC 9980).
- **note** `pqc-020-pqc-capable-not-configured`: PQC-capable software is configured to stay classical (protocols: tls, ssh); a configuration change closes the gap.
- **note** `pqc-030-classical-boot-chain`: Boot chain is classical: IMA code-signing certificates are EC P-384.
- **note** `pqc-031-kerberos-weak-enctypes`: Kerberos: 128-bit enctypes are permitted (aes128-cts-hmac-sha1-96, aes128-cts-hmac-sha256-128); Grover's algorithm leaves them ~64-bit security and CNSA 2.0 requires AES-256.

</details>

<details>
<summary><b>Red Hat Enterprise Linux 10.2 (UBI container)</b>: 4 findings</summary>

- **warning** `pqc-005-slh-dsa-in-tls-context`: OpenSSL exposes SLH-DSA signature algorithms (SLH-DSA-SHA2-128f, SLH-DSA-SHA2-128s, SLH-DSA-SHA2-192f, SLH-DSA-SHA2-192s, SLH-DSA-SHA2-256f, SLH-DSA-SHA2-256s, SLH-DSA-SHAKE-128f, SLH-DSA-SHAKE-128s, SLH-DSA-SHAKE-192f, SLH-DSA-SHAKE-192s, SLH-DSA-SHAKE-256f, SLH-DSA-SHAKE-256s); prefer ML-DSA for TLS handshakes.
- **note** `pqc-004-classical-only-trust-store`: Scanned 390 certificates across 3 trust-store directories; every cert uses classical signatures.
- **note** `pqc-030-classical-boot-chain`: Boot chain is classical: IMA code-signing certificates are EC P-384.
- **note** `pqc-031-kerberos-weak-enctypes`: Kerberos: 128-bit enctypes are permitted (aes128-cts-hmac-sha1-96, aes128-cts-hmac-sha256-128); Grover's algorithm leaves them ~64-bit security and CNSA 2.0 requires AES-256.

</details>

<details>
<summary><b>Rocky Linux 8.10 (Green Obsidian)</b>: 18 findings</summary>

- **warning** `pqc-001-openssl-pre-3.5`: OpenSSL 1.1.1k  FIPS 25 Mar 2021 is older than 3.5.0 — native ML-KEM / ML-DSA are not available.
- **warning** `pqc-010-sshd-pqc-kex-not-offered`: sshd offers no post-quantum key exchange although the installed OpenSSH supports one; offered: curve25519-sha256, curve25519-sha256@libssh.org, ecdh-sha2-nistp256, ecdh-sha2-nistp384, ....
- **warning** `pqc-011-service-crypto-library-without-pqc`: sshd.service on tcp 0.0.0.0:22 uses openssl 1.x (from soname), which has no ML-KEM hybrid key exchange; its connections stay classical.
- **warning** `pqc-011-service-crypto-library-without-pqc`: sshd.service on tcp [::]:22 uses openssl 1.x (from soname), which has no ML-KEM hybrid key exchange; its connections stay classical.
- **warning** `pqc-011-service-crypto-library-without-pqc`: rpcbind.service on tcp 0.0.0.0:111 uses openssl 1.x (from soname), which has no ML-KEM hybrid key exchange; its connections stay classical.
- **warning** `pqc-011-service-crypto-library-without-pqc`: rpcbind.service on tcp [::]:111 uses openssl 1.x (from soname), which has no ML-KEM hybrid key exchange; its connections stay classical.
- **warning** `pqc-011-service-crypto-library-without-pqc`: rpcbind.service on udp 0.0.0.0:111 uses openssl 1.x (from soname), which has no ML-KEM hybrid key exchange; its connections stay classical.
- **warning** `pqc-011-service-crypto-library-without-pqc`: rpcbind.service on udp [::]:111 uses openssl 1.x (from soname), which has no ML-KEM hybrid key exchange; its connections stay classical.
- **warning** `pqc-011-service-crypto-library-without-pqc`: chronyd.service on udp 127.0.0.1:323 uses gnutls 3.6.16, which has no ML-KEM hybrid key exchange; its connections stay classical.
- **warning** `pqc-011-service-crypto-library-without-pqc`: chronyd.service on udp [::1]:323 uses gnutls 3.6.16, which has no ML-KEM hybrid key exchange; its connections stay classical.
- **warning** `pqc-013-crypto-library-without-pqc`: gnutls 3.6.16 has no ML-KEM / ML-DSA (evidence: binary); software using it fails at PQC.
- **warning** `pqc-013-crypto-library-without-pqc`: libgcrypt 1.8.5 has no ML-KEM / ML-DSA (evidence: binary); software using it fails at PQC.
- **warning** `pqc-013-crypto-library-without-pqc`: libssh 0.9.6 has no ML-KEM / ML-DSA (evidence: binary); software using it fails at PQC.
- **note** `pqc-004-classical-only-trust-store`: Scanned 356 certificates across 3 trust-store directories; every cert uses classical signatures.
- **note** `pqc-009-classical-package-signing-keys`: All 1 trusted package-signing keys are classical (RSA); none uses ML-DSA or SLH-DSA (RFC 9980).
- **note** `pqc-020-pqc-capable-not-configured`: PQC-capable software is configured to stay classical (protocols: ssh); a configuration change closes the gap.
- **note** `pqc-030-classical-boot-chain`: Boot chain is classical: kernel modules are signed with RSA-3072 / sha256.
- **note** `pqc-031-kerberos-weak-enctypes`: Kerberos: 128-bit enctypes are permitted (aes128-cts-hmac-sha1-96, aes128-cts-hmac-sha256-128, camellia128-cts-cmac); Grover's algorithm leaves them ~64-bit security and CNSA 2.0 requires AES-256.

</details>

<details>
<summary><b>Rocky Linux 9.8 (Blue Onyx)</b>: 10 findings</summary>

- **warning** `pqc-005-slh-dsa-in-tls-context`: OpenSSL exposes SLH-DSA signature algorithms (SLH-DSA-SHA2-128f, SLH-DSA-SHA2-128s, SLH-DSA-SHA2-192f, SLH-DSA-SHA2-192s, SLH-DSA-SHA2-256f, SLH-DSA-SHA2-256s, SLH-DSA-SHAKE-128f, SLH-DSA-SHAKE-128s, SLH-DSA-SHAKE-192f, SLH-DSA-SHAKE-192s, SLH-DSA-SHAKE-256f, SLH-DSA-SHAKE-256s); prefer ML-DSA for TLS handshakes.
- **warning** `pqc-008-crypto-policy-blocks-pqc`: Crypto policy DEFAULT allows no PQC TLS groups, although OpenSSL supports SecP256r1MLKEM768, SecP384r1MLKEM1024, X25519MLKEM768, MLKEM1024, MLKEM512, MLKEM768.
- **warning** `pqc-010-sshd-pqc-kex-not-offered`: sshd offers no post-quantum key exchange although the installed OpenSSH supports one; offered: curve25519-sha256, curve25519-sha256@libssh.org, ecdh-sha2-nistp256, ecdh-sha2-nistp384, ....
- **warning** `pqc-013-crypto-library-without-pqc`: libgcrypt 1.10.0 has no ML-KEM / ML-DSA (evidence: binary); software using it fails at PQC.
- **warning** `pqc-013-crypto-library-without-pqc`: libssh 0.10.4 has no ML-KEM / ML-DSA (evidence: binary); software using it fails at PQC.
- **note** `pqc-004-classical-only-trust-store`: Scanned 390 certificates across 3 trust-store directories; every cert uses classical signatures.
- **note** `pqc-009-classical-package-signing-keys`: All 1 trusted package-signing keys are classical (RSA); none uses ML-DSA or SLH-DSA (RFC 9980).
- **note** `pqc-020-pqc-capable-not-configured`: PQC-capable software is configured to stay classical (protocols: tls, ssh); a configuration change closes the gap.
- **note** `pqc-030-classical-boot-chain`: Boot chain is classical: kernel modules are signed with RSA-3072 / sha256; IMA code-signing certificates are EC P-384.
- **note** `pqc-031-kerberos-weak-enctypes`: Kerberos: 128-bit enctypes are permitted (aes128-cts-hmac-sha1-96, aes128-cts-hmac-sha256-128); Grover's algorithm leaves them ~64-bit security and CNSA 2.0 requires AES-256.

</details>

<details>
<summary><b>Rocky Linux 10.2 (Red Quartz)</b>: 6 findings</summary>

- **warning** `pqc-005-slh-dsa-in-tls-context`: OpenSSL exposes SLH-DSA signature algorithms (SLH-DSA-SHA2-128f, SLH-DSA-SHA2-128s, SLH-DSA-SHA2-192f, SLH-DSA-SHA2-192s, SLH-DSA-SHA2-256f, SLH-DSA-SHA2-256s, SLH-DSA-SHAKE-128f, SLH-DSA-SHAKE-128s, SLH-DSA-SHAKE-192f, SLH-DSA-SHAKE-192s, SLH-DSA-SHAKE-256f, SLH-DSA-SHAKE-256s); prefer ML-DSA for TLS handshakes.
- **note** `pqc-004-classical-only-trust-store`: Scanned 390 certificates across 3 trust-store directories; every cert uses classical signatures.
- **note** `pqc-009-classical-package-signing-keys`: All 1 trusted package-signing keys are classical (RSA); none uses ML-DSA or SLH-DSA (RFC 9980).
- **note** `pqc-014-crypto-library-pre-standard-mlkem`: libgcrypt 1.11.0: Upstream libgcrypt before 1.11.1 implements Kyber as in the FIPS 203 initial public draft, which does not interoperate with final ML-KEM; a distribution build may carry the final-standard patch.
- **note** `pqc-030-classical-boot-chain`: Boot chain is classical: kernel modules are signed with RSA-3072 / sha256; IMA code-signing certificates are EC P-384.
- **note** `pqc-031-kerberos-weak-enctypes`: Kerberos: 128-bit enctypes are permitted (aes128-cts-hmac-sha1-96, aes128-cts-hmac-sha256-128); Grover's algorithm leaves them ~64-bit security and CNSA 2.0 requires AES-256.

</details>

<details>
<summary><b>AlmaLinux 8.10 (Cerulean Leopard)</b>: 18 findings</summary>

- **warning** `pqc-001-openssl-pre-3.5`: OpenSSL 1.1.1k  FIPS 25 Mar 2021 is older than 3.5.0 — native ML-KEM / ML-DSA are not available.
- **warning** `pqc-010-sshd-pqc-kex-not-offered`: sshd offers no post-quantum key exchange although the installed OpenSSH supports one; offered: curve25519-sha256, curve25519-sha256@libssh.org, ecdh-sha2-nistp256, ecdh-sha2-nistp384, ....
- **warning** `pqc-011-service-crypto-library-without-pqc`: sshd.service on tcp 0.0.0.0:22 uses openssl 1.x (from soname), which has no ML-KEM hybrid key exchange; its connections stay classical.
- **warning** `pqc-011-service-crypto-library-without-pqc`: sshd.service on tcp [::]:22 uses openssl 1.x (from soname), which has no ML-KEM hybrid key exchange; its connections stay classical.
- **warning** `pqc-011-service-crypto-library-without-pqc`: rpcbind.service on tcp 0.0.0.0:111 uses openssl 1.x (from soname), which has no ML-KEM hybrid key exchange; its connections stay classical.
- **warning** `pqc-011-service-crypto-library-without-pqc`: rpcbind.service on tcp [::]:111 uses openssl 1.x (from soname), which has no ML-KEM hybrid key exchange; its connections stay classical.
- **warning** `pqc-011-service-crypto-library-without-pqc`: rpcbind.service on udp 0.0.0.0:111 uses openssl 1.x (from soname), which has no ML-KEM hybrid key exchange; its connections stay classical.
- **warning** `pqc-011-service-crypto-library-without-pqc`: rpcbind.service on udp [::]:111 uses openssl 1.x (from soname), which has no ML-KEM hybrid key exchange; its connections stay classical.
- **warning** `pqc-011-service-crypto-library-without-pqc`: chronyd.service on udp 127.0.0.1:323 uses gnutls 3.6.16, which has no ML-KEM hybrid key exchange; its connections stay classical.
- **warning** `pqc-011-service-crypto-library-without-pqc`: chronyd.service on udp [::1]:323 uses gnutls 3.6.16, which has no ML-KEM hybrid key exchange; its connections stay classical.
- **warning** `pqc-013-crypto-library-without-pqc`: gnutls 3.6.16 has no ML-KEM / ML-DSA (evidence: binary); software using it fails at PQC.
- **warning** `pqc-013-crypto-library-without-pqc`: libgcrypt 1.8.5 has no ML-KEM / ML-DSA (evidence: binary); software using it fails at PQC.
- **warning** `pqc-013-crypto-library-without-pqc`: libssh 0.9.6 has no ML-KEM / ML-DSA (evidence: binary); software using it fails at PQC.
- **note** `pqc-004-classical-only-trust-store`: Scanned 390 certificates across 3 trust-store directories; every cert uses classical signatures.
- **note** `pqc-009-classical-package-signing-keys`: All 2 trusted package-signing keys are classical (RSA); none uses ML-DSA or SLH-DSA (RFC 9980).
- **note** `pqc-020-pqc-capable-not-configured`: PQC-capable software is configured to stay classical (protocols: ssh); a configuration change closes the gap.
- **note** `pqc-030-classical-boot-chain`: Boot chain is classical: kernel modules are signed with RSA-3072 / sha256.
- **note** `pqc-031-kerberos-weak-enctypes`: Kerberos: 128-bit enctypes are permitted (aes128-cts-hmac-sha1-96, aes128-cts-hmac-sha256-128, camellia128-cts-cmac); Grover's algorithm leaves them ~64-bit security and CNSA 2.0 requires AES-256.

</details>

<details>
<summary><b>AlmaLinux 9.8 (Olive Jaguar)</b>: 10 findings</summary>

- **warning** `pqc-005-slh-dsa-in-tls-context`: OpenSSL exposes SLH-DSA signature algorithms (SLH-DSA-SHA2-128f, SLH-DSA-SHA2-128s, SLH-DSA-SHA2-192f, SLH-DSA-SHA2-192s, SLH-DSA-SHA2-256f, SLH-DSA-SHA2-256s, SLH-DSA-SHAKE-128f, SLH-DSA-SHAKE-128s, SLH-DSA-SHAKE-192f, SLH-DSA-SHAKE-192s, SLH-DSA-SHAKE-256f, SLH-DSA-SHAKE-256s); prefer ML-DSA for TLS handshakes.
- **warning** `pqc-008-crypto-policy-blocks-pqc`: Crypto policy DEFAULT allows no PQC TLS groups, although OpenSSL supports SecP256r1MLKEM768, SecP384r1MLKEM1024, X25519MLKEM768, MLKEM1024, MLKEM512, MLKEM768.
- **warning** `pqc-010-sshd-pqc-kex-not-offered`: sshd offers no post-quantum key exchange although the installed OpenSSH supports one; offered: curve25519-sha256, curve25519-sha256@libssh.org, ecdh-sha2-nistp256, ecdh-sha2-nistp384, ....
- **warning** `pqc-013-crypto-library-without-pqc`: libgcrypt 1.10.0 has no ML-KEM / ML-DSA (evidence: binary); software using it fails at PQC.
- **warning** `pqc-013-crypto-library-without-pqc`: libssh 0.10.4 has no ML-KEM / ML-DSA (evidence: binary); software using it fails at PQC.
- **note** `pqc-004-classical-only-trust-store`: Scanned 390 certificates across 3 trust-store directories; every cert uses classical signatures.
- **note** `pqc-009-classical-package-signing-keys`: All 1 trusted package-signing keys are classical (RSA); none uses ML-DSA or SLH-DSA (RFC 9980).
- **note** `pqc-020-pqc-capable-not-configured`: PQC-capable software is configured to stay classical (protocols: tls, ssh); a configuration change closes the gap.
- **note** `pqc-030-classical-boot-chain`: Boot chain is classical: kernel modules are signed with RSA-3072 / sha256; IMA code-signing certificates are EC P-384.
- **note** `pqc-031-kerberos-weak-enctypes`: Kerberos: 128-bit enctypes are permitted (aes128-cts-hmac-sha1-96, aes128-cts-hmac-sha256-128); Grover's algorithm leaves them ~64-bit security and CNSA 2.0 requires AES-256.

</details>

<details>
<summary><b>AlmaLinux 10.2 (Lavender Lion)</b>: 6 findings</summary>

- **warning** `pqc-005-slh-dsa-in-tls-context`: OpenSSL exposes SLH-DSA signature algorithms (SLH-DSA-SHA2-128f, SLH-DSA-SHA2-128s, SLH-DSA-SHA2-192f, SLH-DSA-SHA2-192s, SLH-DSA-SHA2-256f, SLH-DSA-SHA2-256s, SLH-DSA-SHAKE-128f, SLH-DSA-SHAKE-128s, SLH-DSA-SHAKE-192f, SLH-DSA-SHAKE-192s, SLH-DSA-SHAKE-256f, SLH-DSA-SHAKE-256s); prefer ML-DSA for TLS handshakes.
- **note** `pqc-004-classical-only-trust-store`: Scanned 390 certificates across 3 trust-store directories; every cert uses classical signatures.
- **note** `pqc-009-classical-package-signing-keys`: All 1 trusted package-signing keys are classical (RSA); none uses ML-DSA or SLH-DSA (RFC 9980).
- **note** `pqc-014-crypto-library-pre-standard-mlkem`: libgcrypt 1.11.0: Upstream libgcrypt before 1.11.1 implements Kyber as in the FIPS 203 initial public draft, which does not interoperate with final ML-KEM; a distribution build may carry the final-standard patch.
- **note** `pqc-030-classical-boot-chain`: Boot chain is classical: kernel modules are signed with RSA-3072 / sha256; IMA code-signing certificates are EC P-384.
- **note** `pqc-031-kerberos-weak-enctypes`: Kerberos: 128-bit enctypes are permitted (aes128-cts-hmac-sha1-96, aes128-cts-hmac-sha256-128); Grover's algorithm leaves them ~64-bit security and CNSA 2.0 requires AES-256.

</details>

<details>
<summary><b>Oracle Linux Server 8.10</b>: 14 findings</summary>

- **warning** `pqc-001-openssl-pre-3.5`: OpenSSL 1.1.1k  FIPS 25 Mar 2021 is older than 3.5.0 — native ML-KEM / ML-DSA are not available.
- **warning** `pqc-010-sshd-pqc-kex-not-offered`: sshd offers no post-quantum key exchange although the installed OpenSSH supports one; offered: curve25519-sha256, curve25519-sha256@libssh.org, ecdh-sha2-nistp256, ecdh-sha2-nistp384, ....
- **warning** `pqc-011-service-crypto-library-without-pqc`: sshd.service on tcp 0.0.0.0:22 uses openssl 1.x (from soname), which has no ML-KEM hybrid key exchange; its connections stay classical.
- **warning** `pqc-011-service-crypto-library-without-pqc`: sshd.service on tcp [::]:22 uses openssl 1.x (from soname), which has no ML-KEM hybrid key exchange; its connections stay classical.
- **warning** `pqc-011-service-crypto-library-without-pqc`: chronyd.service on udp 127.0.0.1:323 uses gnutls 3.6.16, which has no ML-KEM hybrid key exchange; its connections stay classical.
- **warning** `pqc-011-service-crypto-library-without-pqc`: chronyd.service on udp [::1]:323 uses gnutls 3.6.16, which has no ML-KEM hybrid key exchange; its connections stay classical.
- **warning** `pqc-013-crypto-library-without-pqc`: gnutls 3.6.16 has no ML-KEM / ML-DSA (evidence: binary); software using it fails at PQC.
- **warning** `pqc-013-crypto-library-without-pqc`: libgcrypt 1.8.5 has no ML-KEM / ML-DSA (evidence: binary); software using it fails at PQC.
- **warning** `pqc-013-crypto-library-without-pqc`: libssh 0.9.6 has no ML-KEM / ML-DSA (evidence: binary); software using it fails at PQC.
- **note** `pqc-004-classical-only-trust-store`: Scanned 390 certificates across 3 trust-store directories; every cert uses classical signatures.
- **note** `pqc-009-classical-package-signing-keys`: All 1 trusted package-signing keys are classical (RSA); none uses ML-DSA or SLH-DSA (RFC 9980).
- **note** `pqc-020-pqc-capable-not-configured`: PQC-capable software is configured to stay classical (protocols: ssh); a configuration change closes the gap.
- **note** `pqc-030-classical-boot-chain`: Boot chain is classical: kernel modules are signed with RSA-4096 / sha512.
- **note** `pqc-031-kerberos-weak-enctypes`: Kerberos: 128-bit enctypes are permitted (aes128-cts-hmac-sha1-96, aes128-cts-hmac-sha256-128, camellia128-cts-cmac); Grover's algorithm leaves them ~64-bit security and CNSA 2.0 requires AES-256.

</details>

<details>
<summary><b>Oracle Linux Server 9.8</b>: 10 findings</summary>

- **warning** `pqc-005-slh-dsa-in-tls-context`: OpenSSL exposes SLH-DSA signature algorithms (SLH-DSA-SHA2-128f, SLH-DSA-SHA2-128s, SLH-DSA-SHA2-192f, SLH-DSA-SHA2-192s, SLH-DSA-SHA2-256f, SLH-DSA-SHA2-256s, SLH-DSA-SHAKE-128f, SLH-DSA-SHAKE-128s, SLH-DSA-SHAKE-192f, SLH-DSA-SHAKE-192s, SLH-DSA-SHAKE-256f, SLH-DSA-SHAKE-256s); prefer ML-DSA for TLS handshakes.
- **warning** `pqc-008-crypto-policy-blocks-pqc`: Crypto policy DEFAULT allows no PQC TLS groups, although OpenSSL supports SecP256r1MLKEM768, SecP384r1MLKEM1024, X25519MLKEM768, MLKEM1024, MLKEM512, MLKEM768.
- **warning** `pqc-010-sshd-pqc-kex-not-offered`: sshd offers no post-quantum key exchange although the installed OpenSSH supports one; offered: curve25519-sha256, curve25519-sha256@libssh.org, ecdh-sha2-nistp256, ecdh-sha2-nistp384, ....
- **warning** `pqc-013-crypto-library-without-pqc`: libgcrypt 1.10.0 has no ML-KEM / ML-DSA (evidence: binary); software using it fails at PQC.
- **warning** `pqc-013-crypto-library-without-pqc`: libssh 0.10.4 has no ML-KEM / ML-DSA (evidence: binary); software using it fails at PQC.
- **note** `pqc-004-classical-only-trust-store`: Scanned 390 certificates across 3 trust-store directories; every cert uses classical signatures.
- **note** `pqc-009-classical-package-signing-keys`: All 2 trusted package-signing keys are classical (RSA); none uses ML-DSA or SLH-DSA (RFC 9980).
- **note** `pqc-020-pqc-capable-not-configured`: PQC-capable software is configured to stay classical (protocols: tls, ssh); a configuration change closes the gap.
- **note** `pqc-030-classical-boot-chain`: Boot chain is classical: kernel modules are signed with RSA-4096 / sha256; IMA code-signing certificates are EC P-384.
- **note** `pqc-031-kerberos-weak-enctypes`: Kerberos: 128-bit enctypes are permitted (aes128-cts-hmac-sha1-96, aes128-cts-hmac-sha256-128); Grover's algorithm leaves them ~64-bit security and CNSA 2.0 requires AES-256.

</details>

<details>
<summary><b>CentOS Stream 9</b>: 10 findings</summary>

- **warning** `pqc-005-slh-dsa-in-tls-context`: OpenSSL exposes SLH-DSA signature algorithms (SLH-DSA-SHA2-128f, SLH-DSA-SHA2-128s, SLH-DSA-SHA2-192f, SLH-DSA-SHA2-192s, SLH-DSA-SHA2-256f, SLH-DSA-SHA2-256s, SLH-DSA-SHAKE-128f, SLH-DSA-SHAKE-128s, SLH-DSA-SHAKE-192f, SLH-DSA-SHAKE-192s, SLH-DSA-SHAKE-256f, SLH-DSA-SHAKE-256s); prefer ML-DSA for TLS handshakes.
- **warning** `pqc-008-crypto-policy-blocks-pqc`: Crypto policy DEFAULT allows no PQC TLS groups, although OpenSSL supports SecP256r1MLKEM768, SecP384r1MLKEM1024, X25519MLKEM768, MLKEM1024, MLKEM512, MLKEM768.
- **warning** `pqc-010-sshd-pqc-kex-not-offered`: sshd offers no post-quantum key exchange although the installed OpenSSH supports one; offered: curve25519-sha256, curve25519-sha256@libssh.org, ecdh-sha2-nistp256, ecdh-sha2-nistp384, ....
- **warning** `pqc-013-crypto-library-without-pqc`: libgcrypt 1.10.0 has no ML-KEM / ML-DSA (evidence: binary); software using it fails at PQC.
- **warning** `pqc-013-crypto-library-without-pqc`: libssh 0.10.4 has no ML-KEM / ML-DSA (evidence: binary); software using it fails at PQC.
- **note** `pqc-004-classical-only-trust-store`: Scanned 396 certificates across 3 trust-store directories; every cert uses classical signatures.
- **note** `pqc-009-classical-package-signing-keys`: All 2 trusted package-signing keys are classical (RSA); none uses ML-DSA or SLH-DSA (RFC 9980).
- **note** `pqc-020-pqc-capable-not-configured`: PQC-capable software is configured to stay classical (protocols: tls, ssh); a configuration change closes the gap.
- **note** `pqc-030-classical-boot-chain`: Boot chain is classical: kernel modules are signed with RSA-3072 / sha256; IMA code-signing certificates are EC P-384.
- **note** `pqc-031-kerberos-weak-enctypes`: Kerberos: 128-bit enctypes are permitted (aes128-cts-hmac-sha1-96, aes128-cts-hmac-sha256-128); Grover's algorithm leaves them ~64-bit security and CNSA 2.0 requires AES-256.

</details>

<details>
<summary><b>CentOS Stream 10 (Coughlan)</b>: 6 findings</summary>

- **warning** `pqc-005-slh-dsa-in-tls-context`: OpenSSL exposes SLH-DSA signature algorithms (SLH-DSA-SHA2-128f, SLH-DSA-SHA2-128s, SLH-DSA-SHA2-192f, SLH-DSA-SHA2-192s, SLH-DSA-SHA2-256f, SLH-DSA-SHA2-256s, SLH-DSA-SHAKE-128f, SLH-DSA-SHAKE-128s, SLH-DSA-SHAKE-192f, SLH-DSA-SHAKE-192s, SLH-DSA-SHAKE-256f, SLH-DSA-SHAKE-256s); prefer ML-DSA for TLS handshakes.
- **note** `pqc-004-classical-only-trust-store`: Scanned 396 certificates across 3 trust-store directories; every cert uses classical signatures.
- **note** `pqc-009-classical-package-signing-keys`: All 2 trusted package-signing keys are classical (RSA); none uses ML-DSA or SLH-DSA (RFC 9980).
- **note** `pqc-014-crypto-library-pre-standard-mlkem`: libgcrypt 1.11.0: Upstream libgcrypt before 1.11.1 implements Kyber as in the FIPS 203 initial public draft, which does not interoperate with final ML-KEM; a distribution build may carry the final-standard patch.
- **note** `pqc-030-classical-boot-chain`: Boot chain is classical: kernel modules are signed with RSA-3072 / sha256; IMA code-signing certificates are EC P-384.
- **note** `pqc-031-kerberos-weak-enctypes`: Kerberos: 128-bit enctypes are permitted (aes128-cts-hmac-sha1-96, aes128-cts-hmac-sha256-128); Grover's algorithm leaves them ~64-bit security and CNSA 2.0 requires AES-256.

</details>

<details>
<summary><b>Fedora Linux 43 (Cloud Edition)</b>: 6 findings</summary>

- **warning** `pqc-005-slh-dsa-in-tls-context`: OpenSSL exposes SLH-DSA signature algorithms (SLH-DSA-SHA2-128f, SLH-DSA-SHA2-128s, SLH-DSA-SHA2-192f, SLH-DSA-SHA2-192s, SLH-DSA-SHA2-256f, SLH-DSA-SHA2-256s, SLH-DSA-SHAKE-128f, SLH-DSA-SHAKE-128s, SLH-DSA-SHAKE-192f, SLH-DSA-SHAKE-192s, SLH-DSA-SHAKE-256f, SLH-DSA-SHAKE-256s); prefer ML-DSA for TLS handshakes.
- **warning** `pqc-013-crypto-library-without-pqc`: libssh 0.11.3 has no ML-KEM / ML-DSA (evidence: binary); software using it fails at PQC.
- **note** `pqc-004-classical-only-trust-store`: Scanned 390 certificates across 3 trust-store directories; every cert uses classical signatures.
- **note** `pqc-009-classical-package-signing-keys`: All 1 trusted package-signing keys are classical (RSA); none uses ML-DSA or SLH-DSA (RFC 9980).
- **note** `pqc-030-classical-boot-chain`: Boot chain is classical: kernel modules are signed with RSA-4096 / sha256; IMA code-signing certificates are EC P-256.
- **note** `pqc-031-kerberos-weak-enctypes`: Kerberos: 128-bit enctypes are permitted (aes128-cts-hmac-sha1-96, aes128-cts-hmac-sha256-128, camellia128-cts-cmac); Grover's algorithm leaves them ~64-bit security and CNSA 2.0 requires AES-256.

</details>

<details>
<summary><b>Fedora Linux 44 (Cloud Edition)</b>: 5 findings</summary>

- **warning** `pqc-005-slh-dsa-in-tls-context`: OpenSSL exposes SLH-DSA signature algorithms (SLH-DSA-SHA2-128f, SLH-DSA-SHA2-128s, SLH-DSA-SHA2-192f, SLH-DSA-SHA2-192s, SLH-DSA-SHA2-256f, SLH-DSA-SHA2-256s, SLH-DSA-SHAKE-128f, SLH-DSA-SHAKE-128s, SLH-DSA-SHAKE-192f, SLH-DSA-SHAKE-192s, SLH-DSA-SHAKE-256f, SLH-DSA-SHAKE-256s); prefer ML-DSA for TLS handshakes.
- **note** `pqc-004-classical-only-trust-store`: Scanned 388 certificates across 3 trust-store directories; every cert uses classical signatures.
- **note** `pqc-009-classical-package-signing-keys`: All 1 trusted package-signing keys are classical (RSA); none uses ML-DSA or SLH-DSA (RFC 9980).
- **note** `pqc-030-classical-boot-chain`: Boot chain is classical: kernel modules are signed with RSA-4096 / sha256; IMA code-signing certificates are EC P-256.
- **note** `pqc-031-kerberos-weak-enctypes`: Kerberos: 128-bit enctypes are permitted (aes128-cts-hmac-sha1-96, aes128-cts-hmac-sha256-128, camellia128-cts-cmac); Grover's algorithm leaves them ~64-bit security and CNSA 2.0 requires AES-256.

</details>

<details>
<summary><b>Amazon Linux 2023.12.20261012</b>: 9 findings</summary>

- **warning** `pqc-005-slh-dsa-in-tls-context`: OpenSSL exposes SLH-DSA signature algorithms (SLH-DSA-SHA2-128f, SLH-DSA-SHA2-128s, SLH-DSA-SHA2-192f, SLH-DSA-SHA2-192s, SLH-DSA-SHA2-256f, SLH-DSA-SHA2-256s, SLH-DSA-SHAKE-128f, SLH-DSA-SHAKE-128s, SLH-DSA-SHAKE-192f, SLH-DSA-SHAKE-192s, SLH-DSA-SHAKE-256f, SLH-DSA-SHAKE-256s); prefer ML-DSA for TLS handshakes.
- **warning** `pqc-008-crypto-policy-blocks-pqc`: Crypto policy DEFAULT allows no PQC TLS groups, although OpenSSL supports SecP256r1MLKEM768, SecP384r1MLKEM1024, X25519MLKEM768, MLKEM1024, MLKEM512, MLKEM768.
- **warning** `pqc-010-sshd-pqc-kex-not-offered`: sshd offers no post-quantum key exchange although the installed OpenSSH supports one; offered: curve25519-sha256, curve25519-sha256@libssh.org, ecdh-sha2-nistp256, ecdh-sha2-nistp384, ....
- **warning** `pqc-013-crypto-library-without-pqc`: libgcrypt 1.10.2 has no ML-KEM / ML-DSA (evidence: binary); software using it fails at PQC.
- **note** `pqc-004-classical-only-trust-store`: Scanned 310 certificates across 3 trust-store directories; every cert uses classical signatures.
- **note** `pqc-009-classical-package-signing-keys`: All 1 trusted package-signing keys are classical (RSA); none uses ML-DSA or SLH-DSA (RFC 9980).
- **note** `pqc-020-pqc-capable-not-configured`: PQC-capable software is configured to stay classical (protocols: tls, ssh); a configuration change closes the gap.
- **note** `pqc-030-classical-boot-chain`: Boot chain is classical: kernel modules are signed with RSA-4096 / sha256.
- **note** `pqc-031-kerberos-weak-enctypes`: Kerberos: 128-bit enctypes are permitted (aes128-cts-hmac-sha1-96, aes128-cts-hmac-sha256-128); Grover's algorithm leaves them ~64-bit security and CNSA 2.0 requires AES-256.

</details>

<details>
<summary><b>Ubuntu 26.04.1 LTS</b>: 6 findings</summary>

- **warning** `pqc-005-slh-dsa-in-tls-context`: OpenSSL exposes SLH-DSA signature algorithms (SLH-DSA-SHA2-128f, SLH-DSA-SHA2-128s, SLH-DSA-SHA2-192f, SLH-DSA-SHA2-192s, SLH-DSA-SHA2-256f, SLH-DSA-SHA2-256s, SLH-DSA-SHAKE-128f, SLH-DSA-SHAKE-128s, SLH-DSA-SHAKE-192f, SLH-DSA-SHAKE-192s, SLH-DSA-SHAKE-256f, SLH-DSA-SHAKE-256s); prefer ML-DSA for TLS handshakes.
- **warning** `pqc-011-service-crypto-library-without-pqc`: chrony.service on udp 127.0.0.1:323 uses gnutls 3.8.12, which has no ML-KEM hybrid key exchange; its connections stay classical.
- **warning** `pqc-011-service-crypto-library-without-pqc`: chrony.service on udp [::1]:323 uses gnutls 3.8.12, which has no ML-KEM hybrid key exchange; its connections stay classical.
- **note** `pqc-004-classical-only-trust-store`: Scanned 121 certificates across 1 trust-store directories; every cert uses classical signatures.
- **note** `pqc-009-classical-package-signing-keys`: All 3 trusted package-signing keys are classical (RSA); none uses ML-DSA or SLH-DSA (RFC 9980).
- **note** `pqc-030-classical-boot-chain`: Boot chain is classical: kernel modules are signed with RSA-4096 / sha512.

</details>

<details>
<summary><b>openSUSE Leap 15.6</b>: 12 findings</summary>

- **warning** `pqc-001-openssl-pre-3.5`: OpenSSL 3.1.4 24 Oct 2023 (Library: OpenSSL 3.1.4 24 Oct 2023) is older than 3.5.0 — native ML-KEM / ML-DSA are not available.
- **warning** `pqc-011-service-crypto-library-without-pqc`: sshd.service on tcp 0.0.0.0:22 uses openssl 3.1.4, which has no ML-KEM hybrid key exchange; its connections stay classical.
- **warning** `pqc-011-service-crypto-library-without-pqc`: sshd.service on tcp [::]:22 uses openssl 3.1.4, which has no ML-KEM hybrid key exchange; its connections stay classical.
- **warning** `pqc-011-service-crypto-library-without-pqc`: chronyd.service on udp 127.0.0.1:323 uses gnutls 3.8.3, which has no ML-KEM hybrid key exchange; its connections stay classical.
- **warning** `pqc-011-service-crypto-library-without-pqc`: chronyd.service on udp [::1]:323 uses gnutls 3.8.3, which has no ML-KEM hybrid key exchange; its connections stay classical.
- **warning** `pqc-013-crypto-library-without-pqc`: gnutls 3.8.3 has no ML-KEM / ML-DSA (evidence: binary); software using it fails at PQC.
- **warning** `pqc-013-crypto-library-without-pqc`: libgcrypt 1.10.3 has no ML-KEM / ML-DSA (evidence: binary); software using it fails at PQC.
- **warning** `pqc-013-crypto-library-without-pqc`: libssh 0.9.8 has no ML-KEM / ML-DSA (evidence: binary); software using it fails at PQC.
- **note** `pqc-004-classical-only-trust-store`: Scanned 145 certificates across 1 trust-store directories; every cert uses classical signatures.
- **note** `pqc-009-classical-package-signing-keys`: All 6 trusted package-signing keys are classical (RSA); none uses ML-DSA or SLH-DSA (RFC 9980).
- **note** `pqc-030-classical-boot-chain`: Boot chain is classical: the kernel is configured for RSA module signing.
- **note** `pqc-031-kerberos-weak-enctypes`: Kerberos: 128-bit enctypes are permitted (aes128-cts-hmac-sha1-96, aes128-cts-hmac-sha256-128, camellia128-cts-cmac); Grover's algorithm leaves them ~64-bit security and CNSA 2.0 requires AES-256.

</details>

<details>
<summary><b>openSUSE Leap 16.0</b>: 6 findings</summary>

- **warning** `pqc-005-slh-dsa-in-tls-context`: OpenSSL exposes SLH-DSA signature algorithms (SLH-DSA-SHA2-128f, SLH-DSA-SHA2-128s, SLH-DSA-SHA2-192f, SLH-DSA-SHA2-192s, SLH-DSA-SHA2-256f, SLH-DSA-SHA2-256s, SLH-DSA-SHAKE-128f, SLH-DSA-SHAKE-128s, SLH-DSA-SHAKE-192f, SLH-DSA-SHAKE-192s, SLH-DSA-SHAKE-256f, SLH-DSA-SHAKE-256s); prefer ML-DSA for TLS handshakes.
- **warning** `pqc-013-crypto-library-without-pqc`: libssh 0.11.5 has no ML-KEM / ML-DSA (evidence: binary); software using it fails at PQC.
- **note** `pqc-004-classical-only-trust-store`: Scanned 121 certificates across 1 trust-store directories; every cert uses classical signatures.
- **note** `pqc-009-classical-package-signing-keys`: All 6 trusted package-signing keys are classical (RSA); none uses ML-DSA or SLH-DSA (RFC 9980).
- **note** `pqc-030-classical-boot-chain`: Boot chain is classical: the kernel is configured for RSA module signing.
- **note** `pqc-031-kerberos-weak-enctypes`: Kerberos: 128-bit enctypes are permitted (aes128-cts-hmac-sha1-96, aes128-cts-hmac-sha256-128, camellia128-cts-cmac); Grover's algorithm leaves them ~64-bit security and CNSA 2.0 requires AES-256.

</details>

<details>
<summary><b>openSUSE Tumbleweed</b>: 5 findings</summary>

- **warning** `pqc-005-slh-dsa-in-tls-context`: OpenSSL exposes SLH-DSA signature algorithms (SLH-DSA-SHA2-128f, SLH-DSA-SHA2-128s, SLH-DSA-SHA2-192f, SLH-DSA-SHA2-192s, SLH-DSA-SHA2-256f, SLH-DSA-SHA2-256s, SLH-DSA-SHAKE-128f, SLH-DSA-SHAKE-128s, SLH-DSA-SHAKE-192f, SLH-DSA-SHAKE-192s, SLH-DSA-SHAKE-256f, SLH-DSA-SHAKE-256s); prefer ML-DSA for TLS handshakes.
- **warning** `pqc-013-crypto-library-without-pqc`: libssh 0.11.5 has no ML-KEM / ML-DSA (evidence: binary); software using it fails at PQC.
- **note** `pqc-004-classical-only-trust-store`: Scanned 121 certificates across 1 trust-store directories; every cert uses classical signatures.
- **note** `pqc-009-classical-package-signing-keys`: All 5 trusted package-signing keys are classical (RSA); none uses ML-DSA or SLH-DSA (RFC 9980).
- **note** `pqc-030-classical-boot-chain`: Boot chain is classical: the kernel is configured for RSA module signing.

</details>

## How this was run

- **Scanner.** `pqc-readiness.pyz` v2.4.0 (schema 1.8), SHA-256 `7a60a0e9b8b34547f13d347af1def830152c7d74e38dc41e01e77cae591415d6`, identical to the [release asset](https://github.com/aclater/pqc-readiness/releases/tag/v2.4.0). It ran as root, using the newest Python 3.9+ on each image; python3.11 was installed from the distribution's repository where the image lacked a supported Python (EL8, Leap 15.6).
- **Scans.** `--json --scan-packages --scan-trust-store --scan-crypto-material --scan-signing-keys --scan-services --scan-boot-chain --scan-crypto-libraries --scan-kerberos --scan-processes --scan-tunnels --scan-dnssec --bench --bench-tls --seconds 1`, then the same scans with `--sarif`.
- **VMs.** 17 unmodified, checksum-verified vendor cloud images (the same builds as the v2.2.0 run), booted by the [distro-matrix](https://github.com/aclater/distro-matrix) runner's qemu backend with cloud-init: 4 vCPU, 4 GiB RAM, `-cpu host`, SeaBIOS, at most four VMs at once under the host's VM budget. Command: `scripts/run-matrix.sh --scanner pqc-readiness.pyz --scanner-args '--json … --bench --bench-tls --seconds 1' --compare-scanner pqc-readiness.pyz --compare-args '--sarif …' --prepare prepare/pqc-readiness.tsv --ground-truth ground-truth/pqc-readiness.tsv --vcpus 4 --memory 4096 --parallel auto`. The verdict is `POOR` on every VM because 4 GiB is below the memory threshold. That is a property of the test VM, not the distribution.
- **RHEL rows.** RHEL 8.10, 9.8 and 10.2 ran in the same pinned UBI containers as the v2.2.0 run (`ubi8/ubi:8.10-1791892468`, `ubi9/ubi:9.8-1791888712`, `ubi10/ubi:10.2-1791893534`) with 4 CPUs and 4 GiB. Each added the packages a RHEL server image ships (`python3` or `python3.11`, `openssl`, `openssh-server`, `openssh-clients`) and generated host keys as first boot would. OpenSSL, crypto-policies, OpenSSH and the trust store are the real RHEL packages. Containers have no firmware, kernel or running services, and they see the host's RAM, so their boot chain, FIPS kernel and verdict values don't compare with the VM rows.
- **Scope.** These are stock images with no workloads. A production host running web servers, VPNs or a KDC will raise more of the service, tunnel and Kerberos rules. Debian 13 and Ubuntu 24.04 aren't in this matrix; their images are only on the maintainer's home image store.
