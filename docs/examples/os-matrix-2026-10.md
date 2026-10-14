# Example output: cross-OS scan matrix (v2.2.0)

> **Example output, not a support statement.** This page records what `pqc-readiness` v2.2.0 reported on 20 stock Linux images on 2026-10-14. It shows what the scanner produces across distributions and what each distribution ships out of the box. Results will change as distributions update their packages. Distribution support tiers are in the [README](../../README.md#distribution-support).

Every image was scanned **unmodified**: nothing was configured before the scan. The [method](#how-this-was-run) section lists the exact flags and VM sizing.

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

The TLS, SSH and IPsec columns are the per-protocol `pqc_deployment_gap.protocols.*.state` verdict ([JSON reference](../json-output.md)). `sshd kex` is the effective server configuration from `sshd -T`.

| OS | Firmware | OpenSSL | OpenSSH (PQC kex) | Crypto policy | Hybrid TLS default | TLS | SSH | IPsec | sshd kex |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **Red Hat Enterprise Linux 8.10 (UBI container)** | container | 1.1.1k (no PQC) | 8.0p1 (sntrup only) | DEFAULT | no | ❌ not capable | ⚠️ capable, off | — not present | classical |
| **Red Hat Enterprise Linux 9.8 (UBI container)** | container | 3.5.8 | 9.9p1 (ML-KEM) | DEFAULT | no | ⚠️ capable, off | ⚠️ capable, off | — not present | classical |
| **Red Hat Enterprise Linux 10.2 (UBI container)** | container | 3.5.8 | 9.9p1 (ML-KEM) | DEFAULT | yes | ✅ deployed | ✅ deployed | — not present | PQC first |
| **Rocky Linux 8.10 (Green Obsidian)** | UEFI, SB off | 1.1.1k (no PQC) | 8.0p1 (sntrup only) | DEFAULT | no | ❌ not capable | ⚠️ capable, off | — not present | classical |
| **Rocky Linux 9.8 (Blue Onyx)** | UEFI, SB off | 3.5.5 | 9.9p1 (ML-KEM) | DEFAULT | no | ⚠️ capable, off | ⚠️ capable, off | — not present | classical |
| **Rocky Linux 10.2 (Red Quartz)** | UEFI, SB off | 3.5.5 | 9.9p1 (ML-KEM) | DEFAULT | yes | ✅ deployed | ✅ deployed | — not present | PQC first |
| **AlmaLinux 8.10 (Cerulean Leopard)** | UEFI, SB off | 1.1.1k (no PQC) | 8.0p1 (sntrup only) | DEFAULT | no | ❌ not capable | ⚠️ capable, off | — not present | classical |
| **AlmaLinux 9.8 (Olive Jaguar)** | UEFI, SB off | 3.5.8 | 9.9p1 (ML-KEM) | DEFAULT | no | ⚠️ capable, off | ⚠️ capable, off | — not present | classical |
| **AlmaLinux 10.2 (Lavender Lion)** | UEFI, SB off | 3.5.8 | 9.9p1 (ML-KEM) | DEFAULT | yes | ✅ deployed | ✅ deployed | — not present | PQC first |
| **Oracle Linux Server 8.10** | UEFI, SB off | 1.1.1k (no PQC) | 8.0p1 (sntrup only) | DEFAULT | no | ❌ not capable | ⚠️ capable, off | — not present | classical |
| **Oracle Linux Server 9.8** | UEFI, SB off | 3.5.5 | 9.9p1 (ML-KEM) | DEFAULT | no | ⚠️ capable, off | ⚠️ capable, off | — not present | classical |
| **CentOS Stream 9** | UEFI, SB off | 3.5.8 | 9.9p1 (ML-KEM) | DEFAULT | no | ⚠️ capable, off | ⚠️ capable, off | — not present | classical |
| **CentOS Stream 10 (Coughlan)** | UEFI, SB off | 3.5.8 | 9.9p1 (ML-KEM) | DEFAULT | yes | ✅ deployed | ✅ deployed | — not present | PQC first |
| **Fedora Linux 43 (Cloud Edition)** | UEFI, SB off | 3.5.1 | 10.0p2 (ML-KEM) | DEFAULT | yes | ✅ deployed | ✅ deployed | — not present | PQC first |
| **Fedora Linux 44 (Cloud Edition)** | UEFI, SB off | 3.5.5 | 10.2p1 (ML-KEM) | DEFAULT | yes | ✅ deployed | ✅ deployed | — not present | PQC first |
| **Amazon Linux 2023.12.20261012** | UEFI, SB off | 3.5.8 | 9.9p1 (ML-KEM) | DEFAULT | no | ⚠️ capable, off | ⚠️ capable, off | — not present | classical |
| **Ubuntu 26.04.1 LTS** | UEFI, SB off | 3.5.5 | 10.2p1 (ML-KEM) | none | yes | ✅ deployed | ✅ deployed | — not present | PQC first |
| **openSUSE Leap 15.6** | UEFI, SB off | 3.1.4 (no PQC) | 9.6p1 (sntrup only) | DEFAULT | no | ❌ not capable | ✅ deployed | — not present | PQC first |
| **openSUSE Leap 16.0** | UEFI, SB off | 3.5.0 | 10.0p2 (ML-KEM) | DEFAULT | yes | ✅ deployed | ✅ deployed | — not present | PQC first |
| **openSUSE Tumbleweed** | UEFI, SB off | 3.5.3 | 10.5p1 (ML-KEM) | DEFAULT | yes | ✅ deployed | ✅ deployed | — not present | PQC first |

## Compliance and inventory

`PQC libs` is PQC-capable / installed crypto libraries. `Trust store` is total certificates / PQC or hybrid certificates. `Findings` is errors / warnings / notes.

| OS | PQC libs | CNSA 2.0 | FIPS kernel | Packages (source) | Trust store | Pkg signing keys | Secure Boot certs | Kerberos | Findings E/W/N |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **Red Hat Enterprise Linux 8.10 (UBI container)** | 0/3 (no PQC: gnutls, libgcrypt, libssh) | partial | off | 198 (rpmdb-bdb) | 390 / 0 | 2, all classical | none | AES-128 allowed | 0 / 5 / 4 |
| **Red Hat Enterprise Linux 9.8 (UBI container)** | 1/2 (no PQC: libgcrypt) | partial | off | 200 (rpmdb-sqlite) | 390 / 0 | 2, all classical | none | AES-128 allowed | 0 / 4 / 5 |
| **Red Hat Enterprise Linux 10.2 (UBI container)** | 1/1 | partial | off | 182 (rpmdb-sqlite) | 390 / 0 | 3, 1 hybrid, 0 PQC | none | AES-128 allowed | 0 / 1 / 3 |
| **Rocky Linux 8.10 (Green Obsidian)** | 0/3 (no PQC: gnutls, libgcrypt, libssh) | partial | off | 461 (rpmdb-bdb) | 356 / 0 | 1, all classical | 1 (RSA-2048) | AES-128 allowed | 0 / 13 / 5 |
| **Rocky Linux 9.8 (Blue Onyx)** | 1/3 (no PQC: libgcrypt, libssh) | compliant | off | 422 (rpmdb-sqlite) | 390 / 0 | 1, all classical | 1 (RSA-2048) | AES-128 allowed | 0 / 5 / 5 |
| **Rocky Linux 10.2 (Red Quartz)** | 3/3 | compliant | off | 443 (rpmdb-sqlite) | 390 / 0 | 1, all classical | 1 (RSA-2048) | AES-128 allowed | 0 / 1 / 5 |
| **AlmaLinux 8.10 (Cerulean Leopard)** | 0/3 (no PQC: gnutls, libgcrypt, libssh) | partial | off | 440 (rpmdb-bdb) | 390 / 0 | 2, all classical | 3 (RSA-2048, RSA-3072, RSA-4096) | AES-128 allowed | 0 / 13 / 5 |
| **AlmaLinux 9.8 (Olive Jaguar)** | 1/3 (no PQC: libgcrypt, libssh) | compliant | off | 387 (rpmdb-sqlite) | 390 / 0 | 1, all classical | 3 (RSA-2048, RSA-3072, RSA-4096) | AES-128 allowed | 0 / 5 / 5 |
| **AlmaLinux 10.2 (Lavender Lion)** | 3/3 | compliant | off | 380 (rpmdb-sqlite) | 390 / 0 | 1, all classical | 3 (RSA-2048, RSA-3072, RSA-4096) | AES-128 allowed | 0 / 1 / 5 |
| **Oracle Linux Server 8.10** | 0/3 (no PQC: gnutls, libgcrypt, libssh) | partial | off | 373 (rpmdb-bdb) | 390 / 0 | 1, all classical | 4 (RSA-3072, RSA-4096) | AES-128 allowed | 0 / 9 / 5 |
| **Oracle Linux Server 9.8** | 1/3 (no PQC: libgcrypt, libssh) | compliant | off | 373 (rpmdb-sqlite) | 390 / 0 | 2, all classical | 4 (RSA-3072, RSA-4096) | AES-128 allowed | 0 / 5 / 5 |
| **CentOS Stream 9** | 1/3 (no PQC: libgcrypt, libssh) | compliant | off | 473 (rpmdb-sqlite) | 396 / 0 | 2, all classical | 2 (RSA-2048, RSA-4096) | AES-128 allowed | 0 / 5 / 5 |
| **CentOS Stream 10 (Coughlan)** | 3/3 | compliant | off | 512 (rpmdb-sqlite) | 396 / 0 | 2, all classical | 2 (RSA-2048, RSA-4096) | AES-128 allowed | 0 / 1 / 5 |
| **Fedora Linux 43 (Cloud Edition)** | 2/3 (no PQC: libssh) | partial | off | 430 (rpmdb-sqlite) | 390 / 0 | 1, all classical | 1 (RSA-2048) | AES-128 allowed | 0 / 2 / 4 |
| **Fedora Linux 44 (Cloud Edition)** | 3/3 | partial | off | 427 (rpmdb-sqlite) | 388 / 0 | 1, all classical | 1 (RSA-2048) | AES-128 allowed | 0 / 1 / 4 |
| **Amazon Linux 2023.12.20261012** | 1/2 (no PQC: libgcrypt) | compliant | off | 471 (rpmdb-sqlite) | 310 / 0 | 1, all classical | none | AES-128 allowed | 0 / 4 / 5 |
| **Ubuntu 26.04.1 LTS** | 2/2 | partial | off | 678 (dpkg-query) | 121 / 0 | 3, all classical | 1 (RSA-2048) | n/a | 0 / 3 / 3 |
| **openSUSE Leap 15.6** | 0/3 (no PQC: gnutls, libgcrypt, libssh) | partial | off | 375 (rpmdb-bdb) | 145 / 0 | 6, all classical | 1 (RSA-2048) | AES-128 allowed | 0 / 8 / 4 |
| **openSUSE Leap 16.0** | 2/3 (no PQC: libssh) | compliant | off | 378 (rpmdb-ndb) | 121 / 0 | 6, all classical | 1 (RSA-2048) | AES-128 allowed | 0 / 2 / 4 |
| **openSUSE Tumbleweed** | 2/3 (no PQC: libssh) | partial | off | 372 (rpmdb-ndb) | 121 / 0 | 5, all classical | 1 (RSA-2048) | n/a | 0 / 2 / 3 |

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

Single-thread `openssl speed` (1 s per test) and the loopback TLS 1.3 handshake benchmark (`--bench --bench-tls`), in operations per second. Every host ran on the same CPU (AMD Ryzen AI 9 HX 370 w/ Radeon 890M), so the differences come from each distribution's OpenSSL build. Up to six VMs ran at once, which adds noise. The RHEL container rows ran without virtualization or that contention, so their numbers run higher and should not be compared with the VM rows. Hosts without native PQC in OpenSSL have no PQC numbers.

| OS | ML-KEM-768 encaps | ML-KEM-768 decaps | ML-DSA-65 sign | ML-DSA-65 verify | SLH-DSA-128s sign | RSA-2048 sign | ECDH | TLS x25519 | TLS X25519MLKEM768 | TLS MLKEM768 | Hybrid vs classical |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **Red Hat Enterprise Linux 8.10 (UBI container)** | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a |
| **Red Hat Enterprise Linux 9.8 (UBI container)** | 47,766 | 31,472 | 1,652 | 9,014 | 4.9 | 5,085 | 49,444 | 121 | 110 | 115 | -9% |
| **Red Hat Enterprise Linux 10.2 (UBI container)** | 55,423 | 35,732 | 1,682 | 8,872 | 5.0 | 5,374 | 48,553 | 119 | 112 | 113 | -6% |
| **Rocky Linux 8.10 (Green Obsidian)** | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a |
| **Rocky Linux 9.8 (Blue Onyx)** | 23,758 | 17,219 | 942 | 5,334 | 2.8 | 3,098 | 34,280 | 169 | 143 | 171 | -15% |
| **Rocky Linux 10.2 (Red Quartz)** | 37,597 | 19,777 | 900 | 4,985 | 3.4 | 3,573 | 43,258 | 141 | 143 | 154 | +1% |
| **AlmaLinux 8.10 (Cerulean Leopard)** | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a |
| **AlmaLinux 9.8 (Olive Jaguar)** | 26,247 | 16,596 | 909 | 4,908 | 2.7 | 3,120 | 31,910 | 144 | 161 | 144 | +12% |
| **AlmaLinux 10.2 (Lavender Lion)** | 31,429 | 19,020 | 1,000 | 6,354 | 3.8 | 4,148 | 39,644 | 191 | 187 | 187 | -2% |
| **Oracle Linux Server 8.10** | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a |
| **Oracle Linux Server 9.8** | 19,147 | 12,428 | 709 | 3,536 | 2.0 | 2,158 | 19,933 | 75 | 81 | 82 | +8% |
| **CentOS Stream 9** | 38,291 | 21,146 | 981 | 5,704 | 3.2 | 3,948 | 39,632 | 144 | 143 | 165 | -1% |
| **CentOS Stream 10 (Coughlan)** | 42,927 | 22,272 | 1,339 | 7,094 | 4.5 | 3,798 | 32,636 | 235 | 220 | 240 | -6% |
| **Fedora Linux 43 (Cloud Edition)** | 36,321 | 23,573 | 799 | 65 | 2.0 | 3,543 | 32,712 | 146 | 149 | 156 | +2% |
| **Fedora Linux 44 (Cloud Edition)** | 39,646 | 30,668 | 1,220 | 7,183 | 4.0 | 4,599 | 41,701 | 226 | 237 | 192 | +5% |
| **Amazon Linux 2023.12.20261012** | 36,078 | 22,767 | 715 | 3,484 | 1.9 | 2,187 | 19,510 | 82 | 78 | 80 | -5% |
| **Ubuntu 26.04.1 LTS** | 21,937 | 14,034 | 609 | 3,355 | 1.9 | 2,150 | 19,275 | 86 | 78 | 83 | -9% |
| **openSUSE Leap 15.6** | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a |
| **openSUSE Leap 16.0** | 21,437 | 13,975 | n/a | n/a | n/a | 2,125 | 19,310 | 12 | 12 | 12 | -2% |
| **openSUSE Tumbleweed** | 21,517 | 14,088 | 799 | 65 | 2.0 | 2,136 | 19,125 | 11 | 11 | 11 | -2% |

## Findings by OS

<details>
<summary><b>Red Hat Enterprise Linux 8.10 (UBI container)</b>: 9 findings</summary>

- **warning** `pqc-001-openssl-pre-3.5`: OpenSSL OpenSSL 1.1.1k FIPS 25 Mar 2021 is older than 3.5.0 — native ML-KEM / ML-DSA are not available.
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

- **warning** `pqc-001-openssl-pre-3.5`: OpenSSL OpenSSL 1.1.1k FIPS 25 Mar 2021 is older than 3.5.0 — native ML-KEM / ML-DSA are not available.
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
- **note** `pqc-030-classical-boot-chain`: Boot chain is classical: Secure Boot trusts 1 certificates (PK/KEK/db/MOK), all classical: RSA-2048; kernel modules are signed with RSA-3072 / sha256.
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
- **note** `pqc-030-classical-boot-chain`: Boot chain is classical: Secure Boot trusts 1 certificates (PK/KEK/db/MOK), all classical: RSA-2048; kernel modules are signed with RSA-3072 / sha256; IMA code-signing certificates are EC P-384.
- **note** `pqc-031-kerberos-weak-enctypes`: Kerberos: 128-bit enctypes are permitted (aes128-cts-hmac-sha1-96, aes128-cts-hmac-sha256-128); Grover's algorithm leaves them ~64-bit security and CNSA 2.0 requires AES-256.

</details>

<details>
<summary><b>Rocky Linux 10.2 (Red Quartz)</b>: 6 findings</summary>

- **warning** `pqc-005-slh-dsa-in-tls-context`: OpenSSL exposes SLH-DSA signature algorithms (SLH-DSA-SHA2-128f, SLH-DSA-SHA2-128s, SLH-DSA-SHA2-192f, SLH-DSA-SHA2-192s, SLH-DSA-SHA2-256f, SLH-DSA-SHA2-256s, SLH-DSA-SHAKE-128f, SLH-DSA-SHAKE-128s, SLH-DSA-SHAKE-192f, SLH-DSA-SHAKE-192s, SLH-DSA-SHAKE-256f, SLH-DSA-SHAKE-256s); prefer ML-DSA for TLS handshakes.
- **note** `pqc-004-classical-only-trust-store`: Scanned 390 certificates across 3 trust-store directories; every cert uses classical signatures.
- **note** `pqc-009-classical-package-signing-keys`: All 1 trusted package-signing keys are classical (RSA); none uses ML-DSA or SLH-DSA (RFC 9980).
- **note** `pqc-014-crypto-library-pre-standard-mlkem`: libgcrypt 1.11.0: Upstream libgcrypt before 1.11.1 implements Kyber as in the FIPS 203 initial public draft, which does not interoperate with final ML-KEM; a distribution build may carry the final-standard patch.
- **note** `pqc-030-classical-boot-chain`: Boot chain is classical: Secure Boot trusts 1 certificates (PK/KEK/db/MOK), all classical: RSA-2048; kernel modules are signed with RSA-3072 / sha256; IMA code-signing certificates are EC P-384.
- **note** `pqc-031-kerberos-weak-enctypes`: Kerberos: 128-bit enctypes are permitted (aes128-cts-hmac-sha1-96, aes128-cts-hmac-sha256-128); Grover's algorithm leaves them ~64-bit security and CNSA 2.0 requires AES-256.

</details>

<details>
<summary><b>AlmaLinux 8.10 (Cerulean Leopard)</b>: 18 findings</summary>

- **warning** `pqc-001-openssl-pre-3.5`: OpenSSL OpenSSL 1.1.1k FIPS 25 Mar 2021 is older than 3.5.0 — native ML-KEM / ML-DSA are not available.
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
- **note** `pqc-030-classical-boot-chain`: Boot chain is classical: Secure Boot trusts 3 certificates (PK/KEK/db/MOK), all classical: RSA-2048, RSA-3072, RSA-4096; kernel modules are signed with RSA-3072 / sha256.
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
- **note** `pqc-030-classical-boot-chain`: Boot chain is classical: Secure Boot trusts 3 certificates (PK/KEK/db/MOK), all classical: RSA-2048, RSA-3072, RSA-4096; kernel modules are signed with RSA-3072 / sha256; IMA code-signing certificates are EC P-384.
- **note** `pqc-031-kerberos-weak-enctypes`: Kerberos: 128-bit enctypes are permitted (aes128-cts-hmac-sha1-96, aes128-cts-hmac-sha256-128); Grover's algorithm leaves them ~64-bit security and CNSA 2.0 requires AES-256.

</details>

<details>
<summary><b>AlmaLinux 10.2 (Lavender Lion)</b>: 6 findings</summary>

- **warning** `pqc-005-slh-dsa-in-tls-context`: OpenSSL exposes SLH-DSA signature algorithms (SLH-DSA-SHA2-128f, SLH-DSA-SHA2-128s, SLH-DSA-SHA2-192f, SLH-DSA-SHA2-192s, SLH-DSA-SHA2-256f, SLH-DSA-SHA2-256s, SLH-DSA-SHAKE-128f, SLH-DSA-SHAKE-128s, SLH-DSA-SHAKE-192f, SLH-DSA-SHAKE-192s, SLH-DSA-SHAKE-256f, SLH-DSA-SHAKE-256s); prefer ML-DSA for TLS handshakes.
- **note** `pqc-004-classical-only-trust-store`: Scanned 390 certificates across 3 trust-store directories; every cert uses classical signatures.
- **note** `pqc-009-classical-package-signing-keys`: All 1 trusted package-signing keys are classical (RSA); none uses ML-DSA or SLH-DSA (RFC 9980).
- **note** `pqc-014-crypto-library-pre-standard-mlkem`: libgcrypt 1.11.0: Upstream libgcrypt before 1.11.1 implements Kyber as in the FIPS 203 initial public draft, which does not interoperate with final ML-KEM; a distribution build may carry the final-standard patch.
- **note** `pqc-030-classical-boot-chain`: Boot chain is classical: Secure Boot trusts 3 certificates (PK/KEK/db/MOK), all classical: RSA-2048, RSA-3072, RSA-4096; kernel modules are signed with RSA-3072 / sha256; IMA code-signing certificates are EC P-384.
- **note** `pqc-031-kerberos-weak-enctypes`: Kerberos: 128-bit enctypes are permitted (aes128-cts-hmac-sha1-96, aes128-cts-hmac-sha256-128); Grover's algorithm leaves them ~64-bit security and CNSA 2.0 requires AES-256.

</details>

<details>
<summary><b>Oracle Linux Server 8.10</b>: 14 findings</summary>

- **warning** `pqc-001-openssl-pre-3.5`: OpenSSL OpenSSL 1.1.1k FIPS 25 Mar 2021 is older than 3.5.0 — native ML-KEM / ML-DSA are not available.
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
- **note** `pqc-030-classical-boot-chain`: Boot chain is classical: Secure Boot trusts 4 certificates (PK/KEK/db/MOK), all classical: RSA-3072, RSA-4096; kernel modules are signed with RSA-4096 / sha512.
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
- **note** `pqc-030-classical-boot-chain`: Boot chain is classical: Secure Boot trusts 4 certificates (PK/KEK/db/MOK), all classical: RSA-3072, RSA-4096; kernel modules are signed with RSA-4096 / sha256; IMA code-signing certificates are EC P-384.
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
- **note** `pqc-030-classical-boot-chain`: Boot chain is classical: Secure Boot trusts 2 certificates (PK/KEK/db/MOK), all classical: RSA-2048, RSA-4096; kernel modules are signed with RSA-3072 / sha256; IMA code-signing certificates are EC P-384.
- **note** `pqc-031-kerberos-weak-enctypes`: Kerberos: 128-bit enctypes are permitted (aes128-cts-hmac-sha1-96, aes128-cts-hmac-sha256-128); Grover's algorithm leaves them ~64-bit security and CNSA 2.0 requires AES-256.

</details>

<details>
<summary><b>CentOS Stream 10 (Coughlan)</b>: 6 findings</summary>

- **warning** `pqc-005-slh-dsa-in-tls-context`: OpenSSL exposes SLH-DSA signature algorithms (SLH-DSA-SHA2-128f, SLH-DSA-SHA2-128s, SLH-DSA-SHA2-192f, SLH-DSA-SHA2-192s, SLH-DSA-SHA2-256f, SLH-DSA-SHA2-256s, SLH-DSA-SHAKE-128f, SLH-DSA-SHAKE-128s, SLH-DSA-SHAKE-192f, SLH-DSA-SHAKE-192s, SLH-DSA-SHAKE-256f, SLH-DSA-SHAKE-256s); prefer ML-DSA for TLS handshakes.
- **note** `pqc-004-classical-only-trust-store`: Scanned 396 certificates across 3 trust-store directories; every cert uses classical signatures.
- **note** `pqc-009-classical-package-signing-keys`: All 2 trusted package-signing keys are classical (RSA); none uses ML-DSA or SLH-DSA (RFC 9980).
- **note** `pqc-014-crypto-library-pre-standard-mlkem`: libgcrypt 1.11.0: Upstream libgcrypt before 1.11.1 implements Kyber as in the FIPS 203 initial public draft, which does not interoperate with final ML-KEM; a distribution build may carry the final-standard patch.
- **note** `pqc-030-classical-boot-chain`: Boot chain is classical: Secure Boot trusts 2 certificates (PK/KEK/db/MOK), all classical: RSA-2048, RSA-4096; kernel modules are signed with RSA-3072 / sha256; IMA code-signing certificates are EC P-384.
- **note** `pqc-031-kerberos-weak-enctypes`: Kerberos: 128-bit enctypes are permitted (aes128-cts-hmac-sha1-96, aes128-cts-hmac-sha256-128); Grover's algorithm leaves them ~64-bit security and CNSA 2.0 requires AES-256.

</details>

<details>
<summary><b>Fedora Linux 43 (Cloud Edition)</b>: 6 findings</summary>

- **warning** `pqc-005-slh-dsa-in-tls-context`: OpenSSL exposes SLH-DSA signature algorithms (SLH-DSA-SHA2-128f, SLH-DSA-SHA2-128s, SLH-DSA-SHA2-192f, SLH-DSA-SHA2-192s, SLH-DSA-SHA2-256f, SLH-DSA-SHA2-256s, SLH-DSA-SHAKE-128f, SLH-DSA-SHAKE-128s, SLH-DSA-SHAKE-192f, SLH-DSA-SHAKE-192s, SLH-DSA-SHAKE-256f, SLH-DSA-SHAKE-256s); prefer ML-DSA for TLS handshakes.
- **warning** `pqc-013-crypto-library-without-pqc`: libssh 0.11.3 has no ML-KEM / ML-DSA (evidence: binary); software using it fails at PQC.
- **note** `pqc-004-classical-only-trust-store`: Scanned 390 certificates across 3 trust-store directories; every cert uses classical signatures.
- **note** `pqc-009-classical-package-signing-keys`: All 1 trusted package-signing keys are classical (RSA); none uses ML-DSA or SLH-DSA (RFC 9980).
- **note** `pqc-030-classical-boot-chain`: Boot chain is classical: Secure Boot trusts 1 certificates (PK/KEK/db/MOK), all classical: RSA-2048; kernel modules are signed with RSA-4096 / sha256; IMA code-signing certificates are EC P-256.
- **note** `pqc-031-kerberos-weak-enctypes`: Kerberos: 128-bit enctypes are permitted (aes128-cts-hmac-sha1-96, aes128-cts-hmac-sha256-128, camellia128-cts-cmac); Grover's algorithm leaves them ~64-bit security and CNSA 2.0 requires AES-256.

</details>

<details>
<summary><b>Fedora Linux 44 (Cloud Edition)</b>: 5 findings</summary>

- **warning** `pqc-005-slh-dsa-in-tls-context`: OpenSSL exposes SLH-DSA signature algorithms (SLH-DSA-SHA2-128f, SLH-DSA-SHA2-128s, SLH-DSA-SHA2-192f, SLH-DSA-SHA2-192s, SLH-DSA-SHA2-256f, SLH-DSA-SHA2-256s, SLH-DSA-SHAKE-128f, SLH-DSA-SHAKE-128s, SLH-DSA-SHAKE-192f, SLH-DSA-SHAKE-192s, SLH-DSA-SHAKE-256f, SLH-DSA-SHAKE-256s); prefer ML-DSA for TLS handshakes.
- **note** `pqc-004-classical-only-trust-store`: Scanned 388 certificates across 3 trust-store directories; every cert uses classical signatures.
- **note** `pqc-009-classical-package-signing-keys`: All 1 trusted package-signing keys are classical (RSA); none uses ML-DSA or SLH-DSA (RFC 9980).
- **note** `pqc-030-classical-boot-chain`: Boot chain is classical: Secure Boot trusts 1 certificates (PK/KEK/db/MOK), all classical: RSA-2048; kernel modules are signed with RSA-4096 / sha256; IMA code-signing certificates are EC P-256.
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
- **note** `pqc-030-classical-boot-chain`: Boot chain is classical: Secure Boot trusts 1 certificates (PK/KEK/db/MOK), all classical: RSA-2048; kernel modules are signed with RSA-4096 / sha512.

</details>

<details>
<summary><b>openSUSE Leap 15.6</b>: 12 findings</summary>

- **warning** `pqc-001-openssl-pre-3.5`: OpenSSL OpenSSL 3.1.4 24 Oct 2023 (Library: OpenSSL 3.1.4 24 Oct 2023) is older than 3.5.0 — native ML-KEM / ML-DSA are not available.
- **warning** `pqc-011-service-crypto-library-without-pqc`: sshd.service on tcp 0.0.0.0:22 uses openssl 3.1.4, which has no ML-KEM hybrid key exchange; its connections stay classical.
- **warning** `pqc-011-service-crypto-library-without-pqc`: sshd.service on tcp [::]:22 uses openssl 3.1.4, which has no ML-KEM hybrid key exchange; its connections stay classical.
- **warning** `pqc-011-service-crypto-library-without-pqc`: chronyd.service on udp 127.0.0.1:323 uses gnutls 3.8.3, which has no ML-KEM hybrid key exchange; its connections stay classical.
- **warning** `pqc-011-service-crypto-library-without-pqc`: chronyd.service on udp [::1]:323 uses gnutls 3.8.3, which has no ML-KEM hybrid key exchange; its connections stay classical.
- **warning** `pqc-013-crypto-library-without-pqc`: gnutls 3.8.3 has no ML-KEM / ML-DSA (evidence: binary); software using it fails at PQC.
- **warning** `pqc-013-crypto-library-without-pqc`: libgcrypt 1.10.3 has no ML-KEM / ML-DSA (evidence: binary); software using it fails at PQC.
- **warning** `pqc-013-crypto-library-without-pqc`: libssh 0.9.8 has no ML-KEM / ML-DSA (evidence: binary); software using it fails at PQC.
- **note** `pqc-004-classical-only-trust-store`: Scanned 145 certificates across 1 trust-store directories; every cert uses classical signatures.
- **note** `pqc-009-classical-package-signing-keys`: All 6 trusted package-signing keys are classical (RSA); none uses ML-DSA or SLH-DSA (RFC 9980).
- **note** `pqc-030-classical-boot-chain`: Boot chain is classical: Secure Boot trusts 1 certificates (PK/KEK/db/MOK), all classical: RSA-2048; the kernel is configured for RSA module signing.
- **note** `pqc-031-kerberos-weak-enctypes`: Kerberos: 128-bit enctypes are permitted (aes128-cts-hmac-sha1-96, aes128-cts-hmac-sha256-128, camellia128-cts-cmac); Grover's algorithm leaves them ~64-bit security and CNSA 2.0 requires AES-256.

</details>

<details>
<summary><b>openSUSE Leap 16.0</b>: 6 findings</summary>

- **warning** `pqc-005-slh-dsa-in-tls-context`: OpenSSL exposes SLH-DSA signature algorithms (SLH-DSA-SHA2-128f, SLH-DSA-SHA2-128s, SLH-DSA-SHA2-192f, SLH-DSA-SHA2-192s, SLH-DSA-SHA2-256f, SLH-DSA-SHA2-256s, SLH-DSA-SHAKE-128f, SLH-DSA-SHAKE-128s, SLH-DSA-SHAKE-192f, SLH-DSA-SHAKE-192s, SLH-DSA-SHAKE-256f, SLH-DSA-SHAKE-256s); prefer ML-DSA for TLS handshakes.
- **warning** `pqc-013-crypto-library-without-pqc`: libssh 0.11.5 has no ML-KEM / ML-DSA (evidence: binary); software using it fails at PQC.
- **note** `pqc-004-classical-only-trust-store`: Scanned 121 certificates across 1 trust-store directories; every cert uses classical signatures.
- **note** `pqc-009-classical-package-signing-keys`: All 6 trusted package-signing keys are classical (RSA); none uses ML-DSA or SLH-DSA (RFC 9980).
- **note** `pqc-030-classical-boot-chain`: Boot chain is classical: Secure Boot trusts 1 certificates (PK/KEK/db/MOK), all classical: RSA-2048; the kernel is configured for RSA module signing.
- **note** `pqc-031-kerberos-weak-enctypes`: Kerberos: 128-bit enctypes are permitted (aes128-cts-hmac-sha1-96, aes128-cts-hmac-sha256-128, camellia128-cts-cmac); Grover's algorithm leaves them ~64-bit security and CNSA 2.0 requires AES-256.

</details>

<details>
<summary><b>openSUSE Tumbleweed</b>: 5 findings</summary>

- **warning** `pqc-005-slh-dsa-in-tls-context`: OpenSSL exposes SLH-DSA signature algorithms (SLH-DSA-SHA2-128f, SLH-DSA-SHA2-128s, SLH-DSA-SHA2-192f, SLH-DSA-SHA2-192s, SLH-DSA-SHA2-256f, SLH-DSA-SHA2-256s, SLH-DSA-SHAKE-128f, SLH-DSA-SHAKE-128s, SLH-DSA-SHAKE-192f, SLH-DSA-SHAKE-192s, SLH-DSA-SHAKE-256f, SLH-DSA-SHAKE-256s); prefer ML-DSA for TLS handshakes.
- **warning** `pqc-013-crypto-library-without-pqc`: libssh 0.11.5 has no ML-KEM / ML-DSA (evidence: binary); software using it fails at PQC.
- **note** `pqc-004-classical-only-trust-store`: Scanned 121 certificates across 1 trust-store directories; every cert uses classical signatures.
- **note** `pqc-009-classical-package-signing-keys`: All 5 trusted package-signing keys are classical (RSA); none uses ML-DSA or SLH-DSA (RFC 9980).
- **note** `pqc-030-classical-boot-chain`: Boot chain is classical: Secure Boot trusts 1 certificates (PK/KEK/db/MOK), all classical: RSA-2048; the kernel is configured for RSA module signing.

</details>

## How this was run

- **Scanner.** `pqc-readiness.pyz` v2.2.0, SHA-256 `8ab9b4f8dbca1063180a5d4f39e38a7f10cb87af0c6b4e34f4d832658aa2f075`, identical to the [release asset](https://github.com/aclater/pqc-readiness/releases/tag/v2.2.0). It ran as root, using the newest Python 3.9+ on each image. Python was installed from the distribution's repository where the image lacked it.
- **Scans.** `--json --scan-packages --scan-trust-store --scan-crypto-material --scan-signing-keys --scan-services --scan-boot-chain --scan-crypto-libraries --scan-kerberos --scan-processes --scan-tunnels --scan-dnssec --bench --bench-tls --seconds 1`, then the same scans with `--sarif`, then `--recommend --policy auto`.
- **VMs.** Unmodified, checksum-verified vendor cloud images, booted under cloud-init with qemu-kvm, 4 vCPU, 4 GiB RAM, `-cpu host` and UEFI (OVMF, Secure Boot off). The verdict is `POOR` on every VM because 4 GiB is below the memory threshold. That is a property of the test VM, not the distribution.
- **RHEL rows.** RHEL 8.10, 9.8 and 10.2 ran in pinned UBI containers (`ubi8/ubi:8.10-1791892468`, `ubi9/ubi:9.8-1791888712`, `ubi10/ubi:10.2-1791893534`) with 4 CPUs and 4 GiB. Each added the packages a RHEL server image ships (`python3`, `openssl`, `openssh-server`, `openssh-clients`) and generated host keys as first boot would. OpenSSL, crypto-policies, OpenSSH and the trust store are the real RHEL packages. Containers have no firmware, kernel or running services, and they see the host's RAM, so their boot chain, FIPS kernel and verdict values don't compare with the VM rows.
- **Scope.** These are stock images with no workloads. A production host running web servers, VPNs or a KDC will raise more of the service, tunnel and Kerberos rules.
