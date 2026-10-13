# pqc-030-classical-boot-chain

**Default level:** note

## What it detects

`--scan-boot-chain` found boot-chain trust anchors and none of them is
post-quantum. The finding names each classical layer:

- **Secure Boot:** every certificate in the UEFI `PK`, `KEK` and `db`
  databases and in shim's `MokList` uses a classical algorithm (today
  RSA-2048 / RSA-4096 almost everywhere).
- **Module signing:** the kernel's modules are signed with a classical key
  (read from one module's appended PKCS#7 signature, or from
  `CONFIG_MODULE_SIG_KEY_TYPE_*` when no module could be read).
- **IMA:** the IMA code-signing certificates under `/etc/keys/ima` are
  classical.
- **TPM:** the TPM answered `TPM2_GetCapability` and implements none of the
  TPM 2.0 Library v1.85 post-quantum algorithms (ML-KEM, ML-DSA,
  HashML-DSA).

## Why it matters

These keys authorise every piece of code that runs before and inside the
kernel, and they are the slowest to rotate: firmware vendors own PK,
Microsoft and the distributions own KEK / db and shim, the distribution
owns the module and IMA signing keys, and the machine owner enrols MOKs.

- CNSA 2.0 (NSA, **final**): software and firmware signing should support
  and prefer ML-DSA-87 or LMS / XMSS by 2025 and use them exclusively by
  2030: <https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF>
- Linux 7.0 added ML-DSA-44 / 65 / 87 module signing
  (`CONFIG_MODULE_SIG_KEY_TYPE_MLDSA_*`, `certs/Kconfig`), **released**.
- TPM 2.0 Library Specification v1.85 adds ML-KEM and ML-DSA
  (`TPM_ALG_MLKEM` 0x00A0, `TPM_ALG_MLDSA` 0x00A1, `TPM_ALG_HASH_MLDSA`
  0x00A2). The IDs are taken from wolfTPM's v1.85 implementation; v1.85 is
  described there as a **release candidate**.

## Remediation

This is informational: almost no shipping firmware, distribution or TPM
offers post-quantum boot-chain keys yet. Use the finding to plan.

- **Secure Boot:** track your firmware vendor's and distribution's plans
  for post-quantum PK / KEK / db entries; on fleets you own, test enrolling
  your own keys (`mokutil --import`, or custom PK / KEK in setup mode).
- **Module signing:** kernels you build yourself can be signed with
  ML-DSA from Linux 7.0 (`CONFIG_MODULE_SIG_KEY_TYPE_MLDSA_65` or `_87`,
  needs OpenSSL 3.5 or later to build); distribution kernels follow the
  distribution's key.
- **IMA:** re-sign with a post-quantum key once your distribution's IMA
  tooling supports it, and add the new certificate to the IMA keyring.
- **TPM:** plan hardware refresh against TPMs that report spec revision
  1.85 or later with ML-KEM / ML-DSA.
- See `--recommend --role firmware-signing` for the algorithm to use under
  your policy; with `--scan-boot-chain` it also lists these layers.

## False positives and limitations

- Hash-only `db` entries and `dbx` revocations are counted but don't make a
  chain post-quantum or classical.
- The module-signing check reads one module. A kernel with modules signed
  by several keys is reported by the first readable one.
- `.ko.zst` modules need Python 3.14; on older Python the rule falls back
  to the kernel config.
- The TPM is only queried as root or a member of the `tss` group; without
  that, the TPM layer is not reported either way.

## Related

[pqc-009](pqc-009-classical-package-signing-keys.md),
[pqc-004](pqc-004-classical-only-trust-store.md).
