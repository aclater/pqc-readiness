# SARIF rules

`pqc-readiness --sarif` emits findings against these rules. Each rule's
`helpUri` points at its page here. A test (`tests/test_sarif_rule_docs.py`)
fails if a registered rule has no page.

| Rule | Default level | Summary |
|---|---|---|
| [pqc-001-openssl-pre-3.5](pqc-001-openssl-pre-3.5.md) | warning | OpenSSL is older than 3.5 (no native PQC) |
| [pqc-002-fips-pqc-conflict](pqc-002-fips-pqc-conflict.md) | error | Kernel FIPS mode on, but PQC is exposed through a non-FIPS provider |
| [pqc-003-no-pqc-isa-support](pqc-003-no-pqc-isa-support.md) | warning | Poor ISA tier and no PQC-capable accelerator |
| [pqc-004-classical-only-trust-store](pqc-004-classical-only-trust-store.md) | note | Trust store holds no PQC or hybrid certificates |
| [pqc-005-slh-dsa-in-tls-context](pqc-005-slh-dsa-in-tls-context.md) | warning | SLH-DSA is exposed where TLS can pick it |
| [pqc-006-no-network-hsm-pqc-firmware](pqc-006-no-network-hsm-pqc-firmware.md) | warning | Network HSM client present, appliance not known to be PQC-capable |
| [pqc-007-fips-without-algorithm-fence](pqc-007-fips-without-algorithm-fence.md) | error | FIPS on, but the default provider reaches non-FIPS algorithms |
| [pqc-008-crypto-policy-blocks-pqc](pqc-008-crypto-policy-blocks-pqc.md) | warning | OpenSSL can do PQC TLS groups; the system crypto policy keeps them out |
| [pqc-009-classical-package-signing-keys](pqc-009-classical-package-signing-keys.md) | note | Every trusted package-signing key is classical |
| [pqc-010-sshd-pqc-kex-not-offered](pqc-010-sshd-pqc-kex-not-offered.md) | warning | OpenSSH can do a PQC key exchange; sshd doesn't offer it (note: offered but not first) |
| [pqc-020-classical-boot-chain](pqc-020-classical-boot-chain.md) | note | Boot chain signing keys (Secure Boot, module signing, IMA) are all classical; TPM has no PQC |

Sources are cited with their status. **Draft** means the document is not
final, for example NIST IR 8547, which is still an initial public draft.
