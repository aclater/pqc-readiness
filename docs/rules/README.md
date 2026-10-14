# SARIF rules

`pqc-readiness --sarif` emits findings against these rules. Each rule's
`helpUri` points at its page here. A test (`tests/test_sarif_rule_docs.py`)
fails if a registered rule has no page.

Most rules fire at most once per host. Rules `pqc-011` to `pqc-018`,
except `pqc-015`, fire once per subject (a listening service, library,
toolchain install, IPsec connection, package or unreadable config), so one
host can carry several results for the same rule.

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
| [pqc-011-service-crypto-library-without-pqc](pqc-011-service-crypto-library-without-pqc.md) | warning | A listening service uses a crypto library that cannot do PQC |
| [pqc-012-go-service-without-hybrid-mlkem](pqc-012-go-service-without-hybrid-mlkem.md) | warning | A Go service does not offer hybrid ML-KEM |
| [pqc-013-crypto-library-without-pqc](pqc-013-crypto-library-without-pqc.md) | warning | An installed crypto library, JDK or Go toolchain cannot do PQC |
| [pqc-014-crypto-library-pre-standard-mlkem](pqc-014-crypto-library-pre-standard-mlkem.md) | note | A crypto library only has pre-standard ML-KEM (Kyber) |
| [pqc-015-ipsec-mlkem-unsupported-by-stack](pqc-015-ipsec-mlkem-unsupported-by-stack.md) | warning | IPsec connections configure ML-KEM the installed stack can't do |
| [pqc-016-ipsec-classical-only-ike](pqc-016-ipsec-classical-only-ike.md) | warning | An IPsec connection's IKE proposals are classical only |
| [pqc-017-bundled-crypto-without-pqc](pqc-017-bundled-crypto-without-pqc.md) | warning | A package bundling its own crypto (OpenJDK, Go) cannot do PQC |
| [pqc-018-pqc-capability-undetermined](pqc-018-pqc-capability-undetermined.md) | note | PQC capability could not be determined; verify by hand |
| [pqc-020-pqc-capable-not-configured](pqc-020-pqc-capable-not-configured.md) | warning | PQC-capable software (TLS, SSH, IPsec, a service or an outbound client) is configured to stay classical (note: only restates pqc-008 / pqc-010) |
| [pqc-030-classical-boot-chain](pqc-030-classical-boot-chain.md) | note | Boot chain signing keys (Secure Boot, module signing, IMA) are all classical; TPM has no PQC |
| [pqc-031-kerberos-weak-enctypes](pqc-031-kerberos-weak-enctypes.md) | warning | Kerberos allows deprecated enctypes (note: only 128-bit enctypes, or classical PKINIT) |
| [pqc-032-wireguard-peer-without-psk](pqc-032-wireguard-peer-without-psk.md) | warning | WireGuard peers have no pre-shared key |
| [pqc-033-openvpn-classical-key-exchange](pqc-033-openvpn-classical-key-exchange.md) | warning | An OpenVPN configuration rules out PQC key exchange |
| [pqc-034-dnssec-classical-signing](pqc-034-dnssec-classical-signing.md) | note | DNSSEC zones are signed with classical algorithms only (warning: an algorithm IANA marks MUST NOT for signing) |

Sources are cited with their status. **Draft** means the document is not
final, for example NIST IR 8547, which is still an initial public draft.
