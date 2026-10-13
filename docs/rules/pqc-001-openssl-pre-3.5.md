# pqc-001-openssl-pre-3.5

**Default level:** warning

## What it detects

The host's OpenSSL is available but reports no native PQC support
(`openssl.pqc_native` is false). OpenSSL 3.5.0 is the first release with
built-in ML-KEM, ML-DSA and SLH-DSA, so this means OpenSSL is older than
3.5.

The finding carries `openssl:version` and `openssl:upgrade_path`, a
family-aware hint for the specific host.

## Why it matters

Applications that use the system OpenSSL can't offer PQC key exchange or
PQC signatures, including the hybrid TLS 1.3 groups such as X25519MLKEM768,
without a third-party provider.

- FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA), **final**, 2024-08-13: <https://csrc.nist.gov/pubs/fips/203/final>, <https://csrc.nist.gov/pubs/fips/204/final>, <https://csrc.nist.gov/pubs/fips/205/final>
- RFC 10024, hybrid ML-KEM key agreement for TLS 1.3, **final** (Proposed Standard), 2026-08: <https://www.rfc-editor.org/rfc/rfc10024>
- NIST IR 8547, transition timeline, **draft** (initial public draft): <https://csrc.nist.gov/pubs/ir/8547/ipd>

## Remediation

Check `openssl version` and the finding's `openssl:upgrade_path`. These
releases were observed shipping OpenSSL 3.5 in the 2026-10-13 cloud-image
and container checks:

- **RHEL family and Fedora:**
  - EL8 ships OpenSSL 1.1.1, so move the workload to EL9 or EL10.
  - EL9.8, EL10 and Fedora 43/44 images ship OpenSSL 3.5.x.
  - On EL9 and later, update the `openssl` package to the current minor release.
- **Debian / Ubuntu:**
  - Ubuntu 26.04 LTS ships OpenSSL 3.5 in `main`.
  - Ubuntu 24.04 LTS ships 3.0 and has no 3.5 package.
  - On Debian, use a release whose `openssl` is 3.5 or later.
- **SUSE:** openSUSE Leap 16.0 and Tumbleweed ship 3.5.x. On SLES 15, check
  the available `openssl-3` package version before planning an upgrade.

A third-party PQC provider can add algorithms to an older OpenSSL, but it is
outside any FIPS validation boundary. Treat that as a stop-gap.

## False positives and limitations

- Applications that bundle their own TLS library don't use the system
  OpenSSL. For those, see `--scan-services` (which library a listener
  actually loads) and the `packages.bundled_crypto` inventory.
- A distribution may backport PQC into an older version string. The rule
  keys on capability (`pqc_native`), not only on the version number.

## Related

[pqc-008](pqc-008-crypto-policy-blocks-pqc.md): OpenSSL is capable, but policy disables PQC.
