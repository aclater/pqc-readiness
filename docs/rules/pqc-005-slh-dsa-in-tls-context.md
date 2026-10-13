# pqc-005-slh-dsa-in-tls-context

**Default level:** warning

## What it detects

OpenSSL exposes SLH-DSA (stateless hash-based) signature algorithms. The
finding lists them.

## Why it matters

SLH-DSA signatures are very large compared with ML-DSA (7,856 bytes for
SLH-DSA-SHA2-128s), and signing is slow. Both substantially slow TLS
handshakes. SLH-DSA is a conservative choice for long-lived artefacts such
as firmware and software signing, but not for per-connection
authentication. The `--recommend` engine reflects this: SLH-DSA is primary
for `firmware-signing` outside CNSA 2.0, and ML-DSA for TLS roles.

- FIPS 205 (SLH-DSA), **final**, 2024-08-13: <https://csrc.nist.gov/pubs/fips/205/final>
- FIPS 204 (ML-DSA), **final**: <https://csrc.nist.gov/pubs/fips/204/final>
- CNSA 2.0 does not include SLH-DSA (NSA CNSA 2.0 FAQ v2.1, **final**):
  <https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSI_CNSA_2.0_FAQ_.PDF>

## Remediation

You don't need to remove the algorithms. Make sure TLS configurations don't
*prefer* them:

- **RHEL family and Fedora:** the system crypto policy controls which
  signature algorithms TLS offers. Check the OpenSSL back-end the active
  policy generates. The scanner's `crypto_policy` and `openssl.config`
  fields show both.
- **Debian / Ubuntu and SUSE:** check `SignatureAlgorithms` in the
  OpenSSL configuration (see `openssl.config` in the report) and in each
  service's TLS settings.

## False positives and limitations

- Exposure isn't use. The rule fires when the algorithms are available,
  not when a server presents an SLH-DSA certificate.

## Related

`docs/recommendation-policies.md`.
