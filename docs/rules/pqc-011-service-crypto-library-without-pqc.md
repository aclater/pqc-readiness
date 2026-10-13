# pqc-011-service-crypto-library-without-pqc

**Default level:** warning. One result per listening service (protocol, address family, port, executable).

## What it detects

With `--scan-services`, a process listening on this host maps a TLS / crypto
library whose *version* has no ML-KEM hybrid key exchange:
`service_crypto_linkage.listeners[].crypto_libraries[].library_pqc_capable`
is `false`. Today that means OpenSSL (or a fork reporting an OpenSSL version)
older than 3.5, or NSS older than 3.108. Libraries without a verified version
threshold are reported as [pqc-018](pqc-018-pqc-capability-undetermined.md)
instead, never as failing.

## Why it matters

Whatever the system crypto policy allows, a service on such a library can
only negotiate classical key exchange, so recorded sessions stay exposed to
harvest-now-decrypt-later. This is the per-service version of
[pqc-001](pqc-001-openssl-pre-3.5.md): a host can have OpenSSL 3.5 installed
while a vendored or container-bundled service still runs an older copy.

- FIPS 203 (ML-KEM), **final**: <https://csrc.nist.gov/pubs/fips/203/final>
- RFC 10024, TLS 1.3 hybrid ML-KEM groups (`X25519MLKEM768`), **final**:
  <https://www.rfc-editor.org/rfc/rfc10024>
- NIST IR 8547 (transition timeline), **draft** (initial public draft):
  <https://csrc.nist.gov/pubs/ir/8547/ipd>

## Remediation

Upgrade the library the service actually loads (the finding's
`service:crypto_libraries[].path`), then restart the service; if the path is
inside the application's own directory, the vendor has to ship a new build.

- **RHEL 10 family / Fedora:** OpenSSL in the base OS is already 3.5; a
  finding usually points at an application bundling its own copy.
- **RHEL 9 family:** measured 9.8 cloud images ship OpenSSL 3.5.x; older 9.x
  minors need `dnf update openssl-libs` and a service restart.
- **Debian / Ubuntu:** Ubuntu 26.04 LTS ships OpenSSL 3.5; older releases
  need a distribution upgrade (see `openssl.upgrade_path`).
- **SUSE:** Leap 16 / Tumbleweed ship OpenSSL 3.5; SLES 15 needs the
  vendor's OpenSSL 3.5 stream where offered.

## False positives and limitations

- Needs `--scan-services` with enough privilege to read other processes
  (root, or the opt-in OpenShift overlay); unreadable processes are counted,
  not guessed.
- The verdict is about the library *version*. A new library can still be
  configured without PQC: that is [pqc-008](pqc-008-crypto-policy-blocks-pqc.md)
  or the service's own TLS settings.
- A process that maps several libraries is reported once, listing the
  failing ones.

## Related

[pqc-001](pqc-001-openssl-pre-3.5.md), [pqc-012](pqc-012-go-service-without-hybrid-mlkem.md),
[pqc-018](pqc-018-pqc-capability-undetermined.md).
