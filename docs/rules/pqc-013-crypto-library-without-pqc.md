# pqc-013-crypto-library-without-pqc

**Default level:** warning. One result per library, or per install for JDKs and Go toolchains.

## What it detects

With `--scan-crypto-libraries`, an installed library or toolchain has no
ML-KEM / ML-DSA (`crypto_libraries.libraries.<name>.pqc_capable` is `false`):

- **GnuTLS, libgcrypt, libssh, wolfSSL, AWS-LC:** no PQC algorithm or group
  names inside the library file (evidence `binary`), or a version below the
  upstream release that added them (evidence `version`).
- **JDK installs:** older than JDK 24 (no ML-KEM / ML-DSA in the JCA,
  JEP 496 / 497).
- **Go toolchains:** older than Go 1.24, so programs built with them get no
  default hybrid ML-KEM.

Unknown results go to [pqc-018](pqc-018-pqc-capability-undetermined.md).

## Why it matters

Software built on or linked against these libraries fails at PQC whatever
the rest of the host can do. libssh matters for automation: Ansible
connections through it stay classical while OpenSSH itself offers ML-KEM.

- GnuTLS NEWS: <https://gitlab.com/gnutls/gnutls/-/blob/master/NEWS>
- libgcrypt NEWS: <https://github.com/gpg/libgcrypt/blob/master/NEWS>
- libssh CHANGELOG: <https://gitlab.com/libssh/libssh-mirror/-/blob/master/CHANGELOG>
- wolfSSL ChangeLog: <https://github.com/wolfSSL/wolfssl/blob/master/ChangeLog.md>
- AWS-LC releases: <https://github.com/aws/aws-lc/releases>
- JEP 496 (ML-KEM) / 497 (ML-DSA), **final** in JDK 24:
  <https://openjdk.org/jeps/496>, <https://openjdk.org/jeps/497>
- Go 1.24 release notes: <https://go.dev/doc/go1.24>

## Remediation

Upgrade the package named in `library:files` / `library:path`, or remove an
old JDK / Go install nothing uses.

- **RHEL / Fedora:** `dnf update gnutls libgcrypt libssh`; install
  `java-25-openjdk` (or newer) alongside or instead of older JDKs; use the
  current `golang` package for builds.
- **Debian / Ubuntu:** `apt install --only-upgrade libgnutls30t64 libgcrypt20 libssh-4`
  (package names vary by release); `openjdk-25-jdk` or newer.
- **SUSE:** `zypper up libgnutls30 libgcrypt20 libssh4`; `java-25-openjdk`.

## False positives and limitations

- An installed library is not necessarily used; [pqc-011](pqc-011-service-crypto-library-without-pqc.md)
  shows the ones running services actually load.
- Version evidence can miss distribution backports; binary evidence is used
  whenever the library file is readable.

## Related

[pqc-014](pqc-014-crypto-library-pre-standard-mlkem.md), [pqc-017](pqc-017-bundled-crypto-without-pqc.md).
