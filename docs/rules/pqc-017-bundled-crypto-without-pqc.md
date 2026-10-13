# pqc-017-bundled-crypto-without-pqc

**Default level:** warning. One result per package.

## What it detects

With `--scan-packages`, a package that embeds its own crypto stack
(`packages.bundled_crypto`) is installed at a version that definitely lacks
PQC:

- **OpenJDK** older than 24: no ML-KEM / ML-DSA (JEP 496 / 497).
- **Go toolchain packages** older than 1.24: no default hybrid ML-KEM in
  `crypto/tls`.

Packages whose version gives no definite answer (Node.js, Rust, browsers,
Bouncy Castle) are not reported. JDK and Go packages are skipped when
`--scan-crypto-libraries` already judged each install
([pqc-013](pqc-013-crypto-library-without-pqc.md)).

## Why it matters

Applications on these runtimes do not use the host's OpenSSL, so they stay
classical however the OS is configured. Works in offline `--root` scans too.

- JEP 496 / 497 (JDK 24), **final**: <https://openjdk.org/jeps/496>,
  <https://openjdk.org/jeps/497>
- Go 1.24 release notes: <https://go.dev/doc/go1.24>

## Remediation

- **RHEL / Fedora / SUSE:** install `java-25-openjdk` (or newer) and move
  applications to it; update `golang` / `go1.x`.
- **Debian / Ubuntu:** `openjdk-25-jdk` or newer; current `golang-go`.

## False positives and limitations

JDK 24–26 has ML-KEM / ML-DSA in the JCA but no hybrid key exchange in TLS
by default (JEP 527, JDK 27); that is not reported here.

## Related

[pqc-013](pqc-013-crypto-library-without-pqc.md).
