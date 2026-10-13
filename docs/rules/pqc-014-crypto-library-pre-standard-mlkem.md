# pqc-014-crypto-library-pre-standard-mlkem

**Default level:** note. One result per library.

## What it detects

With `--scan-crypto-libraries`, a library carries post-quantum algorithm
names but its version predates the release that moved them to the final
standards (`crypto_libraries.libraries.<name>.caveats` is non-empty):
libgcrypt before 1.11.1 (FIPS 203 initial-public-draft Kyber) and wolfSSL
before 5.7.4 (pre-final Kyber / Dilithium).

## Why it matters

Draft Kyber and final ML-KEM are different algorithms on the wire: peers
using the standard will not interoperate with the draft. Measured: Rocky
Linux 10.2 ships libgcrypt 1.11.0.

- FIPS 203 (ML-KEM), **final**: <https://csrc.nist.gov/pubs/fips/203/final>
- libgcrypt NEWS: <https://github.com/gpg/libgcrypt/blob/master/NEWS>
- wolfSSL ChangeLog: <https://github.com/wolfSSL/wolfssl/blob/master/ChangeLog.md>

## Remediation

Update to the distribution's newest build; check its changelog
(`rpm -q --changelog libgcrypt`, `apt changelog libgcrypt20`) for a
final-standard ML-KEM backport before treating the finding as open.

## False positives and limitations

Distribution builds may carry the final-standard patch while keeping the
older upstream version number; that is why this is a note, not a warning.

## Related

[pqc-013](pqc-013-crypto-library-without-pqc.md).
