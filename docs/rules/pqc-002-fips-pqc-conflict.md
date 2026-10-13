# pqc-002-fips-pqc-conflict

**Default level:** error

## What it detects

Kernel FIPS mode is on and OpenSSL lists PQC algorithms, but the OpenSSL
FIPS provider doesn't include them (`fips_pqc_conflict.in_conflict`). The
algorithms show up in listings but can't be used in a FIPS-validated
workflow.

The finding carries `fips:kernel`, `fips:openssl_provider` and the
KEM/signature algorithm lists.

## Why it matters

Teams planning a PQC migration under FIPS read the algorithm list and
assume ML-KEM / ML-DSA are usable. Inside the validated boundary they
aren't, until a FIPS 140-3 module that includes them is validated and
deployed.

- FIPS 140-3, module validation framework, **final**: <https://csrc.nist.gov/pubs/fips/140-3/final>
- FIPS 203 / 204 / 205, **final**, 2024-08-13 (algorithm standards; validation of a specific module is separate).

## Remediation

- **RHEL family:** check the release notes and the module's CMVP
  certificate for whether its FIPS provider includes ML-KEM / ML-DSA. Until
  it does, keep PQC out of FIPS-scoped workloads, or document an exception
  with your compliance authority.
- **Debian / Ubuntu and SUSE:** apply the same check to the FIPS module your
  distribution or subscription provides.
- Run `pqc-readiness --fips-strict` in CI or fleet checks to gate on the
  related fence condition ([pqc-007](pqc-007-fips-without-algorithm-fence.md)).

## False positives and limitations

- The rule is based on the provider's algorithm list at scan time. A
  module whose PQC algorithms are validated but not yet reflected in the
  provider's metadata would be reported incorrectly. Confirm against the
  CMVP certificate.

## Related

[pqc-007](pqc-007-fips-without-algorithm-fence.md); `docs/findings/fips-algorithm-fence.md`.
