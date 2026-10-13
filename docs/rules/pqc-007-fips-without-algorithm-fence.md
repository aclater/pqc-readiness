# pqc-007-fips-without-algorithm-fence

**Default level:** error

## What it detects

FIPS mode is active and the OpenSSL FIPS provider is loaded, but the
*default* provider still reaches algorithms outside the FIPS provider's
set (`fips.fence_check_active` true, `fips.algorithm_fence_engaged`
false). The finding lists the extra KEMs, signatures and TLS groups.

## Why it matters

Operators often read "FIPS mode is on" as "only FIPS-validated algorithms
are reachable". On builds without downstream gating patches that isn't
true: PQC and other non-validated algorithms stay callable through the
public interface. Whether that is a compliance problem is for your
compliance authority to decide, but the gap is invisible unless the two
providers' algorithm lists are compared.

- FIPS 140-3, **final**: <https://csrc.nist.gov/pubs/fips/140-3/final>
- Full mechanism, a 12-VM reproduction and mitigations: [`docs/findings/fips-algorithm-fence.md`](../findings/fips-algorithm-fence.md)

## Remediation

- **Every distribution:** gate on `pqc-readiness --fips-strict`, which
  exits 4 when the fence isn't engaged.
- **RHEL family:** RHEL's OpenSSL carries the gating patches. Rebuild
  distributions may not, so verify for each release.
- **Debian / Ubuntu and SUSE:** check what your FIPS offering's OpenSSL
  build exposes through the default provider while FIPS is active.
- If the application is the only OpenSSL consumer, enforce an algorithm
  allow-list at the application layer.

## False positives and limitations

- The check compares provider algorithm lists. It doesn't prove whether a
  given application actually calls a non-validated algorithm.

## Related

[pqc-002](pqc-002-fips-pqc-conflict.md).
