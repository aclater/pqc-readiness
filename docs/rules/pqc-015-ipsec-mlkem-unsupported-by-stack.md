# pqc-015-ipsec-mlkem-unsupported-by-stack

**Default level:** warning.

## What it detects

IPsec configuration (`ipsec_pqc.configured`) has connections whose IKEv2
proposals ask for ML-KEM, but the installed IPsec stack reports no ML-KEM
support (`ipsec_pqc.configured.capability_mismatch` is present).

## Why it matters

Such connections fail to load rather than falling back to a classical
proposal, so the tunnel is down, not merely classical. Measured: Libreswan
5.3.2 on Rocky Linux 10.2 rejects `ke=ml_kem_768` and `addke1=`.

- RFC 9370, multiple key exchanges in IKEv2, **final**:
  <https://www.rfc-editor.org/rfc/rfc9370>
- ML-KEM in IKEv2, `draft-ietf-ipsecme-ikev2-mlkem-09`, **draft**
  (IESG-approved, in the RFC Editor queue):
  <https://datatracker.ietf.org/doc/draft-ietf-ipsecme-ikev2-mlkem/>

## Remediation

Either upgrade the stack to one with ML-KEM (Libreswan 5.4 or later;
strongSwan 6 builds that list `ML_KEM_*` in `swanctl --list-algs`), or make
the ML-KEM exchange optional (strongSwan `ke1_mlkem768-ke1_none`) until it
is, so the connection still loads.

## False positives and limitations

Libreswan support is judged by version (5.4+); a distribution backport into
an older version is reported as a mismatch until verified.

## Related

[pqc-016](pqc-016-ipsec-classical-only-ike.md).
