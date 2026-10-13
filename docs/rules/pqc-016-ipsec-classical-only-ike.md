# pqc-016-ipsec-classical-only-ike

**Default level:** warning. One result per IPsec connection.

## What it detects

Every IKE proposal configured for a connection (strongSwan `swanctl.conf` /
`ipsec.conf`, Libreswan `ipsec.conf` / `ipsec.d`) names only classical key
exchanges (`category` is `classical` for all of the connection's IKE
proposals). Connections whose proposals rely on the implementation's default
key exchange are reported as [pqc-018](pqc-018-pqc-capability-undetermined.md).

## Why it matters

The IKE SA and every child SA key derived from it are quantum-vulnerable, so
recorded tunnel traffic is exposed to harvest-now-decrypt-later. CNSA 2.0
expects traditional networking equipment, including VPNs, to support and
prefer CNSA 2.0 algorithms from 2026 and use them exclusively by 2030.

- RFC 9370, **final**: <https://www.rfc-editor.org/rfc/rfc9370>
- ML-KEM in IKEv2, **draft**:
  <https://datatracker.ietf.org/doc/draft-ietf-ipsecme-ikev2-mlkem/>

## Remediation

Add an ML-KEM additional key exchange to the IKE proposal:

- **strongSwan:** `proposals = aes256-sha384-x25519-ke1_mlkem768` (add
  `-ke1_none` to keep it optional while peers catch up).
- **Libreswan 5.4+:** `ike=aes256-sha2;dh31;addke1=ml_kem_768`.

Both peers must support it; check with your peer before making it mandatory.

## False positives and limitations

Only configured proposals are read; a peer may negotiate something else at
runtime. `%default` templates are not counted as connections.

## Related

[pqc-015](pqc-015-ipsec-mlkem-unsupported-by-stack.md).
