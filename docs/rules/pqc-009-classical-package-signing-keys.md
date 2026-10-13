# pqc-009-classical-package-signing-keys

**Default level:** note

## What it detects

`--scan-signing-keys` found trusted package-signing keys, and every one
uses a classical algorithm. Sources are rpm `gpg-pubkey` entries, apt
keyrings and `signed-by` files, the pacman keyring and apk keys. The
finding lists the keys by ID and algorithm.

## Why it matters

Package-signing keys are long-lived trust anchors for software supply. A
host only verifies PQC-signed packages if it already trusts a PQC or
composite key, so key distribution has to come before re-signing.

- CNSA 2.0 (NSA, **final**): software and firmware signing should support
  and prefer CNSA 2.0 algorithms (ML-DSA-87, or LMS/XMSS) by 2025 and use
  them exclusively by 2030:
  <https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF>
- RFC 9980, OpenPGP ML-DSA and SLH-DSA keys, **final**.

## Remediation

This is informational. The re-signing is done by the distribution or
repository owner, and the host's job is to trust the new key when it's
published.

- **RHEL family and Fedora:** import vendor-published PQC or composite
  release keys with `rpmkeys --import`, typically through the
  distribution's key package update. On 2026-10-13 a RHEL 10.2 image
  already trusted a composite ML-DSA-87+Ed448 release key, while UBI 10
  packages were still RSA-signed.
- **Debian / Ubuntu:** install the updated archive keyring package, and
  point `signed-by=` at the new keyring.
- **SUSE:** import updated repository keys
  (`zypper --gpg-auto-import-keys ref` after the key package update).
- For internal repositories, generate a PQC-capable signing key and ship
  it to hosts before re-signing.

## False positives and limitations

- The rule looks at trusted keys, not at which key signed each installed
  package.
- A key the scanner can't classify is not counted as PQC. If a trusted
  key uses an algorithm the scanner doesn't recognise yet, the rule still
  fires. Check the listed keys before acting.

## Related

[pqc-004](pqc-004-classical-only-trust-store.md).
