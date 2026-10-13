# pqc-034-dnssec-classical-signing

**Default level:** note (warning when an algorithm IANA marks MUST NOT for signing is in use)

## What it detects

`--scan-dnssec` found an authoritative DNS server on the host that signs
zones with classical algorithms only: BIND `dnssec-policy` key algorithms
for zones that use a policy (the built-in `default` policy is one
ECDSAP256SHA256 CSK) and `K<zone>+<alg>+<id>.key` files, Knot DNS policies
with `dnssec-signing: on`, or PowerDNS default KSK / ZSK algorithms.

## Why it matters

DNSSEC signatures authenticate DNS data; a quantum attacker able to forge
them could spoof signed zones. Unlike key exchange, signatures are not
harvest-now-decrypt-later, so this is a note unless a deprecated algorithm
is in use.

- IANA DNS Security Algorithm Numbers registry:
  <https://www.iana.org/assignments/dns-sec-alg-numbers/>. ML-DSA-44 is
  algorithm 18 (`MLDSA44`, "MAY"), registered from
  draft-westerbaan-dnssec-mldsa (**Internet-Draft**, not a standard).
  RSAMD5, DSA, RSASHA1 and their NSEC3 variants, and ECC-GOST are "MUST NOT"
  for signing.

## Remediation

- **Deprecated algorithms (warning):** roll the zone to ECDSAP256SHA256 or
  ED25519 now; this is a classical weakness, not only a quantum one.
- **Classical-only (note):** no post-quantum DNSSEC algorithm is
  standardised yet, and resolvers don't validate ML-DSA-44 widely. Keep
  algorithm rollover procedures tested and track the IETF DNSOP work so
  zones can roll when validators support it.

## False positives and limitations

- The algorithms come from configuration and key file names, not from the
  served zone data.
- Signing done elsewhere (a hidden primary or a signing service) isn't seen.

## Related

[pqc-030](pqc-030-classical-boot-chain.md).
