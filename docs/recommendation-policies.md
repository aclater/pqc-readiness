# Recommendation policies

`pqc-readiness --recommend --policy <name>` produces a host-specific
algorithm recommendation that is only meaningful relative to a
compliance regime. Different cryptographic authorities hold materially
different positions on hybrid vs. pure-PQC preference, so a single
hardcoded recommendation is wrong for the majority of users regardless
of what it says.

This document is the audit trail for the recommendation engine: every
policy enumerated below names the issuing authority, links to the
authoritative document, and states the position the engine encodes.

The policy-to-preference mapping itself lives as a single declarative
dictionary (`POLICY_PREFERENCES`) in `pqc_readiness/recommendation.py`. Updating a
policy when an authority revises guidance is a one-place edit; it must
not require touching the engine.

## `cnsa-2.0` — US National Security Systems

- **Authority:** NSA, Commercial National Security Algorithm Suite 2.0
- **Source:**
  - CNSA 2.0 advisory:
    https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF
  - CNSA 2.0 FAQ, ver. 2.1 (December 2024):
    https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSI_CNSA_2.0_FAQ_.PDF
- **Position:** ML-KEM-1024 and ML-DSA-87 (plus single-tree LMS/XMSS
  for software/firmware signing) for National Security Systems. Pure
  PQC is preferred. Hybrids are permitted but not required; NSA
  anticipates one for IKEv2 (RFC 9370). SLH-DSA and HSS/XMSS^MT are not
  approved.
- **Deadlines (2022 advisory and FAQ ver. 2.1):** new NSS acquisitions
  compliant from 1 January 2027; equipment that cannot support CNSA 2.0
  phased out by 31 December 2030; CNSA 2.0 mandated by 31 December
  2031; all NSS quantum-resistant by 2035. Exclusive use by category:
  software/firmware signing and traditional networking 2030; web
  browsers/servers and cloud, operating systems and niche equipment
  2033; custom and legacy equipment updated or replaced by 2033. The
  engine reports the category for the role in `timeline`.
- **Hash:** SHA-384.
- **Engine output:**
  - KEM: `ML-KEM-1024` (pure)
  - Signature: `ML-DSA-87`
  - Hash: `SHA-384`
  - FIPS-validated cryptographic modules required.

## `nist-civilian` — US federal civilian / FCEB

- **Authority:** NIST
- **Source:**
  - FIPS 203 (ML-KEM): https://csrc.nist.gov/pubs/fips/203/final
  - FIPS 204 (ML-DSA): https://csrc.nist.gov/pubs/fips/204/final
  - FIPS 205 (SLH-DSA): https://csrc.nist.gov/pubs/fips/205/final
  - NIST IR 8547 (initial public draft, 12 Nov 2024; no final version):
    https://csrc.nist.gov/pubs/ir/8547/ipd
  - The IR 8547 draft deprecates quantum-vulnerable algorithms at
    112-bit strength after 2030 and disallows all of them after 2035.
    These dates are from a draft and may change.
  - NIST SP 800-56C Rev. 2:
    https://csrc.nist.gov/pubs/sp/800/56/c/r2/final
  - NIST SP 800-227: https://csrc.nist.gov/pubs/sp/800/227/final
- **Position:** ML-KEM, ML-DSA, and SLH-DSA per FIPS 203/204/205 are
  the standardized civilian suite. Hybrid key establishment is
  permitted under SP 800-56C Rev. 2; it is not required.
- **Hash:** SHA-256 or SHA-384 per FIPS 180-4 family.
- **Engine output:**
  - KEM: `ML-KEM-768` (pure; hybrid permitted)
  - Signature: `ML-DSA-65`
  - Hash: `SHA-256`
  - FIPS-validated cryptographic modules required.

## `eu-anssi-bsi` — ANSSI / BSI hybrid

- **Authority:** ANSSI (France) and BSI (Germany)
- **Source:**
  - ANSSI views on the Post-Quantum Cryptography transition (2023
    follow up, 21 December 2023):
    https://cyber.gouv.fr/en/publications/follow-position-paper-post-quantum-cryptography
  - BSI TR-02102-1, Cryptographic Mechanisms: Recommendations and Key
    Lengths, version 2026-01 (23 January 2026):
    https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-1.pdf
  - EU NIS Cooperation Group, A Coordinated Implementation Roadmap for
    the Transition to Post-Quantum Cryptography, Part 1, v1.1
    (11 June 2025):
    https://digital-strategy.ec.europa.eu/en/library/coordinated-implementation-roadmap-transition-post-quantum-cryptography
- **Position:** Both authorities recommend hybrid deployment of PQC
  alongside a classical primitive throughout the migration period
  (ANSSI: hybridation "wherever post-quantum mitigation is needed" in
  the short and medium term; BSI: quantum-safe mechanisms "should be
  used in hybrid form"). BSI recommends ML-KEM-768 and ML-KEM-1024,
  alongside FrodoKEM and Classic McEliece.
- **Deadlines (EU roadmap):** Member States complete First Steps by the
  end of 2026; high-risk use cases transitioned, with no stand-alone
  quantum-vulnerable public-key mechanisms, by the end of 2030; the
  transition complete for as many systems as feasible, and medium-risk
  use cases off stand-alone quantum-vulnerable mechanisms, by the end
  of 2035.
- **Hash:** SHA-256 or SHA-384.
- **Engine output:**
  - KEM: `ML-KEM-768` (hybrid)
  - Signature: `ML-DSA-65`
  - Hash: `SHA-256`
  - FIPS validation is not a precondition under EU guidance.

## `commercial` — no specific compliance regime

- **Authority:** none. This policy applies when no specific compliance
  regime governs the deployment (general-purpose enterprise or
  consumer software).
- **Position:** Both pure-PQC and hybrid deployments are acceptable.
  Hybrid is suggested for data with long-confidentiality requirements
  on harvest-now-decrypt-later (HNDL) grounds.
- **Hash:** SHA-256.
- **Engine output:**
  - KEM: `ML-KEM-768` (pure; hybrid suggested for HNDL data)
  - Signature: `ML-DSA-65`
  - Hash: `SHA-256`

## `auto` — composite

`--policy auto` (the default) emits one recommendation per real policy
above, side by side, with no single "preferred" answer. Operators in
unclear or multi-jurisdiction contexts should consult the side-by-side
output and select the policy that matches their compliance scope.

## Roles

`--role` selects the workload the recommendation is for. Policy decides
*which* algorithms are acceptable; role decides which operation is the
bottleneck and therefore which host capabilities and caveats matter.
Every implemented role emits the same record keys (`kem`, `signature`,
`hash`, `host_capability_inputs`, `caveats`) so consumers never need to
special-case a role.

### `tls-server` (default)

- **Bottleneck:** signing every handshake, plus KEM decapsulation.
- **KEM / signature:** the policy primaries above. Below ISA tier
  `excellent` (and without a PQC accelerator) the reason strings explain
  why ML-DSA-65 rather than ML-DSA-87 is chosen on sign-latency grounds;
  under CNSA 2.0 the mandated parameter sets are kept and a caveat is
  emitted instead.
- **Capability check:** the host's OpenSSL must advertise TLS 1.3 groups
  for the chosen mode (hybrid or pure).

### `tls-client`

- **Bottleneck:** *verifying* the server's certificate chain. A TLS
  client does not sign (outside mTLS), and ML-DSA verify is far cheaper
  than sign, so ISA tier matters much less than for a server. Reason
  strings and caveats reference verify throughput.
- **KEM / hybrid vs pure:** same policy-driven choice as `tls-server`,
  and the same OpenSSL TLS-group capability check.
- **ClientHello size caveat:** the client places its ML-KEM
  *encapsulation key* in the ClientHello `key_share` — 1184 bytes for
  ML-KEM-768 and 1568 bytes for ML-KEM-1024 (FIPS 203: `384·k + 32`),
  plus 32 bytes for the X25519 half of a hybrid group. When the share
  exceeds 1200 bytes (ML-KEM-1024 under CNSA 2.0, or hybrid
  X25519MLKEM768 under ANSSI/BSI) a caveat warns that some legacy
  middleboxes mishandle large ClientHellos.

### `signing-service`

- **Bottleneck:** *signing* at request rate (certificate issuance, token
  or artifact signing as a service). Reason strings and caveats quote the
  per-core sign/s floors from `ALGO_THRESHOLDS`.
- **KEM:** `{"algorithm": null, "mode": "n/a", "reason": ...}`. A
  signing service does no key exchange; the field is kept (as null) so
  every role's record has the same shape.
- **Signature:** `ML-DSA-87` under CNSA 2.0, otherwise `ML-DSA-65`. Below
  ISA tier `excellent` without an accelerator a sign-throughput caveat is
  emitted. No TLS-group check: signing services negotiate no TLS groups.
- **HSM-aware:** when a PQC-capable accelerator is present, the reason
  and caveats point at offloading signing to it, and the ISA-tier
  throughput caveat is dropped.
- **SLH-DSA:** under every non-CNSA policy a caveat names
  SLH-DSA-SHA2-128s as a conservative hash-based alternative for
  low-volume signing. It stays a caveat, not the primary, because a
  signing service implies request-rate signing and SLH-DSA signs at
  single-digit ops/s. SLH-DSA is not a CNSA 2.0 algorithm, so it is not
  offered under `cnsa-2.0`.

### `firmware-signing`

- **Bottleneck:** none at sign time. Firmware is signed at build time
  and verified for the device's whole field life, so long-term
  confidence in the primitive dominates and no ISA-tier or throughput
  caveats are emitted.
- **KEM:** `null` with `mode: "n/a"`, as for `signing-service`.
- **Signature:**

  | Policy | Signature | Reason |
  |--------|-----------|--------|
  | `cnsa-2.0` | `ML-DSA-87` | Mandated by CNSA 2.0 |
  | `nist-civilian` | `SLH-DSA-SHA2-128s` | Hash-based, conservative for firmware |
  | `eu-anssi-bsi` | `SLH-DSA-SHA2-128s` | Hash-based, conservative for firmware |
  | `commercial` | `SLH-DSA-SHA2-128s` | Hash-based, most conservative choice |

  SLH-DSA relies only on hash-function security (no lattice
  assumptions). Its slow sign rate is irrelevant at build time and its
  7856-byte signatures are negligible next to megabyte firmware images.
  ML-DSA-65 is named in the reason as the alternative for
  performance-sensitive build pipelines.
- **CNSA 2.0 caveat:** SLH-DSA is not a CNSA 2.0 algorithm. CNSA 2.0's
  hash-based option for software and firmware signing is the stateful
  LMS / XMSS family (NIST SP 800-208), which the caveat points to; those
  schemes need strict key-state management, typically inside an HSM.
- **HSM:** when a PQC-capable accelerator is present a caveat recommends
  keeping the signing key in it.

### `generic`

No workload profile, so there is nothing role-specific to optimise. It
returns a stub record (`implemented: false`) carrying the policy basis.
Pick one of the roles above for an algorithm recommendation.

## How a policy update should be made

1. Edit `POLICY_PREFERENCES` in `pqc_readiness/recommendation.py`. This is the only
   place the engine reads policy preferences from.
2. Update the corresponding section in this document with the new
   authority position and a citation to the publication that motivated
   the change.
3. Update the policy tests in `tests/test_recommendation.py` so the
   expected algorithm names track the new policy.
4. The engine itself (`recommend`, the per-role `_recommend_*`
   functions, `_recommend_one`) should not need changes for a routine policy
   update — if it does, that is a sign the policy table needs another
   field, not that the engine should special-case the new policy.

The policy table is a snapshot in time. Tracking authority position
changes is a maintenance task, not an automation goal.

## Out of scope

- Sector-specific guidance (financial, healthcare, telecom). Sectors
  vary too widely; the four policies above cover the relevant
  authorities they refer back to.
- Country-specific policies beyond ANSSI / BSI / NSA / NIST. Add via
  follow-up issues when a customer asks; do not pre-implement.
- Long-term migration roadmap beyond the recommendation itself.
- Auto-applying configuration to the host. The recommendation is
  advisory; the operator applies it.
- Recommendations for cryptographic primitives outside NIST FIPS
  203/204/205.

## Other national timelines

The `--recommend` document's `policy_sources` block also carries these,
for context. They are not separate engine policies.

| Authority | Document | Milestones |
| --- | --- | --- |
| UK NCSC | [Timelines for migration to PQC](https://www.ncsc.gov.uk/guidance/pqc-migration-timelines) | 2028 discovery and plan; 2031 highest-priority migrations; 2035 all systems |
| Canada CCCS | [ITSM.40.001](https://www.cyber.gc.ca/en/guidance/roadmap-migration-post-quantum-cryptography-government-canada-itsm40001) | April 2026 departmental plans; end of 2031 high-priority systems; end of 2035 remaining systems |
| Australia ASD | [ISM, Guidelines for Cryptography](https://www.cyber.gov.au/business-government/asds-cyber-security-frameworks/ism/cyber-security-guidelines/guidelines-for-cryptography) (ISM-0472/0474/0475) | DH, ECDH and ECDSA not approved beyond 2030 |

Every date in this document was read from the issuing body's own
publication on 2026-10-13. `docs/json-output.md` describes the
`timeline` and `policy_sources` fields.
