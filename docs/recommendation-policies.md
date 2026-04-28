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
dictionary (`POLICY_PREFERENCES`) in `pqc_readiness.py`. Updating a
policy when an authority revises guidance is a one-place edit; it must
not require touching the engine.

## `cnsa-2.0` — US National Security Systems

- **Authority:** NSA, Commercial National Security Algorithm Suite 2.0
- **Source:**
  - CNSA 2.0 advisory:
    https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF
  - CNSA 2.0 FAQ:
    https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSI_CNSA_2.0_FAQ_.PDF
- **Position:** ML-KEM-1024 and ML-DSA-87 for National Security
  Systems. Pure PQC is preferred. Hybrid is permitted only where a
  protocol mandates it (e.g., IKEv2 per RFC 9370).
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
  - NIST IR 8547: https://csrc.nist.gov/pubs/ir/8547/final
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
  - ANSSI position on PQC migration:
    https://cyber.gouv.fr/publications/should-quantum-key-distribution-be-used-secure-communications
  - BSI guidance on PQC:
    https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Informationen-und-Empfehlungen/Quantentechnologien-und-Post-Quanten-Kryptografie/quantentechnologien-und-post-quanten-kryptografie_node.html
- **Position:** Both authorities recommend hybrid deployment of PQC
  alongside a classical primitive throughout the migration period.
  Pure-PQC deployments are discouraged until confidence in the new
  primitives matures.
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

## How a policy update should be made

1. Edit `POLICY_PREFERENCES` in `pqc_readiness.py`. This is the only
   place the engine reads policy preferences from.
2. Update the corresponding section in this document with the new
   authority position and a citation to the publication that motivated
   the change.
3. Update the policy tests in `tests/test_recommendation.py` so the
   expected algorithm names track the new policy.
4. The engine itself (`recommend`, `_recommend_tls_server`,
   `_recommend_one`) should not need changes for a routine policy
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
