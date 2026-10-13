"""CBOM profiles (--cbom-profile): data tables, no logic (#144).

A profile annotates the canonical CBOM with the fields a reporting regime
asks for.  Everything regime-specific lives here as data so that, when
CISA/NIST publish the minimum CBOM elements required by EO 14412 §5(d)
(due ~March 2027), remapping is a table edit (#150), not an emitter
rewrite.  render/cbom.py reads these tables; it encodes no dates or
mandate names itself.

Every date and requirement below was checked against the primary
document on 2026-10-13:

* EO 14412, "Securing the Nation Against Advanced Cryptographic Attacks"
  (signed 2026-06-22; Federal Register document 2026-12909, published
  2026-06-25).  §4(b)(ii): PQC key establishment for HVAs and high
  impact systems by 2030-12-31.  §4(b)(iii): PQC digital signatures by
  2031-12-31.  §5(d): CISA, with NIST, to publish the minimum elements
  for a CBOM within 270 days.
  https://public-inspection.federalregister.gov/2026-12909.pdf
* OMB M-26-15, "Execution of the Migration to Post-Quantum
  Cryptography" (2026-06-24).  §4: TLS 1.3 or successor "not later than
  January 2, 2030" (consistent with EO 14306).  Appendix A: the
  quantum-vulnerable algorithms, split into key establishment (ECDH,
  MQV, DH, RSA key establishment) and signatures (ECDSA, RSA, DSA), plus
  "other non-PQC asymmetric".
  https://www.whitehouse.gov/wp-content/uploads/2026/06/M-26-15-Execution-of-the-Migration-to-Post-Quantum-Cryptography.pdf
* OMB M-23-02 (2022-11-18): the nine per-system inventory items, and
  footnote 15 defining "actively used" as possible to be employed during
  operation, including only for legacy clients.  Not rescinded; M-26-15
  builds on its inventories.
  https://bidenwhitehouse.archives.gov/wp-content/uploads/2022/11/M-23-02-M-Memo-on-Migrating-to-Post-Quantum-Cryptography.pdf
"""

from __future__ import annotations

from typing import Any

PROFILE_NONE = "none"
PROFILE_FEDERAL_DRAFT = "federal-draft"

FEDERAL_DRAFT: dict[str, Any] = {
    "id": PROFILE_FEDERAL_DRAFT,
    # Property-name prefix for every field this profile adds.
    "prefix": "federal:",
    "status": (
        "draft: pending the CISA/NIST minimum CBOM elements "
        "(EO 14412 §5(d), due ~2027-03); remapped in #150"
    ),
    "sources": {
        "eo_14412": "https://public-inspection.federalregister.gov/2026-12909.pdf",
        "omb_m_26_15": (
            "https://www.whitehouse.gov/wp-content/uploads/2026/06/"
            "M-26-15-Execution-of-the-Migration-to-Post-Quantum-Cryptography.pdf"
        ),
        "omb_m_23_02": (
            "https://bidenwhitehouse.archives.gov/wp-content/uploads/2022/11/"
            "M-23-02-M-Memo-on-Migrating-to-Post-Quantum-Cryptography.pdf"
        ),
    },
    # CycloneDX algorithm primitive -> M-26-15 Appendix A function.  The
    # two functions have different deadlines, so the split matters.
    "function_by_primitive": {
        "kem": "key-establishment",
        "key-agree": "key-establishment",
        "combiner": "key-establishment",
        "signature": "digital-signature",
    },
    # Function -> (deadline, source clause).
    "deadlines": {
        "key-establishment": ("2030-12-31", "EO 14412 §4(b)(ii)"),
        "digital-signature": ("2031-12-31", "EO 14412 §4(b)(iii)"),
    },
    "tls13_deadline": ("2030-01-02", "OMB M-26-15 §4 (EO 14306)"),
    # Canonical asset category -> quantum-vulnerable?  Hybrids combine a
    # classical and a PQC component; M-26-15 §3 accepts hybrid
    # architectures, so they are not counted as vulnerable.
    "quantum_vulnerable_by_category": {
        "openssl_kem": False,
        "openssl_sig": False,
        "openssl_tls_hybrid": False,
        "openssl_tls_pqc": False,
        "openssl_tls_classical": True,
        "ssh_kex_hybrid": False,
        "ssh_kex_pqc": False,
        "ssh_kex_classical": True,
        # PQC names found in other crypto libraries' binaries (#110, #194).
        "library_kem": False,
        "library_sig": False,
        "library_tls_hybrid": False,
        "library_ssh_kex_hybrid": False,
        "library_ssh_kex_pqc": False,
    },
    # Trust-store certificate category -> quantum-vulnerable?
    "quantum_vulnerable_by_cert_category": {
        "classical": True,
        "hybrid_composite": False,
        "pure_pqc": False,
    },
    # What the scanner can say about M-23-02 "actively used" (footnote
    # 15).  An algorithm a host library exposes is *possible* to employ;
    # whether configuration allows it is #104/#106, and whether it is
    # negotiated is #107/#149.
    "in_use": {"value": "possible", "basis": "library-capability"},
    # M-23-02 per-system items: (number, label, where the value comes from).
    # "metadata:<key>" = the operator file (--inventory-metadata);
    # "scan:<what>" = collected by the scanner.
    "m23_02_items": (
        (1, "FISMA system identifier", "metadata:fisma_system_id"),
        (2, "FIPS 199 categorization", "metadata:fips199_categorization"),
        (3, "HVA identifier", "metadata:hva_id"),
        (4, "CRQC-vulnerable cryptographic systems actively used", "scan:assets"),
        (5, "Software package provenance (COTS/GOTS/other)", "scan:packages"),
        (6, "Operating system with major/minor version", "scan:os"),
        (7, "Hosting model and provider", "metadata:hosting"),
        (8, "Data lifecycle and time to live", "metadata:data_lifecycle"),
        (9, "Additional notes", "metadata:notes"),
    ),
}

PROFILES: dict[str, dict[str, Any] | None] = {
    PROFILE_NONE: None,
    PROFILE_FEDERAL_DRAFT: FEDERAL_DRAFT,
}
