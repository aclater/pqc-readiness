"""Algorithm recommendation engine (--recommend) and its text / markdown renderers."""

from __future__ import annotations

import argparse
from typing import Any, Callable

from . import algorithms as _algorithms
from . import report as _report
from . import registry as _registry


# ---------------------------------------------------------------------------
# Algorithm recommendation engine
# ---------------------------------------------------------------------------
#
# `recommend()` is a pure function over (Report, policy, role).  It does
# NOT consult network or disk; everything it needs is already on the
# Report.  The policy-to-preference mapping is a single declarative dict
# (POLICY_PREFERENCES) so that authority position changes can be made
# without touching the engine.  The authoritative document for each
# policy is cited in `docs/recommendation-policies.md`.
#
# Five policy modes, four full and one composite:
#   cnsa-2.0      US National Security Systems / NSA-aligned.  Pure PQC
#                 preferred; hybrids permitted but not required (NSA
#                 anticipates one for IKEv2).
#   nist-civilian US federal civilian / FCEB.  ML-KEM, ML-DSA, SLH-DSA
#                 per FIPS 203/204/205.  Hybrid permitted, not required.
#   eu-anssi-bsi  EU public sector under ANSSI / BSI.  Hybrid actively
#                 recommended throughout the migration period.
#   commercial    No specific compliance regime.  Both pure and hybrid
#                 acceptable; hybrid suggested for long-confidentiality
#                 (HNDL-relevant) data.
#   auto          Side-by-side recommendation under all four real
#                 policies, with no single "preferred" answer.
#
# Roles (all implemented except `generic`):
#   tls-server        KEM + signature, weighted to sign/handshake cost
#   tls-client        KEM + signature, weighted to verify cost (#90)
#   signing-service   signature only (kem.mode "n/a"), sign throughput (#91)
#   firmware-signing  signature only; SLH-DSA primary outside CNSA 2.0 (#92)
#   generic           stub: returns {"implemented": False, ...}

POLICY_PREFERENCES: dict[str, dict[str, Any]] = {
    "cnsa-2.0": {
        "name": "CNSA 2.0",
        "authority": "NSA / CNSA 2.0 (US National Security Systems)",
        "hybrid_policy": "discouraged",
        "hybrid_allowed_for": ["ikev2"],
        "kem_primary": "ML-KEM-1024",
        "sig_primary": "ML-DSA-87",
        "hash_primary": "SHA-384",
        "requires_fips": True,
        "citation": (
            "CNSA 2.0 specifies ML-KEM-1024 and ML-DSA-87 for National "
            "Security Systems.  Pure PQC is preferred; hybrids are "
            "permitted but not required, and NSA anticipates one for "
            "IKEv2 (CNSA 2.0 FAQ ver. 2.1)."
        ),
        "source": (
            "NSA CSA Announcing CNSA 2.0 (Sept 2022) and CNSA 2.0 FAQ "
            "ver. 2.1 (Dec 2024)"
        ),
    },
    "nist-civilian": {
        "name": "NIST civilian / FCEB",
        "authority": "NIST FIPS 203 / 204 / 205 (US federal civilian)",
        "hybrid_policy": "permitted",
        "hybrid_allowed_for": ["tls-server", "tls-client", "ikev2"],
        "kem_primary": "ML-KEM-768",
        "sig_primary": "ML-DSA-65",
        "hash_primary": "SHA-256",
        "requires_fips": True,
        "citation": (
            "NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), and FIPS 205 "
            "(SLH-DSA) standardize the civilian PQC suite.  Hybrid is "
            "permitted under SP 800-56C Rev. 2; it is not required."
        ),
        "source": (
            "NIST FIPS 203 / 204 / 205, NIST IR 8547 (initial public draft), "
            "NIST SP 800-56C Rev. 2, NIST SP 800-227"
        ),
    },
    "eu-anssi-bsi": {
        "name": "ANSSI / BSI hybrid",
        "authority": "ANSSI (FR) and BSI (DE) PQC migration guidance",
        "hybrid_policy": "recommended",
        "hybrid_allowed_for": [
            "tls-server",
            "tls-client",
            "ikev2",
            "signing-service",
        ],
        "kem_primary": "ML-KEM-768",
        "sig_primary": "ML-DSA-65",
        "hash_primary": "SHA-256",
        "requires_fips": False,
        "citation": (
            "ANSSI and BSI both recommend deploying PQC alongside a "
            "classical primitive (hybrid) during the migration period.  "
            "Pure-PQC deployments are discouraged until confidence in "
            "the new primitives matures."
        ),
        "source": (
            "BSI TR-02102-1 version 2026-01; ANSSI views on the PQC "
            "transition (2023 follow up); EU Coordinated Implementation "
            "Roadmap for the Transition to PQC v1.1 (2025)"
        ),
    },
    "commercial": {
        "name": "Commercial / no specific regime",
        "authority": "no specific compliance regime",
        "hybrid_policy": "either",
        "hybrid_allowed_for": [
            "tls-server",
            "tls-client",
            "ikev2",
            "signing-service",
        ],
        "kem_primary": "ML-KEM-768",
        "sig_primary": "ML-DSA-65",
        "hash_primary": "SHA-256",
        "requires_fips": False,
        "citation": (
            "Outside a specific compliance regime, both pure-PQC and "
            "hybrid deployments are acceptable.  Hybrid is suggested "
            "for data with long-confidentiality requirements (HNDL)."
        ),
        "source": "no single source — see policy guidance documentation",
    },
}


# ---------------------------------------------------------------------------
# Migration timelines and their sources (#141)
# ---------------------------------------------------------------------------
#
# Every milestone below was read from the issuing body's own document on
# 2026-10-13 (archived copies where the publisher blocks scripted fetches;
# noted per entry).  `status` is the document's own standing: "final" or
# "draft".  Claims that could not be confirmed from a primary source are
# deliberately absent: they are listed in the #141 PR, not encoded here.
POLICY_SOURCES: dict[str, dict[str, Any]] = {
    "us-nss-cnsa-2.0": {
        "authority": "NSA (US National Security Systems)",
        "documents": [
            {
                "title": "Announcing the Commercial National Security Algorithm Suite 2.0",
                "date": "2022-09",
                "status": "final",
                "url": "https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF",
            },
            {
                "title": "The Commercial National Security Algorithm Suite 2.0 and Quantum Computing FAQ, ver. 2.1",
                "date": "2024-12",
                "status": "final",
                "url": "https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSI_CNSA_2.0_FAQ_.PDF",
            },
        ],
        "milestones": [
            {
                "by": "2027-01-01",
                "event": "All new NSS acquisitions CNSA 2.0 compliant (CNSSP 15)",
            },
            {
                "by": "2030-12-31",
                "event": "Equipment and services that cannot support CNSA 2.0 phased out",
            },
            {"by": "2031-12-31", "event": "CNSA 2.0 algorithms mandated for use"},
            {"by": "2035", "event": "All NSS quantum-resistant (NSM-10)"},
        ],
        # Per-category "support and prefer" / "exclusively use" years from
        # the 2022 advisory's transition timeline.
        "categories": {
            "software-firmware-signing": {
                "support_and_prefer": "2025",
                "exclusive_use": "2030",
            },
            "web-browsers-servers-cloud": {
                "support_and_prefer": "2025",
                "exclusive_use": "2033",
            },
            "traditional-networking": {
                "support_and_prefer": "2026",
                "exclusive_use": "2030",
            },
            "operating-systems": {
                "support_and_prefer": "2027",
                "exclusive_use": "2033",
            },
            "niche-equipment": {"support_and_prefer": "2030", "exclusive_use": "2033"},
            "custom-legacy": {"support_and_prefer": None, "exclusive_use": "2033"},
        },
        "notes": [
            "Only ML-KEM-1024, ML-DSA-87 and single-tree LMS/XMSS are approved; SLH-DSA and HSS/XMSS^MT are not.",
            "Hybrids are permitted but not required.",
        ],
        "verified": "2026-10-13 (media.defense.gov blocks scripted fetches; read via web.archive.org)",
    },
    "us-nist": {
        "authority": "NIST (US federal civilian)",
        "documents": [
            {
                "title": "NIST IR 8547, Transition to Post-Quantum Cryptography Standards",
                "date": "2024-11-12",
                "status": "draft",
                "url": "https://csrc.nist.gov/pubs/ir/8547/ipd",
            },
        ],
        "milestones": [
            {
                "by": "2030",
                "event": "Quantum-vulnerable algorithms at 112-bit strength deprecated after 2030 (draft)",
            },
            {
                "by": "2035",
                "event": "All quantum-vulnerable public-key algorithms disallowed after 2035 (draft)",
            },
        ],
        "verified": "2026-10-13",
    },
    "eu": {
        "authority": "EU NIS Cooperation Group (PQC work stream)",
        "documents": [
            {
                "title": "A Coordinated Implementation Roadmap for the Transition to Post-Quantum Cryptography, Part 1, v1.1",
                "date": "2025-06-11",
                "status": "final",
                "url": "https://digital-strategy.ec.europa.eu/en/library/coordinated-implementation-roadmap-transition-post-quantum-cryptography",
            },
        ],
        "milestones": [
            {
                "by": "2026-12-31",
                "event": "Member States complete First Steps, including national transition plans",
            },
            {
                "by": "2030-12-31",
                "event": "High-risk use cases transitioned; no stand-alone quantum-vulnerable public-key mechanisms",
            },
            {
                "by": "2035-12-31",
                "event": "Transition complete for as many systems as feasible; medium-risk use cases off stand-alone quantum-vulnerable mechanisms",
            },
        ],
        "verified": "2026-10-13",
    },
    "de-bsi": {
        "authority": "BSI (Germany)",
        "documents": [
            {
                "title": "BSI TR-02102-1, Cryptographic Mechanisms: Recommendations and Key Lengths, version 2026-01",
                "date": "2026-01-23",
                "status": "final",
                "url": "https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-1.pdf",
            },
        ],
        "milestones": [],
        "notes": [
            "Quantum-safe mechanisms should be used in hybrid form, combined with a classical method.",
            "ML-KEM-768 and ML-KEM-1024 are recommended, alongside FrodoKEM and Classic McEliece.",
        ],
        "verified": "2026-10-13",
    },
    "fr-anssi": {
        "authority": "ANSSI (France)",
        "documents": [
            {
                "title": "ANSSI views on the Post-Quantum Cryptography transition (2023 follow up)",
                "date": "2023-12-21",
                "status": "final",
                "url": "https://cyber.gouv.fr/en/publications/follow-position-paper-post-quantum-cryptography",
            },
        ],
        "milestones": [],
        "notes": [
            "Hybridation is required wherever post-quantum mitigation is needed in the short and medium term.",
            "Hybrid PQC is recommended especially for products protecting information beyond 2030.",
        ],
        "verified": "2026-10-13",
    },
    "uk-ncsc": {
        "authority": "NCSC (United Kingdom)",
        "documents": [
            {
                "title": "Timelines for migration to post-quantum cryptography",
                "date": "2026-08",
                "status": "final",
                "url": "https://www.ncsc.gov.uk/guidance/pqc-migration-timelines",
            },
        ],
        "milestones": [
            {
                "by": "2028",
                "event": "Migration goals defined, full discovery done, initial plan built",
            },
            {
                "by": "2031",
                "event": "Early, highest-priority migration activities done",
            },
            {
                "by": "2035",
                "event": "Migration of all systems, services and products complete",
            },
        ],
        "verified": "2026-10-13",
    },
    "ca-cccs": {
        "authority": "Canadian Centre for Cyber Security",
        "documents": [
            {
                "title": "Roadmap for the migration to post-quantum cryptography for the Government of Canada (ITSM.40.001)",
                "date": None,
                "status": "final",
                "url": "https://www.cyber.gc.ca/en/guidance/roadmap-migration-post-quantum-cryptography-government-canada-itsm40001",
            },
        ],
        "milestones": [
            {
                "by": "2026-04",
                "event": "Initial departmental PQC migration plan; annual progress reports from then",
            },
            {"by": "2031-12-31", "event": "High-priority systems migrated"},
            {"by": "2035-12-31", "event": "Remaining systems migrated"},
        ],
        "verified": "2026-10-13",
    },
    "au-asd": {
        "authority": "ASD (Australia)",
        "documents": [
            {
                "title": "Information Security Manual, Guidelines for Cryptography (ISM-0472/0474/0475, Dec 2024)",
                "date": "2024-12",
                "status": "final",
                "url": "https://www.cyber.gov.au/business-government/asds-cyber-security-frameworks/ism/cyber-security-guidelines/guidelines-for-cryptography",
            },
        ],
        "milestones": [
            {"by": "2030", "event": "DH, ECDH and ECDSA not approved beyond 2030"},
        ],
        "verified": "2026-10-13 (cyber.gov.au unreachable from the build host; read via web.archive.org)",
    },
}


# Which sources back each recommendation policy.  The remaining national
# timelines are reported alongside, for context, in `policy_sources`.
POLICY_TIMELINE_SOURCES: dict[str, tuple[str, ...]] = {
    "cnsa-2.0": ("us-nss-cnsa-2.0",),
    "nist-civilian": ("us-nist",),
    "eu-anssi-bsi": ("eu", "de-bsi", "fr-anssi"),
    "commercial": (),
}


# CNSA 2.0 deadline category per workload role.
CNSA_2_0_ROLE_CATEGORY: dict[str, str] = {
    "tls-server": "web-browsers-servers-cloud",
    "tls-client": "web-browsers-servers-cloud",
    "signing-service": "software-firmware-signing",
    "firmware-signing": "software-firmware-signing",
}


def _timeline(policy: str, role: str) -> dict[str, Any]:
    """Per-record pointer into POLICY_SOURCES, plus the CNSA 2.0 deadline
    category for the role when the policy is CNSA 2.0."""
    out: dict[str, Any] = {"sources": list(POLICY_TIMELINE_SOURCES[policy])}
    category = CNSA_2_0_ROLE_CATEGORY.get(role) if policy == "cnsa-2.0" else None
    if category is not None:
        dates = POLICY_SOURCES["us-nss-cnsa-2.0"]["categories"][category]
        out["cnsa_2_0_category"] = {"category": category, **dates}
    return out


VALID_POLICIES = ("cnsa-2.0", "nist-civilian", "eu-anssi-bsi", "commercial")


VALID_ROLES = (
    "tls-server",
    "tls-client",
    "signing-service",
    "firmware-signing",
    "generic",
)


def _accel_pqc_capable(accelerators: list[dict[str, Any]]) -> bool:
    return any(a.get("pqc_capable") for a in (accelerators or []))


def _isa_supports_large_params(isa_tier_str: str, has_pqc_accel: bool) -> bool:
    """ISA tier 'excellent', or any tier with a PQC-capable accelerator,
    can carry the larger parameter sets (ML-KEM-1024 / ML-DSA-87) at
    typical service SLOs."""
    return isa_tier_str == "excellent" or has_pqc_accel


def _recommend_kem(
    policy: str, isa: str, accel_pqc: bool, caveats: list[str]
) -> tuple[str, str, str]:
    """Policy-driven KEM choice shared by the TLS roles.  Returns
    (algorithm, mode, reason) and appends any ISA caveat to `caveats`."""
    pref = POLICY_PREFERENCES[policy]
    if policy == "cnsa-2.0":
        kem_chosen = "ML-KEM-1024"
        if _isa_supports_large_params(isa, accel_pqc):
            kem_reason = (
                "ML-KEM-1024 per CNSA 2.0; ISA tier and/or PQC accelerator "
                "supports the larger parameter set"
            )
        else:
            kem_reason = "ML-KEM-1024 mandated by CNSA 2.0"
            caveats.append(
                f"Policy mandates ML-KEM-1024 but host ISA tier is '{isa}' "
                "and no PQC-capable accelerator is present; encapsulation "
                "throughput will be lower than ML-KEM-768.  Add a PQC "
                "accelerator or accept the slower path."
            )
    elif policy == "eu-anssi-bsi":
        kem_chosen = "ML-KEM-768"
        kem_reason = (
            "ML-KEM-768 deployed in hybrid; ANSSI and BSI both recommend "
            "hybrid during the migration period"
        )
    elif policy == "nist-civilian":
        kem_chosen = "ML-KEM-768"
        if _isa_supports_large_params(isa, accel_pqc):
            kem_reason = (
                "ML-KEM-768 per FIPS 203; ISA tier could support ML-KEM-1024 "
                "if compliance scope demands it"
            )
        else:
            kem_reason = "ML-KEM-768 per FIPS 203; balanced for civilian deployments"
    else:  # commercial
        kem_chosen = "ML-KEM-768"
        kem_reason = (
            "ML-KEM-768 — broadly interoperable default for commercial "
            "deployments; consider hybrid for long-confidentiality data"
        )

    # Hybrid vs pure.  CNSA 2.0 discourages hybrid except where the
    # protocol mandates it (IKEv2); TLS is not IKEv2.  nist-civilian and
    # commercial default to pure with hybrid permitted.
    kem_mode = "hybrid" if pref["hybrid_policy"] == "recommended" else "pure"
    return kem_chosen, kem_mode, kem_reason


def _tls_groups_for(
    openssl: dict[str, Any], kem_chosen: str, kem_mode: str
) -> list[str]:
    """Advertised TLS groups that carry `kem_chosen` in `kem_mode`, using
    the registered group table (RFC 10024 / draft-ietf-tls-mlkem names)."""
    groups = openssl.get("tls_groups") or {}
    bucket = groups.get("hybrid" if kem_mode == "hybrid" else "pure_pqc") or []
    return sorted(
        n
        for n in bucket
        if (_algorithms.TLS_PQC_GROUPS.get(n) or {}).get("kem") == kem_chosen
    )


def _tls_group_caveats(
    openssl: dict[str, Any],
    kem_chosen: str,
    kem_mode: str,
    endpoint: str,
    caveats: list[str],
) -> list[str]:
    """Check the advertised TLS 1.3 groups can carry the chosen KEM in the
    chosen mode; return the groups that can.  A group of the right mode
    with the wrong ML-KEM parameter set does not count: X25519MLKEM768
    cannot carry the ML-KEM-1024 that CNSA 2.0 mandates (#139).
    `endpoint` is 'server' or 'client' and only affects wording."""
    tls_groups = openssl.get("tls_groups") or {}
    hybrid_groups = list(tls_groups.get("hybrid") or [])
    pure_groups = list(tls_groups.get("pure_pqc") or [])
    usable = _tls_groups_for(openssl, kem_chosen, kem_mode)
    if openssl.get("available"):
        if kem_mode == "hybrid" and not hybrid_groups:
            caveats.append(
                "No TLS 1.3 hybrid groups are advertised by this OpenSSL "
                "build.  Upgrade OpenSSL or load the relevant provider "
                f"before deploying a hybrid TLS {endpoint}."
            )
        elif kem_mode == "pure" and not pure_groups:
            caveats.append(
                "No TLS 1.3 pure-PQC groups are advertised by this "
                "OpenSSL build.  Upgrade OpenSSL or load the relevant "
                "provider before deploying pure-PQC TLS."
            )
        elif not usable:
            offered = hybrid_groups if kem_mode == "hybrid" else pure_groups
            caveats.append(
                f"The advertised {kem_mode} TLS groups ({', '.join(sorted(offered))}) "
                f"do not carry {kem_chosen}.  Enable a group that does before "
                f"deploying this TLS {endpoint}."
            )
    else:
        caveats.append(
            "OpenSSL was not detected on this host; the recommended "
            "algorithms cannot be served via TLS until an OpenSSL build "
            "with TLS 1.3 PQC group support is installed."
        )
    return usable


def _fips_caveat(policy: str, fips_kernel: bool, caveats: list[str]) -> None:
    pref = POLICY_PREFERENCES[policy]
    if pref["requires_fips"] and not fips_kernel:
        caveats.append(
            f"Kernel FIPS mode is not enabled.  {pref['name']} requires "
            "use of FIPS-validated cryptographic modules; enable kernel "
            "FIPS mode and load a FIPS-validated provider before going "
            "to production."
        )


def _recommendation_record(
    r: _report.Report,
    policy: str,
    role: str,
    kem: dict[str, Any],
    signature: dict[str, Any],
    caveats: list[str],
) -> dict[str, Any]:
    """Assemble the per-policy record.  Every implemented role emits the
    same keys so downstream consumers never special-case a role."""
    pref = POLICY_PREFERENCES[policy]
    hash_chosen = pref["hash_primary"]
    openssl = r.openssl or {}
    return {
        "role": role,
        "policy": policy,
        "policy_authority": pref["authority"],
        "policy_basis": pref["citation"],
        "policy_source": pref["source"],
        "implemented": True,
        "kem": kem,
        "signature": signature,
        "hash": {
            "algorithm": hash_chosen,
            "reason": f"{hash_chosen} aligned with {pref['name']} guidance",
        },
        "host_capability_inputs": {
            "isa_tier": (r.isa_tier or "unknown").lower(),
            "pqc_accelerator_present": _accel_pqc_capable(r.accelerators),
            "fips_kernel": bool((r.fips or {}).get("kernel")),
            "openssl_version": openssl.get("version") or "",
            "kernel_release": (r.kernel_info or {}).get("release") or "",
        },
        "timeline": _timeline(policy, role),
        "caveats": caveats,
    }


def _recommend_tls_server(r: _report.Report, policy: str) -> dict[str, Any]:
    isa = (r.isa_tier or "unknown").lower()
    accel_pqc = _accel_pqc_capable(r.accelerators)
    caveats: list[str] = []

    kem_chosen, kem_mode, kem_reason = _recommend_kem(policy, isa, accel_pqc, caveats)
    tls_groups = _tls_group_caveats(
        r.openssl or {}, kem_chosen, kem_mode, "server", caveats
    )

    # Signature: a TLS server signs every handshake, so sign latency is
    # the constraint.
    if policy == "cnsa-2.0":
        sig_chosen = "ML-DSA-87"
        if _isa_supports_large_params(isa, accel_pqc):
            sig_reason = (
                "ML-DSA-87 per CNSA 2.0; ISA tier supports the signing "
                "latency at typical service SLOs"
            )
        else:
            sig_reason = "ML-DSA-87 mandated by CNSA 2.0"
            caveats.append(
                f"Policy mandates ML-DSA-87 but host ISA tier is '{isa}' "
                "without a PQC accelerator; ML-DSA-87 sign p99 latency "
                "may exceed typical service SLOs.  Consider a hardware "
                "accelerator or accept the slower path."
            )
    else:
        sig_chosen = "ML-DSA-65"
        if isa == "good":
            sig_reason = (
                "ML-DSA-65 over ML-DSA-87 because ISA tier is 'good' not "
                "'excellent'; ML-DSA-87 sign p99 latency will likely "
                "exceed typical service SLOs"
            )
        elif isa in ("poor", "marginal"):
            sig_reason = (
                f"ML-DSA-65 because ISA tier is '{isa}' without a PQC "
                "accelerator; ML-DSA-87 sign p99 latency would likely "
                "exceed typical SLOs"
            )
        elif isa == "excellent":
            sig_reason = (
                "ML-DSA-65 — balanced default for civilian/commercial "
                "deployments; ISA tier could support ML-DSA-87 if "
                "compliance scope demands it"
            )
        else:
            sig_reason = (
                "ML-DSA-65 — balanced default for civilian/commercial deployments"
            )

    _fips_caveat(policy, bool((r.fips or {}).get("kernel")), caveats)
    return _recommendation_record(
        r,
        policy,
        "tls-server",
        {
            "algorithm": kem_chosen,
            "mode": kem_mode,
            "reason": kem_reason,
            "tls_groups": tls_groups,
        },
        {"algorithm": sig_chosen, "reason": sig_reason},
        caveats,
    )


# Size of the ML-KEM encapsulation key a TLS client places in its
# ClientHello key_share.  FIPS 203: ek = 384*k + 32 bytes (k=3 for
# ML-KEM-768, k=4 for ML-KEM-1024).  A test pins the ML-KEM-768 value to
# PQC_SIZES so the two tables cannot drift.
ML_KEM_ENCAPS_KEY_BYTES: dict[str, int] = {
    "ML-KEM-768": 384 * 3 + 32,
    "ML-KEM-1024": 384 * 4 + 32,
}


# Hybrid groups (X25519MLKEM768 etc.) append a classical share.
X25519_SHARE_BYTES = 32


# Key shares above this size push the ClientHello past what some legacy
# middleboxes accept in a single record/segment during migration.
CLIENT_HELLO_MIDDLEBOX_BYTES = 1200


def _recommend_tls_client(r: _report.Report, policy: str) -> dict[str, Any]:
    isa = (r.isa_tier or "unknown").lower()
    accel_pqc = _accel_pqc_capable(r.accelerators)
    caveats: list[str] = []

    kem_chosen, kem_mode, kem_reason = _recommend_kem(policy, isa, accel_pqc, caveats)
    tls_groups = _tls_group_caveats(
        r.openssl or {}, kem_chosen, kem_mode, "client", caveats
    )

    share_bytes = ML_KEM_ENCAPS_KEY_BYTES[kem_chosen]
    if kem_mode == "hybrid":
        share_bytes += X25519_SHARE_BYTES
    if share_bytes > CLIENT_HELLO_MIDDLEBOX_BYTES:
        caveats.append(
            f"The {kem_chosen} ({kem_mode}) key share adds {share_bytes} "
            "bytes to the ClientHello.  Some middleboxes on legacy "
            f"networks mishandle ClientHellos with key shares over "
            f"{CLIENT_HELLO_MIDDLEBOX_BYTES} bytes; test the network path "
            "before enforcing PQC-only negotiation."
        )

    # Signature: a TLS client verifies the server's certificate chain and
    # does not sign (outside mTLS), so verify throughput is the
    # constraint.  ML-DSA verify is far cheaper than sign, so ISA tier
    # matters much less than for a server.
    if policy == "cnsa-2.0":
        sig_chosen = "ML-DSA-87"
        if isa in ("poor", "marginal") and not accel_pqc:
            sig_reason = (
                "ML-DSA-87 mandated by CNSA 2.0; client cost is "
                "certificate-chain verify, not sign"
            )
            caveats.append(
                f"Policy mandates ML-DSA-87 and host ISA tier is '{isa}' "
                "without a PQC accelerator; ML-DSA-87 verify p99 latency "
                "per certificate chain will be higher than on modern "
                "hardware.  Verify is cheap relative to sign, so this "
                "is rarely limiting for a client."
            )
        else:
            sig_reason = (
                "ML-DSA-87 per CNSA 2.0; ISA tier comfortably supports "
                "ML-DSA-87 verify throughput for server certificate chains"
            )
    else:
        sig_chosen = "ML-DSA-65"
        if isa in ("poor", "marginal") and not accel_pqc:
            sig_reason = (
                f"ML-DSA-65 because ISA tier is '{isa}'; ML-DSA-65 verify "
                "keeps certificate-chain validation latency low on this host"
            )
        else:
            sig_reason = (
                "ML-DSA-65 — matches the server certificates civilian/"
                "commercial deployments issue; ISA tier comfortably "
                "supports ML-DSA verify throughput"
            )

    _fips_caveat(policy, bool((r.fips or {}).get("kernel")), caveats)
    return _recommendation_record(
        r,
        policy,
        "tls-client",
        {
            "algorithm": kem_chosen,
            "mode": kem_mode,
            "reason": kem_reason,
            "tls_groups": tls_groups,
        },
        {"algorithm": sig_chosen, "reason": sig_reason},
        caveats,
    )


def _no_kem(why: str) -> dict[str, Any]:
    """KEM record for roles that do no key exchange.  Keeps the record
    shape uniform so consumers indexing rec['kem'] never KeyError."""
    return {"algorithm": None, "mode": "n/a", "reason": why}


def _sign_rate_floor(algo: str, tier: str) -> str:
    """Per-core sign/s floor for `tier` from ALGO_THRESHOLDS, formatted."""
    return f"{_algorithms.ALGO_THRESHOLDS[algo][1][tier]:g}"


def _hsm_offload_caveat(sig_chosen: str) -> str:
    return (
        "A PQC-capable accelerator is present; route "
        f"{sig_chosen} signing through it (e.g. via PKCS#11) so sign "
        "throughput is bounded by the accelerator rather than host ISA tier."
    )


def _recommend_signing_service(r: _report.Report, policy: str) -> dict[str, Any]:
    isa = (r.isa_tier or "unknown").lower()
    accel_pqc = _accel_pqc_capable(r.accelerators)
    caveats: list[str] = []

    # Signature: a signing service signs at request rate, so sign
    # throughput is the constraint.  Thresholds quoted from
    # ALGO_THRESHOLDS so the reasoning matches the per-algo verdict.
    if policy == "cnsa-2.0":
        sig_chosen = "ML-DSA-87"
        if accel_pqc:
            sig_reason = (
                "ML-DSA-87 per CNSA 2.0; signing offloads to the PQC-capable "
                "accelerator, so host sign throughput is not the limit"
            )
        elif isa == "excellent":
            sig_reason = (
                "ML-DSA-87 per CNSA 2.0; ISA tier 'excellent' sustains "
                f"≥{_sign_rate_floor('ML-DSA-87', 'excellent')} sign/s per "
                "core at typical request rates"
            )
        else:
            sig_reason = "ML-DSA-87 mandated by CNSA 2.0"
            caveats.append(
                f"Policy mandates ML-DSA-87 but host ISA tier is '{isa}' "
                "without a PQC accelerator; expect ML-DSA-87 sign "
                f"throughput below {_sign_rate_floor('ML-DSA-87', 'excellent')} "
                "sign/s per core.  Size the signing fleet for it or add a "
                "PQC-capable HSM."
            )
    else:
        sig_chosen = "ML-DSA-65"
        if accel_pqc:
            sig_reason = (
                "ML-DSA-65 — balanced default; signing offloads to the "
                "PQC-capable accelerator, so host sign throughput is not "
                "the limit"
            )
        elif isa == "excellent":
            sig_reason = (
                "ML-DSA-65 — sustains "
                f"≥{_sign_rate_floor('ML-DSA-65', 'excellent')} sign/s per "
                "core on ISA tier 'excellent'; ML-DSA-87 is viable if "
                "compliance scope demands it"
            )
        elif isa == "good":
            sig_reason = (
                "ML-DSA-65 over ML-DSA-87 because ISA tier is 'good' not "
                "'excellent'; ML-DSA-87 sign throughput would cap the "
                "service's request rate"
            )
        elif isa in ("poor", "marginal"):
            sig_reason = (
                f"ML-DSA-65 because ISA tier is '{isa}' without a PQC "
                "accelerator; it is the cheaper-to-sign ML-DSA parameter set"
            )
            caveats.append(
                f"Host ISA tier is '{isa}' without a PQC accelerator; expect "
                "ML-DSA-65 sign throughput below "
                f"{_sign_rate_floor('ML-DSA-65', 'good')} sign/s per core.  "
                "Size the signing fleet for it or add a PQC-capable HSM."
            )
        else:
            sig_reason = "ML-DSA-65 — balanced default for request-rate signing"
        slh_sig = _algorithms.PQC_SIZES["SLH-DSA-SHA2-128s"]["sig"]
        caveats.append(
            "For low-volume signing (releases, documents), SLH-DSA-SHA2-128s "
            "is a conservative hash-based alternative with no lattice "
            f"assumptions.  Its sign rate (single-digit sign/s) and {slh_sig}"
            "-byte signatures rule it out for request-rate signing."
        )

    if accel_pqc:
        caveats.append(_hsm_offload_caveat(sig_chosen))
    _fips_caveat(policy, bool((r.fips or {}).get("kernel")), caveats)
    return _recommendation_record(
        r,
        policy,
        "signing-service",
        _no_kem("Key exchange is not applicable for signing services"),
        {"algorithm": sig_chosen, "reason": sig_reason},
        caveats,
    )


def _recommend_firmware_signing(r: _report.Report, policy: str) -> dict[str, Any]:
    accel_pqc = _accel_pqc_capable(r.accelerators)
    caveats: list[str] = []

    # Firmware is signed at build time and verified for the device's
    # whole field life, so long-term confidence in the primitive matters
    # and sign throughput does not: no ISA-tier caveats for this role.
    if policy == "cnsa-2.0":
        sig_chosen = "ML-DSA-87"
        sig_reason = (
            "ML-DSA-87 mandated by CNSA 2.0; firmware is signed at build "
            "time, so sign cost is irrelevant to the choice"
        )
        caveats.append(
            "CNSA 2.0 also specifies stateful hash-based signatures (LMS / "
            "XMSS, NIST SP 800-208) for software and firmware signing.  "
            "They suit long-lived firmware but require strict key-state "
            "management, typically inside an HSM.  SLH-DSA is not a "
            "CNSA 2.0 algorithm."
        )
    else:
        sig_chosen = "SLH-DSA-SHA2-128s"
        slh_sig = _algorithms.PQC_SIZES["SLH-DSA-SHA2-128s"]["sig"]
        sig_reason = (
            "SLH-DSA-SHA2-128s — hash-based, relying only on hash-function "
            "security with no lattice assumptions: the most conservative "
            "choice for long-lived firmware that must verify for its whole "
            "field life.  Build-time signing makes its slow sign rate "
            f"irrelevant, and {slh_sig}-byte signatures are negligible next "
            "to firmware images.  ML-DSA-65 is an alternative for "
            "performance-sensitive build pipelines."
        )

    if accel_pqc:
        caveats.append(
            "A PQC-capable accelerator is present; keep the firmware "
            f"signing key in it and sign {sig_chosen} there so the key "
            "never leaves the HSM."
        )
    _fips_caveat(policy, bool((r.fips or {}).get("kernel")), caveats)
    return _recommendation_record(
        r,
        policy,
        "firmware-signing",
        _no_kem("Key exchange is not applicable for firmware signing"),
        {"algorithm": sig_chosen, "reason": sig_reason},
        caveats,
    )


def _recommend_stub(r: _report.Report, policy: str, role: str) -> dict[str, Any]:
    """Placeholder for roles without a recommender.  Returns the
    policy basis so the JSON shape is consistent across roles, but
    leaves the algorithm fields empty.

    Every workload role has a dedicated recommender in
    _ROLE_RECOMMENDERS.  'generic' has no workload profile to optimise
    for, so it lands here."""
    pref = POLICY_PREFERENCES[policy]
    return {
        "role": role,
        "policy": policy,
        "policy_authority": pref["authority"],
        "policy_basis": pref["citation"],
        "policy_source": pref["source"],
        "implemented": False,
        "note": (
            f"Recommendations for role={role!r} are not yet implemented.  "
            "Implemented roles: " + ", ".join(sorted(_ROLE_RECOMMENDERS)) + "."
        ),
        "host_capability_inputs": {
            "isa_tier": (r.isa_tier or "unknown").lower(),
            "pqc_accelerator_present": _accel_pqc_capable(r.accelerators),
        },
        "timeline": _timeline(policy, role),
        "caveats": [],
    }


_ROLE_RECOMMENDERS: dict[str, Callable[[_report.Report, str], dict[str, Any]]] = {
    "tls-server": _recommend_tls_server,
    "tls-client": _recommend_tls_client,
    "signing-service": _recommend_signing_service,
    "firmware-signing": _recommend_firmware_signing,
}


def _recommend_one(r: _report.Report, policy: str, role: str) -> dict[str, Any]:
    impl = _ROLE_RECOMMENDERS.get(role)
    if impl is not None:
        return impl(r, policy)
    return _recommend_stub(r, policy, role)


def recommend(
    r: _report.Report,
    policy: str = "auto",
    role: str = "tls-server",
) -> dict[str, Any]:
    """Produce a host-specific PQC algorithm recommendation.

    Pure function over (Report, policy, role).  Returns a record that
    contains the recommendation AND the policy basis as separate fields,
    so downstream tooling can audit the chain of reasoning without
    re-deriving it.

    policy='auto' emits one recommendation per real policy in
    POLICY_PREFERENCES, side by side, with no single 'preferred' answer.
    """
    if role not in VALID_ROLES:
        raise ValueError(
            f"unknown role {role!r}; valid roles: {', '.join(VALID_ROLES)}"
        )
    if policy == "auto":
        return {
            "role": role,
            "mode": "auto",
            "hostname": r.hostname,
            "generated_at": r.generated_at,
            "recommendations": {p: _recommend_one(r, p, role) for p in VALID_POLICIES},
            "policy_sources": POLICY_SOURCES,
        }
    if policy not in POLICY_PREFERENCES:
        raise ValueError(
            f"unknown policy {policy!r}; valid policies: "
            f"{', '.join(VALID_POLICIES)} (or 'auto')"
        )
    return {
        "role": role,
        "mode": "single",
        "policy": policy,
        "hostname": r.hostname,
        "generated_at": r.generated_at,
        "recommendations": {policy: _recommend_one(r, policy, role)},
        "policy_sources": POLICY_SOURCES,
    }


def _render_recommendation_block(rec: dict[str, Any]) -> list[str]:
    """Render a single per-policy recommendation as plain-text lines."""
    L: list[str] = []
    L.append(f"Policy: {rec['policy']} ({rec['policy_authority']})")
    if not rec.get("implemented", False):
        L.append(f"  {rec.get('note', 'not implemented')}")
        return L
    kem = rec["kem"]
    sig = rec["signature"]
    h = rec["hash"]
    if kem["algorithm"] is None:
        L.append("  KEM:        n/a")
    else:
        L.append(f"  KEM:        {kem['algorithm']} ({kem['mode']})")
    L.append(f"              Reason: {kem['reason']}")
    L.append(f"  Signature:  {sig['algorithm']}")
    L.append(f"              Reason: {sig['reason']}")
    L.append(f"  Hash:       {h['algorithm']}")
    L.append(f"              Reason: {h['reason']}")
    L.append(f"  Policy basis: {rec['policy_basis']}")
    L.append(f"  Source:       {rec['policy_source']}")
    if rec["caveats"]:
        L.append("  Caveats:")
        for c in rec["caveats"]:
            L.append(f"    - {c}")
    return L


def render_recommendation_text(report: _report.Report, rec: dict[str, Any]) -> str:
    L: list[str] = []
    L.append(f"PQC algorithm recommendation — {report.hostname or 'unknown'}")
    L.append(f"Role: {rec['role']}")
    L.append(f"Mode: {rec['mode']}")
    L.append("")
    for _, sub in rec["recommendations"].items():
        L.extend(_render_recommendation_block(sub))
        L.append("")
    return "\n".join(L).rstrip() + "\n"


def render_recommendation_markdown(report: _report.Report, rec: dict[str, Any]) -> str:
    L: list[str] = []
    L.append(f"# PQC algorithm recommendation — {report.hostname or 'unknown'}")
    L.append("")
    L.append(f"_Generated {report.generated_at}_")
    L.append("")
    L.append(f"**Role:** `{rec['role']}` &nbsp;·&nbsp; **Mode:** `{rec['mode']}`")
    L.append("")
    for _, sub in rec["recommendations"].items():
        L.append(f"## Policy: `{sub['policy']}` — {sub['policy_authority']}")
        L.append("")
        if not sub.get("implemented", False):
            L.append(f"> {sub.get('note', 'not implemented')}")
            L.append("")
            continue
        kem = sub["kem"]
        sig = sub["signature"]
        h = sub["hash"]
        L.append("| Primitive | Algorithm | Reason |")
        L.append("|-----------|-----------|--------|")
        kem_algo = "n/a" if kem["algorithm"] is None else f"`{kem['algorithm']}`"
        L.append(f"| KEM ({kem['mode']}) | {kem_algo} | {kem['reason']} |")
        L.append(f"| Signature | `{sig['algorithm']}` | {sig['reason']} |")
        L.append(f"| Hash | `{h['algorithm']}` | {h['reason']} |")
        L.append("")
        L.append(f"**Policy basis:** {sub['policy_basis']}")
        L.append("")
        L.append(f"**Source:** {sub['policy_source']}")
        L.append("")
        if sub["caveats"]:
            L.append("**Caveats:**")
            L.append("")
            for c in sub["caveats"]:
                L.append(f"- {c}")
            L.append("")
    return "\n".join(L).rstrip() + "\n"


@_registry.register_arguments(80)
def add_arguments(ap: argparse.ArgumentParser) -> None:
    """--recommend, --policy, --role."""
    ap.add_argument(
        "--recommend",
        action="store_true",
        help=(
            "emit a host-specific PQC algorithm recommendation under the "
            "selected policy and role, instead of the readiness report"
        ),
    )
    ap.add_argument(
        "--policy",
        choices=[*VALID_POLICIES, "auto"],
        default="auto",
        help=(
            "compliance context for --recommend; 'auto' (default) emits "
            "all policies side by side"
        ),
    )
    ap.add_argument(
        "--role",
        choices=list(VALID_ROLES),
        default=None,
        help=(
            "workload role.  Drives both the recommendation engine "
            "(every workload role is implemented; 'generic' returns a "
            "stub response) and the memory-tier "
            "threshold (per-role good thresholds: tls-server=16 GiB, "
            "tls-client=4 GiB, signing-service=8 GiB, firmware-signing="
            "2 GiB, generic=16 GiB).  When omitted, the report contains "
            "memory tier evaluations for every role side-by-side under "
            "memory.tier_by_role; the recommendation engine still "
            "defaults to tls-server."
        ),
    )
