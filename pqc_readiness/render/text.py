"""Human-readable text and markdown report renderers."""

from __future__ import annotations

import argparse
import re
from typing import Any

from .. import report as _report
from .. import registry as _registry
from ..detect import config_policy as _config_policy
from ..detect import protocols_boot as _boot
from ..detect import protocols_kerberos as _kerberos


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------


class C:
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    RED = "\033[31m"
    CYAN = "\033[36m"
    MAGENTA = "\033[35m"
    enabled = False

    @classmethod
    def configure(cls, on: bool) -> None:
        cls.enabled = on

    @classmethod
    def wrap(cls, color: str, text: str) -> str:
        return f"{color}{text}{cls.RESET}" if cls.enabled else text


TIER_COLOR = {
    "excellent": C.GREEN,
    "good": C.GREEN,
    "marginal": C.YELLOW,
    "poor": C.RED,
    "unknown": C.DIM,
}


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------


def _tier_label(tier: str) -> str:
    return C.wrap(TIER_COLOR.get(tier, ""), tier.upper())


def _render_text_header(r: _report.Report) -> list[str]:
    """Banner and host-identity preamble (host, CPU, cores, memory, timestamp)."""
    bar = "=" * 76
    L: list[str] = [
        C.wrap(C.BOLD, bar),
        C.wrap(C.BOLD, "  Post-Quantum Cryptography Readiness Report"),
        C.wrap(C.BOLD, bar),
        f"  Host:          {r.hostname}  ({r.os}, {r.arch})",
        f"  CPU:           {r.cpu_model}",
    ]
    if r.cpu_freq_mhz:
        L.append(f"  Max freq:      {r.cpu_freq_mhz / 1000:.2f} GHz")
    L.append(
        f"  Cores:         {r.cores_physical} physical / {r.cores_logical} logical"
    )
    L.append(
        f"  Memory:        {r.mem_total_gb:.1f} GiB total / {r.mem_avail_gb:.1f} GiB available"
    )
    if r.memory_bandwidth_gb_s is not None:
        L.append(
            f"  Mem bandwidth: ~{r.memory_bandwidth_gb_s} GB/s ({r.memory_bandwidth_method})"
        )
    elif r.memory_bandwidth_method:
        L.append(f"  Mem bandwidth: {r.memory_bandwidth_method}")
    L.append(f"  Generated:     {r.generated_at}")
    L.append("")
    return L


def _render_text_isa(r: _report.Report) -> list[str]:
    """Section 1: CPU instruction-set support for PQC."""
    L: list[str] = [
        C.wrap(C.BOLD, "1. CPU instruction-set support for PQC"),
        f"   Tier: {_tier_label(r.isa_tier)}  (score {r.isa_score})",
        f"   {r.isa_reason}",
    ]
    if r.isa_features:
        for _, info in sorted(r.isa_features.items()):
            L.append(f"     + {info['name']:<22} {info['purpose']}")
    else:
        L.append("     (no PQC-relevant ISA features detected)")
    L.append("")
    return L


def _render_text_accelerators(r: _report.Report) -> list[str]:
    """Section 2: Cryptographic accelerators, HSMs, TPMs, PKCS#11 modules."""
    L: list[str] = [C.wrap(C.BOLD, "2. Cryptographic accelerators / HSMs / TPMs")]
    if r.accelerators:
        for a in r.accelerators:
            pqc_mark = " [PQC-capable]" if a.get("pqc_capable") else ""
            L.append(f"     [{a['kind']:>11}] {a['name']}{pqc_mark}  ({a['detail']})")
    else:
        L.append("     none detected - host would do all PQC in CPU/memory")
    if r.hsm_present_but_not_pqc:
        L.append(
            C.wrap(
                C.YELLOW,
                "     NOTE: HSM(s) detected but none currently confirmed PQC-capable.",
            )
        )
        L.append(
            "           Verify firmware version against vendor's PQC release notes."
        )
    if r.tpm_pqc.get("present"):
        marker = "yes" if r.tpm_pqc.get("pqc_advertised") else "no"
        L.append(
            f"     TPM PQC algorithms advertised: {marker}  ({r.tpm_pqc.get('note', '')})"
        )
    if r.pkcs11_modules:
        L.append(f"     PKCS#11 modules installed: {len(r.pkcs11_modules)}")
        for p in r.pkcs11_modules[:5]:
            L.append(f"       - {p}")
        if len(r.pkcs11_modules) > 5:
            L.append(f"       ... and {len(r.pkcs11_modules) - 5} more")
    L.append("")
    return L


def _render_text_kernel_crypto(r: _report.Report) -> list[str]:
    """Section 3a: kernel release, /proc/crypto PQC drivers and hw-accel, kTLS."""
    L: list[str] = []
    if r.kernel_info:
        rh = r.kernel_info.get("redhat_release") or {}
        if rh.get("raw"):
            L.append(f"   Distribution:  {rh.get('raw')}")
        L.append(f"   Kernel:        {r.kernel_info.get('release', '?')}")
        pqc_drivers = r.kernel_info.get("proc_crypto_pqc") or []
        if pqc_drivers:
            L.append(f"   /proc/crypto PQC drivers: {', '.join(pqc_drivers)}")
        else:
            L.append(
                "   /proc/crypto PQC drivers: none (kernel-side PQC not in mainline)"
            )
    if r.kernel_crypto_hw:
        L.append(f"   /proc/crypto hw-accel: {len(r.kernel_crypto_hw)} drivers")
        for d in r.kernel_crypto_hw[:6]:
            L.append(f"     - {d}")
        if len(r.kernel_crypto_hw) > 6:
            L.append(f"     ... and {len(r.kernel_crypto_hw) - 6} more")
    if r.ktls_supported is not None:
        L.append(f"   Kernel TLS:    {'yes' if r.ktls_supported else 'no'}")
    return L


def _render_text_fips(r: _report.Report) -> list[str]:
    """Section 3b: FIPS mode and FIPS/PQC conflict warning."""
    L: list[str] = []
    if r.fips:
        L.append(
            f"   FIPS mode:     kernel={r.fips.get('kernel')}, openssl-provider={r.fips.get('openssl_provider')}"
        )
    if r.fips_pqc_conflict.get("in_conflict"):
        L.append(
            C.wrap(
                C.RED,
                f"   ⚠  FIPS/PQC conflict: {r.fips_pqc_conflict.get('explanation')}",
            )
        )
    return L


def _render_text_ssh_ipsec_nss(r: _report.Report) -> list[str]:
    """Section 3c: OpenSSH PQC kex groups, strongSwan IPsec, NSS."""
    L: list[str] = []
    if r.ssh_pqc.get("available"):
        pqc = r.ssh_pqc.get("pqc_kex") or []
        L.append(
            f"   OpenSSH kex:   {len(pqc)} PQC algorithm(s)"
            + (f": {', '.join(pqc)}" if pqc else "")
        )
        kg = r.ssh_pqc.get("kex_groups") or {}
        hyb = kg.get("hybrid") or []
        pure = kg.get("pure_pqc") or []
        if hyb:
            L.append(f"     hybrid:    {', '.join(hyb)}")
        if pure:
            L.append(f"     pure PQC:  {', '.join(pure)}")
    sshd = r.sshd
    if sshd.get("available"):
        if sshd.get("kex_offered") is None:
            offered = "compiled-in default (not determinable from config)"
        elif sshd.get("pqc_offered"):
            offered = "PQC offered" + (
                " first"
                if sshd.get("pqc_first")
                else f", but {sshd.get('first_kex')} first"
            )
        else:
            offered = "no PQC key exchange offered"
        L.append(f"   sshd kex:      {offered}  (via {sshd.get('source')})")
        keys = [k for k in sshd.get("host_keys") or [] if k.get("readable")]
        if keys:
            L.append(
                "     host keys: "
                + ", ".join(f"{k.get('type')} {k.get('bits', '?')}" for k in keys)
            )
    if r.ipsec_pqc.get("available"):
        impl = {"strongswan": "strongSwan", "libreswan": "Libreswan"}.get(
            str(r.ipsec_pqc.get("implementation")), "IPsec"
        )
        L.append(
            f"   {impl + ':':<15}PQC support {'yes' if r.ipsec_pqc.get('pqc') else 'no'}"
        )
    ike_sum = (r.ipsec_pqc.get("configured") or {}).get("summary") or {}
    if ike_sum.get("ike_proposals"):
        L.append(
            f"   IKE config:    {ike_sum['ike_proposals']} proposal(s) in "
            f"{ike_sum.get('connections', 0)} connection(s); ML-KEM offered by "
            f"{ike_sum.get('connections_offering_pqc', 0)}, required by "
            f"{ike_sum.get('connections_requiring_pqc', 0)}"
        )
    if r.nss.get("available"):
        L.append(
            f"   NSS:           {r.nss.get('version')}  (PQC-capable: {r.nss.get('pqc_capable')})"
        )
    return L


def _crypto_config_summary(cp: dict[str, object]) -> str:
    ossl = cp.get("openssl") or {}
    settings = ossl.get("settings") or {} if isinstance(ossl, dict) else {}
    parts = []
    if settings.get("MinProtocol"):
        parts.append(f"MinProtocol {settings['MinProtocol']}")
    if isinstance(ossl, dict) and ossl.get("seclevel") is not None:
        parts.append(f"SECLEVEL {ossl['seclevel']}")
    if isinstance(ossl, dict) and ossl.get("groups_configured"):
        parts.append("Groups " + ":".join(ossl["groups_configured"]))
    return ", ".join(parts) or "no OpenSSL settings"


def _render_text_crypto_config(cp: dict[str, object]) -> list[str]:
    """Ubuntu crypto-config (#170): the profile, what its OpenSSL snippet
    sets, and whether PQC key exchange is left to the library default."""
    en = cp.get("pqc_enabled") or {}
    tls = en.get("tls_key_exchange") if isinstance(en, dict) else None
    pqc = (
        "library default (profile sets no TLS groups)"
        if tls is None
        else ("yes" if tls else "no")
    )
    return [
        f"   Crypto policy: crypto-config profile {cp.get('active')}  ({_crypto_config_summary(cp)})",
        f"     PQC TLS kex: {pqc}",
    ]


def _render_text_crypto_policy(r: _report.Report) -> list[str]:
    """Section 3d: system-wide crypto policy and what it lets PQC do (#104)."""
    cp = r.crypto_policy
    if not cp.get("available"):
        return []
    if cp.get("framework") == "crypto-config":
        return _render_text_crypto_config(cp)
    state = "applied" if cp.get("applied") else "NOT applied"
    if cp.get("applied") is None:
        state = "applied: unknown"
    en = cp.get("pqc_enabled") or {}

    def yn(v: object) -> str:
        return "?" if v is None else ("yes" if v else "no")

    L = [
        f"   Crypto policy: {cp.get('active')} ({state})",
        "     PQC allowed: "
        f"TLS kex {yn(en.get('tls_key_exchange'))}, "
        f"TLS sig {yn(en.get('tls_signatures'))}, "
        f"SSH kex {yn(en.get('ssh_key_exchange_server'))}, "
        f"IKE {yn(en.get('ike_key_exchange'))}",
    ]
    if cp.get("pq_disabled_by_subpolicy"):
        L.append(
            C.wrap(
                C.YELLOW,
                f"     ⚠  PQC removed by subpolicy: {', '.join(cp['pq_disabled_by_subpolicy'])}",
            )
        )
    if _config_policy.policy_blocks_capable_pqc(cp, r.openssl):
        L.append(
            C.wrap(
                C.YELLOW,
                "     ⚠  OpenSSL supports PQC TLS groups but the policy keeps them out",
            )
        )
    return L


def _render_text_os_crypto(r: _report.Report) -> list[str]:
    """Section 3: OS crypto plumbing. Composite of kernel/proc-crypto, FIPS,
    and SSH/IPsec/NSS sub-blocks under a single bold heading."""
    L: list[str] = [C.wrap(C.BOLD, "3. Operating-system crypto plumbing")]
    L.extend(_render_text_kernel_crypto(r))
    L.extend(_render_text_fips(r))
    L.extend(_render_text_ssh_ipsec_nss(r))
    L.extend(_render_text_crypto_policy(r))
    L.append("")
    return L


def _render_text_openssl_tls_groups(tls_groups: dict[str, Any]) -> list[str]:
    """Section 4 sub-block: TLS PQC group lines (hybrid / pure / classical)."""
    hybrid = tls_groups.get("hybrid") or []
    pure = tls_groups.get("pure_pqc") or []
    classical = tls_groups.get("classical") or []
    L: list[str] = []
    if not (hybrid or pure):
        L.append("   TLS PQC groups: not exposed")
    else:
        L.append(
            f"   TLS PQC groups (hybrid): {', '.join(hybrid) if hybrid else 'none'}"
        )
        L.append(f"   TLS PQC groups (pure):   {', '.join(pure) if pure else 'none'}")
    if classical:
        L.append(f"   TLS classical groups:    {len(classical)} detected")
    return L


def _render_text_openssl(r: _report.Report) -> list[str]:
    """Section 4: OpenSSL PQC capability (version, KEMs, sigs, TLS groups)."""
    L: list[str] = [C.wrap(C.BOLD, "4. PQC library capability (OpenSSL)")]
    if not r.openssl.get("available"):
        L.append(f"   {r.openssl.get('reason', 'unknown')}")
    else:
        L.append(f"   Version:       {r.openssl.get('version')}")
        L.append(
            f"   PQC native:    {'yes (>=3.5)' if r.openssl.get('pqc_native') else 'no'}"
        )
        kems = r.openssl.get("kem_algorithms") or []
        sigs = r.openssl.get("sig_algorithms") or []
        L.append(f"   ML-KEM:        {', '.join(kems) if kems else 'not exposed'}")
        L.append(f"   PQC sigs:      {', '.join(sigs) if sigs else 'not exposed'}")
        L.extend(_render_text_openssl_tls_groups(r.openssl.get("tls_groups") or {}))
        cfg = r.openssl.get("config") or {}
        if cfg.get("available"):
            src = cfg.get("default_groups_source")
            pqc = "yes" if cfg.get("pqc_key_exchange_by_default") else "no"
            L.append(f"   Config:        {cfg.get('path')} (default groups from {src})")
            L.append(f"   PQC kex by default: {pqc}")
        tp = [p.get("name") for p in r.openssl.get("third_party_providers") or []]
        if tp:
            L.append(f"   3rd-party providers: {', '.join(str(n) for n in tp)}")
    L.append("")
    return L


def _render_text_pqc_sizes(r: _report.Report) -> list[str]:
    """Section 5: NIST PQC parameter sizes (bytes) per algorithm."""
    L: list[str] = [C.wrap(C.BOLD, "5. NIST PQC parameter sizes (bytes)")]
    for name, sz in r.pqc_sizes.items():
        role = sz.get("role", "")
        nums = " ".join(f"{k}={v}" for k, v in sz.items() if k != "role")
        L.append(f"   {name:<20} {role:<18} {nums}")
    L.append("")
    return L


def _render_text_benchmark(r: _report.Report) -> list[str]:
    """Section 6: PQC microbenchmark — emitted only when r.benchmark is set."""
    if not r.benchmark:
        return []
    L: list[str] = [C.wrap(C.BOLD, "6. Microbenchmark")]
    if not r.benchmark.get("available"):
        L.append(f"   unavailable: {r.benchmark.get('reason', 'unknown')}")
    else:
        L.append(
            f"   engine: {r.benchmark['engine']}, {r.benchmark['seconds_per_test']}s per test, "
            f"{r.benchmark.get('threads', 1)} thread(s)"
        )
        for algo, data in (r.benchmark.get("pqc") or {}).items():
            L.append(f"   {algo}:")
            for k, v in data.items():
                if isinstance(v, dict):
                    agg = ", ".join(f"{kk}={vv:.1f}" for kk, vv in v.items())
                    L.append(f"     {k}: {agg}")
                elif isinstance(v, (int, float)):
                    L.append(f"     {k:<12} {v:>12.1f}")
                else:
                    L.append(f"     {k}: {v}")
        classical = r.benchmark.get("classical") or {}
        if classical:
            L.append("   Classical baseline (per-core):")
            for name, rates in classical.items():
                s = ", ".join(f"{k}={v:.1f}" for k, v in rates.items())
                L.append(f"     {name:<10} {s}")
    L.append("")
    return L


def _render_text_tls_handshake(r: _report.Report) -> list[str]:
    """Section 6b: TLS-handshake benchmark (loopback). Conditional on
    r.benchmark_tls_handshake."""
    if not r.benchmark_tls_handshake:
        return []
    b = r.benchmark_tls_handshake
    L: list[str] = [C.wrap(C.BOLD, "6b. TLS handshake benchmark (loopback)")]
    if not b.get("available"):
        L.append(f"   unavailable: {b.get('reason', 'unknown')}")
    else:
        L.append(
            f"   engine: {b.get('engine')}, transport: {b.get('transport')}, "
            f"{b.get('iterations_per_suite')} handshakes/suite"
        )
        for s in b.get("suites") or []:
            if "error" in s:
                L.append(
                    f"   {s.get('label', s.get('role', '?')):<32} error: {s['error']}"
                )
                continue
            if s.get("skipped"):
                L.append(f"   {s.get('label', '?'):<32} skipped: {s.get('reason', '')}")
                continue
            hps = s.get("handshakes_per_sec")
            ttfb = s.get("ttfb_ms_median")
            bw = s.get("bytes_on_wire_per_handshake")
            L.append(
                f"   {s.get('label', '?'):<32} "
                f"{hps:>7.1f} hs/s  "
                f"ttfb={ttfb:>6.2f} ms  "
                f"wire={bw if bw is not None else '?'} B"
            )
    L.append("")
    return L


def _render_text_per_algo(r: _report.Report) -> list[str]:
    """Section 7: Per-algorithm production verdict, conditional on r.per_algo."""
    if not r.per_algo:
        return []
    L: list[str] = [C.wrap(C.BOLD, "7. Per-algorithm production verdict")]
    for key, v in r.per_algo.items():
        tier_s = _tier_label(v["tier"])
        extra = ""
        if "rate_per_core" in v:
            extra = f" - {v['rate_per_core']:.1f} {v['metric']}/core, ~{v['rate_host_estimate']:.0f} host"
        L.append(f"   {key:<22} {tier_s:<14}{extra}")
        L.append(f"     {v.get('reason', '')}")
        for note in v.get("notes", []):
            L.append(C.wrap(C.YELLOW, f"     note: {note}"))
    L.append("")
    return L


def _render_text_production_estimate(r: _report.Report) -> list[str]:
    """Section 8: production capacity estimate (60% CPU headroom),
    conditional on r.production_estimate."""
    if not r.production_estimate:
        return []
    L: list[str] = [
        C.wrap(C.BOLD, "8. Production capacity estimate (60% CPU headroom)")
    ]
    e = r.production_estimate
    if "tls_pqc_handshakes_per_sec" in e:
        L.append(
            f"   TLS-PQC handshakes/sec:           ~{e['tls_pqc_handshakes_per_sec']:,}"
        )
    if "ml_dsa_signatures_per_sec" in e:
        L.append(
            f"   ML-DSA-65 signatures/sec:         ~{e['ml_dsa_signatures_per_sec']:,}"
        )
    if "slh_dsa_sha2_128s_signatures_per_sec" in e:
        L.append(
            f"   SLH-DSA-SHA2-128s signatures/sec: ~{e['slh_dsa_sha2_128s_signatures_per_sec']}"
        )
    if "concurrent_connections_realistic" in e:
        L.append(
            f"   Concurrent conns (realistic):     ~{e['concurrent_connections_realistic']:,}  (192 KB/conn)"
        )
    if "concurrent_connections_theoretical_max" in e:
        L.append(
            f"   Concurrent conns (theoretical):   ~{e['concurrent_connections_theoretical_max']:,}  (32 KB/conn)"
        )
    if "assumptions" in e:
        L.append(f"   ({e['assumptions']})")
    L.append("")
    return L


def _render_text_cnsa_2_0(r: _report.Report) -> list[str]:
    """Section 10: CNSA 2.0 compliance, conditional on r.cnsa_2_0 being set."""
    if not r.cnsa_2_0:
        return []
    L: list[str] = [
        C.wrap(C.BOLD, "10. CNSA 2.0 compliance (NSA national security suite)")
    ]
    status = r.cnsa_2_0.get("status", "unknown")
    status_color = {
        "compliant": C.GREEN,
        "partial": C.YELLOW,
        "non_compliant": C.RED,
        "unknown": C.DIM,
    }.get(status, C.DIM)
    L.append(f"   Status:                 {C.wrap(status_color, status.upper())}")
    L.append(
        f"   ML-KEM-1024 (KEM):      {'yes' if r.cnsa_2_0.get('kem_compliant') else 'no'}"
    )
    L.append(
        f"   ML-DSA-87  (signature): {'yes' if r.cnsa_2_0.get('signature_compliant') else 'no'}"
    )
    L.append(
        f"   AES-256    (symmetric): {'yes' if r.cnsa_2_0.get('symmetric_compliant') else 'no'}"
    )
    L.append(
        f"   SHA-384/512 (hash, hw): {'yes' if r.cnsa_2_0.get('hash_compliant') else 'no'}"
    )
    for note in r.cnsa_2_0.get("notes") or []:
        L.append(C.wrap(C.YELLOW, f"   note: {note}"))
    L.append("")
    return L


def _render_text_trust_store(r: _report.Report) -> list[str]:
    """Section 9: trust store inventory, conditional on the trust-store
    scanner having run successfully (r.trust_store['available'])."""
    if not r.trust_store.get("available"):
        return []
    L: list[str] = [C.wrap(C.BOLD, "9. Trust store inventory")]
    L.append(f"   Scanned dirs:     {', '.join(r.trust_store.get('scanned_dirs', []))}")
    L.append(f"   Total certs:      {r.trust_store.get('total_certs', 0)}")
    if r.trust_store.get("truncated"):
        L.append(
            "   "
            + C.wrap(
                C.YELLOW,
                f"Truncated:        scanned {r.trust_store.get('scanned_count')} of "
                f"{r.trust_store.get('total_found')} certificates "
                "(raise with --trust-store-max-certs)",
            )
        )
    L.append(f"   PQC certs:        {r.trust_store.get('pqc_certs', 0)}")
    L.append(f"   Hybrid certs:     {r.trust_store.get('hybrid_certs', 0)}")
    cats = r.trust_store.get("cert_categories") or {}
    if cats:
        L.append(
            "   Categories:       "
            f"classical={cats.get('classical', 0)}, "
            f"hybrid_composite={cats.get('hybrid_composite', 0)}, "
            f"pure_pqc={cats.get('pure_pqc', 0)}"
        )
    L.append("")
    return L


def _render_text_verdict(r: _report.Report) -> list[str]:
    """Trailing verdict block: bracketed by horizontal rules with the
    overall verdict, reason, and optional caveat."""
    sub = "-" * 76
    L: list[str] = [
        sub,
        f"  VERDICT: {C.wrap(C.BOLD, r.verdict)}",
        f"           {r.verdict_reason}",
    ]
    if r.verdict_caveat:
        L.append(C.wrap(C.YELLOW, f"  CAVEAT:  {r.verdict_caveat}"))
    L.append(sub)
    return L


def _render_text_pqc_failures(r: _report.Report) -> list[str]:
    """Software that will fail at PQC (#193): the per-service / library /
    connection findings, so they are visible without a SARIF viewer."""
    from . import sarif as _sarif  # deferred: sarif imports detection modules

    found = _sarif.pqc_failure_findings(r)
    if not found:
        return []
    fails = [f for f in found if f.rule_id != _sarif._UNDETERMINED]
    unknown = [f for f in found if f.rule_id == _sarif._UNDETERMINED]
    L: list[str] = [C.wrap(C.BOLD, "Will fail at PQC")]
    for f in fails:
        rule = f.rule_id.split("-", 2)
        L.append(C.wrap(C.YELLOW, f"   [{rule[0]}-{rule[1]}] {f.message}"))
    if unknown:
        L.append(
            C.wrap(C.DIM, f"   Could not determine ({len(unknown)}; verify by hand):")
        )
        for f in unknown:
            L.append(C.wrap(C.DIM, f"     - {f.message}"))
    L.append("")
    return L


def _render_text_signing_keys(r: _report.Report) -> list[str]:
    """Package-signing trust anchors (--scan-signing-keys, #153)."""
    sk = r.signing_keys
    if not sk.get("available"):
        return []
    summary = sk.get("summary") or {}
    L: list[str] = [C.wrap(C.BOLD, "11. Package-signing keys")]
    L.append(
        f"   Trusted keys:     {summary.get('total', 0)} "
        f"(classical={summary.get('classical', 0)}, hybrid={summary.get('hybrid', 0)}, "
        f"pure_pqc={summary.get('pure_pqc', 0)})"
    )
    for key in sk.get("keys") or []:
        size = key.get("bits") or key.get("curve") or ""
        uid = key.get("uid") or ""
        L.append(
            f"   {str(key.get('key_id') or '-'):<18} {key.get('algorithm', '?')} "
            f"{size} [{key.get('signing_pqc_category')}] {uid}".rstrip()
        )
    errors = [src for src in sk.get("sources") or [] if src.get("error")]
    for src in errors:
        L.append(
            C.wrap(C.YELLOW, f"   Unreadable:       {src['source']} ({src['error']})")
        )
    if summary.get("all_classical"):
        L.append(
            C.wrap(
                C.YELLOW,
                "   All trusted signing keys are classical (no ML-DSA / SLH-DSA).",
            )
        )
    L.append("")
    return L


def _render_text_boot_chain(r: _report.Report) -> list[str]:
    """Secure Boot, module signing, IMA and TPM (--scan-boot-chain, #112)."""
    bc = r.boot_chain
    if not bc:
        return []
    L: list[str] = [C.wrap(C.BOLD, "14. Boot chain")]
    if not bc.get("available"):
        L += [f"   Unavailable: {bc.get('reason')}", ""]
        return L
    sb = bc.get("secure_boot") or {}
    if sb.get("available"):
        state = {True: "enabled", False: "disabled", None: "unknown"}[sb.get("enabled")]
        L.append(f"   Secure Boot:      {state} (setup mode: {sb.get('setup_mode')})")
        for key, db in (sb.get("databases") or {}).items():
            if not db.get("present"):
                continue
            certs = db.get("certificates") or []
            algos = sorted(
                {
                    f"{c.get('key_algorithm')} {c.get('key_size') or ''}".strip()
                    for c in certs
                }
            )
            L.append(
                f"   {key:<9} {len(certs)} cert(s), {db.get('sha256_hashes', 0)} hash(es)"
                + (f": {', '.join(algos)}" if algos else "")
            )
    else:
        L.append(f"   Secure Boot:      {sb.get('reason')}")
    mod = bc.get("module_signing") or {}
    sample = mod.get("sample_module") or {}
    if sample.get("parsed"):
        size = f"-{sample['key_size']}" if sample.get("key_size") else ""
        L.append(
            f"   Module signing:   {sample.get('signature_algorithm')}{size} / "
            f"{sample.get('digest_algorithm')} ({sample.get('signer')})"
        )
    elif mod.get("key_types_configured"):
        L.append(
            f"   Module signing:   {'/'.join(mod['key_types_configured'])} (kernel config)"
        )
    ima = bc.get("ima_evm") or {}
    ima_algos = sorted(
        {str(c.get("key_algorithm")) for c in ima.get("certificates") or []}
    )
    if ima_algos:
        L.append(f"   IMA certificates: {', '.join(ima_algos)}")
    if bc.get("lockdown"):
        L.append(f"   Lockdown:         {bc['lockdown']}")
    tpm = bc.get("tpm") or {}
    if tpm.get("queried"):
        L.append(
            f"   TPM:              spec {tpm.get('spec_revision')}, PQC algorithms: "
            + (", ".join(tpm.get("pqc_algorithms") or []) or "none")
        )
    elif tpm.get("present"):
        L.append(f"   TPM:              not queried ({tpm.get('reason')})")
    for line in _boot.describe_classical_layers(bc):
        L.append(C.wrap(C.YELLOW, f"   Classical: {line}."))
    L.append("")
    return L


def _render_text_kerberos(r: _report.Report) -> list[str]:
    """Kerberos enctypes and PKINIT (--scan-kerberos, #109)."""
    kb = r.kerberos
    if not kb:
        return []
    L: list[str] = [C.wrap(C.BOLD, "15. Kerberos")]
    if not kb.get("available"):
        L += [f"   Unavailable: {kb.get('reason')}", ""]
        return L
    cfg = kb.get("config") or {}
    permitted = (cfg.get("enctype_lists") or {}).get("permitted_enctypes") or {}
    L.append(
        f"   permitted_enctypes ({permitted.get('source')}): "
        + ", ".join(permitted.get("enctypes") or [])
    )
    for kt in kb.get("keytabs") or []:
        if kt.get("parsed"):
            counts = ", ".join(
                f"{n} x{c}" for n, c in sorted((kt.get("enctypes") or {}).items())
            )
            L.append(
                f"   Keytab {kt['path']}: {len(kt.get('entries') or [])} keys ({counts})"
            )
        else:
            L.append(f"   Keytab {kt['path']}: {kt.get('reason')}")
    pk = cfg.get("pkinit") or {}
    if pk.get("identity_configured"):
        ident = pk.get("identity") or {}
        L.append(
            "   PKINIT identity: "
            + (
                ", ".join(ident.get("key_algorithms") or [])
                or str(ident.get("store") or "?")
            )
        )
    level, parts = _kerberos.describe_findings(kb)
    for part in parts:
        L.append(C.wrap(C.YELLOW, f"   {part[0].upper() + part[1:]}."))
    L.append("")
    return L


def _offline_na_sections(r: _report.Report) -> str:
    """Human-readable list of what an offline --root scan cannot answer."""
    return (
        "CPU / ISA tier, memory, accelerators / HSMs / TPM, kernel, /proc/crypto, "
        "kTLS, FIPS mode, running services, OpenSSL / SSH / IPsec capability "
        "probes, CNSA 2.0 evaluation, benchmarks and the readiness tier"
    )


def _render_text_offline_openssl(r: _report.Report) -> list[str]:
    """OpenSSL as packaged in the tree (no binary is run, #152)."""
    o = r.openssl
    pkg = o.get("package") or {}
    native = o.get("pqc_native_expected")
    L = [C.wrap(C.BOLD, "OpenSSL in the tree")]
    if pkg:
        L.append(f"   Package:       {pkg.get('name')} {pkg.get('version')}")
    else:
        L.append("   Package:       no OpenSSL library package found in the tree")
    L.append(
        "   PQC-capable version (>=3.5): "
        + ("unknown" if native is None else ("yes" if native else "no"))
    )
    cfg = o.get("config") or {}
    if cfg.get("available"):
        pqc = "yes" if cfg.get("pqc_key_exchange_by_default") else "no"
        L.append(
            f"   Config:        {cfg.get('path')} (default groups from "
            f"{cfg.get('default_groups_source')})"
        )
        L.append(f"   PQC kex by default: {pqc}")
    elif cfg:
        L.append(f"   Config:        {cfg.get('reason', 'not found')}")
    L.append("")
    return L


_GAP_LABELS = {
    "deployed": "deployed",
    "capable_not_configured": "capable, NOT configured",
    "configured_not_capable": "configured, NOT capable",
    "not_capable": "not capable",
    "unknown": "unknown",
    "not_present": "not present",
}


def _render_text_deployment_gap(r: _report.Report) -> list[str]:
    """Capability vs configuration per protocol and service (#107)."""
    g = r.pqc_deployment_gap or {}
    protocols = g.get("protocols") or {}
    if not protocols:
        return []
    L: list[str] = [C.wrap(C.BOLD, "PQC deployment gap (capable vs configured)")]
    for name in ("tls", "ssh", "ipsec"):
        v = protocols.get(name) or {}
        state = str(v.get("state", "unknown"))
        line = f"   {name.upper():<6} {_GAP_LABELS.get(state, state)}"
        if v.get("note"):
            line += f"  ({v['note']})"
        L.append(line)
    services = g.get("services") or {}
    for svc in services.get("items") or []:
        if svc.get("follows_host_default"):
            continue
        state = str(svc.get("state", "unknown"))
        fams = ",".join(svc.get("crypto_families") or [])
        L.append(
            f"   {str(svc.get('process')):<14} {svc.get('protocol')}/{svc.get('port'):<6} "
            f"[{fams}] {_GAP_LABELS.get(state, state)}"
        )
    same = sum(
        1 for svc in services.get("items") or [] if svc.get("follows_host_default")
    )
    if same:
        L.append(f"   ({same} more service(s) follow the host defaults above)")
    L.append("")
    return L


def _render_text_crypto_libraries(r: _report.Report) -> list[str]:
    """Crypto libraries besides OpenSSL / NSS (--scan-crypto-libraries, #110)."""
    cl = r.crypto_libraries
    if not cl.get("available"):
        return []
    L: list[str] = [C.wrap(C.BOLD, "12. Other crypto libraries")]
    for name, lib in (cl.get("libraries") or {}).items():
        if not lib.get("installed"):
            continue
        state = {True: "PQC", False: "classical only", None: "unknown"}[
            lib.get("pqc_capable")
        ]
        algos = sorted(
            {a for names in (lib.get("algorithms") or {}).values() for a in names}
        )
        if lib.get("installs"):
            versions = ", ".join(str(i.get("version")) for i in lib["installs"])
        else:
            versions = str(lib.get("version") or "?")
        line = f"   {name:<10} {versions:<16} [{state}, {lib.get('evidence')}]"
        if algos:
            line += " " + ", ".join(algos)
        L.append(line)
    L.append("")
    return L


def _render_text_processes(r: _report.Report) -> list[str]:
    """Processes -> crypto library (--scan-processes, #155).  Lists the
    groups that cannot do PQC first; capable groups are summarised."""
    pc = r.process_crypto_linkage
    if not pc.get("available"):
        return []
    s = pc.get("summary") or {}
    L: list[str] = [C.wrap(C.BOLD, "13. Processes using crypto")]
    L.append(
        f"   {s.get('processes_with_crypto', 0)} process(es) in "
        f"{s.get('groups', 0)} group(s); not PQC-capable: "
        f"{s.get('processes_not_pqc_capable', 0)} "
        f"(outbound-only clients: {s.get('client_processes_not_pqc_capable', 0)})"
    )
    for g in pc.get("groups") or []:
        if g.get("pqc_capable") is not False:
            continue
        libs = ", ".join(
            f"{lib.get('family')} {lib.get('version') or '?'}"
            for lib in g.get("crypto_libraries") or []
        )
        go = g.get("go")
        if go:
            libs = ", ".join(x for x in (libs, f"Go {go.get('go_version')}") if x)
        roles = g.get("roles") or {}
        role = "/".join(k for k in ("server", "client", "idle") if roles.get(k))
        L.append(
            f"   {C.wrap(C.RED, 'no PQC')}  {g.get('exe') or g.get('process')} "
            f"x{g.get('process_count')} [{role}]  {libs}"
        )
    if pc.get("note"):
        L.append(C.wrap(C.DIM, f"   {pc['note']}"))
    L.append("")
    return L


def render_text_offline(r: _report.Report) -> str:
    """Text report for --root PATH (#152): only what the tree answers, plus
    an explicit list of sections that are not applicable."""
    bar = "=" * 76
    mode = r.scan_mode or {}
    L: list[str] = [
        C.wrap(C.BOLD, bar),
        C.wrap(C.BOLD, "  Post-Quantum Cryptography Readiness Report (offline tree)"),
        C.wrap(C.BOLD, bar),
        f"  Tree:          {mode.get('root', '?')}",
        f"  OS / arch:     {r.os}, {r.arch}",
    ]
    if r.hostname:
        L.append(f"  Hostname:      {r.hostname}  (from the tree's /etc/hostname)")
    L.append(f"  Generated:     {r.generated_at}")
    L.append(C.wrap(C.DIM, f"  Not applicable offline: {_offline_na_sections(r)}."))
    L.append("")
    plumbing = _render_text_crypto_policy(r) + _render_text_ssh_ipsec_nss(r)
    if plumbing:
        L.append(C.wrap(C.BOLD, "Crypto configuration in the tree"))
        L.extend(plumbing)
        L.append("")
    L.extend(_render_text_offline_openssl(r))
    L.extend(_render_text_trust_store(r))
    L.extend(_render_text_signing_keys(r))
    L.extend(_render_text_crypto_libraries(r))
    L.extend(_render_text_pqc_failures(r))
    L.extend(_render_text_verdict(r))
    # Reused live sections carry live numbering ("9.", "11."); offline
    # headings are unnumbered.
    return "\n".join(re.sub(r"^((?:\x1b\[[0-9;]*m)?)\d+\. ", r"\1", line) for line in L)


def render_markdown_offline(r: _report.Report) -> str:
    """Markdown report for --root PATH (#152)."""
    mode = r.scan_mode or {}
    o = r.openssl
    pkg = o.get("package") or {}
    native = o.get("pqc_native_expected")
    L = [
        f"# PQC Readiness — offline tree `{mode.get('root', '?')}`",
        "",
        f"_Generated {r.generated_at}_",
        "",
        f"**Verdict:** {r.verdict}",
        "",
        f"> {r.verdict_reason}",
        "",
        "## Tree",
        f"- OS / arch: `{r.os}` / `{r.arch}`",
    ]
    if r.hostname:
        L.append(f"- Hostname (from /etc/hostname): `{r.hostname}`")
    L.append(f"- **Not applicable offline:** {_offline_na_sections(r)}")
    L.append("")
    L.append("## OpenSSL in the tree")
    L.append(
        f"- Package: `{pkg.get('name')} {pkg.get('version')}`"
        if pkg
        else "- Package: _no OpenSSL library package found_"
    )
    L.append(
        "- PQC-capable version (>=3.5): "
        + ("unknown" if native is None else ("yes" if native else "**no**"))
    )
    cfg = o.get("config") or {}
    if cfg.get("available"):
        L.append(
            f"- Config: `{cfg.get('path')}`; PQC key exchange by default: "
            f"{'yes' if cfg.get('pqc_key_exchange_by_default') else '**no**'}"
        )
    L.append("")
    cp = r.crypto_policy
    if cp.get("available"):
        en = cp.get("pqc_enabled") or {}
        L.append("## System crypto policy")
        L.append(f"- Active: `{cp.get('active')}`")
        L.append(
            "- PQC allowed: "
            + ", ".join(
                f"{label} {'unknown' if en.get(k) is None else ('yes' if en.get(k) else '**no**')}"
                for k, label in (
                    ("tls_key_exchange", "TLS key exchange"),
                    ("tls_signatures", "TLS signatures"),
                    ("ssh_key_exchange_server", "SSH key exchange"),
                    ("ike_key_exchange", "IKE"),
                )
            )
        )
        L.append("")
    ts = r.trust_store
    if ts.get("available"):
        cats = ts.get("cert_categories") or {}
        L.append("## Trust store")
        L.append(
            f"- Certificates: {ts.get('total_certs')} "
            f"(classical {cats.get('classical', 0)}, hybrid/composite "
            f"{cats.get('hybrid_composite', 0)}, pure PQC {cats.get('pure_pqc', 0)})"
        )
        L.append("")
    sk = r.signing_keys
    if sk.get("available"):
        L.append("## Package-signing keys")
        sm = sk.get("summary") or {}
        L.append(
            f"- Trusted keys: {sm.get('total', 0)} (classical {sm.get('classical', 0)}, "
            f"hybrid {sm.get('hybrid', 0)}, pure PQC {sm.get('pure_pqc', 0)})"
        )
        L.append("")
    return "\n".join(L)


def render_text(r: _report.Report) -> str:
    """Render the full report as plain text (color-aware via the module-
    level C). Composes per-section helpers in numbered order; each helper
    returns the lines it owns, including the trailing blank-line spacer."""
    if r.scan_mode:
        return render_text_offline(r)
    L: list[str] = []
    L.extend(_render_text_header(r))
    L.extend(_render_text_isa(r))
    L.extend(_render_text_accelerators(r))
    L.extend(_render_text_os_crypto(r))
    L.extend(_render_text_openssl(r))
    L.extend(_render_text_pqc_sizes(r))
    L.extend(_render_text_benchmark(r))
    L.extend(_render_text_tls_handshake(r))
    L.extend(_render_text_per_algo(r))
    L.extend(_render_text_production_estimate(r))
    L.extend(_render_text_trust_store(r))
    L.extend(_render_text_cnsa_2_0(r))
    L.extend(_render_text_signing_keys(r))
    L.extend(_render_text_crypto_libraries(r))
    L.extend(_render_text_processes(r))
    L.extend(_render_text_boot_chain(r))
    L.extend(_render_text_kerberos(r))
    L.extend(_render_text_pqc_failures(r))
    L.extend(_render_text_deployment_gap(r))
    L.extend(_render_text_verdict(r))
    return "\n".join(L)


def render_markdown(r: _report.Report) -> str:
    if r.scan_mode:
        return render_markdown_offline(r)
    L: list[str] = []
    L.append(f"# PQC Readiness — {r.hostname}")
    L.append("")
    L.append(f"_Generated {r.generated_at}_")
    L.append("")
    L.append(f"**Verdict:** {r.verdict}")
    L.append("")
    L.append(f"> {r.verdict_reason}")
    L.append("")
    L.append("## Host")
    L.append(f"- OS / arch: `{r.os}` / `{r.arch}`")
    L.append(f"- CPU: {r.cpu_model}")
    L.append(f"- Cores: {r.cores_physical} physical / {r.cores_logical} logical")
    L.append(f"- Memory: {r.mem_total_gb:.1f} GiB total")
    if r.memory_bandwidth_gb_s is not None:
        L.append(f"- Memory bandwidth (rough probe): ~{r.memory_bandwidth_gb_s} GB/s")
    L.append("")
    L.append(f"## ISA tier: **{r.isa_tier.upper()}** (score {r.isa_score})")
    L.append(f"_{r.isa_reason}_")
    L.append("")
    if r.isa_features:
        L.append("| Flag | Purpose |")
        L.append("|------|---------|")
        for _, info in sorted(r.isa_features.items()):
            L.append(f"| `{info['name']}` | {info['purpose']} |")
        L.append("")
    L.append("## Accelerators")
    if r.accelerators:
        for a in r.accelerators:
            L.append(f"- **[{a['kind']}]** {a['name']} — `{a['detail']}`")
    else:
        L.append("- _none detected_")
    L.append("")
    if r.openssl.get("available"):
        L.append("## OpenSSL PQC capability")
        L.append(f"- Version: `{r.openssl.get('version')}`")
        L.append(
            f"- KEM algorithms: {', '.join(r.openssl.get('kem_algorithms') or []) or '_none_'}"
        )
        L.append(
            f"- Signature algorithms: {', '.join(r.openssl.get('sig_algorithms') or []) or '_none_'}"
        )
        tg_md = r.openssl.get("tls_groups") or {}
        hybrid_md = tg_md.get("hybrid") or []
        pure_md = tg_md.get("pure_pqc") or []
        L.append(f"- TLS 1.3 hybrid groups: {', '.join(hybrid_md) or '_none_'}")
        L.append(f"- TLS 1.3 pure PQC groups: {', '.join(pure_md) or '_none_'}")
        L.append("")
    cp = r.crypto_policy
    if cp.get("available"):
        en = cp.get("pqc_enabled") or {}

        def md_yn(v: object) -> str:
            return "unknown" if v is None else ("yes" if v else "**no**")

        L.append("## System crypto policy")
        if cp.get("framework") == "crypto-config":
            L.append(
                f"- Active: crypto-config profile `{cp.get('active')}` "
                f"({_crypto_config_summary(cp)})"
            )
        else:
            L.append(
                f"- Active: `{cp.get('active')}` (configured `{cp.get('configured')}`)"
            )
        L.append(
            f"- PQC allowed: TLS key exchange {md_yn(en.get('tls_key_exchange'))}, "
            f"TLS signatures {md_yn(en.get('tls_signatures'))}, "
            f"SSH key exchange {md_yn(en.get('ssh_key_exchange_server'))}, "
            f"IKE {md_yn(en.get('ike_key_exchange'))}"
        )
        if _config_policy.policy_blocks_capable_pqc(cp, r.openssl):
            L.append(
                "- ⚠ OpenSSL supports PQC TLS groups but the active policy keeps them out"
            )
        L.append("")
    if r.per_algo:
        L.append("## Per-algorithm verdict")
        L.append("| Algorithm | Tier | Per-core | Host estimate | Metric |")
        L.append("|-----------|------|----------|---------------|--------|")
        for algo, v in r.per_algo.items():
            rc = f"{v.get('rate_per_core', '-')}"
            rh = f"{v.get('rate_host_estimate', '-')}"
            L.append(
                f"| {algo} | **{v['tier']}** | {rc} | {rh} | {v.get('metric', '-')} |"
            )
        L.append("")
    if r.production_estimate:
        e = r.production_estimate
        L.append("## Production capacity (60% headroom)")
        for k, v in e.items():
            L.append(f"- {k}: {v}")
        L.append("")
    if r.benchmark_tls_handshake and r.benchmark_tls_handshake.get("available"):
        b = r.benchmark_tls_handshake
        L.append("## TLS handshake benchmark (loopback)")
        L.append(
            f"_{b.get('iterations_per_suite')} handshakes per suite via "
            f"`{b.get('openssl_version', 'openssl')}`. "
            "ttfb includes s_client process startup._"
        )
        L.append("")
        L.append(
            "| Suite | Role | Handshakes/sec | TTFB median (ms) | Bytes on wire / handshake |"
        )
        L.append(
            "|-------|------|---------------:|-----------------:|--------------------------:|"
        )
        for s in b.get("suites") or []:
            if "error" in s:
                L.append(
                    f"| {s.get('label', '?')} | {s.get('role', '?')} | error | error | error |"
                )
                continue
            if s.get("skipped"):
                L.append(
                    f"| {s.get('label', '?')} | {s.get('role', '?')} | skipped | skipped | skipped |"
                )
                continue
            L.append(
                f"| {s.get('label', '?')} | {s.get('role', '?')} | "
                f"{s.get('handshakes_per_sec', '-')} | "
                f"{s.get('ttfb_ms_median', '-')} | "
                f"{s.get('bytes_on_wire_per_handshake', '-')} |"
            )
        L.append("")
    return "\n".join(L)


@_registry.register_arguments(11)
def add_format_arguments(ap: argparse.ArgumentParser) -> None:
    """--markdown."""
    ap.add_argument("--markdown", action="store_true", help="emit markdown")


@_registry.register_arguments(40)
def add_display_arguments(ap: argparse.ArgumentParser) -> None:
    """--quiet, --no-color."""
    ap.add_argument("--quiet", action="store_true", help="print only verdict line")
    ap.add_argument("--no-color", action="store_true", help="disable ANSI color")


_registry.register_output(
    _registry.OutputFormat("markdown", 40, lambda r: render_markdown(r))
)


_registry.register_output(
    _registry.OutputFormat("quiet", 50, lambda r: r.verdict, machine_readable=False)
)
