"""Human-readable text and markdown report renderers."""

from __future__ import annotations

import argparse
from typing import Any

from .. import report as _report
from .. import registry as _registry
from ..detect import config_policy as _config_policy


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
    if r.ipsec_pqc.get("available"):
        L.append(
            f"   strongSwan:    PQC support {'yes' if r.ipsec_pqc.get('pqc') else 'no'}"
        )
    if r.nss.get("available"):
        L.append(
            f"   NSS:           {r.nss.get('version')}  (PQC-capable: {r.nss.get('pqc_capable')})"
        )
    return L


def _render_text_crypto_policy(r: _report.Report) -> list[str]:
    """Section 3d: system-wide crypto policy and what it lets PQC do (#104)."""
    cp = r.crypto_policy
    if not cp.get("available"):
        return []
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


def render_text(r: _report.Report) -> str:
    """Render the full report as plain text (color-aware via the module-
    level C). Composes per-section helpers in numbered order; each helper
    returns the lines it owns, including the trailing blank-line spacer."""
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
    L.extend(_render_text_verdict(r))
    return "\n".join(L)


def render_markdown(r: _report.Report) -> str:
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
