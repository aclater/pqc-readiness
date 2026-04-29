# SPDX-License-Identifier: Apache-2.0
"""Per-section helper tests for `render_text`.

Audit option B1 split `render_text` into a flat top-level driver plus
one helper per numbered report section. The existing
`tests/test_render_text.py` covers `render_text` end-to-end (no `None`
leaks, all section headings present, partial-population tolerance).

This file complements that with one focused test per helper, so a
regression in (say) `_render_text_fips` surfaces as a tightly-scoped
failure rather than as a global golden-output diff. Helpers are
imported by name; the suite never reaches them through `getattr` or
reflection.
"""
from __future__ import annotations

import pqc_readiness as pr
from pqc_readiness import (
    _render_text_accelerators,
    _render_text_benchmark,
    _render_text_cnsa_2_0,
    _render_text_fips,
    _render_text_header,
    _render_text_isa,
    _render_text_kernel_crypto,
    _render_text_openssl,
    _render_text_openssl_tls_groups,
    _render_text_os_crypto,
    _render_text_per_algo,
    _render_text_pqc_sizes,
    _render_text_production_estimate,
    _render_text_ssh_ipsec_nss,
    _render_text_tls_handshake,
    _render_text_trust_store,
    _render_text_verdict,
)
from test_render_text import _make_full_coverage_report

# Color is module-level state; pin off so `C.wrap` is identity and the
# section-text assertions match the source strings verbatim.
pr.C.configure(False)


def test_header_includes_hostname_and_cpu() -> None:
    r = _make_full_coverage_report()
    out = "\n".join(_render_text_header(r))
    assert r.hostname in out
    assert r.cpu_model in out
    assert "Post-Quantum Cryptography Readiness Report" in out


def test_isa_emits_section_heading_and_features() -> None:
    r = _make_full_coverage_report()
    out = "\n".join(_render_text_isa(r))
    assert "1. CPU instruction-set support for PQC" in out
    # Features come from _make_report (AVX-512 IFMA / VBMI).
    assert "AVX-512 IFMA" in out


def test_isa_handles_empty_isa_features() -> None:
    r = pr.Report()
    out = "\n".join(_render_text_isa(r))
    assert "(no PQC-relevant ISA features detected)" in out


def test_accelerators_emits_heading_and_pkcs11_count() -> None:
    r = _make_full_coverage_report()
    out = "\n".join(_render_text_accelerators(r))
    assert "2. Cryptographic accelerators / HSMs / TPMs" in out
    assert "PKCS#11 modules installed: 1" in out


def test_accelerators_falls_back_when_none_detected() -> None:
    r = pr.Report()
    out = "\n".join(_render_text_accelerators(r))
    assert "none detected - host would do all PQC in CPU/memory" in out


def test_kernel_crypto_emits_distribution_and_kernel() -> None:
    r = _make_full_coverage_report()
    out = "\n".join(_render_text_kernel_crypto(r))
    assert "Distribution:" in out
    assert "Kernel:" in out
    # The fixture sets a single PQC driver; the joined line must include it.
    assert "ml-kem-768" in out


def test_fips_block_silent_when_fips_dict_empty() -> None:
    r = pr.Report()
    out = _render_text_fips(r)
    assert out == []


def test_fips_block_warns_on_conflict() -> None:
    r = _make_full_coverage_report()
    r.fips = {"kernel": True, "openssl_provider": True}
    r.fips_pqc_conflict = {"in_conflict": True, "explanation": "boom"}
    out = "\n".join(_render_text_fips(r))
    assert "FIPS mode:" in out
    assert "FIPS/PQC conflict" in out
    assert "boom" in out


def test_ssh_ipsec_nss_lists_pqc_kex_groups() -> None:
    r = _make_full_coverage_report()
    out = "\n".join(_render_text_ssh_ipsec_nss(r))
    assert "OpenSSH kex:" in out
    assert "mlkem768x25519-sha256" in out
    assert "strongSwan:" in out
    assert "NSS:" in out


def test_os_crypto_umbrella_emits_section_3_heading() -> None:
    r = _make_full_coverage_report()
    out = "\n".join(_render_text_os_crypto(r))
    assert "3. Operating-system crypto plumbing" in out


def test_openssl_emits_version_and_kem_list() -> None:
    r = _make_full_coverage_report()
    out = "\n".join(_render_text_openssl(r))
    assert "4. PQC library capability (OpenSSL)" in out
    assert "Version:" in out
    assert "ML-KEM-768" in out


def test_openssl_unavailable_renders_reason() -> None:
    r = _make_full_coverage_report()
    r.openssl = {"available": False, "reason": "openssl not installed"}
    out = "\n".join(_render_text_openssl(r))
    assert "openssl not installed" in out


def test_openssl_tls_groups_unexposed_when_no_pqc() -> None:
    out = _render_text_openssl_tls_groups({})
    assert "TLS PQC groups: not exposed" in out[0]


def test_openssl_tls_groups_split_hybrid_pure_classical() -> None:
    out = "\n".join(
        _render_text_openssl_tls_groups(
            {"hybrid": ["X25519MLKEM768"], "pure_pqc": ["MLKEM768"], "classical": ["X25519"]}
        )
    )
    assert "TLS PQC groups (hybrid):" in out
    assert "X25519MLKEM768" in out
    assert "TLS classical groups:" in out


def test_pqc_sizes_emits_each_algorithm_row() -> None:
    r = pr.Report()
    r.pqc_sizes = {"ML-KEM-768": {"role": "kem", "public_key": 1184}}
    out = "\n".join(_render_text_pqc_sizes(r))
    assert "5. NIST PQC parameter sizes (bytes)" in out
    assert "ML-KEM-768" in out
    assert "public_key=1184" in out


def test_benchmark_returns_empty_list_without_data() -> None:
    r = pr.Report()
    assert _render_text_benchmark(r) == []


def test_benchmark_emits_engine_and_pqc_rows() -> None:
    r = _make_full_coverage_report()
    out = "\n".join(_render_text_benchmark(r))
    assert "6. Microbenchmark" in out
    assert "engine: openssl" in out
    assert "ML-KEM-768:" in out


def test_tls_handshake_returns_empty_without_data() -> None:
    r = pr.Report()
    assert _render_text_tls_handshake(r) == []


def test_tls_handshake_emits_per_suite_rates() -> None:
    r = _make_full_coverage_report()
    out = "\n".join(_render_text_tls_handshake(r))
    assert "6b. TLS handshake benchmark (loopback)" in out
    assert "TLS_AES_128_GCM_SHA256" in out
    assert "hs/s" in out


def test_per_algo_returns_empty_without_data() -> None:
    r = pr.Report()
    assert _render_text_per_algo(r) == []


def test_per_algo_emits_tier_label_and_notes() -> None:
    r = _make_full_coverage_report()
    out = "\n".join(_render_text_per_algo(r))
    assert "7. Per-algorithm production verdict" in out
    assert "ml-kem-768" in out
    assert "informational note" in out


def test_production_estimate_returns_empty_without_data() -> None:
    r = pr.Report()
    assert _render_text_production_estimate(r) == []


def test_production_estimate_emits_thousands_separated() -> None:
    r = _make_full_coverage_report()
    out = "\n".join(_render_text_production_estimate(r))
    assert "8. Production capacity estimate (60% CPU headroom)" in out
    # Locale-independent comma grouping is enforced by the f-string.
    assert "~5,000" in out
    assert "60% CPU headroom" in out


def test_trust_store_returns_empty_when_unavailable() -> None:
    r = pr.Report()
    assert _render_text_trust_store(r) == []


def test_trust_store_emits_categories_when_present() -> None:
    r = _make_full_coverage_report()
    out = "\n".join(_render_text_trust_store(r))
    assert "9. Trust store inventory" in out
    assert "Categories:" in out
    assert "classical=142" in out


def test_cnsa_2_0_returns_empty_without_data() -> None:
    r = pr.Report()
    assert _render_text_cnsa_2_0(r) == []


def test_cnsa_2_0_emits_status_and_each_compliance_field() -> None:
    r = _make_full_coverage_report()
    out = "\n".join(_render_text_cnsa_2_0(r))
    assert "10. CNSA 2.0 compliance (NSA national security suite)" in out
    assert "ML-KEM-1024 (KEM):" in out
    assert "ML-DSA-87" in out
    assert "AES-256" in out
    assert "SHA-384/512" in out


def test_verdict_emits_two_horizontal_rules_and_caveat() -> None:
    r = _make_full_coverage_report()
    lines = _render_text_verdict(r)
    rule = "-" * 76
    assert lines[0] == rule
    assert lines[-1] == rule
    body = "\n".join(lines)
    assert "VERDICT:" in body
    assert r.verdict_reason in body
    assert "CAVEAT:" in body  # full-coverage fixture sets one


def test_verdict_skips_caveat_when_absent() -> None:
    r = pr.Report()
    out = "\n".join(_render_text_verdict(r))
    assert "CAVEAT" not in out
