# SPDX-License-Identifier: Apache-2.0
"""Tests for trust-store certificate categorisation.

Covers the IETF composite-signature OID detection added to support
classifying hybrid-composite certs separately from classical and pure
PQC certs (issue #10)."""

from __future__ import annotations

from pathlib import Path

import pqc_readiness as pr


# ---------------------------------------------------------------------------
# categorise_cert_dump — pure unit tests
# ---------------------------------------------------------------------------

CLASSICAL_DUMP = """\
Certificate:
    Data:
        Signature Algorithm: sha256WithRSAEncryption (1.2.840.113549.1.1.11)
        Issuer: CN=Example RSA CA
        Subject: CN=example.com
"""

PURE_PQC_DUMP = """\
Certificate:
    Data:
        Signature Algorithm: id-ml-dsa-65 (2.16.840.1.101.3.4.3.18)
        Issuer: CN=Example ML-DSA CA
        Subject: CN=pqc.example.com
"""

# Composite-ML-DSA-44-ECDSA-P256-SHA256 (1.3.6.1.5.5.7.6.40).
COMPOSITE_DUMP = """\
Certificate:
    Data:
        Signature Algorithm: id-MLDSA44-ECDSA-P256-SHA256 (1.3.6.1.5.5.7.6.40)
        Issuer: CN=Example Composite CA
        Subject: CN=hybrid.example.com
"""

# Composite cert dumps typically also reference the embedded ML-DSA OID
# (e.g. inside the SubjectPublicKeyInfo or the openssl debug output).
# The categoriser must still pick `hybrid_composite`, not `pure_pqc`.
COMPOSITE_DUMP_WITH_EMBEDDED_PQC = """\
Certificate:
    Data:
        Signature Algorithm: id-MLDSA65-Ed25519-SHA512 (1.3.6.1.5.5.7.6.48)
        Subject Public Key Info:
            Public Key Algorithm: composite (embeds 2.16.840.1.101.3.4.3.18)
"""


def test_categorise_classical() -> None:
    assert pr.categorise_cert_dump(CLASSICAL_DUMP) == "classical"


def test_categorise_pure_pqc_ml_dsa() -> None:
    assert pr.categorise_cert_dump(PURE_PQC_DUMP) == "pure_pqc"


def test_categorise_pure_pqc_slh_dsa() -> None:
    # SLH-DSA-SHAKE-256s OID 2.16.840.1.101.3.4.3.31 — top of the NIST PQC range.
    dump = "Signature Algorithm: id-slh-dsa-shake-256s (2.16.840.1.101.3.4.3.31)"
    assert pr.categorise_cert_dump(dump) == "pure_pqc"


def test_categorise_composite_low_oid() -> None:
    # Lowest assigned composite OID (.37 — id-MLDSA44-RSA2048-PSS-SHA256).
    dump = "Signature Algorithm: id-MLDSA44-RSA2048-PSS-SHA256 (1.3.6.1.5.5.7.6.37)"
    assert pr.categorise_cert_dump(dump) == "hybrid_composite"


def test_categorise_composite_high_oid() -> None:
    # Highest assigned composite OID (.54 — id-MLDSA87-ECDSA-P521-SHA512).
    dump = "Signature Algorithm: id-MLDSA87-ECDSA-P521-SHA512 (1.3.6.1.5.5.7.6.54)"
    assert pr.categorise_cert_dump(dump) == "hybrid_composite"


def test_categorise_composite() -> None:
    assert pr.categorise_cert_dump(COMPOSITE_DUMP) == "hybrid_composite"


def test_categorise_composite_takes_precedence_over_pure_pqc() -> None:
    # A composite cert dump that also mentions the embedded PQC OID must
    # categorise as composite, not pure PQC — composite is the more
    # specific (and correct) IETF category.
    assert (
        pr.categorise_cert_dump(COMPOSITE_DUMP_WITH_EMBEDDED_PQC) == "hybrid_composite"
    )


def test_oid_outside_composite_range_is_classical() -> None:
    # Adjacent IANA SMI OIDs (e.g. .36 just below the composite range and
    # .55 just above) must NOT match — they aren't composite signatures.
    below = "Signature Algorithm: id-something (1.3.6.1.5.5.7.6.36)"
    above = "Signature Algorithm: id-something (1.3.6.1.5.5.7.6.55)"
    assert pr.categorise_cert_dump(below) == "classical"
    assert pr.categorise_cert_dump(above) == "classical"


def test_composite_oid_with_trailing_digit_does_not_falsely_match() -> None:
    # Word-boundary anchor must reject e.g. `1.3.6.1.5.5.7.6.374` —
    # the trailing `4` extends the leaf and the OID is not composite.
    dump = "Signature Algorithm: id-something (1.3.6.1.5.5.7.6.374)"
    assert pr.categorise_cert_dump(dump) == "classical"


# ---------------------------------------------------------------------------
# scan_trust_store integration — categorises real certs read via openssl
# ---------------------------------------------------------------------------


def _write_pem(path: Path, body: str = "fake") -> None:
    path.write_text(f"-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n")


def test_scan_trust_store_no_openssl(monkeypatch) -> None:
    monkeypatch.setattr(pr.shutil, "which", lambda name: None)
    result = pr.scan_trust_store(dirs=["/nonexistent"])
    assert result == {"available": False, "reason": "openssl not on PATH"}


def test_scan_trust_store_categorises_each_cert(monkeypatch, tmp_path) -> None:
    # Three fake PEM files; we monkeypatch _run to return a dump matching
    # each cert's filename so we exercise all three categories without
    # needing a real composite-sig cert (which openssl can't yet sign).
    classical = tmp_path / "classical.pem"
    composite = tmp_path / "composite.pem"
    pure_pqc = tmp_path / "pure_pqc.pem"
    _write_pem(classical)
    _write_pem(composite)
    _write_pem(pure_pqc)

    dumps_by_path: dict[str, str] = {
        str(classical): CLASSICAL_DUMP,
        str(composite): COMPOSITE_DUMP,
        str(pure_pqc): PURE_PQC_DUMP,
    }

    monkeypatch.setattr(pr.shutil, "which", lambda name: "/usr/bin/openssl")

    def fake_run(cmd, timeout=None):  # noqa: ARG001 — signature must match _run
        # cmd is like ["openssl", "x509", "-in", <path>, ...]
        path = cmd[cmd.index("-in") + 1]
        return 0, dumps_by_path[path]

    monkeypatch.setattr(pr, "_run", fake_run)

    result = pr.scan_trust_store(dirs=[str(tmp_path)])

    assert result["available"] is True
    assert result["total_certs"] == 3
    assert result["cert_categories"] == {
        "classical": 1,
        "hybrid_composite": 1,
        "pure_pqc": 1,
    }


def test_scan_trust_store_skips_unreadable_certs(monkeypatch, tmp_path) -> None:
    # If openssl returns a non-zero exit code for a cert, that cert must
    # not be counted in either total_certs or any category.
    good = tmp_path / "good.pem"
    bad = tmp_path / "bad.pem"
    _write_pem(good)
    _write_pem(bad)

    monkeypatch.setattr(pr.shutil, "which", lambda name: "/usr/bin/openssl")

    def fake_run(cmd, timeout=None):  # noqa: ARG001
        path = cmd[cmd.index("-in") + 1]
        if path.endswith("bad.pem"):
            return 1, ""
        return 0, CLASSICAL_DUMP

    monkeypatch.setattr(pr, "_run", fake_run)

    result = pr.scan_trust_store(dirs=[str(tmp_path)])

    assert result["total_certs"] == 1
    assert result["cert_categories"]["classical"] == 1
    assert result["cert_categories"]["hybrid_composite"] == 0
    assert result["cert_categories"]["pure_pqc"] == 0


def test_scan_trust_store_empty_when_no_dirs_match(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(pr.shutil, "which", lambda name: "/usr/bin/openssl")
    result = pr.scan_trust_store(dirs=[str(tmp_path / "missing")])
    assert result["total_certs"] == 0
    assert result["cert_categories"] == {
        "classical": 0,
        "hybrid_composite": 0,
        "pure_pqc": 0,
    }
