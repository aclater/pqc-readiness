# SPDX-License-Identifier: Apache-2.0
"""Tests for trust-store certificate categorisation.

Certificates are classified from the algorithm OIDs in their DER encoding
(#116).  The fixtures under tests/fixtures/trust_store/ are real
certificates issued by OpenSSL 3.5.9, which prints ML-DSA / SLH-DSA by
name in `openssl x509 -text` — the case the previous text-matching scanner
misclassified as classical.  Regenerate with e.g.:

    openssl req -x509 -newkey ML-DSA-65 -nodes -days 36500 \\
        -subj "/CN=pqc-readiness fixture ml-dsa-65" \\
        -keyout /tmp/k.pem -out tests/fixtures/trust_store/ml-dsa-65.pem

(keys stay out of the repo).  OpenSSL cannot issue IETF composite
certificates yet, so composite cases use the minimal DER builder below.
"""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path

import pytest
import shutil

import pqc_readiness as pr

FIXTURES = Path(__file__).parent / "fixtures" / "trust_store"

ML_DSA_65 = "2.16.840.1.101.3.4.3.18"
SLH_DSA_SHA2_128S = "2.16.840.1.101.3.4.3.20"
ECDSA_SHA256 = "1.2.840.10045.4.3.2"
EC_PUBLIC_KEY = "1.2.840.10045.2.1"
RSA_ENCRYPTION = "1.2.840.113549.1.1.1"
SHA256_RSA = "1.2.840.113549.1.1.11"
# Composite-ML-DSA-44-ECDSA-P256-SHA256 (1.3.6.1.5.5.7.6.40).
COMPOSITE_MLDSA44_P256 = "1.3.6.1.5.5.7.6.40"


# ---------------------------------------------------------------------------
# Minimal DER builder for hand-constructed certificates
# ---------------------------------------------------------------------------


def _len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _len(len(value)) + value


def _oid(dotted: str) -> bytes:
    arcs = [int(a) for a in dotted.split(".")]
    out = bytearray([40 * arcs[0] + arcs[1]])
    for arc in arcs[2:]:
        chunk = [arc & 0x7F]
        arc >>= 7
        while arc:
            chunk.append(0x80 | (arc & 0x7F))
            arc >>= 7
        out.extend(reversed(chunk))
    return _tlv(0x06, bytes(out))


def _alg(oid: str) -> bytes:
    return _tlv(0x30, _oid(oid))


def build_cert(
    sig_oid: str, spki_oid: str, serial: int = 1, key_bytes: int = 32
) -> bytes:
    """Structurally valid X.509 Certificate DER (not cryptographically
    valid).  `key_bytes` > 127 exercises long-form lengths."""
    tbs = _tlv(
        0x30,
        _tlv(0xA0, _tlv(0x02, b"\x02"))  # version v3
        + _tlv(0x02, serial.to_bytes(4, "big"))
        + _alg(sig_oid)
        + _tlv(0x30, b"")  # issuer
        + _tlv(0x30, _tlv(0x17, b"250101000000Z") * 2)  # validity
        + _tlv(0x30, b"")  # subject
        + _tlv(0x30, _alg(spki_oid) + _tlv(0x03, b"\x00" + b"\x01" * key_bytes)),
    )
    return _tlv(0x30, tbs + _alg(sig_oid) + _tlv(0x03, b"\x00" + b"\x02" * 64))


def to_pem(der: bytes, label: str = "CERTIFICATE") -> str:
    b64 = base64.b64encode(der).decode()
    lines = "\n".join(b64[i : i + 64] for i in range(0, len(b64), 64))
    return f"-----BEGIN {label}-----\n{lines}\n-----END {label}-----\n"


def _fixture_der(name: str) -> bytes:
    return pr.detect.certs._certs_in_file(FIXTURES / name)[0]


def _no_subprocess(monkeypatch) -> None:
    """The scan must not need openssl (or any subprocess) at all."""

    def boom(cmd, timeout=None):  # noqa: ARG001 — signature must match _run
        raise AssertionError(f"scan_trust_store must not spawn {cmd}")

    monkeypatch.setattr(pr._platform, "_run", boom)
    monkeypatch.setattr(shutil, "which", lambda name: None)


# ---------------------------------------------------------------------------
# categorise_cert_oids — pure unit tests
# ---------------------------------------------------------------------------


def test_categorise_classical() -> None:
    assert pr.categorise_cert_oids([SHA256_RSA, RSA_ENCRYPTION]) == "classical"


def test_categorise_pure_pqc_ml_dsa() -> None:
    assert pr.categorise_cert_oids([ML_DSA_65, ML_DSA_65]) == "pure_pqc"


def test_categorise_pure_pqc_slh_dsa_top_of_range() -> None:
    # SLH-DSA-SHAKE-256s, 2.16.840.1.101.3.4.3.31 — top of the NIST PQC range.
    assert pr.categorise_cert_oids(["2.16.840.1.101.3.4.3.31"]) == "pure_pqc"


@pytest.mark.parametrize("leaf", ["16", "32", "170", "18.1"])
def test_pqc_range_boundaries_are_classical(leaf: str) -> None:
    assert pr.categorise_cert_oids([f"2.16.840.1.101.3.4.3.{leaf}"]) == "classical"


@pytest.mark.parametrize("leaf", ["37", "40", "54"])
def test_categorise_composite_range(leaf: str) -> None:
    assert pr.categorise_cert_oids([f"1.3.6.1.5.5.7.6.{leaf}"]) == "hybrid_composite"


@pytest.mark.parametrize("leaf", ["36", "55", "374"])
def test_oid_outside_composite_range_is_classical(leaf: str) -> None:
    assert pr.categorise_cert_oids([f"1.3.6.1.5.5.7.6.{leaf}"]) == "classical"


def test_categorise_composite_takes_precedence_over_pure_pqc() -> None:
    # A composite signature over an ML-DSA public key is still composite —
    # the more specific IETF category.
    assert (
        pr.categorise_cert_oids([COMPOSITE_MLDSA44_P256, ML_DSA_65])
        == "hybrid_composite"
    )


# ---------------------------------------------------------------------------
# DER reader
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("ml-dsa-65.pem", [ML_DSA_65, ML_DSA_65]),
        ("slh-dsa-sha2-128s.pem", [SLH_DSA_SHA2_128S, SLH_DSA_SHA2_128S]),
        ("ec-p256.pem", [ECDSA_SHA256, EC_PUBLIC_KEY]),
        ("rsa-2048.pem", [SHA256_RSA, RSA_ENCRYPTION]),
    ],
)
def test_cert_algorithm_oids_real_openssl_certs(name: str, expected: list[str]) -> None:
    assert pr.cert_algorithm_oids(_fixture_der(name)) == expected


@pytest.mark.parametrize("key_bytes", [8, 200, 70000])
def test_cert_algorithm_oids_short_and_long_form_lengths(key_bytes: int) -> None:
    der = build_cert(COMPOSITE_MLDSA44_P256, COMPOSITE_MLDSA44_P256, key_bytes=key_bytes)
    assert pr.cert_algorithm_oids(der) == [COMPOSITE_MLDSA44_P256] * 2


@pytest.mark.parametrize("name", ["ml-dsa-65.pem", "ec-p256.pem"])
def test_every_truncation_raises_dererror_only(name: str) -> None:
    # Bounds checks: any prefix of a real cert is rejected cleanly, never
    # with IndexError or by reading past the buffer.
    der = _fixture_der(name)
    for cut in range(len(der)):
        with pytest.raises(pr.DERError):
            pr.cert_algorithm_oids(der[:cut])


@pytest.mark.parametrize(
    "der",
    [
        b"",
        b"\x30",
        b"\x30\x80\x00\x00",  # indefinite length
        b"\x30\x85\x01\x00\x00\x00\x00",  # 5-byte length
        b"\x31\x00",  # SET, not SEQUENCE
        b"\x30\x03\x02\x01\x01",  # tbsCertificate is an INTEGER
        bytes(range(256)),
    ],
)
def test_malformed_der_raises_dererror(der: bytes) -> None:
    with pytest.raises(pr.DERError):
        pr.cert_algorithm_oids(der)


# ---------------------------------------------------------------------------
# scan_trust_store — the #116 regressions
# ---------------------------------------------------------------------------


def test_scan_classifies_real_openssl35_pqc_certs(monkeypatch, tmp_path) -> None:
    # Regression for #116 bug 1: OpenSSL >= 3.5 names these algorithms in
    # its text output, and the old scanner called both certs classical.
    _no_subprocess(monkeypatch)
    for name in ("ml-dsa-65.pem", "slh-dsa-sha2-128s.pem", "ec-p256.pem"):
        (tmp_path / name).write_bytes((FIXTURES / name).read_bytes())
    result = pr.scan_trust_store(dirs=[str(tmp_path)])
    assert result["available"] is True
    assert result["total_certs"] == 3
    assert result["pqc_certs"] == 2
    assert result["cert_categories"] == {
        "classical": 1,
        "hybrid_composite": 0,
        "pure_pqc": 2,
    }


def test_scan_inspects_every_cert_in_a_bundle(monkeypatch) -> None:
    # Regression for #116 bug 2: `openssl x509 -in` read only the first
    # certificate of a bundle; the PQC certs after it were never seen.
    _no_subprocess(monkeypatch)
    result = pr.scan_trust_store(dirs=[str(FIXTURES)])
    # rsa + ml-dsa + slh-dsa + ec, each present both in its own file and
    # in mixed-bundle.pem (the EC copy in TRUSTED CERTIFICATE form).
    assert result["total_found"] == 4
    assert result["total_certs"] == 4
    assert result["cert_categories"] == {
        "classical": 2,
        "hybrid_composite": 0,
        "pure_pqc": 2,
    }


def test_scan_bundle_alone(monkeypatch, tmp_path) -> None:
    _no_subprocess(monkeypatch)
    (tmp_path / "bundle.pem").write_bytes((FIXTURES / "mixed-bundle.pem").read_bytes())
    result = pr.scan_trust_store(dirs=[str(tmp_path)])
    assert result["total_certs"] == 4
    assert result["pqc_certs"] == 2


def test_trusted_certificate_form_dedups_with_plain(monkeypatch, tmp_path) -> None:
    # The TRUSTED CERTIFICATE block carries trailing trust settings; only
    # the Certificate element is hashed, so both forms count once.
    _no_subprocess(monkeypatch)
    der = _fixture_der("ec-p256.pem")
    (tmp_path / "plain.pem").write_text(to_pem(der))
    (tmp_path / "trusted.crt").write_text(
        to_pem(der + bytes.fromhex("3006300406022b06"), label="TRUSTED CERTIFICATE")
    )
    result = pr.scan_trust_store(dirs=[str(tmp_path)])
    assert result["total_found"] == 1
    assert result["total_certs"] == 1


def test_scan_counts_composite_certs(monkeypatch, tmp_path) -> None:
    _no_subprocess(monkeypatch)
    (tmp_path / "composite.pem").write_text(
        to_pem(build_cert(COMPOSITE_MLDSA44_P256, COMPOSITE_MLDSA44_P256))
    )
    result = pr.scan_trust_store(dirs=[str(tmp_path)])
    assert result["cert_categories"]["hybrid_composite"] == 1
    assert result["pqc_certs"] == 0


def test_scan_counts_legacy_hybrid_oids(monkeypatch, tmp_path) -> None:
    _no_subprocess(monkeypatch)
    (tmp_path / "oqs.pem").write_text(to_pem(build_cert("1.3.9999.6.4.13", "1.3.9999.6.4.13")))
    result = pr.scan_trust_store(dirs=[str(tmp_path)])
    assert result["hybrid_certs"] == 1
    assert result["cert_categories"]["classical"] == 1


def test_scan_reads_der_encoded_crt(monkeypatch, tmp_path) -> None:
    _no_subprocess(monkeypatch)
    (tmp_path / "der.crt").write_bytes(_fixture_der("ml-dsa-65.pem"))
    result = pr.scan_trust_store(dirs=[str(tmp_path)])
    assert result["cert_categories"]["pure_pqc"] == 1


def test_scan_ignores_private_keys_and_non_cert_pem(monkeypatch, tmp_path) -> None:
    _no_subprocess(monkeypatch)
    (tmp_path / "key.pem").write_text(to_pem(b"\x30\x03\x02\x01\x00", label="PRIVATE KEY"))
    (tmp_path / "notes.pem").write_text("hello")
    result = pr.scan_trust_store(dirs=[str(tmp_path)])
    assert result["total_found"] == 0
    assert result["total_certs"] == 0


def test_scan_skips_corrupt_blocks_and_continues(monkeypatch, tmp_path) -> None:
    _no_subprocess(monkeypatch)
    good = (FIXTURES / "ec-p256.pem").read_text()
    (tmp_path / "good.pem").write_text(good)
    (tmp_path / "truncated.pem").write_text(good[: len(good) // 2])
    (tmp_path / "garbage.crt").write_text(
        "-----BEGIN CERTIFICATE-----\n!!\n-----END CERTIFICATE-----\n"
    )
    (tmp_path / "bad-der.pem").write_text(to_pem(b"\x30\x05\x02\x01\x01\x02\x00"))
    result = pr.scan_trust_store(dirs=[str(tmp_path)])
    assert result["available"] is True
    # bad-der decodes (found) but fails structural parsing (not counted).
    assert result["total_found"] == 2
    assert result["total_certs"] == 1
    assert result["cert_categories"]["classical"] == 1


def test_scan_skips_oversized_files(monkeypatch, tmp_path) -> None:
    _no_subprocess(monkeypatch)
    monkeypatch.setattr(pr.detect.certs, "TRUST_STORE_MAX_FILE_BYTES", 100)
    (tmp_path / "big.pem").write_bytes((FIXTURES / "ml-dsa-65.pem").read_bytes())
    result = pr.scan_trust_store(dirs=[str(tmp_path)])
    assert result["total_found"] == 0


def test_scan_skips_unreadable_files(monkeypatch, tmp_path) -> None:
    _no_subprocess(monkeypatch)
    (tmp_path / "a.pem").write_bytes((FIXTURES / "ec-p256.pem").read_bytes())
    (tmp_path / "b.pem").write_bytes((FIXTURES / "rsa-2048.pem").read_bytes())
    real_read = Path.read_bytes

    def flaky(self: Path) -> bytes:
        if self.name == "a.pem":
            raise PermissionError("denied")
        return real_read(self)

    monkeypatch.setattr(Path, "read_bytes", flaky)
    result = pr.scan_trust_store(dirs=[str(tmp_path)])
    assert result["total_certs"] == 1


# ---------------------------------------------------------------------------
# max_certs cap (issue #87) — applied per unique certificate
# ---------------------------------------------------------------------------


def _write_distinct_certs(directory: Path, n: int, per_file: int = 1) -> None:
    serial = 0
    for f in range(0, n, per_file):
        blocks = []
        for _ in range(min(per_file, n - f)):
            serial += 1
            blocks.append(to_pem(build_cert(SHA256_RSA, RSA_ENCRYPTION, serial=serial)))
        (directory / f"c{f:03d}.pem").write_text("".join(blocks))


@pytest.mark.parametrize(
    ("n_certs", "cap", "scanned", "truncated"),
    [
        (4, 5, 4, False),  # under the cap
        (5, 5, 5, False),  # exactly at the cap — nothing skipped
        (6, 5, 5, True),  # one over the cap
    ],
)
@pytest.mark.parametrize("per_file", [1, 3])
def test_scan_trust_store_max_certs_boundary(
    monkeypatch, tmp_path, n_certs: int, cap: int, scanned: int, truncated: bool, per_file: int
) -> None:
    _no_subprocess(monkeypatch)
    _write_distinct_certs(tmp_path, n_certs, per_file=per_file)
    result = pr.scan_trust_store(dirs=[str(tmp_path)], max_certs=cap)
    assert result["total_found"] == n_certs
    assert result["scanned_count"] == scanned
    assert result["total_certs"] == scanned
    assert result["max_certs"] == cap
    assert result["truncated"] is truncated


def test_scan_trust_store_cap_is_deterministic(monkeypatch, tmp_path) -> None:
    """A capped scan always covers the same certs (sorted file order, then
    order within a file), so two runs on one host are comparable."""
    _no_subprocess(monkeypatch)
    (tmp_path / "b.pem").write_bytes((FIXTURES / "ml-dsa-65.pem").read_bytes())
    (tmp_path / "a.crt").write_bytes((FIXTURES / "ec-p256.pem").read_bytes())
    (tmp_path / "c.pem").write_bytes((FIXTURES / "slh-dsa-sha2-128s.pem").read_bytes())
    for _ in range(2):
        result = pr.scan_trust_store(dirs=[str(tmp_path)], max_certs=2)
        assert result["cert_categories"] == {
            "classical": 1,
            "hybrid_composite": 0,
            "pure_pqc": 1,
        }


def test_scan_trust_store_cap_counts_symlinks_once(monkeypatch, tmp_path) -> None:
    """Distro trust stores are symlink farms; a hash-named symlink to an
    already-seen cert must not consume cap budget or total_found."""
    _no_subprocess(monkeypatch)
    real = tmp_path / "real.pem"
    real.write_bytes((FIXTURES / "ec-p256.pem").read_bytes())
    (tmp_path / "abcd1234.pem").symlink_to(real)
    result = pr.scan_trust_store(dirs=[str(tmp_path)], max_certs=1)
    assert result["total_found"] == 1
    assert result["truncated"] is False


def test_scan_trust_store_default_cap_is_500() -> None:
    assert pr.TRUST_STORE_MAX_CERTS_DEFAULT == 500
    import inspect

    sig = inspect.signature(pr.scan_trust_store)
    assert sig.parameters["max_certs"].default == 500


def test_scan_trust_store_rejects_nonpositive_cap(tmp_path) -> None:
    with pytest.raises(ValueError):
        pr.scan_trust_store(dirs=[str(tmp_path)], max_certs=0)


@pytest.mark.parametrize("bad", ["0", "-3", "many"])
def test_cli_rejects_bad_trust_store_max_certs(monkeypatch, bad: str) -> None:
    import sys

    monkeypatch.setattr(
        sys, "argv", ["pqc_readiness.py", "--trust-store-max-certs", bad]
    )
    with pytest.raises(SystemExit) as exc:
        pr.main()
    assert exc.value.code == 2


def test_truncation_surfaces_in_text_cbom_and_sarif() -> None:
    import json

    r = pr.Report()
    r.trust_store = {
        "available": True,
        "scanned_dirs": ["/etc/pki/tls/certs"],
        "total_certs": 500,
        "pqc_certs": 0,
        "hybrid_certs": 0,
        "cert_categories": {"classical": 500, "hybrid_composite": 0, "pure_pqc": 0},
        "total_found": 1200,
        "scanned_count": 500,
        "max_certs": 500,
        "truncated": True,
    }
    text = pr.render_text(r)
    assert "scanned 500 of 1200" in text

    cbom = json.loads(pr.render_cbom(r))
    ts_comp = [
        c for c in cbom["components"] if c.get("name") == "Trust store certificate inventory"
    ][0]
    props = {p["name"]: p["value"] for p in ts_comp["properties"]}
    assert props["trust_store:truncated"] == "true"
    assert props["trust_store:total_found"] == "1200"

    sarif = json.loads(pr.render_sarif(r))
    results = sarif["runs"][0]["results"]
    ts_res = [x for x in results if x["ruleId"] == "pqc-004-classical-only-trust-store"][0]
    assert "capped at 500 of 1200" in ts_res["message"]["text"]
    assert ts_res["properties"]["trust_store:truncated"] is True


# ---------------------------------------------------------------------------
# Field-deployment edge cases (issue #79): hardened hosts and minimal
# containers often have no trust store or an empty one.
# ---------------------------------------------------------------------------


def test_scan_trust_store_all_default_dirs_missing(monkeypatch, tmp_path) -> None:
    # Default-argument path: every TRUST_STORE_DIRS entry is absent.
    monkeypatch.setattr(
        pr.detect.certs, "TRUST_STORE_DIRS", [str(tmp_path / "a"), str(tmp_path / "b" / "c")]
    )
    _no_subprocess(monkeypatch)
    result = pr.scan_trust_store()
    assert result == {
        "available": True,
        "scanned_dirs": [],
        "total_certs": 0,
        "pqc_certs": 0,
        "hybrid_certs": 0,
        "cert_categories": {"classical": 0, "hybrid_composite": 0, "pure_pqc": 0},
        "total_found": 0,
        "scanned_count": 0,
        "max_certs": pr.TRUST_STORE_MAX_CERTS_DEFAULT,
        "truncated": False,
    }


def test_scan_trust_store_existing_empty_dir(monkeypatch, tmp_path) -> None:
    # The dir exists (so it is reported as scanned) but holds no certs;
    # files without .pem/.crt suffixes are ignored, not parsed.
    empty = tmp_path / "empty"
    empty.mkdir()
    noise = tmp_path / "noise"
    (noise / "sub").mkdir(parents=True)
    (noise / "README").write_text("not a cert")
    (noise / "sub" / "bundle.txt").write_text(to_pem(_fixture_der("ec-p256.pem")))
    _no_subprocess(monkeypatch)
    result = pr.scan_trust_store(dirs=[str(empty), str(noise)])
    assert result["available"] is True
    assert result["scanned_dirs"] == [str(empty), str(noise)]
    assert result["total_certs"] == 0
    assert result["pqc_certs"] == 0
    assert result["hybrid_certs"] == 0
    assert sum(result["cert_categories"].values()) == 0


def test_fixture_hashes_are_stable() -> None:
    # Guard against an accidental fixture regeneration changing what the
    # bundle test measures: the four standalone certs are the bundle's
    # four certs (EC in TRUSTED form).
    standalone = {
        hashlib.sha256(_fixture_der(n)).hexdigest()
        for n in ("rsa-2048.pem", "ml-dsa-65.pem", "slh-dsa-sha2-128s.pem", "ec-p256.pem")
    }
    bundle = {
        hashlib.sha256(d).hexdigest()
        for d in pr.detect.certs._certs_in_file(FIXTURES / "mixed-bundle.pem")
    }
    assert standalone == bundle
