"""Trust-store certificate inventory (--scan-trust-store), DER OID classification."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import logging
import re
from pathlib import Path
from typing import Any
from .. import registry as _registry


log = logging.getLogger("pqc-readiness")


# ---------------------------------------------------------------------------
# Trust store certificate inventory (--scan-trust-store)
# ---------------------------------------------------------------------------

TRUST_STORE_DIRS: list[str] = [
    "/etc/pki/tls/certs",
    "/etc/ssl/certs",
    "/etc/pki/ca-trust/extracted/pem",
]


# Certificates are classified from the algorithm OIDs in their DER
# encoding, not from `openssl x509 -text` output: OpenSSL >= 3.5 prints
# ML-DSA / SLH-DSA by *name*, so text matching on numeric OIDs silently
# classified real PQC certs as classical (#116).  Patterns are matched
# with fullmatch() against one dotted OID at a time.
#
# NIST PQC signature OIDs 2.16.840.1.101.3.4.3.17 .. .31 cover
# ML-DSA-44/65/87 and the SLH-DSA-SHA2 / SLH-DSA-SHAKE family.
PQC_OID_RE = re.compile(r"2\.16\.840\.1\.101\.3\.4\.3\.(1[7-9]|2\d|3[01])")


# Pre-standard hybrid OIDs still seen in test PKIs.
HYBRID_OID_RES: list[re.Pattern[str]] = [
    re.compile(r"1\.3\.6\.1\.4\.1\.42235\.1\.7(\.\d+)+"),  # Mozilla draft
    re.compile(r"1\.3\.9999(\.\d+){3,}"),  # liboqs experimental
]


# IETF composite signature OIDs (draft-ietf-lamps-pq-composite-sigs).
# IANA early-allocated 2025-10-20 under the SMI Security PKIX Algorithms arc
# 1.3.6.1.5.5.7.6.{37..54} — covers all 18 Composite-ML-DSA variants pairing
# ML-DSA-44/65/87 with RSA, ECDSA, or EdDSA classical components.  These
# certs use a single composite signature algorithm OID and form the
# "hybrid_composite" category in trust_store.cert_categories.
COMPOSITE_SIG_OID_RE = re.compile(r"1\.3\.6\.1\.5\.5\.7\.6\.(3[7-9]|4\d|5[0-4])")


def categorise_cert_oids(oids: list[str]) -> str:
    """Categorise a certificate by its algorithm OIDs (signature algorithm
    and SubjectPublicKeyInfo algorithm) as 'classical', 'hybrid_composite',
    or 'pure_pqc'.

    Composite is checked first: it is the more specific IETF category for
    a cert that pairs ML-DSA with a classical algorithm."""
    if any(COMPOSITE_SIG_OID_RE.fullmatch(o) for o in oids):
        return "hybrid_composite"
    if any(PQC_OID_RE.fullmatch(o) for o in oids):
        return "pure_pqc"
    return "classical"


class DERError(ValueError):
    """Malformed or unsupported DER encountered while reading a cert."""


def _der_tlv(buf: bytes, pos: int, end: int) -> tuple[int, int, int]:
    """Read one DER TLV at buf[pos:end].  Returns (tag, value_start,
    value_end).  Rejects indefinite lengths, lengths over 4 bytes, and
    any element that would run past `end`."""
    if pos + 2 > end:
        raise DERError("truncated TLV header")
    tag = buf[pos]
    if tag & 0x1F == 0x1F:
        raise DERError("high-tag-number form not used in certificates")
    first = buf[pos + 1]
    pos += 2
    if first < 0x80:
        length = first
    else:
        n = first & 0x7F
        if n == 0 or n > 4:
            raise DERError("indefinite or oversized length")
        if pos + n > end:
            raise DERError("truncated length")
        length = int.from_bytes(buf[pos : pos + n], "big")
        pos += n
    if pos + length > end:
        raise DERError("element runs past its container")
    return tag, pos, pos + length


def _der_oid(value: bytes) -> str:
    """Decode the contents of an OBJECT IDENTIFIER to dotted form."""
    if not value or value[-1] & 0x80:
        raise DERError("empty or unterminated OID")
    first = value[0]
    if first & 0x80:
        raise DERError("multi-byte first OID arc not supported")
    top = min(first // 40, 2)
    arcs = [top, first - 40 * top]
    n = 0
    for b in value[1:]:
        n = (n << 7) | (b & 0x7F)
        if not b & 0x80:
            arcs.append(n)
            n = 0
    return ".".join(str(a) for a in arcs)


def _der_algorithm_oid(buf: bytes, pos: int, end: int) -> tuple[str, int]:
    """Read an AlgorithmIdentifier SEQUENCE at pos; return its OID and the
    position just after the SEQUENCE."""
    tag, start, stop = _der_tlv(buf, pos, end)
    if tag != 0x30:
        raise DERError("AlgorithmIdentifier is not a SEQUENCE")
    tag, ostart, ostop = _der_tlv(buf, start, stop)
    if tag != 0x06:
        raise DERError("AlgorithmIdentifier does not start with an OID")
    return _der_oid(buf[ostart:ostop]), stop


def cert_algorithm_oids(der: bytes) -> list[str]:
    """Return [signature_algorithm_oid, subject_public_key_algorithm_oid]
    from an X.509 certificate's tbsCertificate.  Raises DERError on any
    structural problem; never reads past the buffer."""
    tag, cstart, cstop = _der_tlv(der, 0, len(der))
    if tag != 0x30:
        raise DERError("Certificate is not a SEQUENCE")
    tag, pos, tstop = _der_tlv(der, cstart, cstop)
    if tag != 0x30:
        raise DERError("tbsCertificate is not a SEQUENCE")
    if pos < tstop and der[pos] == 0xA0:  # [0] EXPLICIT version
        pos = _der_tlv(der, pos, tstop)[2]
    pos = _der_tlv(der, pos, tstop)[2]  # serialNumber
    sig_oid, pos = _der_algorithm_oid(der, pos, tstop)
    for _ in range(3):  # issuer, validity, subject
        pos = _der_tlv(der, pos, tstop)[2]
    tag, sstart, sstop = _der_tlv(der, pos, tstop)  # subjectPublicKeyInfo
    if tag != 0x30:
        raise DERError("subjectPublicKeyInfo is not a SEQUENCE")
    spki_oid, _ = _der_algorithm_oid(der, sstart, sstop)
    return [sig_oid, spki_oid]


# Default ceiling on certificates classified by scan_trust_store.  Parsing
# is in-process and cheap (well under 1 ms per cert), so the cap now only
# bounds work on pathological stores (test PKIs with 10k+ certs); stock
# distro trust stores hold a few hundred unique certs.  Override with
# --trust-store-max-certs.
TRUST_STORE_MAX_CERTS_DEFAULT = 500


# Files larger than this are not read: no legitimate trust-store bundle
# comes close, and it keeps a stray image or archive from being slurped.
TRUST_STORE_MAX_FILE_BYTES = 64 * 1024 * 1024


_PEM_CERT_RE = re.compile(
    rb"-----BEGIN (?:TRUSTED )?CERTIFICATE-----(.*?)-----END (?:TRUSTED )?CERTIFICATE-----",
    re.S,
)


def _trust_store_candidates(target_dirs: list[str]) -> list[Path]:
    """Enumerate *.pem / *.crt files under target_dirs, de-duplicated by
    resolved path (distro trust stores are symlink farms) and in a
    deterministic order so a capped scan always covers the same certs."""
    seen: set[str] = set()
    out: list[Path] = []
    for d in target_dirs:
        p = Path(d)
        if not p.is_dir():
            continue
        for cert in sorted(list(p.rglob("*.pem")) + list(p.rglob("*.crt"))):
            try:
                key = str(cert.resolve())
            except OSError as e:
                log.debug("scan_trust_store: cannot resolve %s: %s", cert, e)
                continue
            if key in seen:
                continue
            seen.add(key)
            out.append(cert)
    return out


def _certs_in_file(path: Path) -> list[bytes]:
    """Return the DER bytes of every certificate in a PEM file (bundles
    hold hundreds), or the file itself when it is a bare DER certificate.
    Unreadable files and undecodable PEM blocks are skipped with a debug
    log; private keys and other PEM types are ignored."""
    try:
        if path.stat().st_size > TRUST_STORE_MAX_FILE_BYTES:
            log.debug("scan_trust_store: skipping oversized file %s", path)
            return []
        data = path.read_bytes()
    except OSError as e:
        log.debug("scan_trust_store: cannot read %s: %s", path, e)
        return []
    blocks = _PEM_CERT_RE.findall(data)
    if not blocks:
        # DER-encoded .crt files are legal; a SEQUENCE tag is the cheapest
        # sniff, and cert_algorithm_oids() validates the rest.
        return [data] if data[:1] == b"\x30" else []
    out: list[bytes] = []
    for i, body in enumerate(blocks):
        try:
            der = base64.b64decode(b"".join(body.split()), validate=True)
        except (binascii.Error, ValueError) as e:
            log.debug("scan_trust_store: bad base64 in %s block %d: %s", path, i, e)
            continue
        # A TRUSTED CERTIFICATE block is the Certificate followed by
        # OpenSSL trust settings.  Keep only the Certificate element so the
        # same CA in a .trust.crt bundle and a plain bundle de-duplicates.
        try:
            der = der[: _der_tlv(der, 0, len(der))[2]]
        except DERError:
            pass  # kept as-is; cert_algorithm_oids() rejects it and logs
        out.append(der)
    return out


def scan_trust_store(
    dirs: list[str] | None = None,
    max_certs: int = TRUST_STORE_MAX_CERTS_DEFAULT,
) -> dict[str, Any]:
    """Categorise every certificate in the trust store by its algorithm
    OIDs, classifying at most `max_certs` certificates.

    Counts are per unique certificate (SHA-256 of the DER), not per file:
    `total_found` is the number of unique certificates found across all
    files (bundles included), `scanned_count` the number classified
    (≤ max_certs), and `truncated` is true when the cap left certificates
    unclassified.  `total_certs` counts only certificates whose DER parsed;
    malformed ones are skipped and logged under --debug."""
    if max_certs < 1:
        raise ValueError(f"max_certs must be >= 1, got {max_certs}")
    target_dirs = dirs if dirs is not None else TRUST_STORE_DIRS
    unique: dict[str, bytes] = {}
    for path in _trust_store_candidates(target_dirs):
        for der in _certs_in_file(path):
            unique.setdefault(hashlib.sha256(der).hexdigest(), der)
    to_scan = list(unique.values())[:max_certs]
    total = 0
    pqc_certs = 0
    hybrid_certs = 0
    cert_categories: dict[str, int] = {
        "classical": 0,
        "hybrid_composite": 0,
        "pure_pqc": 0,
    }
    for der in to_scan:
        try:
            oids = cert_algorithm_oids(der)
        except DERError as e:
            log.debug("scan_trust_store: skipping malformed certificate: %s", e)
            continue
        total += 1
        if any(PQC_OID_RE.fullmatch(o) for o in oids):
            pqc_certs += 1
        if any(p.fullmatch(o) for p in HYBRID_OID_RES for o in oids):
            hybrid_certs += 1
        cert_categories[categorise_cert_oids(oids)] += 1
    return {
        "available": True,
        "scanned_dirs": [d for d in target_dirs if Path(d).is_dir()],
        "total_certs": total,
        "pqc_certs": pqc_certs,
        "hybrid_certs": hybrid_certs,
        "cert_categories": cert_categories,
        "total_found": len(unique),
        "scanned_count": len(to_scan),
        "max_certs": max_certs,
        "truncated": len(unique) > max_certs,
    }


@_registry.register_arguments(50)
def add_arguments(ap: argparse.ArgumentParser) -> None:
    """--scan-trust-store, --trust-store-max-certs."""
    ap.add_argument(
        "--scan-trust-store",
        action="store_true",
        help="walk system trust store dirs and count PQC / hybrid certs",
    )
    ap.add_argument(
        "--trust-store-max-certs",
        type=_registry.positive_int,
        default=TRUST_STORE_MAX_CERTS_DEFAULT,
        metavar="N",
        help=(
            "cap on unique certificates classified by --scan-trust-store "
            f"(default {TRUST_STORE_MAX_CERTS_DEFAULT}); "
            "trust_store.truncated is set when the cap is hit"
        ),
    )
