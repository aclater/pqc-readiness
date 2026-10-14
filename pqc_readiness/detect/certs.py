"""Trust-store certificate inventory (--scan-trust-store), DER OID classification."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import logging
import os
import re
from pathlib import Path
from datetime import datetime, timezone
from typing import Any

from .. import _platform
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


# ---------------------------------------------------------------------------
# Full certificate parse (#108): identity, validity, key and CA status
# ---------------------------------------------------------------------------

# Attribute type OIDs rendered in RFC 4514 order (most specific first).
_NAME_ATTRS: dict[str, str] = {
    "2.5.4.3": "CN",
    "2.5.4.5": "serialNumber",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "1.2.840.113549.1.9.1": "emailAddress",
    "0.9.2342.19200300.100.1.25": "DC",
    "0.9.2342.19200300.100.1.1": "UID",
}

# DirectoryString / IA5 / BMP / Universal string tags.
_STRING_TAGS = {
    0x0C: "utf-8",
    0x13: "ascii",
    0x16: "ascii",
    0x14: "latin-1",
    0x1E: "utf-16-be",
    0x1C: "utf-32-be",
}

# SubjectPublicKeyInfo algorithm OID -> (name, fixed key size in bits or None).
# Sizes for RSA and EC are read from the key itself; PQC parameter sets
# are named by OID (FIPS 203/204/205; RFC 9881 / RFC 9935 for X.509).
_SPKI_ALGORITHMS: dict[str, tuple[str, int | None]] = {
    "1.2.840.113549.1.1.1": ("RSA", None),
    "1.2.840.113549.1.1.10": ("RSASSA-PSS", None),
    "1.2.840.10045.2.1": ("EC", None),
    "1.2.840.10040.4.1": ("DSA", None),
    "1.3.101.110": ("X25519", 255),
    "1.3.101.111": ("X448", 448),
    "1.3.101.112": ("Ed25519", 255),
    "1.3.101.113": ("Ed448", 448),
    "2.16.840.1.101.3.4.3.17": ("ML-DSA-44", None),
    "2.16.840.1.101.3.4.3.18": ("ML-DSA-65", None),
    "2.16.840.1.101.3.4.3.19": ("ML-DSA-87", None),
    "2.16.840.1.101.3.4.3.20": ("SLH-DSA-SHA2-128s", None),
    "2.16.840.1.101.3.4.3.21": ("SLH-DSA-SHA2-128f", None),
    "2.16.840.1.101.3.4.3.22": ("SLH-DSA-SHA2-192s", None),
    "2.16.840.1.101.3.4.3.23": ("SLH-DSA-SHA2-192f", None),
    "2.16.840.1.101.3.4.3.24": ("SLH-DSA-SHA2-256s", None),
    "2.16.840.1.101.3.4.3.25": ("SLH-DSA-SHA2-256f", None),
    "2.16.840.1.101.3.4.3.26": ("SLH-DSA-SHAKE-128s", None),
    "2.16.840.1.101.3.4.3.27": ("SLH-DSA-SHAKE-128f", None),
    "2.16.840.1.101.3.4.3.28": ("SLH-DSA-SHAKE-192s", None),
    "2.16.840.1.101.3.4.3.29": ("SLH-DSA-SHAKE-192f", None),
    "2.16.840.1.101.3.4.3.30": ("SLH-DSA-SHAKE-256s", None),
    "2.16.840.1.101.3.4.3.31": ("SLH-DSA-SHAKE-256f", None),
    "2.16.840.1.101.3.4.4.1": ("ML-KEM-512", None),
    "2.16.840.1.101.3.4.4.2": ("ML-KEM-768", None),
    "2.16.840.1.101.3.4.4.3": ("ML-KEM-1024", None),
}

_EC_CURVES: dict[str, tuple[str, int]] = {
    "1.2.840.10045.3.1.7": ("P-256", 256),
    "1.3.132.0.34": ("P-384", 384),
    "1.3.132.0.35": ("P-521", 521),
    "1.3.132.0.10": ("secp256k1", 256),
    "1.3.36.3.3.2.8.1.1.7": ("brainpoolP256r1", 256),
    "1.3.36.3.3.2.8.1.1.11": ("brainpoolP384r1", 384),
    "1.3.36.3.3.2.8.1.1.13": ("brainpoolP512r1", 512),
}

_OID_BASIC_CONSTRAINTS = "2.5.29.19"
_OID_KEY_USAGE = "2.5.29.15"


def _der_string(tag: int, value: bytes) -> str:
    enc = _STRING_TAGS.get(tag)
    if enc is None:
        return value.hex()
    return value.decode(enc, "replace")


def _rfc4514_escape(v: str) -> str:
    out = []
    for i, ch in enumerate(v):
        if (
            ch in ',+"\\<>;='
            or (ch == "#" and i == 0)
            or (ch == " " and i in (0, len(v) - 1))
        ):
            out.append("\\" + ch)
        else:
            out.append(ch)
    return "".join(out)


def _der_name(buf: bytes, start: int, stop: int) -> str:
    """Render an X.501 Name as an RFC 4514 string (last RDN first)."""
    rdns: list[str] = []
    pos = start
    while pos < stop:
        tag, sstart, sstop = _der_tlv(buf, pos, stop)
        if tag != 0x31:
            raise DERError("RDN is not a SET")
        parts: list[str] = []
        apos = sstart
        while apos < sstop:
            tag, astart, astop = _der_tlv(buf, apos, sstop)
            if tag != 0x30:
                raise DERError("AttributeTypeAndValue is not a SEQUENCE")
            otag, ostart, ostop = _der_tlv(buf, astart, astop)
            if otag != 0x06:
                raise DERError("attribute type is not an OID")
            oid = _der_oid(buf[ostart:ostop])
            vtag, vstart, vstop = _der_tlv(buf, ostop, astop)
            parts.append(
                f"{_NAME_ATTRS.get(oid, oid)}={_rfc4514_escape(_der_string(vtag, buf[vstart:vstop]))}"
            )
            apos = astop
        rdns.append("+".join(parts))
        pos = sstop
    return ",".join(reversed(rdns))


def _der_time(tag: int, value: bytes) -> str:
    """UTCTime / GeneralizedTime (Z form, as RFC 5280 requires) -> ISO 8601 UTC."""
    text = value.decode("ascii", "replace")
    if not text.endswith("Z"):
        raise DERError("certificate time is not in UTC (Z) form")
    if tag == 0x17:  # UTCTime YYMMDDHHMMSSZ, RFC 5280 4.1.2.5.1
        yy = int(text[:2])
        text = ("19" if yy >= 50 else "20") + text
    elif tag != 0x18:
        raise DERError("validity time has an unknown tag")
    try:
        dt = datetime.strptime(text[:14], "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    except ValueError as e:
        raise DERError(f"bad certificate time {text!r}") from e
    return dt.isoformat()


def _der_int_bits(value: bytes) -> int:
    return int.from_bytes(value, "big").bit_length()


def _spki_key(buf: bytes, start: int, stop: int) -> tuple[str, str, int | None]:
    """(algorithm OID, algorithm name, key size in bits or None) from a
    SubjectPublicKeyInfo body.  Only public key data is read."""
    tag, astart, astop = _der_tlv(buf, start, stop)
    if tag != 0x30:
        raise DERError("SPKI algorithm is not a SEQUENCE")
    otag, ostart, ostop = _der_tlv(buf, astart, astop)
    oid = _der_oid(buf[ostart:ostop])
    name, size = _SPKI_ALGORITHMS.get(oid, (oid, None))
    if oid == "1.2.840.10045.2.1" and ostop < astop:  # named curve parameter
        ptag, pstart, pstop = _der_tlv(buf, ostop, astop)
        if ptag == 0x06:
            curve = _der_oid(buf[pstart:pstop])
            cname, size = _EC_CURVES.get(curve, (curve, None))
            name = f"EC {cname}"
    elif name in ("RSA", "RSASSA-PSS"):
        btag, bstart, bstop = _der_tlv(buf, astop, stop)  # subjectPublicKey BIT STRING
        if btag == 0x03 and bstart < bstop:
            rtag, rstart, rstop = _der_tlv(buf, bstart + 1, bstop)  # RSAPublicKey
            if rtag == 0x30:
                mtag, mstart, mstop = _der_tlv(buf, rstart, rstop)
                if mtag == 0x02:
                    size = _der_int_bits(buf[mstart:mstop])
    return oid, name, size


def _extensions(buf: bytes, start: int, stop: int) -> dict[str, bytes]:
    """Map extension OID -> extnValue contents from an Extensions SEQUENCE."""
    out: dict[str, bytes] = {}
    tag, pos, end = _der_tlv(buf, start, stop)
    if tag != 0x30:
        raise DERError("Extensions is not a SEQUENCE")
    while pos < end:
        tag, estart, estop = _der_tlv(buf, pos, end)
        otag, ostart, ostop = _der_tlv(buf, estart, estop)
        oid = _der_oid(buf[ostart:ostop])
        npos = ostop
        ntag, nstart, nstop = _der_tlv(buf, npos, estop)
        if ntag == 0x01:  # critical BOOLEAN
            ntag, nstart, nstop = _der_tlv(buf, nstop, estop)
        if ntag == 0x04:
            out[oid] = buf[nstart:nstop]
        pos = estop
    return out


def _is_ca(exts: dict[str, bytes]) -> bool:
    """basicConstraints cA=TRUE (RFC 5280 4.2.1.9)."""
    bc = exts.get(_OID_BASIC_CONSTRAINTS)
    if not bc:
        return False
    tag, start, stop = _der_tlv(bc, 0, len(bc))
    if tag != 0x30 or start >= stop:
        return False
    btag, bstart, bstop = _der_tlv(bc, start, stop)
    return btag == 0x01 and bstop > bstart and bc[bstart] != 0


def parse_certificate(der: bytes) -> dict[str, Any]:
    """Parse an X.509 certificate's public fields in-process.

    Returns the #138 per-certificate contract (`sha256`, `serial`,
    `subject`, `issuer`, `not_before`, `not_after`, `category`) plus
    `signature_algorithm_oid`, `key_algorithm`, `key_algorithm_oid`,
    `key_size`, `is_ca`, `self_signed` and `role` (`ca` / `leaf`).  Raises DERError on malformed
    input; never reads past the buffer."""
    tag, cstart, cstop = _der_tlv(der, 0, len(der))
    if tag != 0x30:
        raise DERError("Certificate is not a SEQUENCE")
    tag, pos, tstop = _der_tlv(der, cstart, cstop)
    if tag != 0x30:
        raise DERError("tbsCertificate is not a SEQUENCE")
    if pos < tstop and der[pos] == 0xA0:  # [0] EXPLICIT version
        pos = _der_tlv(der, pos, tstop)[2]
    stag, sstart, sstop = _der_tlv(der, pos, tstop)
    if stag != 0x02:
        raise DERError("serialNumber is not an INTEGER")
    serial = der[sstart:sstop].hex()
    sig_oid, pos = _der_algorithm_oid(der, sstop, tstop)
    itag, istart, istop = _der_tlv(der, pos, tstop)
    if itag != 0x30:
        raise DERError("issuer is not a SEQUENCE")
    issuer = _der_name(der, istart, istop)
    vtag, vstart, vstop = _der_tlv(der, istop, tstop)
    if vtag != 0x30:
        raise DERError("validity is not a SEQUENCE")
    t1, b1, e1 = _der_tlv(der, vstart, vstop)
    t2, b2, e2 = _der_tlv(der, e1, vstop)
    not_before = _der_time(t1, der[b1:e1])
    not_after = _der_time(t2, der[b2:e2])
    jtag, jstart, jstop = _der_tlv(der, vstop, tstop)
    if jtag != 0x30:
        raise DERError("subject is not a SEQUENCE")
    subject = _der_name(der, jstart, jstop)
    ktag, kstart, kstop = _der_tlv(der, jstop, tstop)
    if ktag != 0x30:
        raise DERError("subjectPublicKeyInfo is not a SEQUENCE")
    key_oid, key_name, key_size = _spki_key(der, kstart, kstop)
    exts: dict[str, bytes] = {}
    pos = kstop
    while pos < tstop:  # [1] issuerUID, [2] subjectUID, [3] extensions
        etag, estart, estop = _der_tlv(der, pos, tstop)
        if etag == 0xA3:
            exts = _extensions(der, estart, estop)
        pos = estop
    is_ca = _is_ca(exts)
    self_signed = subject == issuer
    return {
        "sha256": hashlib.sha256(der).hexdigest(),
        "serial": serial,
        "subject": subject,
        "issuer": issuer,
        "not_before": not_before,
        "not_after": not_after,
        "category": categorise_cert_oids([sig_oid, key_oid]),
        "signature_algorithm_oid": sig_oid,
        "key_algorithm": key_name,
        "key_algorithm_oid": key_oid,
        "key_size": key_size,
        "is_ca": is_ca,
        "self_signed": self_signed,
        # v1 trust anchors carry no basicConstraints; a self-signed cert
        # without the extension is treated as a CA, as path validation does.
        "role": "ca"
        if is_ca or (self_signed and _OID_BASIC_CONSTRAINTS not in exts)
        else "leaf",
    }


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


def _cert_files(top: Path) -> list[Path]:
    """*.pem and *.crt files under `top`, sorted.  Under a prefix, linked
    subdirectories are not descended into: their targets could be the
    scanning machine's directories (#258)."""
    if not _platform.HOST_PREFIX:
        return sorted(list(top.rglob("*.pem")) + list(top.rglob("*.crt")))
    out: list[Path] = []
    for dirpath, _dirnames, filenames in os.walk(top, followlinks=False):
        out.extend(Path(dirpath) / n for n in filenames if n.endswith((".pem", ".crt")))
    return sorted(out)


def _trust_store_candidates(target_dirs: list[str]) -> list[Path]:
    """Enumerate *.pem / *.crt files under target_dirs, de-duplicated by
    resolved path (distro trust stores are symlink farms) and in a
    deterministic order so a capped scan always covers the same certs."""
    seen: set[str] = set()
    out: list[Path] = []
    for d in target_dirs:
        p = Path(d)
        if not _platform.safe_is_dir(p):
            continue
        for cert in _cert_files(p):
            # Under --root, links resolve inside the tree: Debian's
            # /etc/ssl/certs/*.pem are absolute links that the OS would
            # follow onto the scanning machine's files (#258).
            real = _platform.in_tree(cert)
            try:
                key = str(real if _platform.OFFLINE_ROOT else cert.resolve())
            except OSError as e:
                log.debug("scan_trust_store: cannot resolve %s: %s", cert, e)
                continue
            if key in seen:
                continue
            seen.add(key)
            out.append(real)
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
    # Under --host-mount the trust store is the *host's*: read it through
    # host_path, not the scanner image's own /etc (#108).
    local_dirs = [str(_platform.host_path(d)) for d in target_dirs]
    unique: dict[str, bytes] = {}
    for path in _trust_store_candidates(local_dirs):
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
    certificates: list[dict[str, Any]] = []
    for der in to_scan:
        try:
            oids = cert_algorithm_oids(der)
        except DERError as e:
            log.debug("scan_trust_store: skipping malformed certificate: %s", e)
            continue
        try:
            certificates.append(trust_store_certificate(parse_certificate(der)))
        except DERError as e:  # classifiable but e.g. a non-UTC time
            log.debug("scan_trust_store: certificate not fully parsed: %s", e)
        total += 1
        if any(PQC_OID_RE.fullmatch(o) for o in oids):
            pqc_certs += 1
        if any(p.fullmatch(o) for p in HYBRID_OID_RES for o in oids):
            hybrid_certs += 1
        cert_categories[categorise_cert_oids(oids)] += 1
    return {
        "available": True,
        "scanned_dirs": [
            d
            for d, ld in zip(target_dirs, local_dirs)
            if _platform.safe_is_dir(Path(ld))
        ],
        "total_certs": total,
        "pqc_certs": pqc_certs,
        "hybrid_certs": hybrid_certs,
        "cert_categories": cert_categories,
        "total_found": len(unique),
        "scanned_count": len(to_scan),
        "max_certs": max_certs,
        "truncated": len(unique) > max_certs,
        "certificates": certificates,
    }


def trust_store_certificate(cert: dict[str, Any]) -> dict[str, Any]:
    """Project a parse_certificate() result onto the per-certificate
    contract the CycloneDX 1.7 emitter consumes (#138), plus the key and
    role fields that make the JSON useful on its own."""
    keys = (
        "sha256",
        "serial",
        "subject",
        "issuer",
        "not_before",
        "not_after",
        "category",
        "role",
        "key_algorithm",
        "key_size",
    )
    return {k: cert[k] for k in keys}


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
