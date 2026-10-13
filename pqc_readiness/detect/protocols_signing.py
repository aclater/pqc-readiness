"""Package-signing key inventory (#153).

Which public keys does the host's package manager trust to sign
packages, and are any of them post-quantum?  CNSA 2.0 requires
software/firmware signing to move to ML-DSA-87 or LMS/XMSS by 2030, and
package signing keys are long-lived trust anchors, so they are among the
first classical keys a migration has to replace.

Sources, per family:

* rpm (rhel / suse): keys imported into the rpm database (`gpg-pubkey`
  pseudo-packages, read in-process from sqlite / Berkeley DB / ndb, with
  `rpm -q gpg-pubkey` as the fallback), any file-backed rpm keystore,
  and the local key files that enabled repositories reference with
  ``gpgkey=file://``.
* debian: ``/etc/apt/trusted.gpg``, ``/etc/apt/trusted.gpg.d/*``, and
  every keyring a source names with ``signed-by`` / ``Signed-By``
  (including inline keys in deb822 ``.sources`` files).
* arch: the packaged keyrings in ``/usr/share/pacman/keyrings``, with
  the ``*-trusted`` lists marking which keys pacman trusts.
* alpine: the PEM public keys in ``/etc/apk/keys``.

Only public keys are read, and only algorithm, size / curve,
fingerprint, key ID, creation time and user ID are reported; key
material never leaves this module.

OpenPGP parsing follows RFC 9580 (v4 and v6 keys); the post-quantum
public-key algorithm IDs 30-36 are the IANA assignments from RFC 9980
(Post-Quantum Cryptography in OpenPGP).
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import logging
import os
import platform
import re
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from .. import _platform as _platform
from .. import registry as _registry
from ..detect import packages as _packages

log = logging.getLogger("pqc-readiness")


# ---------------------------------------------------------------------------
# OpenPGP algorithm tables (IANA "OpenPGP Public Key Algorithms")
# ---------------------------------------------------------------------------

# id -> (name, capability, pqc_category).  capability is "sign", "encrypt"
# or "both"; pqc_category uses the report-wide buckets classical / hybrid /
# pure_pqc.  RFC 9580 for 1-28, RFC 9980 for 30-36.
OPENPGP_ALGORITHMS: dict[int, tuple[str, str, str]] = {
    1: ("RSA", "both", "classical"),
    2: ("RSA (encrypt-only)", "encrypt", "classical"),
    3: ("RSA (sign-only)", "sign", "classical"),
    16: ("Elgamal", "encrypt", "classical"),
    17: ("DSA", "sign", "classical"),
    18: ("ECDH", "encrypt", "classical"),
    19: ("ECDSA", "sign", "classical"),
    22: ("EdDSALegacy", "sign", "classical"),
    25: ("X25519", "encrypt", "classical"),
    26: ("X448", "encrypt", "classical"),
    27: ("Ed25519", "sign", "classical"),
    28: ("Ed448", "sign", "classical"),
    30: ("ML-DSA-65+Ed25519", "sign", "hybrid"),
    31: ("ML-DSA-87+Ed448", "sign", "hybrid"),
    32: ("SLH-DSA-SHAKE-128s", "sign", "pure_pqc"),
    33: ("SLH-DSA-SHAKE-128f", "sign", "pure_pqc"),
    34: ("SLH-DSA-SHAKE-256s", "sign", "pure_pqc"),
    35: ("ML-KEM-768+X25519", "encrypt", "hybrid"),
    36: ("ML-KEM-1024+X448", "encrypt", "hybrid"),
}

# Curve OIDs used by ECDSA / ECDH / EdDSALegacy keys (RFC 9580 §9.2).
_CURVE_OIDS: dict[str, str] = {
    "1.2.840.10045.3.1.7": "NIST P-256",
    "1.3.132.0.34": "NIST P-384",
    "1.3.132.0.35": "NIST P-521",
    "1.3.36.3.3.2.8.1.1.7": "brainpoolP256r1",
    "1.3.36.3.3.2.8.1.1.11": "brainpoolP384r1",
    "1.3.36.3.3.2.8.1.1.13": "brainpoolP512r1",
    "1.3.6.1.4.1.11591.15.1": "Ed25519",
    "1.3.6.1.4.1.3029.1.5.1": "Curve25519",
}

_PQC_RANK = {"classical": 0, "hybrid": 1, "pure_pqc": 2}

_PKT_SIGNATURE = 2
_PKT_PUBLIC_KEY = 6
_PKT_USER_ID = 13
_PKT_PUBLIC_SUBKEY = 14


class KeyParseError(ValueError):
    """A key file or keyring could not be parsed; the source is reported
    with an error and skipped, never partially trusted."""


# ---------------------------------------------------------------------------
# OpenPGP packet parsing (RFC 9580 §4)
# ---------------------------------------------------------------------------


_ARMOR_RE = re.compile(
    r"-----BEGIN PGP PUBLIC KEY BLOCK-----(.*?)-----END PGP PUBLIC KEY BLOCK-----",
    re.S,
)


def dearmor(text: str) -> list[bytes]:
    """Every ASCII-armored public key block in `text`, decoded.  Armor
    headers (``Version:`` ...) end at the first blank line; the CRC24
    line, optional since RFC 9580, is dropped."""
    out: list[bytes] = []
    for m in _ARMOR_RE.finditer(text):
        lines = [ln.strip() for ln in m.group(1).strip("\r\n").splitlines()]
        if any(":" in ln for ln in lines[:1]) or "" in lines:
            # Header lines precede the first blank line.
            lines = lines[lines.index("") + 1 :] if "" in lines else lines
        body = "".join(ln for ln in lines if ln and not ln.startswith("="))
        try:
            out.append(base64.b64decode(body, validate=True))
        except (binascii.Error, ValueError) as e:
            raise KeyParseError(f"bad armor base64: {e}") from e
    return out


def iter_packets(data: bytes) -> Iterator[tuple[int, bytes]]:
    """(tag, body) for each OpenPGP packet, old or new format.  Partial
    body lengths only occur in literal/compressed data, never in key
    material, so they are rejected."""
    pos = 0
    n = len(data)
    while pos < n:
        hdr = data[pos]
        if not hdr & 0x80:
            raise KeyParseError(f"invalid packet header 0x{hdr:02x} at {pos}")
        pos += 1
        if hdr & 0x40:  # new format
            tag = hdr & 0x3F
            if pos >= n:
                raise KeyParseError("truncated packet length")
            b0 = data[pos]
            if b0 < 192:
                length, pos = b0, pos + 1
            elif b0 < 224:
                if pos + 1 >= n:
                    raise KeyParseError("truncated packet length")
                length = ((b0 - 192) << 8) + data[pos + 1] + 192
                pos += 2
            elif b0 == 255:
                if pos + 5 > n:
                    raise KeyParseError("truncated packet length")
                length = struct.unpack_from(">I", data, pos + 1)[0]
                pos += 5
            else:
                raise KeyParseError("partial body length in key data")
        else:  # old format
            tag = (hdr >> 2) & 0x0F
            ltype = hdr & 0x03
            if ltype == 3:
                length = n - pos
            else:
                size = (1, 2, 4)[ltype]
                if pos + size > n:
                    raise KeyParseError("truncated packet length")
                length = int.from_bytes(data[pos : pos + size], "big")
                pos += size
        if pos + length > n:
            raise KeyParseError(f"packet (tag {tag}) overruns data")
        yield tag, data[pos : pos + length]
        pos += length


def _mpi_bits(body: bytes, pos: int) -> int:
    if pos + 2 > len(body):
        raise KeyParseError("truncated MPI")
    return int(struct.unpack_from(">H", body, pos)[0])


def parse_public_key_packet(tag: int, body: bytes) -> dict[str, Any]:
    """Describe one public-key or public-subkey packet: version, algorithm,
    size or curve, creation time, key ID and fingerprint (RFC 9580 §5.5.2,
    §5.5.4).  Version 3 keys are reported without a fingerprint."""
    if len(body) < 6:
        raise KeyParseError("public key packet too short")
    version = body[0]
    info: dict[str, Any] = {"version": version}
    if version == 3:
        created = struct.unpack_from(">I", body, 1)[0]
        algo = body[7] if len(body) > 7 else -1
        material = 8
        info["fingerprint"] = None
        info["key_id"] = None
    elif version in (4, 5, 6):
        created = struct.unpack_from(">I", body, 1)[0]
        algo = body[5]
        material = 6
        if version in (5, 6):
            material += 4  # four-octet key material length
        if version == 4:
            digest = hashlib.sha1(  # noqa: S324 - RFC 9580 v4 fingerprint
                b"\x99" + struct.pack(">H", len(body)) + body
            ).hexdigest()
            info["key_id"] = digest[-16:].upper()
        else:
            prefix = b"\x9b" if version == 6 else b"\x9a"
            digest = hashlib.sha256(
                prefix + struct.pack(">I", len(body)) + body
            ).hexdigest()
            info["key_id"] = digest[:16].upper()
        info["fingerprint"] = digest.upper()
    else:
        raise KeyParseError(f"unsupported key packet version {version}")
    name, capability, category = OPENPGP_ALGORITHMS.get(
        algo, (f"unknown ({algo})", "unknown", "classical")
    )
    info.update(
        algorithm=name,
        algorithm_id=algo,
        capability=capability,
        pqc_category=category,
        created=datetime.fromtimestamp(created, tz=timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
    )
    if algo in (1, 2, 3, 16, 17):
        info["bits"] = _mpi_bits(body, material)
    elif algo in (18, 19, 22):
        if material >= len(body):
            raise KeyParseError("truncated curve OID")
        olen = body[material]
        oid = body[material + 1 : material + 1 + olen]
        dotted = _oid_str(oid)
        info["curve"] = _CURVE_OIDS.get(dotted, "oid:" + dotted)
    if tag == _PKT_PUBLIC_SUBKEY:
        info["subkey"] = True
    return info


def parse_openpgp_keys(data: bytes) -> list[dict[str, Any]]:
    """Every transferable public key in a binary keyring: the primary key
    with its first user ID and its subkeys.  The key's `pqc_category` is
    the most post-quantum of the primary and any signing-capable subkey,
    because that is what a package signature can be made with."""
    keys: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for tag, body in iter_packets(data):
        if tag == _PKT_PUBLIC_KEY:
            current = parse_public_key_packet(tag, body)
            current["subkeys"] = []
            keys.append(current)
        elif tag == _PKT_PUBLIC_SUBKEY and current is not None:
            sub = parse_public_key_packet(tag, body)
            sub.pop("subkey", None)
            current["subkeys"].append(sub)
        elif tag == _PKT_USER_ID and current is not None and "uid" not in current:
            current["uid"] = body.decode("utf-8", "replace")
    for key in keys:
        candidates = [key] + [
            s for s in key["subkeys"] if s["capability"] in ("sign", "both")
        ]
        key["signing_pqc_category"] = max(
            (
                c["pqc_category"]
                for c in candidates
                if c["capability"] in ("sign", "both")
            ),
            key=_PQC_RANK.__getitem__,
            default="classical",
        )
    return keys


def parse_key_blob(data: bytes) -> list[dict[str, Any]]:
    """Keys from a file that is either armored or a binary keyring.
    Armored files may carry explanatory text around the blocks (Red Hat's
    RPM-GPG-KEY-redhat-release does), so armor is searched for anywhere."""
    if b"-----BEGIN PGP PUBLIC KEY BLOCK-----" in data:
        keys: list[dict[str, Any]] = []
        for block in dearmor(data.decode("ascii", "replace")):
            keys.extend(parse_openpgp_keys(block))
        return keys
    return parse_openpgp_keys(data)


# ---------------------------------------------------------------------------
# X.509 SubjectPublicKeyInfo (apk keys)
# ---------------------------------------------------------------------------

_SPKI_ALGORITHMS: dict[str, tuple[str, str]] = {
    "1.2.840.113549.1.1.1": ("RSA", "classical"),
    "1.2.840.10045.2.1": ("ECDSA", "classical"),
    "1.3.101.112": ("Ed25519", "classical"),
    "1.3.101.113": ("Ed448", "classical"),
    "2.16.840.1.101.3.4.3.17": ("ML-DSA-44", "pure_pqc"),
    "2.16.840.1.101.3.4.3.18": ("ML-DSA-65", "pure_pqc"),
    "2.16.840.1.101.3.4.3.19": ("ML-DSA-87", "pure_pqc"),
}
_SPKI_CURVES = {
    "1.2.840.10045.3.1.7": "NIST P-256",
    "1.3.132.0.34": "NIST P-384",
    "1.3.132.0.35": "NIST P-521",
}


def _der(buf: bytes, pos: int) -> tuple[int, int, int]:
    """(tag, value start, value end) of the DER element at `pos`."""
    if pos + 2 > len(buf):
        raise KeyParseError("truncated DER")
    tag, ln = buf[pos], buf[pos + 1]
    pos += 2
    if ln & 0x80:
        nb = ln & 0x7F
        if nb == 0 or nb > 4 or pos + nb > len(buf):
            raise KeyParseError("bad DER length")
        ln = int.from_bytes(buf[pos : pos + nb], "big")
        pos += nb
    if pos + ln > len(buf):
        raise KeyParseError("DER element overruns data")
    return tag, pos, pos + ln


def _oid_str(value: bytes) -> str:
    if not value:
        raise KeyParseError("empty OID")
    parts = [str(min(value[0] // 40, 2)), str(value[0] - 40 * min(value[0] // 40, 2))]
    acc = 0
    for b in value[1:]:
        acc = (acc << 7) | (b & 0x7F)
        if not b & 0x80:
            parts.append(str(acc))
            acc = 0
    return ".".join(parts)


def parse_spki_pem(text: str) -> dict[str, Any]:
    """Algorithm, size / curve and SHA-256 fingerprint of a PEM
    ``PUBLIC KEY`` (SubjectPublicKeyInfo), as used by apk."""
    m = re.search(r"-----BEGIN (?:RSA )?PUBLIC KEY-----(.*?)-----END", text, re.S)
    if not m:
        raise KeyParseError("no PEM public key")
    try:
        der = base64.b64decode("".join(m.group(1).split()), validate=True)
    except (binascii.Error, ValueError) as e:
        raise KeyParseError(f"bad PEM base64: {e}") from e
    tag, s, spki_end = _der(der, 0)
    if tag != 0x30:
        raise KeyParseError("SPKI is not a SEQUENCE")
    tag, a_s, a_e = _der(der, s)  # AlgorithmIdentifier
    tag, o_s, o_e = _der(der, a_s)
    if tag != 0x06:
        raise KeyParseError("AlgorithmIdentifier has no OID")
    oid = _oid_str(der[o_s:o_e])
    name, category = _SPKI_ALGORITHMS.get(oid, (f"oid:{oid}", "classical"))
    info: dict[str, Any] = {
        "version": None,
        "algorithm": name,
        "algorithm_oid": oid,
        "capability": "sign",
        "pqc_category": category,
        "signing_pqc_category": category,
        "fingerprint": hashlib.sha256(der[0:spki_end]).hexdigest().upper(),
        "key_id": None,
        "subkeys": [],
    }
    if o_e < a_e:
        ptag, p_s, p_e = _der(der, o_e)
        if ptag == 0x06:
            info["curve"] = _SPKI_CURVES.get(
                _oid_str(der[p_s:p_e]), "oid:" + _oid_str(der[p_s:p_e])
            )
    if name == "RSA":
        tag, b_s, b_e = _der(der, a_e)  # BIT STRING
        if tag != 0x03:
            raise KeyParseError("SPKI has no BIT STRING")
        tag, r_s, _ = _der(der, b_s + 1)  # RSAPublicKey SEQUENCE
        tag, n_s, n_e = _der(der, r_s)  # modulus INTEGER
        modulus = der[n_s:n_e].lstrip(b"\x00")
        info["bits"] = len(modulus) * 8 - (
            8 - modulus[0].bit_length() if modulus else 0
        )
    return info


# ---------------------------------------------------------------------------
# Host paths
# ---------------------------------------------------------------------------


def _host(p: str) -> Path:
    """Host path under --host-mount.  Package-manager trust stores live
    outside the namespaces host_path() redirects (/var/lib/rpm,
    /usr/share/pacman ...), and they are always host state, so every
    path here is prefixed."""
    return Path(_platform.HOST_PREFIX + p) if _platform.HOST_PREFIX else Path(p)


def _read(path: Path, limit: int = 16 * 1024 * 1024) -> bytes:
    if path.stat().st_size > limit:
        raise KeyParseError(f"{path} larger than {limit} bytes; skipped")
    return path.read_bytes()


# ---------------------------------------------------------------------------
# rpm: imported keys (gpg-pubkey pseudo-packages) and repo key files
# ---------------------------------------------------------------------------

_RPMTAG_NAME = 1000
_RPMTAG_DESCRIPTION = 1005


def _rpm_header_strings(blob: bytes, tags: tuple[int, ...]) -> dict[int, str]:
    """First string value of each wanted tag in an rpmdb header blob,
    bounds-checked like packages.parse_rpm_header."""
    if len(blob) < 8:
        raise KeyParseError("rpm header blob too short")
    il, dl = struct.unpack_from(">II", blob, 0)
    base = 8 + 16 * il
    if il == 0 or base + dl > len(blob):
        raise KeyParseError("rpm header blob truncated")
    out: dict[int, str] = {}
    for tag, typ, off, _cnt in struct.iter_unpack(">IIII", blob[8:base]):
        if tag in tags and typ in (6, 8, 9) and off < dl:
            start = base + off
            end = blob.find(b"\0", start, base + dl)
            if end >= 0:
                out[tag] = blob[start:end].decode("utf-8", "replace")
    return out


def _rpmdb_pubkey_texts(db: tuple[str, Path, str]) -> list[str]:
    """Armored public keys of the `gpg-pubkey` entries, read in-process.
    Raises packages.RpmdbError / KeyParseError so callers fall back."""
    host_dir, local_dir, backend = db
    texts: list[str] = []
    if backend == "sqlite":
        blobs = _packages._fetch_rpmdb_sqlite(
            local_dir / "rpmdb.sqlite",
            "SELECT blob FROM Packages WHERE hnum IN "
            "(SELECT hnum FROM Name WHERE key = ?)",
            ("gpg-pubkey",),
        )
    else:
        db_file = local_dir / _packages._RPMDB_FILE_BY_BACKEND[backend]
        reader = _packages._RPMDB_BLOB_READERS[backend]
        fd = os.open(db_file, os.O_RDONLY)
        try:
            blobs = list(reader(fd, os.fstat(fd).st_size))
        finally:
            os.close(fd)
    for blob in blobs:
        fields = _rpm_header_strings(blob, (_RPMTAG_NAME, _RPMTAG_DESCRIPTION))
        if fields.get(_RPMTAG_NAME) == "gpg-pubkey" and _RPMTAG_DESCRIPTION in fields:
            texts.append(fields[_RPMTAG_DESCRIPTION])
    return texts


def _rpm_cli_pubkey_texts(db: tuple[str, Path, str] | None) -> list[str]:
    """Fallback: `rpm -q gpg-pubkey` description fields (armored keys),
    pointed at the host under --host-mount."""
    argv = ["rpm", "-q", "gpg-pubkey", "--queryformat", "%{DESCRIPTION}\\n"]
    if _platform.HOST_PREFIX and db is not None:
        argv[1:1] = ["--root", _platform.HOST_PREFIX, "--dbpath", db[0]]
    rc, out = _platform._run(argv, timeout=15)
    if rc != 0 and "-----BEGIN PGP" not in out:
        raise KeyParseError(f"rpm -q gpg-pubkey failed (rc={rc})")
    return [m.group(0) for m in _ARMOR_RE.finditer(out)]


_REPO_DIRS = ("/etc/yum.repos.d", "/etc/zypp/repos.d")


def _repo_key_files(os_release: dict[str, Any]) -> list[str]:
    """Local key files referenced by `gpgkey=file://` in enabled repos.
    $releasever / $basearch are expanded from the host; anything else
    that remains a variable is globbed."""
    version = str(os_release.get("version_id") or "")
    subs = {
        "releasever": version,
        "releasever_major": version.split(".")[0],
        "basearch": platform.machine(),
        "arch": platform.machine(),
    }
    found: list[str] = []
    for d in _REPO_DIRS:
        root = _host(d)
        if not root.is_dir():
            continue
        for repo in sorted(root.glob("*.repo")):
            try:
                text = repo.read_text(errors="replace")
            except OSError as e:
                log.debug("signing keys: cannot read %s: %s", repo, e)
                continue
            for section in re.split(r"^\s*\[[^\]]+\]\s*$", text, flags=re.M)[1:]:
                kv = dict(
                    (k.strip().lower(), v.strip())
                    for k, _, v in (
                        ln.partition("=") for ln in section.splitlines() if "=" in ln
                    )
                )
                if kv.get("enabled", "1").strip() not in ("1", "true", "yes"):
                    continue
                for url in re.split(r"[\s,]+", kv.get("gpgkey", "")):
                    if not url.startswith("file://"):
                        continue
                    path = re.sub(
                        r"\$\{?(\w+)\}?",
                        lambda m: subs.get(m.group(1), "*"),
                        url[len("file://") :],
                    )
                    if path not in found:
                        found.append(path)
    return found


def _rpm_sources() -> Iterator[tuple[str, str, list[dict[str, Any]] | Exception]]:
    db = _packages.locate_rpmdb()
    keys: list[dict[str, Any]] = []
    try:
        if db is None:
            raise _packages.RpmdbError("no rpm database found")
        texts = _rpmdb_pubkey_texts(db)
        method = f"rpmdb-{db[2]}"
    except (_packages.RpmdbError, KeyParseError, OSError) as e:
        log.debug("signing keys: in-process rpmdb read failed (%s); trying rpm CLI", e)
        if _platform.HOST_PREFIX and db is None:
            yield "rpmdb", "rpm database", e
            texts, method = [], ""
        else:
            try:
                texts = _rpm_cli_pubkey_texts(db)
                method = "rpm-cli"
            except KeyParseError as e2:
                yield "rpmdb", "rpm database", e2
                texts, method = [], ""
    if method:
        for t in texts:
            try:
                keys.extend(parse_key_blob(t.encode("ascii", "replace")))
            except KeyParseError as e:
                log.debug("signing keys: unparsable imported key: %s", e)
        yield "rpmdb", f"{db[0] if db else 'rpm'} ({method})", keys


# ---------------------------------------------------------------------------
# apt, pacman, apk
# ---------------------------------------------------------------------------

_APT_SOURCE_DIRS = ("/etc/apt/sources.list", "/etc/apt/sources.list.d")


def _apt_signed_by() -> tuple[list[str], list[str]]:
    """(keyring paths, inline armored keys) named by signed-by in one-line
    `.list` entries and deb822 `.sources` stanzas."""
    paths: list[str] = []
    inline: list[str] = []
    files: list[Path] = []
    for d in _APT_SOURCE_DIRS:
        p = _host(d)
        if p.is_file():
            files.append(p)
        elif p.is_dir():
            files.extend(sorted(p.glob("*.list")) + sorted(p.glob("*.sources")))
    for f in files:
        try:
            text = f.read_text(errors="replace")
        except OSError as e:
            log.debug("signing keys: cannot read %s: %s", f, e)
            continue
        if f.suffix == ".sources":
            for stanza in re.split(r"\n\s*\n", text):
                m = re.search(r"^Signed-By:(.*(?:\n[ \t].*)*)", stanza, re.M | re.I)
                if not m:
                    continue
                value = m.group(1)
                if "BEGIN PGP PUBLIC KEY BLOCK" in value:
                    # deb822 continuation lines: strip one leading space; a
                    # lone "." stands for an empty line.
                    lines = [
                        ln[1:] if ln[:1] in " \t" else ln for ln in value.splitlines()
                    ]
                    inline.append(
                        "\n".join("" if ln.strip() == "." else ln for ln in lines)
                    )
                else:
                    paths.extend(v for v in value.split() if v.startswith("/"))
        else:
            for m in re.finditer(r"signed-by=([^\s\]]+)", text):
                paths.extend(v for v in m.group(1).split(",") if v.startswith("/"))
    return list(dict.fromkeys(paths)), inline


def _file_sources(
    origin: str, files: list[Path]
) -> Iterator[tuple[str, str, list[dict[str, Any]] | Exception]]:
    for f in files:
        try:
            yield origin, str(f), parse_key_blob(_read(f))
        except (KeyParseError, OSError) as e:
            yield origin, str(f), e


def _strip_prefix(p: Path) -> str:
    s = str(p)
    pre = _platform.HOST_PREFIX
    return s[len(pre) :] if pre and s.startswith(pre) else s


def _apt_sources() -> Iterator[tuple[str, str, list[dict[str, Any]] | Exception]]:
    trusted: list[Path] = []
    main = _host("/etc/apt/trusted.gpg")
    if main.is_file():
        trusted.append(main)
    d = _host("/etc/apt/trusted.gpg.d")
    if d.is_dir():
        trusted.extend(sorted(p for p in d.iterdir() if p.suffix in (".gpg", ".asc")))
    yield from _file_sources("apt-trusted", trusted)
    paths, inline = _apt_signed_by()
    yield from _file_sources("apt-signed-by", [_host(p) for p in paths])
    for i, text in enumerate(inline):
        try:
            yield "apt-signed-by", f"inline #{i + 1}", parse_key_blob(text.encode())
        except KeyParseError as e:
            yield "apt-signed-by", f"inline #{i + 1}", e


def _pacman_sources() -> Iterator[tuple[str, str, list[dict[str, Any]] | Exception]]:
    root = _host("/usr/share/pacman/keyrings")
    if not root.is_dir():
        return
    trusted: set[str] = set()
    for t in root.glob("*-trusted"):
        try:
            trusted.update(
                ln.split(":")[0].strip().upper()
                for ln in t.read_text(errors="replace").splitlines()
                if ln.strip() and not ln.startswith("#")
            )
        except OSError as e:
            log.debug("signing keys: cannot read %s: %s", t, e)
    for origin, src, res in _file_sources("pacman-keyring", sorted(root.glob("*.gpg"))):
        if isinstance(res, list) and trusted:
            res = [k for k in res if (k.get("fingerprint") or "") in trusted]
        yield origin, src, res


def _apk_sources() -> Iterator[tuple[str, str, list[dict[str, Any]] | Exception]]:
    root = _host("/etc/apk/keys")
    if not root.is_dir():
        return
    for f in sorted(root.glob("*.pub")):
        try:
            yield (
                "apk-keys",
                str(f),
                [parse_spki_pem(_read(f).decode("ascii", "replace"))],
            )
        except (KeyParseError, OSError, UnicodeDecodeError) as e:
            yield "apk-keys", str(f), e


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def scan_signing_keys(os_release: dict[str, Any] | None = None) -> dict[str, Any]:
    """Inventory the package manager's trusted signing keys.

    Returns ``{available, family, sources[], keys[], summary}``; keys are
    de-duplicated by fingerprint, each listing every source that carries
    it.  ``available`` is false when the family has no supported package
    manager or no trust store was found."""
    os_release = os_release or {}
    family = os_release.get("family", "unknown")
    if family in ("rhel", "suse"):
        gen = list(_rpm_sources())
        repo_files = [_host(p) for p in _repo_key_files(os_release)]
        expanded: list[Path] = []
        for f in repo_files:
            if any(c in str(f) for c in "*?["):
                expanded.extend(
                    sorted(Path(f.anchor).glob(str(f.relative_to(f.anchor))))
                )
            elif f.is_file():
                expanded.append(f)
            else:
                # An enabled repo trusting a key file that is not there is
                # worth surfacing, not skipping.
                gen.append(
                    (
                        "repo-gpgkey",
                        str(f),
                        KeyParseError("referenced by an enabled repo but missing"),
                    )
                )
        gen.extend(_file_sources("repo-gpgkey", expanded))
    elif family == "debian":
        gen = list(_apt_sources())
    elif family == "arch":
        gen = list(_pacman_sources())
    elif family == "alpine":
        gen = list(_apk_sources())
    else:
        return {
            "available": False,
            "family": family,
            "reason": f"no package-signing key source known for family={family}",
        }

    by_fp: dict[str, dict[str, Any]] = {}
    unkeyed: list[dict[str, Any]] = []
    sources: list[dict[str, Any]] = []
    for origin, src, res in gen:
        src_disp = _strip_prefix(Path(src)) if src.startswith("/") else src
        if isinstance(res, Exception):
            sources.append(
                {"origin": origin, "source": src_disp, "keys": 0, "error": str(res)}
            )
            continue
        sources.append({"origin": origin, "source": src_disp, "keys": len(res)})
        for key in res:
            fp = key.get("fingerprint")
            if fp is None:
                key["origins"] = [{"origin": origin, "source": src_disp}]
                unkeyed.append(key)
                continue
            entry = by_fp.setdefault(fp, {**key, "origins": []})
            entry["origins"].append({"origin": origin, "source": src_disp})
    keys = sorted(by_fp.values(), key=lambda k: k["fingerprint"]) + unkeyed
    if not sources:
        return {
            "available": False,
            "family": family,
            "reason": "no package-signing trust store found",
        }
    counts = {"classical": 0, "hybrid": 0, "pure_pqc": 0}
    for k in keys:
        counts[k["signing_pqc_category"]] += 1
    result: dict[str, Any] = {
        "available": True,
        "family": family,
        "sources": sources,
        "keys": keys,
        "summary": {
            "total": len(keys),
            **counts,
            "all_classical": bool(keys) and counts["hybrid"] + counts["pure_pqc"] == 0,
        },
    }
    note = _platform.host_fs_unavailable_note(
        "Package-signing key inventory", "the package manager's trust store"
    )
    if note:
        result.update(note)
    return result


@_registry.register_arguments(52)
def add_arguments(ap: argparse.ArgumentParser) -> None:
    ap.add_argument(
        "--scan-signing-keys",
        action="store_true",
        help=(
            "inventory the package manager's trusted signing keys (rpm, apt, "
            "pacman, apk): algorithm, size, fingerprint; flags all-classical "
            "trust anchors"
        ),
    )
