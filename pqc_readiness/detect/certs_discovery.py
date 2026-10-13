"""Filesystem certificate, private-key and keystore discovery (#108).

Opt-in with --scan-crypto-material.  Walks configurable paths (host-mount
aware), classifies every certificate found (leaf vs CA, key algorithm and
size, PQC category, expiry), and records private keys and Java keystores
as *metadata only*.

Private-key policy: key bytes are read only to compute the file's SHA-256
and to see the PEM header label; nothing derived from the key body is
parsed, kept or emitted.  A key's algorithm and size come from its
public half: a certificate in the same file, or a certificate with the
same file stem (reported as a heuristic).
"""

from __future__ import annotations

import argparse
import hashlib
import logging
import os
import re
import shutil
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .. import _platform
from .. import registry as _registry
from . import certs as _certs
from . import packages as _packages

log = logging.getLogger("pqc-readiness")


# Where service certificates and keys usually live.  Trust-store
# directories are included on purpose: leaf certs (e.g. mod_ssl's
# localhost.crt) sit next to the CA bundles, and the role field tells
# them apart.  SSH host keys are left to the sshd detection (#105).
CRYPTO_MATERIAL_DEFAULT_PATHS: list[str] = [
    "/etc/pki",
    "/etc/ssl",
    "/etc/httpd",
    "/etc/nginx",
    "/etc/letsencrypt",
    "/etc/haproxy",
    "/etc/postfix",
    "/etc/dovecot",
    "/etc/openldap",
    "/etc/ipa",
    "/etc/dirsrv",
    "/etc/kubernetes/pki",
    "/var/lib/kubelet/pki",
    "/etc/containers/certs.d",
    "/etc/docker/certs.d",
    "/usr/lib/jvm",
]

CRYPTO_MATERIAL_MAX_FILES_DEFAULT = 5000
# PEM/DER certificate and key files are a few KB; anything above this is
# not one, so it is skipped rather than read.
MAX_PEM_FILE_BYTES = 1024 * 1024
MAX_KEYSTORE_BYTES = 32 * 1024 * 1024

_CERT_SUFFIXES = {".pem", ".crt", ".cer", ".der", ".cert"}
_KEY_SUFFIXES = {".key", ".pem"}
_KEYSTORE_SUFFIXES = {".jks", ".p12", ".pfx", ".keystore", ".truststore", ".jceks"}
_KEYSTORE_NAMES = {"cacerts"}

# The well-known default password of JDK cacerts (documented by every JDK
# vendor); no other keystore is ever opened with a password.
_CACERTS_STOREPASS = "changeit"

# PEM private-key labels -> key type.  "PRIVATE KEY" (PKCS#8) does not
# name its algorithm in the header; it is resolved from the public half.
_PEM_KEY_LABELS: dict[bytes, str] = {
    b"RSA PRIVATE KEY": "RSA",
    b"EC PRIVATE KEY": "EC",
    b"DSA PRIVATE KEY": "DSA",
    b"PRIVATE KEY": "PKCS#8",
    b"ENCRYPTED PRIVATE KEY": "PKCS#8 (encrypted)",
    b"OPENSSH PRIVATE KEY": "OpenSSH",
}
_PEM_KEY_RE = re.compile(
    rb"-----BEGIN ((?:RSA |EC |DSA |ENCRYPTED |OPENSSH )?PRIVATE KEY)-----"
)
_PEM_ENCRYPTED_HDR = b"Proc-Type: 4,ENCRYPTED"

# Migration milestones the expiry flags are measured against: NIST IR 8547
# (initial public draft) deprecates quantum-vulnerable algorithms after
# 2030 and disallows them after 2035; OMB M-26-15 sets 2030-12-31 for PQC
# key establishment on high-value systems.
_DEADLINE_2030 = datetime(2030, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
_DEADLINE_2035 = datetime(2035, 12, 31, 23, 59, 59, tzinfo=timezone.utc)

_JKS_MAGIC = 0xFEEDFEED
_JCEKS_MAGIC = 0xCECECECE


def expiry_bucket(not_after: str, now: datetime | None = None) -> str:
    """`expired`, `lt_30d`, `lt_90d`, `lt_1y` or `gt_1y`."""
    now = now or datetime.now(timezone.utc)
    end = datetime.fromisoformat(not_after)
    if end <= now:
        return "expired"
    left = end - now
    if left < timedelta(days=30):
        return "lt_30d"
    if left < timedelta(days=90):
        return "lt_90d"
    if left < timedelta(days=365):
        return "lt_1y"
    return "gt_1y"


def _host_root(path: str) -> Path:
    """The process-visible location of host path `path` (under the
    --host-mount prefix when one is set)."""
    return Path(_platform.HOST_PREFIX + path) if _platform.HOST_PREFIX else Path(path)


def _host_rel(local: Path) -> str:
    """Host-relative path for output."""
    s = str(local)
    prefix = _platform.HOST_PREFIX
    return s[len(prefix) :] if prefix and s.startswith(prefix) else s


def _classify_file(path: Path) -> str | None:
    name = path.name
    suffix = path.suffix.lower()
    if name in _KEYSTORE_NAMES or suffix in _KEYSTORE_SUFFIXES:
        return "keystore"
    if suffix in _CERT_SUFFIXES or suffix in _KEY_SUFFIXES or suffix == ".0":
        return "pem"
    return None


def _walk(
    roots: list[str], max_files: int
) -> tuple[list[tuple[Path, str]], list[str], bool]:
    """Candidate files under the host roots, in a deterministic order.
    Symlinked directories are not followed (no escapes from the host
    tree, no loops); symlinked files are resolved inside the host prefix
    and de-duplicated by their resolved path."""
    found: list[tuple[Path, str]] = []
    seen: set[str] = set()
    scanned: list[str] = []
    truncated = False
    for root in roots:
        local = _host_root(root)
        if not local.is_dir():
            continue
        scanned.append(root)
        for dirpath, dirnames, filenames in os.walk(local, followlinks=False):
            dirnames.sort()
            for fname in sorted(filenames):
                p = Path(dirpath) / fname
                kind = _classify_file(p)
                if kind is None:
                    continue
                try:
                    real = _packages.resolve_under_prefix(
                        _host_rel(p), _platform.HOST_PREFIX
                    )
                except Exception as e:  # noqa: BLE001 - resolution errors only skip the file
                    log.debug("crypto_material: cannot resolve %s: %s", p, e)
                    continue
                if real in seen:
                    continue
                seen.add(real)
                if len(found) >= max_files:
                    truncated = True
                    return found, scanned, truncated
                found.append((_host_root(real), kind))
    return found, scanned, truncated


def _mode_info(st: os.stat_result) -> dict[str, Any]:
    mode = stat.S_IMODE(st.st_mode)
    return {
        "mode": f"{mode:04o}",
        "group_readable": bool(mode & stat.S_IRGRP),
        "world_readable": bool(mode & stat.S_IROTH),
    }


def _read_pem_file(path: Path) -> tuple[list[bytes], dict[str, Any] | None]:
    """Certificates (DER) in a PEM/DER file plus private-key metadata when
    the file holds a key.  The key dict carries only the header-derived
    type, the file hash and permission bits; key bytes never leave this
    function."""
    try:
        st = path.stat()
        if st.st_size > MAX_PEM_FILE_BYTES:
            log.debug("crypto_material: skipping oversized %s", path)
            return [], None
        data = path.read_bytes()
    except OSError as e:
        log.debug("crypto_material: cannot read %s: %s", path, e)
        return [], None
    certs = (
        _certs._certs_in_file(path)
        if b"CERTIFICATE" in data or data[:1] == b"\x30"
        else []
    )
    key: dict[str, Any] | None = None
    m = _PEM_KEY_RE.search(data)
    if m:
        label = m.group(1)
        key = {
            "path": _host_rel(path),
            "sha256": hashlib.sha256(data).hexdigest(),
            "key_type": _PEM_KEY_LABELS.get(label, "unknown"),
            "encrypted": label.startswith(b"ENCRYPTED") or _PEM_ENCRYPTED_HDR in data,
            **_mode_info(st),
        }
    del data
    return certs, key


def _parse_jks_certificates(data: bytes) -> tuple[list[bytes], int]:
    """Certificates in a JKS keystore, read without a password: trusted-
    certificate entries and the public certificate chains of private-key
    entries are stored in the clear.  The (encrypted) private-key blobs
    are skipped by length and never kept.  Returns (certs, number of
    private-key entries).  Integrity is not verified (that needs the
    password), which is acceptable for an inventory of public certs."""
    pos = 0

    def u32() -> int:
        nonlocal pos
        if pos + 4 > len(data):
            raise _certs.DERError("truncated JKS")
        v = int.from_bytes(data[pos : pos + 4], "big")
        pos += 4
        return v

    def skip_utf() -> None:
        nonlocal pos
        if pos + 2 > len(data):
            raise _certs.DERError("truncated JKS string")
        n = int.from_bytes(data[pos : pos + 2], "big")
        pos += 2 + n

    def blob() -> bytes:
        nonlocal pos
        n = u32()
        if pos + n > len(data):
            raise _certs.DERError("JKS entry runs past the file")
        b = data[pos : pos + n]
        pos += n
        return b

    if u32() != _JKS_MAGIC:
        raise _certs.DERError("not a JKS keystore")
    if u32() not in (1, 2):
        raise _certs.DERError("unsupported JKS version")
    count = u32()
    if count > 100_000:
        raise _certs.DERError("implausible JKS entry count")
    certs: list[bytes] = []
    private_entries = 0
    for _ in range(count):
        tag = u32()
        skip_utf()  # alias
        pos += 8  # creation timestamp
        if tag == 1:  # private key entry
            private_entries += 1
            n = u32()
            pos += n  # encrypted key: skipped, never read into a value
            for _ in range(u32()):  # certificate chain (public)
                skip_utf()
                certs.append(blob())
        elif tag == 2:  # trusted certificate entry
            skip_utf()
            certs.append(blob())
        else:
            raise _certs.DERError(f"unknown JKS entry tag {tag}")
    return certs, private_entries


def _keytool_list_cacerts(path: Path) -> list[bytes] | None:
    """`keytool -list -rfc` for a JDK cacerts file (PKCS#12 on modern
    JDKs), using the published default password.  None when keytool is
    absent or fails."""
    if not shutil.which("keytool"):
        return None
    rc, out = _platform._run(
        [
            "keytool",
            "-list",
            "-rfc",
            "-keystore",
            str(path),
            "-storepass",
            _CACERTS_STOREPASS,
        ],
        timeout=30,
    )
    if rc != 0:
        log.debug("crypto_material: keytool failed on %s (rc=%s)", path, rc)
        return None
    import base64
    import binascii

    certs: list[bytes] = []
    for body in _certs._PEM_CERT_RE.findall(out.encode()):
        try:
            certs.append(base64.b64decode(b"".join(body.split()), validate=True))
        except (binascii.Error, ValueError):
            continue
    return certs


def _read_keystore(path: Path) -> tuple[dict[str, Any], list[bytes]]:
    rec: dict[str, Any] = {"path": _host_rel(path)}
    try:
        st = path.stat()
        rec["size_bytes"] = st.st_size
        if st.st_size > MAX_KEYSTORE_BYTES:
            rec.update(
                store_type="unknown",
                listed=False,
                reason="larger than the keystore size cap",
            )
            return rec, []
        data = path.read_bytes()
    except OSError as e:
        rec.update(
            store_type="unknown", listed=False, reason=f"unreadable: {e.strerror or e}"
        )
        return rec, []
    rec["sha256"] = hashlib.sha256(data).hexdigest()
    magic = int.from_bytes(data[:4], "big") if len(data) >= 4 else 0
    if magic == _JKS_MAGIC:
        rec["store_type"] = "jks"
        try:
            certs, private_entries = _parse_jks_certificates(data)
        except _certs.DERError as e:
            rec.update(listed=False, reason=f"unparseable JKS: {e}")
            return rec, []
        rec.update(
            listed=True, method="in-process", private_key_entries=private_entries
        )
        return rec, certs
    if magic == _JCEKS_MAGIC:
        rec.update(
            store_type="jceks",
            listed=False,
            reason="JCEKS needs a password; not opened",
        )
        return rec, []
    rec["store_type"] = "pkcs12" if data[:1] == b"\x30" else "unknown"
    if path.name == "cacerts":
        certs_kt = _keytool_list_cacerts(path)
        if certs_kt is not None:
            rec.update(listed=True, method="keytool (default cacerts password)")
            return rec, certs_kt
        rec.update(listed=False, reason="keytool not available")
        return rec, []
    rec.update(listed=False, reason="password-protected; not opened")
    return rec, []


def _cert_record(cert: dict[str, Any], now: datetime) -> dict[str, Any]:
    out = _certs.trust_store_certificate(cert)
    end = datetime.fromisoformat(cert["not_after"])
    out.update(
        expiry_bucket=expiry_bucket(cert["not_after"], now),
        valid_past_2030=end > _DEADLINE_2030,
        valid_past_2035=end > _DEADLINE_2035,
        paths=[],
    )
    return out


def scan_crypto_material(
    paths: list[str] | None = None,
    max_files: int = CRYPTO_MATERIAL_MAX_FILES_DEFAULT,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Discover certificates, private keys and keystores under `paths`
    (host paths; --host-mount aware).  See the module docstring for the
    private-key policy."""
    if max_files < 1:
        raise ValueError(f"max_files must be >= 1, got {max_files}")
    now = now or datetime.now(timezone.utc)
    roots = paths if paths is not None else CRYPTO_MATERIAL_DEFAULT_PATHS
    files, scanned, truncated = _walk(roots, max_files)
    certificates: dict[str, dict[str, Any]] = {}
    keys: list[dict[str, Any]] = []
    keystores: list[dict[str, Any]] = []
    file_certs: dict[str, list[str]] = {}  # host path -> cert sha256s in that file
    malformed = 0

    def add_cert(der: bytes, where: str) -> None:
        nonlocal malformed
        sha = hashlib.sha256(der).hexdigest()
        rec = certificates.get(sha)
        if rec is None:
            try:
                rec = _cert_record(_certs.parse_certificate(der), now)
            except _certs.DERError as e:
                malformed += 1
                log.debug("crypto_material: malformed certificate in %s: %s", where, e)
                return
            certificates[sha] = rec
        if where not in rec["paths"]:
            rec["paths"].append(where)
        file_certs.setdefault(where, []).append(sha)

    for path, kind in files:
        where = _host_rel(path)
        if kind == "keystore":
            rec, certs_in_store = _read_keystore(path)
            for der in certs_in_store:
                add_cert(der, where)
            rec["certificates_found"] = len(certs_in_store)
            keystores.append(rec)
            continue
        certs_in_file, key = _read_pem_file(path)
        for der in certs_in_file:
            add_cert(der, where)
        if key is not None:
            keys.append(key)

    _attach_public_halves(keys, certificates, file_certs)
    cert_list = list(certificates.values())
    categories = {"classical": 0, "hybrid_composite": 0, "pure_pqc": 0}
    for c in cert_list:
        categories[c["category"]] += 1
    return {
        "available": True,
        "scanned_paths": scanned,
        "files_examined": len(files),
        "max_files": max_files,
        "truncated": truncated,
        "malformed_certificates": malformed,
        "summary": {
            "certificates": len(cert_list),
            "leaf_certificates": sum(1 for c in cert_list if c["role"] == "leaf"),
            "ca_certificates": sum(1 for c in cert_list if c["role"] == "ca"),
            "cert_categories": categories,
            "expired": sum(1 for c in cert_list if c["expiry_bucket"] == "expired"),
            "valid_past_2030_classical": sum(
                1
                for c in cert_list
                if c["valid_past_2030"] and c["category"] == "classical"
            ),
            "private_keys": len(keys),
            "private_keys_world_readable": sum(1 for k in keys if k["world_readable"]),
            "keystores": len(keystores),
        },
        "certificates": cert_list,
        "private_keys": keys,
        "keystores": keystores,
    }


def _attach_public_halves(
    keys: list[dict[str, Any]],
    certificates: dict[str, dict[str, Any]],
    file_certs: dict[str, list[str]],
) -> None:
    """Give each key its algorithm/size from a public half: a leaf
    certificate in the same file (definitive) or, failing that, the
    single leaf certificate whose file has the same stem (heuristic, e.g.
    /etc/pki/tls/private/localhost.key <-> /etc/pki/tls/certs/localhost.crt)."""
    by_stem: dict[str, set[str]] = {}
    for where, shas in file_certs.items():
        for sha in shas:
            if certificates[sha]["role"] == "leaf":
                by_stem.setdefault(Path(where).stem, set()).add(sha)
    for key in keys:
        same_file = [
            s
            for s in file_certs.get(key["path"], [])
            if certificates[s]["role"] == "leaf"
        ]
        if same_file:
            sha, source = same_file[0], "certificate in the same file"
        else:
            stem_matches = by_stem.get(Path(key["path"]).stem, set())
            if len(stem_matches) != 1:
                key["public_half"] = None
                continue
            sha, source = (
                next(iter(stem_matches)),
                "certificate with the same file stem (heuristic)",
            )
        cert = certificates[sha]
        key["public_half"] = {
            "certificate_sha256": sha,
            "key_algorithm": cert["key_algorithm"],
            "key_size": cert["key_size"],
            "source": source,
        }


@_registry.register_arguments(52)
def add_arguments(ap: argparse.ArgumentParser) -> None:
    """--scan-crypto-material, --crypto-material-path, --crypto-material-max-files."""
    ap.add_argument(
        "--scan-crypto-material",
        action="store_true",
        help=(
            "discover certificates, private keys (metadata only) and Java "
            "keystores under common service paths"
        ),
    )
    ap.add_argument(
        "--crypto-material-path",
        action="append",
        metavar="PATH",
        default=None,
        help=(
            "host path to search with --scan-crypto-material (repeatable; "
            "replaces the default path list)"
        ),
    )
    ap.add_argument(
        "--crypto-material-max-files",
        type=_registry.positive_int,
        default=CRYPTO_MATERIAL_MAX_FILES_DEFAULT,
        metavar="N",
        help=(
            "cap on candidate files examined by --scan-crypto-material "
            f"(default {CRYPTO_MATERIAL_MAX_FILES_DEFAULT}); "
            "crypto_material.truncated is set when the cap is hit"
        ),
    )
