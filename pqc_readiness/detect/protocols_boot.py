"""Boot chain inventory (--scan-boot-chain, #112).

The boot chain holds the longest-lived classical signing keys on a host:
UEFI Secure Boot's PK / KEK / db, the shim's Machine Owner Keys, the key
that signs kernel modules, and the certificates IMA appraisal trusts.
CNSA 2.0 expects firmware and software signing to move to ML-DSA-87 or
LMS / XMSS by 2030, and these keys are the hardest to rotate, so the
report says which algorithms each layer uses today.

Everything is read in-process; no subprocess runs:

* UEFI variables come from efivarfs (``/sys/firmware/efi/efivars``): each
  file is a 4-byte attribute word followed by the variable's data.  PK,
  KEK, db and dbx are EFI_SIGNATURE_LIST arrays (UEFI 2.10 §32.4.1); X.509
  entries are parsed with the trust-store DER parser (#120), hash entries
  are only counted.  GUIDs are the edk2 definitions
  (MdePkg/Include/Guid/GlobalVariable.h, ImageAuthentication.h); the MOK
  variables use shim's SHIM_LOCK_GUID (rhboot/shim lib/guid.c), read from
  the kernel's ``/sys/firmware/efi/mok-variables`` copy when present
  (complete lists, no attribute word) or the ``MokListRT`` runtime
  variable otherwise.
* Kernel module signing: ``CONFIG_MODULE_SIG*`` from the running
  kernel's config, and the PKCS#7 signature appended to one module file
  (``~Module signature appended~``; struct module_signature in
  include/linux/module_signature.h), parsed for its digest and signature
  algorithm.  ML-DSA module signing (CONFIG_MODULE_SIG_KEY_TYPE_MLDSA_44 /
  _65 / _87) exists from Linux 7.0 (certs/Kconfig; absent in 6.19).
* IMA / EVM: securityfs state, the kernel command line, the IMA policy
  when readable, and the IMA certificates under ``/etc/keys/ima``.
* TPM: one read-only TPM2_GetCapability on ``/dev/tpmrm0`` for the
  specification revision and the TPM 2.0 Library v1.85 post-quantum
  algorithm IDs (TPM_ALG_MLKEM 0x00A0, TPM_ALG_MLDSA 0x00A1,
  TPM_ALG_HASH_MLDSA 0x00A2).  Those IDs are taken from wolfTPM's v1.85
  implementation (wolftpm/tpm2.h, docs/fwtpm/post-quantum.md, v4.2.0); the
  TCG specification PDFs could not be fetched for verification, and
  wolfTPM describes v1.85 as a release candidate.

Only certificates and public algorithm identifiers are reported; no key
material, signature bytes or variable contents beyond that leave this
module.
"""

from __future__ import annotations

import argparse
import errno
import gzip
import logging
import lzma
import os
import re
import select
import struct
import uuid
from pathlib import Path
from typing import Any

from .. import _platform as _platform
from .. import registry as _registry
from . import certs as _certs

log = logging.getLogger("pqc-readiness")


# ---------------------------------------------------------------------------
# UEFI
# ---------------------------------------------------------------------------

EFI_GLOBAL_VARIABLE = "8be4df61-93ca-11d2-aa0d-00e098032b8c"
EFI_IMAGE_SECURITY_DATABASE = "d719b2cb-3d3a-4596-a3bc-dad00e67656f"
SHIM_LOCK = "605dab50-e046-4300-abb6-3dd810dd8b23"

EFI_CERT_X509 = "a5c059a1-94e4-4aa7-87b5-ab155c2bf072"
EFI_CERT_SHA256 = "c1c41626-504c-4092-aca9-41f936934328"
EFI_CERT_RSA2048 = "3c5766e8-269c-4e34-aa14-ed776e85b3b6"

EFIVARS_DIR = "/sys/firmware/efi/efivars"
MOK_VARIABLES_DIR = "/sys/firmware/efi/mok-variables"

# (report key, variable name, vendor GUID).  dbx is a revocation list:
# only its size and certificate algorithms are reported.
SIGNATURE_DATABASES: tuple[tuple[str, str, str], ...] = (
    ("PK", "PK", EFI_GLOBAL_VARIABLE),
    ("KEK", "KEK", EFI_GLOBAL_VARIABLE),
    ("db", "db", EFI_IMAGE_SECURITY_DATABASE),
    ("dbx", "dbx", EFI_IMAGE_SECURITY_DATABASE),
    ("MokList", "MokListRT", SHIM_LOCK),
    ("MokListX", "MokListXRT", SHIM_LOCK),
)

# Databases whose certificates authorise boot code (dbx and MokListX
# revoke, so they don't count towards "the chain is classical").
TRUST_DATABASES = ("PK", "KEK", "db", "MokList")

# Cap per variable: real db/dbx are tens of KiB; anything larger is not a
# signature database.
MAX_VARIABLE_BYTES = 4 * 1024 * 1024


def _guid(raw: bytes) -> str:
    return str(uuid.UUID(bytes_le=raw))


def _read_efivar(name: str, guid: str) -> bytes | None:
    """Data of an efivarfs variable without its 4-byte attribute word, or
    None when absent / unreadable."""
    path = _platform.host_path(f"{EFIVARS_DIR}/{name}-{guid}")
    try:
        with path.open("rb") as fh:
            data = fh.read(MAX_VARIABLE_BYTES + 5)
    except OSError as e:
        if e.errno != errno.ENOENT:
            log.debug("boot_chain: cannot read %s: %s", path, e)
        return None
    if len(data) < 4 or len(data) > MAX_VARIABLE_BYTES + 4:
        log.debug("boot_chain: %s has implausible size %d", path, len(data))
        return None
    return data[4:]


def _read_mok_variable(name: str) -> tuple[bytes | None, str]:
    """MOK list data and where it came from.  The kernel's mok-variables
    copy holds the complete list (MokListRT can be split by shim when it
    outgrows a runtime variable), so it wins when present."""
    path = _platform.host_path(f"{MOK_VARIABLES_DIR}/{name}")
    try:
        with path.open("rb") as fh:
            data = fh.read(MAX_VARIABLE_BYTES + 1)
        if len(data) <= MAX_VARIABLE_BYTES:
            return data, "mok-variables"
    except OSError as e:
        if e.errno != errno.ENOENT:
            log.debug("boot_chain: cannot read %s: %s", path, e)
    return _read_efivar(name, SHIM_LOCK), "efivars"


def _bool_efivar(name: str) -> bool | None:
    data = _read_efivar(name, EFI_GLOBAL_VARIABLE)
    if data is None or len(data) < 1:
        return None
    return data[0] == 1


def parse_signature_lists(data: bytes) -> dict[str, Any]:
    """Parse an array of EFI_SIGNATURE_LIST structures.

    Each list: SignatureType GUID (16), SignatureListSize (u32 LE),
    SignatureHeaderSize (u32), SignatureSize (u32), the header, then
    entries of SignatureSize bytes (owner GUID 16 + data).  Certificates are
    parsed; hashes and unknown types are counted.  Malformed lists stop the
    walk and are reported in `errors` rather than raising."""
    certificates: list[dict[str, Any]] = []
    hashes = 0
    rsa2048_keys = 0
    other: dict[str, int] = {}
    errors: list[str] = []
    pos = 0
    while pos < len(data):
        if pos + 28 > len(data):
            errors.append(f"truncated signature list header at offset {pos}")
            break
        sig_type = _guid(data[pos : pos + 16])
        list_size, header_size, sig_size = struct.unpack_from("<III", data, pos + 16)
        end = pos + list_size
        first = pos + 28 + header_size
        if list_size < 28 or end > len(data) or sig_size < 16 or first > end:
            errors.append(f"malformed signature list at offset {pos}")
            break
        if (end - first) % sig_size:
            errors.append(f"signature list at offset {pos} has a partial entry")
        for entry in range(first, end - sig_size + 1, sig_size):
            payload = data[entry + 16 : entry + sig_size]
            if sig_type == EFI_CERT_X509:
                try:
                    cert = _certs.parse_certificate(payload)
                except _certs.DERError as e:
                    errors.append(f"unparsable X.509 entry: {e}")
                    continue
                certificates.append(_cert_summary(cert))
            elif sig_type == EFI_CERT_SHA256:
                hashes += 1
            elif sig_type == EFI_CERT_RSA2048:
                rsa2048_keys += 1
            else:
                other[sig_type] = other.get(sig_type, 0) + 1
        pos = end
    return {
        "certificates": certificates,
        "sha256_hashes": hashes,
        "rsa2048_keys": rsa2048_keys,
        "other_entries": other,
        "errors": errors,
    }


def _cert_summary(cert: dict[str, Any]) -> dict[str, Any]:
    """The per-certificate fields worth reporting for a boot-chain cert."""
    keys = (
        "subject",
        "issuer",
        "sha256",
        "not_after",
        "key_algorithm",
        "key_size",
        "category",
    )
    return {k: cert.get(k) for k in keys}


def detect_secure_boot() -> dict[str, Any]:
    """Secure Boot state and the algorithms of every signature database."""
    if not _platform.safe_is_dir(_platform.host_path("/sys/firmware/efi")):
        return {
            "available": False,
            "firmware": "bios",
            "reason": "no /sys/firmware/efi: legacy BIOS boot (no UEFI Secure Boot)",
        }
    efivars = _platform.host_path(EFIVARS_DIR)
    if not _platform.safe_is_dir(efivars):
        return {
            "available": False,
            "firmware": "uefi",
            "reason": f"{EFIVARS_DIR} is not mounted (efivarfs)",
        }
    try:
        with os.scandir(efivars) as it:
            next(it, None)
    except OSError as e:
        # Measured: rootless podman with default SELinux labels gets EACCES
        # on efivarfs even with /sys bind-mounted; the quadlet's
        # SecurityLabelDisable lifts it.
        log.debug("boot_chain: cannot list %s: %s", efivars, e)
        return {
            "available": False,
            "firmware": "uefi",
            "reason": (
                f"{EFIVARS_DIR} is not readable ({e.strerror}); SELinux-confined "
                "containers are denied efivarfs"
            ),
        }
    databases: dict[str, Any] = {}
    for key, name, guid in SIGNATURE_DATABASES:
        if guid == SHIM_LOCK:
            data, source = _read_mok_variable(name)
        else:
            data, source = _read_efivar(name, guid), "efivars"
        if data is None:
            databases[key] = {"present": False}
            continue
        parsed = parse_signature_lists(data)
        parsed.update(present=True, source=source)
        databases[key] = parsed
    mok_state = _read_mok_variable("MokSBStateRT")[0]
    return {
        "available": True,
        "firmware": "uefi",
        "enabled": _bool_efivar("SecureBoot"),
        "setup_mode": _bool_efivar("SetupMode"),
        "shim_validation_disabled": (mok_state[0] == 1) if mok_state else False,
        "databases": databases,
    }


# ---------------------------------------------------------------------------
# Kernel module signing
# ---------------------------------------------------------------------------

MODULE_SIG_MAGIC = b"~Module signature appended~\n"
# struct module_signature: algo, hash, id_type, signer_len, key_id_len,
# __pad[3], __be32 sig_len.
_MODULE_SIG_STRUCT = struct.Struct(">BBBBB3xI")
PKEY_ID_PKCS7 = 2
MAX_MODULE_BYTES = 64 * 1024 * 1024
# Modules sampled for a signature; one parse is enough to name the key.
MODULE_SAMPLE_LIMIT = 5

_DIGEST_OIDS: dict[str, str] = {
    "1.3.14.3.2.26": "sha1",
    "2.16.840.1.101.3.4.2.1": "sha256",
    "2.16.840.1.101.3.4.2.2": "sha384",
    "2.16.840.1.101.3.4.2.3": "sha512",
    "2.16.840.1.101.3.4.2.8": "sha3-256",
    "2.16.840.1.101.3.4.2.9": "sha3-384",
    "2.16.840.1.101.3.4.2.10": "sha3-512",
    "2.16.840.1.101.3.4.2.11": "shake128",
    "2.16.840.1.101.3.4.2.12": "shake256",
}

# PKCS#7 SignerInfo signatureAlgorithm -> (algorithm family, category).
_SIGNATURE_OIDS: dict[str, tuple[str, str]] = {
    "1.2.840.113549.1.1.1": ("RSA", "classical"),
    "1.2.840.113549.1.1.5": ("RSA", "classical"),
    "1.2.840.113549.1.1.11": ("RSA", "classical"),
    "1.2.840.113549.1.1.12": ("RSA", "classical"),
    "1.2.840.113549.1.1.13": ("RSA", "classical"),
    "1.2.840.10045.2.1": ("ECDSA", "classical"),
    "1.2.840.10045.4.3.2": ("ECDSA", "classical"),
    "1.2.840.10045.4.3.3": ("ECDSA", "classical"),
    "1.2.840.10045.4.3.4": ("ECDSA", "classical"),
    "1.3.101.112": ("Ed25519", "classical"),
    "1.3.101.113": ("Ed448", "classical"),
    "2.16.840.1.101.3.4.3.17": ("ML-DSA-44", "pure_pqc"),
    "2.16.840.1.101.3.4.3.18": ("ML-DSA-65", "pure_pqc"),
    "2.16.840.1.101.3.4.3.19": ("ML-DSA-87", "pure_pqc"),
}

_KERNEL_CONFIG_RE = re.compile(r"^(CONFIG_(?:MODULE_SIG\w*|IMA\w*|EVM\w*))=(.*)$")


def kernel_release() -> str:
    """The running (host) kernel's release string."""
    try:
        return _platform.host_path("/proc/sys/kernel/osrelease").read_text().strip()
    except OSError:
        return os.uname().release


def _kernel_dirs(release: str) -> list[str]:
    """Where the kernel's modules and config live.  Under --host-mount only
    /usr/lib/modules is redirected to the host (usr-merged distributions,
    reachable through the deployments' /usr mount); /boot and /lib/modules
    would be the scanner container's own, so they are skipped there."""
    if _platform.HOST_PREFIX:
        return [f"/usr/lib/modules/{release}"]
    return [f"/lib/modules/{release}", f"/usr/lib/modules/{release}"]


def read_kernel_config(release: str) -> tuple[dict[str, str], str | None]:
    """CONFIG_MODULE_SIG* / IMA* / EVM* settings from /boot/config-<release>,
    <modules dir>/config or /proc/config.gz, and which file they came from."""
    candidates = [] if _platform.HOST_PREFIX else [f"/boot/config-{release}"]
    candidates += [f"{d}/config" for d in _kernel_dirs(release)]
    for c in candidates:
        try:
            text = _platform.host_path(c).read_text(errors="replace")
        except OSError:
            continue
        return parse_kernel_config(text), c
    try:
        raw = _platform.host_path("/proc/config.gz").read_bytes()
        return parse_kernel_config(gzip.decompress(raw).decode(errors="replace")), (
            "/proc/config.gz"
        )
    except (OSError, EOFError, gzip.BadGzipFile) as e:
        log.debug("boot_chain: no kernel config: %s", e)
    return {}, None


def parse_kernel_config(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        m = _KERNEL_CONFIG_RE.match(line.strip())
        if m:
            out[m.group(1)] = m.group(2).strip('"')
    return out


def _decompress_module(path: Path, raw: bytes) -> bytes | None:
    name = path.name
    try:
        if name.endswith(".ko"):
            return raw
        if name.endswith(".ko.xz"):
            return lzma.decompress(raw)
        if name.endswith(".ko.gz"):
            return gzip.decompress(raw)
        if name.endswith(".ko.zst"):
            try:
                from compression import zstd  # type: ignore[import-not-found,unused-ignore]
            except ImportError:
                log.debug("boot_chain: %s is zstd; Python < 3.14 cannot read it", path)
                return None
            data: bytes = zstd.decompress(raw)
            return data
    except (lzma.LZMAError, OSError, EOFError, ValueError) as e:
        log.debug("boot_chain: cannot decompress %s: %s", path, e)
    return None


def parse_module_signature(data: bytes) -> dict[str, Any] | None:
    """Digest and signature algorithm of a module's appended PKCS#7
    signature, or None when the module is unsigned / not PKCS#7."""
    if not data.endswith(MODULE_SIG_MAGIC):
        return None
    tail = len(data) - len(MODULE_SIG_MAGIC)
    if tail < _MODULE_SIG_STRUCT.size:
        return None
    algo, hash_, id_type, signer_len, key_id_len, sig_len = (
        _MODULE_SIG_STRUCT.unpack_from(data, tail - _MODULE_SIG_STRUCT.size)
    )
    start = tail - _MODULE_SIG_STRUCT.size - sig_len
    if id_type != PKEY_ID_PKCS7 or sig_len == 0 or start < 0:
        return {"format": f"id_type {id_type}", "parsed": False}
    try:
        info = parse_pkcs7_signer(data[start : start + sig_len])
    except _certs.DERError as e:
        return {"format": "PKCS#7", "parsed": False, "reason": str(e)}
    info.update(format="PKCS#7", parsed=True)
    return info


def parse_pkcs7_signer(der: bytes) -> dict[str, Any]:
    """First SignerInfo of a CMS / PKCS#7 SignedData (RFC 5652 §5): digest
    algorithm, signature algorithm and, for RSA, the key size implied by
    the signature length."""
    tlv = _certs._der_tlv
    tag, start, stop = tlv(der, 0, len(der))
    if tag != 0x30:
        raise _certs.DERError("ContentInfo is not a SEQUENCE")
    tag, ostart, ostop = tlv(der, start, stop)
    if tag != 0x06 or _certs._der_oid(der[ostart:ostop]) != "1.2.840.113549.1.7.2":
        raise _certs.DERError("not a SignedData ContentInfo")
    tag, estart, estop = tlv(der, ostop, stop)
    if tag != 0xA0:
        raise _certs.DERError("missing [0] content")
    tag, pos, sd_stop = tlv(der, estart, estop)
    if tag != 0x30:
        raise _certs.DERError("SignedData is not a SEQUENCE")
    signer_infos = None
    while pos < sd_stop:
        tag, vstart, vstop = tlv(der, pos, sd_stop)
        signer_infos = (tag, vstart, vstop)
        pos = vstop
    if signer_infos is None or signer_infos[0] != 0x31:
        raise _certs.DERError("no signerInfos SET")
    _, sis_start, sis_stop = signer_infos
    tag, si, si_stop = tlv(der, sis_start, sis_stop)
    if tag != 0x30:
        raise _certs.DERError("SignerInfo is not a SEQUENCE")
    tag, _, pos = tlv(der, si, si_stop)  # version
    tag, sid_start, sid_stop = tlv(der, pos, si_stop)
    signer = None
    if tag == 0x30:  # IssuerAndSerialNumber
        itag, istart, istop = tlv(der, sid_start, sid_stop)
        if itag == 0x30:
            signer = _certs._der_name(der, istart, istop)
    pos = sid_stop
    digest_oid, pos = _certs._der_algorithm_oid(der, pos, si_stop)
    if pos < si_stop and der[pos] == 0xA0:  # signedAttrs
        pos = tlv(der, pos, si_stop)[2]
    sig_oid, pos = _certs._der_algorithm_oid(der, pos, si_stop)
    tag, sstart, sstop = tlv(der, pos, si_stop)
    family, category = _SIGNATURE_OIDS.get(sig_oid, (sig_oid, "unknown"))
    key_size = (sstop - sstart) * 8 if family == "RSA" and tag == 0x04 else None
    return {
        "signer": signer,
        "digest_algorithm": _DIGEST_OIDS.get(digest_oid, digest_oid),
        "signature_algorithm": family,
        "signature_algorithm_oid": sig_oid,
        "key_size": key_size,
        "category": category,
    }


def _module_candidates(release: str) -> list[Path]:
    """Module files to sample, in modules.dep order (deterministic).  When
    modules.dep can't be read (measured: SELinux-confined containers are
    denied it while the module files stay readable), walk the module tree
    in sorted order instead."""
    for base in _kernel_dirs(release):
        root = _platform.host_path(base)
        if not _platform.safe_is_dir(root):
            continue
        out: list[Path] = []
        try:
            dep = (root / "modules.dep").read_text(errors="replace")
        except OSError as e:
            log.debug("boot_chain: cannot read %s/modules.dep: %s", root, e)
        else:
            for line in dep.splitlines():
                rel = line.split(":", 1)[0].strip()
                if rel:
                    out.append(root / rel)
                if len(out) >= MODULE_SAMPLE_LIMIT:
                    return out
            if out:
                return out
        for dirpath, dirnames, filenames in os.walk(root / "kernel"):
            dirnames.sort()
            for name in sorted(filenames):
                if ".ko" in name:
                    out.append(Path(dirpath) / name)
                    if len(out) >= MODULE_SAMPLE_LIMIT:
                        return out
        if out:
            return out
    return []


def detect_module_signing() -> dict[str, Any]:
    release = kernel_release()
    config, config_source = read_kernel_config(release)
    key_types = sorted(
        k.removeprefix("CONFIG_MODULE_SIG_KEY_TYPE_")
        for k, v in config.items()
        if k.startswith("CONFIG_MODULE_SIG_KEY_TYPE_") and v == "y"
    )
    enforce = None
    try:
        raw = _platform.host_path(
            "/sys/module/module/parameters/sig_enforce"
        ).read_text()
        enforce = raw.strip() == "Y"
    except OSError as e:
        log.debug("boot_chain: sig_enforce unreadable: %s", e)
    sample: dict[str, Any] | None = None
    for path in _module_candidates(release):
        try:
            if path.stat().st_size > MAX_MODULE_BYTES:
                continue
            data = _decompress_module(path, path.read_bytes())
        except OSError as e:
            log.debug("boot_chain: cannot read module %s: %s", path, e)
            continue
        if data is None:
            continue
        sig = parse_module_signature(data)
        if sig is None:
            sample = {"module": path.name, "signed": False}
            continue
        sample = {"module": path.name, "signed": True, **sig}
        if sig.get("parsed"):
            break
    pqc: bool | None = None
    if sample and sample.get("parsed"):
        pqc = sample.get("category") == "pure_pqc"
    elif key_types:
        pqc = any(t.startswith("MLDSA") for t in key_types)
    return {
        "kernel_release": release,
        "kernel_config_source": config_source,
        "module_sig": config.get("CONFIG_MODULE_SIG") == "y" if config else None,
        "module_sig_force": config.get("CONFIG_MODULE_SIG_FORCE") == "y"
        if config
        else None,
        "module_sig_hash": config.get("CONFIG_MODULE_SIG_HASH"),
        "key_types_configured": key_types,
        "sig_enforce": enforce,
        "sample_module": sample,
        "pqc": pqc,
    }


# ---------------------------------------------------------------------------
# IMA / EVM and lockdown
# ---------------------------------------------------------------------------

IMA_CERT_DIRS = ("/etc/keys/ima",)
_CMDLINE_KEYS = ("ima_policy", "ima_appraise", "ima_hash", "ima_template", "evm")


def detect_ima_evm() -> dict[str, Any]:
    securityfs = _platform.host_path("/sys/kernel/security")
    ima_dir = securityfs / "ima"
    cmdline: dict[str, str] = {}
    try:
        for tok in _platform.host_path("/proc/cmdline").read_text().split():
            k, _, v = tok.partition("=")
            if k in _CMDLINE_KEYS:
                cmdline[k] = v
    except OSError as e:
        log.debug("boot_chain: /proc/cmdline unreadable: %s", e)
    policy: dict[str, Any] = {"readable": False}
    try:
        rules = [
            line.strip()
            for line in (ima_dir / "policy").read_text().splitlines()
            if line.strip() and not line.startswith("#")
        ]
        policy = {
            "readable": True,
            "rules": len(rules),
            "measure_rules": sum(r.startswith("measure") for r in rules),
            "appraise_rules": sum(r.startswith("appraise") for r in rules),
            "signature_required_rules": sum("appraise_type=imasig" in r for r in rules),
        }
    except OSError as e:
        log.debug("boot_chain: IMA policy unreadable: %s", e)
    evm_mode: int | None = None
    for p in (securityfs / "evm", securityfs / "integrity" / "evm" / "evm"):
        try:
            evm_mode = int(p.read_text().strip())
            break
        except (OSError, ValueError):
            continue
    certificates: list[dict[str, Any]] = []
    for d in IMA_CERT_DIRS:
        base = _platform.host_path(d)
        if not _platform.safe_is_dir(base):
            continue
        for f in sorted(_platform.safe_iterdir(base)):
            try:
                if f.stat().st_size > 1024 * 1024:
                    continue
                for der in _certs._certs_in_file(f):
                    try:
                        cert = _cert_summary(_certs.parse_certificate(der))
                    except _certs.DERError:
                        continue
                    cert["path"] = f"{d}/{f.name}"
                    certificates.append(cert)
            except OSError as e:
                log.debug("boot_chain: cannot read %s: %s", f, e)
    return {
        "ima_securityfs": _platform.safe_is_dir(ima_dir),
        "cmdline": cmdline,
        "policy": policy,
        "evm_mode": evm_mode,
        "certificates": certificates,
    }


def detect_lockdown() -> str | None:
    """Active kernel lockdown mode (the bracketed word), or None."""
    try:
        text = _platform.host_path("/sys/kernel/security/lockdown").read_text()
    except OSError:
        return None
    m = re.search(r"\[(\w+)\]", text)
    return m.group(1) if m else None


# ---------------------------------------------------------------------------
# TPM 2.0 (read-only TPM2_GetCapability)
# ---------------------------------------------------------------------------

TPM2_ST_NO_SESSIONS = 0x8001
TPM2_CC_GET_CAPABILITY = 0x0000017A
TPM2_CAP_ALGS = 0x00000000
TPM2_CAP_TPM_PROPERTIES = 0x00000006
TPM2_PT_FIXED = 0x100
TPM2_PT_FAMILY_INDICATOR = TPM2_PT_FIXED + 0
TPM2_PT_REVISION = TPM2_PT_FIXED + 2
TPM2_PT_YEAR = TPM2_PT_FIXED + 4
TPM2_PT_MANUFACTURER = TPM2_PT_FIXED + 5

# TPM 2.0 Library v1.85 post-quantum algorithm IDs (see module docstring).
TPM_PQC_ALGORITHMS: dict[int, str] = {
    0x00A0: "ML-KEM",
    0x00A1: "ML-DSA",
    0x00A2: "HashML-DSA",
}
TPM_SPEC_NOTE = (
    "TPM_ALG_MLKEM / MLDSA / HASH_MLDSA (0x00A0-0x00A2) per wolfTPM's TPM 2.0 "
    "Library v1.85 implementation; TCG v1.85 is a release candidate"
)
TPM_TIMEOUT_S = 5.0


def tpm2_get_capability_command(capability: int, prop: int, count: int) -> bytes:
    return struct.pack(
        ">HIIIII",
        TPM2_ST_NO_SESSIONS,
        22,
        TPM2_CC_GET_CAPABILITY,
        capability,
        prop,
        count,
    )


def parse_get_capability_response(resp: bytes) -> tuple[int, list[tuple[int, int]]]:
    """(responseCode, [(id, value), ...]) from a TPM2_GetCapability
    response for TPM_CAP_ALGS (id = alg, value = attributes) or
    TPM_CAP_TPM_PROPERTIES (id = property, value = value)."""
    if len(resp) < 10:
        raise ValueError("short TPM response")
    _tag, size, rc = struct.unpack_from(">HII", resp, 0)
    if rc != 0:
        return rc, []
    if size > len(resp) or len(resp) < 19:
        raise ValueError("truncated TPM response")
    capability, count = struct.unpack_from(">II", resp, 11)
    entries: list[tuple[int, int]] = []
    pos = 19
    if capability == TPM2_CAP_ALGS:
        for _ in range(count):
            if pos + 6 > size:
                raise ValueError("truncated algorithm list")
            alg, attrs = struct.unpack_from(">HI", resp, pos)
            entries.append((alg, attrs))
            pos += 6
    elif capability == TPM2_CAP_TPM_PROPERTIES:
        for _ in range(count):
            if pos + 8 > size:
                raise ValueError("truncated property list")
            entries.append(struct.unpack_from(">II", resp, pos))
            pos += 8
    else:
        raise ValueError(f"unexpected capability {capability:#x}")
    return rc, entries


def _tpm_transact(fd: int, command: bytes) -> bytes:
    os.write(fd, command)
    ready, _, _ = select.select([fd], [], [], TPM_TIMEOUT_S)
    if not ready:
        raise TimeoutError("TPM did not answer")
    return os.read(fd, 4096)


def _ascii_u32(value: int) -> str:
    # TCG vendor IDs are space- or NUL-padded, e.g. "IBM ".
    return value.to_bytes(4, "big").decode("ascii", "replace").rstrip("\0 ")


def detect_tpm_capabilities() -> dict[str, Any]:
    """Spec revision and v1.85 PQC algorithm support of the host TPM."""
    tpm_class = _platform.host_path("/sys/class/tpm/tpm0")
    out: dict[str, Any] = {
        "present": _platform.safe_exists(tpm_class),
        "spec_note": TPM_SPEC_NOTE,
    }
    try:
        out["version_major"] = int((tpm_class / "tpm_version_major").read_text())
    except (OSError, ValueError):
        out["version_major"] = None
    if not out["present"]:
        out.update(queried=False, reason="no TPM at /sys/class/tpm/tpm0")
        return out
    if out["version_major"] not in (None, 2):
        out.update(queried=False, reason="not a TPM 2.0")
        return out
    dev = _platform.host_path("/dev/tpmrm0")
    try:
        fd = os.open(dev, os.O_RDWR)
    except OSError as e:
        out.update(
            queried=False,
            reason=f"cannot open {dev}: {e.strerror} (needs root or the tss group)",
        )
        return out
    try:
        rc, props = parse_get_capability_response(
            _tpm_transact(
                fd,
                tpm2_get_capability_command(
                    TPM2_CAP_TPM_PROPERTIES, TPM2_PT_FAMILY_INDICATOR, 6
                ),
            )
        )
        prop = dict(props) if rc == 0 else {}
        rc2, algs = parse_get_capability_response(
            _tpm_transact(
                fd,
                tpm2_get_capability_command(
                    TPM2_CAP_ALGS, min(TPM_PQC_ALGORITHMS), len(TPM_PQC_ALGORITHMS)
                ),
            )
        )
    except (OSError, ValueError, TimeoutError) as e:
        out.update(queried=False, reason=f"TPM2_GetCapability failed: {e}")
        return out
    finally:
        os.close(fd)
    supported = [
        TPM_PQC_ALGORITHMS[a] for a, _ in algs if rc2 == 0 and a in TPM_PQC_ALGORITHMS
    ]
    revision = prop.get(TPM2_PT_REVISION)
    out.update(
        queried=True,
        family=_ascii_u32(prop[TPM2_PT_FAMILY_INDICATOR])
        if TPM2_PT_FAMILY_INDICATOR in prop
        else None,
        spec_revision=f"{revision / 100:.2f}" if revision is not None else None,
        spec_year=prop.get(TPM2_PT_YEAR),
        manufacturer=_ascii_u32(prop[TPM2_PT_MANUFACTURER])
        if TPM2_PT_MANUFACTURER in prop
        else None,
        pqc_algorithms=supported,
        pqc_capable=bool(supported),
    )
    return out


# ---------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------


def _summarise(
    sb: dict[str, Any], mod: dict[str, Any], ima: dict[str, Any], tpm: dict[str, Any]
) -> dict[str, Any]:
    cats: dict[str, int] = {}
    for key in TRUST_DATABASES:
        db = (sb.get("databases") or {}).get(key) or {}
        for cert in db.get("certificates") or []:
            c = str(cert.get("category"))
            cats[c] = cats.get(c, 0) + 1
        if db.get("rsa2048_keys"):
            cats["classical"] = cats.get("classical", 0) + db["rsa2048_keys"]
    total = sum(cats.values())
    pqc_certs = cats.get("pure_pqc", 0) + cats.get("hybrid_composite", 0)
    classical_layers = []
    if total and not pqc_certs:
        classical_layers.append("secure_boot")
    if mod.get("pqc") is False:
        classical_layers.append("module_signing")
    ima_certs = ima.get("certificates") or []
    if ima_certs and not any(
        c.get("category") in ("pure_pqc", "hybrid_composite") for c in ima_certs
    ):
        classical_layers.append("ima")
    if tpm.get("queried") and not tpm.get("pqc_capable"):
        classical_layers.append("tpm")
    algorithms = sorted(
        {
            f"{c.get('key_algorithm')}-{c.get('key_size')}"
            if c.get("key_algorithm") in ("RSA",)
            else str(c.get("key_algorithm"))
            for key in TRUST_DATABASES
            for c in ((sb.get("databases") or {}).get(key) or {}).get("certificates")
            or []
        }
    )
    return {
        "secure_boot_certificates": total,
        "secure_boot_certificate_categories": cats,
        "secure_boot_all_classical": bool(total) and not pqc_certs,
        "secure_boot_algorithms": algorithms,
        "module_signing_pqc": mod.get("pqc"),
        "classical_layers": classical_layers,
    }


def describe_classical_layers(bc: dict[str, Any]) -> list[str]:
    """One sentence per classical boot-chain layer, for findings, the text
    report and recommendation caveats."""
    if not bc.get("available"):
        return []
    summary = bc.get("summary") or {}
    layers = summary.get("classical_layers") or []
    out: list[str] = []
    if "secure_boot" in layers:
        out.append(
            f"Secure Boot trusts {summary.get('secure_boot_certificates')} "
            "certificates (PK/KEK/db/MOK), all classical: "
            + ", ".join(summary.get("secure_boot_algorithms") or [])
        )
    if "module_signing" in layers:
        mod = bc.get("module_signing") or {}
        sample = mod.get("sample_module") or {}
        if sample.get("parsed"):
            size = f"-{sample['key_size']}" if sample.get("key_size") else ""
            out.append(
                f"kernel modules are signed with {sample.get('signature_algorithm')}"
                f"{size} / {sample.get('digest_algorithm')}"
            )
        else:
            out.append(
                "the kernel is configured for "
                + "/".join(mod.get("key_types_configured") or ["?"])
                + " module signing"
            )
    if "ima" in layers:
        algos = sorted(
            {
                str(c.get("key_algorithm"))
                for c in (bc.get("ima_evm") or {}).get("certificates") or []
            }
        )
        out.append("IMA code-signing certificates are " + ", ".join(algos))
    if "tpm" in layers:
        tpm = bc.get("tpm") or {}
        out.append(
            f"the TPM (spec {tpm.get('spec_revision')}) reports no ML-KEM / "
            "ML-DSA support"
        )
    return out


def scan_boot_chain() -> dict[str, Any]:
    """Boot chain inventory: Secure Boot, module signing, IMA/EVM,
    lockdown and TPM.  Linux only."""
    if not _platform.is_linux():
        return {"available": False, "reason": "boot chain inventory is Linux-only"}
    sb = detect_secure_boot()
    mod = detect_module_signing()
    ima = detect_ima_evm()
    tpm = detect_tpm_capabilities()
    out: dict[str, Any] = {
        "available": True,
        "secure_boot": sb,
        "module_signing": mod,
        "ima_evm": ima,
        "lockdown": detect_lockdown(),
        "tpm": tpm,
        "summary": _summarise(sb, mod, ima, tpm),
    }
    note = _platform.host_fs_unavailable_note(
        "Boot chain inventory",
        "/sys/firmware/efi, /sys/kernel/security, /boot and /lib/modules",
    )
    if note:
        out.update(note)
    return out


@_registry.register_arguments(53)
def add_arguments(ap: argparse.ArgumentParser) -> None:
    ap.add_argument(
        "--scan-boot-chain",
        action="store_true",
        help=(
            "inventory the boot chain: Secure Boot PK/KEK/db/dbx/MOK "
            "certificate algorithms, kernel module signing, IMA/EVM, "
            "lockdown and TPM 2.0 PQC support (read-only)"
        ),
    )
