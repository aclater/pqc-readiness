"""PQC capability of crypto libraries other than OpenSSL and NSS (#110, #217).

A host can have a PQC-ready OpenSSL while the service that terminates TLS
or SSH links GnuTLS, wolfSSL, AWS-LC or libssh, or runs on a JVM or a Go
toolchain with its own TLS stack.  This module reports, per library:

* whether it is installed (package inventory, or the library file);
* its version (package version first, else the version string the
  library embeds);
* which PQC algorithms the installed binary actually carries.

The primary evidence is the shared library itself: each library embeds
the names of the algorithms and TLS / SSH groups it implements, so the
probe reads the file and looks for those names.  That is right even
where a distribution backports PQC into an older release, or builds
GnuTLS without a PQC backend.  The upstream version thresholds below are
the fallback when no library file can be read, and are reported
alongside the evidence.  No subprocess is run.

Every threshold is taken from the project's own release notes, cited
next to it.
"""

from __future__ import annotations

import argparse
import glob
import logging
import re
from pathlib import Path
from typing import Any

from .. import _platform as _platform
from .. import registry as _registry
from ..detect import packages as _packages
from ..detect import runtime_services as _runtime_services

log = logging.getLogger("pqc-readiness")

# Library files larger than this are not read (all known builds are
# under 8 MiB; the cap bounds runtime on unusual hosts).
_MAX_LIBRARY_BYTES = 64 * 1024 * 1024

_LIB_DIRS: tuple[str, ...] = (
    "/usr/lib64",
    "/usr/lib",
    "/lib64",
    "/lib",
    "/usr/lib/x86_64-linux-gnu",
    "/usr/lib/aarch64-linux-gnu",
    "/usr/lib/s390x-linux-gnu",
    "/usr/lib/powerpc64le-linux-gnu",
    "/lib/x86_64-linux-gnu",
    "/lib/aarch64-linux-gnu",
)

GNUTLS_REFERENCE = "https://gitlab.com/gnutls/gnutls/-/blob/master/NEWS"
LIBGCRYPT_REFERENCE = "https://github.com/gpg/libgcrypt/blob/master/NEWS"
LIBSSH_REFERENCE = "https://gitlab.com/libssh/libssh-mirror/-/blob/master/CHANGELOG"
WOLFSSL_REFERENCE = "https://github.com/wolfSSL/wolfssl/blob/master/ChangeLog.md"
AWSLC_REFERENCE = "https://github.com/aws/aws-lc/releases"
JDK_REFERENCES = (
    "https://openjdk.org/jeps/496",
    "https://openjdk.org/jeps/497",
    "https://openjdk.org/jeps/527",
)
GO_REFERENCE = "https://go.dev/doc/go1.24"
MBEDTLS_REFERENCE = (
    "https://github.com/Mbed-TLS/mbedtls/releases "
    "https://github.com/Mbed-TLS/TF-PSA-Crypto/releases"
)

# library -> spec.  `markers` map a reported name to the byte string the
# library embeds when it implements it, grouped by capability kind.
# `thresholds` map a capability to (minimum upstream version, note).
LIBRARY_SPECS: dict[str, dict[str, Any]] = {
    "gnutls": {
        "files": ("libgnutls.so.30*",),
        "packages": {
            "rhel": ("gnutls",),
            "suse": ("libgnutls30",),
            "arch": ("gnutls",),
            "alpine": ("gnutls",),
        },
        "debian_package_re": r"^libgnutls30(t64)?$",
        "probe_package_re": r"^(lib)?gnutls(30)?$",
        "version_re": rb"GnuTLS (\d+\.\d+\.\d+)",
        "markers": {
            "tls_hybrid_groups": {
                "X25519MLKEM768": b"X25519-MLKEM768",
                "SecP256r1MLKEM768": b"SECP256R1-MLKEM768",
                "SecP384r1MLKEM1024": b"SECP384R1-MLKEM1024",
            },
            "kem": {"ML-KEM-768": b"ML-KEM-768", "ML-KEM-1024": b"ML-KEM-1024"},
            "signatures": {
                "ML-DSA-44": b"ML-DSA-44",
                "ML-DSA-65": b"ML-DSA-65",
                "ML-DSA-87": b"ML-DSA-87",
            },
        },
        # GnuTLS NEWS: 3.8.8 (2024-11-05) experimental X25519MLKEM768 and
        # SecP256r1MLKEM768; 3.8.9 (2025-02-07) ML-KEM-1024
        # (SecP384r1MLKEM1024) and experimental ML-DSA; 3.8.10
        # (2025-07-08) ML-DSA in TLS.  All need a PQC backend at build time
        # (liboqs, or leancrypto from 3.8.9; liboqs dropped in 3.8.10).
        "thresholds": {
            "tls_hybrid_mlkem768": (
                (3, 8, 8),
                "experimental; needs a PQC backend at build time",
            ),
            "tls_hybrid_mlkem1024": ((3, 8, 9), "needs a PQC backend at build time"),
            "ml_dsa": ((3, 8, 9), "needs a PQC backend at build time"),
            "ml_dsa_tls": ((3, 8, 10), "ML-DSA TLS signatures"),
        },
        "build_dependent": True,
        "reference": GNUTLS_REFERENCE,
    },
    "libgcrypt": {
        "files": ("libgcrypt.so.20*",),
        "packages": {
            "rhel": ("libgcrypt",),
            "suse": ("libgcrypt20",),
            "arch": ("libgcrypt",),
            "alpine": ("libgcrypt",),
        },
        "debian_package_re": r"^libgcrypt20$",
        "probe_package_re": r"^libgcrypt(20)?$",
        "version_re": rb"Libgcrypt (\d+\.\d+\.\d+)",
        "markers": {
            "kem": {
                "ML-KEM-512": b"kyber512",
                "ML-KEM-768": b"kyber768",
                "ML-KEM-1024": b"kyber1024",
                "sntrup761": b"sntrup761",
            },
            "signatures": {
                "ML-DSA-44": b"dilithium2",
                "ML-DSA-65": b"dilithium3",
                "ML-DSA-87": b"dilithium5",
            },
        },
        # libgcrypt NEWS: 1.11.0 (2024-06-19) Kyber per FIPS 203 ipd and
        # sntrup761; 1.11.1 (2025-05-07, 1.11 branch) Kyber updated to the
        # final FIPS 203; 1.12.0 (2026-01-29) Dilithium (ML-DSA).
        "thresholds": {
            "ml_kem_draft": ((1, 11, 0), "FIPS 203 initial public draft"),
            "ml_kem": ((1, 11, 1), "final FIPS 203"),
            "ml_dsa": ((1, 12, 0), "ML-DSA"),
        },
        # (threshold, caveat) pairs: the caveat is reported when the version
        # is known to be below the threshold, i.e. the names in the binary
        # may be a pre-standard implementation.
        "caveats": (
            (
                "ml_kem",
                "Upstream libgcrypt before 1.11.1 implements Kyber as in the FIPS 203 "
                "initial public draft, which does not interoperate with final ML-KEM; "
                "a distribution build may carry the final-standard patch.",
            ),
        ),
        "build_dependent": False,
        "reference": LIBGCRYPT_REFERENCE,
    },
    "libssh": {
        "files": ("libssh.so.4*", "libssh-gcrypt.so.4*"),
        "packages": {
            "rhel": ("libssh",),
            "suse": ("libssh4",),
            "arch": ("libssh",),
            "alpine": ("libssh",),
        },
        "debian_package_re": r"^libssh-(gcrypt-)?4(t64)?$",
        "probe_package_re": r"^libssh(4)?$",
        # The default client/server banner (Buildroot 2026.08: libssh 0.12.1).
        "version_re": rb"SSH-2\.0-libssh_(\d+\.\d+\.\d+)",
        "markers": {
            "ssh_kex": {
                "mlkem768x25519-sha256": b"mlkem768x25519-sha256",
                "mlkem768nistp256-sha256": b"mlkem768nistp256-sha256",
                "mlkem1024nistp384-sha384": b"mlkem1024nistp384-sha384",
                "sntrup761x25519-sha512": b"sntrup761x25519-sha512",
            },
        },
        # libssh CHANGELOG: 0.12.0 (2026-02-10) adds and prefers
        # sntrup761x25519-sha512, mlkem768nistp256-sha256,
        # mlkem768x25519-sha256 and (OpenSSL 3.5+ / libgcrypt backends
        # only) mlkem1024nistp384-sha384.  0.11.x has no PQC key exchange.
        "thresholds": {
            "ssh_pqc_kex": ((0, 12, 0), "hybrid ML-KEM / sntrup761 key exchange"),
        },
        "build_dependent": False,
        "reference": LIBSSH_REFERENCE,
    },
    "wolfssl": {
        "files": ("libwolfssl.so*",),
        "packages": {
            "rhel": ("wolfssl",),
            "suse": ("wolfssl",),
            "arch": ("wolfssl",),
            "alpine": ("wolfssl",),
        },
        "debian_package_re": r"^libwolfssl\d+(t64)?$",
        "probe_package_re": r"^(lib)?wolfssl",
        "version_re": None,
        "markers": {
            "tls_hybrid_groups": {
                "X25519MLKEM768": b"X25519MLKEM768",
                "SecP256r1MLKEM768": b"SecP256r1MLKEM768",
                "SecP384r1MLKEM1024": b"SecP384r1MLKEM1024",
            },
            "kem": {"ML-KEM": b"ML-KEM"},
            "signatures": {"ML-DSA": b"ML-DSA"},
        },
        # wolfSSL ChangeLog: 5.7.4 (2024-10-24) Kyber and Dilithium updated
        # to the final specifications; 5.9.1 (2026-04-08) ML-KEM enabled
        # by default (earlier builds needed --enable-mlkem / --enable-kyber).
        "thresholds": {
            "ml_kem_final": (
                (5, 7, 4),
                "final FIPS 203 / 204; build option before 5.9.1",
            ),
            "ml_kem_default": ((5, 9, 1), "ML-KEM on by default"),
        },
        "caveats": (
            (
                "ml_kem_final",
                "wolfSSL before 5.7.4 implements pre-final Kyber / Dilithium, which do "
                "not interoperate with final ML-KEM / ML-DSA.",
            ),
        ),
        "build_dependent": True,
        "reference": WOLFSSL_REFERENCE,
    },
    "aws-lc": {
        # AWS-LC installs libcrypto / libssl under the same names as
        # OpenSSL on some distributions (Alpine), so its files are found
        # by the "AWS-LC x.y.z" string it embeds, not by name.
        "files": (),
        "identify_re": rb"AWS-LC (\d+\.\d+\.\d+)",
        "identify_files": ("libcrypto.so*", "libcrypto-awslc*.so*"),
        "packages": {"alpine": ("aws-lc",)},
        "debian_package_re": r"^libaws-lc",
        "probe_package_re": r"^(lib)?aws-lc",
        "version_re": rb"AWS-LC (\d+\.\d+\.\d+)",
        "markers": {
            "tls_hybrid_groups": {
                "X25519MLKEM768": b"X25519MLKEM768",
                "SecP256r1MLKEM768": b"SecP256r1MLKEM768",
                "SecP384r1MLKEM1024": b"SecP384r1MLKEM1024",
            },
            "kem": {
                "ML-KEM-512": b"ML-KEM-512",
                "ML-KEM-768": b"ML-KEM-768",
                "ML-KEM-1024": b"ML-KEM-1024",
            },
            "signatures": {
                "ML-DSA-44": b"ML-DSA-44",
                "ML-DSA-65": b"ML-DSA-65",
                "ML-DSA-87": b"ML-DSA-87",
            },
        },
        # AWS-LC releases: v1.35.0 (2024-09-17) ML-KEM per final FIPS 203;
        # v1.35.1 (2024-09-19) ML-KEM-768 hybrid groups in libssl;
        # v1.41.0 (2024-12-10) ML-DSA-44/65/87; v1.50.0 (2025-04-25)
        # SecP384r1MLKEM1024.
        "thresholds": {
            "ml_kem": ((1, 35, 0), "final FIPS 203"),
            "tls_hybrid_mlkem768": ((1, 35, 1), "X25519MLKEM768 / SecP256r1MLKEM768"),
            "ml_dsa": ((1, 41, 0), "ML-DSA-44/65/87"),
            "tls_hybrid_mlkem1024": ((1, 50, 0), "SecP384r1MLKEM1024"),
        },
        "build_dependent": False,
        "reference": AWSLC_REFERENCE,
    },
}

# Mbed TLS: the TLS stack of most embedded images (OpenWrt's default,
# #217).  2.x/3.x ship libmbedtls, libmbedx509 and libmbedcrypto; 4.x moves
# the crypto library to TF-PSA-Crypto (libtfpsacrypto).  No released Mbed
# TLS (through 4.2.0, 2026-07-07) or TF-PSA-Crypto (through 1.2.0,
# 2026-07-07) offers ML-KEM or ML-DSA to applications, or ML-KEM groups in
# TLS: their release notes list LMS verification only.  TF-PSA-Crypto's
# development branch (ChangeLog.d/mldsa.txt) adds an experimental,
# driver-level ML-DSA-87 that "is not yet exposed to applications".  So
# there is no version threshold, and the binary markers look only for TLS
# group names a PQC-capable build would carry.
LIBRARY_SPECS["mbedtls"] = {
    "files": ("libmbedtls.so*", "libmbedcrypto.so*", "libtfpsacrypto.so*"),
    "packages": {
        "rhel": ("mbedtls",),
        "arch": ("mbedtls",),
        "alpine": ("mbedtls",),
    },
    "debian_package_re": r"^libmbedtls\d+(t64)?$",
    "probe_package_re": r"^(libmbedtls\d*|mbedtls)$",
    "version_re": rb"[Mm]bed TLS (\d+\.\d+\.\d+)",
    # Mbed TLS names its shared libraries after the release
    # (libmbedtls.so.3.6.6), unlike libtool-versioned libraries; builds that
    # drop the version string (OpenWrt) are still versioned this way.
    # libtfpsacrypto carries the TF-PSA-Crypto version, so it is excluded.
    "filename_version_re": r"^libmbed(?:tls|crypto|x509)\.so\.(\d+\.\d+\.\d+)$",
    "markers": {
        "tls_hybrid_groups": {
            "X25519MLKEM768": b"X25519MLKEM768",
            "SecP256r1MLKEM768": b"SecP256r1MLKEM768",
            "SecP384r1MLKEM1024": b"SecP384r1MLKEM1024",
        },
    },
    "thresholds": {},
    "notes": (
        "No released Mbed TLS (through 4.2.0) or TF-PSA-Crypto (through 1.2.0) "
        "offers ML-KEM or ML-DSA to applications or ML-KEM groups in TLS; only LMS "
        "signature verification. An experimental driver-level ML-DSA-87 in "
        "TF-PSA-Crypto development is not exposed to applications.",
    ),
    "build_dependent": False,
    "reference": MBEDTLS_REFERENCE,
}

# JDK: JEP 496 (ML-KEM) and JEP 497 (ML-DSA) delivered in JDK 24 (JCA
# APIs, not TLS); JEP 527 (post-quantum hybrid key exchange for TLS 1.3)
# delivered in JDK 27 with X25519MLKEM768 enabled by default and
# SecP256r1MLKEM768 / SecP384r1MLKEM1024 available but off by default.
JDK_JCA_PQC_MAJOR = 24
JDK_TLS_HYBRID_MAJOR = 27
_JVM_DIRS = ("/usr/lib/jvm", "/usr/lib64/jvm", "/usr/java", "/opt/java")

# Go toolchains: thresholds shared with the static-binary probe (#111).
_GO_ROOTS = (
    "/usr/lib/golang",
    "/usr/lib/go",
    "/usr/local/go",
    "/usr/lib/go-*",
    "/usr/lib64/go/*",
    "/usr/share/go-*",
)


def _version_tuple(text: str | None) -> tuple[int, ...] | None:
    """Leading numeric dotted version: "3.8.13-1.fc44" -> (3, 8, 13)."""
    if not text:
        return None
    m = re.match(r"(?:\d+:)?(\d+(?:\.\d+)*)", text.strip())
    if not m:
        return None
    return tuple(int(x) for x in m.group(1).split("."))


def _host(p: str) -> Path:
    return Path(_platform.HOST_PREFIX + p) if _platform.HOST_PREFIX else Path(p)


def _unhost(p: Path) -> str:
    s = str(p)
    pre = _platform.HOST_PREFIX
    return s[len(pre) :] if pre and s.startswith(pre) else s


def _find_files(patterns: tuple[str, ...]) -> list[Path]:
    """Real library files matching `patterns` in the standard library
    directories, de-duplicated by resolved path."""
    seen: set[str] = set()
    out: list[Path] = []
    for d in _LIB_DIRS:
        base = _host(d)
        if not _platform.safe_is_dir(base):
            continue
        for pat in patterns:
            for hit in sorted(base.glob(pat)):
                try:
                    real = hit.resolve()
                except OSError:
                    continue
                if not _platform.safe_is_file(real) or str(real) in seen:
                    continue
                if _platform.HOST_PREFIX and not str(real).startswith(
                    _platform.HOST_PREFIX
                ):
                    # An absolute symlink resolved into the scanner image.
                    real = Path(_platform.HOST_PREFIX + str(real))
                    if not _platform.safe_is_file(real) or str(real) in seen:
                        continue
                seen.add(str(real))
                out.append(real)
    return out


def _read_library(path: Path) -> bytes | None:
    try:
        if path.stat().st_size > _MAX_LIBRARY_BYTES:
            log.debug("crypto libraries: %s too large; skipped", path)
            return None
        return path.read_bytes()
    except OSError as e:
        log.debug("crypto libraries: cannot read %s: %s", path, e)
        return None


# ---------------------------------------------------------------------------
# Package versions (no subprocess where a database file can be read)
# ---------------------------------------------------------------------------


def _dpkg_versions(pattern: str) -> list[dict[str, str]]:
    """Installed packages matching `pattern` from /var/lib/dpkg/status."""
    path = _host("/var/lib/dpkg/status")
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return []
    rx = re.compile(pattern)
    out: list[dict[str, str]] = []
    for stanza in text.split("\n\n"):
        fields: dict[str, str] = {}
        for line in stanza.splitlines():
            if ":" in line and not line.startswith(" "):
                k, _, v = line.partition(":")
                fields[k.strip()] = v.strip()
        name = fields.get("Package", "")
        if rx.search(name) and "installed" in fields.get("Status", "").split():
            out.append({"name": name, "version": fields.get("Version", "")})
    return out


def _apk_versions(names: tuple[str, ...]) -> list[dict[str, str]]:
    """Installed packages from apk's database (P:/V: lines)."""
    try:
        text = _host("/lib/apk/db/installed").read_text(errors="replace")
    except OSError:
        return []
    out: list[dict[str, str]] = []
    for stanza in text.split("\n\n"):
        fields = dict(
            (line[0], line[2:])
            for line in stanza.splitlines()
            if len(line) > 2 and line[1] == ":"
        )
        if fields.get("P") in names:
            out.append({"name": fields["P"], "version": fields.get("V", "")})
    return out


def _pacman_versions(names: tuple[str, ...]) -> list[dict[str, str]]:
    """Installed packages from pacman's local database directories."""
    base = _host("/var/lib/pacman/local")
    out: list[dict[str, str]] = []
    if not _platform.safe_is_dir(base):
        return out
    for d in _platform.safe_iterdir(base):
        name, _, rest = d.name.rpartition("-")  # strip pkgrel
        name, _, ver = name.rpartition("-")
        if name in names:
            out.append({"name": name, "version": f"{ver}-{rest}"})
    return out


def _package_versions(spec: dict[str, Any], family: str) -> list[dict[str, str]]:
    if family in ("rhel", "suse"):
        names = spec["packages"].get(family) or ()
        if not names:
            return []
        inv = _packages.query_rpm_named(tuple(names))
        if not inv.get("available"):
            return []
        # release / epoch / arch let the CBOM emit the exact purl --sbom
        # uses for the same package (#222).
        return [
            {"name": p["name"], "version": p.get("version", "")}
            | {
                k: str(p[k])
                for k in ("release", "epoch", "arch")
                if p.get(k) not in (None, "")
            }
            for p in inv["packages"]
        ]
    if family == "debian":
        return _dpkg_versions(spec["debian_package_re"])
    if family == "alpine":
        return _apk_versions(spec["packages"].get("alpine") or ())
    if family == "arch":
        return _pacman_versions(spec["packages"].get("arch") or ())
    return _probed_versions(spec.get("probe_package_re"))


def _probed_versions(pattern: str | None) -> list[dict[str, str]]:
    """Library packages from whichever database the tree has, for families
    without a registered package tool (OpenWrt, Yocto, unknown; #217)."""
    if not pattern:
        return []
    found = _packages.probe_package_db_cached()
    if not found:
        return []
    rx = re.compile(pattern)
    return [p for p in found["packages"] if rx.search(p["name"])]


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


def _markers_found(
    blobs: list[bytes], markers: dict[str, dict[str, bytes]]
) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    for kind, table in markers.items():
        found[kind] = [
            name for name, needle in table.items() if any(needle in b for b in blobs)
        ]
    return found


def _thresholds_met(
    version: tuple[int, ...] | None, thresholds: dict[str, tuple[tuple[int, ...], str]]
) -> dict[str, Any]:
    return {
        cap: {
            "minimum_version": ".".join(str(x) for x in minimum),
            "met": None if version is None else version >= minimum,
            "note": note,
        }
        for cap, (minimum, note) in thresholds.items()
    }


def _probe_library(name: str, spec: dict[str, Any], family: str) -> dict[str, Any]:
    files: list[Path]
    if spec.get("identify_re"):
        rx = re.compile(spec["identify_re"])
        files = []
        embedded = None
        for f in _find_files(spec["identify_files"]):
            blob = _read_library(f)
            m = rx.search(blob) if blob else None
            if m:
                files.append(f)
                embedded = m.group(1).decode()
        # The matching libssl is the exact sibling name ("libcrypto.so" ->
        # "libssl.so"), never a glob: on Alpine OpenSSL's libssl.so.3 sits
        # in the same directory and must not be credited to AWS-LC.
        for f in list(files):
            sibling = f.with_name(f.name.replace("libcrypto", "libssl", 1))
            if (
                sibling != f
                and _platform.safe_is_file(sibling)
                and sibling not in files
            ):
                files.append(sibling)
    else:
        files = _find_files(spec["files"])
        embedded = None
    blobs = [b for b in (_read_library(f) for f in files) if b]
    if embedded is None and spec.get("version_re"):
        # Package-less trees (Buildroot, #217): the version the library
        # embeds, without running anything.
        rx = re.compile(spec["version_re"])
        for blob in blobs:
            m = rx.search(blob)
            if m:
                embedded = m.group(1).decode()
                break
    from_filename = None
    if embedded is None and spec.get("filename_version_re"):
        frx = re.compile(spec["filename_version_re"])
        for f in files:
            fm = frx.match(f.name)
            if fm:
                from_filename = fm.group(1)
                break
    pkgs = _package_versions(spec, family)
    if pkgs:
        version, version_source = pkgs[0]["version"], "package"
    elif embedded:
        version, version_source = embedded, "library"
    elif from_filename:
        version, version_source = from_filename, "library-filename"
    else:
        version, version_source = None, None
    if not files and not pkgs:
        return {"installed": False}
    found = _markers_found(blobs, spec["markers"]) if blobs else {}
    pqc_names = sorted({n for names in found.values() for n in names})
    vt = _version_tuple(version)
    thresholds = _thresholds_met(vt, spec["thresholds"])
    if blobs:
        evidence = "binary"
        pqc_capable: bool | None = bool(pqc_names)
    elif vt is not None:
        evidence = "version"
        met = [t["met"] for t in thresholds.values()]
        # A build-dependent library may lack PQC even above the threshold.
        pqc_capable = None if spec["build_dependent"] and any(met) else any(met)
    else:
        evidence = "none"
        pqc_capable = None
    caveats = [
        text
        for key, text in spec.get("caveats", ())
        if thresholds[key]["met"] is False and (pqc_names or evidence != "binary")
    ] + list(spec.get("notes", ()))
    return {
        "installed": True,
        "version": version,
        "version_source": version_source,
        "packages": pkgs,
        "files": [_unhost(f) for f in files],
        "evidence": evidence,
        "pqc_capable": pqc_capable,
        "algorithms": found,
        "version_thresholds": thresholds,
        "build_dependent": spec["build_dependent"],
        "caveats": caveats,
        "reference": spec["reference"],
    }


def _probe_jdks() -> dict[str, Any]:
    installs: list[dict[str, Any]] = []
    seen: set[str] = set()
    for d in _JVM_DIRS:
        base = _host(d)
        if not _platform.safe_is_dir(base):
            continue
        for entry in sorted(_platform.safe_iterdir(base)):
            rel = entry / "release"
            try:
                real = str(entry.resolve())
                text = rel.read_text(errors="replace")
            except OSError:
                continue
            if real in seen:
                continue
            seen.add(real)
            fields = dict(
                (k, v.strip().strip('"'))
                for k, _, v in (line.partition("=") for line in text.splitlines())
                if v
            )
            ver = fields.get("JAVA_VERSION")
            vt = _version_tuple(ver)
            major = vt[0] if vt else None
            installs.append(
                {
                    "path": _unhost(Path(real)),
                    "version": ver,
                    "implementor": fields.get("IMPLEMENTOR"),
                    "jca_ml_kem_ml_dsa": None
                    if major is None
                    else major >= JDK_JCA_PQC_MAJOR,
                    "tls_hybrid_default": None
                    if major is None
                    else major >= JDK_TLS_HYBRID_MAJOR,
                }
            )
    if not installs:
        return {"installed": False}
    return {
        "installed": True,
        "installs": installs,
        "evidence": "version",
        "pqc_capable": any(i["jca_ml_kem_ml_dsa"] for i in installs),
        "version_thresholds": {
            "jca_ml_kem_ml_dsa": {
                "minimum_version": str(JDK_JCA_PQC_MAJOR),
                "note": "JEP 496 / JEP 497",
            },
            "tls_hybrid_default": {
                "minimum_version": str(JDK_TLS_HYBRID_MAJOR),
                "note": "JEP 527: X25519MLKEM768 on by default in TLS 1.3",
            },
        },
        "reference": " ".join(JDK_REFERENCES),
    }


def _probe_go() -> dict[str, Any]:
    installs: list[dict[str, Any]] = []
    seen: set[str] = set()
    for root in _GO_ROOTS:
        for hit in sorted(glob.glob(str(_host(root)))):
            vf = Path(hit) / "VERSION"
            try:
                real = str(Path(hit).resolve())
                first = vf.read_text(errors="replace").splitlines()[0].strip()
            except (OSError, IndexError):
                continue
            if real in seen or not first.startswith("go"):
                continue
            seen.add(real)
            vt = _version_tuple(first[2:])
            installs.append(
                {
                    "path": _unhost(Path(real)),
                    "version": first,
                    "tls_mlkem_default": None
                    if vt is None
                    else vt[:2] >= _runtime_services.GO_MLKEM_DEFAULT_VERSION,
                }
            )
    if not installs:
        return {"installed": False}
    major, minor = _runtime_services.GO_MLKEM_DEFAULT_VERSION
    return {
        "installed": True,
        "installs": installs,
        "evidence": "version",
        "pqc_capable": any(i["tls_mlkem_default"] for i in installs),
        "version_thresholds": {
            "tls_mlkem_default": {
                "minimum_version": f"{major}.{minor}",
                "note": "X25519MLKEM768 on by default in crypto/tls (GODEBUG tlsmlkem=0 reverts)",
            }
        },
        "reference": GO_REFERENCE,
    }


def scan_crypto_libraries(os_release: dict[str, Any] | None = None) -> dict[str, Any]:
    """Probe GnuTLS, libgcrypt, libssh, wolfSSL, AWS-LC, Mbed TLS, JDKs and Go
    toolchains.  Returns ``{available, libraries: {name: {...}},
    summary}``; libraries that are not installed report
    ``{installed: false}``."""
    family = (os_release or {}).get("family", "unknown")
    if not _platform.is_linux():
        return {
            "available": False,
            "reason": "crypto library probes support Linux only",
        }
    libraries: dict[str, Any] = {
        name: _probe_library(name, spec, family) for name, spec in LIBRARY_SPECS.items()
    }
    libraries["java"] = _probe_jdks()
    libraries["go"] = _probe_go()
    installed = sorted(n for n, v in libraries.items() if v.get("installed"))
    result: dict[str, Any] = {
        "available": True,
        "libraries": libraries,
        "summary": {
            "installed": installed,
            "pqc_capable": sorted(
                n for n in installed if libraries[n].get("pqc_capable")
            ),
            "classical_only": sorted(
                n for n in installed if libraries[n].get("pqc_capable") is False
            ),
            "unknown": sorted(
                n for n in installed if libraries[n].get("pqc_capable") is None
            ),
        },
    }
    note = _platform.host_fs_unavailable_note(
        "Crypto library probes", "the host's library files and package database"
    )
    if note:
        result.update(note)
    return result


@_registry.register_arguments(53)
def add_arguments(ap: argparse.ArgumentParser) -> None:
    ap.add_argument(
        "--scan-crypto-libraries",
        action="store_true",
        help=(
            "probe GnuTLS, libgcrypt, libssh, wolfSSL, AWS-LC, Mbed TLS, JDKs and Go "
            "toolchains for PQC support (algorithm names in the installed "
            "library files, then upstream version thresholds)"
        ),
    )


__all__ = [
    "LIBRARY_SPECS",
    "scan_crypto_libraries",
]
