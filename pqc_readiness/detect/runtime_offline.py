# SPDX-License-Identifier: Apache-2.0
"""Offline scan of a filesystem tree (--root PATH, #152).

A mounted disk image or an extracted container rootfs has packages,
certificates, keys, crypto policies and openssl.cnf, but no running
kernel, CPU, devices or processes behind it, and the binaries on PATH
belong to the scanning machine.  This module collects only what the tree
itself can answer and marks every other section `not_applicable`, so no
output format mixes the scanner's own hardware or tools into a report
about the tree.

Distinct from --host-mount, which scans a *live* host whose /proc, /sys
and /etc are bind-mounted into the scanner's container.
"""

from __future__ import annotations

import argparse
import logging
import re
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .. import _platform
from .. import registry as _registry
from .. import report as _report
from ..detect import certs as _certs
from ..detect import certs_discovery as _certs_discovery
from ..detect import config_openssl as _config_openssl
from ..detect import config_policy as _config_policy
from ..detect import osinfo as _osinfo
from ..detect import packages as _packages
from ..detect import protocols as _protocols
from ..detect import protocols_ike as _ike
from ..detect import protocols_signing as _signing

log = logging.getLogger("pqc-readiness")

MODE = "offline_root"

_HOST_STATE_REASON = (
    "offline --root scan: {what} describes a running host (kernel, CPU, "
    "devices or processes), and there is none behind a filesystem tree"
)
_BINARY_REASON = (
    "offline --root scan: this probe runs {tool}, which would describe the "
    "scanning machine rather than the tree"
)

# Report fields that cannot be answered from a filesystem tree.  Listed in
# scan_mode.not_applicable so every renderer and consumer can tell "not
# applicable" apart from "probed and found nothing".
NOT_APPLICABLE_FIELDS: tuple[str, ...] = (
    "cpu_model",
    "cpu_freq_mhz",
    "cores_logical",
    "cores_physical",
    "mem_total_gb",
    "mem_avail_gb",
    "memory",
    "isa_features",
    "isa_score",
    "isa_tier",
    "isa_reason",
    "accelerators",
    "hsm_present_but_not_pqc",
    "pkcs11_modules",
    "kernel_crypto_hw",
    "ktls_supported",
    "fips",
    "tpm_pqc",
    "memory_bandwidth_gb_s",
    "memory_bandwidth_method",
    "ssh_pqc",
    "kernel_info",
    "fips_pqc_conflict",
    "cnsa_2_0",
    "runtime_environment",
    "service_crypto_linkage",
    "host_fs_detections_unavailable",
    "benchmark",
    "benchmark_tls_handshake",
    "per_algo",
    "production_estimate",
    "replace_required",
)

# Flags whose work needs a live host (or a readiness tier, which needs CPU
# and memory data); rejected with --root rather than silently ignored.
_INCOMPATIBLE_FLAGS: tuple[tuple[str, str], ...] = (
    ("host_mount", "--host-mount"),
    ("bench", "--bench"),
    ("bench_tls", "--bench-tls"),
    ("scan_services", "--scan-services"),
    ("check", "--check"),
    ("fips_strict", "--fips-strict"),
    ("recommend", "--recommend"),
)

# OpenSSL library packages per family, in preference order.
_OPENSSL_PACKAGES: dict[str, tuple[str, ...]] = {
    "rhel": ("openssl-libs", "openssl"),
    "suse": ("libopenssl3", "openssl-3", "openssl"),
    "debian": ("libssl3t64", "libssl3", "openssl"),
    "alpine": ("libssl3", "openssl"),
    "arch": ("openssl",),
}

# ELF e_machine values -> platform.machine()-style names.
_ELF_MACHINES: dict[int, str] = {
    3: "i686",
    40: "arm",
    62: "x86_64",
    183: "aarch64",
    243: "riscv64",
    22: "s390x",
    20: "ppc",
}
_ARCH_PROBE_PATHS: tuple[str, ...] = ("/usr/bin/env", "/bin/sh", "/usr/bin/sh")


def not_applicable(reason: str) -> dict[str, Any]:
    """The marker every dict-valued N/A section carries."""
    return {"available": False, "not_applicable": True, "reason": reason}


def _tree_file(path: str) -> bytes | None:
    """Bytes of a host path inside the tree, following symlinks the way
    the tree's own root would (never into the scanner's filesystem)."""
    try:
        rel = _packages.resolve_under_prefix(path, _platform.HOST_PREFIX)
        with open(_platform.HOST_PREFIX + rel, "rb") as fh:
            return fh.read(64)
    except (OSError, _packages.RpmdbError) as e:
        log.debug("offline root: cannot read %s: %s", path, e)
        return None


def elf_arch(header: bytes) -> str | None:
    """Architecture from an ELF header (class, byte order, e_machine)."""
    if len(header) < 20 or header[:4] != b"\x7fELF":
        return None
    order = "<" if header[5] == 1 else ">"
    (machine,) = struct.unpack_from(order + "H", header, 18)
    if machine == 21:  # EM_PPC64: byte order decides the platform name
        return "ppc64le" if order == "<" else "ppc64"
    if machine == 22 and header[4] == 1:
        return "s390"
    return _ELF_MACHINES.get(machine)


def tree_arch() -> str:
    """The tree's architecture, read from a core binary's ELF header."""
    for path in _ARCH_PROBE_PATHS:
        header = _tree_file(path)
        if header:
            arch = elf_arch(header)
            if arch:
                return arch
    return "unknown"


def tree_hostname() -> str:
    """The tree's configured hostname (/etc/hostname), or ""."""
    try:
        text = _platform.host_path("/etc/hostname").read_text(errors="replace")
    except OSError as e:
        log.debug("offline root: no /etc/hostname: %s", e)
        return ""
    return text.strip().splitlines()[0].strip() if text.strip() else ""


def _version_tuple(version: str) -> list[int] | None:
    m = re.match(r"(?:\d+:)?(\d+)\.(\d+)(?:\.(\d+))?", version)
    if not m:
        return None
    return [int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)]


def openssl_package(family: str) -> dict[str, str] | None:
    """The tree's OpenSSL library package (name, version), from its own
    package database: the only safe source, since running the scanner's
    `openssl` would describe the scanning machine."""
    names = _OPENSSL_PACKAGES.get(family)
    if not names:
        return None
    pkgs: list[dict[str, str]] = []
    if family in ("rhel", "suse"):
        # The full inventory, not a named lookup: it is read in-process for
        # every rpm database format, whereas named lookups on Berkeley DB /
        # ndb run the scanner's `rpm -q` (and on sqlite trust the Name
        # index).  It is cached, so the NSS lookup reuses it.
        inv = _packages.query_rpm_packages()
        if inv.get("available"):
            pkgs = [
                {"name": p["name"], "version": p["version"]}
                for p in inv["packages"]
                if p["name"] in names
            ]
    else:
        try:
            all_pkgs, _ = _packages.read_prefixed_package_db(family)
        except OSError as e:
            log.debug("offline root: no %s package database: %s", family, e)
            return None
        pkgs = [p for p in all_pkgs if p["name"] in names]
    for name in names:
        for p in pkgs:
            if p["name"] == name:
                return p
    return None


def offline_openssl(os_release: dict[str, Any]) -> dict[str, Any]:
    """OpenSSL section for a tree: capability probes are not applicable,
    but the packaged version and the tree's openssl.cnf still answer what
    the image would offer by default."""
    family = os_release.get("family", "unknown")
    pkg = openssl_package(family)
    vt = _version_tuple(pkg["version"]) if pkg else None
    out = not_applicable(_BINARY_REASON.format(tool="`openssl list`"))
    out.update(
        {
            "package": pkg,
            "version_tuple": vt,
            "pqc_native_expected": (tuple(vt[:2]) >= (3, 5)) if vt else None,
            "config": _config_openssl.detect_openssl_config(os_release, vt),
        }
    )
    return out


def offline_nss() -> dict[str, Any]:
    """NSS from the tree's rpm database (certutil would be the scanner's)."""
    found = _protocols._nss_from_rpmdb()
    if found is not None:
        return found
    return not_applicable(
        _BINARY_REASON.format(tool="`certutil --version`")
        + "; no NSS package was found in the tree's rpm database"
    )


def offline_ipsec() -> dict[str, Any]:
    """IPsec: the configured proposals are files in the tree; capability
    comes from running swanctl / ipsec, which is not applicable."""
    out = not_applicable(_BINARY_REASON.format(tool="`swanctl` / `ipsec --version`"))
    out["configured"] = _ike.scan_ike_proposals()
    return out


def scan_mode_record(root: str) -> dict[str, Any]:
    return {
        "mode": MODE,
        "root": root,
        "not_applicable": list(NOT_APPLICABLE_FIELDS),
        "partial": {
            "openssl": "capability probes not applicable; package version and openssl.cnf read from the tree",
            "ipsec_pqc": "capability not applicable; configured proposals read from the tree",
            "nss": "version from the tree's rpm database when present",
        },
        "reason": (
            "Offline scan of a filesystem tree: packages, certificates, keys, "
            "crypto policies, openssl.cnf and signing keys are read from the "
            "tree; host hardware, kernel, process and benchmark sections are "
            "not applicable and no readiness tier is computed."
        ),
    }


VERDICT = "NOT APPLICABLE - offline filesystem scan"


def collect_offline_report(args: argparse.Namespace) -> _report.Report:
    """Assemble the Report for --root PATH from the tree alone."""
    root = _platform.OFFLINE_ROOT
    os_release = _osinfo.detect_os()
    family = os_release.get("family", "unknown")
    host_state = not_applicable(_HOST_STATE_REASON.format(what="this section"))

    trust_store: dict[str, Any] = {}
    if getattr(args, "scan_trust_store", False):
        trust_store = _certs.scan_trust_store(max_certs=args.trust_store_max_certs)
    crypto_material: dict[str, Any] = {}
    if getattr(args, "scan_crypto_material", False):
        crypto_material = _certs_discovery.scan_crypto_material(
            paths=args.crypto_material_path,
            max_files=args.crypto_material_max_files,
        )
    packages: dict[str, Any] = {}
    if getattr(args, "scan_packages", False):
        packages = _packages.scan_packages(os_release)
    signing_keys: dict[str, Any] = {}
    if getattr(args, "scan_signing_keys", False):
        signing_keys = _signing.scan_signing_keys(os_release)

    return _report.Report(
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        hostname=tree_hostname(),
        os=os_release.get("pretty_name") or "unknown",
        arch=tree_arch(),
        isa_tier="not_applicable",
        isa_reason="offline --root scan: no CPU behind a filesystem tree",
        memory=dict(host_state),
        fips=dict(host_state),
        openssl=offline_openssl(os_release),
        tpm_pqc=dict(host_state),
        ssh_pqc=not_applicable(_BINARY_REASON.format(tool="`ssh -Q kex`")),
        ipsec_pqc=offline_ipsec(),
        nss=offline_nss()
        if family in ("rhel", "suse")
        else not_applicable(_BINARY_REASON.format(tool="`certutil --version`")),
        crypto_policy=_config_policy.detect_crypto_policy(),
        kernel_info=dict(host_state),
        fips_pqc_conflict=dict(host_state),
        cnsa_2_0=not_applicable(
            "offline --root scan: CNSA 2.0 evaluation needs the live OpenSSL "
            "algorithm lists and /proc/crypto"
        ),
        trust_store=trust_store,
        crypto_material=crypto_material,
        runtime_environment=dict(host_state),
        service_crypto_linkage=dict(host_state),
        packages=packages,
        signing_keys=signing_keys,
        os_release=os_release,
        verdict=VERDICT,
        verdict_reason=scan_mode_record(root)["reason"],
        exit_code=0,
        inventory_metadata=getattr(args, "inventory_metadata", None),
        scan_mode=scan_mode_record(root),
    )


def apply_root(ap: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    """Validate --root and switch the process into offline mode.  Flags
    that need a live host are usage errors (exit 2), not silently ignored."""
    if not args.root:
        return
    bad = [flag for dest, flag in _INCOMPATIBLE_FLAGS if getattr(args, dest, None)]
    if bad:
        ap.error(
            f"--root scans a filesystem tree offline and cannot be combined with "
            f"{', '.join(bad)} (they need a live host)"
        )
    if not Path(args.root).is_dir():
        ap.error(f"--root: {args.root!r} is not a directory")
    _platform.set_offline_root(str(Path(args.root).resolve()))


@_registry.register_arguments(61)
def add_arguments(ap: argparse.ArgumentParser) -> None:
    """--root."""
    ap.add_argument(
        "--root",
        metavar="PATH",
        default="",
        help=(
            "scan a filesystem tree offline (mounted disk image or extracted "
            "container rootfs): package, certificate, key, crypto-policy, "
            "openssl.cnf and signing-key checks read PATH; CPU, kernel, "
            "device, process and benchmark sections are marked not "
            "applicable.  Unlike --host-mount, no live host is assumed"
        ),
    )
