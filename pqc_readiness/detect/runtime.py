"""Runtime environment (container vs host) and host-filesystem availability notes."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from .. import _platform as _platform

log = logging.getLogger("pqc-readiness")


def _host_fs_note_for(key: str) -> dict[str, Any] | None:
    """Look up `key` in `_HOST_FS_DEPENDENT_DETECTIONS` and return its
    `unavailable_in_container` note (or None).  Sourcing the label and
    host-resource text from the catalogue keeps the per-detection note
    byte-identical to the Report-level `host_fs_detections_unavailable`
    entry for the same key."""
    for k, label, host_resources in _HOST_FS_DEPENDENT_DETECTIONS:
        if k == key:
            return _platform.host_fs_unavailable_note(label, host_resources)
    raise KeyError(f"{key!r} is not in _HOST_FS_DEPENDENT_DETECTIONS")


# ---------------------------------------------------------------------------
# Runtime environment detection (container vs host)
# ---------------------------------------------------------------------------


def parse_cgroup_for_container(text: str) -> str | None:
    """Inspect /proc/1/cgroup content for container-runtime hierarchy
    markers.  Returns a marker string when one is found, else None."""
    for marker in (
        "kubepods",
        "/docker/",
        "/containerd/",
        "/podman-",
        "/crio-",
        "/system.slice/docker-",
        "/lxc/",
    ):
        if marker in text:
            return marker
    return None


# Catalogue of detection probes whose results depend on host filesystem
# paths or host-only commands (lspci / dmidecode).  Used by
# build_host_fs_detections_unavailable() to compute one annotation per
# probe when running inside a container without --host-mount.  The keys
# match Report field names so the aggregator can correlate counts back
# to the field they describe.
_HOST_FS_DEPENDENT_DETECTIONS: tuple[tuple[str, str, str], ...] = (
    (
        "accelerators",
        "PCI accelerator detection",
        "lspci output and /dev hints (/dev/kfd, /dev/nvidia*, etc.)",
    ),
    ("kernel_crypto_hw", "Kernel crypto hardware detection", "/proc/crypto"),
    ("ktls", "kTLS module detection", "/proc/modules and /sys/module/tls"),
    ("fips", "FIPS mode detection", "/proc/sys/crypto/fips_enabled"),
    ("tpm_pqc", "TPM PQC detection", "/dev/tpmrm0, /dev/tpm0 and tpm2_getcap"),
    ("kernel_info", "Kernel info detection", "/etc/redhat-release and /proc/crypto"),
    (
        "os_release",
        "OS release detection",
        "/etc/os-release, /usr/lib/os-release, /etc/redhat-release, /etc/debian_version",
    ),
    (
        "pkcs11_modules",
        "PKCS#11 module scan",
        "/usr/lib*/<arch>/ and /usr/lib*/pkcs11/ under host /usr",
    ),
    (
        "packages",
        "RPM package inventory",
        "the rpm database (/usr/lib/sysimage/rpm, /var/lib/rpm or /usr/share/rpm)",
    ),
    (
        "openssl_config",
        "OpenSSL configuration detection",
        "openssl.cnf and its .include files under /etc and /usr/lib/ssl",
    ),
    (
        "crypto_policy",
        "System crypto-policy detection",
        "/etc/crypto-policies and /usr/share/crypto-policies",
    ),
    (
        "sshd",
        "sshd configuration detection",
        "/etc/ssh, /usr/etc/ssh and the crypto-policies OpenSSH back-ends",
    ),
    (
        "nss",
        "NSS version detection",
        "certutil and the rpm database (/usr/lib/sysimage/rpm, /var/lib/rpm or /usr/share/rpm)",
    ),
)


def build_host_fs_detections_unavailable() -> dict[str, dict[str, Any]]:
    """Compute the `host_fs_detections_unavailable` map for the current
    invocation.  Returns an empty dict on bare metal or when --host-mount
    is in effect; otherwise returns one annotation per host-fs-dependent
    probe in `_HOST_FS_DEPENDENT_DETECTIONS`.  The aggregator preserves
    these keys so fleet rollups can report "X hosts had detection Y
    unavailable in container" without re-running detection."""
    out: dict[str, dict[str, Any]] = {}
    for key, label, host_resources in _HOST_FS_DEPENDENT_DETECTIONS:
        note = _platform.host_fs_unavailable_note(label, host_resources)
        if note:
            out[key] = note
    return out


def detect_runtime_environment() -> dict[str, Any]:
    """Identify whether we're executing inside a container.  Used by
    every detection function that may need a `unavailable_in_container`
    note appended to its result.  Detection is heuristic; combined with
    --host-mount /host the report still produces accurate host data."""
    if _platform.safe_exists(_platform.host_path("/.dockerenv")):
        return {"environment": "container", "evidence": "/.dockerenv present"}
    if _platform.safe_exists(_platform.host_path("/run/.containerenv")):
        return {"environment": "container", "evidence": "/run/.containerenv present"}
    try:
        cg = Path("/proc/1/cgroup").read_text()
    except OSError as e:
        log.debug("detect_runtime_environment: cannot read /proc/1/cgroup: %s", e)
        cg = ""
    marker = parse_cgroup_for_container(cg)
    if marker:
        return {"environment": "container", "evidence": f"cgroup marker {marker}"}
    return {"environment": "host", "evidence": "no container markers"}
