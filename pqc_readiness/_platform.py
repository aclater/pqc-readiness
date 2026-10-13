"""Shared runtime primitives: subprocess runner, host-path prefix (--host-mount), platform shims.

Other modules call these through the module (``_platform._run``) so tests have one patch point."""

from __future__ import annotations

import argparse
import functools
import logging
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from .detect import runtime as _runtime
from . import registry as _registry


# Module logger.  Silent by default (WARNING); --debug routes DEBUG to
# stderr so field operators can tell "tool absent" from "tool present but
# read/parse failed" without reading the source.
log = logging.getLogger("pqc-readiness")


# Host-filesystem prefix for DaemonSet / containerized invocations.  When
# the tool runs inside a container with the host's /proc /sys /dev /etc
# bind-mounted under (e.g.) /host, --host-mount /host sets this prefix
# so detection still reads from the host rather than the container's
# own pid 1 namespace.  Empty in normal bare-metal use.
HOST_PREFIX: str = ""


# Path namespaces that should be redirected through HOST_PREFIX when set.
# Paths outside these namespaces (binary lookups, /opt/..., /tmp/...) are
# left alone — they belong to the running container, not the host kernel.
# /usr/lib/os-release is enumerated explicitly because /etc/os-release is
# a symlink to it on most modern distros (Fedora, Debian, Ubuntu, Arch);
# bind-mounting only /etc would dangle the symlink in the container.
_HOST_NAMESPACES = (
    "/proc",
    "/sys",
    "/dev",
    "/etc",
    "/var/lib/dpkg",
    "/usr/share",
    "/usr/lib/os-release",
)


def set_host_prefix(prefix: str) -> None:
    """Apply --host-mount.  The single writer of HOST_PREFIX, so the value
    has one owner once the code is split across modules (#80); readers
    such as host_path() keep reading the module-level value.  An empty
    string restores bare-metal behaviour."""
    global HOST_PREFIX
    HOST_PREFIX = prefix.rstrip("/")


def host_path(p: str) -> Path:
    """Return Path(p) under HOST_PREFIX when --host-mount is in effect
    and p targets a kernel/state namespace.  Bare-metal callers and
    user-space paths are unaffected."""
    if HOST_PREFIX and any(
        p == ns or p.startswith(ns + "/") for ns in _HOST_NAMESPACES
    ):
        return Path(HOST_PREFIX + p)
    return Path(p)


def host_fs_unavailable_note(
    detection_label: str, host_resources: str
) -> dict[str, Any] | None:
    """Return an `unavailable_in_container` annotation when running inside
    a container without `--host-mount` for a detection whose result
    depends on the host filesystem (any of /proc /sys /dev /etc /var/lib
    /usr/lib) or on `lspci` / `dmidecode` whose output reflects the
    container's view, not the host.  Returns None when the detection is
    trustworthy: bare-metal invocation, or --host-mount in effect.

    detection_label is the human-readable name of the detection (e.g.
    "PCI accelerator detection"); host_resources names the host-fs
    paths or commands the detection consults.  Both are surfaced verbatim
    in the returned `reason` field so consumers can render a precise
    "X is unavailable because Y" message."""
    if HOST_PREFIX:
        return None
    env = _runtime.detect_runtime_environment()
    if env.get("environment") != "container":
        return None
    return {
        "unavailable_in_container": True,
        "reason": (
            f"{detection_label} reads {host_resources}; running inside a "
            f"container without --host-mount, so the result reflects the "
            f"container's namespace, not the host."
        ),
    }


# ---------------------------------------------------------------------------
# Platform shims
# ---------------------------------------------------------------------------


def _run(cmd: list[str], timeout: int = 10) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError) as e:
        log.debug("run %s failed: %s", cmd, e)
        return 127, str(e)
    log.debug("run %s -> rc=%d", cmd, p.returncode)
    return p.returncode, (p.stdout or "") + (p.stderr or "")


# openssl version output is constant for the process lifetime; cache to
# avoid repeated subprocess calls.
@functools.lru_cache(maxsize=None)
def _openssl_version_text() -> tuple[int, str]:
    """Return cached (rc, text) from `openssl version`. Constant per process.
    Tests requiring a fresh subprocess call must invoke .cache_clear()."""
    return _run(["openssl", "version"], timeout=5)


def _sysctl(key: str) -> str:
    if not shutil.which("sysctl"):
        return ""
    rc, out = _run(["sysctl", "-n", key], timeout=3)
    return out.strip() if rc == 0 else ""


def is_linux() -> bool:
    return sys.platform.startswith("linux")


def is_macos() -> bool:
    return sys.platform == "darwin"


@_registry.register_arguments(60)
def add_arguments(ap: argparse.ArgumentParser) -> None:
    """--host-mount."""
    ap.add_argument(
        "--host-mount",
        metavar="PATH",
        default="",
        help=(
            "path where the host root is mounted (DaemonSet / quadlet "
            "pattern); host reads of /proc /sys /dev /etc, os-release and "
            "the rpm / dpkg databases go through it"
        ),
    )
