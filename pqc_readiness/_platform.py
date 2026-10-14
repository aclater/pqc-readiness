"""Shared runtime primitives: subprocess runner, host-path prefix (--host-mount), platform shims.

Other modules call these through the module (``_platform._run``) so tests have one patch point."""

from __future__ import annotations

import argparse
import errno
import fnmatch
import functools
import glob as _glob
import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable

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
    # SUSE vendor configuration (/usr/etc/ssh/sshd_config is read when
    # /etc/ssh/sshd_config is absent, measured on Leap 16.0; #105).
    "/usr/etc",
    # Kernel config and module files for boot-chain module-signing
    # detection (#112); reachable through the deployments' /usr mount.
    "/usr/lib/modules",
    # Kubelet container log names, which identify each container's pod
    # (#233); only listed, never opened.
    "/var/log/containers",
)


def set_host_prefix(prefix: str) -> None:
    """Apply --host-mount.  The single writer of HOST_PREFIX, so the value
    has one owner once the code is split across modules (#80); readers
    such as host_path() keep reading the module-level value.  An empty
    string restores bare-metal behaviour."""
    global HOST_PREFIX
    HOST_PREFIX = prefix.rstrip("/")


# Offline scan of a filesystem tree (--root PATH, #152).  Reuses the
# HOST_PREFIX redirection for every file read; OFFLINE_ROOT additionally
# tells collection that there is no live kernel, CPU or process table
# behind the tree, and that binaries on PATH belong to the scanning
# machine rather than the tree.  Empty in live scans.
OFFLINE_ROOT: str = ""


def set_offline_root(root: str) -> None:
    """Apply --root.  Sets HOST_PREFIX too, so prefix-aware readers (rpm,
    dpkg, certificates, crypto policies, openssl.cnf) read the tree.  An
    empty string restores live behaviour."""
    global OFFLINE_ROOT
    OFFLINE_ROOT = root.rstrip("/")
    set_host_prefix(root)


def resolve_in_root(path: str, root: str, max_links: int = 40) -> str:
    """Resolve symlinks in absolute path `path` as a system booted from
    `root` would: each component is looked up under `root`, `..` stops at
    the root, and absolute link targets are re-rooted under it, so a link
    is never followed into the scanning machine's filesystem (#258).
    Returns the resolved root-relative path ("/a/b").  Raises OSError
    (ELOOP) past `max_links` links.  With an empty root this is plain
    symlink resolution."""
    pending = [c for c in path.split("/") if c]
    done: list[str] = []
    links = 0
    while pending:
        part = pending.pop(0)
        if part == ".":
            continue
        if part == "..":
            if done:
                done.pop()
            continue
        candidate = root + "/" + "/".join([*done, part])
        if os.path.islink(candidate):
            links += 1
            if links > max_links:
                raise OSError(errno.ELOOP, "too many symlinks resolving", path)
            target = os.readlink(candidate)
            if target.startswith("/"):
                done = []
            pending = [c for c in target.split("/") if c] + pending
            continue
        done.append(part)
    return "/" + "/".join(done)


# Where host_path() points a path whose symlinks loop under --root: a
# name that can't exist in the tree, so the read fails instead of letting
# the OS follow the loop's last link out of the tree.
_LOOP_SINK = "/.pqc-readiness-symlink-loop"


def host_path(p: str) -> Path:
    """Return Path(p) under HOST_PREFIX when --host-mount is in effect
    and p targets a kernel/state namespace.  Bare-metal callers and
    user-space paths are unaffected.

    Under --root the tree is the whole filesystem, so every absolute path
    maps into it, with symlinks resolved inside the tree (#258): an
    absolute link such as /etc/os-release -> /usr/lib/os-release would
    otherwise be followed by the OS onto the scanning machine's file.
    --host-mount keeps plain prefixing: its /proc holds magic links
    (/proc/<pid>/exe, fd/*) that must be followed as the kernel does."""
    if OFFLINE_ROOT and p.startswith("/"):
        try:
            return Path(OFFLINE_ROOT + resolve_in_root(p, OFFLINE_ROOT))
        except OSError as e:
            log.debug("host_path: cannot resolve %s under --root: %s", p, e)
            return Path(OFFLINE_ROOT + _LOOP_SINK + os.path.normpath(p))
    if HOST_PREFIX and any(
        p == ns or p.startswith(ns + "/") for ns in _HOST_NAMESPACES
    ):
        return Path(HOST_PREFIX + p)
    return Path(p)


def in_tree(p: str | os.PathLike[str]) -> Path:
    """A path that is already under the --root tree or --host-mount prefix
    (typically an entry from listing a directory), with its symlinks
    resolved inside that prefix before it is opened, so an absolute link
    never reaches the scanning machine's files (#258).  Without a prefix,
    or for a path outside it, it is returned unchanged.  Not for /proc:
    its magic links must be followed as the kernel does."""
    s = os.fspath(p)
    pre = HOST_PREFIX
    if not pre or not (s == pre or s.startswith(pre + "/")):
        return Path(s)
    rel = s[len(pre) :] or "/"
    try:
        return Path(pre + resolve_in_root(rel, pre))
    except OSError as e:
        log.debug("in_tree: cannot resolve %s: %s", s, e)
        return Path(pre + _LOOP_SINK + os.path.normpath(rel))


def host_glob(pattern: str) -> list[str]:
    """Host paths matching absolute glob `pattern` (`*`, `?`, `[...]` per
    component; no `**`), sorted.  Under a prefix every directory on the
    way is resolved inside it, so a linked directory such as an absolute
    /etc/openvpn -> /etc/openvpn is listed in the tree, not on the
    scanning machine (#258).  Results are the logical paths (the names
    the pattern matched), not their link targets."""
    pre = HOST_PREFIX
    if not pre:
        return sorted(_glob.glob(pattern))
    found = ["/"]
    for part in (c for c in pattern.split("/") if c):
        nxt: list[str] = []
        for base in found:
            child = base.rstrip("/") + "/"
            if not _glob.has_magic(part):
                nxt.append(child + part)
                continue
            try:
                names = os.listdir(pre + resolve_in_root(base, pre))
            except OSError:
                continue
            nxt.extend(
                child + n
                for n in sorted(names)
                if fnmatch.fnmatchcase(n, part)
                and (part.startswith(".") or not n.startswith("."))
            )
        found = nxt
    out = []
    for p in found:
        try:
            if os.path.lexists(pre + resolve_in_root(p, pre)):
                out.append(p)
        except OSError:
            continue
    return out


# Path probes that never raise (#229).  On Python 3.9-3.12, Path.is_dir(),
# is_file(), exists() and is_symlink() swallow only ENOENT/ENOTDIR/EBADF/
# ELOOP and raise on EACCES, so a single unreadable host directory (SELinux
# or AppArmor denial in a confined container, a 0700 dir on bare metal)
# would abort the whole scan.  Detectors probe host paths through these
# instead, and an unreadable path reads as absent for that detection only.
# tests/test_unreadable_paths.py enforces their use under pqc_readiness/detect.


def _probe(p: str | os.PathLike[str], test: Callable[[Path], bool]) -> bool:
    try:
        return test(Path(p))
    except (OSError, ValueError) as e:  # ValueError: embedded NUL in a path
        log.debug("path probe failed for %s: %s", p, e)
        return False


def safe_is_dir(p: str | os.PathLike[str]) -> bool:
    """Path(p).is_dir(), but False instead of raising (e.g. EACCES)."""
    return _probe(p, Path.is_dir)


def safe_is_file(p: str | os.PathLike[str]) -> bool:
    """Path(p).is_file(), but False instead of raising (e.g. EACCES)."""
    return _probe(p, Path.is_file)


def safe_exists(p: str | os.PathLike[str]) -> bool:
    """Path(p).exists(), but False instead of raising (e.g. EACCES)."""
    return _probe(p, Path.exists)


def safe_is_symlink(p: str | os.PathLike[str]) -> bool:
    """Path(p).is_symlink(), but False instead of raising (e.g. EACCES)."""
    return _probe(p, Path.is_symlink)


def safe_iterdir(p: str | os.PathLike[str]) -> list[Path]:
    """Path(p).iterdir() as a list, or [] when the directory can't be
    listed (missing, not a directory, or unreadable)."""
    try:
        return list(Path(p).iterdir())
    except OSError as e:
        log.debug("cannot list %s: %s", p, e)
        return []


def safe_listdir(p: str | os.PathLike[str]) -> list[str]:
    """os.listdir(p), or [] when the directory can't be listed."""
    try:
        return os.listdir(p)
    except OSError as e:
        log.debug("cannot list %s: %s", p, e)
        return []


def guarded_scan(
    name: str, fn: Callable[..., dict[str, Any]], *a: Any, **kw: Any
) -> dict[str, Any]:
    """Run an opt-in scanner so that an OSError it didn't handle (an
    unreadable host path: SELinux/AppArmor denial, a 0700 directory)
    marks that section unavailable instead of aborting the scan (#229).
    Other exceptions still propagate: they're bugs, not host state."""
    try:
        return fn(*a, **kw)
    except OSError as e:
        where = f": {e.filename}" if e.filename else ""
        reason = f"unreadable{where}: {e.strerror or e}"
        log.warning("%s: skipped, %s", name, reason)
        return {"available": False, "reason": reason}


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
