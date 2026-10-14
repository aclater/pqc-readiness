"""Reading host configuration files: absent vs unreadable (#232).

A config reader that collapses every OSError into "not there" tells an
unprivileged scan that sshd isn't configured when the file is merely
0600 root (RHCOS ships sshd_config that way), so the verdict says
`not_present` instead of `unknown`.  Readers here keep the two apart:

- a missing path returns ``None``;
- a path that exists but can't be read raises :class:`ConfigUnreadable`
  carrying a short reason.

Permission errors also surface from ``stat()``-based checks such as
``Path.exists()`` on Python <= 3.12 when a parent directory isn't
searchable, so every check here catches them and reports *unreadable*,
not absent.
"""

from __future__ import annotations

import errno
import logging
import stat
from pathlib import Path

from .. import _platform as _platform
from . import packages as _packages

log = logging.getLogger("pqc-readiness")

PERMISSION_HINT = "run as root or with CAP_DAC_READ_SEARCH"

_ABSENT_ERRNOS = frozenset({errno.ENOENT, errno.ENOTDIR})

# Every config read is capped: a scanned tree may be hostile, and real
# configs are a few KiB.
DEFAULT_MAX_BYTES = 1024 * 1024


class ConfigUnreadable(Exception):
    """A host config path exists (or may exist) but can't be read."""

    def __init__(self, path: str, reason: str) -> None:
        super().__init__(f"{path}: {reason}")
        self.path = path
        self.reason = reason

    def as_entry(self) -> dict[str, str]:
        return {"path": self.path, "reason": self.reason}


def reason_for(e: OSError) -> str | None:
    """Why `e` stops a read, or None when it means the path is absent."""
    if e.errno in _ABSENT_ERRNOS:
        return None
    if isinstance(e, PermissionError):
        return f"permission denied; {PERMISSION_HINT}"
    if e.errno == errno.ELOOP:
        return "symlink loop"
    if e.errno == errno.EISDIR:
        return "is a directory"
    return e.strerror or str(e)


def host_file(path: str) -> Path:
    """`path` on the host: symlinks resolved inside HOST_PREFIX, so a host
    link is never followed into the scanner container's own filesystem."""
    try:
        resolved = _packages.resolve_under_prefix(path, _platform.HOST_PREFIX)
    except _packages.RpmdbError as e:
        raise ConfigUnreadable(path, str(e)) from e
    return Path(_platform.HOST_PREFIX + resolved)


def read_host_text(path: str, max_bytes: int = DEFAULT_MAX_BYTES) -> str | None:
    """Text of host config file `path`; None when it doesn't exist.
    Raises ConfigUnreadable when it exists but can't be read, isn't a
    regular file, or is larger than `max_bytes`.  The read itself is
    bounded too, since st_size can understate (a file growing after
    stat(), or a pseudo-file reporting 0)."""
    p = host_file(path)
    try:
        st = p.stat()
    except OSError as e:
        reason = reason_for(e)
        if reason is None:
            return None
        raise ConfigUnreadable(path, reason) from e
    if not stat.S_ISREG(st.st_mode):
        raise ConfigUnreadable(path, "not a regular file")
    too_big = ConfigUnreadable(path, f"larger than {max_bytes} bytes; skipped")
    if st.st_size > max_bytes:
        raise too_big
    try:
        with p.open("rb") as f:
            data = f.read(max_bytes + 1)
    except OSError as e:
        reason = reason_for(e)
        if reason is None:  # removed between stat() and open()
            return None
        raise ConfigUnreadable(path, reason) from e
    if len(data) > max_bytes:
        raise too_big
    # Universal newlines, as Path.read_text() gave the parsers before.
    text = data.decode("utf-8", errors="replace")
    return text.replace("\r\n", "\n").replace("\r", "\n")


def list_host_dir(path: str) -> list[str] | None:
    """Entry names in host directory `path`; None when it doesn't exist.
    Raises ConfigUnreadable when it exists but can't be listed."""
    p = host_file(path)
    try:
        return sorted(e.name for e in p.iterdir())
    except OSError as e:
        reason = reason_for(e)
        if reason is None:
            return None
        raise ConfigUnreadable(path, reason) from e


def probe(path: str) -> str | None:
    """Why host path `path` can't be read, or None when it is readable or
    absent.  For callers whose reader only says "no text"."""
    try:
        p = host_file(path)
        if p.is_dir():
            list_host_dir(path)
        else:
            read_host_text(path)
    except ConfigUnreadable as e:
        return e.reason
    except OSError as e:  # is_dir() itself on Python <= 3.12
        return reason_for(e)
    return None


def present(path: str) -> bool:
    """Whether host path `path` exists, counting one this user can't see
    into as existing (only ENOENT/ENOTDIR mean absent)."""
    try:
        host_file(path).lstat()
    except ConfigUnreadable:
        return True
    except OSError as e:
        return reason_for(e) is not None
    return True
