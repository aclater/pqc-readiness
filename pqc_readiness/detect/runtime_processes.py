"""All-process -> crypto library attribution (--scan-processes, #155).

--scan-services (#111) answers "which library negotiates on this port";
this extends the same /proc inspection to every process, so TLS *clients*
are covered too: package managers, agents, backup and monitoring daemons
that only ever connect out.  Their PQC readiness is client-side readiness,
and a process with no listening socket never shows up in a service scan.

Output is grouped by (executable, crypto libraries + versions, Go TLS
default) so its size is bounded by the number of distinct binaries, not
the number of processes; each group carries a process count and a few
sample PIDs.  Per process, socket state classifies the role:

* ``server``  -- holds at least one listening TCP / bound UDP socket;
* ``client``  -- holds established TCP connections but no listening socket
  (outbound-only: the population a service scan cannot see);
* ``idle``    -- neither (e.g. a CLI linked against libcrypto but not
  currently talking).

"Established TCP" says nothing about TLS on that connection; the role only
tells you which processes *would* negotiate as a client with the library
they have mapped.

Pure /proc reads through ``host_path`` (no subprocesses, no network), the
helpers shared with runtime_services: maps parsing, embedded library
versions, Go buildinfo, systemd unit from the cgroup path.  Bounded by a
PID cap, a wall-clock budget and a group cap.  Without root (or
CAP_SYS_PTRACE + CAP_DAC_READ_SEARCH) other users' processes are
unreadable; they are counted, never guessed.
"""

from __future__ import annotations

import argparse
import logging
import os
import time
from typing import Any

from .. import _platform as _platform
from .. import registry as _registry
from . import runtime_services as _svc

log = logging.getLogger("pqc-readiness")

PROCESSES_MAX_PIDS_DEFAULT = 16384
PROCESSES_TIME_BUDGET_S_DEFAULT = 30.0
# Distinct (exe, libraries, Go default) combinations kept in the output;
# beyond this, groups are counted in `omitted_groups`.
PROCESSES_MAX_GROUPS_DEFAULT = 500
_SAMPLE_PIDS = 5
_MAX_UNITS = 10
_MAX_CONTAINERS = 10

_TCP_ESTABLISHED = "01"


def parse_established_inodes(text: str) -> set[int]:
    """Socket inodes in TCP state ESTABLISHED from a /proc/net/tcp{,6} table.

    Malformed rows are skipped (debug log) rather than aborting the scan."""
    out: set[int] = set()
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 10 or parts[3] != _TCP_ESTABLISHED:
            continue
        try:
            inode = int(parts[9])
        except ValueError:
            log.debug("processes: skipping /proc/net row %r", line)
            continue
        if inode:
            out.add(inode)
    return out


def _netns_tables(pid: int) -> tuple[set[int], set[int]]:
    """(listening inodes, established TCP inodes) for pid's network namespace."""
    listening = {s["inode"] for s in _svc._listening_sockets(pid)}
    established: set[int] = set()
    for name in ("tcp", "tcp6"):
        try:
            text = _svc._proc(pid, "net", name).read_text()
        except OSError as e:
            log.debug("processes: cannot read /proc/%s/net/%s: %s", pid, name, e)
            continue
        established |= parse_established_inodes(text)
    return listening, established


def group_pqc_capable(details: dict[str, Any]) -> bool | None:
    """Whether everything the process could negotiate TLS with is PQC-capable.

    False when any mapped crypto library is known not to be (it may be the
    one the process uses), or a Go binary has no hybrid ML-KEM default;
    True when every library / the Go runtime is known capable; None when
    nothing is known (no crypto library and not Go, or versions unknown)."""
    verdicts = [lib.get("library_pqc_capable") for lib in details["crypto_libraries"]]
    go = details.get("go")
    if go is not None:
        verdicts.append(go.get("default_hybrid_kex") is not None)
    if any(v is False for v in verdicts):
        return False
    if verdicts and all(v is True for v in verdicts):
        return True
    return None


def _group_key(details: dict[str, Any]) -> tuple[Any, ...]:
    libs = tuple(
        sorted(
            (lib["family"], lib["version"] or "", lib["path"], bool(lib["deleted"]))
            for lib in details["crypto_libraries"]
        )
    )
    go = details.get("go")
    go_key = (go.get("go_version"), go.get("default_hybrid_kex")) if go else None
    return (details.get("exe") or details.get("process") or "?", libs, go_key)


def _role(socket_inodes: set[int], listening: set[int], established: set[int]) -> str:
    if socket_inodes & listening:
        return "server"
    if socket_inodes & established:
        return "client"
    return "idle"


def scan_processes(
    max_pids: int = PROCESSES_MAX_PIDS_DEFAULT,
    time_budget_s: float = PROCESSES_TIME_BUDGET_S_DEFAULT,
    max_groups: int = PROCESSES_MAX_GROUPS_DEFAULT,
) -> dict[str, Any]:
    """Map every process to the crypto library (or Go runtime) it has loaded.

    Result: ``{available, groups: [...], summary, scanned_pids,
    unreadable_pids, kernel_threads, truncated, omitted_groups, limits}`` or
    ``{available: False, reason}``.  Only processes that map a crypto
    library or are Go binaries are grouped; the rest are counted in
    ``summary.processes_without_crypto``."""
    if not _platform.is_linux():
        return {"available": False, "reason": "process scan needs Linux /proc"}
    started = time.monotonic()
    pids = _svc._pids()
    if not pids:
        return {"available": False, "reason": "cannot list /proc"}
    host_ns = _svc._netns(1)
    # The scanner maps libcrypto itself (hashlib); it is not part of the
    # host's inventory.  /proc/self under the host prefix resolves to this
    # process's PID in that /proc's PID namespace (hostPID DaemonSets too).
    # Without a host prefix /proc is our own, so os.getpid() is a safe
    # fallback; under --host-mount our local PID belongs to another PID
    # namespace and must not be used to drop a host process.
    own_pid: int | None
    try:
        own_pid = int(os.readlink(_platform.host_path("/proc/self")))
    except (OSError, ValueError):
        own_pid = None if _platform.HOST_PREFIX else os.getpid()
    pids = [p for p in pids if p != own_pid]
    truncated = len(pids) > max_pids
    pids = pids[:max_pids]

    cache = _svc._Cache()
    tables: dict[str | None, tuple[set[int], set[int]]] = {}
    groups: dict[tuple[Any, ...], dict[str, Any]] = {}
    scanned = unreadable = kernel_threads = without_crypto = 0
    for pid in pids:
        if time.monotonic() - started > time_budget_s:
            truncated = True
            break
        try:
            maps = _svc._proc(pid, "maps").read_text()
        except PermissionError:
            unreadable += 1
            continue
        except OSError as e:  # exited mid-scan
            log.debug("processes: cannot read /proc/%s/maps: %s", pid, e)
            continue
        scanned += 1
        # /proc/<pid>/net shows the namespace's tables, identical for every
        # process in it: read them once, from the first process seen there.
        ns = _svc._netns(pid)
        if ns not in tables:
            tables[ns] = _netns_tables(pid)
        if not maps and _svc._exe(pid) is None:
            # Kernel threads have no address space and no exe link.
            kernel_threads += 1
            continue
        details = _svc._process_details(pid, cache, maps)
        if not details["crypto_libraries"] and details.get("go") is None:
            without_crypto += 1
            continue
        listening, established = tables[ns]
        inodes = _svc._socket_inodes(pid)
        role = _role(inodes or set(), listening, established)
        key = _group_key(details)
        g = groups.get(key)
        if g is None:
            g = groups[key] = {
                "exe": details.get("exe"),
                "process": details.get("process"),
                "crypto_libraries": details["crypto_libraries"],
                "static_binary": details.get("static_binary"),
                "go": details.get("go"),
                "pqc_capable": group_pqc_capable(details),
                "process_count": 0,
                "sample_pids": [],
                "systemd_units": set(),
                # Container ID -> container_identity() (#262).
                "containers": {},
                "container_processes": 0,
                "network_namespaces": set(),
                "roles": {"server": 0, "client": 0, "idle": 0},
                "established_tcp_connections": 0,
                "fd_unreadable_processes": 0,
            }
        g["process_count"] += 1
        if len(g["sample_pids"]) < _SAMPLE_PIDS:
            g["sample_pids"].append(pid)
        if details.get("systemd_unit"):
            g["systemd_units"].add(details["systemd_unit"])
        container = details.get("container")
        if container:
            g["container_processes"] += 1
            g["containers"].setdefault(container["id"], container)
        g["network_namespaces"].add(
            "host" if ns is not None and ns == host_ns else "other"
        )
        g["roles"][role] += 1
        if inodes is None:
            g["fd_unreadable_processes"] += 1
        else:
            g["established_tcp_connections"] += len(inodes & established)

    ordered = sorted(
        groups.values(),
        key=lambda g: (
            {False: 0, None: 1, True: 2}[g["pqc_capable"]],
            -g["process_count"],
            g["exe"] or "",
        ),
    )
    kept = ordered[:max_groups]
    for g in kept:
        units = sorted(g["systemd_units"])
        g["systemd_units"] = units[:_MAX_UNITS]
        if len(units) > _MAX_UNITS:
            g["systemd_units_omitted"] = len(units) - _MAX_UNITS
        g["network_namespaces"] = sorted(g["network_namespaces"])
        containers = sorted(
            g["containers"].values(),
            key=lambda c: (
                c.get("pod_namespace") or "~",
                c.get("pod_name") or "~",
                c.get("container_name") or "~",
                c["id"],
            ),
        )
        g["containers"] = containers[:_MAX_CONTAINERS]
        if len(containers) > _MAX_CONTAINERS:
            g["containers_omitted"] = len(containers) - _MAX_CONTAINERS

    with_crypto = sum(g["process_count"] for g in ordered)
    by_family: dict[str, int] = {}
    for g in ordered:
        fams = {lib["family"] for lib in g["crypto_libraries"]}
        if g["go"] is not None:
            fams.add("go")
        for f in fams:
            by_family[f] = by_family.get(f, 0) + g["process_count"]
    not_capable = [g for g in ordered if g["pqc_capable"] is False]
    result: dict[str, Any] = {
        "available": True,
        "groups": kept,
        "summary": {
            "groups": len(ordered),
            "processes_with_crypto": with_crypto,
            "processes_without_crypto": without_crypto,
            "processes_by_crypto_family": dict(sorted(by_family.items())),
            "processes_not_pqc_capable": sum(g["process_count"] for g in not_capable),
            "client_processes_not_pqc_capable": sum(
                g["roles"]["client"] for g in not_capable
            ),
            "processes_with_deleted_crypto_library": sum(
                g["process_count"]
                for g in ordered
                if any(lib["deleted"] for lib in g["crypto_libraries"])
            ),
        },
        "scanned_pids": scanned,
        "unreadable_pids": unreadable,
        "kernel_threads": kernel_threads,
        "truncated": truncated,
        "omitted_groups": len(ordered) - len(kept),
        "limits": {
            "max_pids": max_pids,
            "time_budget_s": time_budget_s,
            "max_groups": max_groups,
        },
    }
    if unreadable:
        result["note"] = (
            f"{unreadable} process(es) could not be inspected; run as root (or with "
            "CAP_SYS_PTRACE and CAP_DAC_READ_SEARCH) for complete attribution"
        )
    container = _platform.host_fs_unavailable_note(
        "Process crypto linkage",
        "/proc/<pid>/{maps,exe,root,fd,net} for host processes (needs hostPID)",
    )
    if container:
        result.update(container)
    return result


@_registry.register_arguments(54)
def add_arguments(ap: argparse.ArgumentParser) -> None:
    """--scan-processes."""
    ap.add_argument(
        "--scan-processes",
        action="store_true",
        help=(
            "map every running process (servers and outbound-only clients) "
            "to the crypto library or Go runtime it has loaded, grouped by "
            "executable and library version; reads /proc only, needs root "
            "for other users' processes"
        ),
    )
