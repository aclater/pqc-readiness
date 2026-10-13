"""OpenSSL microbenchmarks, loopback TLS handshake benchmark, memory bandwidth probe."""

from __future__ import annotations

import argparse
import logging
import re
import select
import shutil
import socket
import statistics
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

from . import _platform as _platform
from .detect import config as _config
from . import registry as _registry

log = logging.getLogger("pqc-readiness")


# ---------------------------------------------------------------------------
# Benchmarking
# ---------------------------------------------------------------------------


def parse_speed_row(
    text: str, algo: str, labels: tuple[str, ...]
) -> dict[str, float] | None:
    """Parse the per-algorithm summary row from `openssl speed` output.

    The summary row looks like:
        ML-KEM-768 0.000027s 0.000017s 0.000026s   37542.4   59259.0   38383.0
    The first len(labels) columns are seconds-per-op; the last len(labels)
    columns are ops/sec.  We take the trailing rates.

    Bug fixes:
      - Use `\\d+(?:\\.\\d+)?` so integer rates (slow algorithms like
        SLH-DSA, where ops/sec may print as a bare integer in some builds)
        are not silently dropped.
      - Match the algo name anywhere on the line via word boundaries, not
        just at column zero, since some OpenSSL builds prefix the row with
        parameter strings.
    """
    needle = re.escape(algo)
    pat = re.compile(rf"\b{needle}\b")
    for line in text.splitlines():
        if not pat.search(line):
            continue
        nums = re.findall(r"\d+(?:\.\d+)?", line)
        if len(nums) >= len(labels) * 2:
            tail = nums[-len(labels) :]
            return {labels[i]: float(tail[i]) for i in range(len(labels))}
    return None


def parse_classical_speed(text: str) -> dict[str, dict[str, float]]:
    """Parse classical asymmetric `openssl speed` output.

    Headers vary by algorithm: RSA emits `sign/s verify/s encr./s decr./s`,
    ECDH emits `op/s`, EdDSA emits `sign/s verify/s`, and PQC-style entries
    (rsa-as-KEM) emit `keygens/s encaps/s decaps/s` or `keygens/s sign/s
    verify/s`.  A header is followed by a single data row whose trailing
    columns hold the per-second rates.

    Detection rule: a line is a header iff it contains 1+ tokens ending in
    `/s` and no numeric leading content.  Earlier code required the
    literal substring `op/s`, which silently skipped RSA/EdDSA/PQC headers.
    """
    out: dict[str, dict[str, float]] = {}
    pending: list[str] = []
    # Algorithm names can appear at column 0 (`rsa  2048 bits ...`,
    # `rsa2048 ...`) or mid-line wrapped in a description
    # (` 253 bits ecdh (X25519)`, ` 253 bits EdDSA (Ed25519)`).
    name_re = re.compile(
        r"\b(rsa\s*\d+|ed25519|ed448|ecdh|ecdsa|eddsa|x25519|x448)\b",
        re.IGNORECASE,
    )
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        per_s_tokens = re.findall(r"\S+?/s\b", s)
        # A header line: contains one or more `*/s` tokens and does not
        # start with a digit (data rows like ` 253 bits ...` start with
        # numeric content).
        if per_s_tokens and not re.match(r"^\s*\d", line):
            pending = per_s_tokens
            continue
        if not pending:
            continue
        m = name_re.search(line)
        if not m:
            continue
        name = re.sub(r"\s+", "", m.group(1).lower())
        nums = re.findall(r"\d+(?:\.\d+)?", line)
        if len(nums) < len(pending):
            continue
        rates = [float(x) for x in nums[-len(pending) :]]
        # The same algorithm appears under several header sections in
        # `openssl speed` (OpenSSL 3.5 runs RSA as a legacy block, then as
        # a KEM, then as a signature scheme, with no flag to narrow it).
        # The legacy block keeps the bare key so existing consumers see the
        # same numbers; the KEM / signature blocks (marked by a keygens/s
        # column) land under `<name>_kem` / `<name>_signature` rather than
        # being discarded — RSA keygen/s is the classical counterpart to
        # ML-KEM / ML-DSA keygen (#117).
        if "keygens/s" in pending:
            name += "_kem" if "encaps/s" in pending else "_signature"
        out.setdefault(name, dict(zip(pending, rates)))
        pending = []
    return out


BENCH_SKIPPED_NOT_PROVIDED = "algorithm not provided by this OpenSSL"


def _bench_provided_algorithms(osinfo: dict[str, Any] | None) -> set[str] | None:
    """KEM + signature algorithm names this OpenSSL exposes, taken from the
    lists openssl_capability() already gathered (no extra subprocess).

    Returns None when no capability data is available, which the caller
    must treat as "unknown" and fall back to its own lookup.  Names are
    upper-cased so the membership test is case-insensitive."""
    if not osinfo or not osinfo.get("available"):
        return None
    names = list(osinfo.get("kem_algorithms") or []) + list(
        osinfo.get("sig_algorithms") or []
    )
    return {n.upper() for n in names}


def _bench_lookup_provided_algorithms() -> set[str]:
    """Standalone fallback for run_benchmarks() callers that do not pass
    capability data: query the KEM and signature lists directly."""
    provided: set[str] = set()
    for flag, pattern in (
        ("-kem-algorithms", r"ML-KEM-\d+"),
        ("-signature-algorithms", r"ML-DSA-\d+|SLH-DSA-[A-Za-z0-9-]+"),
    ):
        rc, text = _platform._run(["openssl", "list", flag], timeout=5)
        if rc == 0:
            provided |= {a.upper() for a in re.findall(pattern, text)}
    return provided


def run_pqc_bench(
    seconds: int, threads: int, provided: set[str] | None = None
) -> dict[str, Any]:
    """Run `openssl speed` for each PQC algorithm in the plan.

    `provided` is the set of (upper-cased) algorithm names this OpenSSL
    exposes.  An algorithm outside it is never benchmarked: given a name
    it does not recognise, `openssl speed -signature-algorithms NAME`
    silently benchmarks *every* signature algorithm (and likewise for
    KEMs), which burns the whole timeout and then reports a misleading
    failure (#117).  None means "unknown" and is resolved by a direct
    lookup so the guard always applies."""
    if provided is None:
        provided = _bench_lookup_provided_algorithms()
    plan: list[tuple[str, str, tuple[str, ...]]] = [
        ("ML-KEM-768", "-kem-algorithms", ("keygen/s", "encaps/s", "decaps/s")),
        ("ML-DSA-65", "-signature-algorithms", ("keygen/s", "sign/s", "verify/s")),
        (
            "SLH-DSA-SHA2-128s",
            "-signature-algorithms",
            ("keygen/s", "sign/s", "verify/s"),
        ),
    ]
    results: dict[str, Any] = {}
    for algo, flag, labels in plan:
        if algo.upper() not in provided:
            log.debug("run_pqc_bench: skipping %s: %s", algo, BENCH_SKIPPED_NOT_PROVIDED)
            results[algo] = {"skipped": BENCH_SKIPPED_NOT_PROVIDED}
            continue
        cmd = ["openssl", "speed", "-seconds", str(seconds), flag, algo]
        rc, out = _platform._run(cmd, timeout=seconds * 8 + 30)
        if rc != 0:
            results[algo] = {
                "error": out.strip().splitlines()[-1][:200] if out else f"rc={rc}"
            }
            continue
        rates = parse_speed_row(out, algo, labels)
        if rates is None:
            results[algo] = {"raw": out.strip().splitlines()[-1][:200]}
        else:
            results[algo] = rates
        if threads > 1:
            cmd_m = [
                "openssl",
                "speed",
                "-multi",
                str(threads),
                "-seconds",
                str(seconds),
                flag,
                algo,
            ]
            rc2, out2 = _platform._run(cmd_m, timeout=seconds * 8 + 60)
            if rc2 == 0:
                m_rates = parse_speed_row(out2, algo, labels)
                if m_rates:
                    results[algo][f"x{threads}_aggregate"] = m_rates
    return results


def run_classical_baseline(seconds: int) -> dict[str, dict[str, float]]:
    rc, out = _platform._run(
        [
            "openssl",
            "speed",
            "-seconds",
            str(seconds),
            "rsa2048",
            "ed25519",
            "ecdhx25519",
        ],
        timeout=seconds * 6 + 30,
    )
    if rc != 0:
        return {}
    return parse_classical_speed(out)


def run_benchmarks(
    seconds: int = 1,
    threads: int = 1,
    osinfo: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Microbenchmark PQC + classical primitives.  Pass `osinfo` (the
    openssl_capability() result) to reuse its algorithm lists; without it
    the lists are looked up directly so the #117 guard still applies."""
    if not shutil.which("openssl"):
        return {"available": False, "reason": "openssl not on PATH"}
    rc, ver = _platform._openssl_version_text()
    m = re.search(r"OpenSSL\s+(\d+)\.(\d+)", ver)
    if not m or (int(m.group(1)), int(m.group(2))) < (3, 5):
        return {"available": False, "reason": f"OpenSSL pre-3.5 (got {ver.strip()})"}
    return {
        "available": True,
        "engine": "openssl speed",
        "seconds_per_test": seconds,
        "threads": threads,
        "pqc": run_pqc_bench(seconds, threads, _bench_provided_algorithms(osinfo)),
        "classical": run_classical_baseline(seconds),
    }


# ---------------------------------------------------------------------------
# TLS-handshake benchmark
#
# `openssl speed` measures algorithm operations in isolation; it does not
# capture the network-side cost of larger PQC keys and signatures (cert
# chain inflation, initcwnd overflow) that only shows up at the handshake
# layer specified in RFC 8446.  This benchmark drives `openssl s_server`
# and `openssl s_client` over loopback so the wire-side bandwidth impact
# becomes visible alongside the algorithm-level numbers.
# ---------------------------------------------------------------------------


def _tls_pick_classical_group(classical: list[str]) -> str | None:
    """Pick a sensible classical TLS 1.3 group for the baseline.

    Prefer x25519 (modern default); fall back to secp256r1 if x25519 is
    not exposed by the local OpenSSL.  Older curves (secp384r1, etc.)
    are accepted only as a last resort so the comparison stays apples
    to apples with the PQC suites.
    """
    lowered = {g.lower(): g for g in classical}
    for pref in ("x25519", "secp256r1", "secp384r1"):
        if pref in lowered:
            return lowered[pref]
    return classical[0] if classical else None


def _tls_find_composite_signature_alg(sig_algs: list[str]) -> str | None:
    """Detect a composite signature scheme exposed by the local OpenSSL.

    Composite signatures (draft-ietf-lamps-pq-composite-sigs) bind a PQC
    signature with a classical signature in a single key, providing a
    hybrid hedge during PQC migration.  Only stock OpenSSL builds with
    a provider exposing such names will return a non-None value.
    Returns the OpenSSL algorithm name (suitable as `-newkey` arg) or
    None if no composite scheme is available.
    """
    pat = re.compile(
        r"^(?:id-)?(?:ml-?dsa)[-_]?\d+[-_]?"
        r"(?:rsa\d*|p\d{3}|ecdsa[-_]?p\d{3}|ed25519|ed448)",
        re.IGNORECASE,
    )
    for name in sig_algs:
        if pat.match(name):
            return name
    return None


def _tls_build_suites(osinfo: dict[str, Any]) -> list[dict[str, str]]:
    """Pick the set of TLS group/cert configurations to benchmark.

    Returns a list of suite descriptors with `label`, `role`, `group`,
    and (optionally) `cert_signature_algorithm` keys.  Suites that are
    not supported by the local OpenSSL are silently omitted.
    """
    groups = osinfo.get("tls_groups") or {}
    suites: list[dict[str, str]] = []
    classical = _tls_pick_classical_group(list(groups.get("classical") or []))
    if classical:
        suites.append(
            {
                "label": f"classical ({classical})",
                "role": "classical",
                "group": classical,
            }
        )
    hybrid = list(groups.get("hybrid") or [])
    pref_hybrid = next(
        (g for g in hybrid if g.lower() in ("x25519mlkem768",)),
        hybrid[0] if hybrid else None,
    )
    if pref_hybrid:
        suites.append(
            {"label": f"hybrid ({pref_hybrid})", "role": "hybrid", "group": pref_hybrid}
        )
    pure = list(groups.get("pure_pqc") or [])
    pref_pure = next(
        (g for g in pure if g.lower() in ("mlkem768",)),
        pure[0] if pure else None,
    )
    if pref_pure:
        suites.append(
            {"label": f"pure-pqc ({pref_pure})", "role": "pure_pqc", "group": pref_pure}
        )
    return suites


def _tls_get_free_port() -> int:
    """Return a TCP port that is currently free on 127.0.0.1.

    We close the probe socket before returning, so there is a small
    race where another process could grab the port before s_server
    binds.  In practice loopback contention on a CI runner is low
    enough that this is not a problem in practice; we accept the race
    rather than maintain a long-lived parent socket.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _tls_wait_for_port(port: int, timeout: float) -> bool:
    """Poll-connect to 127.0.0.1:port until it accepts or timeout expires."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.05)
    return False


def _tls_byte_counting_proxy(
    listen_port: int,
    target_port: int,
    expected_connections: int,
    accumulator: dict[str, int],
    timeout: float,
    ready_event: threading.Event,
) -> None:
    """Forward TCP between listen_port and target_port, counting bytes.

    Runs in its own thread.  Accepts up to `expected_connections`
    inbound connections (one per s_client invocation), forwards each to
    target_port, and accumulates the total byte count in
    accumulator['total'] with the connection count in accumulator['n'].
    Sets ready_event once it is listening.
    """
    deadline = time.monotonic() + timeout
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(("127.0.0.1", listen_port))
        srv.listen(max(expected_connections, 1))
    except OSError:
        ready_event.set()
        srv.close()
        return
    ready_event.set()
    accepted = 0
    try:
        while accepted < expected_connections and time.monotonic() < deadline:
            srv.settimeout(max(0.1, deadline - time.monotonic()))
            try:
                client, _ = srv.accept()
            except (socket.timeout, TimeoutError):
                break
            accepted += 1
            try:
                upstream = socket.create_connection(
                    ("127.0.0.1", target_port), timeout=2.0
                )
            except OSError as e:
                log.debug("tls proxy: upstream connect to port %d failed: %s", target_port, e)
                client.close()
                continue
            client.settimeout(None)
            upstream.settimeout(None)
            socks: list[socket.socket] = [client, upstream]
            conn_bytes = 0
            try:
                while socks:
                    rlist, _, _ = select.select(socks, [], [], 5.0)
                    if not rlist:
                        break
                    closed = False
                    for s in rlist:
                        try:
                            data = s.recv(8192)
                        except OSError:
                            data = b""
                        if not data:
                            closed = True
                            break
                        conn_bytes += len(data)
                        peer = upstream if s is client else client
                        try:
                            peer.sendall(data)
                        except OSError:
                            closed = True
                            break
                    if closed:
                        break
            finally:
                try:
                    client.shutdown(socket.SHUT_RDWR)
                except OSError as e:
                    log.debug("tls proxy: client shutdown failed: %s", e)
                try:
                    upstream.shutdown(socket.SHUT_RDWR)
                except OSError as e:
                    log.debug("tls proxy: upstream shutdown failed: %s", e)
                client.close()
                upstream.close()
            accumulator["total"] += conn_bytes
            accumulator["n"] += 1
    finally:
        srv.close()


def _tls_generate_test_cert(
    cert: Path, key: Path, key_alg: str = "RSA:2048"
) -> tuple[bool, str]:
    """Create a self-signed loopback test cert.

    Uses RSA-2048 by default since it is universally supported by
    OpenSSL 3.x without requiring the EC subsystem.  Returns
    (True, "") on success, (False, reason) on failure.
    """
    cmd = [
        "openssl",
        "req",
        "-x509",
        "-newkey",
        key_alg,
        "-keyout",
        str(key),
        "-out",
        str(cert),
        "-noenc",
        "-subj",
        "/CN=localhost",
        "-addext",
        "subjectAltName=DNS:localhost,IP:127.0.0.1",
        "-days",
        "1",
    ]
    rc, out = _platform._run(cmd, timeout=20)
    if rc != 0 or not cert.exists() or not key.exists():
        return False, (out.strip().splitlines() or [f"rc={rc}"])[-1][:200]
    return True, ""


def _tls_run_one_handshake(
    cert: Path, group: str, port: int, timeout: float = 10.0
) -> float | None:
    """Run a single full TLS handshake against 127.0.0.1:port via s_client.

    Returns elapsed wall-clock seconds for the s_client invocation, or
    None if the handshake failed.  Note: this measurement includes the
    cost of spawning the openssl process; the relative comparison
    between groups remains valid because spawn cost is constant.
    """
    cmd = [
        "openssl",
        "s_client",
        "-connect",
        f"127.0.0.1:{port}",
        "-groups",
        group,
        "-CAfile",
        str(cert),
        "-verify_return_error",
        "-quiet",
        "-no_ign_eof",
    ]
    start = time.perf_counter()
    try:
        p = subprocess.run(
            cmd,
            input=b"GET / HTTP/1.0\r\n\r\n",
            capture_output=True,
            timeout=timeout,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None
    elapsed = time.perf_counter() - start
    # `s_server -www` returns an HTTP 200 page and closes; s_client exits 0.
    # Some OpenSSL builds exit non-zero on the server-side close even when
    # the handshake succeeded, so we accept any exit code as long as the
    # response payload is present.
    if p.returncode != 0 and b"s_server" not in p.stdout:
        return None
    return elapsed


def _tls_bench_one_suite(
    cert: Path,
    key: Path,
    suite: dict[str, str],
    iterations: int,
    handshake_timeout: float = 10.0,
) -> dict[str, Any]:
    """Run `iterations` handshakes for one TLS suite and report metrics."""
    server_port = _tls_get_free_port()
    proxy_port = _tls_get_free_port()
    while proxy_port == server_port:
        proxy_port = _tls_get_free_port()
    server_cmd = [
        "openssl",
        "s_server",
        "-accept",
        str(server_port),
        "-cert",
        str(cert),
        "-key",
        str(key),
        "-groups",
        suite["group"],
        "-www",
        "-no_ticket",
        "-naccept",
        str(iterations + 4),
        "-quiet",
    ]
    try:
        server = subprocess.Popen(
            server_cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
    except OSError as exc:
        return {"error": f"failed to spawn s_server: {exc}"}
    try:
        if not _tls_wait_for_port(server_port, timeout=5.0):
            stderr = b""
            try:
                stderr = server.stderr.read() if server.stderr else b""
            except OSError:
                stderr = b""
            return {
                "error": "s_server failed to listen",
                "detail": stderr.decode("utf-8", "replace").strip()[:200],
            }
        accumulator: dict[str, int] = {"total": 0, "n": 0}
        ready = threading.Event()
        proxy = threading.Thread(
            target=_tls_byte_counting_proxy,
            args=(
                proxy_port,
                server_port,
                iterations,
                accumulator,
                handshake_timeout * iterations + 30.0,
                ready,
            ),
            daemon=True,
        )
        proxy.start()
        ready.wait(timeout=5.0)
        if not _tls_wait_for_port(proxy_port, timeout=5.0):
            return {"error": "byte-counting proxy failed to listen"}
        times: list[float] = []
        for _ in range(iterations):
            t = _tls_run_one_handshake(
                cert, suite["group"], proxy_port, timeout=handshake_timeout
            )
            if t is not None:
                times.append(t)
        proxy.join(timeout=10.0)
    finally:
        try:
            server.terminate()
            server.wait(timeout=3)
        except subprocess.TimeoutExpired:
            try:
                server.kill()
                server.wait(timeout=2)
            except OSError as e:
                log.debug("tls bench: s_server kill failed: %s", e)
        except OSError as e:
            log.debug("tls bench: s_server terminate failed: %s", e)
        if server.stderr:
            try:
                server.stderr.close()
            except OSError as e:
                log.debug("tls bench: closing s_server stderr failed: %s", e)
    if not times:
        return {"error": "no successful handshakes"}
    total = sum(times)
    bytes_per = (
        round(accumulator["total"] / accumulator["n"]) if accumulator["n"] > 0 else None
    )
    return {
        "iterations": len(times),
        "handshakes_per_sec": round(len(times) / total, 2) if total > 0 else 0.0,
        "ttfb_ms_mean": round(statistics.mean(times) * 1000.0, 3),
        "ttfb_ms_median": round(statistics.median(times) * 1000.0, 3),
        "bytes_on_wire_per_handshake": bytes_per,
        "bytes_observed_connections": accumulator["n"],
    }


def _tls_bench_composite_signature(
    tmpdir: Path,
    osinfo: dict[str, Any],
    iterations: int,
) -> dict[str, Any] | None:
    """Run the composite-signature variant of the suite, if available.

    Composite signatures bind a PQC scheme with a classical scheme in a
    single signing key (per draft-ietf-lamps-pq-composite-sigs).  Only
    OpenSSL builds with a provider exposing such names can generate a
    cert with a composite key; the function returns None when no such
    algorithm is exposed or when cert generation fails.
    """
    sig_algs = list(osinfo.get("sig_algorithms") or [])
    composite = _tls_find_composite_signature_alg(sig_algs)
    if not composite:
        return None
    classical_group = _tls_pick_classical_group(
        list((osinfo.get("tls_groups") or {}).get("classical") or [])
    )
    if not classical_group:
        return None
    cert = tmpdir / "cert-composite.pem"
    key = tmpdir / "key-composite.pem"
    ok, reason = _tls_generate_test_cert(cert, key, key_alg=composite)
    if not ok:
        return {
            "label": f"composite-sig ({composite})",
            "role": "composite_sig",
            "group": classical_group,
            "cert_signature_algorithm": composite,
            "skipped": True,
            "reason": f"cert generation failed: {reason}",
        }
    suite: dict[str, str] = {
        "label": f"composite-sig ({composite})",
        "role": "composite_sig",
        "group": classical_group,
        "cert_signature_algorithm": composite,
    }
    metrics = _tls_bench_one_suite(cert, key, suite, iterations)
    return {**suite, **metrics}


def run_tls_handshake_bench(
    seconds: int, osinfo: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Loopback TLS handshake benchmark across classical / hybrid / PQC.

    Drives `openssl s_server` and `openssl s_client` over a Python
    byte-counting proxy on 127.0.0.1.  Reports handshakes/sec, mean and
    median time-to-first-byte (in milliseconds, including s_client
    process startup), and bytes-on-wire per handshake for each
    available TLS group selection plus an optional composite-signature
    cert variant.
    """
    if not shutil.which("openssl"):
        return {"available": False, "reason": "openssl not on PATH"}
    rc, ver = _platform._openssl_version_text()
    m = re.search(r"OpenSSL\s+(\d+)\.(\d+)", ver)
    if not m or (int(m.group(1)), int(m.group(2))) < (3, 5):
        return {
            "available": False,
            "reason": f"OpenSSL pre-3.5 lacks ML-KEM groups (got {ver.strip()})",
        }
    if osinfo is None:
        osinfo = _config.openssl_capability()
    if not osinfo.get("available"):
        return {"available": False, "reason": "openssl_capability probe failed"}
    suites = _tls_build_suites(osinfo)
    if not suites:
        return {
            "available": False,
            "reason": "no TLS groups recognised by the local OpenSSL",
        }
    iterations = max(20, min(200, seconds * 30))
    with tempfile.TemporaryDirectory(prefix="pqc-readiness-tls-") as td_str:
        td = Path(td_str)
        cert = td / "cert.pem"
        key = td / "key.pem"
        ok, reason = _tls_generate_test_cert(cert, key)
        if not ok:
            return {
                "available": False,
                "reason": f"failed to generate test cert: {reason}",
            }
        results: list[dict[str, Any]] = []
        for s in suites:
            metrics = _tls_bench_one_suite(cert, key, s, iterations)
            results.append({**s, **metrics})
        composite = _tls_bench_composite_signature(td, osinfo, iterations)
        if composite is not None:
            results.append(composite)
    return {
        "available": True,
        "engine": "tls-handshake",
        "transport": "loopback",
        "openssl_version": (osinfo.get("version") or "").strip(),
        "iterations_per_suite": iterations,
        "seconds_budget": seconds,
        "note": (
            "ttfb measurements include the s_client process startup cost; "
            "comparisons across groups are still meaningful because that "
            "cost is constant"
        ),
        "suites": results,
    }


def memory_bandwidth_probe() -> tuple[float | None, str]:
    """STREAM-triad-style memory bandwidth probe (a = b * scalar + c).

    Returns (gb_per_sec, method).  When numpy is unavailable, returns
    (None, "unavailable: numpy not installed") rather than producing a
    misleading number.

    The previous bytes(bytearray) implementation measured a combination
    of allocator throughput and intra-process memcpy and was not
    representative of sustained memory bandwidth — it is removed.
    Section 3's SLH-DSA tier downgrade gates on this probe; if it
    returned None, no downgrade is applied.
    """
    try:
        import numpy as np
    except ImportError:
        return None, "unavailable: numpy not installed"
    try:
        n = 16 * 1024 * 1024  # 128 MiB per array (3 arrays = 384 MiB working set)
        a = np.zeros(n, dtype=np.float64)
        b = np.ones(n, dtype=np.float64)
        c = np.full(n, 2.0, dtype=np.float64)
        # Warm caches.
        np.add(np.multiply(b, 3.0), c, out=a)
        iters = 5
        t0 = time.perf_counter()
        for _ in range(iters):
            np.add(np.multiply(b, 3.0), c, out=a)
        elapsed = time.perf_counter() - t0
        if elapsed <= 0:
            return None, "probe failed: zero elapsed time"
        # Conservative: 3 reads (b, c, intermediate) + 1 write (a) per
        # element per iteration.  numpy may fuse this to 3 ops; we
        # under-report rather than over-report.
        bytes_moved = 4 * 8 * n * iters
        gb_per_s = bytes_moved / elapsed / (1024**3)
        return round(gb_per_s, 1), "STREAM-triad (numpy)"
    except (MemoryError, OSError) as e:
        log.debug("memory_bandwidth_probe: STREAM-triad failed: %s", e)
        return None, f"probe failed: {e}"


@_registry.register_arguments(20)
def add_arguments(ap: argparse.ArgumentParser) -> None:
    """--bench, --bench-tls, --threads, --seconds."""
    ap.add_argument(
        "--bench", action="store_true", help="run PQC + classical microbench"
    )
    ap.add_argument(
        "--bench-tls",
        action="store_true",
        help="run loopback TLS 1.3 handshake benchmark (classical/hybrid/PQC)",
    )
    ap.add_argument("--threads", type=int, default=1, help="add an N-way scaling test")
    ap.add_argument("--seconds", type=int, default=1, help="seconds per benchmark op")
