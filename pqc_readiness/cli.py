"""Command-line entry point: parser, report collection, rendering, exit codes."""

from __future__ import annotations

import argparse
import contextlib
import json
import logging
import os
import platform
import socket
import sys
import tempfile
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import _platform as _platform
from . import aggregate as _aggregate
from . import observations as _observations
from . import algorithms as _algorithms
from . import bench as _bench
from .detect import certs as _certs
from .detect import certs_discovery as _certs_discovery
from .detect import config as _config
from .detect import config_policy as _config_policy
from .detect import hardware as _hardware
from .detect import osinfo as _osinfo
from .detect import packages as _packages
from .detect import protocols as _protocols
from .detect import protocols_signing as _signing
from .detect import runtime as _runtime
from .detect import runtime_services as _runtime_services
from . import recommendation as _recommendation
from .render import text as _text
from . import report as _report
from . import verdict as _verdict
from . import registry as _registry

log = logging.getLogger("pqc-readiness")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def ansible_ignored_flag_warnings(args: argparse.Namespace) -> list[str]:
    """Explain flags that --ansible silently overrides.

    --ansible must always exit 0 (otherwise Ansible marks the play failed
    on the verdict), so it returns before the --check / --fips-strict
    exit-code gates run.  Combining them is legal but the gates have no
    effect; say so on stderr rather than leaving the user to discover it
    from a surprising exit code (#95).  stdout stays pure JSON.
    """
    if not args.ansible:
        return []
    out: list[str] = []
    if args.check:
        out.append(
            f"--check {args.check} is ignored when --ansible is active "
            "(--ansible always exits 0; read the verdict from the JSON)"
        )
    if args.fips_strict:
        out.append(
            "--fips-strict is ignored when --ansible is active "
            "(--ansible always exits 0; read fips.* from the JSON)"
        )
    return out


# Exit code when --output FILE cannot be written after the probe ran.
# Distinct from 0-4 so a write failure is never mistaken for a verdict.
EXIT_OUTPUT_WRITE_FAILED = 5


def _validate_output_path(
    ap: argparse.ArgumentParser, output: str | None
) -> Path | None:
    """Fail fast (argparse usage error, exit 2) before any probing when
    --output FILE cannot possibly be written.  The parent directory is
    deliberately never created: a typo should not leave stray directory
    trees on a customer host."""
    if not output:
        return None
    path = Path(output)
    parent = path.parent
    if not parent.is_dir():
        ap.error(f"--output: parent directory {str(parent)!r} does not exist")
    if path.is_dir():
        ap.error(f"--output: {output!r} is a directory")
    if not os.access(parent, os.W_OK):
        ap.error(f"--output: parent directory {str(parent)!r} is not writable")
    return path


def _emit(text: str, path: Path | None) -> bool:
    """Write report text to stdout, or to --output FILE when given.
    Returns False (after reporting on stderr) if the file write fails."""
    if path is None:
        print(text)
        return True
    try:
        _write_atomically(path, text + "\n")
    except OSError as e:
        print(f"--output: cannot write {str(path)!r}: {e}", file=sys.stderr)
        return False
    log.debug("wrote report to %s", path)
    return True


def _write_atomically(path: Path, data: str) -> None:
    """Write via a temp file in the same directory, then rename over `path`.

    Readers never see a half-written report: node_exporter's textfile
    collector requires this for *.prom files (#140), and the fleet
    aggregator benefits when a timer rewrites a JSON report it is reading.
    The file gets the mode a plain create would (0666 & ~umask), or keeps
    the existing file's mode, rather than mkstemp's 0600."""
    try:
        mode = path.stat().st_mode & 0o777
    except FileNotFoundError:
        umask = os.umask(0)
        os.umask(umask)
        mode = 0o666 & ~umask
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(data)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def _package_doc() -> str | None:
    """The package docstring doubles as the --help description."""
    return sys.modules[__name__.rpartition(".")[0]].__doc__


def build_parser() -> argparse.ArgumentParser:
    """Construct the CLI parser.  Kept separate from main() so tests and
    the README flag check can inspect the full flag set without running
    a scan."""
    ap = argparse.ArgumentParser(
        prog="pqc-readiness",
        description=_package_doc(),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    for add_arguments in _registry.argument_hooks():
        add_arguments(ap)
    return ap


def collect_report(args: argparse.Namespace) -> _report.Report:
    """Run every host probe the CLI flags ask for and assemble the Report.

    Side-effect free apart from the probes themselves: --host-mount must
    already be applied (set_host_prefix) and output/colour handling is
    the caller's job."""
    arch = platform.machine().lower()
    flags = _hardware.cpu_flags(arch)
    total_gb, avail_gb = _hardware.memory_info()
    logical, physical = _hardware.core_counts()
    isa_feat, isa_score = _hardware.detect_isa(arch, flags)
    isa_t, isa_reason = _hardware.isa_tier(arch, isa_score, flags)
    role_for_memory = args.role if args.role else "generic"
    mem_t, mem_reason = _hardware.memory_tier(total_gb, role_for_memory)
    memory_field: dict[str, Any] = {
        "tier": mem_t,
        "reason": mem_reason,
        "tier_basis": {
            "role": role_for_memory,
            "threshold_gib_good": _hardware.MEMORY_TIER_GOOD_THRESHOLD_BY_ROLE[
                role_for_memory
            ],
            "role_supplied": args.role is not None,
        },
    }
    if args.role is None:
        memory_field["tier_by_role"] = _hardware.memory_tier_all_roles(total_gb)
    runtime_env = _runtime.detect_runtime_environment()
    host_fs_detections_unavailable = _runtime.build_host_fs_detections_unavailable()
    accels = _hardware.detect_accelerators()
    accels.extend(_hardware.detect_network_hsms())
    os_release = _osinfo.detect_os()
    pkcs11 = _hardware.detect_pkcs11_modules(os_release.get("family", "unknown"))
    kcrypto = _hardware.detect_kernel_crypto_hw_annotated()["items"]
    ktls = _hardware.detect_ktls_annotated()["supported"]
    fips = _config.detect_fips_mode()
    tpm = _hardware.detect_tpm_pqc()
    family = os_release.get("family", "unknown")
    osinfo = _config.openssl_capability(os_release)
    ssh_info = _protocols.detect_ssh_pqc(family)
    _algorithms.annotate_key_exchange(osinfo, ssh_info)
    ipsec_info = _protocols.detect_ipsec_pqc(family)
    nss_info = _protocols.detect_nss()
    crypto_policy = _config_policy.detect_crypto_policy()
    kernel_info = _osinfo.detect_kernel_info(os_release)
    fips = _config.interpret_fips(fips, osinfo, os_release)
    fips_conflict = _config.fips_pqc_conflict_check(fips, osinfo)
    proc_crypto_text: str | None = None
    if _platform.is_linux():
        try:
            proc_crypto_text = _platform.host_path("/proc/crypto").read_text()
        except OSError as e:
            log.debug("main: cannot read /proc/crypto for CNSA 2.0 evaluation: %s", e)
            proc_crypto_text = None
    cnsa_2_0 = _verdict.evaluate_cnsa_2_0(osinfo, proc_crypto_text)
    trust_store_info: dict[str, Any] = {}
    if getattr(args, "scan_trust_store", False):
        trust_store_info = _certs.scan_trust_store(max_certs=args.trust_store_max_certs)
    crypto_material_info: dict[str, Any] = {}
    if getattr(args, "scan_crypto_material", False):
        crypto_material_info = _certs_discovery.scan_crypto_material(
            paths=args.crypto_material_path,
            max_files=args.crypto_material_max_files,
        )
    packages_info: dict[str, Any] = {}
    if getattr(args, "scan_packages", False):
        packages_info = _packages.scan_packages(os_release)
    signing_keys_info: dict[str, Any] = {}
    if getattr(args, "scan_signing_keys", False):
        signing_keys_info = _signing.scan_signing_keys(os_release)
    services_info: dict[str, Any] = {}
    if getattr(args, "scan_services", False):
        services_info = _runtime_services.scan_services()
    dedicated = _hardware.has_dedicated_pqc_silicon(arch, flags, accels)
    hsm_present = any(a.get("kind") in ("hsm", "network_hsm") for a in accels)
    hsm_pqc_capable = any(
        a.get("kind") in ("hsm", "network_hsm") and a.get("pqc_capable") for a in accels
    )
    hsm_present_but_not_pqc = hsm_present and not hsm_pqc_capable

    bench: dict[str, Any] | None = None
    bench_tls: dict[str, Any] | None = None
    membw: float | None = None
    membw_method: str | None = None
    if args.bench:
        bench = _bench.run_benchmarks(
            seconds=args.seconds, threads=max(args.threads, 1), osinfo=osinfo
        )
        membw, membw_method = _bench.memory_bandwidth_probe()
    if args.bench_tls:
        bench_tls = _bench.run_tls_handshake_bench(seconds=args.seconds, osinfo=osinfo)

    cores_for_estimate = physical or logical or 1
    tls_hybrid_avail = bool((osinfo.get("tls_groups") or {}).get("hybrid"))
    palg = (
        _verdict.per_algo_verdict(
            bench,
            cores_for_estimate,
            mem_bw_gb_s=membw,
            tls_hybrid_available=tls_hybrid_avail,
        )
        if bench
        else {}
    )
    pest = _verdict.production_estimate(palg, total_gb) if palg else {}
    verdict, why, code, caveat = _verdict.overall_verdict(isa_t, mem_t, dedicated, palg)
    why = f"{why} ISA: {isa_reason}. Memory: {mem_reason}."

    # replace_required: poor ISA tier AND no PQC silicon AND no PQC-capable
    # accelerator.  Used by fleet planners to count hosts that cannot be
    # made PQC-ready in software regardless of OpenSSL version.
    accel_pqc_present = any(a.get("pqc_capable") for a in accels)
    replace_required = (isa_t == "poor") and not dedicated and not accel_pqc_present

    r = _report.Report(
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        hostname=socket.gethostname(),
        os=os_release.get("pretty_name") or f"{platform.system()} {platform.release()}",
        arch=arch,
        cpu_model=_hardware.cpu_model(),
        cpu_freq_mhz=round(_hardware.cpu_freq_mhz(), 1),
        cores_logical=logical,
        cores_physical=physical or logical,
        mem_total_gb=round(total_gb, 2),
        mem_avail_gb=round(avail_gb, 2),
        isa_features=isa_feat,
        isa_score=isa_score,
        isa_tier=isa_t,
        isa_reason=isa_reason,
        accelerators=accels,
        hsm_present_but_not_pqc=hsm_present_but_not_pqc,
        pkcs11_modules=pkcs11,
        kernel_crypto_hw=kcrypto,
        ktls_supported=ktls,
        fips=fips,
        openssl=osinfo,
        tpm_pqc=tpm,
        memory=memory_field,
        memory_bandwidth_gb_s=membw,
        memory_bandwidth_method=membw_method,
        ssh_pqc=ssh_info,
        ipsec_pqc=ipsec_info,
        nss=nss_info,
        crypto_policy=crypto_policy,
        kernel_info=kernel_info,
        fips_pqc_conflict=fips_conflict,
        cnsa_2_0=cnsa_2_0,
        trust_store=trust_store_info,
        crypto_material=crypto_material_info,
        runtime_environment=runtime_env,
        service_crypto_linkage=services_info,
        host_fs_detections_unavailable=host_fs_detections_unavailable,
        packages=packages_info,
        signing_keys=signing_keys_info,
        replace_required=replace_required,
        os_release=os_release,
        benchmark=bench,
        benchmark_tls_handshake=bench_tls,
        per_algo=palg,
        production_estimate=pest,
        verdict=verdict,
        verdict_reason=why,
        verdict_caveat=caveat,
        exit_code=code,
        inventory_metadata=getattr(args, "inventory_metadata", None),
    )
    return r


def render_output(r: _report.Report, args: argparse.Namespace) -> str:
    """Render the per-host result in the format the flags select.

    --ansible and --recommend are alternate documents and take precedence
    over every report format flag."""
    if args.ansible:
        # Ansible's set_fact / register patterns expect a top-level
        # ansible_facts wrapper.
        return json.dumps({"ansible_facts": {"pqc_readiness": asdict(r)}}, indent=2)
    if args.recommend:
        rec = _recommendation.recommend(
            r, policy=args.policy, role=args.role or "tls-server"
        )
        if args.json:
            return json.dumps(rec, indent=2)
        if args.markdown:
            return _recommendation.render_recommendation_markdown(r, rec)
        return _recommendation.render_recommendation_text(r, rec)
    # First registered format whose flag is set wins (registry precedence:
    # json > cbom > spdx > sarif > markdown > quiet); plain text otherwise.
    for fmt in _registry.outputs():
        if getattr(args, fmt.dest):
            return fmt.render(r)
    return _text.render_text(r)


_TIER_RANK = {"poor": 0, "marginal": 1, "good": 2, "excellent": 3}


# Report.exit_code -> verdict tier; any other code (3) is "poor".
_EXIT_CODE_TIER = {0: "excellent", 1: "good", 2: "marginal"}


def exit_code_for(r: _report.Report, args: argparse.Namespace) -> int:
    """Process exit code for a successfully emitted per-host result.

    --ansible must always exit 0 or Ansible marks the play failed
    regardless of the report content; --recommend is advisory output.
    Otherwise --fips-strict and --check can turn the verdict code into 4."""
    if args.ansible or args.recommend:
        return 0
    if (
        args.fips_strict
        and r.fips.get("fence_check_active")
        and not r.fips.get("algorithm_fence_engaged")
    ):
        return 4
    if args.check == "cnsa-2.0":
        if r.cnsa_2_0.get("status") != "compliant":
            return 4
    elif args.check:
        current = _EXIT_CODE_TIER.get(r.exit_code, "poor")
        if _TIER_RANK[current] < _TIER_RANK[args.check]:
            return 4
    return r.exit_code


def _save_report(r: _report.Report) -> None:
    """--save: write the JSON report under ~/.cache/pqc-readiness/."""
    d = Path.home() / ".cache" / "pqc-readiness"
    d.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    fp = d / f"{r.hostname}-{ts}.json"
    fp.write_text(json.dumps(asdict(r), indent=2))


def _use_color(args: argparse.Namespace, out_path: Path | None) -> bool:
    """ANSI colour only for human-readable text on an interactive stdout."""
    return (
        sys.stdout.isatty()
        and out_path is None
        and not args.no_color
        and not any(
            getattr(args, f.dest) for f in _registry.outputs() if f.machine_readable
        )
    )


def main(argv: list[str] | None = None) -> int:
    ap = build_parser()
    args = ap.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.WARNING,
        format="%(name)s: %(levelname)s: %(message)s",
        stream=sys.stderr,
    )
    out_path = _validate_output_path(ap, args.output)

    def emit(text: str) -> bool:
        return _emit(text, out_path)

    for warning in ansible_ignored_flag_warnings(args):
        print(f"warning: {warning}", file=sys.stderr)

    # --aggregate is a top-level alternate mode; bail before per-host probing.
    if args.observations and not args.aggregate:
        print("--observations requires --aggregate DIR", file=sys.stderr)
        return 2
    if args.aggregate:
        d = Path(args.aggregate)
        if not d.is_dir():
            print(f"--aggregate: {d} is not a directory", file=sys.stderr)
            return 2
        try:
            body, code = _aggregate.run_aggregator(
                d,
                output=args.aggregate_format,
                observations=Path(args.observations) if args.observations else None,
                observations_max_age_days=args.observations_max_age_days,
            )
        except _observations.ObservationFileError as e:
            print(f"--observations: {e}", file=sys.stderr)
            return 2
        return code if emit(body) else EXIT_OUTPUT_WRITE_FAILED

    if args.host_mount:
        _platform.set_host_prefix(args.host_mount)
    _text.C.configure(_use_color(args, out_path))

    r = collect_report(args)
    if args.save:
        _save_report(r)
    if not emit(render_output(r, args)):
        return EXIT_OUTPUT_WRITE_FAILED
    return exit_code_for(r, args)


@_registry.register_arguments(30)
def _add_gate_arguments(ap: argparse.ArgumentParser) -> None:
    """--check, --fips-strict."""
    ap.add_argument(
        "--check",
        choices=["excellent", "good", "marginal", "poor", "cnsa-2.0"],
        help=(
            "exit 4 if verdict is below TIER, or if cnsa-2.0 status != "
            "compliant.  Ignored (with a stderr warning) under --ansible"
        ),
    )
    ap.add_argument(
        "--fips-strict",
        action="store_true",
        help=(
            "exit 4 (parallel to --check) when FIPS is active but the "
            "OpenSSL default provider exposes algorithms not present in "
            "the FIPS provider's set.  See "
            "docs/findings/fips-algorithm-fence.md for the underlying "
            "behavior.  Ignored (with a stderr warning) under --ansible"
        ),
    )


@_registry.register_arguments(31)
def _add_destination_arguments(ap: argparse.ArgumentParser) -> None:
    """--save | --output."""
    dest = ap.add_mutually_exclusive_group()
    dest.add_argument(
        "--save", action="store_true", help="save JSON to ~/.cache/pqc-readiness/"
    )
    dest.add_argument(
        "--output",
        metavar="FILE",
        help=(
            "write the report (any format, incl. --aggregate/--recommend/"
            "--ansible) to FILE instead of stdout; the parent directory "
            "must already exist.  Mutually exclusive with --save"
        ),
    )


@_registry.register_arguments(70)
def _add_ansible_argument(ap: argparse.ArgumentParser) -> None:
    """--ansible."""
    ap.add_argument(
        "--ansible",
        action="store_true",
        help=(
            "emit {ansible_facts: {pqc_readiness: ...}} JSON and always "
            "exit 0; takes precedence over --check and --fips-strict"
        ),
    )


@_registry.register_arguments(100)
def _add_misc_arguments(ap: argparse.ArgumentParser) -> None:
    """--debug, --version."""
    ap.add_argument(
        "--debug",
        action="store_true",
        help=(
            "log detection diagnostics (failed reads, subprocess exit "
            "codes) to stderr; report output on stdout is unchanged"
        ),
    )
    ap.add_argument(
        "--version",
        action="version",
        version=f"pqc-readiness {_report.SCRIPT_VERSION} (schema {_report.SCHEMA_VERSION})",
    )
