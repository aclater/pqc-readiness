"""Fleet aggregation (--aggregate DIR)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Iterable, Iterator

from . import gap as _gap
from . import observations as _observations
from . import report as _report
from . import registry as _registry


# ---------------------------------------------------------------------------
# Fleet aggregation (--aggregate DIR)
# ---------------------------------------------------------------------------


def aggregate_reports(reports: list[dict[str, Any]]) -> dict[str, Any]:
    """Roll up an in-memory list of per-host reports into a fleet view.

    Convenience wrapper over `_aggregate_iter` for tests and programmatic
    callers that already hold the reports in memory.  `run_aggregator`
    streams files through `_aggregate_iter` directly instead.
    """
    return _aggregate_iter(reports)


def _aggregate_iter(reports: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Roll up many per-host reports into a single fleet view.

    Consumes `reports` one at a time and keeps only counters, so memory
    is O(rollup size) rather than O(fleet size) — a 100K-host fleet does
    not need every parsed report resident at once (#88).

    Accepts only reports with matching schema_version; other entries are
    counted as `skipped_schema_mismatch` and listed by file (caller
    populates that field externally — pure version below operates on
    already-validated dicts).

    Output:
      total_hosts, by_arch, by_os_release_id, by_isa_tier, by_verdict,
      by_runtime_environment, accelerator_kinds (count of hosts with
      each kind), unique_cpu_models, replace_required_count,
      host_fs_detections_unavailable_host_count (count of hosts where
      each host-fs-dependent probe was flagged unavailable in container).
    """
    from collections import Counter

    total_hosts = 0
    by_arch: Counter[str] = Counter()
    by_os: Counter[str] = Counter()
    by_isa: Counter[str] = Counter()
    by_verdict: Counter[str] = Counter()
    by_env: Counter[str] = Counter()
    cpu_models: set[str] = set()
    accel_kinds: Counter[str] = Counter()
    detections_unavailable: Counter[str] = Counter()
    replace_required = 0
    # Capability vs configuration verdict (#107): hosts per state per
    # protocol, services per state, and hosts carrying any gap.
    gap_by_protocol: dict[str, Counter[str]] = {p: Counter() for p in _gap.PROTOCOLS}
    gap_services: Counter[str] = Counter()
    gap_hosts: Counter[str] = Counter()
    for r in reports:
        total_hosts += 1
        by_arch[r.get("arch", "?")] += 1
        kinfo = r.get("kernel_info") or {}
        by_os[kinfo.get("os_release_id") or "?"] += 1
        by_isa[r.get("isa_tier", "?")] += 1
        # Strip the trailing "- ..." commentary from the verdict for grouping.
        verdict = (r.get("verdict") or "?").split(" - ", 1)[0].strip()
        by_verdict[verdict] += 1
        runtime = (r.get("runtime_environment") or {}).get("environment", "?")
        by_env[runtime] += 1
        cpu_models.add(r.get("cpu_model") or "?")
        seen_kinds: set[str] = set()
        for a in r.get("accelerators") or []:
            k = a.get("kind", "?")
            if k not in seen_kinds:
                accel_kinds[k] += 1
                seen_kinds.add(k)
        # A detection key is counted at most once per host: the aggregator
        # only cares whether *any* host had probe Y flagged unavailable,
        # not how many duplicate annotations a single host carried.
        for det_key, det_info in (
            r.get("host_fs_detections_unavailable") or {}
        ).items():
            if isinstance(det_info, dict) and det_info.get("unavailable_in_container"):
                detections_unavailable[det_key] += 1
        if r.get("replace_required"):
            replace_required += 1
        g = _gap.gap_for(r)
        host_states: set[str] = set()
        for proto in _gap.PROTOCOLS:
            st = ((g.get("protocols") or {}).get(proto) or {}).get("state", "unknown")
            gap_by_protocol[proto][st] += 1
            host_states.add(st)
        for svc in (g.get("services") or {}).get("items") or []:
            gap_services[svc.get("state", "unknown")] += 1
            host_states.add(svc.get("state", "unknown"))
        for st in ("capable_not_configured", "configured_not_capable"):
            if st in host_states:
                gap_hosts[st] += 1
    out: dict[str, Any] = {
        "total_hosts": total_hosts,
        "schema_version": _report.SCHEMA_VERSION,
    }
    out["by_arch"] = dict(by_arch)
    out["by_os_release_id"] = dict(by_os)
    out["by_isa_tier"] = dict(by_isa)
    out["by_verdict"] = dict(by_verdict)
    out["by_runtime_environment"] = dict(by_env)
    out["accelerator_kinds_host_count"] = dict(accel_kinds)
    out["host_fs_detections_unavailable_host_count"] = dict(detections_unavailable)
    out["unique_cpu_models"] = sorted(cpu_models)
    out["replace_required_count"] = replace_required
    out["pqc_deployment_gap"] = {
        "hosts_by_protocol_state": {
            p: dict(sorted(c.items())) for p, c in gap_by_protocol.items()
        },
        "services_by_state": dict(sorted(gap_services.items())),
        "hosts_with_gap": {
            st: gap_hosts.get(st, 0)
            for st in ("capable_not_configured", "configured_not_capable")
        },
    }
    return out


def aggregate_to_csv(rollup: dict[str, Any]) -> str:
    """Render the rollup to a flat CSV view for ingestion by ops tools.
    One row per (group, key, count) tuple — easy to load in pandas /
    spreadsheet without nested-JSON gymnastics."""
    import io
    import csv

    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["group", "key", "count"])
    w.writerow(["total_hosts", "", rollup.get("total_hosts", 0)])
    w.writerow(["replace_required_count", "", rollup.get("replace_required_count", 0)])
    for group in (
        "by_arch",
        "by_os_release_id",
        "by_isa_tier",
        "by_verdict",
        "by_runtime_environment",
        "accelerator_kinds_host_count",
        "host_fs_detections_unavailable_host_count",
    ):
        for k, v in (rollup.get(group) or {}).items():
            w.writerow([group, k, v])
    for cpu in rollup.get("unique_cpu_models", []):
        w.writerow(["unique_cpu_models", cpu, 1])
    gap = rollup.get("pqc_deployment_gap") or {}
    for proto, states in (gap.get("hosts_by_protocol_state") or {}).items():
        for st, n in states.items():
            w.writerow([f"pqc_deployment_gap_{proto}", st, n])
    for st, n in (gap.get("services_by_state") or {}).items():
        w.writerow(["pqc_deployment_gap_services", st, n])
    for st, n in (gap.get("hosts_with_gap") or {}).items():
        w.writerow(["pqc_deployment_gap_hosts_with", st, n])
    obs = rollup.get("observations")
    if obs:
        w.writerow(["observations_valid", "", obs.get("valid", 0)])
        w.writerow(["observations_invalid", "", len(obs.get("invalid") or [])])
        w.writerow(["observations_stale", "", obs.get("stale", 0)])
        for group in ("by_status", "by_observed_class"):
            for k, v in (obs.get(group) or {}).items():
                w.writerow([f"observations_{group}", k, v])
        for st in obs.get("states") or []:
            key = f"capable={st['capable']};configured={st['configured']};observed={st['observed']}"
            w.writerow(["observations_states", key, st["endpoints"]])
        for st in obs.get("by_gap_state") or []:
            key = f"protocol={st['protocol']};state={st['state']};observed={st['observed']}"
            w.writerow(["observations_by_gap_state", key, st["endpoints"]])
    return buf.getvalue()


def _iter_aggregator_reports(
    dir_path: Path, skipped: list[dict[str, str]]
) -> Iterator[dict[str, Any]]:
    """Yield each valid report under DIR one at a time, parsing lazily.

    Unreadable, non-object and schema-mismatched files are appended to
    `skipped` (in sorted path order) instead of being yielded.  Only the
    sorted path list is held in memory, never the parsed reports."""
    for fp in sorted(dir_path.glob("**/*.json")):
        # UnicodeDecodeError covers binary/non-UTF-8 files dropped into the
        # fleet dir; one stray file must not abort the whole rollup.
        try:
            data = json.loads(fp.read_text())
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as e:
            skipped.append({"file": str(fp), "reason": f"unreadable: {e}"})
            continue
        if not isinstance(data, dict):
            skipped.append(
                {
                    "file": str(fp),
                    "reason": f"unreadable: expected a JSON object, got {type(data).__name__}",
                }
            )
            continue
        sv = data.get("schema_version")
        if sv != _report.SCHEMA_VERSION:
            skipped.append(
                {
                    "file": str(fp),
                    "reason": f"schema mismatch: file={sv!r} expected={_report.SCHEMA_VERSION!r}",
                }
            )
            continue
        yield data


def run_aggregator(
    dir_path: Path,
    output: str = "json",
    observations: Path | None = None,
    observations_max_age_days: float = _observations.DEFAULT_MAX_AGE_DAYS,
) -> tuple[str, int]:
    """Read every *.json under DIR, validate schema, return (output, exit_code).
    Output format: 'json' (rollup as JSON) or 'csv' (flat CSV view).

    Files are parsed and reduced one at a time (#88), so peak memory does
    not grow with fleet size.  With `observations`, the same pass also
    builds a compact host index (names, listeners, certificate
    fingerprints) and the rollup gains an `observations` join (#149).
    Raises observations.ObservationFileError when the file is unusable."""
    loaded = _observations.load_observations(observations) if observations else None
    skipped: list[dict[str, str]] = []
    reports: Iterable[dict[str, Any]] = _iter_aggregator_reports(dir_path, skipped)
    index = _observations.HostIndex()
    if loaded is not None:
        reports = _observations.index_reports(reports, index)
    rollup = _aggregate_iter(reports)
    rollup["skipped"] = skipped
    if loaded is not None:
        rollup["observations"] = _observations.join_observations(
            loaded, index, max_age_days=observations_max_age_days
        )
    if output == "csv":
        return aggregate_to_csv(rollup), 0
    return json.dumps(rollup, indent=2), 0


@_registry.register_arguments(90)
def add_arguments(ap: argparse.ArgumentParser) -> None:
    """--aggregate, --aggregate-format."""
    ap.add_argument(
        "--aggregate",
        metavar="DIR",
        help="aggregate every *.json in DIR into a fleet rollup; exits when done",
    )
    ap.add_argument(
        "--aggregate-format",
        choices=["json", "csv"],
        default="json",
        help="output format for --aggregate (default: json)",
    )
    ap.add_argument(
        "--observations",
        metavar="FILE",
        help=(
            "with --aggregate: join endpoint-observation records (what a "
            "network-side tool saw an endpoint negotiate; schema in "
            "docs/schemas/) to the hosts and listening services in the "
            "reports"
        ),
    )
    ap.add_argument(
        "--observations-max-age-days",
        type=float,
        default=_observations.DEFAULT_MAX_AGE_DAYS,
        metavar="DAYS",
        help=(
            "flag an observation as stale when it was made more than DAYS "
            "before or after the matched host's report "
            f"(default {_observations.DEFAULT_MAX_AGE_DAYS:g})"
        ),
    )
