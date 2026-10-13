"""Prometheus text-format output (--prometheus) for node_exporter's
textfile collector (#140).

node_exporter reads ``*.prom`` files from ``--collector.textfile.directory``.
Files must be replaced atomically, which ``--output`` does (write to a temp
file in the same directory, then rename), and the textfile collector does
not support sample timestamps, so the run time is its own gauge
(``pqc_readiness_last_run_timestamp_seconds``).

Labels are bounded enums only (tier, protocol, kind, status, category): no
hostnames, certificate subjects or algorithm lists, which would make label
cardinality grow with the fleet.  node_exporter adds the instance label.
A series is omitted, not zeroed, when its probe was unavailable: absence
means "unknown" in Prometheus, and a 0 would claim a fact we don't have.
"""

from __future__ import annotations

import argparse
from datetime import datetime
from typing import Any

from .. import registry as _registry
from .. import report as _report

PREFIX = "pqc_readiness"

# Report.exit_code -> verdict tier; 3 (and anything else) is "poor".
_TIERS = ("excellent", "good", "marginal", "poor")
_EXIT_CODE_TIER = {0: "excellent", 1: "good", 2: "marginal"}
_KINDS = ("pure_pqc", "hybrid", "classical")
_CNSA_STATUSES = ("compliant", "partial", "non_compliant", "unknown")
_CERT_CATEGORIES = ("classical", "hybrid_composite", "pure_pqc")


def _escape(value: str) -> str:
    """Label-value escaping from the text exposition format."""
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


class _Metrics:
    """Accumulates metric families in output order."""

    def __init__(self) -> None:
        self.lines: list[str] = []

    def family(
        self,
        name: str,
        help_text: str,
        samples: list[tuple[dict[str, str], float]],
        mtype: str = "gauge",
    ) -> None:
        if not samples:
            return
        full = f"{PREFIX}_{name}"
        self.lines.append(f"# HELP {full} {help_text}")
        self.lines.append(f"# TYPE {full} {mtype}")
        for labels, value in samples:
            lbl = ",".join(f'{k}="{_escape(v)}"' for k, v in labels.items())
            num = repr(float(value)) if value != int(value) else str(int(value))
            self.lines.append(f"{full}{{{lbl}}} {num}" if lbl else f"{full} {num}")


def _bool(value: Any) -> float | None:
    return float(value) if isinstance(value, bool) else None


def _state_set(
    options: tuple[str, ...], current: str | None, label: str
) -> list[tuple[dict[str, str], float]]:
    if current not in options:
        return []
    return [({label: o}, 1.0 if o == current else 0.0) for o in options]


def _group_counts(groups: Any) -> list[tuple[dict[str, str], float]]:
    if not isinstance(groups, dict):
        return []
    return [
        ({"kind": k}, float(len(groups.get(k) or []))) for k in _KINDS if k in groups
    ]


def render_prometheus(r: _report.Report) -> str:
    m = _Metrics()
    m.family(
        "info",
        "Scanner and JSON schema version of this report (value is always 1).",
        [({"version": _report.SCRIPT_VERSION, "schema": _report.SCHEMA_VERSION}, 1.0)],
    )
    # An offline --root scan (#152) has no readiness tier, CPU or memory:
    # every tier series is 0 and the host-only gauges are omitted, so a
    # dashboard never reads a filesystem tree as an "excellent" host.
    offline = bool(r.scan_mode)
    if offline:
        m.family(
            "offline_scan",
            "1 when this report describes a filesystem tree scanned offline (--root), not a live host.",
            [({}, 1.0)],
        )
    m.family(
        "verdict_tier",
        "Overall PQC readiness tier; the series for the current tier is 1.",
        _state_set(
            _TIERS,
            None if offline else _EXIT_CODE_TIER.get(r.exit_code, "poor"),
            "tier",
        ),
    )
    m.family(
        "isa_tier",
        "CPU instruction-set tier for PQC; the series for the current tier is 1.",
        _state_set(_TIERS, r.isa_tier, "tier"),
    )
    if isinstance(r.isa_score, (int, float)) and not offline:
        m.family(
            "isa_score",
            "Weighted score of PQC-relevant CPU features.",
            [({}, float(r.isa_score))],
        )
    replace = None if offline else _bool(r.replace_required)
    if replace is not None:
        m.family(
            "replace_required",
            "1 when the host cannot be made PQC-ready in software (poor ISA, no PQC silicon or accelerator).",
            [({}, replace)],
        )

    openssl = r.openssl or {}
    if openssl.get("available"):
        native = _bool(openssl.get("pqc_native"))
        if native is not None:
            m.family(
                "openssl_pqc_native",
                "1 when the OpenSSL in use exposes NIST PQC algorithms natively (3.5+).",
                [({}, native)],
            )
    tls = _group_counts(openssl.get("tls_groups")) if openssl.get("available") else []
    ssh = r.ssh_pqc or {}
    ssh_groups = _group_counts(ssh.get("kex_groups")) if ssh.get("available") else []
    m.family(
        "key_exchange_groups",
        "Number of key-exchange groups the host's library offers, by protocol and kind.",
        [({"protocol": "tls", **lbl}, v) for lbl, v in tls]
        + [({"protocol": "ssh", **lbl}, v) for lbl, v in ssh_groups],
    )
    hybrid: list[tuple[dict[str, str], float]] = []
    for proto, groups in (("tls", tls), ("ssh", ssh_groups)):
        counts = {lbl["kind"]: v for lbl, v in groups}
        if counts:
            hybrid.append(
                ({"protocol": proto}, 1.0 if counts.get("hybrid", 0) > 0 else 0.0)
            )
    m.family(
        "hybrid_kex_available",
        "1 when the host's library offers at least one hybrid PQC key exchange for the protocol.",
        hybrid,
    )

    nss = r.nss or {}
    if nss.get("available"):
        cap = _bool(nss.get("pqc_capable"))
        if cap is not None:
            m.family(
                "nss_pqc_capable",
                "1 when the installed NSS version supports PQC (3.108+).",
                [({}, cap)],
            )

    fips = r.fips or {}
    fips_samples = [
        ({"layer": layer}, v)
        for layer in ("kernel", "openssl_provider")
        if (v := _bool(fips.get(layer))) is not None
    ]
    m.family(
        "fips_mode", "1 when FIPS mode is active at the given layer.", fips_samples
    )
    if fips.get("fence_check_active"):
        fence = _bool(fips.get("algorithm_fence_engaged"))
        if fence is not None:
            m.family(
                "fips_algorithm_fence_engaged",
                "1 when FIPS mode actually restricts OpenSSL to the FIPS provider's algorithms.",
                [({}, fence)],
            )

    cnsa = r.cnsa_2_0 or {}
    m.family(
        "cnsa_2_0_status",
        "CNSA 2.0 evaluation result; the series for the current status is 1.",
        _state_set(_CNSA_STATUSES, cnsa.get("status"), "status"),
    )

    ts = r.trust_store or {}
    if ts.get("available"):
        cats = ts.get("cert_categories") or {}
        m.family(
            "trust_store_certificates",
            "Unique trust-store certificates by algorithm category (--scan-trust-store).",
            [
                ({"category": c}, float(cats[c]))
                for c in _CERT_CATEGORIES
                if isinstance(cats.get(c), int)
            ],
        )
        trunc = _bool(ts.get("truncated"))
        if trunc is not None:
            m.family(
                "trust_store_truncated",
                "1 when --trust-store-max-certs stopped the scan early.",
                [({}, trunc)],
            )

    pkgs = r.packages or {}
    if pkgs.get("available") and isinstance(pkgs.get("total_packages"), int):
        m.family(
            "packages",
            "Installed packages counted by --scan-packages.",
            [({}, float(pkgs["total_packages"]))],
        )
        bundled = pkgs.get("bundled_crypto")
        if isinstance(bundled, list):
            m.family(
                "bundled_crypto_packages",
                "Installed packages that bundle their own crypto implementation (--scan-packages).",
                [({}, float(len(bundled)))],
            )

    try:
        run_at = datetime.fromisoformat(r.generated_at).timestamp()
    except (TypeError, ValueError):
        run_at = None
    if run_at is not None:
        m.family(
            "last_run_timestamp_seconds",
            "Unix time the report was generated (the textfile collector does not support sample timestamps).",
            [({}, run_at)],
        )
    return "\n".join(m.lines)


@_registry.register_arguments(15)
def add_arguments(ap: argparse.ArgumentParser) -> None:
    """--prometheus."""
    ap.add_argument(
        "--prometheus",
        action="store_true",
        help=(
            "emit Prometheus text format for node_exporter's textfile "
            "collector; use with --output DIR/pqc_readiness.prom"
        ),
    )


# After every other machine-readable format: --prometheus combined with
# e.g. --json still yields JSON, matching how the existing flags resolve.
_registry.register_output(
    _registry.OutputFormat("prometheus", 35, lambda r: render_prometheus(r))
)
