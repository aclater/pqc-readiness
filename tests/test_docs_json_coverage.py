# SPDX-License-Identifier: Apache-2.0
"""docs/json-output.md must document every key the scanner can emit.

Two complementary checks:

1. **Code-derived keys.**  Every string dict key written by a producing
   function (found with `ast`, so branch-only keys such as s390x adapter
   fields or failed-TLS-suite errors are covered without exercising the
   branch) must appear in the doc section for the object it feeds.
2. **Document-derived key paths.**  Every key path in the golden report,
   in `--recommend --json` for every role in auto and single mode, and
   in an `--aggregate` rollup must appear in the right doc section.

A key "appears" in a section when it occurs as a whole word inside one
of that section's inline code spans (so `` `{kem: [...]}` `` documents
`kem`).  Adding a key to the scanner without documenting it fails here.
"""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path
from typing import Any, Iterator

import pytest

import pqc_readiness as pr

ROOT = Path(__file__).resolve().parent.parent
DOC = ROOT / "docs" / "json-output.md"
GOLDEN = ROOT / "tests" / "fixtures" / "golden" / "stubbed-host-report.json"

# The UBI 8 CI image copies only the script and tests/, not docs/.
pytestmark = pytest.mark.skipif(
    not DOC.exists(), reason="docs/ not present in this image"
)

TOP_LEVEL = "Top-level keys"
RECOMMEND = "`--recommend --json` document"
RECORD = "Recommendation record"
POLICY_SOURCES = "Policy sources"
AGGREGATE = "`--aggregate` rollup"

# Producing function -> doc section(s) its keys must appear in.
FUNCTION_SECTIONS: dict[str, tuple[str, ...]] = {
    "memory_tier_all_roles": ("`memory`",),
    "detect_isa": ("`isa_features`",),
    "detect_accelerators": ("`accelerators[]`",),
    "detect_s390x_crypto": ("`accelerators[]`",),
    "detect_network_hsms": ("`accelerators[]`",),
    "detect_fips_mode": ("`fips`",),
    "interpret_fips": ("`fips`",),
    "fips_pqc_conflict_check": ("`fips_pqc_conflict`",),
    "openssl_capability": ("`openssl`",),
    "classify_tls_groups": ("`openssl`",),
    "detect_tpm_pqc": ("`tpm_pqc`",),
    "detect_ssh_pqc": ("`ssh_pqc`",),
    "parse_ssh_kex": ("`ssh_pqc`",),
    "classify_ssh_kex": ("`ssh_pqc`",),
    "detect_ipsec_pqc": ("`ipsec_pqc`",),
    "detect_nss": ("`nss`",),
    "_nss_from_rpmdb": ("`nss`",),
    "_nss_from_certutil": ("`nss`",),
    "detect_kernel_info": ("`kernel_info`",),
    "parse_redhat_release": ("`kernel_info`",),
    "evaluate_cnsa_2_0": ("`cnsa_2_0`",),
    "scan_trust_store": ("`trust_store`", TOP_LEVEL),
    "trust_store_certificate": ("`trust_store`",),
    "scan_crypto_material": ("`crypto_material`",),
    "_cert_record": ("`crypto_material`",),
    "_read_pem_file": ("`crypto_material`",),
    "_read_keystore": ("`crypto_material`",),
    "_attach_public_halves": ("`crypto_material`",),
    "detect_runtime_environment": ("`runtime_environment`",),
    "host_fs_unavailable_note": ("`host_fs_detections_unavailable`",),
    "scan_packages": ("`packages`",),
    "_scan_rpm_packages": ("`packages`",),
    "classify_bundled_crypto": ("`packages`",),
    "parse_os_release": ("`os_release`",),
    "_detect_os_impl": ("`os_release`",),
    "run_benchmarks": ("`benchmark`",),
    "run_pqc_bench": ("`benchmark`",),
    "run_tls_handshake_bench": ("`benchmark_tls_handshake`",),
    "_tls_build_suites": ("`benchmark_tls_handshake`",),
    "_tls_bench_one_suite": ("`benchmark_tls_handshake`",),
    "_tls_bench_composite_signature": ("`benchmark_tls_handshake`",),
    "per_algo_verdict": ("`per_algo`",),
    "production_estimate": ("`production_estimate`",),
    "recommend": (RECOMMEND,),
    "_recommend_stub": (RECORD,),
    "_recommendation_record": (RECORD,),
    "_recommend_tls_server": (RECORD,),
    "_recommend_tls_client": (RECORD,),
    "_recommend_signing_service": (RECORD,),
    "_recommend_firmware_signing": (RECORD,),
    "_aggregate_iter": (AGGREGATE,),
    "run_aggregator": (AGGREGATE,),
}

# Keys that a producing function builds for internal use and never emits.
INTERNAL_KEYS: dict[str, set[str]] = {
    # byte-counting proxy accumulator, reduced to bytes_* before return
    "_tls_bench_one_suite": {"n", "total"},
    # intermediate {name, version} list handed to classify_bundled_crypto
    "_scan_rpm_packages": {"name"},
}

# Object paths whose immediate child keys are open-ended data, not schema.
DYNAMIC_CHILDREN = {"isa_features"}

# Keys present in the golden fixture only because test_main_decompose's
# stubs return them; the real producers never emit them (real
# detect_fips_mode emits kernel / openssl_provider, real
# openssl_capability emits sig_algorithms).
GOLDEN_STUB_ONLY = {"fips.enabled", "fips.sources", "openssl.signature_algorithms"}

# Nested object path -> doc section.  Longest prefix wins.
PATH_SECTIONS: dict[str, str] = {
    "memory": "`memory`",
    "isa_features": "`isa_features`",
    "accelerators": "`accelerators[]`",
    "fips": "`fips`",
    "fips_pqc_conflict": "`fips_pqc_conflict`",
    "openssl": "`openssl`",
    "tpm_pqc": "`tpm_pqc`",
    "ssh_pqc": "`ssh_pqc`",
    "ipsec_pqc": "`ipsec_pqc`",
    "nss": "`nss`",
    "kernel_info": "`kernel_info`",
    "cnsa_2_0": "`cnsa_2_0`",
    "trust_store": "`trust_store`",
    "crypto_material": "`crypto_material`",
    "runtime_environment": "`runtime_environment`",
    "host_fs_detections_unavailable": "`host_fs_detections_unavailable`",
    "packages": "`packages`",
    "os_release": "`os_release`",
    "pqc_sizes": "`pqc_sizes`",
    "benchmark": "`benchmark`",
    "benchmark_tls_handshake": "`benchmark_tls_handshake`",
    "per_algo": "`per_algo`",
    "production_estimate": "`production_estimate`",
}


def _sections() -> dict[str, str]:
    """Map each `##` / `###` heading (text after the hashes) to its body."""
    out: dict[str, str] = {}
    current = None
    for line in DOC.read_text().splitlines():
        m = re.match(r"^#{2,3} (.+)$", line)
        if m:
            current = m.group(1).strip()
            out[current] = ""
        elif current is not None:
            out[current] += line + "\n"
    return out


def _documented(section_body: str, key: str) -> bool:
    spans = " ".join(re.findall(r"`([^`]+)`", section_body))
    return re.search(r"(?<![\w./-])" + re.escape(key) + r"(?![\w-])", spans) is not None


def _section(sections: dict[str, str], title: str) -> str:
    assert title in sections, f"docs/json-output.md has no section {title!r}"
    return sections[title]


def _function_keys(name: str) -> set[str]:
    # The scanner is a package (#80): search every module's source.
    from conftest import PACKAGE_SRC

    nodes = [
        n
        for f in sorted(PACKAGE_SRC.rglob("*.py"))
        for n in ast.parse(f.read_text()).body
    ]
    for node in nodes:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            keys: set[str] = set()
            for n in ast.walk(node):
                if isinstance(n, ast.Dict):
                    keys |= {
                        k.value
                        for k in n.keys
                        if isinstance(k, ast.Constant) and isinstance(k.value, str)
                    }
                elif (
                    isinstance(n, ast.Subscript)
                    and isinstance(n.ctx, ast.Store)
                    and isinstance(n.slice, ast.Constant)
                    and isinstance(n.slice.value, str)
                ):
                    keys.add(n.slice.value)
            return keys - INTERNAL_KEYS.get(name, set())
    raise AssertionError(
        f"producing function {name} no longer exists; update FUNCTION_SECTIONS"
    )


@pytest.mark.parametrize("func", sorted(FUNCTION_SECTIONS))
def test_every_key_a_producer_writes_is_documented(func: str) -> None:
    sections = _sections()
    bodies = [_section(sections, t) for t in FUNCTION_SECTIONS[func]]
    missing = sorted(
        k for k in _function_keys(func) if not any(_documented(b, k) for b in bodies)
    )
    assert not missing, (
        f"{func} emits keys not documented under {FUNCTION_SECTIONS[func]} "
        f"in docs/json-output.md: {missing}"
    )


def _paths(value: Any, prefix: str = "") -> Iterator[tuple[str, str]]:
    """Yield (parent object path, key) for every dict key, '[]' for lists."""
    if isinstance(value, dict):
        for k, v in value.items():
            if prefix not in DYNAMIC_CHILDREN:
                yield prefix, k
            yield from _paths(v, f"{prefix}.{k}" if prefix else k)
    elif isinstance(value, list):
        for item in value:
            yield from _paths(item, prefix)


def _section_for(parent: str) -> str:
    if not parent:
        return TOP_LEVEL
    head = parent.split(".", 1)[0]
    return PATH_SECTIONS.get(head, TOP_LEVEL)


def _golden_report() -> dict[str, Any]:
    data = json.loads(GOLDEN.read_text())
    return data.get("report", data)


def test_every_report_key_path_is_documented() -> None:
    sections = _sections()
    report = _golden_report()
    missing = sorted(
        f"{parent + '.' if parent else ''}{key}"
        for parent, key in _paths(report)
        if f"{parent}.{key}" not in GOLDEN_STUB_ONLY
        and not _documented(_section(sections, _section_for(parent)), key)
    )
    assert not missing, f"undocumented --json key paths: {missing}"


def test_every_top_level_report_field_is_in_the_table() -> None:
    table = _section(_sections(), TOP_LEVEL)
    fields = [f.name for f in pr.Report.__dataclass_fields__.values()]
    assert [f for f in fields if f"| `{f}` |" not in table] == []


@pytest.mark.parametrize("role", pr.VALID_ROLES)
@pytest.mark.parametrize("policy", ["auto", "cnsa-2.0"])
def test_every_recommend_key_path_is_documented(role: str, policy: str) -> None:
    sections = _sections()
    report = pr.Report(**_golden_report())
    doc = pr.recommend(report, policy=policy, role=role)
    missing = []
    for parent, key in _paths(doc):
        if parent == "recommendations":
            if key not in pr.VALID_POLICIES:
                missing.append(f"recommendations.{key}")
            continue
        if parent == "policy_sources":
            # Map keyed by jurisdiction id; the ids are listed in the
            # `policy_sources` row of the document table.
            if not _documented(_section(sections, RECOMMEND), key):
                missing.append(f"policy_sources.{key}")
            continue
        if parent.startswith("policy_sources."):
            title = POLICY_SOURCES
        else:
            title = RECOMMEND if not parent else RECORD
        if not _documented(_section(sections, title), key):
            missing.append(f"{parent}.{key}" if parent else key)
    assert not missing, f"undocumented --recommend keys ({role}, {policy}): {missing}"


def test_every_aggregate_key_is_documented(tmp_path: Path) -> None:
    (tmp_path / "host.json").write_text(json.dumps(_golden_report()))
    (tmp_path / "stray.json").write_text("[1, 2, 3]")
    body, _code = pr.run_aggregator(tmp_path)
    rollup = json.loads(body)
    section = _section(_sections(), AGGREGATE)
    top = [k for k in rollup if not _documented(section, k)]
    skipped = [k for s in rollup["skipped"] for k in s if not _documented(section, k)]
    assert top == [] and skipped == []
