"""SPDX 3.0 JSON-LD output (--spdx)."""

from __future__ import annotations

import argparse
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from ..render import cbom as _cbom
from ..render import sarif as _sarif
from .. import report as _report
from .. import registry as _registry


# ---------------------------------------------------------------------------
# SPDX 3.0 JSON-LD output (--spdx)
# ---------------------------------------------------------------------------
# SPDX 3.0 added a Security profile that overlaps with CBOM use cases.
# Some procurement contexts (notably US federal) standardise on SPDX
# rather than CycloneDX, so emitting both broadens compatibility without
# forcing customers to convert formats.
#
# Same source data as --cbom — both renderers project from the
# canonical_assets() pipeline above.  Findings (the same set of rule
# predicates that drive --sarif) are emitted here as
# security_Vulnerability elements with VEX "affects" relationships
# linking each finding to the host package.
#
# Validation: SPDX 3.0.1 does not publish a JSON Schema; the canonical
# validation surface is the OWL/SHACL ontology.  tests/test_spdx.py
# bundles the official JSON-LD context file and runs a structural
# validator that mirrors the spec's required-shape constraints
# (top-level @context + @graph, every Element carries creationInfo,
# every type/property is a known term in the SPDX 3.0.1 context).
#
# Refs:
#   https://spdx.github.io/spdx-spec/v3.0.1/  (SPDX 3.0.1 spec)
#   https://spdx.org/rdf/3.0.1/spdx-context.jsonld  (canonical context)

SPDX_VERSION = "3.0.1"


SPDX_CONTEXT_URL = "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"


SPDX_DATA_LICENSE = "https://spdx.org/licenses/CC0-1.0"


# URN namespace prefix for spdxIds emitted by this tool.  URNs are valid
# IRIs and avoid implying a resolvable HTTP endpoint.
SPDX_URN_PREFIX = "urn:pqc-readiness"


def _spdx_safe(s: str) -> str:
    """Sanitise a string for inclusion in a URN segment.  SPDX 3.0
    spdxIds are IRIs; we conservatively keep alphanumerics plus
    [.-_] and replace runs of anything else with a single dash."""
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", s).strip("-")
    return cleaned or "unknown"


def _spdx_software_purpose(asset: _cbom.CryptoAsset) -> str:
    """Map a canonical asset onto the SPDX 3.0 SoftwarePurpose enum.

    The enum is fixed (see /Software/SoftwarePurpose) so we collapse
    crypto-asset categories to the closest enum entry: hardware-execution
    assets surface as `device`, software algorithms / protocols as
    `library`, and the trust-store summary as `data`."""
    if asset.execution_environment == "hardware":
        return "device"
    if asset.asset_type == "related-crypto-material":
        return "data"
    return "library"


def _spdx_creation_info(creator_id: str) -> dict[str, Any]:
    """SPDX 3.0 inlines CreationInfo on every Element.  Every element in
    a single document shares the same created-time + creator agent."""
    return {
        "type": "CreationInfo",
        "specVersion": SPDX_VERSION,
        "created": _CURRENT_RUN_TIME[0],
        "createdBy": [creator_id],
    }


# Module-level slot so _spdx_creation_info renders a stable timestamp
# across all elements in one document; render_spdx() updates it once.
_CURRENT_RUN_TIME: list[str] = ["1970-01-01T00:00:00Z"]


def _spdx_element_base(
    spdx_id: str,
    type_name: str,
    name: str,
    creator_id: str,
) -> dict[str, Any]:
    return {
        "type": type_name,
        "spdxId": spdx_id,
        "creationInfo": _spdx_creation_info(creator_id),
        "name": name,
    }


def _spdx_creator_agent(spdx_id: str) -> dict[str, Any]:
    """The pqc-readiness tool itself, modelled as a SoftwareAgent.

    SoftwareAgent is the SPDX 3.0 class for software acting on a system.
    The agent is its own creator (self-reference is permitted by the
    spec and is the standard bootstrap pattern) so the document does
    not require an external Agent registry."""
    return {
        "type": "SoftwareAgent",
        "spdxId": spdx_id,
        "creationInfo": _spdx_creation_info(spdx_id),
        "name": "pqc-readiness",
        "description": (
            "Open-source PQC readiness scanner — see "
            "https://github.com/aclater/pqc-readiness"
        ),
    }


def _spdx_host_package(
    spdx_id: str,
    creator_id: str,
    r: _report.Report,
) -> dict[str, Any]:
    """The scanned host as a software_Package.

    The host is the package whose cryptographic inventory this document
    describes.  Findings (Vulnerability elements) attach to it via VEX
    relationships."""
    pkg = _spdx_element_base(
        spdx_id,
        "software_Package",
        r.hostname or "unknown-host",
        creator_id,
    )
    summary_bits: list[str] = []
    if r.os:
        summary_bits.append(r.os)
    if r.arch:
        summary_bits.append(r.arch)
    if summary_bits:
        pkg["summary"] = " / ".join(summary_bits)
    pkg["software_primaryPurpose"] = "platform"
    if r.cpu_model:
        pkg["description"] = f"CPU: {r.cpu_model}"
    return pkg


def _spdx_asset_package(
    asset: _cbom.CryptoAsset,
    namespace: str,
    creator_id: str,
) -> dict[str, Any]:
    """Project a canonical CryptoAsset into an SPDX 3.0 software_Package.

    SPDX 3.0 doesn't ship a native cryptographic-asset element type, so
    we model each asset as a software_Package with `software_primaryPurpose`
    set per the asset's execution environment.  Crypto metadata that has
    no native SPDX field (primitive, parameter set, NIST category, source,
    free-form properties) goes into `description` as a stable, parseable
    `key=value` block — the same data CBOM emits as `properties`."""
    spdx_id = f"{namespace}:asset:{_spdx_safe(asset.key)}"
    elem = _spdx_element_base(
        spdx_id,
        "software_Package",
        asset.name,
        creator_id,
    )
    elem["summary"] = f"Cryptographic asset (category={asset.category})"
    elem["software_primaryPurpose"] = _spdx_software_purpose(asset)

    desc_lines: list[str] = [f"category={asset.category}"]
    desc_lines.append(f"assetType={asset.asset_type}")
    if asset.primitive:
        desc_lines.append(f"primitive={asset.primitive}")
    if asset.execution_environment:
        desc_lines.append(f"executionEnvironment={asset.execution_environment}")
    if asset.implementation_platform:
        desc_lines.append(f"implementationPlatform={asset.implementation_platform}")
    if asset.protocol_type:
        desc_lines.append(f"protocolType={asset.protocol_type}")
    if asset.related_material_type:
        desc_lines.append(f"relatedMaterialType={asset.related_material_type}")
    if asset.source:
        desc_lines.append(f"source={asset.source}")
    for k, v in asset.properties:
        desc_lines.append(f"{k}={v}")
    elem["description"] = "\n".join(desc_lines)

    if asset.parameter_set:
        elem["software_packageVersion"] = asset.parameter_set
    if asset.nist_category is not None:
        elem["externalIdentifier"] = [
            {
                "type": "ExternalIdentifier",
                "externalIdentifierType": "other",
                "identifier": f"nist-pqc-category-{asset.nist_category}",
            }
        ]
    return elem


# Help-URL base for security_Vulnerability elements emitted to SPDX —
# reuses the SARIF rule docs so each finding type has one canonical
# explanation page across formats.
SPDX_FINDING_HELP_BASE = _sarif.SARIF_HELP_BASE


SPDX_FINDING_LEVEL_TO_NOTE = {
    "error": "severity: error",
    "warning": "severity: warning",
    "note": "severity: note",
}


def _spdx_vulnerability(
    finding: _sarif.Finding,
    rule_spec: _sarif.RuleSpec,
    namespace: str,
    creator_id: str,
    idx: int,
) -> dict[str, Any]:
    """Each Finding becomes a security_Vulnerability whose summary is
    the rule's short description and whose full description is the
    rule body plus the rule-fired message.

    Keeping the SARIF rule_id as the externalIdentifier lets tooling
    correlate the same finding across SARIF and SPDX outputs."""
    spdx_id = f"{namespace}:finding:{idx:04d}:{_spdx_safe(rule_spec.id)}"
    elem = _spdx_element_base(
        spdx_id,
        "security_Vulnerability",
        rule_spec.id,
        creator_id,
    )
    elem["summary"] = rule_spec.short_description
    elem["description"] = f"{rule_spec.full_description}\n\nDetected: {finding.message}"
    elem["comment"] = SPDX_FINDING_LEVEL_TO_NOTE.get(
        finding.level, f"severity: {finding.level}"
    )
    elem["security_publishedTime"] = _CURRENT_RUN_TIME[0]
    elem["externalIdentifier"] = [
        {
            "type": "ExternalIdentifier",
            "externalIdentifierType": "other",
            "identifier": rule_spec.id,
        }
    ]
    elem["externalRef"] = [
        {
            "type": "ExternalRef",
            "externalRefType": "securityAdvisory",
            "locator": [rule_spec.help_uri],
        }
    ]
    return elem


def _spdx_vex_affects(
    vuln_id: str,
    target_id: str,
    namespace: str,
    creator_id: str,
    idx: int,
    action_statement: str,
) -> dict[str, Any]:
    """Link a security_Vulnerability to the host package via a VEX
    `affects` relationship.

    VexAffectedVulnAssessmentRelationship is the SPDX 3.0 way to declare
    "vulnerability V affects element E" — in this document E is always
    the scanned host package."""
    return {
        "type": "security_VexAffectedVulnAssessmentRelationship",
        "spdxId": f"{namespace}:vex:{idx:04d}",
        "creationInfo": _spdx_creation_info(creator_id),
        "relationshipType": "affects",
        "from": vuln_id,
        "to": [target_id],
        "security_assessedElement": target_id,
        "security_actionStatement": action_statement,
        "security_publishedTime": _CURRENT_RUN_TIME[0],
    }


def render_spdx(r: _report.Report) -> str:
    """Render the report as an SPDX 3.0 JSON-LD document.

    The document profileConformance includes core, software, and
    security: cryptographic assets are software_Package elements and
    findings are security_Vulnerability elements with VEX `affects`
    relationships to the scanned host."""
    timestamp = r.generated_at or datetime.now(timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    # The official spec wants an `xsd:dateTimeStamp`; that means a
    # mandatory timezone designator.  Report.generated_at carries
    # +00:00; SPDX examples use the trailing-Z form.  We accept either.
    _CURRENT_RUN_TIME[0] = timestamp

    host_safe = _spdx_safe(r.hostname or "unknown-host")
    namespace = f"{SPDX_URN_PREFIX}:{host_safe}"
    creator_id = f"{SPDX_URN_PREFIX}:tool:{_spdx_safe(_report.SCRIPT_VERSION)}"
    host_id = f"{namespace}:host"
    sbom_id = f"{namespace}:sbom"
    doc_id = f"{namespace}:document:{uuid.uuid4()}"

    creator = _spdx_creator_agent(creator_id)
    host_pkg = _spdx_host_package(host_id, creator_id, r)
    asset_pkgs = [
        _spdx_asset_package(a, namespace, creator_id) for a in _cbom.canonical_assets(r)
    ]

    findings = _sarif.build_findings(r)
    rule_specs_by_id = {s.id: s for s in _sarif.RULE_SPECS}
    vulns: list[dict[str, Any]] = []
    vex_rels: list[dict[str, Any]] = []
    for idx, f in enumerate(findings):
        spec = rule_specs_by_id.get(f.rule_id)
        if spec is None:
            continue
        vuln = _spdx_vulnerability(f, spec, namespace, creator_id, idx)
        vulns.append(vuln)
        vex_rels.append(
            _spdx_vex_affects(
                vuln["spdxId"],
                host_id,
                namespace,
                creator_id,
                idx,
                action_statement=f.message,
            )
        )

    member_ids: list[str] = (
        [host_id]
        + [pkg["spdxId"] for pkg in asset_pkgs]
        + [v["spdxId"] for v in vulns]
        + [rel["spdxId"] for rel in vex_rels]
    )

    sbom: dict[str, Any] = {
        "type": "software_Sbom",
        "spdxId": sbom_id,
        "creationInfo": _spdx_creation_info(creator_id),
        "name": f"pqc-readiness inventory for {r.hostname or 'unknown-host'}",
        "profileConformance": ["core", "software", "security"],
        "rootElement": [host_id],
        "element": member_ids,
        "software_sbomType": ["analyzed"],
    }

    document: dict[str, Any] = {
        "type": "SpdxDocument",
        "spdxId": doc_id,
        "creationInfo": _spdx_creation_info(creator_id),
        "name": f"pqc-readiness {_report.SCRIPT_VERSION} report",
        "profileConformance": ["core", "software", "security"],
        "dataLicense": SPDX_DATA_LICENSE,
        "rootElement": [sbom_id],
        "element": [sbom_id, *member_ids, creator_id],
    }

    graph: list[dict[str, Any]] = [
        creator,
        document,
        sbom,
        host_pkg,
        *asset_pkgs,
        *vulns,
        *vex_rels,
    ]

    out = {"@context": SPDX_CONTEXT_URL, "@graph": graph}
    return json.dumps(out, indent=2)


@_registry.register_arguments(13)
def add_arguments(ap: argparse.ArgumentParser) -> None:
    """--spdx."""
    ap.add_argument(
        "--spdx",
        action="store_true",
        help="emit SPDX 3.0 JSON-LD (Security profile) for SPDX-native pipelines",
    )


_registry.register_output(_registry.OutputFormat("spdx", 20, lambda r: render_spdx(r)))
