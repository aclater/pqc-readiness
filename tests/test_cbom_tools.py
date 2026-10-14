# SPDX-License-Identifier: Apache-2.0
"""deploy/cbom/cbom_tools.py: helpers for CBOM importers (#218).

The merge-repair inputs reproduce what the CycloneDX CLI 0.33.1
``merge --hierarchical`` command wrote for two pqc-readiness CBOMs on
2026-10-14 (docs/integrations/posture-platforms.md).
"""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest

import pqc_readiness as pr
from test_cbom import _make_report, _validate_with_jsonschema

SCRIPT = Path(__file__).resolve().parent.parent / "deploy" / "cbom" / "cbom_tools.py"
if not SCRIPT.exists():  # container test images ship tests/ but not deploy/
    pytest.skip("deploy/ not present", allow_module_level=True)
_spec = importlib.util.spec_from_file_location("cbom_tools", SCRIPT)
assert _spec is not None and _spec.loader is not None
tools = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tools)


def _cert(ref: str, fp: str, name: str = "CN=example") -> dict[str, Any]:
    return {
        "type": "cryptographic-asset",
        "bom-ref": ref,
        "name": name,
        "cryptoProperties": {
            "assetType": "certificate",
            "certificateProperties": {"fingerprint": {"alg": "SHA-256", "content": fp}},
        },
    }


def _bom(
    components: list[dict[str, Any]], deps: list[dict[str, Any]] | None = None
) -> dict[str, Any]:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "version": 1,
        "metadata": {
            "component": {
                "type": "operating-system",
                "bom-ref": "host/unknown",
                "name": "unknown-host",
            }
        },
        "components": components,
        "dependencies": deps or [],
    }


def test_name_host_renames_host_and_its_dependency_edges() -> None:
    bom = _bom(
        [],
        [
            {
                "ref": "host/unknown",
                "dependsOn": ["pkg:rpm/rhel/gnutls@3.8.10?distro=rhel-10.2"],
            },
            {
                "ref": "pkg:rpm/rhel/gnutls@3.8.10?distro=rhel-10.2",
                "provides": ["library/gnutls/kem/ML-KEM-768"],
            },
        ],
    )
    out = tools.name_host(bom, "ubi10-image")
    assert out["metadata"]["component"]["bom-ref"] == "host/ubi10-image"
    assert out["metadata"]["component"]["name"] == "ubi10-image"
    assert out["dependencies"][0]["ref"] == "host/ubi10-image"
    # Entries without dependsOn are left as they were (no empty list added).
    assert "dependsOn" not in out["dependencies"][1]
    assert "host/unknown" not in json.dumps(out)


def test_name_host_output_stays_schema_valid() -> None:
    bom = json.loads(pr.render_cbom(_make_report(), "1.7"))
    _validate_with_jsonschema(tools.name_host(bom, "renamed"), "1.7")


def test_repair_merge_drops_cli_null_state_and_zero_size() -> None:
    rcm = {
        "type": "cryptographic-asset",
        "bom-ref": "a@:trust-store/summary",
        "name": "trust-store",
        "cryptoProperties": {
            "assetType": "related-crypto-material",
            "relatedCryptoMaterialProperties": {
                "type": "other",
                "state": "null",
                "size": 0,
            },
        },
    }
    out = tools.repair_merge(_bom([rcm]))
    props = out["components"][0]["cryptoProperties"]["relatedCryptoMaterialProperties"]
    assert props == {"type": "other"}


def test_repair_merge_keeps_real_state_and_size() -> None:
    rcm = {
        "type": "cryptographic-asset",
        "bom-ref": "k",
        "name": "k",
        "cryptoProperties": {
            "assetType": "related-crypto-material",
            "relatedCryptoMaterialProperties": {
                "type": "private-key",
                "state": "active",
                "size": 256,
            },
        },
    }
    out = tools.repair_merge(_bom([copy.deepcopy(rcm)]))
    assert out["components"][0] == rcm


def test_repair_merge_prefixes_provides_like_the_cli_prefixes_dependson() -> None:
    lib = {
        "type": "library",
        "bom-ref": "host-a@:pkg:generic/openssl@3.5.9",
        "name": "openssl",
    }
    alg = {
        "type": "cryptographic-asset",
        "bom-ref": "host-a@:openssl/kem/ML-KEM-768",
        "name": "ML-KEM-768",
    }
    deps = [
        {
            "ref": "host-a@:pkg:generic/openssl@3.5.9",
            "provides": ["openssl/kem/ML-KEM-768"],
        }
    ]
    out = tools.repair_merge(
        _bom(
            [
                {
                    "type": "device",
                    "bom-ref": "host-a@:host/a",
                    "name": "a",
                    "components": [lib, alg],
                }
            ],
            deps,
        )
    )
    assert out["dependencies"][0]["provides"] == ["host-a@:openssl/kem/ML-KEM-768"]


def test_repair_merge_leaves_unmerged_documents_alone() -> None:
    deps = [
        {"ref": "pkg:generic/openssl@3.5.9", "provides": ["openssl/kem/ML-KEM-768"]}
    ]
    bom = _bom(
        [
            {
                "type": "cryptographic-asset",
                "bom-ref": "openssl/kem/ML-KEM-768",
                "name": "ML-KEM-768",
            }
        ],
        deps,
    )
    assert tools.repair_merge(copy.deepcopy(bom)) == bom


def test_join_certificates_matches_on_sha256_fingerprint_case_insensitively() -> None:
    fp = "9a6ec012e1a7da9dbe34194d478ad7c0db1822fb071df12981496ed104384113"  # pragma: allowlist secret (public CA fingerprint)
    host = _bom(
        [
            _cert("cert/sha256:" + fp, fp, "CN=on-host"),
            _cert("cert/sha256:" + "11" * 32, "11" * 32),
        ]
    )
    other = _bom(
        [_cert("endpoint-cert-1", fp.upper()), _cert("endpoint-cert-2", "00" * 32)]
    )
    matches = tools.join_certificates(host, other)
    assert [(m[0], m[1]["name"]) for m in matches] == [(fp, "CN=on-host")]


def test_join_packages_matches_upstream_version_across_release_arch_epoch() -> None:
    cbom = _bom(
        [
            {
                "type": "library",
                "bom-ref": "l1",
                "name": "gnutls",
                "purl": "pkg:rpm/fedora/gnutls@3.8.13?distro=fedora-44",
            },
            {
                "type": "library",
                "bom-ref": "l2",
                "name": "java",
                "purl": "pkg:generic/java@25.0.4.1",
            },
        ]
    )
    sbom = {
        "components": [
            {
                "purl": "pkg:rpm/fedora/gnutls@3.8.13-1.fc44?arch=x86_64&distro=fedora-44"
            },
            {"purl": "pkg:rpm/fedora/gnutls@3.8.13-1.fc44?arch=i686&distro=fedora-44"},
            {
                "purl": "pkg:rpm/fedora/gnutls@3.8.12-1.fc44?arch=x86_64&distro=fedora-44"
            },
        ]
    }
    assert tools.join_packages(cbom, sbom) == [
        (
            "pkg:rpm/fedora/gnutls@3.8.13?distro=fedora-44",
            [
                "pkg:rpm/fedora/gnutls@3.8.13-1.fc44?arch=x86_64&distro=fedora-44",
                "pkg:rpm/fedora/gnutls@3.8.13-1.fc44?arch=i686&distro=fedora-44",
            ],
        ),
        ("pkg:generic/java@25.0.4.1", []),
    ]


def test_cli_round_trip(tmp_path: Path, capsys: Any) -> None:
    fp = "ab" * 32
    host, other = tmp_path / "host.json", tmp_path / "other.json"
    host.write_text(json.dumps(_bom([_cert("c", fp, "CN=x")])))
    other.write_text(json.dumps(_bom([_cert("o", fp)])))
    assert tools.main(["join-certificates", str(host), str(other)]) == 0
    out = capsys.readouterr()
    assert out.out == f"{fp}\tCN=x\n"
    assert "1 of 1 certificates" in out.err
    renamed = tmp_path / "renamed.json"
    assert tools.main(["name-host", str(host), str(renamed), "img"]) == 0
    assert (
        json.loads(renamed.read_text())["metadata"]["component"]["bom-ref"]
        == "host/img"
    )
