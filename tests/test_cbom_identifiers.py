# SPDX-License-Identifier: Apache-2.0
"""CBOM identifiers for cross-document joins (#222).

1. A library component for a package the scan resolved carries the same
   exact purl --sbom emits for that package, so an exact purl join between
   a host's CBOM and SBOM finds it.
2. --cbom-namespaced-properties prefixes every property name with
   `pqc-readiness:` and keeps the BOM schema-valid.
3. --host-name names the host in every scan mode, including offline
   --root trees with no /etc/hostname.
"""

from __future__ import annotations

import argparse
import json
import socket
from typing import Any

import pytest
from test_cbom import _make_report, _validate_with_jsonschema

import pqc_readiness as pr
from pqc_readiness import cli
from pqc_readiness.detect import packages
from pqc_readiness.detect import runtime_offline
from pqc_readiness.render import cbom, sbom

FEDORA = {"family": "rhel", "id": "fedora", "version_id": "44"}
# As the rpm reader returns them: epoch, release and arch are separate.
# Both match the rhel bundled-crypto catalogue (packages that carry their
# own crypto).
JDK = {
    "name": "java-21-openjdk-headless",
    "version": "21.0.8.0.9",
    "release": "1.fc44",
    "epoch": "1",
    "arch": "x86_64",
}
GOLANG = {"name": "golang", "version": "1.25.3", "release": "2.fc44", "arch": "x86_64"}
GNUTLS = {"name": "gnutls", "version": "3.8.10", "release": "2.fc44", "arch": "x86_64"}


def _fedora_report() -> pr.Report:
    r = _make_report()
    r.os_release = dict(FEDORA)
    r.packages = {
        "available": True,
        "bundled_crypto": packages.classify_bundled_crypto([JDK, GOLANG], "rhel"),
    }
    return r


def _library_purls(bom: dict[str, Any]) -> set[str]:
    return {
        c["purl"] for c in bom["components"] if c["type"] == "library" and "purl" in c
    }


# 1. purl alignment --------------------------------------------------------


def test_bundled_crypto_keeps_release_epoch_arch() -> None:
    rows = {
        row["package"]: row
        for row in packages.classify_bundled_crypto([JDK, GOLANG], "rhel")
    }
    assert rows["java-21-openjdk-headless"]["release"] == "1.fc44"
    assert rows["java-21-openjdk-headless"]["epoch"] == "1"
    assert rows["java-21-openjdk-headless"]["arch"] == "x86_64"
    # Absent fields stay absent rather than appearing empty.
    assert "epoch" not in rows["golang"]


def test_rpm_package_scan_keeps_release_epoch_arch(monkeypatch) -> None:
    """The live rpm path, not just the classifier: _scan_rpm_packages used
    to cut rows down to name and version before classifying them."""
    monkeypatch.setattr(
        packages,
        "query_rpm_packages",
        lambda: {
            "available": True,
            "source": "rpmdb-sqlite",
            "db_root": "/var/lib/rpm",
            "packages": [dict(JDK), dict(GOLANG)],
        },
    )
    rows = {
        row["package"]: row for row in packages.scan_packages(FEDORA)["bundled_crypto"]
    }
    assert rows["java-21-openjdk-headless"]["release"] == "1.fc44"
    assert rows["golang"]["arch"] == "x86_64"


def test_bundled_crypto_without_extra_fields_is_unchanged() -> None:
    rows = packages.classify_bundled_crypto(
        [{"name": "golang", "version": "1.25.3"}], "rhel"
    )
    assert set(rows[0]) == {"package", "version", "note"}


@pytest.mark.parametrize(
    "interop", [cbom.INTEROP_DEPENDENCY_TRACK, cbom.INTEROP_SBOM_ONLY]
)
def test_cbom_library_purls_match_sbom_purls(monkeypatch, interop: str) -> None:
    r = _fedora_report()
    monkeypatch.setattr(sbom, "installed_packages", lambda osr: ([JDK, GOLANG], None))
    sbom_purls = {c["purl"] for c in sbom.build_sbom(r)["components"] if "purl" in c}
    bom = json.loads(cbom.render_cbom(r, "1.7", "none", interop))
    joined = _library_purls(bom) & sbom_purls
    assert joined == {
        sbom.package_purl(JDK, FEDORA),
        sbom.package_purl(GOLANG, FEDORA),
    }
    assert (
        "pkg:rpm/fedora/java-21-openjdk-headless@21.0.8.0.9-1.fc44"
        "?arch=x86_64&distro=fedora-44&epoch=1"
    ) in joined
    _validate_with_jsonschema(bom, "1.7")


def test_cbom_library_version_matches_sbom_version(monkeypatch) -> None:
    r = _fedora_report()
    monkeypatch.setattr(sbom, "installed_packages", lambda osr: ([GOLANG], None))
    sbom_versions = {
        c["purl"]: c["version"] for c in sbom.build_sbom(r)["components"] if "purl" in c
    }
    bom = json.loads(cbom.render_cbom(r, "1.7", "none", cbom.INTEROP_SBOM_ONLY))
    for comp in bom["components"]:
        if comp.get("purl") in sbom_versions:
            assert comp["version"] == sbom_versions[comp["purl"]]


def test_crypto_library_component_uses_resolved_package_purl() -> None:
    r = _fedora_report()
    r.crypto_libraries = {
        "available": True,
        "libraries": {
            "gnutls": {
                "installed": True,
                "version": "3.8.10",
                "version_source": "package",
                # As protocols_libraries now reports it (release, arch kept).
                "packages": [dict(GNUTLS)],
                "files": ["/usr/lib64/libgnutls.so.30"],
                "pqc_capable": True,
                "evidence": "binary",
                "algorithms": {},
            }
        },
    }
    bom = json.loads(cbom.render_cbom(r, "1.7", "none", cbom.INTEROP_NONE))
    lib = next(
        c for c in bom["components"] if c["type"] == "library" and c["name"] == "gnutls"
    )
    assert lib["purl"] == sbom.package_purl(GNUTLS, FEDORA)


def test_library_probe_keeps_rpm_release_arch(monkeypatch) -> None:
    from pqc_readiness.detect import protocols_libraries

    monkeypatch.setattr(
        protocols_libraries._packages,
        "query_rpm_named",
        lambda names: {"available": True, "packages": [dict(GNUTLS)]},
    )
    spec = {"packages": {"rhel": ("gnutls",)}}
    (pkg,) = protocols_libraries._package_versions(spec, "rhel")
    assert pkg == {
        "name": "gnutls",
        "version": "3.8.10",
        "release": "2.fc44",
        "arch": "x86_64",
    }


# 2. namespaced property names ---------------------------------------------


def _property_names(node: Any) -> list[str]:
    names: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "properties" and isinstance(value, list):
                names += [p["name"] for p in value]
            else:
                names += _property_names(value)
    elif isinstance(node, list):
        for item in node:
            names += _property_names(item)
    return names


@pytest.mark.parametrize("version", ["1.7", "1.6"])
@pytest.mark.parametrize("interop", [cbom.INTEROP_NONE, cbom.INTEROP_DEPENDENCY_TRACK])
def test_namespaced_properties_prefix_every_name(version: str, interop: str) -> None:
    r = _fedora_report()
    plain = json.loads(cbom.render_cbom(r, version, "federal-draft", interop))
    spaced = json.loads(
        cbom.render_cbom(r, version, "federal-draft", interop, namespaced=True)
    )
    before, after = _property_names(plain), _property_names(spaced)
    assert any(not n.startswith("pqc-readiness:") for n in before)
    assert len(before) == len(after)
    assert all(n.startswith(("pqc-readiness:", "cdx:")) for n in after)
    # Names that were already namespaced are not double-prefixed.
    assert not any(n.startswith("pqc-readiness:pqc-readiness:") for n in after)
    _validate_with_jsonschema(spaced, version)


def test_namespaced_properties_default_off() -> None:
    r = _fedora_report()
    a = json.loads(cbom.render_cbom(r, "1.7"))
    b = json.loads(cbom.render_cbom(r, "1.7", namespaced=False))
    a.pop("serialNumber"), b.pop("serialNumber")
    assert a == b
    # Today's un-namespaced names (importers key on them) are untouched.
    assert "detectedBy" in _property_names(a)


def test_namespaced_flag_parses() -> None:
    ap = cli.build_parser()
    args = ap.parse_args(["--cbom", "--cbom-namespaced-properties"])
    assert args.cbom_namespaced_properties is True
    assert cbom._selected_namespaced is True
    ap = cli.build_parser()
    assert cbom._selected_namespaced is False


# 3. host identity ---------------------------------------------------------


def test_host_name_flag_wins_over_env_and_detected(monkeypatch) -> None:
    monkeypatch.setattr(socket, "gethostname", lambda: "detected")
    monkeypatch.setattr(pr._platform, "HOST_PREFIX", "")
    monkeypatch.setenv("PQC_HOSTNAME", "from-env")
    assert cli._report_hostname(argparse.Namespace(host_name="img-a")) == "img-a"
    assert cli._report_hostname(argparse.Namespace(host_name="  ")) == "from-env"
    monkeypatch.delenv("PQC_HOSTNAME")
    assert cli._report_hostname(argparse.Namespace(host_name="")) == "detected"


def test_offline_scan_takes_host_name(monkeypatch, tmp_path) -> None:
    """A --root tree without /etc/hostname used to be host/unknown."""
    monkeypatch.setattr(pr._platform, "OFFLINE_ROOT", str(tmp_path))
    monkeypatch.delenv("PQC_HOSTNAME", raising=False)
    monkeypatch.setattr(
        runtime_offline, "collect_offline_report", lambda args: pr.Report(hostname="")
    )
    monkeypatch.setattr(cli, "_with_gap", lambda r: r)
    r = cli.collect_report(argparse.Namespace(host_name="rhel9-golden"))
    assert r.hostname == "rhel9-golden"
    bom = json.loads(cbom.render_cbom(r, "1.7"))
    assert bom["metadata"]["component"]["bom-ref"] == "host/rhel9-golden"


def test_offline_scan_keeps_tree_hostname_without_flag(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(pr._platform, "OFFLINE_ROOT", str(tmp_path))
    monkeypatch.delenv("PQC_HOSTNAME", raising=False)
    monkeypatch.setattr(
        runtime_offline,
        "collect_offline_report",
        lambda args: pr.Report(hostname="tree"),
    )
    monkeypatch.setattr(cli, "_with_gap", lambda r: r)
    assert cli.collect_report(argparse.Namespace(host_name="")).hostname == "tree"
