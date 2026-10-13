# SPDX-License-Identifier: Apache-2.0
"""Crypto libraries (#110) and service→library linkage (#111) in the CBOM
(#194): library components that `provide` the algorithms found in their
binaries, and application components that depend on the library they map."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest
from test_cbom import _make_report, _validate_with_jsonschema

import pqc_readiness as pr
from pqc_readiness.render import cbom

GNUTLS_PURL = "pkg:rpm/fedora/gnutls@3.8.13?distro=fedora-44"


def _report() -> pr.Report:
    r = _make_report()
    r.os_release = {"id": "fedora", "version_id": "44", "family": "rhel"}
    r.crypto_libraries = {
        "available": True,
        "libraries": {
            "gnutls": {
                "installed": True,
                "version": "3.8.13",
                "version_source": "package",
                "packages": [
                    {"name": "gnutls", "version": "3.8.13"},
                    {"name": "gnutls", "version": "3.8.13"},
                ],
                "files": ["/usr/lib64/libgnutls.so.30"],
                "evidence": "binary",
                "pqc_capable": True,
                "algorithms": {
                    "tls_hybrid_groups": ["X25519MLKEM768"],
                    "kem": ["ML-KEM-768"],
                    "signatures": ["ML-DSA-65"],
                },
                "caveats": [],
                "reference": "https://gitlab.com/gnutls/gnutls/-/blob/master/NEWS",
            },
            "libssh": {
                "installed": True,
                "version": "0.12.2",
                "packages": [{"name": "libssh", "version": "0.12.2"}],
                "files": ["/usr/lib64/libssh.so.4"],
                "evidence": "binary",
                "pqc_capable": True,
                "algorithms": {
                    "ssh_kex": ["mlkem768x25519-sha256", "mlkem1024"],
                },
                "caveats": [],
            },
            "libgcrypt": {
                "installed": True,
                "version": "1.11.0",
                "packages": [],
                "files": [],
                "evidence": "version",
                "pqc_capable": None,
                "algorithms": {},
                "caveats": ["pre-standard ML-KEM"],
            },
            "java": {
                "installed": True,
                "installs": [
                    {
                        "path": "/usr/lib/jvm/java-25",
                        "version": "25.0.4",
                        "implementor": "Red Hat, Inc.",
                        "jca_ml_kem_ml_dsa": True,
                        "tls_hybrid_default": False,
                    }
                ],
                "evidence": "version",
                "pqc_capable": True,
            },
            "wolfssl": {"installed": False},
        },
    }
    r.service_crypto_linkage = {
        "available": True,
        "listeners": [
            {
                "protocol": "tcp",
                "family": "ipv4",
                "address": "0.0.0.0",
                "port": 443,
                "pid": 101,
                "process": "httpd",
                "exe": "/usr/sbin/httpd",
                "systemd_unit": "httpd.service",
                "crypto_libraries": [
                    {
                        "family": "openssl",
                        "version": "3.5.5",
                        "library_pqc_capable": True,
                    },
                    {
                        "family": "gnutls",
                        "version": "3.8.13",
                        "library_pqc_capable": True,
                    },
                ],
                "static_binary": False,
                "go": None,
            },
            {
                "protocol": "tcp",
                "family": "ipv6",
                "address": "::",
                "port": 443,
                "pid": 101,
                "process": "httpd",
                "exe": "/usr/sbin/httpd",
                "systemd_unit": "httpd.service",
                "crypto_libraries": [
                    {
                        "family": "openssl",
                        "version": "3.5.5",
                        "library_pqc_capable": True,
                    }
                ],
                "static_binary": False,
                "go": None,
            },
            {
                "protocol": "tcp",
                "family": "ipv4",
                "address": "0.0.0.0",
                "port": 8443,
                "pid": 202,
                "process": "myapp",
                "exe": "/opt/myapp/myapp",
                "systemd_unit": "app-gnome-myapp-4242.scope",
                "crypto_libraries": [],
                "static_binary": True,
                "go": {"go_version": "go1.22.5", "default_hybrid_kex": None},
            },
            {  # unattributed: no process to name
                "protocol": "udp",
                "family": "ipv4",
                "address": "127.0.0.53",
                "port": 53,
                "pid": None,
                "exe": None,
                "crypto_libraries": [],
            },
        ],
    }
    return r


def _bom(r: pr.Report, version: str = "1.7", **kw: str) -> dict[str, Any]:
    return json.loads(
        cbom.render_cbom(
            r, version, kw.get("profile", "none"), kw.get("interop", "none")
        )
    )


def _by_ref(bom: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {c["bom-ref"]: c for c in bom["components"]}


def _deps(bom: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {d["ref"]: d for d in bom.get("dependencies", [])}


def _props(comp: dict[str, Any]) -> list[tuple[str, str]]:
    return [(p["name"], p["value"]) for p in comp.get("properties", [])]


def _assert_refs_resolve(bom: dict[str, Any]) -> None:
    refs = set(_by_ref(bom)) | {bom["metadata"]["component"]["bom-ref"]}
    for d in bom.get("dependencies", []):
        for ref in [d["ref"], *d.get("dependsOn", []), *d.get("provides", [])]:
            assert ref in refs, ref


@pytest.mark.parametrize(
    ("profile", "interop"),
    [
        ("none", "none"),
        ("federal-draft", "none"),
        ("none", "dependency-track"),
        ("none", "sbom-only"),
        ("federal-draft", "dependency-track"),
    ],
)
def test_libraries_and_services_validate_and_resolve(
    profile: str, interop: str
) -> None:
    bom = _bom(_report(), profile=profile, interop=interop)
    _validate_with_jsonschema(bom, "1.7")
    _assert_refs_resolve(bom)


def test_library_components_and_provides() -> None:
    bom = _bom(_report())
    comps, deps = _by_ref(bom), _deps(bom)
    gnutls = comps[GNUTLS_PURL]
    assert gnutls["type"] == "library" and gnutls["purl"] == GNUTLS_PURL
    assert ("pqc-readiness:library:pqc_capable", "true") in _props(gnutls)
    assert sorted(deps[GNUTLS_PURL]["provides"]) == [
        "library/gnutls/kem/ML-KEM-768",
        "library/gnutls/sig/ML-DSA-65",
        "library/gnutls/tls-hybrid/X25519MLKEM768",  # pragma: allowlist secret
    ]
    kem = comps["library/gnutls/kem/ML-KEM-768"]
    assert kem["cryptoProperties"]["algorithmProperties"]["primitive"] == "kem"
    assert kem["cryptoProperties"]["algorithmProperties"]["algorithmFamily"] == "ML-KEM"
    # SSH kex split by name, as for OpenSSH's own assets.
    assert "library/libssh/ssh-kex/hybrid/mlkem768x25519-sha256" in comps
    assert "library/libssh/ssh-kex/pure-pqc/mlkem1024" in comps
    # Unknown capability and caveats are carried, never guessed.
    gcrypt = comps["pkg:generic/libgcrypt@1.11.0"]
    assert ("pqc-readiness:library:pqc_capable", "unknown") in _props(gcrypt)
    assert ("pqc-readiness:library:caveat", "pre-standard ML-KEM") in _props(gcrypt)
    # JDK installs: one component per install; not-installed libraries absent.
    java = comps["pkg:generic/java@25.0.4"]
    assert ("pqc-readiness:library:tls_hybrid_default", "false") in _props(java)
    assert not any(c.get("name") == "wolfssl" for c in bom["components"])


def test_services_depend_on_their_libraries() -> None:
    bom = _bom(_report())
    comps, deps = _by_ref(bom), _deps(bom)
    httpd = comps["service/httpd.service"]
    assert httpd["type"] == "application" and httpd["name"] == "httpd.service"
    endpoints = [v for k, v in _props(httpd) if k == "service:endpoint"]
    assert endpoints == [
        "tcp/0.0.0.0:443",
        "tcp/[::]:443",
    ]  # two listeners, one component
    assert deps["service/httpd.service"]["dependsOn"] == [
        "pkg:generic/openssl@3.5.5",
        GNUTLS_PURL,  # resolved to the probed library, not a duplicate
    ]
    # Transient scope -> named by executable; static Go runtime as a library.
    assert deps["service//opt/myapp/myapp"]["dependsOn"] == ["pkg:generic/go@1.22.5"]
    go = comps["pkg:generic/go@1.22.5"]
    assert ("pqc-readiness:library:basis", "service-linkage") in _props(go)
    # Unattributed listener skipped; host depends on every library and service.
    assert sum(1 for c in bom["components"] if c["type"] == "application") == 2
    host = deps[bom["metadata"]["component"]["bom-ref"]]["dependsOn"]
    assert "service/httpd.service" in host and GNUTLS_PURL in host


def test_federal_profile_annotates_library_algorithms() -> None:
    comps = _by_ref(_bom(_report(), profile="federal-draft"))
    props = dict(_props(comps["library/gnutls/kem/ML-KEM-768"]))
    assert props["federal:function"] == "key-establishment"
    assert props["federal:quantum_vulnerable"] == "false"


def test_dependency_track_mirrors_library_assets_and_merges_probed_openssl() -> None:
    bom = _bom(_report(), interop="dependency-track")
    comps, deps = _by_ref(bom), _deps(bom)
    kem = comps["library/gnutls/kem/ML-KEM-768"]
    assert ("pqc-readiness:crypto:classification", "pure-pqc") in _props(kem)
    # The probed OpenSSL stack (#175) and the service's mapped OpenSSL are
    # the same bom-ref: one component, both bases, the probed provides kept.
    openssl = [
        c for c in bom["components"] if c["bom-ref"] == "pkg:generic/openssl@3.5.5"
    ]
    assert len(openssl) == 1
    bases = {v for k, v in _props(openssl[0]) if k == "pqc-readiness:library:basis"}
    assert bases == {"probed-stack", "service-linkage"}
    assert deps["pkg:generic/openssl@3.5.5"]["provides"]


def test_sbom_only_has_libraries_and_services_but_no_provides() -> None:
    bom = _bom(_report(), interop="sbom-only")
    assert {c["type"] for c in bom["components"]} == {"library", "application"}
    assert all("provides" not in d for d in bom["dependencies"])


def test_cbom_16_unchanged_by_library_and_service_data() -> None:
    plain = json.loads(cbom.render_cbom(_make_report(), "1.6"))
    rich = _report()
    rich.os_release = {}  # isolate: only the new fields differ
    with_data = json.loads(cbom.render_cbom(rich, "1.6"))
    for b in (plain, with_data):
        b.pop("serialNumber")
    assert plain == with_data


def test_no_new_components_without_the_scan_flags() -> None:
    r = _make_report()
    before = copy.deepcopy(r)
    bom = _bom(r)
    assert "dependencies" not in bom
    assert not any(c["type"] in ("library", "application") for c in bom["components"])
    assert r == before


def test_library_assets_are_namespaced_by_group() -> None:
    # Dependency-Track 5.2.0 merges same-named components: without a group,
    # GnuTLS's ML-KEM-768 collapsed into OpenSSL's (55 of 73 assets stored
    # on a real upload; 73 of 73 with the group).
    comps = _by_ref(_bom(_report()))
    assert comps["library/gnutls/kem/ML-KEM-768"]["group"] == "gnutls"
    assert "group" not in comps["openssl/kem/ML-KEM-768"]


def test_dependency_track_mirrors_provides_as_provided_by() -> None:
    # DT re-exports CycloneDX 1.5, which has no dependencies[].provides.
    comps = _by_ref(_bom(_report(), interop="dependency-track"))
    assert (
        "pqc-readiness:crypto:providedBy",
        GNUTLS_PURL,
    ) in _props(comps["library/gnutls/kem/ML-KEM-768"])
    plain = _by_ref(_bom(_report()))
    assert not any(
        n.endswith("providedBy")
        for n, _ in _props(plain["library/gnutls/kem/ML-KEM-768"])
    )
