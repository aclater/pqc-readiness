# SPDX-License-Identifier: Apache-2.0
"""Outbound-client process groups in the deployment-gap verdict (#202)."""

from __future__ import annotations

import csv
import io
from dataclasses import asdict
from typing import Any

import pytest

import pqc_readiness as pr
from pqc_readiness import aggregate, gap
from pqc_readiness.render import sarif

# Shapes follow process_crypto_linkage.groups[] from real --scan-processes
# runs (Rocky Linux 9.8, Fedora 44).
_OPENSSL_35 = {
    "family": "openssl",
    "version": "3.5.5",
    "path": "/usr/lib64/libssl.so.3",
    "deleted": False,
    "library_pqc_capable": True,
}
_OPENSSL_11 = {
    "family": "openssl",
    "version": None,
    "path": "/usr/lib64/libssl.so.1.1",
    "deleted": False,
    "library_pqc_capable": None,
}
_GNUTLS_UNKNOWN = {
    "family": "gnutls",
    "version": "3.8.3",
    "path": "/usr/lib64/libgnutls.so.30",
    "deleted": False,
    "library_pqc_capable": None,
}


def _host(tls_policy_pqc: bool) -> dict[str, Any]:
    return {
        "hostname": "h.example",
        "openssl": {
            "available": True,
            "pqc_native": True,
            "tls_groups": {
                "hybrid": ["X25519MLKEM768"],
                "pure_pqc": [],
                "classical": [],
            },
        },
        "crypto_policy": {
            "available": True,
            "pqc_enabled": {"tls_key_exchange": tls_policy_pqc},
        },
    }


def _group(
    exe: str,
    libs: list[dict[str, Any]],
    *,
    go: dict[str, Any] | None = None,
    client: int = 1,
    server: int = 0,
    idle: int = 0,
) -> dict[str, Any]:
    return {
        "exe": exe,
        "process": exe.rsplit("/", 1)[-1],
        "crypto_libraries": libs,
        "static_binary": go is not None and not libs,
        "go": go,
        "process_count": client + server + idle,
        "systemd_units": [f"{exe.rsplit('/', 1)[-1]}.service"],
        "roles": {"server": server, "client": client, "idle": idle},
    }


def _go(version: str, reverts: list[str] | None = None) -> dict[str, Any]:
    return {
        "go_version": version,
        "default_hybrid_kex": None if reverts else "X25519MLKEM768",
        "godebug_reverts": reverts or [],
    }


def _with_processes(
    raw: dict[str, Any], groups: list[dict[str, Any]]
) -> dict[str, Any]:
    raw["process_crypto_linkage"] = {"available": True, "groups": groups}
    return raw


def _clients(raw: dict[str, Any]) -> dict[str, Any]:
    return gap.compute_gap(raw)["clients"]


def _by_exe(clients: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {c["exe"]: c for c in clients["items"]}


# ---------------------------------------------------------------------------
# go_tls_capability / library_capable
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("version", "reverts", "expected"),
    [
        ("go1.26.1", [], (True, True)),
        ("go1.24.0", [], (True, True)),
        ("go1.26.1", ["tlsmlkem"], (True, False)),
        ("go1.23.4", [], (False, None)),
        ("go1.22.0", [], (False, None)),
        ("", [], (None, None)),
    ],
)
def test_go_tls_capability(
    version: str, reverts: list[str], expected: tuple[bool | None, bool | None]
) -> None:
    assert gap.go_tls_capability(_go(version, reverts)) == expected


def test_library_capable_is_shared_with_the_failure_findings() -> None:
    # #193's service findings and the client verdict use one judgement.
    assert not hasattr(sarif, "_service_lib_capable")
    assert gap.library_capable(dict(_OPENSSL_11), {}) == (False, "soname")
    assert gap.library_capable(dict(_OPENSSL_35), {}) == (True, "version")
    probes = {
        "gnutls": {
            "installed": True,
            "pqc_capable": True,
            "files": ["/usr/lib64/libgnutls.so.30"],
        }
    }
    assert gap.library_capable(dict(_GNUTLS_UNKNOWN), probes) == (
        True,
        "crypto_libraries",
    )
    assert gap.library_capable(dict(_GNUTLS_UNKNOWN), {}) == (None, "")


# ---------------------------------------------------------------------------
# Per-client verdicts
# ---------------------------------------------------------------------------


def test_clients_unavailable_without_process_scan() -> None:
    assert _clients(_host(True)) == {"available": False}


def test_only_client_role_groups_get_a_verdict() -> None:
    raw = _with_processes(
        _host(True),
        [
            _group("/usr/sbin/httpd", [_OPENSSL_35], client=0, server=3),
            _group("/usr/bin/vim", [_OPENSSL_35], client=0, idle=1),
            _group("/usr/bin/curl", [_OPENSSL_35], client=2),
        ],
    )
    c = _clients(raw)
    assert [i["exe"] for i in c["items"]] == ["/usr/bin/curl"]
    assert c["items"][0]["client_processes"] == 2


def test_library_clients_follow_the_host_tls_configuration() -> None:
    groups = [
        _group("/usr/bin/curl", [_OPENSSL_35], client=2),
        _group("/opt/legacy/agent", [_OPENSSL_11], client=1),
        _group("/usr/bin/gnutls-cli", [_GNUTLS_UNKNOWN], client=1),
    ]
    # Rocky 9.8 DEFAULT: capable OpenSSL, policy keeps TLS classical.
    rocky = _by_exe(_clients(_with_processes(_host(False), [dict(g) for g in groups])))
    assert rocky["/usr/bin/curl"]["state"] == "capable_not_configured"
    assert rocky["/usr/bin/curl"]["follows_host_default"] is True
    assert rocky["/opt/legacy/agent"]["state"] == "not_capable"
    assert rocky["/opt/legacy/agent"]["follows_host_default"] is False
    assert rocky["/usr/bin/gnutls-cli"]["state"] == "unknown"
    # Fedora 44: capable and configured.
    fedora = _by_exe(_clients(_with_processes(_host(True), [dict(g) for g in groups])))
    assert fedora["/usr/bin/curl"]["state"] == "deployed"
    assert fedora["/usr/bin/curl"]["follows_host_default"] is True
    assert fedora["/usr/bin/curl"]["evidence"] == {
        "capable": ["process_crypto_linkage.groups[0].crypto_libraries"],
        "configured": ["crypto_policy.pqc_enabled.tls_key_exchange"],
    }


def test_any_non_pqc_library_makes_the_client_not_capable() -> None:
    # Same semantics as #107 services: under a PQC-enabling host default the
    # client is "configured" but its library can't follow.
    groups = [_group("/usr/bin/mixed", [_OPENSSL_35, _OPENSSL_11])]
    on = _with_processes(_host(True), [dict(g) for g in groups])
    off = _with_processes(_host(False), [dict(g) for g in groups])
    assert _clients(on)["items"][0]["capable"] is False
    assert _clients(on)["items"][0]["state"] == "configured_not_capable"
    assert _clients(off)["items"][0]["state"] == "not_capable"


def test_library_probe_settles_unknown_versions() -> None:
    raw = _with_processes(
        _host(True), [_group("/usr/bin/gnutls-cli", [_GNUTLS_UNKNOWN])]
    )
    raw["crypto_libraries"] = {
        "libraries": {
            "gnutls": {
                "installed": True,
                "pqc_capable": True,
                "files": ["/usr/lib64/libgnutls.so.30"],
            }
        }
    }
    assert _clients(raw)["items"][0]["state"] == "deployed"


def test_go_clients_use_their_own_default() -> None:
    raw = _with_processes(
        _host(False),
        [
            _group("/usr/local/bin/new", [], go=_go("go1.26.1")),
            _group("/usr/local/bin/reverted", [], go=_go("go1.26.1", ["tlsmlkem"])),
            _group("/usr/local/bin/old", [], go=_go("go1.22.0")),
        ],
    )
    c = _by_exe(_clients(raw))
    # The host policy is classical, but Go ignores it.
    assert c["/usr/local/bin/new"]["state"] == "deployed"
    assert c["/usr/local/bin/reverted"]["state"] == "capable_not_configured"
    assert c["/usr/local/bin/old"]["state"] == "not_capable"
    assert all(not i["follows_host_default"] for i in c.values())
    assert c["/usr/local/bin/new"]["evidence"]["configured"] == [
        "process_crypto_linkage.groups[0].go"
    ]
    assert "go" in c["/usr/local/bin/new"]["crypto_families"]


def test_counts_order_and_omitted_groups() -> None:
    raw = _with_processes(
        _host(True),
        [
            _group("/usr/bin/a", [_OPENSSL_11], client=3),
            _group("/usr/bin/b", [_OPENSSL_35], client=5),
            _group("/usr/bin/c", [_OPENSSL_35], client=1),
        ],
    )
    raw["process_crypto_linkage"]["omitted_groups"] = 4
    c = _clients(raw)
    assert [i["exe"] for i in c["items"]] == ["/usr/bin/b", "/usr/bin/c", "/usr/bin/a"]
    assert c["by_state"] == {"configured_not_capable": 1, "deployed": 2}
    assert c["client_processes_by_state"] == {
        "configured_not_capable": 3,
        "deployed": 6,
    }
    assert c["differing_from_host"] == 1
    assert c["groups_omitted_by_scan"] == 4


# ---------------------------------------------------------------------------
# gaps, pqc-020, rollup
# ---------------------------------------------------------------------------


def _report(raw: dict[str, Any]) -> pr.Report:
    r = pr.Report(**raw)
    r.pqc_deployment_gap = gap.compute_gap(asdict(r))
    return r


def test_differing_client_gaps_are_listed() -> None:
    raw = _with_processes(
        _host(False),
        [
            _group("/usr/bin/curl", [_OPENSSL_35]),
            _group("/usr/local/bin/reverted", [], go=_go("go1.26.1", ["tlsmlkem"])),
        ],
    )
    gaps = gap.compute_gap(raw)["gaps"]
    assert "client:/usr/local/bin/reverted:capable_not_configured" in gaps
    # curl only restates the host's TLS gap.
    assert not any(g.startswith("client:/usr/bin/curl") for g in gaps)


def test_pqc020_lists_differing_clients_as_a_warning() -> None:
    raw = _with_processes(
        _host(True),
        [_group("/usr/local/bin/reverted", [], go=_go("go1.26.1", ["tlsmlkem"]))],
    )
    (f,) = [
        x
        for x in sarif.build_findings(_report(raw))
        if x.rule_id == "pqc-020-pqc-capable-not-configured"
    ]
    assert f.level == "warning"
    assert f.properties["gap:clients"] == ["/usr/local/bin/reverted"]
    assert "clients: /usr/local/bin/reverted" in f.message


def test_rollup_counts_client_groups_and_processes() -> None:
    rocky = _with_processes(
        _host(False),
        [
            _group("/usr/bin/curl", [_OPENSSL_35], client=2),
            _group("/opt/legacy/agent", [_OPENSSL_11], client=1),
        ],
    )
    fedora = _with_processes(_host(True), [_group("/usr/bin/curl", [_OPENSSL_35])])
    rollup = aggregate.aggregate_reports([rocky, fedora, _host(True)])
    g = rollup["pqc_deployment_gap"]
    assert g["client_groups_by_state"] == {
        "capable_not_configured": 1,
        "deployed": 1,
        "not_capable": 1,
    }
    assert g["client_processes_by_state"] == {
        "capable_not_configured": 2,
        "deployed": 1,
        "not_capable": 1,
    }
    rows = list(csv.reader(io.StringIO(aggregate.aggregate_to_csv(rollup))))
    assert ["pqc_deployment_gap_client_groups", "not_capable", "1"] in rows
    assert [
        "pqc_deployment_gap_client_processes",
        "capable_not_configured",
        "2",
    ] in rows
