# SPDX-License-Identifier: Apache-2.0
"""Capability vs configuration verdict (#107)."""

from __future__ import annotations

import csv
import io
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

import pytest

import pqc_readiness as pr
from pqc_readiness import aggregate, gap, observations
from pqc_readiness.render import sarif

# ---------------------------------------------------------------------------
# Report builders: shapes taken from real scans (Rocky 9.8 DEFAULT, Fedora 44)
# ---------------------------------------------------------------------------


def _openssl(hybrid: bool = True) -> dict[str, Any]:
    return {
        "available": True,
        "pqc_native": hybrid,
        "tls_groups": {
            "hybrid": ["X25519MLKEM768"] if hybrid else [],
            "pure_pqc": [],
            "classical": ["X25519"],
        },
        "config": {"available": True, "pqc_key_exchange_by_default": hybrid},
    }


def _rocky98_default() -> dict[str, Any]:
    """OpenSSL / OpenSSH can do PQC; DEFAULT policy keeps both classical."""
    return {
        "hostname": "rocky98.example",
        "openssl": _openssl(True),
        "crypto_policy": {
            "available": True,
            "pqc_enabled": {
                "tls_key_exchange": False,
                "ssh_key_exchange_server": False,
                "ike_key_exchange": False,
            },
        },
        "ssh_pqc": {
            "available": True,
            "kex_groups": {
                "hybrid": ["mlkem768x25519-sha256"],
                "pure_pqc": [],
                "classical": [],
            },
        },
        "sshd": {
            "available": True,
            "pqc_offered": False,
            "pqc_first": False,
            "first_kex": "curve25519-sha256",
            "openssh_supports_pqc_kex": True,
        },
        "ipsec_pqc": {"available": False},
    }


def _fedora44() -> dict[str, Any]:
    r = _rocky98_default()
    r["hostname"] = "fedora44.example"
    r["crypto_policy"]["pqc_enabled"].update(
        tls_key_exchange=True, ssh_key_exchange_server=True
    )
    r["sshd"].update(
        pqc_offered=True, pqc_first=True, first_kex="mlkem768x25519-sha256"
    )
    return r


def _listener(
    process: str, port: int, libs: list[dict[str, Any]], **kw: Any
) -> dict[str, Any]:
    base = {
        "protocol": "tcp",
        "address": "0.0.0.0",
        "port": port,
        "bind_scope": "any",
        "network_namespace": "host",
        "pid": 100 + port,
        "process": process,
        "exe": f"/usr/sbin/{process}",
        "systemd_unit": f"{process}.service",
        "crypto_libraries": libs,
        "go": None,
    }
    base.update(kw)
    return base


_OPENSSL_35 = {"family": "openssl", "version": "3.5.5", "library_pqc_capable": True}
_OPENSSL_30 = {"family": "openssl", "version": "3.0.7", "library_pqc_capable": False}


# ---------------------------------------------------------------------------
# State matrix
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("capable", "configured", "state"),
    [
        (True, True, "deployed"),
        (True, False, "capable_not_configured"),
        (True, None, "unknown"),
        (False, True, "configured_not_capable"),
        (False, False, "not_capable"),
        (False, None, "not_capable"),
        (None, True, "unknown"),
        (None, False, "unknown"),
        (None, None, "unknown"),
    ],
)
def test_classify_matrix(
    capable: bool | None, configured: bool | None, state: str
) -> None:
    assert gap.classify(capable, configured) == state


def test_states_are_documented_constants() -> None:
    assert set(gap.STATES) == {
        "deployed",
        "capable_not_configured",
        "configured_not_capable",
        "not_capable",
        "unknown",
        "not_present",
    }


# ---------------------------------------------------------------------------
# Protocol verdicts
# ---------------------------------------------------------------------------


def test_rocky98_default_is_capable_not_configured_for_tls_and_ssh() -> None:
    g = gap.compute_gap(_rocky98_default())
    tls, ssh, ipsec = (g["protocols"][p] for p in ("tls", "ssh", "ipsec"))
    assert tls["state"] == "capable_not_configured"
    assert tls["evidence"] == {
        "capable": ["openssl.tls_groups"],
        "configured": ["crypto_policy.pqc_enabled.tls_key_exchange"],
    }
    assert ssh["state"] == "capable_not_configured"
    assert ssh["evidence"]["capable"] == ["sshd.openssh_supports_pqc_kex"]
    assert ssh["evidence"]["configured"] == ["sshd.pqc_offered"]
    assert ipsec == {
        "state": "not_present",
        "capable": None,
        "configured": None,
        "evidence": {"capable": [], "configured": []},
    }
    assert g["gaps"] == ["tls:capable_not_configured", "ssh:capable_not_configured"]


def test_fedora44_is_deployed() -> None:
    g = gap.compute_gap(_fedora44())
    assert g["protocols"]["tls"]["state"] == "deployed"
    assert g["protocols"]["ssh"]["state"] == "deployed"
    assert g["gaps"] == []


def test_ssh_offered_but_not_first_is_deployed_with_note() -> None:
    r = _fedora44()
    r["sshd"].update(pqc_first=False, first_kex="curve25519-sha256")
    ssh = gap.compute_gap(r)["protocols"]["ssh"]
    assert ssh["state"] == "deployed"
    assert "curve25519-sha256 is preferred first" in ssh["note"]


def test_openssl_30_with_permissive_policy_is_not_capable() -> None:
    r = _fedora44()
    r["openssl"] = _openssl(False)
    assert gap.compute_gap(r)["protocols"]["tls"]["state"] == "configured_not_capable"


def test_tls_configured_falls_back_to_openssl_config_without_policy() -> None:
    # Debian / Ubuntu: no crypto-policies framework.
    r = _fedora44()
    r["crypto_policy"] = {"available": False}
    tls = gap.compute_gap(r)["protocols"]["tls"]
    assert tls["state"] == "deployed"
    assert tls["evidence"]["configured"] == [
        "openssl.config.pqc_key_exchange_by_default"
    ]


def test_ssh_falls_back_to_client_kex_and_policy_without_sshd() -> None:
    r = _rocky98_default()
    r["sshd"] = {"available": False}
    ssh = gap.compute_gap(r)["protocols"]["ssh"]
    assert ssh["state"] == "capable_not_configured"
    assert ssh["evidence"] == {
        "capable": ["ssh_pqc.kex_groups"],
        "configured": ["crypto_policy.pqc_enabled.ssh_key_exchange_server"],
    }


def test_offline_tree_uses_packaged_openssl_version() -> None:
    r = {
        "openssl": {"available": False, "pqc_native_expected": True, "config": {}},
        "crypto_policy": {
            "available": True,
            "pqc_enabled": {"tls_key_exchange": False},
        },
    }
    tls = gap.compute_gap(r)["protocols"]["tls"]
    assert tls["state"] == "capable_not_configured"
    assert tls["evidence"]["capable"] == ["openssl.pqc_native_expected"]


@pytest.mark.parametrize(
    ("pqc", "offering", "state"),
    [
        (True, 1, "deployed"),
        (True, 0, "capable_not_configured"),
        (False, 1, "configured_not_capable"),
        (False, 0, "not_capable"),
    ],
)
def test_ipsec_from_configured_proposals(pqc: bool, offering: int, state: str) -> None:
    r = _fedora44()
    r["ipsec_pqc"] = {
        "available": True,
        "pqc": pqc,
        "configured": {
            "summary": {"connections": 2, "connections_offering_pqc": offering}
        },
    }
    if state == "configured_not_capable":
        r["ipsec_pqc"]["configured"]["capability_mismatch"] = {
            "connections": ["site-a"]
        }
    v = gap.compute_gap(r)["protocols"]["ipsec"]
    assert v["state"] == state
    assert v["evidence"]["configured"] == [
        "ipsec_pqc.configured.summary.connections_offering_pqc"
    ]
    if state == "configured_not_capable":
        assert "site-a" in v["note"]


def test_missing_evidence_is_unknown_not_a_gap() -> None:
    g = gap.compute_gap(
        {"openssl": {"available": True}, "ssh_pqc": {"available": True}}
    )
    assert g["protocols"]["tls"]["state"] == "unknown"
    assert g["protocols"]["ssh"]["state"] == "unknown"
    assert g["gaps"] == []


# ---------------------------------------------------------------------------
# Services
# ---------------------------------------------------------------------------


def _with_services(
    r: dict[str, Any], listeners: list[dict[str, Any]]
) -> dict[str, Any]:
    r["service_crypto_linkage"] = {"available": True, "listeners": listeners}
    return r


def test_services_without_scan_are_unavailable() -> None:
    assert gap.compute_gap(_fedora44())["services"] == {"available": False}


def test_service_verdicts_and_collapsing() -> None:
    r = _with_services(
        _rocky98_default(),
        [
            _listener("httpd", 443, [_OPENSSL_35]),
            _listener("httpd", 443, [_OPENSSL_35], family="ipv6", address="::"),
            _listener("legacyd", 8443, [_OPENSSL_30]),
            _listener("sshd", 22, [_OPENSSL_35]),
            _listener("chronyd", 323, []),
            _listener(None, 9999, [], pid=None),  # type: ignore[arg-type]
        ],
    )
    svc = gap.compute_gap(r)["services"]
    items = {(s["process"], s["port"]): s for s in svc["items"]}
    assert items[("httpd", 443)]["state"] == "capable_not_configured"
    assert len(items[("httpd", 443)]["listeners"]) == 2  # IPv4 + IPv6 collapsed
    assert items[("legacyd", 8443)]["state"] == "not_capable"
    # sshd takes the host's SSH verdict.
    assert items[("sshd", 22)]["kind"] == "ssh"
    assert items[("sshd", 22)]["evidence"]["configured"] == ["sshd.pqc_offered"]
    assert svc["listeners_without_crypto_library"] == 1
    assert svc["listeners_unattributed"] == 1
    assert svc["by_state"] == {"capable_not_configured": 2, "not_capable": 1}
    # httpd and sshd only follow the host defaults: not gaps of their own.
    assert items[("httpd", 443)]["follows_host_default"] is True
    assert items[("sshd", 22)]["follows_host_default"] is True
    # legacyd's bundled OpenSSL 3.0 differs from the host's verdict.
    assert items[("legacyd", 8443)]["follows_host_default"] is False
    assert svc["differing_from_host"] == 1
    g = gap.compute_gap(r)
    assert g["gaps"] == ["tls:capable_not_configured", "ssh:capable_not_configured"]


def test_go_service_ignores_system_policy() -> None:
    go_on = {"version": "go1.26.0", "default_hybrid_kex": True, "godebug_reverts": []}
    go_off = {**go_on, "godebug_reverts": ["tlsmlkem"]}
    r = _with_services(
        _rocky98_default(),
        [
            _listener("goapp", 8080, [], go=go_on, exe="/opt/goapp"),
            _listener("goapp-old", 8081, [], go=go_off, exe="/opt/goapp-old"),
        ],
    )
    items = {s["process"]: s for s in gap.compute_gap(r)["services"]["items"]}
    assert items["goapp"]["state"] == "deployed"
    assert items["goapp"]["evidence"]["configured"] == [
        "service_crypto_linkage.listeners[0].go"
    ]
    assert items["goapp-old"]["state"] == "not_capable"


def test_instances_with_different_crypto_stay_separate() -> None:
    r = _with_services(
        _fedora44(),
        [
            _listener("worker", 9000, [_OPENSSL_35], systemd_unit="a.scope"),
            _listener("worker", 9000, [_OPENSSL_30], systemd_unit="b.scope"),
        ],
    )
    states = sorted(s["state"] for s in gap.compute_gap(r)["services"]["items"])
    # The host default wants PQC; the OpenSSL 3.0 instance cannot do it.
    assert states == ["configured_not_capable", "deployed"]


# ---------------------------------------------------------------------------
# Report integration
# ---------------------------------------------------------------------------


def test_gap_for_prefers_the_reports_own_verdict() -> None:
    own = {"protocols": {"tls": {"state": "deployed"}}, "services": {}, "gaps": []}
    assert gap.gap_for({"pqc_deployment_gap": own}) is own
    # Reports written before #107 have none: computed from their fields.
    assert gap.gap_for(_rocky98_default())["protocols"]["tls"]["state"] == (
        "capable_not_configured"
    )


def test_report_dataclass_round_trip() -> None:
    r = pr.Report(**{k: v for k, v in _rocky98_default().items()})
    r.pqc_deployment_gap = gap.compute_gap(asdict(r))
    assert r.pqc_deployment_gap["protocols"]["tls"]["state"] == "capable_not_configured"
    json.dumps(asdict(r))  # serialisable


# ---------------------------------------------------------------------------
# SARIF / NDJSON rule pqc-020
# ---------------------------------------------------------------------------


def _report_with_gap(raw: dict[str, Any]) -> pr.Report:
    r = pr.Report(**raw)
    r.pqc_deployment_gap = gap.compute_gap(asdict(r))
    return r


def _pqc020(r: pr.Report) -> list[sarif.Finding]:
    return [
        f
        for f in sarif.build_findings(r)
        if f.rule_id == "pqc-020-pqc-capable-not-configured"
    ]


def test_pqc020_is_a_note_when_only_tls_ssh_gaps() -> None:
    (f,) = _pqc020(_report_with_gap(_rocky98_default()))
    assert f.level == "note"
    assert f.properties == {"gap:protocols": ["tls", "ssh"], "gap:services": []}


def test_pqc020_is_a_warning_for_services_or_ipsec() -> None:
    # A service following the host default restates the TLS gap: note only.
    raw = _with_services(_rocky98_default(), [_listener("httpd", 443, [_OPENSSL_35])])
    (f,) = _pqc020(_report_with_gap(raw))
    assert (f.level, f.properties["gap:services"]) == ("note", [])
    # An app bundling a PQC-capable OpenSSL on a host whose own OpenSSL
    # can't: the service differs from the host verdict, so it is listed.
    raw = _with_services(_rocky98_default(), [_listener("app", 8443, [_OPENSSL_35])])
    raw["openssl"] = _openssl(False)
    raw["sshd"]["openssh_supports_pqc_kex"] = False
    raw["ssh_pqc"]["kex_groups"] = {"hybrid": [], "pure_pqc": [], "classical": ["x"]}
    (f,) = _pqc020(_report_with_gap(raw))
    assert f.level == "warning"
    assert f.properties == {"gap:protocols": [], "gap:services": ["app tcp/8443"]}

    raw = _fedora44()
    raw["ipsec_pqc"] = {
        "available": True,
        "pqc": True,
        "configured": {"summary": {"connections": 1, "connections_offering_pqc": 0}},
    }
    (f,) = _pqc020(_report_with_gap(raw))
    assert f.level == "warning"
    assert f.properties["gap:protocols"] == ["ipsec"]


def test_pqc020_silent_when_deployed_or_unknown() -> None:
    assert _pqc020(_report_with_gap(_fedora44())) == []
    assert _pqc020(pr.Report()) == []


# ---------------------------------------------------------------------------
# Aggregator
# ---------------------------------------------------------------------------


def test_rollup_counts_states_per_protocol_and_service() -> None:
    rocky = _with_services(_rocky98_default(), [_listener("httpd", 443, [_OPENSSL_35])])
    rollup = aggregate.aggregate_reports([rocky, _fedora44(), _fedora44()])
    g = rollup["pqc_deployment_gap"]
    assert g["hosts_by_protocol_state"]["tls"] == {
        "capable_not_configured": 1,
        "deployed": 2,
    }
    assert g["hosts_by_protocol_state"]["ipsec"] == {"not_present": 3}
    assert g["services_by_state"] == {"capable_not_configured": 1}
    assert g["hosts_with_gap"] == {
        "capable_not_configured": 1,
        "configured_not_capable": 0,
    }
    rows = list(csv.reader(io.StringIO(aggregate.aggregate_to_csv(rollup))))
    assert ["pqc_deployment_gap_tls", "deployed", "2"] in rows
    assert ["pqc_deployment_gap_services", "capable_not_configured", "1"] in rows
    assert ["pqc_deployment_gap_hosts_with", "capable_not_configured", "1"] in rows


def test_rollup_uses_reports_own_verdict_when_present() -> None:
    r = _fedora44()
    r["pqc_deployment_gap"] = {
        "protocols": {p: {"state": "unknown"} for p in gap.PROTOCOLS},
        "services": {"available": False},
        "gaps": [],
    }
    g = aggregate.aggregate_reports([r])["pqc_deployment_gap"]
    assert g["hosts_by_protocol_state"]["tls"] == {"unknown": 1}


def test_observation_join_adds_gap_state(tmp_path: Path) -> None:
    rocky = _with_services(
        _rocky98_default(),
        [_listener("httpd", 443, [_OPENSSL_35]), _listener("sshd", 22, [_OPENSSL_35])],
    )
    rocky["generated_at"] = "2026-10-13T12:00:00+00:00"
    rocky["schema_version"] = pr.SCHEMA_VERSION
    (tmp_path / "rocky.json").write_text(json.dumps(rocky))
    obs = tmp_path / "obs.jsonl"
    common = {
        "observation_schema_version": "1.0",
        "fqdn": "rocky98.example",
        "observed_at": "2026-10-13T12:05:00+00:00",
        "source": {"category": "active-endpoint-scan"},
    }
    obs.write_text(
        "\n".join(
            json.dumps(x)
            for x in (
                {
                    **common,
                    "protocol": "tls",
                    "port": 443,
                    "negotiated_group": "X25519",
                },
                {
                    **common,
                    "protocol": "ssh",
                    "port": 22,
                    "negotiated_group": "curve25519-sha256",
                },
            )
        )
        + "\n"
    )
    out, code = aggregate.run_aggregator(tmp_path, observations=obs)
    assert code == 0
    o = json.loads(out)["observations"]
    states = {(m["protocol"], m["state"]) for m in o["matches"]}
    assert states == {
        ("tls", "capable_not_configured"),
        ("ssh", "capable_not_configured"),
    }
    assert {
        "protocol": "tls",
        "state": "capable_not_configured",
        "observed": "classical",
        "endpoints": 1,
    } in o["by_gap_state"]


def test_observation_judgements_come_from_gap_module() -> None:
    entry = observations._host_entry(_rocky98_default())
    assert (entry.tls_configured, entry.ssh_configured, entry.ssh_capable) == (
        gap.tls_configured(_rocky98_default())[0],
        gap.ssh_configured(_rocky98_default())[0],
        gap.ssh_capable(_rocky98_default())[0],
    )
