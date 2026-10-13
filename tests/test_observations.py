# SPDX-License-Identifier: Apache-2.0
"""Endpoint-observation ingestion and join (#149)."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any

import pytest

import pqc_readiness as pr
from pqc_readiness import aggregate as agg
from pqc_readiness import observations as obs

SCHEMA = (
    Path(__file__).resolve().parent.parent
    / "docs"
    / "schemas"
    / ("endpoint-observation-1.0.schema.json")
)
REPORT_TIME = "2026-10-13T12:00:00+00:00"


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------


def _listener(
    port: int,
    *,
    protocol: str = "tcp",
    address: str = "0.0.0.0",
    bind_scope: str = "any",
    netns: str = "host",
    process: str = "httpd",
    family: str = "openssl",
    pqc_capable: bool | None = True,
    go: dict[str, Any] | None = None,
) -> dict[str, Any]:
    libs = (
        []
        if family == "none"
        else [
            {
                "family": family,
                "path": "/usr/lib64/libssl.so.3",
                "version": "3.5.5",
                "version_source": "embedded",
                "deleted": False,
                "library_pqc_capable": pqc_capable,
            }
        ]
    )
    return {
        "protocol": protocol,
        "family": "ipv6" if ":" in address else "ipv4",
        "address": address,
        "port": port,
        "bind_scope": bind_scope,
        "network_namespace": netns,
        "pid": 100,
        "pids": [100],
        "process": process,
        "exe": f"/usr/sbin/{process}",
        "systemd_unit": f"{process}.service",
        "cgroup": f"/system.slice/{process}.service",
        "crypto_libraries": libs,
        "static_binary": go is not None,
        "go": go,
    }


def _report(
    hostname: str,
    listeners: list[dict[str, Any]] | None,
    *,
    certs: list[str] = (),  # type: ignore[assignment]
    tls_policy: bool | None = True,
    ssh_kex: dict[str, list[str]] | None = None,
    generated_at: str = REPORT_TIME,
) -> dict[str, Any]:
    r: dict[str, Any] = {
        "schema_version": pr.SCHEMA_VERSION,
        "generated_at": generated_at,
        "hostname": hostname,
        "arch": "x86_64",
        "isa_tier": "good",
        "verdict": "GOOD - production-capable in software",
        "service_crypto_linkage": (
            {}
            if listeners is None
            else {"available": True, "listeners": listeners, "summary": {}}
        ),
        "crypto_material": {
            "available": True,
            "certificates": [{"sha256": c, "role": "leaf"} for c in certs],
        },
        "crypto_policy": {
            "available": True,
            "pqc_enabled": {"tls_key_exchange": tls_policy},
        },
        "ssh_pqc": {"available": True, "kex_groups": ssh_kex or {}},
    }
    return r


def _record(**kw: Any) -> dict[str, Any]:
    rec: dict[str, Any] = {
        "observed_at": "2026-10-13T11:00:00Z",
        "protocol": "tls",
        "port": 443,
        "negotiated_group": "X25519MLKEM768",
        "source": {"category": "active-endpoint-scan", "name": "adapter-test"},
    }
    rec.update(kw)
    return rec


def _run(
    tmp_path: Path,
    reports: list[dict[str, Any]],
    records: list[dict[str, Any]],
    *,
    output: str = "json",
    max_age: float = obs.DEFAULT_MAX_AGE_DAYS,
) -> Any:
    d = tmp_path / "fleet"
    d.mkdir(exist_ok=True)
    for i, r in enumerate(reports):
        (d / f"host{i}.json").write_text(json.dumps(r))
    f = tmp_path / "obs.json"
    f.write_text(
        json.dumps({"observation_schema_version": "1.0", "observations": records})
    )
    body, code = agg.run_aggregator(
        d, output=output, observations=f, observations_max_age_days=max_age
    )
    assert code == 0
    return body if output == "csv" else json.loads(body)["observations"]


# ---------------------------------------------------------------------------
# Join: tiers, listeners, ambiguity
# ---------------------------------------------------------------------------


def test_fqdn_match_attributes_listener_and_states(tmp_path: Path) -> None:
    hosts = [_report("web01.example.com", [_listener(443)])]
    out = _run(
        tmp_path, hosts, [_record(fqdn="web01.example.com", negotiated_group="x25519")]
    )
    (m,) = out["matches"]
    assert m["status"] == "matched"
    assert m["match_basis"] == "fqdn"
    assert m["host"] == "web01.example.com"
    assert m["listener"]["process"] == "httpd"
    assert m["listener"]["crypto_families"] == ["openssl"]
    assert m["observed_class"] == "classical"
    assert (m["capable"], m["configured"]) == (True, True)
    assert out["per_host"]["web01.example.com"]["capable_but_observed_classical"] == 1
    assert out["states"] == [
        {"capable": "yes", "configured": "yes", "observed": "classical", "endpoints": 1}
    ]


def test_fqdn_match_is_case_and_trailing_dot_insensitive(tmp_path: Path) -> None:
    out = _run(
        tmp_path,
        [_report("Web01.Example.com", [_listener(443)])],
        [_record(fqdn="WEB01.example.com.")],
    )
    assert out["matches"][0]["status"] == "matched"


def test_sni_matches_when_fqdn_is_a_load_balancer_name(tmp_path: Path) -> None:
    out = _run(
        tmp_path,
        [_report("app02.example.com", [_listener(8443)])],
        [_record(fqdn="lb.example.com", sni="app02.example.com", port=8443)],
    )
    (m,) = out["matches"]
    assert (m["status"], m["match_basis"]) == ("matched", "sni")


def test_ip_matches_a_specific_ipv6_bind(tmp_path: Path) -> None:
    listener = _listener(443, address="2001:db8::10", bind_scope="specific")
    out = _run(
        tmp_path,
        [_report("v6host", [listener])],
        [_record(ip="2001:DB8:0:0::10")],
    )
    (m,) = out["matches"]
    assert (m["status"], m["match_basis"]) == ("matched", "ip")


def test_ipv4_mapped_ipv6_observation_matches_ipv4_bind(tmp_path: Path) -> None:
    listener = _listener(443, address="192.0.2.7", bind_scope="specific")
    out = _run(
        tmp_path, [_report("v4host", [listener])], [_record(ip="::ffff:192.0.2.7")]
    )
    assert out["matches"][0]["match_basis"] == "ip"


def test_ip_cannot_identify_a_host_with_only_wildcard_binds(tmp_path: Path) -> None:
    # The report carries no interface addresses, so a wildcard bind gives
    # no IP to match; the record needs a name (documented limitation).
    out = _run(tmp_path, [_report("h", [_listener(443)])], [_record(ip="192.0.2.9")])
    assert out["matches"][0]["status"] == "unmatched_host"


def test_specific_bind_on_another_address_does_not_match(tmp_path: Path) -> None:
    listeners = [
        _listener(443, address="192.0.2.7", bind_scope="specific"),
        _listener(8443, address="192.0.2.8", bind_scope="specific"),
    ]
    out = _run(tmp_path, [_report("h", listeners)], [_record(ip="192.0.2.8", port=443)])
    assert out["matches"][0]["status"] == "unmatched_listener"


def test_short_name_matches_a_short_hostname(tmp_path: Path) -> None:
    out = _run(
        tmp_path,
        [_report("db03", [_listener(5432, process="postgres")])],
        [_record(fqdn="db03.corp.example", port=5432)],
    )
    (m,) = out["matches"]
    assert (m["match_basis"], m["listener"]["process"]) == ("short-name", "postgres")


def test_duplicate_hostnames_are_ambiguous(tmp_path: Path) -> None:
    hosts = [_report("web01", [_listener(443)]), _report("web01", [_listener(443)])]
    out = _run(tmp_path, hosts, [_record(fqdn="web01")])
    (m,) = out["matches"]
    assert m["status"] == "ambiguous"
    assert m["candidates"] == ["web01", "web01"]
    assert m["host"] is None
    assert out["per_host"] == {}


def test_certificate_breaks_a_name_tie(tmp_path: Path) -> None:
    fp = "ab" * 32
    hosts = [
        _report("web01", [_listener(443)], certs=[fp]),
        _report("web01", [_listener(443)], certs=["cd" * 32]),
    ]
    out = _run(tmp_path, hosts, [_record(fqdn="web01", certificate_sha256=fp.upper())])
    (m,) = out["matches"]
    assert (m["status"], m["match_basis"], m["certificate_on_host"]) == (
        "matched",
        "fqdn+certificate",
        True,
    )


def test_certificate_alone_identifies_the_host(tmp_path: Path) -> None:
    fp = "ef" * 32
    out = _run(
        tmp_path,
        [
            _report("edge-1", [_listener(443)], certs=[fp]),
            _report("edge-2", [_listener(443)]),
        ],
        [_record(fqdn="www.example.com", certificate_sha256=fp)],
    )
    (m,) = out["matches"]
    assert (m["host"], m["match_basis"]) == ("edge-1", "certificate")


def test_certificate_mismatch_is_reported_on_a_name_match(tmp_path: Path) -> None:
    out = _run(
        tmp_path,
        [_report("web01.example.com", [_listener(443)], certs=["11" * 32])],
        [_record(fqdn="web01.example.com", certificate_sha256="22" * 32)],
    )
    assert out["matches"][0]["certificate_on_host"] is False


def test_unmatched_host(tmp_path: Path) -> None:
    out = _run(
        tmp_path,
        [_report("a.example.com", [_listener(443)])],
        [_record(fqdn="b.example.com")],
    )
    assert out["matches"][0]["status"] == "unmatched_host"
    assert out["by_status"] == {"unmatched_host": 1}


def test_loopback_listener_is_not_reachable(tmp_path: Path) -> None:
    listener = _listener(443, address="127.0.0.1", bind_scope="loopback")
    out = _run(
        tmp_path, [_report("h.example", [listener])], [_record(fqdn="h.example")]
    )
    assert out["matches"][0]["status"] == "unmatched_listener"


def test_udp_protocol_needs_a_udp_listener(tmp_path: Path) -> None:
    hosts = [
        _report(
            "q.example",
            [_listener(443), _listener(443, protocol="udp", process="h3srv")],
        )
    ]
    out = _run(tmp_path, hosts, [_record(fqdn="q.example", protocol="quic")])
    assert out["matches"][0]["listener"]["process"] == "h3srv"


def test_listener_in_another_namespace_matches_with_note(tmp_path: Path) -> None:
    listener = _listener(8443, netns="other", process="podman-app")
    out = _run(
        tmp_path,
        [_report("c.example", [listener])],
        [_record(fqdn="c.example", port=8443)],
    )
    (m,) = out["matches"]
    assert m["status"] == "matched"
    assert "port mapping" in m["note"]


def test_host_without_service_scan(tmp_path: Path) -> None:
    out = _run(tmp_path, [_report("n.example", None)], [_record(fqdn="n.example")])
    (m,) = out["matches"]
    assert m["status"] == "no_service_scan"
    assert m["capable"] is None and m["configured"] is True
    assert out["per_host"]["n.example"]["endpoints"] == 1


def test_ssh_uses_host_level_capability(tmp_path: Path) -> None:
    hosts = [
        _report(
            "s.example",
            [_listener(22, process="sshd")],
            ssh_kex={
                "hybrid": ["mlkem768x25519-sha256"],
                "classical": ["curve25519-sha256"],
            },
        )
    ]
    out = _run(
        tmp_path,
        hosts,
        [
            _record(
                fqdn="s.example",
                protocol="ssh",
                port=22,
                negotiated_group="curve25519-sha256",
            )
        ],
    )
    (m,) = out["matches"]
    assert (m["observed_class"], m["capable"], m["configured"]) == (
        "classical",
        True,
        None,
    )


def test_go_listener_default_hybrid_counts_as_capable_and_configured(
    tmp_path: Path,
) -> None:
    go = {
        "go_version": "go1.24.4",
        "default_hybrid_kex": "X25519MLKEM768",
        "godebug_reverts": [],
    }
    listener = _listener(9000, family="none", process="gosrv", go=go)
    out = _run(
        tmp_path,
        [_report("g.example", [listener], tls_policy=False)],
        [_record(fqdn="g.example", port=9000)],
    )
    (m,) = out["matches"]
    assert (m["capable"], m["configured"], m["observed_class"]) == (
        True,
        True,
        "hybrid",
    )


def test_go_godebug_revert_turns_capability_off(tmp_path: Path) -> None:
    go = {
        "go_version": "go1.24.4",
        "default_hybrid_kex": "X25519MLKEM768",
        "godebug_reverts": ["tlsmlkem"],
    }
    listener = _listener(9000, family="none", process="gosrv", go=go)
    out = _run(
        tmp_path,
        [_report("g.example", [listener])],
        [_record(fqdn="g.example", port=9000, negotiated_group="x25519")],
    )
    assert out["matches"][0]["capable"] is False


# ---------------------------------------------------------------------------
# Staleness
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("observed_at", "max_age", "stale"),
    [
        ("2026-10-13T11:00:00Z", 7.0, False),
        ("2026-09-01T00:00:00Z", 7.0, True),
        ("2026-10-20T13:00:00+00:00", 7.0, True),  # after the report, too
        ("2026-10-11T12:00:00+00:00", 1.0, True),
        ("2026-10-11T12:00:00+02:00", 3.0, False),
    ],
)
def test_staleness(
    tmp_path: Path, observed_at: str, max_age: float, stale: bool
) -> None:
    out = _run(
        tmp_path,
        [_report("h.example", [_listener(443)])],
        [_record(fqdn="h.example", observed_at=observed_at)],
        max_age=max_age,
    )
    assert out["matches"][0]["stale"] is stale
    assert out["stale"] == int(stale)


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("rec", "canonical", "cls"),
    [
        (
            {"protocol": "tls", "negotiated_group": "X25519MLKEM768"},
            "X25519MLKEM768",
            "hybrid",
        ),
        ({"protocol": "tls", "negotiated_group": "0x11EC"}, "X25519MLKEM768", "hybrid"),
        ({"protocol": "tls", "negotiated_group": "4588"}, "X25519MLKEM768", "hybrid"),
        (
            {"protocol": "tls", "negotiated_group": "x25519_mlkem768"},
            "X25519MLKEM768",
            "hybrid",
        ),
        ({"protocol": "tls", "negotiated_group": "0x0202"}, "MLKEM1024", "pure_pqc"),
        ({"protocol": "quic", "negotiated_group": "0x001d"}, "x25519", "classical"),
        ({"protocol": "tls", "negotiated_group": "P-256"}, "secp256r1", "classical"),
        (
            {"protocol": "dtls", "negotiated_group": "ffdhe2048"},
            "ffdhe2048",
            "classical",
        ),
        (
            {"protocol": "tls", "negotiated_group": "FutureGroup9"},
            "FutureGroup9",
            "unknown",
        ),
        ({"protocol": "tls"}, None, "unknown"),
        (
            {"protocol": "ssh", "negotiated_group": "mlkem768x25519-sha256"},
            "mlkem768x25519-sha256",
            "hybrid",
        ),
        (
            {"protocol": "ssh", "negotiated_group": "ecdh-sha2-nistp256"},
            "ecdh-sha2-nistp256",
            "classical",
        ),
        (
            {
                "protocol": "ikev2",
                "negotiated_group": "ecp256",
                "additional_key_exchanges": ["mlkem768"],
            },
            "ecp256+mlkem768",
            "hybrid",
        ),
        (
            {"protocol": "ikev2", "negotiated_group": "curve25519"},
            "curve25519",
            "classical",
        ),
        (
            {"protocol": "ikev2", "negotiated_group": "mlkem1024"},
            "mlkem1024",
            "pure_pqc",
        ),
    ],
)
def test_classify_observed(
    rec: dict[str, Any], canonical: str | None, cls: str
) -> None:
    assert obs.classify_observed(rec) == (canonical, cls)


# ---------------------------------------------------------------------------
# Validation and file formats
# ---------------------------------------------------------------------------

VALID = _record(observation_schema_version="1.0", fqdn="h.example")

INVALID_CASES = [
    ({**VALID, "source": None}, "source object is required"),
    ({**VALID, "port": 0}, "port must be"),
    ({**VALID, "port": True}, "port must be"),
    ({**VALID, "observed_at": "2026-10-13T11:00:00"}, "observed_at"),
    ({**VALID, "protocol": "smtp"}, "protocol must be"),
    ({**VALID, "transport": "udp"}, "does not carry tls"),
    ({k: v for k, v in VALID.items() if k != "fqdn"}, "fqdn or ip"),
    ({**VALID, "fqdn": "bad name!"}, "fqdn is not a DNS name"),
    ({**VALID, "ip": "999.1.1.1"}, "ip is not"),
    ({**VALID, "certificate_sha256": "abc"}, "certificate_sha256"),
    ({**VALID, "colour": "red"}, "unknown keys: colour"),
    ({**VALID, "source": {"category": "rumour"}}, "source.category"),
    ({**VALID, "observation_schema_version": "2.0"}, "unsupported"),
    ({**VALID, "observation_schema_version": "1"}, "MAJOR.MINOR"),
    ({**VALID, "offered_groups": ["x25519", ""]}, "offered_groups"),
]


@pytest.mark.parametrize(("rec", "message"), INVALID_CASES)
def test_invalid_records(rec: dict[str, Any], message: str) -> None:
    problems = obs.validate_record(rec)
    assert any(message in p for p in problems), problems


def test_valid_record_and_extensions() -> None:
    assert obs.validate_record(VALID) == []
    assert (
        obs.validate_record(
            {
                **VALID,
                "x-scanner-run": "42",
                "source": {"category": "manual", "x-note": "n"},
            }
        )
        == []
    )


def test_newer_minor_version_unknown_keys_are_ignored() -> None:
    assert (
        obs.validate_record(
            {**VALID, "observation_schema_version": "1.3", "alpn": "h2"}
        )
        == []
    )


def test_invalid_records_are_listed_not_fatal(tmp_path: Path) -> None:
    records = [_record(fqdn="h.example"), {**_record(fqdn="h.example"), "port": "443"}]
    out = _run(tmp_path, [_report("h.example", [_listener(443)])], records)
    assert (out["total"], out["valid"]) == (2, 1)
    assert out["invalid"] == [
        {"record": 2, "reason": "port must be an integer 1-65535"}
    ]
    assert out["matches"][0]["record"] == 1


def test_jsonl_file_with_blank_and_broken_lines(tmp_path: Path) -> None:
    f = tmp_path / "obs.jsonl"
    lines = [
        json.dumps({**VALID, "id": "a"}),
        "",
        "{not json",
        json.dumps(
            {k: v for k, v in VALID.items() if k != "observation_schema_version"}
        ),
    ]
    f.write_text("\n".join(lines) + "\n")
    loaded = obs.load_observations(f)
    assert loaded.file_format == "jsonl"
    assert [r["id"] for r in loaded.records] == ["a"]
    assert [i["record"] for i in loaded.invalid] == [3, 4]
    assert "observation_schema_version" in loaded.invalid[1]["reason"]


@pytest.mark.parametrize(
    "text",
    [
        '{"observation_schema_version": "2.0", "observations": []}',
        '{"observation_schema_version": "1.0", "observations": {}}',
    ],
)
def test_unusable_envelope_raises(tmp_path: Path, text: str) -> None:
    f = tmp_path / "obs.json"
    f.write_text(text)
    with pytest.raises(obs.ObservationFileError):
        obs.load_observations(f)


def test_unreadable_file_raises(tmp_path: Path) -> None:
    with pytest.raises(obs.ObservationFileError):
        obs.load_observations(tmp_path / "missing.json")


# ---------------------------------------------------------------------------
# JSON Schema agreement (structural cases; format checks need extra deps)
# ---------------------------------------------------------------------------


def _schema_validator() -> Any:
    jsonschema = pytest.importorskip("jsonschema")
    if not SCHEMA.exists():
        pytest.skip("docs/ not present in this image")
    return jsonschema.Draft202012Validator(json.loads(SCHEMA.read_text()))


AGREEMENT_CASES = [VALID, {**VALID, "x-ext": 1}] + [
    rec
    for rec, msg in INVALID_CASES
    if msg
    not in ("observed_at", "does not carry tls", "fqdn is not a DNS name", "ip is not")
    and rec.get("observation_schema_version") in ("1.0", "2.0", "1")
]


@pytest.mark.parametrize("rec", AGREEMENT_CASES)
def test_python_validator_agrees_with_json_schema(rec: dict[str, Any]) -> None:
    validator = _schema_validator()
    assert validator.is_valid(rec) == (obs.validate_record(rec) == [])


def test_envelope_validates_against_json_schema() -> None:
    validator = _schema_validator()
    record = {k: v for k, v in VALID.items() if k != "observation_schema_version"}
    assert validator.is_valid(
        {"observation_schema_version": "1.0", "observations": [record]}
    )
    assert not validator.is_valid(
        {"observation_schema_version": "1.0", "observations": [{}]}
    )


# ---------------------------------------------------------------------------
# Rollup, CSV and CLI
# ---------------------------------------------------------------------------


def test_rollup_counts_and_per_host(tmp_path: Path) -> None:
    hosts = [
        _report("a.example", [_listener(443), _listener(8443, pqc_capable=False)]),
        _report("b.example", [_listener(443)], tls_policy=False),
    ]
    records = [
        _record(fqdn="a.example", negotiated_group="X25519MLKEM768"),
        _record(fqdn="a.example", port=8443, negotiated_group="x25519"),
        _record(fqdn="b.example", negotiated_group="x25519"),
        _record(fqdn="c.example"),
    ]
    out = _run(tmp_path, hosts, records)
    assert out["by_status"] == {"matched": 3, "unmatched_host": 1}
    assert out["by_observed_class"] == {"classical": 2, "hybrid": 2}
    assert out["per_host"]["a.example"]["by_observed_class"] == {
        "hybrid": 1,
        "classical": 1,
    }
    assert out["per_host"]["b.example"]["capable_but_observed_classical"] == 1
    assert out["per_host"]["b.example"]["configured_but_observed_classical"] == 0
    assert {(s["capable"], s["configured"], s["observed"]) for s in out["states"]} == {
        ("yes", "yes", "hybrid"),
        ("no", "yes", "classical"),
        ("yes", "no", "classical"),
    }


def test_rollup_without_observations_is_unchanged(tmp_path: Path) -> None:
    d = tmp_path / "fleet"
    d.mkdir()
    (d / "h.json").write_text(json.dumps(_report("h", [_listener(443)])))
    rollup = json.loads(agg.run_aggregator(d)[0])
    assert "observations" not in rollup


def test_csv_rows(tmp_path: Path) -> None:
    body = _run(
        tmp_path,
        [_report("a.example", [_listener(443)])],
        [_record(fqdn="a.example")],
        output="csv",
    )
    rows = list(csv.reader(io.StringIO(body)))
    assert ["observations_by_status", "matched", "1"] in rows
    assert [
        "observations_states",
        "capable=yes;configured=yes;observed=hybrid",
        "1",
    ] in rows


def test_cli_observations_requires_aggregate(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    f = tmp_path / "obs.json"
    f.write_text("{}")
    assert pr.main(["--observations", str(f)]) == 2
    assert "requires --aggregate" in capsys.readouterr().err


def test_cli_bad_observations_file_exits_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    d = tmp_path / "fleet"
    d.mkdir()
    f = tmp_path / "obs.json"
    f.write_text('{"observation_schema_version": "9.0", "observations": []}')
    assert pr.main(["--aggregate", str(d), "--observations", str(f)]) == 2
    assert "unsupported" in capsys.readouterr().err


def test_cli_end_to_end(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    d = tmp_path / "fleet"
    d.mkdir()
    (d / "h.json").write_text(json.dumps(_report("h.example", [_listener(443)])))
    f = tmp_path / "obs.jsonl"
    f.write_text(json.dumps({**VALID, "fqdn": "h.example"}) + "\n")
    rc = pr.main(
        [
            "--aggregate",
            str(d),
            "--observations",
            str(f),
            "--observations-max-age-days",
            "1",
        ]
    )
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["observations"]["max_age_days"] == 1.0
    assert out["observations"]["by_status"] == {"matched": 1}


def test_jsonl_bare_carriage_return_is_one_bad_record(tmp_path: Path) -> None:
    # Found validating #107 on real VMs: `ssh -vv` output captured with a
    # trailing \r put a raw carriage return inside a JSON string.  The
    # record is invalid, but it is ONE record on line 2; splitlines()
    # used to split it in two and shift every later line number.
    good = json.dumps(_record(observation_schema_version="1.0", fqdn="a.example"))
    bad = good.replace("X25519MLKEM768", "X25519MLKEM768\r")
    f = tmp_path / "obs.jsonl"
    f.write_text("\n".join([good, bad, good]) + "\n", newline="")
    loaded = obs.load_observations(f)
    assert len(loaded.records) == 2
    assert [i["record"] for i in loaded.invalid] == [2]


def test_jsonl_crlf_line_endings_still_load(tmp_path: Path) -> None:
    good = json.dumps(_record(observation_schema_version="1.0", fqdn="a.example"))
    f = tmp_path / "obs.jsonl"
    f.write_bytes(("\r\n".join([good, good]) + "\r\n").encode())
    loaded = obs.load_observations(f)
    assert len(loaded.records) == 2
    assert loaded.invalid == []
