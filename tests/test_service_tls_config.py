# SPDX-License-Identifier: Apache-2.0
"""Per-service TLS configuration (--scan-service-configs), #216.

Fixtures are real packaged configs and the exact configs the validation
VMs ran (tests/fixtures/service_tls/README.md).  Each expectation below is
what the daemon actually negotiated with a client offering X25519MLKEM768
on the booted image: True = ML-KEM, False = classical whatever the policy,
None = follows the host's TLS default (crypto policy / openssl.cnf)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import pqc_readiness as pr
from pqc_readiness import gap as _gap
from pqc_readiness.detect import config_services as cs
from pqc_readiness.detect import config_services_parsers as p
from pqc_readiness.render import sarif as _sarif

FIX = Path(__file__).parent / "fixtures" / "service_tls"


def _no_subprocess(cmd, timeout=None):  # noqa: ARG001
    raise AssertionError(f"unexpected subprocess: {cmd}")


def _scan(
    monkeypatch,
    root: Path,
    versions: dict[str, str] | None = None,
    openssl: dict[str, Any] | None = None,
) -> dict[str, Any]:
    monkeypatch.setattr(pr._platform, "HOST_PREFIX", str(root))
    monkeypatch.setattr(pr._platform, "_run", _no_subprocess)
    vers = versions or {}

    def fake_version(spec: dict[str, Any], family: str) -> str | None:
        names = [n for v in spec["packages"].values() for n in v]
        return next((vers[n] for n in names if n in vers), None)

    monkeypatch.setattr(cs, "_version", fake_version)
    return cs.scan_service_configs(
        {"family": "rhel"}, openssl if openssl is not None else {"pqc_native": True}
    )


def _endpoints(stc: dict[str, Any], service: str) -> dict[int, dict[str, Any]]:
    out = {}
    for svc in stc["services"]:
        if svc["service"] == service:
            for ep in svc["endpoints"]:
                for port in ep["ports"]:
                    out[port] = ep
    return out


# ---------------------------------------------------------------------------
# What the VMs negotiated, per endpoint
# ---------------------------------------------------------------------------


@pytest.fixture
def vm(monkeypatch):
    return _scan(
        monkeypatch, FIX / "vm-variants" / "root", versions={"postfix": "3.5.25"}
    )


@pytest.mark.parametrize(
    "service,port,expected",
    [
        (
            "nginx",
            8443,
            None,
        ),  # no group setting: X25519 on Rocky 9.8, ML-KEM elsewhere
        (
            "nginx",
            8444,
            False,
        ),  # ssl_ecdh_curve X25519:prime256v1: classical everywhere
        (
            "nginx",
            8445,
            True,
        ),  # ssl_ecdh_curve X25519MLKEM768: ML-KEM even on Rocky 9.8
        ("apache", 9443, None),
        ("apache", 9444, False),  # SSLOpenSSLConfCmd Groups X25519:prime256v1
        ("haproxy", 7443, None),
        ("haproxy", 7444, False),  # curves X25519:P-256
        ("stunnel", 6444, False),  # curves = X25519:P-256
        ("squid", 3443, None),
        ("postfix", 25, False),  # Postfix 3.5 compiled default: classical
        ("postfix", 2525, False),  # -o tls_eecdh_auto_curves=X25519,prime256v1
        ("dovecot", 993, None),
        ("postgresql", 5432, False),  # PostgreSQL 16: one curve, prime256v1
        ("mysql", 3306, None),
        ("redis", 6380, None),
        ("openldap", 389, None),
        ("tomcat", 8843, None),
    ],
)
def test_vm_variants_match_negotiation(vm, service, port, expected) -> None:
    ep = _endpoints(vm, service)[port]
    assert ep["pqc_key_exchange"] is expected, ep


def test_vm_variant_sources_and_settings(vm) -> None:
    nginx = _endpoints(vm, "nginx")
    assert nginx[8444]["groups"] == ["X25519", "prime256v1"]
    assert nginx[8444]["groups_setting"] == "ssl_ecdh_curve"
    assert nginx[8444]["groups_source"] == "config"
    assert nginx[8443]["groups_source"] == "library default"
    assert nginx[8443]["certificates"] == ["/etc/pqct/cert.pem"]
    pf = _endpoints(vm, "postfix")
    assert pf[25]["groups_source"] == "service default"
    assert pf[2525]["groups_source"] == "config"
    pg = _endpoints(vm, "postgresql")[5432]
    assert pg["service_supports_pqc_groups"] is False
    assert pg["groups"] == ["prime256v1"]


def test_stunnel_default_comes_from_the_binary(monkeypatch, tmp_path) -> None:
    root = tmp_path / "root"
    (root / "etc/stunnel").mkdir(parents=True)
    (root / "etc/stunnel/a.conf").write_text(
        (FIX / "vm-variants/root/etc/stunnel/pqct.conf").read_text()
    )
    (root / "usr/bin").mkdir(parents=True)
    binary = root / "usr/bin/stunnel"
    # EL9 5.71 / EL10 5.72 / Leap 5.74: pre-OpenSSL-3.5 default list.
    binary.write_bytes((FIX / "stunnel/default-classical.bin").read_bytes())
    ep = _endpoints(_scan(monkeypatch, root), "stunnel")[6443]
    assert ep["pqc_key_exchange"] is False
    assert ep["groups"] == ["X25519", "P-256", "X448", "P-521", "P-384"]
    assert ep["groups_source"] == "service default"
    # Fedora 44 / Ubuntu 26.04: the OpenSSL 3.5 build's default.
    binary.write_bytes((FIX / "stunnel/default-mlkem.bin").read_bytes())
    ep = _endpoints(_scan(monkeypatch, root), "stunnel")[6443]
    assert ep["pqc_key_exchange"] is True
    assert ep["groups"][0] == "X25519MLKEM768"


@pytest.mark.parametrize(
    "major,value,expected,supports",
    [
        (13, None, False, False),
        (16, "prime256v1", False, False),
        (18, None, False, None),  # ssl_groups default X25519:prime256v1
        (
            18,
            "X25519MLKEM768:X25519",
            True,
            None,
        ),  # negotiated ML-KEM on Fedora/Ubuntu/Leap
    ],
)
def test_postgresql_by_version(major, value, expected, supports) -> None:
    conf = "ssl = on\n" + (f"ssl_groups = '{value}'\n" if value and major >= 18 else "")
    if value and major < 18:
        conf += f"ssl_ecdh_curve = '{value}'\n"
    r = p.parse_postgresql(
        ["/pg.conf"],
        lambda path: conf if path == "/pg.conf" else None,
        lambda g: [],
        major,
    )
    ep = r["endpoints"][0]
    assert ep["pqc_key_exchange"] is expected
    assert ep["service_supports_pqc_groups"] is supports


def test_postgresql_auto_conf_overrides(monkeypatch, tmp_path) -> None:
    root = tmp_path / "root"
    data = root / "var/lib/pgsql/data"
    data.mkdir(parents=True)
    (data / "postgresql.conf").write_text("ssl = on\n")
    (data / "PG_VERSION").write_text("18\n")
    (data / "postgresql.auto.conf").write_text("ssl_groups = 'X25519MLKEM768:X25519'\n")
    ep = _endpoints(_scan(monkeypatch, root), "postgresql")[5432]
    assert ep["pqc_key_exchange"] is True
    assert ep["file"].endswith("postgresql.conf")


# ---------------------------------------------------------------------------
# Packaged defaults
# ---------------------------------------------------------------------------


def test_rocky9_packaged_defaults(monkeypatch) -> None:
    stc = _scan(monkeypatch, FIX / "rocky9/root", versions={"postfix": "3.5.25"})
    apache = _endpoints(stc, "apache")
    assert apache[443]["file"] == "/etc/httpd/conf.d/ssl.conf"
    assert apache[443]["pqc_key_exchange"] is None
    # EL main.cf ships smtpd TLS (may + a certificate): compiled classical list.
    assert _endpoints(stc, "postfix")[25]["pqc_key_exchange"] is False
    dovecot = _endpoints(stc, "dovecot")
    assert dovecot[993]["pqc_key_exchange"] is None
    assert "/etc/dovecot/local.conf" not in stc["summary"]["unreadable"]  # !include_try
    assert not _endpoints(stc, "nginx") and not _endpoints(stc, "haproxy")


def test_ubuntu2604_postgresql_ships_tls_with_classical_groups(monkeypatch) -> None:
    stc = _scan(monkeypatch, FIX / "ubuntu2604/root")
    ep = _endpoints(stc, "postgresql")[5432]
    assert ep["groups"] == ["X25519", "prime256v1"]
    assert ep["groups_source"] == "service default"
    assert ep["pqc_key_exchange"] is False
    pg = next(s for s in stc["services"] if s["service"] == "postgresql")
    assert pg["version"] == "18"


def test_leap16_and_fedora44_defaults_have_no_tls_endpoints(monkeypatch) -> None:
    for d in ("leap16", "fedora44"):
        stc = _scan(monkeypatch, FIX / d / "root")
        assert stc["available"] is True
        assert stc["summary"]["endpoints"] == 0


def test_nothing_installed_is_unavailable(monkeypatch, tmp_path) -> None:
    (tmp_path / "root/etc").mkdir(parents=True)
    stc = _scan(monkeypatch, tmp_path / "root")
    assert stc == {
        "available": False,
        "reason": "no supported service configuration found",
    }


# ---------------------------------------------------------------------------
# Parser details
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "allowed,mn,mx,expected",
    [
        (None, None, None, None),
        (["TLSv1.2", "TLSv1.3"], None, None, True),
        (["TLSv1.2"], None, None, False),
        (None, "TLSv1.2", "TLSv1.2", False),
        (None, "TLSv1.3", None, None),
        (None, None, "1.3", None),
    ],
)
def test_tls13_allowed(allowed, mn, mx, expected) -> None:
    assert p.tls13_allowed(allowed, mn, mx) is expected


def test_tls12_cap_rules_out_pqc_even_with_mlkem_groups() -> None:
    ep = p.make_endpoint(
        file="/x",
        line=1,
        ports=[443],
        groups=["X25519MLKEM768"],
        max_protocol="TLSv1.2",
    )
    assert ep["pqc_key_exchange"] is False
    assert "TLS 1.3" in ep["reason"]


@pytest.mark.parametrize(
    "value,expected",
    [
        ("auto", None),
        ("", None),
        ("X25519:prime256v1", ["X25519", "prime256v1"]),
        ("?X25519MLKEM768:DEFAULT", ["X25519MLKEM768", "DEFAULT"]),
        ("X25519, prime256v1 secp384r1", ["X25519", "prime256v1", "secp384r1"]),
        ("*X25519MLKEM768/*X25519:-X448", ["X25519MLKEM768", "X25519"]),
    ],
)
def test_split_groups(value, expected) -> None:
    assert p.split_groups(value) == expected


def test_apache_protocols() -> None:
    assert p._apache_protocols("all -SSLv3 -TLSv1 -TLSv1.1") == ["TLSv1.2", "TLSv1.3"]
    assert p._apache_protocols("-all +TLSv1.2") == ["TLSv1.2"]
    assert p._apache_protocols("TLSv1.2 TLSv1.3") == ["TLSv1.2", "TLSv1.3"]


def test_postfix_protocols() -> None:
    assert p._postfix_protocols(">=TLSv1.2") == ("TLSv1.2", None, None)
    assert p._postfix_protocols("!SSLv2, !SSLv3, !TLSv1.3")[2] == [
        "TLSv1",
        "TLSv1.1",
        "TLSv1.2",
    ]


@pytest.mark.parametrize(
    "version,openssl_pqc,expected_pqc",
    [
        ("3.5.25", True, False),
        ("3.10.14", True, False),
        ("3.11.0", True, True),
        ("3.11.0", False, False),
    ],
)
def test_postfix_default_by_version(version, openssl_pqc, expected_pqc) -> None:
    groups = cs.postfix_default_curves(version, openssl_pqc)
    assert bool(p.classify_groups(groups)["hybrid"]) is expected_pqc


def test_haproxy_global_default_curves_and_no_tlsv13() -> None:
    cfg = (
        "global\n  ssl-default-bind-curves X25519:P-256\n"
        "frontend a\n  bind :443 ssl crt /c.pem\n  bind :444 ssl crt /c.pem curves X25519MLKEM768:X25519\n"
        "  bind :445 ssl crt /c.pem no-tlsv13 curves X25519MLKEM768\n"
    )
    r = p.parse_haproxy(["/h.cfg"], lambda path: cfg)
    by_port = {e["ports"][0]: e for e in r["endpoints"]}
    assert by_port[443]["pqc_key_exchange"] is False
    assert by_port[443]["groups_setting"] == "ssl-default-bind-curves"
    assert by_port[444]["pqc_key_exchange"] is True
    assert by_port[445]["pqc_key_exchange"] is False


def test_nginx_inherits_http_level_curve_and_conf_command_wins() -> None:
    cfg = (
        "http { ssl_ecdh_curve X25519:prime256v1;\n"
        "  server { listen 443 ssl; ssl_certificate /a.pem; }\n"
        "  server { listen [::]:8443 ssl; ssl_conf_command Groups X25519MLKEM768:X25519; }\n"
        "  server { listen 80; }\n}\n"
    )
    r = p.parse_nginx("/etc/nginx/nginx.conf", lambda path: cfg, lambda g: [])
    by_port = {e["ports"][0]: e for e in r["endpoints"]}
    assert set(by_port) == {443, 8443}
    assert by_port[443]["pqc_key_exchange"] is False
    assert by_port[8443]["pqc_key_exchange"] is True
    assert by_port[8443]["groups_setting"] == "ssl_conf_command Groups"


def test_openldap_ecname_and_ldaps_url() -> None:
    ldif = "dn: cn=config\nolcTLSCertificateFile: /c.pem\nolcTLSECName: X25519:prime256v1\nolcTLSProtocolMin: 3.3\n"
    r = p.parse_openldap(["/c.ldif"], lambda path: ldif, "ldap:/// ldaps:/// ldapi:///")
    ep = r["endpoints"][0]
    assert ep["ports"] == [389, 636]
    assert ep["pqc_key_exchange"] is False
    assert ep["min_protocol"] == "TLSv1.2"


def test_unreadable_postgresql_data_dir_is_reported(monkeypatch, tmp_path) -> None:
    root = tmp_path / "root"
    (root / "var/lib/pgsql/data").mkdir(parents=True)
    monkeypatch.setattr(cs, "list_glob", lambda pattern: [])
    monkeypatch.setattr(
        cs,
        "read_error",
        lambda path: (
            "Permission denied (needs root)" if path == "/var/lib/pgsql/data" else None
        ),
    )
    stc = _scan(monkeypatch, root)
    pg = next(s for s in stc["services"] if s["service"] == "postgresql")
    assert pg["unreadable"] == [
        {"path": "/var/lib/pgsql/data", "reason": "Permission denied (needs root)"}
    ]


# ---------------------------------------------------------------------------
# Deployment gap and findings
# ---------------------------------------------------------------------------


def _listener(i: int, process: str, port: int, exe: str) -> dict[str, Any]:
    return {
        "protocol": "tcp",
        "port": port,
        "process": process,
        "exe": exe,
        "systemd_unit": f"{process}.service",
        "pid": 100 + i,
        "crypto_libraries": [
            {
                "family": "openssl",
                "path": "/usr/lib64/libssl.so.3",
                "version": "3.5.5",
                "library_pqc_capable": True,
            }
        ],
        "go": None,
    }


def _report(stc: dict[str, Any], policy_pqc: bool) -> dict[str, Any]:
    return {
        "openssl": {
            "available": True,
            "pqc_native": True,
            "tls_groups": {
                "hybrid": ["X25519MLKEM768"],
                "pure_pqc": [],
                "classical": ["x25519"],
            },
        },
        "crypto_policy": {"pqc_enabled": {"tls_key_exchange": policy_pqc}},
        "service_crypto_linkage": {
            "available": True,
            "listeners": [
                _listener(0, "nginx", 8444, "/usr/sbin/nginx"),
                _listener(1, "nginx", 8445, "/usr/sbin/nginx"),
                _listener(2, "nginx", 80, "/usr/sbin/nginx"),
                _listener(3, "postgres", 5432, "/usr/bin/postgres"),
                _listener(4, "master", 25, "/usr/libexec/postfix/master"),
            ],
        },
        "service_tls_config": stc,
    }


def test_gap_uses_each_services_own_configuration(vm) -> None:
    g = _gap.compute_gap(_report(vm, policy_pqc=True))
    items = {(s["process"], s["port"]): s for s in g["services"]["items"]}
    pinned = items[("nginx", 8444)]
    assert pinned["state"] == "capable_not_configured"
    assert pinned["follows_host_default"] is False
    assert pinned["evidence"]["configured"] == [pinned["service_config"]]
    assert pinned["service_config"].startswith("service_tls_config.services[")
    assert items[("nginx", 8445)]["state"] == "deployed"
    # :80 has no TLS endpoint: host default, no service_config.
    assert items[("nginx", 80)]["follows_host_default"] is True
    assert "service_config" not in items[("nginx", 80)]
    # PostgreSQL 16 can't use ML-KEM at all, whatever the library.
    assert items[("postgres", 5432)]["state"] == "not_capable"
    assert items[("master", 25)]["state"] == "capable_not_configured"
    assert "service:nginx/tcp/8444:capable_not_configured" in g["gaps"]


def test_service_pqc_pin_wins_over_a_blocking_policy(vm) -> None:
    g = _gap.compute_gap(_report(vm, policy_pqc=False))
    items = {(s["process"], s["port"]): s for s in g["services"]["items"]}
    assert items[("nginx", 8445)]["state"] == "deployed"  # measured on Rocky 9.8
    assert items[("nginx", 80)]["state"] == "capable_not_configured"


def _rep(stc: dict[str, Any], native: bool) -> pr.report.Report:
    r = pr.report.Report(
        generated_at="2026-10-14T00:00:00+00:00",
        hostname="h",
        os="o",
        arch="x86_64",
        openssl={
            "available": True,
            "pqc_native": native,
            "tls_groups": {
                "hybrid": ["X25519MLKEM768"] if native else [],
                "pure_pqc": [],
                "classical": ["x25519"],
            },
        },
        service_tls_config=stc,
    )
    return r


def test_pqc021_one_finding_per_blocked_endpoint(vm) -> None:
    findings = [
        f
        for f in _sarif.build_findings(_rep(vm, True))
        if f.rule_id == "pqc-021-service-config-blocks-pqc"
    ]
    subjects = {f.subject.split(":")[0] for f in findings}
    assert subjects == {
        "nginx",
        "apache",
        "haproxy",
        "stunnel",
        "postfix",
        "postgresql",
    }
    assert len({f.subject for f in findings}) == len(findings)
    pg = next(f for f in findings if f.subject.startswith("postgresql"))
    assert "PostgreSQL 18" in pg.message
    nginx = next(f for f in findings if f.subject.startswith("nginx"))
    assert "ssl_ecdh_curve X25519:prime256v1" in nginx.message


def test_pqc021_not_raised_when_the_library_cannot_do_pqc(vm) -> None:
    findings = [
        f
        for f in _sarif.build_findings(_rep(vm, False))
        if f.rule_id == "pqc-021-service-config-blocks-pqc"
    ]
    assert findings == []


def test_cli_root_scan_end_to_end(capsys, monkeypatch) -> None:
    # --root sets module-level state; monkeypatch restores it afterwards.
    monkeypatch.setattr(pr._platform, "HOST_PREFIX", "")
    monkeypatch.setattr(pr._platform, "OFFLINE_ROOT", "")
    rc = pr.cli.main(
        ["--root", str(FIX / "ubuntu2604/root"), "--scan-service-configs", "--json"]
    )
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["service_tls_config"]["summary"]["pqc_blocked"] == 1
    assert "service_tls_config" not in out["scan_mode"]["not_applicable"]


def test_prometheus_endpoint_counts(vm) -> None:
    from pqc_readiness.render import prom

    text = prom.render_prometheus(_rep(vm, True))
    assert (
        'pqc_readiness_service_tls_endpoints{service="nginx",pqc="classical"} 1' in text
    )
    assert 'pqc_readiness_service_tls_endpoints{service="nginx",pqc="pqc"} 1' in text
    assert (
        'pqc_readiness_service_tls_endpoints{service="nginx",pqc="library_default"} 1'
        in text
    )
    assert (
        'pqc_readiness_service_tls_endpoints{service="postgresql",pqc="classical"} 1'
        in text
    )


# --- Config files named on the daemon's command line (validation run 3) -----
# The booted images started haproxy as `haproxy -f /etc/haproxy/pqct.cfg` and
# stunnel as `stunnel /tmp/pqct-stunnel.conf`.  Reading only the standard
# paths missed both, and the classical endpoints 7444/6444 were reported as
# deployed although they negotiated X25519.


@pytest.mark.parametrize(
    ("service", "argv", "expected"),
    [
        (
            "haproxy",
            ["haproxy", "-f", "/etc/haproxy/pqct.cfg", "-D"],
            ["/etc/haproxy/pqct.cfg"],
        ),
        (
            "haproxy",
            [
                "/usr/sbin/haproxy",
                "-Ws",
                "-f",
                "/etc/haproxy/haproxy.cfg",
                "-f",
                "/etc/haproxy/conf.d",
                "-p",
                "/run/haproxy.pid",
            ],
            ["/etc/haproxy/haproxy.cfg", "/etc/haproxy/conf.d"],
        ),
        ("haproxy", ["haproxy", "-f/etc/h.cfg"], ["/etc/h.cfg"]),
        ("haproxy", ["haproxy", "-f", "relative.cfg"], []),
        ("stunnel", ["stunnel", "/tmp/pqct-stunnel.conf"], ["/tmp/pqct-stunnel.conf"]),
        (
            "stunnel",
            ["/usr/bin/stunnel", "/etc/stunnel/web.conf"],
            ["/etc/stunnel/web.conf"],
        ),
        ("stunnel", ["stunnel", "-fd", "3"], []),
        ("stunnel", ["stunnel"], []),
        ("nginx", ["nginx", "-c", "/etc/nginx/other.conf"], []),
    ],
)
def test_config_paths_from_cmdline(service, argv, expected) -> None:
    assert cs.config_paths_from_cmdline(service, argv) == expected


def test_running_daemon_config_outside_standard_paths(monkeypatch, tmp_path) -> None:
    v = FIX / "vm-variants" / "root" / "etc"
    (tmp_path / "etc" / "haproxy" / "conf.extra").mkdir(parents=True)
    (tmp_path / "tmp").mkdir()
    (tmp_path / "etc" / "haproxy" / "pqct.cfg").write_text(
        (v / "haproxy" / "haproxy.cfg").read_text()
    )
    (tmp_path / "etc" / "haproxy" / "conf.extra" / "9.cfg").write_text(
        "frontend x\n  bind :9443 ssl crt /c.pem curves P-256\n"
    )
    (tmp_path / "tmp" / "pqct-stunnel.conf").write_text(
        (v / "stunnel" / "pqct.conf").read_text()
    )
    argv = {
        101: [
            "haproxy",
            "-f",
            "/etc/haproxy/pqct.cfg",
            "-f",
            "/etc/haproxy/conf.extra",
            "-D",
        ],
        102: ["stunnel", "/tmp/pqct-stunnel.conf"],
    }
    monkeypatch.setattr(cs, "_cmdline", lambda pid: argv.get(pid, []))
    monkeypatch.setattr(cs, "stunnel_default_curves", lambda: (None, None))
    services_info = {
        "listeners": [
            _listener(1, "haproxy", 7444, "/usr/sbin/haproxy"),
            _listener(1, "haproxy", 9443, "/usr/sbin/haproxy"),
            _listener(2, "stunnel", 6444, "/usr/bin/stunnel"),
            _listener(3, "sshd", 22, "/usr/sbin/sshd"),
        ]
    }
    monkeypatch.setattr(pr._platform, "HOST_PREFIX", str(tmp_path))
    monkeypatch.setattr(pr._platform, "_run", _no_subprocess)
    monkeypatch.setattr(cs, "_version", lambda spec, family: None)

    # Without the running processes nothing is found: standard paths are empty.
    assert (
        cs.scan_service_configs({"family": "rhel"}, {"pqc_native": True})["available"]
        is False
    )

    stc = cs.scan_service_configs(
        {"family": "rhel"}, {"pqc_native": True}, services_info
    )
    ha, st = _endpoints(stc, "haproxy"), _endpoints(stc, "stunnel")
    assert ha[7443]["pqc_key_exchange"] is None
    assert ha[7444]["pqc_key_exchange"] is False
    assert ha[9443]["pqc_key_exchange"] is False
    assert st[6444]["pqc_key_exchange"] is False
    by = {s["service"]: s for s in stc["services"]}
    assert by["haproxy"]["config_from_command_line"] == [
        "/etc/haproxy/pqct.cfg",
        "/etc/haproxy/conf.extra/9.cfg",
    ]
    assert by["stunnel"]["config_from_command_line"] == ["/tmp/pqct-stunnel.conf"]
    # The verdict now uses those endpoints for the matching listeners.
    path, ep = cs.endpoint_for_listener(stc, services_info["listeners"][0])
    assert ep["pqc_key_exchange"] is False and path.startswith(
        "service_tls_config.services["
    )
