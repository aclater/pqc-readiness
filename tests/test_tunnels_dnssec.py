# SPDX-License-Identifier: Apache-2.0
"""WireGuard / OpenVPN (--scan-tunnels) and DNSSEC (--scan-dnssec), #113.

Detection is file-based against a fake host tree; the live `wg show` path
is exercised through its parser only.  Key material must never reach any
output format."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import pqc_readiness as pr
from pqc_readiness.detect import protocols_dnssec as dn
from pqc_readiness.detect import protocols_tunnels as tn

# Fake key material (base64 shaped, not real keys); asserted absent from output.
FAKE_PSK = "Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyMDA="  # pragma: allowlist secret
FAKE_PRIV = "YmF6cXV4YmF6cXV4YmF6cXV4YmF6cXV4YmF6cXV4MDA="  # pragma: allowlist secret


def _no_subprocess(cmd, timeout=None):  # noqa: ARG001
    raise AssertionError(f"unexpected subprocess: {cmd}")


@pytest.fixture
def host(monkeypatch, tmp_path):
    root = tmp_path / "root"
    (root / "etc").mkdir(parents=True)
    monkeypatch.setattr(pr._platform, "HOST_PREFIX", str(root))
    monkeypatch.setattr(pr._platform, "_run", _no_subprocess)
    return root


def _write(root: Path, rel: str, text: str) -> Path:
    p = root / rel.lstrip("/")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    return p


WG_QUICK = f"""[Interface]
PrivateKey = {FAKE_PRIV}
Address = 10.0.0.1/24

[Peer]
PublicKey = cGVlcjE=
PresharedKey = {FAKE_PSK}
AllowedIPs = 10.0.0.2/32

[Peer]
# no PSK here
PublicKey = cGVlcjI=
AllowedIPs = 10.0.0.3/32
"""


# ---------------------------------------------------------------------------
# WireGuard parsers
# ---------------------------------------------------------------------------


def test_parse_wg_quick_counts_psk_presence() -> None:
    assert tn.parse_wg_quick(WG_QUICK) == [
        {"preshared_key": True},
        {"preshared_key": False},
    ]


def test_parse_networkd_netdev_only_for_wireguard() -> None:
    wg = (
        "[NetDev]\nName=wg0\nKind=wireguard\n\n"
        "[WireGuardPeer]\nPublicKey=cGVlcjE=\nPresharedKeyFile=/etc/psk\n\n"
        "[WireGuardPeer]\nPublicKey=cGVlcjI=\n"
    )
    assert tn.parse_networkd_netdev(wg) == [
        {"preshared_key": True},
        {"preshared_key": False},
    ]
    assert tn.parse_networkd_netdev("[NetDev]\nName=br0\nKind=bridge\n") is None


@pytest.mark.parametrize(
    ("peer_lines", "expected"),
    [
        (f"preshared-key={FAKE_PSK}\n", True),
        ("preshared-key-flags=1\n", True),  # agent-owned secret
        ("preshared-key-flags=2\n", True),  # not saved
        ("preshared-key-flags=4\n", False),  # not required
        ("", False),
    ],
)
def test_parse_nm_keyfile_psk_and_agent_flags(peer_lines: str, expected: bool) -> None:
    text = (
        "[connection]\nid=wg0\ntype=wireguard\n\n"
        f"[wireguard-peer.cGVlcjE=]\nallowed-ips=10.0.0.2/32;\n{peer_lines}"
    )
    assert tn.parse_nm_keyfile(text) == [{"preshared_key": expected}]


def test_parse_nm_keyfile_ignores_other_connection_types() -> None:
    assert tn.parse_nm_keyfile("[connection]\ntype=ethernet\n") is None


def test_parse_wg_show_psk_counts_and_drops_values() -> None:
    out = tn.parse_wg_show_psk(
        f"wg0\tcGVlcjE=\t{FAKE_PSK}\nwg0\tcGVlcjI=\t(none)\nwg1\tcGVlcjM=\t(none)\n"
    )
    assert out == {
        "wg0": {"peers": 2, "with_psk": 1},
        "wg1": {"peers": 1, "with_psk": 0},
    }
    assert FAKE_PSK not in json.dumps(out)


def test_wg_running_not_queried_under_host_mount(host) -> None:
    assert tn._wg_running()["queried"] is False


# ---------------------------------------------------------------------------
# OpenVPN
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("config", "kex", "pqc"),
    [
        ("tls-groups X25519MLKEM768:X25519\n", "configured", True),
        ("tls-groups X25519:secp256r1\n", "configured", False),
        ("tls-groups X25519MLKEM768\ntls-version-max 1.2\n", "configured", False),
        ("tls-version-max 1.3\n", "openssl-default", None),
        ("", "openssl-default", None),
        ("tls-version-max 1.2\n", "openssl-default", False),
        ("secret static.key\n", "static-key", None),
    ],
)
def test_openvpn_key_exchange_classification(config: str, kex: str, pqc) -> None:
    entry = tn._openvpn_entry("/x.conf", tn.parse_openvpn_config("client\n" + config))
    assert (entry["key_exchange"], entry["pqc_key_exchange"]) == (kex, pqc)


def test_openvpn_inline_blocks_are_flagged_not_read() -> None:
    text = (
        "server 10.8.0.0 255.255.255.0\n<tls-crypt>\n"
        "-----BEGIN OpenVPN Static key V1-----\nabcdef\n"
        "-----END OpenVPN Static key V1-----\n</tls-crypt>\n"
        "tls-groups X25519\n"
    )
    d = tn.parse_openvpn_config(text)
    assert d["tls-crypt"] == "inline" and d["role"] == "server"
    entry = tn._openvpn_entry("/s.conf", d)
    assert entry["control_channel_psk"] == "tls-crypt"
    assert "abcdef" not in json.dumps(entry)


# ---------------------------------------------------------------------------
# scan_tunnels end to end on a fake host
# ---------------------------------------------------------------------------


def test_scan_tunnels_on_host_tree_never_emits_keys(host) -> None:
    _write(host, "/etc/wireguard/wg0.conf", WG_QUICK)
    _write(
        host,
        "/etc/openvpn/server/server.conf",
        "server 10.8.0.0 255.255.255.0\ntls-groups X25519\n",
    )
    _write(host, "/etc/openvpn/client/ok.conf", "client\n")
    t = tn.scan_tunnels()
    assert t["available"] is True
    wg = t["wireguard"]["summary"]
    assert (wg["configured"], wg["peers"], wg["peers_without_psk"]) == (True, 2, 1)
    ovpn = t["openvpn"]["summary"]
    assert ovpn["without_pqc"] == ["/etc/openvpn/server/server.conf"]
    assert ovpn["follows_openssl_default"] == ["/etc/openvpn/client/ok.conf"]
    r = pr.Report(tunnels=t, generated_at="2026-10-13T00:00:00+00:00", hostname="h")
    for text in (
        json.dumps(t),
        pr.render_sarif(r),
        pr.render_text(r),
        "\n".join(pr.render_ndjson(r).splitlines()),
    ):
        assert FAKE_PSK not in text and FAKE_PRIV not in text
    rules = {f.rule_id for f in pr.render.sarif.build_findings(r)}
    assert {
        "pqc-032-wireguard-peer-without-psk",
        "pqc-033-openvpn-classical-key-exchange",
    } <= rules


def test_unreadable_wg_quick_is_listed(host) -> None:
    p = _write(host, "/etc/wireguard/wg0.conf", WG_QUICK)
    p.chmod(0)
    try:
        if p.stat().st_mode and __import__("os").access(p, __import__("os").R_OK):
            pytest.skip("running as root: file stays readable")
        t = tn.scan_tunnels()
        assert t["wireguard"]["summary"]["unreadable_configs"] == [
            "/etc/wireguard/wg0.conf"
        ]
    finally:
        p.chmod(0o600)


def test_scan_tunnels_unavailable_without_configs(host) -> None:
    assert tn.scan_tunnels() == {
        "available": False,
        "reason": "no WireGuard or OpenVPN configuration found",
    }


def test_describe_openvpn_explains_tls12_cap() -> None:
    t = {
        "openvpn": {
            "configs": [
                {
                    "path": "/a.conf",
                    "readable": True,
                    "tls_groups": None,
                    "tls_version_max": "1.2",
                    "pqc_key_exchange": False,
                }
            ]
        }
    }
    assert tn.describe_openvpn(t) == [
        "/a.conf: tls-version-max 1.2 (hybrid ML-KEM groups need TLS 1.3)"
    ]


def test_describe_wireguard_silent_when_all_peers_have_psk() -> None:
    t = {"wireguard": {"summary": {"peers": 2, "peers_without_psk": 0}}}
    assert tn.describe_wireguard(t) is None


# ---------------------------------------------------------------------------
# DNSSEC
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "number", "name", "status"),
    [
        ("ecdsa256", 13, "ECDSAP256SHA256", "classical"),
        ("RSASHA1", 5, "RSASHA1", "deprecated"),
        ("8", 8, "RSASHA256", "classical"),
        (18, 18, "MLDSA44", "pqc"),
        ("mldsa44", 18, "MLDSA44", "pqc"),
        ("frobnicate", None, "frobnicate", "unknown"),
    ],
)
def test_algorithm_record(value, number, name, status) -> None:
    rec = dn.algorithm_record(value)
    assert (rec["number"], rec["name"], rec["status"]) == (number, name, status)


NAMED_CONF = """
// BIND config with a policy and an include
options {
    directory "/var/named";
    dnssec-validation auto;  # validate
    key-directory "/var/named/keys";
};
dnssec-policy "legacy" {
    keys {
        ksk lifetime unlimited algorithm rsasha1 2048;
        zsk lifetime 30d algorithm ecdsa256;
    };
};
include "/etc/named.zones";
"""
NAMED_ZONES = """
zone "example.com" { type primary; file "example.com.db"; dnssec-policy legacy; };
zone "example.org" { type primary; file "example.org.db"; dnssec-policy default; };
zone "plain.net" { type primary; file "plain.db"; dnssec-policy none; };
"""


def test_scan_bind_policies_includes_default_policy_and_key_files(host) -> None:
    _write(host, "/etc/named.conf", NAMED_CONF)
    _write(host, "/etc/named.zones", NAMED_ZONES)
    _write(host, "/var/named/keys/Kexample.com.+013+12345.key", "public key data")
    _write(host, "/var/named/keys/Kexample.com.+013+12345.private", "secret")
    b = dn.scan_bind()
    assert b is not None
    assert b["config_files"] == ["/etc/named.conf", "/etc/named.zones"]
    assert b["dnssec_validation"] == "auto"
    assert {z["zone"] for z in b["signed_zones"]} == {"example.com", "example.org"}
    assert [a["name"] for a in b["policies"]["legacy"]] == [
        "RSASHA1",
        "ECDSAP256SHA256",
    ]
    assert b["policies"]["default"][0]["name"] == "ECDSAP256SHA256"
    assert [(k["zone"], k["number"], k["directory"]) for k in b["key_files"]] == [
        ("example.com", 13, "/var/named/keys")
    ]


def test_scan_dnssec_summary_and_deprecated_warning(host) -> None:
    _write(host, "/etc/named.conf", NAMED_CONF)
    _write(host, "/etc/named.zones", NAMED_ZONES)
    d = dn.scan_dnssec()
    s = d["summary"]
    assert s["signing_configured"] and not s["signing_pqc"]
    assert s["deprecated_signing"] == ["RSASHA1"]
    level, msg = dn.describe(d)
    assert level == "warning" and "RSASHA1" in msg
    r = pr.Report(dnssec=d)
    rules = {f.rule_id for f in pr.render.sarif.build_findings(r)}
    assert "pqc-034-dnssec-classical-signing" in rules
    assert "17. DNSSEC" in pr.render_text(r)


def test_classical_only_signing_is_a_note(host) -> None:
    _write(
        host,
        "/etc/named.conf",
        'zone "example.org" { type primary; dnssec-policy default; };\n',
    )
    level, msg = dn.describe(dn.scan_dnssec())
    assert level == "note" and "ML-DSA-44" in msg


def test_pqc_signing_raises_no_finding(host) -> None:
    _write(
        host,
        "/etc/knot/knot.conf",
        "policy:\n  - id: pq\n    algorithm: mldsa44\nzone:\n  - domain: x.\n    dnssec-signing: on\n",
    )
    d = dn.scan_dnssec()
    assert d["summary"]["signing_pqc"] is True
    assert dn.describe(d) == (None, None)


def test_powerdns_defaults(host) -> None:
    _write(
        host,
        "/etc/pdns/pdns.conf",
        "default-ksk-algorithm=ed25519\ndefault-zsk-algorithm=ecdsa256\n",  # pragma: allowlist secret
    )
    p = dn.scan_powerdns()
    assert p is not None
    assert {k: v["name"] for k, v in p["default_algorithms"].items()} == {
        "default-ksk-algorithm": "ED25519",
        "default-zsk-algorithm": "ECDSAP256SHA256",
    }


def test_validators_unbound_and_resolved_dropin_override(host) -> None:
    _write(
        host,
        "/etc/unbound/unbound.conf",
        'server:\n  module-config: "validator iterator"\n'
        '  auto-trust-anchor-file: "/var/lib/unbound/root.key"\n',
    )
    _write(host, "/etc/systemd/resolved.conf", "[Resolve]\nDNSSEC=no\n")
    _write(
        host, "/etc/systemd/resolved.conf.d/10-dnssec.conf", "[Resolve]\nDNSSEC=yes\n"
    )
    v = dn.scan_validators()
    assert v["unbound"] == {"validating": True, "trust_anchor_configured": True}
    assert v["systemd_resolved"] == {"dnssec": "yes"}
    d = dn.scan_dnssec()
    assert d["available"] is True and d["summary"]["signing_configured"] is False
    assert dn.describe(d) == (None, None)  # validation only: no signing finding


def test_scan_dnssec_unavailable_without_configs(host) -> None:
    assert dn.scan_dnssec()["available"] is False


# ---------------------------------------------------------------------------
# CLI wiring
# ---------------------------------------------------------------------------


def test_cli_flags_and_defaults() -> None:
    args = pr.cli.build_parser().parse_args(["--scan-tunnels", "--scan-dnssec"])
    assert args.scan_tunnels is True and args.scan_dnssec is True
    r = pr.Report()
    assert r.tunnels == {} and r.dnssec == {}


def test_offline_root_scan_reads_tunnels_and_dnssec(tmp_path, capsys) -> None:
    root = tmp_path / "tree"
    (root / "etc").mkdir(parents=True)
    _write(root, "/etc/os-release", 'ID=fedora\nVERSION_ID=44\nPRETTY_NAME="Fedora"\n')
    _write(root, "/etc/wireguard/wg0.conf", WG_QUICK)
    _write(root, "/etc/named.conf", 'zone "z." { dnssec-policy default; };\n')
    try:
        pr.cli.main(["--root", str(root), "--scan-tunnels", "--scan-dnssec", "--json"])
    finally:
        pr._platform.set_offline_root("")
    report = json.loads(capsys.readouterr().out)
    assert report["tunnels"]["wireguard"]["summary"]["peers_without_psk"] == 1
    assert report["dnssec"]["summary"]["signing_algorithms"][0]["number"] == 13
    assert FAKE_PSK not in json.dumps(report)


def test_unreadable_tunnel_configs_are_undetermined_not_silent() -> None:
    r = pr.Report(
        tunnels={
            "available": True,
            "wireguard": {
                "summary": {
                    "peers": 0,
                    "peers_without_psk": 0,
                    "unreadable_configs": ["/etc/wireguard/wg0.conf"],
                }
            },
            "openvpn": {
                "configs": [
                    {
                        "path": "/etc/openvpn/server/s.conf",
                        "readable": False,
                        "reason": "Permission denied (needs root)",
                    }
                ]
            },
        }
    )
    found = [(f.rule_id, f.subject) for f in pr.render.sarif.build_findings(r)]
    assert (
        "pqc-018-pqc-capability-undetermined",
        "wireguard:/etc/wireguard/wg0.conf",
    ) in found
    assert (
        "pqc-018-pqc-capability-undetermined",
        "openvpn:/etc/openvpn/server/s.conf",
    ) in found
    assert not any(rid.startswith(("pqc-032", "pqc-033")) for rid, _ in found)


def _need_non_root(path: Path) -> None:
    import os

    if os.access(path, os.R_OK):
        pytest.skip("running as root: permissions don't restrict reads")


def test_unlistable_dirs_and_unreadable_named_conf_are_undetermined(host) -> None:
    # Fedora defaults: /etc/wireguard 0700, /etc/openvpn/server 0750,
    # /etc/named.conf root:named 0640.  An unprivileged scan must say
    # "unknown" (pqc-018), not report the host as having none of them.
    wg_dir = host / "etc/wireguard"
    _write(host, "/etc/wireguard/wg0.conf", WG_QUICK)
    ovpn_dir = host / "etc/openvpn/server"
    _write(host, "/etc/openvpn/server/s.conf", "server 10.8.0.0 255.255.255.0\n")
    named = _write(host, "/etc/named.conf", 'zone "z." { dnssec-policy default; };\n')
    for p in (wg_dir, ovpn_dir, named):
        p.chmod(0)
    try:
        _need_non_root(named)
        t = tn.scan_tunnels()
        assert t["available"] is True
        assert t["wireguard"]["summary"]["unreadable_configs"] == ["/etc/wireguard"]
        assert {c["path"] for c in t["openvpn"]["configs"]} == {"/etc/openvpn/server"}
        d = dn.scan_dnssec()
        assert d["available"] is True
        assert [u["path"] for u in d["summary"]["unreadable_configs"]] == [
            "/etc/named.conf"
        ]
        r = pr.Report(tunnels=t, dnssec=d)
        subjects = {
            f.subject
            for f in pr.render.sarif.build_findings(r)
            if f.rule_id == "pqc-018-pqc-capability-undetermined"
        }
        assert subjects == {
            "wireguard:/etc/wireguard",
            "openvpn:/etc/openvpn/server",
            "dnssec:/etc/named.conf",
        }
    finally:
        for p in (wg_dir, ovpn_dir):
            p.chmod(0o755)
        named.chmod(0o644)


def test_unreadable_list_is_reset_between_scans(host) -> None:
    named = _write(host, "/etc/named.conf", 'zone "z." { dnssec-policy default; };\n')
    named.chmod(0)
    try:
        _need_non_root(named)
        assert dn.scan_dnssec()["summary"]["unreadable_configs"]
    finally:
        named.chmod(0o644)
    assert dn.scan_dnssec()["summary"]["unreadable_configs"] == []
