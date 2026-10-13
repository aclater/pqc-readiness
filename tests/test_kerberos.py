# SPDX-License-Identifier: Apache-2.0
"""Kerberos enctypes and PKINIT (--scan-kerberos, #109).

Keytabs are built here from MIT's documented FILE keytab format
(doc/formats/keytab_file_format.rst) with random key bytes, so no real
key material is committed; the parser is also checked against
`klist -k -e` on real VMs (see the PR).
"""

from __future__ import annotations

import json
import os
import struct
from pathlib import Path

import pytest

import pqc_readiness as pr
from pqc_readiness.detect import certs as _certs
from pqc_readiness.detect import protocols_kerberos as kb

FIX = Path(__file__).parent / "fixtures"
RANDOM_KEY = os.urandom(32)


def _data(b: bytes, order: str) -> bytes:
    return struct.pack(order + "H", len(b)) + b


def _entry(
    principal: str, kvno: int, enctype: int, version: int = 2, kvno32: int = 0
) -> bytes:
    order = ">" if version == 2 else "="
    name, realm = principal.rsplit("@", 1)
    comps = name.split("/")
    count = len(comps) + (1 if version == 1 else 0)
    rec = struct.pack(order + "H", count) + _data(realm.encode(), order)
    rec += b"".join(_data(c.encode(), order) for c in comps)
    if version == 2:
        rec += struct.pack(order + "I", 1)  # KRB5_NT_PRINCIPAL
    rec += struct.pack(order + "IB", 1_700_000_000, kvno)
    key = RANDOM_KEY[: 16 if enctype in (17, 19, 25) else 32]
    rec += struct.pack(order + "hH", enctype, len(key)) + key
    if kvno32:
        rec += struct.pack(order + "I", kvno32)
    return rec


def _keytab(entries: list[bytes], version: int = 2, hole: int = 0) -> bytes:
    order = ">" if version == 2 else "="
    out = bytes([5, version])
    if hole:
        out += struct.pack(order + "i", -hole) + b"\0" * hole
    for e in entries:
        out += struct.pack(order + "i", len(e)) + e
    return out


def _no_subprocess(cmd, timeout=None):  # noqa: ARG001
    raise AssertionError(f"unexpected subprocess: {cmd}")


@pytest.fixture
def host(monkeypatch, tmp_path):
    root = tmp_path / "root"
    (root / "etc").mkdir(parents=True)
    monkeypatch.setattr(pr._platform, "HOST_PREFIX", str(root))
    monkeypatch.setattr(pr._platform, "_run", _no_subprocess)
    return root


# ---------------------------------------------------------------------------
# Enctype lists
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "allow_weak", "expected"),
    [
        (None, False, kb.MIT_DEFAULT_ENCTYPES),
        (
            "DEFAULT -rc4 -des3",
            False,
            [
                e
                for e in kb.MIT_DEFAULT_ENCTYPES
                if e not in ("arcfour-hmac", "des3-cbc-sha1")
            ],
        ),
        (
            "aes",
            False,
            [
                "aes256-cts-hmac-sha1-96",
                "aes128-cts-hmac-sha1-96",
                "aes256-cts-hmac-sha384-192",
                "aes128-cts-hmac-sha256-128",
            ],
        ),
        ("aes256-cts,rc4-hmac", False, ["aes256-cts-hmac-sha1-96", "arcfour-hmac"]),
        ("des-cbc-crc aes256-sha2", False, ["aes256-cts-hmac-sha384-192"]),
        (
            "des-cbc-crc aes256-sha2",
            True,
            ["des-cbc-crc", "aes256-cts-hmac-sha384-192"],
        ),
        ("+camellia -camellia128-cts", False, ["camellia256-cts-cmac"]),
    ],
)
def test_expand_enctypes(value, allow_weak, expected) -> None:
    assert kb.expand_enctypes(value, allow_weak) == expected


def test_mit_default_still_contains_deprecated_enctypes() -> None:
    # doc/conf.py |defetypes| (MIT krb5): 3DES and RC4 are deprecated, not
    # "weak", so allow_weak_crypto=false keeps them.
    assert {"des3-cbc-sha1", "arcfour-hmac"} <= set(kb.expand_enctypes(None))


# ---------------------------------------------------------------------------
# Profile parsing and includes
# ---------------------------------------------------------------------------


def test_profile_sections_subsections_and_directives() -> None:
    sections, directives = kb.parse_profile(
        "includedir /etc/krb5.conf.d/\n"
        "[libdefaults]\n  default_realm = EXAMPLE.COM\n  permitted_enctypes = aes256-cts\n"
        "  permitted_enctypes = rc4-hmac\n"
        "[realms]\n EXAMPLE.COM = {\n  kdc = kdc.example.com\n  pkinit_anchors = FILE:/x\n }\n"
    )
    assert directives == [("includedir", "/etc/krb5.conf.d/")]
    assert sections["libdefaults"]["permitted_enctypes"] == "aes256-cts"  # first wins
    assert sections["realms"]["example.com"]["pkinit_anchors"] == "FILE:/x"


def test_includedir_follows_crypto_policies_symlink_under_prefix(host: Path) -> None:
    (host / "etc/krb5.conf").write_text(
        "includedir /etc/krb5.conf.d/\n[libdefaults]\n dns_lookup_kdc = true\n"
    )
    (host / "etc/krb5.conf.d").mkdir()
    be = host / "etc/crypto-policies/back-ends"
    be.mkdir(parents=True)
    (be / "krb5.config").write_text(
        "[libdefaults]\npermitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96\n"
    )
    # Absolute symlink, as RHEL ships it: must resolve inside the prefix.
    os.symlink(
        "/etc/crypto-policies/back-ends/krb5.config",
        host / "etc/krb5.conf.d/crypto-policies",
    )
    (host / "etc/krb5.conf.d/ignored.rpmsave").write_text(
        "[libdefaults]\npermitted_enctypes = des\n"
    )
    out = kb.scan_kerberos()
    assert out["config_files"] == ["/etc/krb5.conf", "/etc/krb5.conf.d/crypto-policies"]
    lists = out["config"]["enctype_lists"]
    assert lists["permitted_enctypes"]["enctypes"] == [
        "aes256-cts-hmac-sha1-96",
        "aes128-cts-hmac-sha1-96",
    ]
    assert lists["default_tgs_enctypes"]["source"] == "permitted_enctypes"
    assert out["summary"]["deprecated_enctypes"] == []
    assert out["summary"]["aes128_enctypes"] == ["aes128-cts-hmac-sha1-96"]


def test_unset_lists_use_mit_default_and_flag_deprecated(host: Path) -> None:
    (host / "etc/krb5.conf").write_text("[libdefaults]\n default_realm = EXAMPLE.COM\n")
    out = kb.scan_kerberos()
    assert (
        out["config"]["enctype_lists"]["permitted_enctypes"]["source"] == "mit_default"
    )
    level, parts = kb.describe_findings(out)
    assert level == "warning" and "MIT krb5's default enctype list" in parts[0]


def test_no_kerberos_config_is_unavailable(host: Path) -> None:
    assert kb.scan_kerberos() == {
        "available": False,
        "reason": "no /etc/krb5.conf or kdc.conf on the host (Kerberos not configured)",
    }


def test_kdc_conf_supported_enctypes(host: Path) -> None:
    d = host / "var/kerberos/krb5kdc"
    d.mkdir(parents=True)
    (d / "kdc.conf").write_text(
        "[realms]\n EXAMPLE.COM = {\n  master_key_type = aes256-cts\n"
        "  supported_enctypes = aes256-cts:special arcfour-hmac:normal\n }\n"
    )
    out = kb.scan_kerberos()
    realm = out["kdc"]["realms"]["example.com"]
    assert realm["supported_enctypes"] == ["aes256-cts-hmac-sha1-96", "arcfour-hmac"]
    assert realm["master_key_type"] == "aes256-cts"
    assert "arcfour-hmac" in out["summary"]["deprecated_enctypes"]


# ---------------------------------------------------------------------------
# Keytabs
# ---------------------------------------------------------------------------


def test_keytab_v2_entries_holes_and_kvno32() -> None:
    data = _keytab(
        [
            _entry("host/a.example.com@EXAMPLE.COM", 3, 18),
            _entry("host/a.example.com@EXAMPLE.COM", 3, 23),
            _entry("HTTP/a.example.com@EXAMPLE.COM", 1, 17, kvno32=300),
        ],
        hole=12,
    )
    out = kb.parse_keytab(data)
    assert out["format_version"] == 2
    assert [
        (e["principal"], e["kvno"], e["enctype"], e["status"]) for e in out["entries"]
    ] == [
        ("host/a.example.com@EXAMPLE.COM", 3, "aes256-cts-hmac-sha1-96", "ok"),
        ("host/a.example.com@EXAMPLE.COM", 3, "arcfour-hmac", "deprecated"),
        ("HTTP/a.example.com@EXAMPLE.COM", 300, "aes128-cts-hmac-sha1-96", "aes128"),
    ]


def test_keytab_v1_native_order() -> None:
    out = kb.parse_keytab(
        _keytab([_entry("host/b@EX.COM", 2, 20, version=1)], version=1)
    )
    assert out["format_version"] == 1
    assert out["entries"][0]["principal"] == "host/b@EX.COM"
    assert out["entries"][0]["enctype"] == "aes256-cts-hmac-sha384-192"


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"\x05\x09",
        _keytab([_entry("h/x@E", 1, 18)])[:-10],
        b"\x05\x02" + struct.pack(">i", 1000),
    ],
)
def test_malformed_keytabs_raise_keytab_error(data: bytes) -> None:
    with pytest.raises(kb.KeytabError):
        kb.parse_keytab(data)


def test_keytab_key_bytes_never_reach_any_output(host: Path) -> None:
    (host / "etc/krb5.conf").write_text(
        "[libdefaults]\n permitted_enctypes = aes256-cts\n"
    )
    (host / "etc/krb5.keytab").write_bytes(
        _keytab(
            [_entry("host/c@EXAMPLE.COM", 5, 18), _entry("host/c@EXAMPLE.COM", 5, 17)]
        )
    )
    r = pr.Report(kerberos=kb.scan_kerberos())
    blobs = [
        json.dumps(r.kerberos).encode(),
        pr.render_text(r).encode(),
        pr.render_sarif(r).encode(),
    ]
    for key in (RANDOM_KEY, RANDOM_KEY[:16], RANDOM_KEY.hex().encode()):
        assert not any(key in b for b in blobs)
    kt = r.kerberos["keytabs"][0]
    assert kt["enctypes"] == {
        "aes256-cts-hmac-sha1-96": 1,
        "aes128-cts-hmac-sha1-96": 1,
    }


def test_unreadable_keytab_is_reported(host: Path, monkeypatch) -> None:
    (host / "etc/krb5.conf").write_text("[libdefaults]\n")
    (host / "etc/krb5.keytab").write_bytes(b"\x05\x02")

    real = Path.read_bytes

    def denied(self):  # noqa: ANN001
        if self.name == "krb5.keytab":
            raise PermissionError(13, "Permission denied")
        return real(self)

    monkeypatch.setattr(Path, "read_bytes", denied)
    kt = kb.scan_kerberos()["keytabs"][0]
    assert kt == {
        "path": "/etc/krb5.keytab",
        "readable": False,
        "reason": "Permission denied (needs root)",
    }


def test_keytab_globs_and_default_keytab_name(host: Path) -> None:
    (host / "etc/krb5.conf").write_text(
        "[libdefaults]\n default_keytab_name = FILE:/etc/custom/svc.keytab\n permitted_enctypes = aes256-cts\n"
    )
    (host / "etc/custom").mkdir()
    (host / "etc/custom/svc.keytab").write_bytes(_keytab([_entry("svc/x@E", 1, 17)]))
    (host / "etc/httpd/conf").mkdir(parents=True)
    (host / "etc/httpd/conf/http.keytab").write_bytes(
        _keytab([_entry("HTTP/x@E", 1, 18)])
    )
    out = kb.scan_kerberos()
    assert [k["path"] for k in out["keytabs"]] == [
        "/etc/custom/svc.keytab",
        "/etc/httpd/conf/http.keytab",
    ]
    assert out["summary"]["keytab_keys_128_bit_only"] is False


# ---------------------------------------------------------------------------
# PKINIT
# ---------------------------------------------------------------------------


def test_pkinit_anchors_alone_are_not_flagged_and_missing_file_is_reported(
    host: Path,
) -> None:
    (host / "etc/krb5.conf").write_text(
        "[libdefaults]\n pkinit_anchors = FILE:/etc/pki/tls/certs/ca-bundle.crt\n permitted_enctypes = aes256-cts\n"
    )
    out = kb.scan_kerberos()
    pk = out["config"]["pkinit"]
    assert pk["anchors"] == {
        "path": "/etc/pki/tls/certs/ca-bundle.crt",
        "exists": False,
    }
    assert pk["identity_configured"] is False
    assert out["summary"]["pkinit_classical"] is False


def test_pkinit_identity_certificate_is_classical(host: Path) -> None:
    (host / "etc/pki").mkdir(parents=True)
    der = _certs._certs_in_file(FIX / "trust_store" / "rsa-2048.pem")[0]
    (host / "etc/pki/kdc.pem").write_bytes(
        (FIX / "trust_store" / "rsa-2048.pem").read_bytes()
    )
    (host / "etc/krb5.conf").write_text(
        "[libdefaults]\n permitted_enctypes = aes256-cts\n"
        "[realms]\n EXAMPLE.COM = {\n  pkinit_identities = FILE:/etc/pki/kdc.pem,/etc/pki/kdc.key\n }\n"
    )
    out = kb.scan_kerberos()
    ident = out["config"]["pkinit"]["identity"]
    assert ident["key_algorithms"] == ["RSA-2048"] and ident["certificates"] == 1
    assert out["summary"]["pkinit_classical"] is True
    assert len(der) > 0
    level, parts = kb.describe_findings(out)
    assert level == "note" and any("PKINIT" in p for p in parts)


def test_pkinit_pkcs11_identity_is_unknown(host: Path) -> None:
    (host / "etc/krb5.conf").write_text(
        "[libdefaults]\n permitted_enctypes = aes256-cts\n pkinit_identities = PKCS11:module_name=/usr/lib64/opensc-pkcs11.so\n"
    )
    out = kb.scan_kerberos()
    assert out["config"]["pkinit"]["identity"] == {"store": "PKCS11"}
    assert out["summary"]["pkinit_classical"] is None


# ---------------------------------------------------------------------------
# Findings, outputs, CLI
# ---------------------------------------------------------------------------


def test_sarif_levels(host: Path) -> None:
    (host / "etc/krb5.conf").write_text(
        "[libdefaults]\n permitted_enctypes = aes256-cts aes128-cts\n"
    )
    r = pr.Report(kerberos=kb.scan_kerberos())
    f = [
        x for x in pr.build_findings(r) if x.rule_id == "pqc-031-kerberos-weak-enctypes"
    ]
    assert len(f) == 1 and f[0].level == "note"
    (host / "etc/krb5.conf").write_text(
        "[libdefaults]\n permitted_enctypes = aes256-cts\n"
    )
    r = pr.Report(kerberos=kb.scan_kerberos())
    assert not [x for x in pr.build_findings(r) if x.rule_id.startswith("pqc-031")]


def test_text_section(host: Path) -> None:
    (host / "etc/krb5.conf").write_text(
        "[libdefaults]\n permitted_enctypes = aes256-cts rc4-hmac\n"
    )
    text = pr.render_text(pr.Report(kerberos=kb.scan_kerberos()))
    assert (
        "15. Kerberos" in text
        and "Deprecated Kerberos enctypes are allowed: arcfour-hmac" in text
    )


def test_cli_flag_and_default() -> None:
    args = pr.cli.build_parser().parse_args(["--scan-kerberos"])
    assert args.scan_kerberos is True
    assert pr.Report().kerberos == {}
