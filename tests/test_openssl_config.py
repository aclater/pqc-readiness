"""OpenSSL effective configuration (#106).

Fixtures: tests/fixtures/openssl_config/ (provenance in its README).
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from conftest import FIXTURES
import pqc_readiness as pr

F = FIXTURES / "openssl_config"
mod = pr.detect.config_openssl
V35 = [3, 5, 5]


@pytest.fixture
def host(monkeypatch):
    def _use(root: Path) -> None:
        monkeypatch.setattr(pr._platform, "HOST_PREFIX", str(root))

    return _use


# ---------------------------------------------------------------------------
# Real layouts
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("tree", "family", "path", "pqc", "source"),
    [
        ("el9-default", "rhel", "/etc/pki/tls/openssl.cnf", False, "config"),
        ("el10-default", "rhel", "/etc/pki/tls/openssl.cnf", True, "config"),
        ("fedora44-oqs", "rhel", "/etc/pki/tls/openssl.cnf", True, "config"),
        ("leap16-default", "suse", "/etc/ssl/openssl.cnf", True, "config"),
        # No ssl_conf: OpenSSL 3.5's built-in list, X25519MLKEM768 first.
        (
            "debian13-stock",
            "debian",
            "/etc/ssl/openssl.cnf",
            True,
            "openssl built-in default (3.5+)",
        ),
        (
            "ubuntu2604-stock",
            "debian",
            "/etc/ssl/openssl.cnf",
            True,
            "openssl built-in default (3.5+)",
        ),
    ],
)
def test_real_layouts(host, tree, family, path, pqc, source) -> None:
    host(F / tree)
    out = mod.detect_openssl_config({"family": family}, V35)
    assert out["available"] is True
    assert out["path"] == path
    assert out["path_source"] == "distribution default"
    # Ubuntu 26.04 includes two directories that only exist once its
    # optional crypto-config package is installed; stock images lack them.
    expected_missing = (
        [
            "/var/lib/crypto-config/profiles/current/openssl.conf.d",
            "/etc/ssl/openssl.conf.d",
        ]
        if tree == "ubuntu2604-stock"
        else []
    )
    assert out["include_errors"] == expected_missing
    assert out["default_groups_source"] == source
    assert out["pqc_key_exchange_by_default"] is pqc


def test_rhel_follows_crypto_policy_include(host) -> None:
    host(F / "el10-default")
    out = mod.detect_openssl_config({"family": "rhel"}, V35)
    assert out["files"] == [
        "/etc/pki/tls/openssl.cnf",
        "/etc/crypto-policies/back-ends/opensslcnf.config",
    ]
    assert out["system_default_section"] == "crypto_policy"
    assert out["groups_configured"][0] == "X25519MLKEM768"
    assert out["default_pqc_groups"]["hybrid"][:1] == ["X25519MLKEM768"]


def test_el9_policy_include_has_no_pqc_groups(host) -> None:
    host(F / "el9-default")
    out = mod.detect_openssl_config({"family": "rhel"}, V35)
    assert out["groups_configured"] is not None
    assert out["default_pqc_groups"] == {"hybrid": [], "pure_pqc": []}


def test_directory_include_and_third_party_provider(host) -> None:
    host(F / "fedora44-oqs")
    out = mod.detect_openssl_config({"family": "rhel"}, V35)
    # openssl.d is read in sorted order; the pkcs11 snippet is all comments.
    assert out["files"][:3] == [
        "/etc/pki/tls/openssl.cnf",
        "/etc/pki/tls/openssl.d/oqsprovider.conf",
        "/etc/pki/tls/openssl.d/pkcs11-provider.conf",
    ]
    by_name = {p["name"]: p for p in out["providers_configured"]}
    assert by_name["default"] == {
        "name": "default",
        "section": "default_sect",
        "activate": True,
        "module": None,
        "third_party": False,
    }
    assert by_name["oqsprovider"]["third_party"] is True
    assert by_name["oqsprovider"]["activate"] is True
    assert "pkcs11" not in by_name
    assert out["third_party_providers_configured"] == ["oqsprovider"]


def test_pre_35_without_groups_has_no_pqc_default(host) -> None:
    host(F / "debian13-stock")
    out = mod.detect_openssl_config({"family": "debian"}, [3, 0, 13])
    assert out["default_groups"] == []
    assert out["pqc_key_exchange_by_default"] is False
    assert "pre-3.5" in out["default_groups_source"]


def test_debian_usr_lib_ssl_symlink_resolves_inside_prefix(host, tmp_path) -> None:
    # On Debian /usr/lib/ssl/openssl.cnf -> /etc/ssl/openssl.cnf.  If only
    # that path existed under the prefix it must still be read from the host.
    root = tmp_path / "host"
    (root / "usr/lib/ssl").mkdir(parents=True)
    (root / "etc/ssl").mkdir(parents=True)
    (root / "etc/ssl/openssl.cnf").write_text("openssl_conf = x\n[x]\n")
    os.symlink("/etc/ssl/openssl.cnf", root / "usr/lib/ssl/openssl.cnf")
    host(root)
    assert mod._read("/usr/lib/ssl/openssl.cnf") == "openssl_conf = x\n[x]\n"


# ---------------------------------------------------------------------------
# Synthetic configs
# ---------------------------------------------------------------------------


def _write(root: Path, rel: str, text: str) -> None:
    p = root / rel.lstrip("/")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def test_config_that_sets_groups_without_pqc(host, tmp_path) -> None:
    _write(
        tmp_path,
        "/etc/ssl/openssl.cnf",
        (
            "openssl_conf = init\n[init]\nssl_conf = ssl\n[ssl]\nsystem_default = sys\n"
            "[sys]\nGroups = X25519:secp256r1   # classical only\nMinProtocol = TLSv1.3\n"
        ),
    )
    host(tmp_path)
    out = mod.detect_openssl_config({"family": "suse"}, V35)
    assert out["groups_configured"] == ["X25519", "secp256r1"]
    assert out["min_protocol"] == "TLSv1.3"
    assert out["default_groups_source"] == "config"
    assert out["pqc_key_exchange_by_default"] is False


def test_relative_include_and_include_errors(host, tmp_path) -> None:
    _write(
        tmp_path,
        "/etc/ssl/openssl.cnf",
        (
            "openssl_conf = init\n[init]\nssl_conf = ssl\n.include extra.cnf\n.include /etc/ssl/missing.cnf\n"
        ),
    )
    _write(
        tmp_path,
        "/etc/ssl/extra.cnf",
        "[ssl]\nsystem_default = sys\n[sys]\nGroups = X25519MLKEM768\n",
    )
    host(tmp_path)
    out = mod.detect_openssl_config({"family": "suse"}, V35)
    assert out["files"] == ["/etc/ssl/openssl.cnf", "/etc/ssl/extra.cnf"]
    assert out["include_errors"] == ["/etc/ssl/missing.cnf"]
    assert out["pqc_key_exchange_by_default"] is True


def test_include_cycle_is_bounded(host, tmp_path) -> None:
    _write(tmp_path, "/etc/ssl/openssl.cnf", ".include /etc/ssl/b.cnf\n")
    _write(tmp_path, "/etc/ssl/b.cnf", ".include /etc/ssl/openssl.cnf\n")
    host(tmp_path)
    out = mod.detect_openssl_config({"family": "suse"}, V35)
    assert out["include_errors"] == ["/etc/ssl/openssl.cnf"]


def test_repeated_sections_merge_later_values_win() -> None:
    texts = {"/a": "[s]\nk = 1\nj = 2\n[s]\nk = 3\n"}
    parsed = mod.parse_openssl_cnf("/a", texts.get, lambda p: None)
    assert parsed["sections"]["s"] == {"k": "3", "j": "2"}


def test_escaped_hash_and_quotes() -> None:
    texts = {"/a": '[s]\nk = "a\\#b"  # comment\n'}
    assert (
        mod.parse_openssl_cnf("/a", texts.get, lambda p: None)["sections"]["s"]["k"]
        == "a#b"
    )


def test_no_config_is_unavailable(host, tmp_path) -> None:
    host(tmp_path)
    out = mod.detect_openssl_config({"family": "rhel"}, V35)
    assert out["available"] is False


def test_under_host_mount_the_image_s_openssl_conf_is_ignored(
    host, tmp_path, monkeypatch
) -> None:
    monkeypatch.setenv("OPENSSL_CONF", "/scanner/image/openssl.cnf")
    _write(tmp_path, "/etc/pki/tls/openssl.cnf", "openssl_conf = init\n[init]\n")
    host(tmp_path)
    path, how = mod.locate_openssl_config("rhel")
    assert (path, how) == ("/etc/pki/tls/openssl.cnf", "distribution default")


# ---------------------------------------------------------------------------
# Loaded third-party providers and algorithms (real oqs-provider output)
# ---------------------------------------------------------------------------


def test_third_party_providers_from_real_output() -> None:
    text = (F / "fedora44-oqs/openssl-output/providers.txt").read_text()
    records = pr.detect.config.parse_openssl_provider_records(text)
    tp = mod.third_party_providers(records)
    assert [p["name"] for p in tp] == ["oqsprovider"]
    assert tp[0]["version"] == "0.12.0"
    assert "liboqs v.0.16.0" in tp[0]["build_info"]
    assert tp[0]["status"] == "active"


def test_third_party_algorithms_from_real_output() -> None:
    kem = mod.third_party_algorithms(
        (F / "fedora44-oqs/openssl-output/kem.txt").read_text()
    )
    sig = mod.third_party_algorithms(
        (F / "fedora44-oqs/openssl-output/sig.txt").read_text()
    )
    assert {a["provider"] for a in kem} == {"oqsprovider"}
    kem_names = {a["name"] for a in kem}
    assert {"efrodo640aes", "x25519_efrodo640aes"} <= kem_names
    assert {"p256_mldsa44", "p384_mldsa65"} <= {a["name"] for a in sig}
    # Built-in algorithms (no "@ provider" suffix, or @ default) are excluded.
    assert not any(a["provider"] in mod.BUILTIN_PROVIDERS for a in kem + sig)


def test_openssl_capability_carries_config_and_third_party(
    monkeypatch, host, tmp_path
) -> None:
    out_dir = F / "fedora44-oqs/openssl-output"
    canned = {
        ("openssl", "list", "-kem-algorithms"): (out_dir / "kem.txt").read_text(),
        ("openssl", "list", "-signature-algorithms"): (out_dir / "sig.txt").read_text(),
        ("openssl", "list", "-tls-groups", "-tls1_3"): (
            out_dir / "tls-groups.txt"
        ).read_text(),
    }
    monkeypatch.setattr(pr.detect.config.shutil, "which", lambda n: "/usr/bin/openssl")
    monkeypatch.setattr(
        pr._platform, "_openssl_version_text", lambda: (0, "OpenSSL 3.5.9 1 Jul 2026")
    )
    monkeypatch.setattr(
        pr._platform, "_run", lambda cmd, timeout=None: (0, canned.get(tuple(cmd), ""))
    )
    monkeypatch.setattr(
        pr.detect.hardware,
        "_openssl_providers_verbose_text",
        lambda: (0, (out_dir / "providers.txt").read_text()),
    )
    host(F / "fedora44-oqs")
    out = pr.detect.config.openssl_capability({"family": "rhel"})
    assert [p["name"] for p in out["third_party_providers"]] == ["oqsprovider"]
    assert len(out["third_party_algorithms"]["kem"]) == 56
    assert out["config"]["third_party_providers_configured"] == ["oqsprovider"]


def test_text_report_shows_config_and_third_party_providers() -> None:
    r = pr.Report(
        hostname="h",
        openssl={
            "available": True,
            "version": "OpenSSL 3.5.9",
            "pqc_native": True,
            "config": {
                "available": True,
                "path": "/etc/pki/tls/openssl.cnf",
                "default_groups_source": "config",
                "pqc_key_exchange_by_default": False,
            },
            "third_party_providers": [{"name": "oqsprovider"}],
        },
    )
    text = pr.render.text.render_text(r)
    assert (
        "Config:        /etc/pki/tls/openssl.cnf (default groups from config)" in text
    )
    assert "PQC kex by default: no" in text
    assert "3rd-party providers: oqsprovider" in text
