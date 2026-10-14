"""System-wide crypto policy detection (#104).

Fixtures under tests/fixtures/crypto_policies/ were captured from booted
cloud-image VMs on 2026-10-13 (see that directory's README): back-end
files were dereferenced from their /usr/share/crypto-policies symlinks,
and module listings recreated as empty .pmod files.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from conftest import FIXTURES
import pqc_readiness as pr

CP = FIXTURES / "crypto_policies"
detect = pr.detect.config_policy


@pytest.fixture
def host(monkeypatch):
    """Point the probes at a host tree, as --host-mount does."""

    def _use(root: Path) -> None:
        monkeypatch.setattr(pr._platform, "HOST_PREFIX", str(root))

    return _use


def _write_tree(
    root: Path, current: str, opensslcnf: str, config: str | None = None
) -> None:
    (root / "etc/crypto-policies/state").mkdir(parents=True)
    (root / "etc/crypto-policies/back-ends").mkdir(parents=True)
    (root / "etc/crypto-policies/state/current").write_text(current + "\n")
    (root / "etc/crypto-policies/config").write_text((config or current) + "\n")
    (root / "etc/crypto-policies/back-ends/opensslcnf.config").write_text(opensslcnf)


# ---------------------------------------------------------------------------
# Real captures
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("tree", "active", "tls_kex", "tls_sig", "ssh_kex", "pq_active"),
    [
        # EL9.8 DEFAULT enables no PQC anywhere, although OpenSSL 3.5 can.
        ("el9-default", "DEFAULT", False, False, False, []),
        ("el9-pq", "DEFAULT:PQ", True, True, True, ["PQ"]),
        # EL10.2 / Fedora / SUSE 16 DEFAULT already enable hybrid ML-KEM + ML-DSA.
        ("el10-default", "DEFAULT", True, True, True, []),
        ("el10-test-pq", "DEFAULT:TEST-PQ", True, True, True, ["TEST-PQ"]),
        ("fedora44-default", "DEFAULT", True, True, True, []),
        ("leap16-default", "DEFAULT", True, True, True, []),
    ],
)
def test_captured_policies(
    host, tree, active, tls_kex, tls_sig, ssh_kex, pq_active
) -> None:
    host(CP / tree)
    out = detect.detect_crypto_policy()
    assert out["available"] is True
    assert out["active"] == active
    assert out["applied"] is True
    assert out["pq_subpolicies_active"] == pq_active
    en = out["pqc_enabled"]
    assert en["tls_key_exchange"] is tls_kex
    assert en["tls_signatures"] is tls_sig
    assert en["ssh_key_exchange_client"] is ssh_kex
    # No measured policy enables ML-KEM for IKE yet; SUSE ships no
    # libreswan back-end at all, which is "unknown", not "no".
    has_ike = (CP / tree / "etc/crypto-policies/back-ends/libreswan.config").exists()
    assert en["ike_key_exchange"] is (False if has_ike else None)
    for name, b in out["backends"].items():
        exists = (CP / tree / f"etc/crypto-policies/back-ends/{name}.config").exists()
        assert b["readable"] is exists, name
    # No /proc in the fixture tree: unknown, not guessed.
    assert out["reboot_required"] is None


def test_el10_test_pq_adds_pure_mlkem_groups(host) -> None:
    host(CP / "el10-default")
    default = detect.detect_crypto_policy()["backends"]["opensslcnf"]["pqc_groups"]
    host(CP / "el10-test-pq")
    test_pq = detect.detect_crypto_policy()["backends"]["opensslcnf"]["pqc_groups"]
    assert default["pure_pqc"] == []
    assert {"mlkem512", "mlkem768", "mlkem1024"} <= set(test_pq["pure_pqc"])
    assert "X25519MLKEM768" in test_pq["hybrid"]


def test_available_subpolicies_differ_by_release(host) -> None:
    host(CP / "el9-default")
    el9 = detect.detect_crypto_policy()["available_subpolicies"]
    host(CP / "el10-default")
    el10 = detect.detect_crypto_policy()["available_subpolicies"]
    assert "PQ" in el9 and "TEST-PQ" not in el9
    assert {"TEST-PQ", "NO-PQ"} <= set(el10) and "PQ" not in el10


def test_suse_without_update_crypto_policies_is_still_read(host) -> None:
    # openSUSE Leap 16 ships the policy files but not the CLI.
    host(CP / "leap16-default")
    out = detect.detect_crypto_policy()
    assert out["available"] is True
    assert "TEST-PQ" in out["available_subpolicies"]


# ---------------------------------------------------------------------------
# Synthetic cases
# ---------------------------------------------------------------------------


def test_no_framework_is_unavailable(host, tmp_path) -> None:
    host(tmp_path)
    out = detect.detect_crypto_policy()
    assert out["available"] is False
    assert "/etc/crypto-policies" in out["reason"]


def test_no_pq_subpolicy_is_reported(host, tmp_path) -> None:
    _write_tree(
        tmp_path,
        "DEFAULT:NO-PQ",
        "Groups = *X25519:secp256r1\nSignatureAlgorithms = ed25519\n",
    )
    host(tmp_path)
    out = detect.detect_crypto_policy()
    assert out["pq_disabled_by_subpolicy"] == ["NO-PQ"]
    assert out["pqc_enabled"]["tls_key_exchange"] is False


def test_unapplied_configuration(host, tmp_path) -> None:
    _write_tree(tmp_path, "DEFAULT", "Groups = X25519\n", config="DEFAULT:TEST-PQ")
    host(tmp_path)
    out = detect.detect_crypto_policy()
    assert out["active"] == "DEFAULT"
    assert out["configured"] == "DEFAULT:TEST-PQ"
    assert out["applied"] is False


@pytest.mark.parametrize(
    ("policy", "kernel", "expected"),
    [
        ("FIPS", "0", True),
        ("DEFAULT", "1", True),
        ("FIPS", "1", False),
        ("DEFAULT", "0", False),
    ],
)
def test_reboot_required_is_fips_mismatch(
    host, tmp_path, policy, kernel, expected
) -> None:
    _write_tree(tmp_path, policy, "Groups = X25519\n")
    (tmp_path / "proc/sys/crypto").mkdir(parents=True)
    (tmp_path / "proc/sys/crypto/fips_enabled").write_text(kernel + "\n")
    host(tmp_path)
    assert detect.detect_crypto_policy()["reboot_required"] is expected


def test_absolute_backend_symlinks_resolve_inside_the_host_prefix(
    host, tmp_path
) -> None:
    # Real hosts: back-ends/*.config -> /usr/share/crypto-policies/DEFAULT/*.txt.
    root = tmp_path / "host"
    _write_tree(root, "DEFAULT", "unused")
    link = root / "etc/crypto-policies/back-ends/opensslcnf.config"
    link.unlink()
    os.symlink("/usr/share/crypto-policies/DEFAULT/opensslcnf.txt", link)
    target = root / "usr/share/crypto-policies/DEFAULT/opensslcnf.txt"
    target.parent.mkdir(parents=True)
    target.write_text("Groups = *?X25519MLKEM768/*X25519\n")
    host(root)
    b = detect.detect_crypto_policy()["backends"]["opensslcnf"]
    assert b["readable"] is True
    assert b["pqc_groups"]["hybrid"] == ["X25519MLKEM768"]


def test_unmounted_symlink_target_is_unreadable_not_the_scanner_s_own(
    host, tmp_path
) -> None:
    # /usr/share not mounted under --host-mount: the link must not fall
    # through to the scanner's own /usr/share/crypto-policies (which exists
    # on Fedora / RHEL test machines).
    root = tmp_path / "host"
    _write_tree(root, "DEFAULT", "unused")
    link = root / "etc/crypto-policies/back-ends/opensslcnf.config"
    link.unlink()
    os.symlink("/usr/share/crypto-policies/DEFAULT/opensslcnf.txt", link)
    host(root)
    out = detect.detect_crypto_policy()
    assert out["backends"]["opensslcnf"] == {"readable": False}
    assert out["pqc_enabled"]["tls_key_exchange"] is None


def test_container_without_host_mount_is_annotated(monkeypatch) -> None:
    monkeypatch.setattr(pr._platform, "HOST_PREFIX", "")
    monkeypatch.setattr(
        pr.detect.runtime,
        "detect_runtime_environment",
        lambda: {"environment": "container"},
    )
    monkeypatch.setattr(detect, "_read_policy_file", lambda path, unreadable: None)
    out = detect.detect_crypto_policy()
    assert out["available"] is False
    assert out["unavailable_in_container"] is True


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------


def test_parse_policy_name() -> None:
    assert detect.parse_policy_name("DEFAULT:TEST-PQ:NO-SHA1\n") == {
        "active": "DEFAULT:TEST-PQ:NO-SHA1",
        "base_policy": "DEFAULT",
        "subpolicies": ["TEST-PQ", "NO-SHA1"],
    }
    assert detect.parse_policy_name("") == {
        "active": None,
        "base_policy": None,
        "subpolicies": [],
    }


def test_opensslcnf_keeps_preference_order_and_strips_markers() -> None:
    b = detect.parse_opensslcnf_backend(
        "Groups = *?X25519MLKEM768:?p256_mlkem768/*X25519:secp256r1\n"
        "SignatureAlgorithms = ?mldsa65:?p256_mldsa44:ed25519\n"
    )
    assert b["groups"] == ["X25519MLKEM768", "p256_mlkem768", "X25519", "secp256r1"]
    assert b["pqc_groups"] == {
        "hybrid": ["X25519MLKEM768", "p256_mlkem768"],
        "pure_pqc": [],
    }
    assert b["pqc_signature_algorithms"] == {
        "hybrid": ["p256_mldsa44"],
        "pure_pqc": ["mldsa65"],
    }


def test_nss_and_gnutls_spellings() -> None:
    nss = detect.parse_nss_backend(
        'config="disallow=ALL allow=mlkem768x25519:mlkem1024:CURVE25519"'
    )
    assert nss["pqc_groups"] == {
        "hybrid": ["mlkem768x25519"],
        "pure_pqc": ["mlkem1024"],
    }
    gn = detect.parse_gnutls_backend(
        "tls-enabled-group = GROUP-X25519-MLKEM768\nsecure-sig = ML-DSA-65\n"
    )
    assert gn["groups"] == ["X25519-MLKEM768"]
    assert gn["pqc_signature_algorithms"]["pure_pqc"] == ["ML-DSA-65"]


def test_openssh_backend_uses_three_bucket_classifier() -> None:
    b = detect.parse_openssh_backend(
        "KexAlgorithms mlkem768x25519-sha256,curve25519-sha256,diffie-hellman-group14-sha256\n"
    )
    assert b["kex_groups"]["hybrid"] == ["mlkem768x25519-sha256"]
    assert "curve25519-sha256" in b["kex_groups"]["classical"]


# ---------------------------------------------------------------------------
# Capable-but-blocked finding
# ---------------------------------------------------------------------------

CAPABLE_OPENSSL = {
    "available": True,
    "pqc_native": True,
    "tls_groups": {"hybrid": ["X25519MLKEM768"], "pure_pqc": []},
}


@pytest.mark.parametrize(
    ("tree", "blocked"),
    [("el9-default", True), ("el9-pq", False), ("el10-default", False)],
)
def test_policy_blocks_capable_pqc(host, tree, blocked) -> None:
    host(CP / tree)
    cp = detect.detect_crypto_policy()
    assert detect.policy_blocks_capable_pqc(cp, CAPABLE_OPENSSL) is blocked
    assert (
        detect.policy_blocks_capable_pqc(cp, {"available": True, "tls_groups": {}})
        is False
    )


def test_unavailable_policy_never_blocks() -> None:
    assert (
        detect.policy_blocks_capable_pqc({"available": False}, CAPABLE_OPENSSL) is False
    )


@pytest.mark.parametrize(
    ("tree", "expect_rule"), [("el9-default", True), ("el10-default", False)]
)
def test_sarif_and_text_surface_the_block(host, tree, expect_rule) -> None:
    host(CP / tree)
    r = pr.Report(
        hostname="h",
        openssl=CAPABLE_OPENSSL,
        crypto_policy=detect.detect_crypto_policy(),
    )
    ids = [f.rule_id for f in pr.render.sarif.build_findings(r)]
    assert ("pqc-008-crypto-policy-blocks-pqc" in ids) is expect_rule
    sarif = json.loads(pr.render.sarif.render_sarif(r))
    assert "pqc-008-crypto-policy-blocks-pqc" in [
        rule["id"] for rule in sarif["runs"][0]["tool"]["driver"]["rules"]
    ]
    text = pr.render.text.render_text(r)
    assert "Crypto policy: DEFAULT (applied)" in text
    assert ("policy keeps them out" in text) is expect_rule
    md = pr.render.text.render_markdown(r)
    assert "## System crypto policy" in md
