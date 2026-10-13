# SPDX-License-Identifier: Apache-2.0
"""Ubuntu crypto-config in `crypto_policy` (#170).

tests/fixtures/crypto_config/ubuntu2604-<profile>/ hold /var/lib/crypto-config
and /usr/share/crypto-config exactly as left by `crypto-config switch
<profile>` on a booted Ubuntu 26.04.1 cloud image with crypto-config
0.7.4-0ubuntu2 (2026-10-13), symlinks included (some absolute, into
/usr/share).  On that host `openssl list -tls-groups` and sshd's
KexAlgorithms were identical under all three profiles: no profile sets
TLS groups or touches OpenSSH.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import pqc_readiness as pr
from pqc_readiness import _platform
from pqc_readiness.detect import config_policy as cp
from pqc_readiness.render import text

FIXTURES = Path(__file__).parent / "fixtures" / "crypto_config"


@pytest.fixture
def ubuntu(monkeypatch):
    def _use(profile: str) -> dict:
        monkeypatch.setattr(
            _platform,
            "HOST_PREFIX",
            str((FIXTURES / f"ubuntu2604-{profile}").resolve()),
        )
        return cp.detect_crypto_policy()

    return _use


@pytest.mark.parametrize(
    ("profile", "settings", "seclevel", "parent"),
    [
        ("default", {}, None, "default"),
        (
            "future",
            {"MinProtocol": "TLSv1.3", "CipherString": "DEFAULT:@SECLEVEL=3"},
            3,
            "like-default",
        ),
        (
            "legacy",
            {
                "MinProtocol": "TLSv1.0 TLSv1.1 TLSv1.2 TLSv1.3",
                "CipherString": "DEFAULT:@SECLEVEL=1",
            },
            1,
            "default",
        ),
    ],
)
def test_measured_profiles(ubuntu, profile, settings, seclevel, parent) -> None:
    got = ubuntu(profile)
    assert got["available"] is True
    assert got["framework"] == "crypto-config"
    assert got["active"] == profile
    assert got["profile"]["parent"] == parent
    assert got["openssl"]["settings"] == settings
    assert got["openssl"]["seclevel"] == seclevel
    # No shipped profile sets TLS groups: PQC key exchange is the library
    # default, reported as unknown rather than "off".
    assert got["openssl"]["groups_configured"] is None
    assert got["pqc_enabled"]["tls_key_exchange"] is None


def test_available_profiles_include_namespaced(ubuntu) -> None:
    got = ubuntu("default")
    assert got["available_profiles"] == [
        "debian/test1",
        "default",
        "future",
        "legacy",
        "like-default",
    ]
    assert got["applications"] == [
        "apt.conf.d",
        "exim",
        "gnutls.conf",
        "nginx.conf.d",
        "openssl.conf.d",
    ]


def test_crypto_config_never_trips_pqc_008(ubuntu) -> None:
    got = ubuntu("future")
    openssl = {"tls_groups": {"hybrid": ["X25519MLKEM768"], "pure_pqc": []}}
    assert cp.policy_blocks_capable_pqc(got, openssl) is False


def _profile_tree(tmp_path: Path, snippet: str) -> Path:
    prof = tmp_path / "usr/share/crypto-config/profiles/custom"
    (prof / "openssl.conf.d").mkdir(parents=True)
    (prof / "openssl.conf.d" / "groups.cnf").write_text(snippet)
    (prof / "metadata.json").write_text('{"summary": "custom", "parent": "default"}')
    profiles = tmp_path / "var/lib/crypto-config/profiles"
    profiles.mkdir(parents=True)
    (profiles / "custom").symlink_to("/usr/share/crypto-config/profiles/custom")
    (profiles / "current").symlink_to("custom")
    return tmp_path


@pytest.mark.parametrize(
    ("groups", "tls_kex", "blocks"),
    [
        ("X25519MLKEM768:X25519", True, False),
        ("X25519:secp256r1", False, True),
    ],
)
def test_profile_that_sets_groups(
    tmp_path, monkeypatch, groups, tls_kex, blocks
) -> None:
    root = _profile_tree(
        tmp_path,
        f"[system_default_sect]\nGroups = {groups}\nCipherString = DEFAULT:@SECLEVEL=2\n",
    )
    monkeypatch.setattr(_platform, "HOST_PREFIX", str(root))
    got = cp.detect_crypto_policy()
    assert got["active"] == "custom"
    assert got["openssl"]["groups_configured"] == groups.split(":")
    assert got["pqc_enabled"]["tls_key_exchange"] is tls_kex
    openssl = {"tls_groups": {"hybrid": ["X25519MLKEM768"], "pure_pqc": []}}
    assert cp.policy_blocks_capable_pqc(got, openssl) is blocks


def test_bad_metadata_is_tolerated(tmp_path, monkeypatch) -> None:
    root = _profile_tree(tmp_path, "[s]\nMinProtocol = TLSv1.2\n")
    (root / "usr/share/crypto-config/profiles/custom/metadata.json").write_text(
        "{not json"
    )
    monkeypatch.setattr(_platform, "HOST_PREFIX", str(root))
    got = cp.detect_crypto_policy()
    assert got["profile"] == {"summary": None, "parent": None}
    assert got["openssl"]["settings"] == {"MinProtocol": "TLSv1.2"}


def test_neither_framework_is_unavailable(tmp_path, monkeypatch) -> None:
    # Stock Ubuntu 26.04 cloud image: crypto-config not installed.
    monkeypatch.setattr(_platform, "HOST_PREFIX", str(tmp_path))
    got = cp.detect_crypto_policy()
    assert got["available"] is False
    assert "/etc/crypto-policies" in got["reason"]
    assert "/var/lib/crypto-config" in got["reason"]


def test_crypto_policies_hosts_report_their_framework(monkeypatch) -> None:
    monkeypatch.setattr(
        _platform,
        "HOST_PREFIX",
        str(
            (
                Path(__file__).parent / "fixtures" / "crypto_policies" / "el9-default"
            ).resolve()
        ),
    )
    assert cp.detect_crypto_policy()["framework"] == "crypto-policies"


def test_text_render(ubuntu) -> None:
    r = pr.Report(
        generated_at="x",
        hostname="h",
        os="Ubuntu 26.04",
        arch="x86_64",
        crypto_policy=ubuntu("future"),
    )
    lines = text._render_text_crypto_policy(r)
    assert "crypto-config profile future" in lines[0]
    assert "SECLEVEL 3" in lines[0]
    assert "library default" in lines[1]
