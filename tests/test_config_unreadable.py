# SPDX-License-Identifier: Apache-2.0
"""Absent vs unreadable host config files (#232).

RHCOS ships /etc/ssh/sshd_config as 0600 root; the base DaemonSet runs as
UID 1001 and used to report "no sshd_config found", which made the SSH gap
row `not_present` and kept pqc-010 from ever firing.  These tests make the
files unreadable with chmod, so they skip when run as root (root reads
them anyway).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from pqc_readiness import _platform, gap
from pqc_readiness.detect import config_openssl as co
from pqc_readiness.detect import config_policy as cpol
from pqc_readiness.detect import config_read as cr
from pqc_readiness.detect import config_services as cs
from pqc_readiness.detect import config_sshd

pytestmark = pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0,
    reason="root can read mode-000 files",
)


def _tree(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        f = root / rel.lstrip("/")
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text)
    return root


@pytest.fixture
def locked():
    """chmod paths to `mode`, restoring 0755/0644 at teardown so pytest
    can clean tmp_path."""
    changed: list[Path] = []

    def _lock(p: Path, mode: int = 0o000) -> None:
        p.chmod(mode)
        changed.append(p)

    yield _lock
    for p in reversed(changed):
        p.chmod(0o755 if p.is_dir() else 0o644)


@pytest.fixture
def host(monkeypatch, tmp_path):
    monkeypatch.setattr(_platform, "HOST_PREFIX", str(tmp_path))
    monkeypatch.setattr(_platform, "_run", lambda cmd, timeout=None: (1, ""))
    return tmp_path


# ---------------------------------------------------------------------------
# The shared reader
# ---------------------------------------------------------------------------


def test_reader_absent_returns_none(host) -> None:
    assert cr.read_host_text("/etc/nope.conf") is None
    assert cr.list_host_dir("/etc/nope.d") is None
    assert cr.present("/etc/nope.conf") is False
    assert cr.probe("/etc/nope.conf") is None


def test_reader_unreadable_raises_with_reason(host, locked) -> None:
    _tree(host, {"/etc/a.conf": "x\n"})
    locked(host / "etc/a.conf")
    with pytest.raises(cr.ConfigUnreadable) as e:
        cr.read_host_text("/etc/a.conf")
    assert e.value.path == "/etc/a.conf"
    assert e.value.reason.startswith("permission denied")
    assert cr.PERMISSION_HINT in e.value.reason
    assert cr.present("/etc/a.conf") is True


def test_reader_unsearchable_parent_is_unreadable_not_absent(host, locked) -> None:
    # stat() of a file under a 000 directory raises EACCES; on Python
    # <= 3.12 Path.exists() propagates it.  Either way: unreadable.
    _tree(host, {"/etc/priv/a.conf": "x\n"})
    locked(host / "etc/priv")
    assert cr.present("/etc/priv/a.conf") is True
    with pytest.raises(cr.ConfigUnreadable):
        cr.read_host_text("/etc/priv/a.conf")
    assert cr.probe("/etc/priv/a.conf") is not None


def test_reader_caps_by_default(host) -> None:
    # Callers that pass no limit (crypto-policies, openssl.cnf) are still
    # bounded: a hostile --root tree can't make the scan read a huge file.
    _tree(host, {"/etc/huge.conf": "x" * (cr.DEFAULT_MAX_BYTES + 1)})
    with pytest.raises(cr.ConfigUnreadable, match="larger than"):
        cr.read_host_text("/etc/huge.conf")


def test_reader_keeps_universal_newlines(host) -> None:
    (host / "etc").mkdir()
    (host / "etc/crlf.conf").write_bytes(b"a\r\nb\rc\n")
    assert cr.read_host_text("/etc/crlf.conf") == "a\nb\nc\n"


def test_reader_size_cap(host) -> None:
    _tree(host, {"/etc/big.conf": "x" * 100})
    with pytest.raises(cr.ConfigUnreadable, match="larger than 10 bytes"):
        cr.read_host_text("/etc/big.conf", max_bytes=10)


# ---------------------------------------------------------------------------
# sshd
# ---------------------------------------------------------------------------


def test_unreadable_sshd_config_is_not_reported_absent(host, locked) -> None:
    _tree(host, {"/etc/ssh/sshd_config": "KexAlgorithms curve25519-sha256\n"})
    locked(host / "etc/ssh/sshd_config")
    got = config_sshd.detect_sshd({})
    assert got["available"] is False
    assert "not readable" in got["reason"]
    assert "no sshd_config found" not in got["reason"]
    assert got["unreadable"][0]["path"] == "/etc/ssh/sshd_config"


def test_unreadable_etc_sshd_config_does_not_fall_back_to_vendor(host, locked) -> None:
    # sshd reads /etc/ssh/sshd_config whenever it exists; the SUSE vendor
    # file is only used when it's absent.
    _tree(
        host,
        {
            "/etc/ssh/sshd_config": "KexAlgorithms curve25519-sha256\n",
            "/usr/etc/ssh/sshd_config": "KexAlgorithms mlkem768x25519-sha256\n",
        },
    )
    locked(host / "etc/ssh/sshd_config")
    got = config_sshd.detect_sshd({})
    assert got["available"] is False
    assert got["unreadable"][0]["path"] == "/etc/ssh/sshd_config"


def test_unreadable_include_before_kex_makes_kex_unknown(host, locked) -> None:
    _tree(
        host,
        {
            "/etc/ssh/sshd_config": (
                "Include /etc/ssh/sshd_config.d/*.conf\n"
                "KexAlgorithms curve25519-sha256\n"
            ),
            "/etc/ssh/sshd_config.d/50-policy.conf": "KexAlgorithms mlkem768x25519-sha256\n",
        },
    )
    locked(host / "etc/ssh/sshd_config.d")
    got = config_sshd.detect_sshd({})
    assert got["available"] is True
    assert got["kex_source"] == "unreadable-config"
    assert got["kex_offered"] is None and got["pqc_offered"] is None
    assert got["unreadable"][0]["path"] == "/etc/ssh/sshd_config.d"


def test_unreadable_include_after_kex_keeps_value(host, locked) -> None:
    # First obtained value wins, so a later unreadable file can't change it.
    _tree(
        host,
        {
            "/etc/ssh/sshd_config": (
                "KexAlgorithms mlkem768x25519-sha256\nInclude /etc/ssh/extra.conf\n"
            ),
            "/etc/ssh/extra.conf": "KexAlgorithms curve25519-sha256\n",
        },
    )
    locked(host / "etc/ssh/extra.conf")
    got = config_sshd.detect_sshd({})
    assert got["kex_source"] == "configured"
    assert got["pqc_offered"] is True
    assert got["unreadable"] == [
        {"path": "/etc/ssh/extra.conf", "reason": got["unreadable"][0]["reason"]}
    ]


def test_ssh_gap_is_unknown_not_absent_when_config_unreadable(host, locked) -> None:
    _tree(host, {"/etc/ssh/sshd_config": "KexAlgorithms curve25519-sha256\n"})
    locked(host / "etc/ssh/sshd_config")
    report: dict[str, Any] = {
        "sshd": config_sshd.detect_sshd({}),
        "ssh_pqc": {"available": False},
    }
    row = gap._ssh(report)
    assert row["state"] == "unknown"
    assert "not readable" in row["note"]


def test_ssh_gap_absent_when_no_config_and_no_client(host) -> None:
    report: dict[str, Any] = {
        "sshd": config_sshd.detect_sshd({}),
        "ssh_pqc": {"available": False},
    }
    assert report["sshd"]["reason"].startswith("no sshd_config found")
    assert gap._ssh(report)["state"] == "not_present"


# ---------------------------------------------------------------------------
# crypto-policies
# ---------------------------------------------------------------------------


def test_unreadable_crypto_policy_state(host, locked) -> None:
    _tree(
        host,
        {
            "/etc/crypto-policies/state/current": "DEFAULT\n",
            "/etc/crypto-policies/config": "DEFAULT\n",
        },
    )
    locked(host / "etc/crypto-policies/state/current")
    locked(host / "etc/crypto-policies/config")
    got = cpol.detect_crypto_policy()
    assert got["available"] is False
    assert "not readable" in got["reason"]
    assert {u["path"] for u in got["unreadable"]} == {
        "/etc/crypto-policies/state/current",
        "/etc/crypto-policies/config",
    }


def test_unreadable_backend_gets_reason_absent_does_not(host, locked) -> None:
    _tree(
        host,
        {
            "/etc/crypto-policies/state/current": "DEFAULT\n",
            "/etc/crypto-policies/config": "DEFAULT\n",
            "/etc/crypto-policies/back-ends/opensshserver.config": "KexAlgorithms x\n",
        },
    )
    locked(host / "etc/crypto-policies/back-ends/opensshserver.config")
    got = cpol.detect_crypto_policy()
    assert got["available"] is True
    assert got["backends"]["opensshserver"]["readable"] is False
    assert "permission denied" in got["backends"]["opensshserver"]["reason"]
    assert got["backends"]["gnutls"] == {"readable": False}
    assert got["unreadable"][0]["path"].endswith("opensshserver.config")


# ---------------------------------------------------------------------------
# openssl.cnf
# ---------------------------------------------------------------------------


def test_unreadable_openssl_cnf(host, locked) -> None:
    _tree(host, {"/etc/pki/tls/openssl.cnf": "[openssl_init]\n"})
    locked(host / "etc/pki/tls/openssl.cnf")
    got = co.detect_openssl_config({"family": "rhel"}, [3, 5, 0])
    assert got["available"] is False
    assert "not readable" in got["reason"]
    assert got["unreadable"][0]["path"] == "/etc/pki/tls/openssl.cnf"


def test_unreadable_openssl_include_listed(host, locked) -> None:
    _tree(
        host,
        {
            "/etc/pki/tls/openssl.cnf": ".include /etc/pki/tls/openssl.d\n[x]\na = b\n",
            "/etc/pki/tls/openssl.d/10.cnf": "[y]\nc = d\n",
        },
    )
    locked(host / "etc/pki/tls/openssl.d")
    got = co.detect_openssl_config({"family": "rhel"}, [3, 5, 0])
    assert got["available"] is True
    assert "/etc/pki/tls/openssl.d" in got["include_errors"]
    assert got["unreadable"][0]["path"] == "/etc/pki/tls/openssl.d"


# ---------------------------------------------------------------------------
# Service TLS configs (#216)
# ---------------------------------------------------------------------------


def test_service_config_missing_and_unreadable_are_split(
    host, locked, monkeypatch
) -> None:
    _tree(
        host,
        {
            "/etc/nginx/nginx.conf": (
                "include /etc/nginx/absent.conf;\n"
                "include /etc/nginx/locked.conf;\n"
                "http { server { listen 443 ssl; ssl_ecdh_curve X25519; } }\n"
            ),
            "/etc/nginx/locked.conf": "# private\n",
        },
    )
    locked(host / "etc/nginx/locked.conf")
    monkeypatch.setattr(cs, "_version", lambda spec, family: None)
    stc = cs.scan_service_configs({"family": "rhel"}, {"pqc_native": True})
    nginx = next(s for s in stc["services"] if s["service"] == "nginx")
    assert nginx["missing"] == ["/etc/nginx/absent.conf"]
    assert [u["path"] for u in nginx["unreadable"]] == ["/etc/nginx/locked.conf"]
    assert nginx["unreadable"][0]["reason"].startswith("permission denied")
    assert stc["summary"]["unreadable"] == ["/etc/nginx/locked.conf"]


def test_service_present_behind_unsearchable_dir(host, locked) -> None:
    _tree(host, {"/etc/priv/a.conf": "x\n"})
    locked(host / "etc/priv")
    assert cs._exists("/etc/priv/a.conf") is True
    assert cs.read_error("/etc/priv/a.conf") is not None
