# SPDX-License-Identifier: Apache-2.0
"""sshd effective configuration (#105).

Fixtures under tests/fixtures/sshd/<distro>/ were captured from booted
official cloud images on 2026-10-13: `sshd -T`, `ssh -Q kex`, and only
the public material sshd's config chain reads (sshd_config, its Include
targets, the crypto-policies OpenSSH back-ends, ssh_host_*_key.pub).
No private host keys were captured.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

import pqc_readiness as pr
from pqc_readiness import _platform
from pqc_readiness.detect import config_sshd

FIXTURES = Path(__file__).parent / "fixtures" / "sshd"
DISTROS = ["fedora44", "rocky9", "rocky10", "alma10", "stream10", "leap16"]


def _client(distro: str) -> dict:
    return pr.parse_ssh_kex((FIXTURES / distro / "ssh-Q-kex.txt").read_text())


@pytest.fixture
def host(monkeypatch):
    def _use(distro: str) -> None:
        monkeypatch.setattr(
            _platform, "HOST_PREFIX", str((FIXTURES / distro / "root").resolve())
        )

    return _use


@pytest.mark.parametrize("distro", DISTROS)
def test_config_file_parse_matches_real_sshd_t(host, distro: str) -> None:
    # The file-parsing fallback must reproduce sshd's own effective
    # KexAlgorithms, Include chain and all, on every measured distro.
    host(distro)
    got = config_sshd.detect_sshd(_client(distro))
    real = pr.parse_sshd_t((FIXTURES / distro / "sshd-T.txt").read_text())
    assert got["source"] == "config files"
    assert got["kex_offered"] == real["values"]["kexalgorithms"].split(",")


@pytest.mark.parametrize(
    ("distro", "first", "pqc_first", "gap"),
    [
        ("fedora44", "mlkem768x25519-sha256", True, None),
        ("rocky10", "mlkem768x25519-sha256", True, None),
        ("alma10", "mlkem768x25519-sha256", True, None),
        ("stream10", "mlkem768x25519-sha256", True, None),
        # Leap 16 prefers the NTRU Prime hybrid; still PQC first.
        ("leap16", "sntrup761x25519-sha512", True, None),
        # Rocky 9.8 DEFAULT policy: client supports ML-KEM, sshd offers none.
        ("rocky9", "curve25519-sha256", False, "not_offered"),
    ],
)
def test_measured_outcomes(host, distro, first, pqc_first, gap) -> None:
    host(distro)
    got = config_sshd.detect_sshd(_client(distro))
    assert got["first_kex"] == first
    assert got["pqc_first"] is pqc_first
    assert config_sshd.sshd_pqc_gap(got) == gap
    assert got["openssh_supports_pqc_kex"] is True


def test_rfc_10042_references_attached(host) -> None:
    host("fedora44")
    got = config_sshd.detect_sshd(_client("fedora44"))
    refs = got["kex_references"]
    assert refs["mlkem768x25519-sha256"]["reference"] == "RFC 10042"
    assert refs["mlkem1024nistp384-sha384"]["cnsa_2_0"] is True


def test_leap16_reads_vendor_config_under_host_mount(host) -> None:
    # No /etc/ssh/sshd_config on Leap 16: sshd reads /usr/etc/ssh, which
    # must be redirected under --host-mount like /etc (#105).
    host("leap16")
    got = config_sshd.detect_sshd(_client("leap16"))
    assert got["config_files"][0] == "/usr/etc/ssh/sshd_config"
    assert (
        got["config_files"][-1] == "/etc/crypto-policies/back-ends/opensshserver.config"
    )


def test_usr_etc_is_a_host_namespace(monkeypatch) -> None:
    monkeypatch.setattr(_platform, "HOST_PREFIX", "/host")
    assert (
        str(_platform.host_path("/usr/etc/ssh/sshd_config"))
        == "/host/usr/etc/ssh/sshd_config"
    )


@pytest.mark.parametrize(
    ("name", "bits", "fingerprint"),
    [
        # Expected values from `ssh-keygen -lf` on the same files.
        (
            "ssh_host_rsa_key.pub",
            3072,
            "SHA256:bQrCkI7l/xQhkn83ecgIEGX600PnzWeXodLGlZFsUUI",
        ),
        (
            "ssh_host_ecdsa_key.pub",
            256,
            "SHA256:UA5lnA6BGOerjmSuMIVCDIQUDrAJTyX6fiiGtlrovLA",
        ),
        (
            "ssh_host_ed25519_key.pub",
            256,
            "SHA256:0DbThYgAxkZVm/Te5E3GPcrDCQAzSjHtf+m2FkaiGUk",
        ),
    ],
)
def test_public_key_matches_ssh_keygen(name, bits, fingerprint) -> None:
    d = pr.describe_public_key(
        (FIXTURES / "rocky9" / "root" / "etc" / "ssh" / name).read_text()
    )
    assert d["bits"] == bits
    assert d["fingerprint_sha256"] == fingerprint
    assert d["pqc"] is False
    assert "comment" not in d


def test_private_host_keys_are_never_opened(host, monkeypatch) -> None:
    host("rocky9")
    real = config_sshd._read_host_file
    read: list[str] = []

    def spy(path: str):
        read.append(path)
        return real(path)

    monkeypatch.setattr(config_sshd, "_read_host_file", spy)
    got = config_sshd.detect_sshd(_client("rocky9"))
    assert [k["path"] for k in got["host_keys"]] == list(config_sshd.DEFAULT_HOST_KEYS)
    key_reads = [p for p in read if "ssh_host_" in p]
    assert key_reads and all(p.endswith(".pub") for p in key_reads)


def _tree(tmp_path: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        f = tmp_path / rel.lstrip("/")
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text)
    return tmp_path


def _detect(monkeypatch, root: Path, client: dict | None = None) -> dict:
    monkeypatch.setattr(_platform, "HOST_PREFIX", str(root))
    return config_sshd.detect_sshd(client or {})


def test_first_value_wins_and_relative_include(tmp_path, monkeypatch) -> None:
    root = _tree(
        tmp_path,
        {
            "/etc/ssh/sshd_config": "Include conf.d/*.conf\nKexAlgorithms curve25519-sha256\n",
            "/etc/ssh/conf.d/10-a.conf": "KexAlgorithms=mlkem768x25519-sha256,curve25519-sha256\n",
            "/etc/ssh/conf.d/20-b.conf": "KexAlgorithms ecdh-sha2-nistp256\n",
        },
    )
    got = _detect(monkeypatch, root)
    assert got["kex_offered"] == ["mlkem768x25519-sha256", "curve25519-sha256"]
    assert got["config_files"][1].endswith("10-a.conf")


def test_match_block_options_are_ignored(tmp_path, monkeypatch) -> None:
    root = _tree(
        tmp_path,
        {
            "/etc/ssh/sshd_config": "Match User backup\n  KexAlgorithms curve25519-sha256\n"
        },
    )
    got = _detect(monkeypatch, root)
    assert got["kex_offered"] is None
    assert got["kex_source"] == "openssh-compiled-default"


def test_relative_modifier_is_not_guessed(tmp_path, monkeypatch) -> None:
    root = _tree(
        tmp_path, {"/etc/ssh/sshd_config": "KexAlgorithms +sntrup761x25519-sha512\n"}
    )
    got = _detect(monkeypatch, root)
    assert got["kex_offered"] is None
    assert got["kex_modifier"] == {
        "operator": "+",
        "algorithms": ["sntrup761x25519-sha512"],
    }
    assert config_sshd.sshd_pqc_gap(got) is None


def test_include_loop_is_bounded(tmp_path, monkeypatch) -> None:
    root = _tree(tmp_path, {"/etc/ssh/sshd_config": "Include /etc/ssh/sshd_config\n"})
    got = _detect(monkeypatch, root)
    assert got["available"] is True
    assert len(got["config_files"]) == config_sshd._MAX_INCLUDE_DEPTH + 1


def test_offered_but_not_first(tmp_path, monkeypatch) -> None:
    root = _tree(
        tmp_path,
        {
            "/etc/ssh/sshd_config": "KexAlgorithms curve25519-sha256,mlkem768x25519-sha256\n"
        },
    )
    got = _detect(monkeypatch, root, _client("fedora44"))
    assert config_sshd.sshd_pqc_gap(got) == "not_first"


def test_no_gap_when_openssh_lacks_pqc(tmp_path, monkeypatch) -> None:
    root = _tree(
        tmp_path, {"/etc/ssh/sshd_config": "KexAlgorithms curve25519-sha256\n"}
    )
    client = pr.parse_ssh_kex("curve25519-sha256\necdh-sha2-nistp256\n")
    got = _detect(monkeypatch, root, client)
    assert got["openssh_supports_pqc_kex"] is False
    assert config_sshd.sshd_pqc_gap(got) is None


def test_missing_config_is_unavailable(tmp_path, monkeypatch) -> None:
    got = _detect(monkeypatch, tmp_path)
    assert got == {
        "available": False,
        "reason": "no sshd_config found (/etc/ssh or /usr/etc/ssh)",
    }


def test_sshd_t_preferred_as_root_without_host_mount(monkeypatch) -> None:
    text = (FIXTURES / "rocky9" / "sshd-T.txt").read_text()
    calls: list[list[str]] = []

    def fake_run(cmd, timeout=None):  # noqa: ARG001
        calls.append(cmd)
        return 0, text

    monkeypatch.setattr(_platform, "HOST_PREFIX", "")
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(config_sshd.shutil, "which", lambda name: f"/usr/sbin/{name}")
    monkeypatch.setattr(_platform, "_run", fake_run)
    monkeypatch.setattr(config_sshd, "inventory_host_keys", lambda paths: [])
    got = config_sshd.detect_sshd(_client("rocky9"))
    assert calls == [["/usr/sbin/sshd", "-T"]]
    assert got["source"] == "sshd -T"
    assert got["pqc_offered"] is False


def test_sshd_t_skipped_under_host_mount(host, monkeypatch) -> None:
    host("rocky9")
    monkeypatch.setattr(os, "geteuid", lambda: 0)

    def no_run(cmd, timeout=None):  # noqa: ARG001
        raise AssertionError("sshd -T must not run against --host-mount")

    monkeypatch.setattr(_platform, "_run", no_run)
    assert config_sshd.detect_sshd(_client("rocky9"))["source"] == "config files"


def _report(sshd: dict) -> pr.Report:
    return pr.Report(
        generated_at="2026-10-13T12:00:00+00:00",
        hostname="testhost.example",
        os="Rocky Linux 9.8",
        arch="x86_64",
        sshd=sshd,
    )


def test_sarif_pqc_010_warns_when_not_offered(host) -> None:
    host("rocky9")
    findings = pr.build_findings(_report(config_sshd.detect_sshd(_client("rocky9"))))
    (f,) = [f for f in findings if f.rule_id == "pqc-010-sshd-pqc-kex-not-offered"]
    assert f.level == "warning"
    assert f.properties["sshd:gap"] == "not_offered"
    assert "curve25519-sha256" in f.message


def test_sarif_pqc_010_note_when_not_first(tmp_path, monkeypatch) -> None:
    root = _tree(
        tmp_path,
        {
            "/etc/ssh/sshd_config": "KexAlgorithms curve25519-sha256,mlkem768x25519-sha256\n"
        },
    )
    findings = pr.build_findings(
        _report(_detect(monkeypatch, root, _client("fedora44")))
    )
    (f,) = [f for f in findings if f.rule_id == "pqc-010-sshd-pqc-kex-not-offered"]
    assert f.level == "note"


def test_sarif_pqc_010_silent_when_pqc_first(host) -> None:
    host("fedora44")
    findings = pr.build_findings(_report(config_sshd.detect_sshd(_client("fedora44"))))
    assert not [f for f in findings if f.rule_id == "pqc-010-sshd-pqc-kex-not-offered"]
    from pqc_readiness.render import sarif

    assert "pqc-010-sshd-pqc-kex-not-offered" in sarif.SECURITY_SEVERITY
