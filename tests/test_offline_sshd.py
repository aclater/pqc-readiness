# SPDX-License-Identifier: Apache-2.0
"""Offline --root scans report sshd's effective key exchange (#247).

The config files are parsed under the root (never `sshd -T`), and the
OpenSSH build's kex methods are read from its binaries in place of
`ssh -Q kex`.  Expected values come from the same booted images: see
tests/fixtures/sshd/openssh-binaries/README.md.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

import pqc_readiness as pr
from pqc_readiness import cli
from pqc_readiness.detect import openssh_build as ob
from pqc_readiness.detect import protocols as _protocols

FIXTURES = Path(__file__).parent / "fixtures" / "sshd"
BINARIES = FIXTURES / "openssh-binaries"
SERVER_BINARY = {
    "rocky9": "usr/libexec/openssh/sshd-session",
    "fedora44": "usr/libexec/openssh/sshd-session",
    "ubuntu2604": "usr/lib/openssh/sshd-session",
    "leap16": "usr/libexec/ssh/sshd-session",
    "tumbleweed": "usr/libexec/ssh/sshd-session",
}


@pytest.fixture(autouse=True)
def live_start(monkeypatch: pytest.MonkeyPatch) -> None:
    """Start live; monkeypatch restores whatever --root set."""
    monkeypatch.setattr(pr._platform, "HOST_PREFIX", "")
    monkeypatch.setattr(pr._platform, "OFFLINE_ROOT", "")


@pytest.fixture
def no_subprocess(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    calls: list[list[str]] = []

    def refuse(cmd: list[str], timeout: int = 10) -> tuple[int, str]:
        calls.append(cmd)
        return 127, "subprocess refused in offline test"

    monkeypatch.setattr(pr._platform, "_run", refuse)
    return calls


def _kex_line(path: Path) -> list[str]:
    for line in path.read_text().splitlines():
        key, _, value = line.partition(" ")
        if key.lower() == "kexalgorithms":
            return value.split(",")
    raise AssertionError(f"no kexalgorithms in {path}")


def _pqc(names: list[str]) -> list[str]:
    g = _protocols.classify_ssh_kex(names)
    return sorted(g["hybrid"] + g["pure_pqc"])


def _tree(tmp_path: Path, config_from: str | None, binary_from: str | None) -> Path:
    root = tmp_path / "root"
    root.mkdir()
    if config_from:
        shutil.copytree(FIXTURES / config_from / "root", root, dirs_exist_ok=True)
    if binary_from:
        target = root / SERVER_BINARY[binary_from]
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(BINARIES / binary_from / "sshd-session.strings", target)
    return root


def _scan(capsys: pytest.CaptureFixture[str], root: Path) -> dict:
    assert cli.main(["--root", str(root), "--json"]) == 0
    return json.loads(capsys.readouterr().out)


# ------------------------------------------------------------- build strings


@pytest.mark.parametrize("distro", sorted(SERVER_BINARY))
def test_binary_pqc_kex_matches_ssh_q_kex(distro: str) -> None:
    """The PQC methods read from the real binary equal what that build's
    `ssh -Q kex` prints, backports included (Rocky 9's 9.9p1 build and
    Fedora's extra ML-KEM NIST-curve hybrids)."""
    data = (BINARIES / distro / "sshd-session.strings").read_bytes()
    expected = [
        line.strip()
        for line in (BINARIES / distro / "ssh-Q-kex.txt").read_text().splitlines()
        if line.strip()
    ]
    assert _pqc(sorted(ob.kex_names_in(data))) == _pqc(expected)


@pytest.mark.parametrize("distro", ["ubuntu2604", "leap16", "tumbleweed"])
def test_single_kex_list_is_the_compiled_default(distro: str, tmp_path: Path) -> None:
    root = _tree(tmp_path, None, distro)
    pr._platform.set_host_prefix(str(root))
    got = ob.compiled_default_kex()
    assert got is not None
    assert got["kex"] == _kex_line(BINARIES / distro / "sshd-T-defaults-kex.txt")
    assert got["binary"] == "/" + SERVER_BINARY[distro]


@pytest.mark.parametrize("distro", ["rocky9", "fedora44"])
def test_several_kex_lists_leave_the_default_unknown(
    distro: str, tmp_path: Path
) -> None:
    """EL builds carry FIPS and ML-KEM-only lists next to the default; no
    rule picks the right one, so the default stays unknown."""
    data = (BINARIES / distro / "sshd-session.strings").read_bytes()
    assert len(ob.kex_lists_in(data)) > 1
    root = _tree(tmp_path, None, distro)
    pr._platform.set_host_prefix(str(root))
    assert ob.compiled_default_kex() is None


def test_cipher_and_mac_lists_are_not_kex_lists() -> None:
    data = (BINARIES / "ubuntu2604" / "sshd-session.strings").read_bytes()
    assert b"chacha20-poly1305@openssh.com," in data
    for items in ob.kex_lists_in(data):
        assert not any("chacha20" in i or "hmac-" in i for i in items)


def test_no_binary_means_no_build_evidence(tmp_path: Path) -> None:
    root = _tree(tmp_path, "rocky9", None)
    pr._platform.set_host_prefix(str(root))
    assert ob.openssh_build_kex() is None


# ----------------------------------------------------------- offline reports


def test_offline_scan_parses_the_trees_sshd_config(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], no_subprocess: list
) -> None:
    """Regression for #247: offline reports had `"sshd": {}`."""
    root = _tree(tmp_path, "rocky9", "rocky9")
    r = _scan(capsys, root)
    s = r["sshd"]
    assert no_subprocess == [], "offline scan ran sshd or ssh"
    assert s["available"] is True
    assert s["source"] == "config files"
    assert s["kex_source"] == "configured"
    # Same list, same order as the booted image's `sshd -T`.
    assert s["kex_offered"] == _kex_line(FIXTURES / "rocky9" / "sshd-T.txt")
    assert "/etc/crypto-policies/back-ends/opensshserver.config" in s["config_files"]
    assert s["pqc_offered"] is False
    assert s["openssh_supports_pqc_kex"] is True
    assert s["openssh_kex_evidence"]["source"] == "binary"
    assert "mlkem768x25519-sha256" in s["openssh_kex_evidence"]["pqc_kex"]
    gap = r["pqc_deployment_gap"]
    ssh = gap.get("protocols", gap)["ssh"]
    assert ssh["state"] == "capable_not_configured"


def test_offline_capable_not_offered_raises_pqc_010(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _tree(tmp_path, "rocky9", "rocky9")
    assert cli.main(["--root", str(root), "--sarif"]) == 0
    sarif = json.loads(capsys.readouterr().out)
    rules = [res["ruleId"] for run in sarif["runs"] for res in run["results"]]
    assert "pqc-010-sshd-pqc-kex-not-offered" in rules


def test_offline_compiled_default_comes_from_the_binary(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Ubuntu 26.04 sets no KexAlgorithms: the default read from its
    binary equals that image's `sshd -T`."""
    root = _tree(tmp_path, "ubuntu2604", "ubuntu2604")
    s = _scan(capsys, root)["sshd"]
    assert s["kex_source"] == "openssh-compiled-default"
    assert s["kex_default_source"] == {
        "source": "binary",
        "binary": "/usr/lib/openssh/sshd-session",
    }
    assert s["kex_offered"] == _kex_line(FIXTURES / "ubuntu2604" / "sshd-T.txt")
    assert s["pqc_offered"] is True and s["pqc_first"] is True


def test_offline_default_stays_unknown_without_a_binary(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _tree(tmp_path, "ubuntu2604", None)
    s = _scan(capsys, root)["sshd"]
    assert s["kex_source"] == "openssh-compiled-default"
    assert s["kex_offered"] is None
    assert "kex_default_source" not in s
    assert s["openssh_supports_pqc_kex"] is None


def test_text_report_says_the_default_was_read_from_the_binary(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _tree(tmp_path, "ubuntu2604", "ubuntu2604")
    assert cli.main(["--root", str(root)]) == 0
    out = capsys.readouterr().out
    assert "compiled-in default read from the OpenSSH binary" in out


def test_includes_and_symlinks_stay_inside_the_root(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A `..` Include and an absolute symlink must resolve inside the tree,
    never to the scanner's own files."""
    outside = tmp_path / "outside.conf"
    outside.write_text("KexAlgorithms mlkem768x25519-sha256\n")
    root = tmp_path / "root"
    ssh = root / "etc/ssh"
    (ssh / "sshd_config.d").mkdir(parents=True)
    (ssh / "sshd_config").write_text(
        "Include ../../../../outside.conf\n"
        "Include /etc/ssh/sshd_config.d/*.conf\n"
        "KexAlgorithms curve25519-sha256\n"
    )
    (ssh / "sshd_config.d/10-link.conf").symlink_to(str(outside))
    s = _scan(capsys, root)["sshd"]
    assert s["kex_offered"] == ["curve25519-sha256"]
    assert str(outside) not in json.dumps(s)


def test_live_scans_never_use_build_strings(monkeypatch: pytest.MonkeyPatch) -> None:
    """Live: the `ssh -Q kex` probe stays the evidence; no binary scan."""
    called: list[str] = []
    monkeypatch.setattr(ob, "openssh_build_kex", lambda: called.append("x"))
    probe = {"available": True, "kex_groups": {"hybrid": ["mlkem768x25519-sha256"]}}
    s = pr.detect_sshd(probe)
    assert called == []
    assert "openssh_kex_evidence" not in s
