# SPDX-License-Identifier: Apache-2.0
"""An offline --root scan never describes the scanning machine (#258).

Two ways the scanner's own facts used to reach a report about a tree:

* live-host APIs: the OS fell back to `platform.system() release()`, the
  package manager came from `shutil.which` on the scanner's PATH, and repo
  `$basearch` from `platform.machine()`;
* absolute symlinks inside the tree, which the OS follows onto the
  scanner's filesystem (/etc/os-release -> /usr/lib/os-release read this
  machine's OS).

The guard tests run whole offline scans with every live-host API spied on,
and with links whose absolute targets exist on this machine.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import platform
import shutil
import socket
import struct
import sys
from pathlib import Path
from typing import Any, Callable

import pytest

import pqc_readiness as pr
from pqc_readiness import cli
from pqc_readiness.detect import osinfo
from pqc_readiness.detect import packages
from pqc_readiness.detect import protocols_signing as signing

FIXTURES = Path(__file__).parent / "fixtures"
EMBEDDED = FIXTURES / "embedded"

# Every --scan-* flag that --root accepts.
OFFLINE_SCANS = [
    "--scan-trust-store",
    "--scan-packages",
    "--scan-crypto-material",
    "--scan-signing-keys",
    "--scan-crypto-libraries",
    "--scan-kerberos",
    "--scan-tunnels",
    "--scan-dnssec",
    "--scan-service-configs",
]
FORMATS: list[list[str]] = [
    [],
    ["--json"],
    ["--markdown"],
    ["--cbom"],
    ["--spdx"],
    ["--sarif"],
    ["--prometheus"],
    ["--ndjson"],
    ["--sbom"],
    ["--ansible"],
]


def _write(path: Path, data: bytes | str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, str):
        path.write_text(data)
    else:
        path.write_bytes(data)
    return path


def _elf_header(machine: int) -> bytes:
    ident = b"\x7fELF" + bytes([2, 1, 1]) + b"\0" * 9
    return ident + struct.pack("<HH", 2, machine) + b"\0" * 44


@pytest.fixture(autouse=True)
def _live_start(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every test starts live; monkeypatch restores what --root set."""
    monkeypatch.setattr(pr._platform, "HOST_PREFIX", "")
    monkeypatch.setattr(pr._platform, "OFFLINE_ROOT", "")


@pytest.fixture
def live_host_calls(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Record every live-host API call made from pqc_readiness code:
    platform.*, os.uname, socket host names, shutil.which and subprocess."""
    calls: list[str] = []

    def spy(name: str, orig: Callable[..., Any]) -> Callable[..., Any]:
        def wrapper(*a: Any, **k: Any) -> Any:
            caller = sys._getframe(1).f_globals.get("__name__", "")
            if caller.startswith("pqc_readiness"):
                calls.append(f"{name} from {caller}")
            return orig(*a, **k)

        return wrapper

    for name in (
        "system",
        "release",
        "version",
        "node",
        "machine",
        "processor",
        "uname",
        "platform",
    ):
        monkeypatch.setattr(
            platform, name, spy(f"platform.{name}", getattr(platform, name))
        )
    monkeypatch.setattr(os, "uname", spy("os.uname", os.uname))
    monkeypatch.setattr(
        socket, "gethostname", spy("socket.gethostname", socket.gethostname)
    )
    monkeypatch.setattr(socket, "getfqdn", spy("socket.getfqdn", socket.getfqdn))
    monkeypatch.setattr(shutil, "which", spy("shutil.which", shutil.which))

    def refuse(cmd: list[str], timeout: int = 10) -> tuple[int, str]:
        calls.append(f"subprocess {cmd[0]}")
        return 127, "subprocess refused in offline test"

    monkeypatch.setattr(pr._platform, "_run", refuse)
    return calls


def _scan(tree: Path, *extra: str) -> str:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = cli.main(["--root", str(tree), "--no-color", *OFFLINE_SCANS, *extra])
    assert rc == 0
    return buf.getvalue()


def _scan_json(tree: Path) -> dict[str, Any]:
    out: dict[str, Any] = json.loads(_scan(tree, "--json"))
    return out


# ---------------------------------------------------------------------------
# Runtime guard: no live-host API, no scanner facts in any output
# ---------------------------------------------------------------------------


def test_offline_scan_of_bare_tree_never_calls_live_host_apis(
    tmp_path: Path, live_host_calls: list[str]
) -> None:
    """A tree with no release file, hostname or binaries: the case that
    used to fall back to this machine's kernel.  Every output format."""
    tree = tmp_path / "bare"
    (tree / "etc").mkdir(parents=True)
    release = platform.release()  # read before any spying matters
    hostname = socket.gethostname()
    outputs = [_scan(tree, *fmt) for fmt in FORMATS]
    assert live_host_calls == []
    for text in outputs:
        assert release not in text
        if len(hostname) > 4 and hostname != "localhost":
            assert hostname not in text


def test_offline_bare_tree_reports_unknown_os_with_reason(tmp_path: Path) -> None:
    tree = tmp_path / "bare"
    (tree / "etc").mkdir(parents=True)
    d = _scan_json(tree)
    assert d["os"] == "unknown"
    assert d["os_release"]["pretty_name"] is None
    assert d["os_release"]["family"] == "unknown"
    assert "no /etc/os-release" in d["os_release"]["reason"]
    assert d["hostname"] == ""


def test_live_scan_without_release_file_still_names_the_kernel(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Live, the kernel is the scanned host's, so the fallback stays."""
    monkeypatch.setattr(pr._platform, "host_path", lambda p: tmp_path / p.lstrip("/"))
    out = osinfo._detect_os_impl()
    assert out["pretty_name"] == f"{platform.system()} {platform.release()}".strip()
    assert "reason" not in out


def test_offline_scan_ignores_scanner_being_macos(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    tree = tmp_path / "deb"
    _write(
        tree / "etc/os-release", 'ID=debian\nVERSION_ID="13"\nPRETTY_NAME="Debian 13"\n'
    )
    monkeypatch.setattr(pr._platform, "is_macos", lambda: True)
    d = _scan_json(tree)
    assert d["os_release"]["id"] == "debian"
    assert d["os"] == "Debian 13"


# ---------------------------------------------------------------------------
# Release files other than os-release (real fixtures)
# ---------------------------------------------------------------------------


def test_yocto_identity_comes_from_buildinfo(tmp_path: Path) -> None:
    tree = tmp_path / "yocto"
    shutil.copytree(
        EMBEDDED / "yocto-6.0.3-core-image-full-cmdline" / "etc", tree / "etc"
    )
    d = _scan_json(tree)
    assert d["os"] == "poky 6.0.3"
    osr = d["os_release"]
    assert (osr["id"], osr["version_id"], osr["source"]) == (
        "poky",
        "6.0.3",
        "/etc/buildinfo",
    )
    assert osr["family"] == "unknown"  # as with ID=poky in an os-release


def test_openwrt_identity_comes_from_openwrt_release(tmp_path: Path) -> None:
    tree = tmp_path / "openwrt"
    shutil.copytree(EMBEDDED / "openwrt-24.10.8" / "etc", tree / "etc")
    d = _scan_json(tree)
    osr = d["os_release"]
    assert osr["id"] == "openwrt"
    assert osr["family"] == "openwrt"
    assert osr["version_id"] == "24.10.8"
    assert osr["pretty_name"] == "OpenWrt 24.10.8 r29233-443ec4032a"
    assert osr["source"] == "/etc/openwrt_release"


def test_os_release_wins_over_other_release_files(tmp_path: Path) -> None:
    tree = tmp_path / "openwrt"
    shutil.copytree(EMBEDDED / "openwrt-24.10.8", tree)
    (tree / "etc/os-release").symlink_to("../usr/lib/os-release")
    osr = _scan_json(tree)["os_release"]
    assert osr["id"] == "openwrt"
    assert "source" not in osr


# ---------------------------------------------------------------------------
# Package manager comes from the tree, not this PATH
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tree_has_dnf", [True, False])
def test_package_manager_is_looked_up_in_the_tree(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, tree_has_dnf: bool
) -> None:
    tree = tmp_path / "el"
    _write(tree / "etc/os-release", 'ID=rhel\nVERSION_ID="9.8"\n')
    if tree_has_dnf:
        # dnf is a link to dnf-3 on EL; a dangling target still counts.
        (tree / "usr/bin").mkdir(parents=True)
        (tree / "usr/bin/dnf").symlink_to("dnf-3")
    # The scanning machine "has" every tool: it must not matter.
    monkeypatch.setattr(shutil, "which", lambda tool: f"/usr/bin/{tool}")
    osr = _scan_json(tree)["os_release"]
    assert osr["package_manager"] == ("dnf" if tree_has_dnf else None)


# ---------------------------------------------------------------------------
# Absolute symlinks resolve inside the tree
# ---------------------------------------------------------------------------


def _abs_link(link: Path, target: str) -> None:
    link.parent.mkdir(parents=True, exist_ok=True)
    link.symlink_to(target)


@pytest.mark.skipif(
    not Path("/usr/lib/os-release").exists() and not Path("/etc/hostname").exists(),
    reason="needs a scanning machine with /usr/lib/os-release or /etc/hostname",
)
def test_absolute_links_never_reach_the_scanning_machine(tmp_path: Path) -> None:
    """Each link's absolute target exists on this machine; before #258 the
    scan reported this machine's OS and hostname instead of the tree's."""
    tree = tmp_path / "tree"
    _write(
        tree / "usr/lib/os-release",
        'ID=debian\nVERSION_ID="13"\nPRETTY_NAME="Tree Debian 13"\n',
    )
    _abs_link(tree / "etc/os-release", "/usr/lib/os-release")
    _write(tree / "srv/name", "tree-host\n")
    _abs_link(tree / "etc/hostname", "/srv/name")
    d = _scan_json(tree)
    assert d["os"] == "Tree Debian 13"
    assert d["os_release"]["id"] == "debian"
    assert d["hostname"] == "tree-host"


def test_absolute_links_give_the_same_report_as_relative_ones(tmp_path: Path) -> None:
    """The same files behind relative and behind absolute links must give
    the same report: trust store, crypto material, OS and hostname."""
    reports = []
    for kind in ("relative", "absolute"):
        tree = tmp_path / kind
        _write(
            tree / "data/os-release",
            'ID=debian\nVERSION_ID="13"\nPRETTY_NAME="Debian 13"\n',
        )
        _write(tree / "data/hostname", "linked\n")
        _write(tree / "usr/bin/env", _elf_header(183))
        for name in ("rsa-2048.pem", "ec-p256.pem", "ml-dsa-65.pem"):
            _write(
                tree / "data/certs" / name,
                (FIXTURES / "trust_store" / name).read_bytes(),
            )
        links = {
            "etc/os-release": "data/os-release",
            "etc/hostname": "data/hostname",
            "etc/ssl/certs/rsa-2048.pem": "data/certs/rsa-2048.pem",
            "etc/ssl/certs/ec-p256.pem": "data/certs/ec-p256.pem",
            "etc/ssl/certs/ml-dsa-65.pem": "data/certs/ml-dsa-65.pem",
        }
        for link, target in links.items():
            depth = link.count("/")
            dest = "/" + target if kind == "absolute" else "../" * depth + target
            _abs_link(tree / link, dest)
        d = _scan_json(tree)
        reports.append(
            (
                d["os"],
                d["hostname"],
                d["arch"],
                d["trust_store"]["total_certs"],
                sorted(c["key_algorithm"] for c in d["trust_store"]["certificates"]),
            )
        )
    assert reports[0] == reports[1]
    assert reports[0][:4] == ("Debian 13", "linked", "aarch64", 3)


def test_linked_rpmdb_file_is_read_from_the_tree(tmp_path: Path) -> None:
    """An rpm database file that is an absolute link resolves inside the
    tree; the OS would follow it to this machine's rpmdb."""
    tree = tmp_path / "el9"
    shutil.copytree(FIXTURES / "rpmdb" / "el9" / "var", tree / "store")
    _write(tree / "etc/os-release", 'ID=rhel\nVERSION_ID="9.8"\n')
    (tree / "var/lib/rpm").mkdir(parents=True)
    for f in (tree / "store/lib/rpm").iterdir():
        (tree / "var/lib/rpm" / f.name).symlink_to(f"/store/lib/rpm/{f.name}")
    pr._platform.set_offline_root(str(tree))
    found = packages.locate_rpmdb()
    assert found is not None
    host_dir, local_dir, _backend = found
    assert host_dir == "/store/lib/rpm"
    assert str(local_dir).startswith(str(tree))


# ---------------------------------------------------------------------------
# The resolver, host_path, in_tree and host_glob
# ---------------------------------------------------------------------------


def test_resolve_in_root_reroots_absolute_targets(tmp_path: Path) -> None:
    (tmp_path / "usr/lib").mkdir(parents=True)
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/os-release").symlink_to("/usr/lib/os-release")
    (tmp_path / "etc/up").symlink_to("../../../../etc")
    resolve = pr._platform.resolve_in_root
    assert resolve("/etc/os-release", str(tmp_path)) == "/usr/lib/os-release"
    # `..` stops at the root, as it does at a real /.
    assert resolve("/etc/up/os-release", str(tmp_path)) == "/usr/lib/os-release"


def test_symlink_loop_never_escapes(tmp_path: Path) -> None:
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/a").symlink_to("/etc/b")
    (tmp_path / "etc/b").symlink_to("/etc/a")
    with pytest.raises(OSError):
        pr._platform.resolve_in_root("/etc/a", str(tmp_path))
    pr._platform.set_offline_root(str(tmp_path))
    p = pr._platform.host_path("/etc/a")
    assert str(p).startswith(str(tmp_path) + "/")
    assert not p.exists()


def test_host_path_maps_every_absolute_path_under_root(tmp_path: Path) -> None:
    """Under --root the tree is the whole filesystem, not just the
    namespaces --host-mount redirects."""
    pr._platform.set_offline_root(str(tmp_path))
    assert (
        pr._platform.host_path("/usr/lib64/libssl.so.3")
        == tmp_path / "usr/lib64/libssl.so.3"
    )
    assert pr._platform.host_path("/opt/app/x.pem") == tmp_path / "opt/app/x.pem"


def test_host_glob_lists_linked_directories_inside_the_tree(tmp_path: Path) -> None:
    _write(tmp_path / "data/vpn/site.conf", "proto udp\n")
    _abs_link(tmp_path / "etc/openvpn", "/data/vpn")
    pr._platform.set_offline_root(str(tmp_path))
    assert pr._platform.host_glob("/etc/openvpn/*.conf") == ["/etc/openvpn/site.conf"]
    assert pr._platform.host_glob("/etc/openvpn/*.ovpn") == []


def test_in_tree_resolves_listed_entries(tmp_path: Path) -> None:
    _write(tmp_path / "data/key.pem", "x")
    _abs_link(tmp_path / "etc/pki/key.pem", "/data/key.pem")
    pr._platform.set_offline_root(str(tmp_path))
    listed = tmp_path / "etc/pki/key.pem"
    assert pr._platform.in_tree(listed) == tmp_path / "data/key.pem"
    assert pr._platform.in_tree("/not/under/root") == Path("/not/under/root")


# ---------------------------------------------------------------------------
# Repo $basearch is the tree's architecture
# ---------------------------------------------------------------------------


def test_repo_basearch_is_the_trees_architecture(
    tmp_path: Path, live_host_calls: list[str]
) -> None:
    _write(tmp_path / "usr/bin/env", _elf_header(183))  # aarch64
    _write(
        tmp_path / "etc/yum.repos.d/base.repo",
        "[base]\nenabled=1\ngpgkey=file:///etc/pki/rpm-gpg/KEY-$basearch\n",
    )
    pr._platform.set_offline_root(str(tmp_path))
    files = signing._repo_key_files({"version_id": "9.8"})
    assert files == ["/etc/pki/rpm-gpg/KEY-aarch64"]
    assert live_host_calls == []


def test_repo_basearch_is_globbed_when_tree_arch_is_unknown(tmp_path: Path) -> None:
    _write(
        tmp_path / "etc/yum.repos.d/base.repo",
        "[base]\nenabled=1\ngpgkey=file:///etc/pki/rpm-gpg/KEY-$basearch\n",
    )
    pr._platform.set_offline_root(str(tmp_path))
    assert signing._repo_key_files({"version_id": "9.8"}) == ["/etc/pki/rpm-gpg/KEY-*"]
