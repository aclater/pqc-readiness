# SPDX-License-Identifier: Apache-2.0
"""Offline scan of a filesystem tree: --root PATH (#152)."""

from __future__ import annotations

import json
import shutil
import struct
from dataclasses import asdict
from pathlib import Path

import pytest

import pqc_readiness as pr
from pqc_readiness import cli
from pqc_readiness.detect import packages as pkgs
from pqc_readiness.detect import runtime_offline as off

FIXTURES = Path(__file__).parent / "fixtures"

OS_RELEASE_EL9 = (
    'NAME="Red Hat Enterprise Linux"\nVERSION="9.8 (Plow)"\nID="rhel"\n'
    'ID_LIKE="fedora"\nVERSION_ID="9.8"\n'
    'PRETTY_NAME="Red Hat Enterprise Linux 9.8 (Plow)"\n'
)
OS_RELEASE_DEBIAN = (
    'PRETTY_NAME="Debian GNU/Linux 13 (trixie)"\nNAME="Debian GNU/Linux"\n'
    'VERSION_ID="13"\nID=debian\n'
)


def _elf_header(machine: int, *, bits64: bool = True, little: bool = True) -> bytes:
    ident = b"\x7fELF" + bytes([2 if bits64 else 1, 1 if little else 2, 1]) + b"\0" * 9
    order = "<" if little else ">"
    return ident + struct.pack(order + "HH", 2, machine) + b"\0" * 44


def _write(path: Path, data: bytes | str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, str):
        path.write_text(data)
    else:
        path.write_bytes(data)
    return path


@pytest.fixture
def no_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    """Start every test live; monkeypatch restores whatever --root set."""
    monkeypatch.setattr(pr._platform, "HOST_PREFIX", "")
    monkeypatch.setattr(pr._platform, "OFFLINE_ROOT", "")


@pytest.fixture
def no_subprocess(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    """Record (and refuse) any subprocess: an offline scan must not run
    the scanner's own binaries to describe the tree."""
    calls: list[list[str]] = []

    def refuse(cmd: list[str], timeout: int = 10) -> tuple[int, str]:
        calls.append(cmd)
        return 127, "subprocess refused in offline test"

    monkeypatch.setattr(pr._platform, "_run", refuse)
    return calls


@pytest.fixture
def el9_tree(tmp_path: Path) -> Path:
    """RHEL 9-like tree: real rpmdb.sqlite fixture, os-release, hostname,
    /bin -> usr/bin and an x86_64 ELF header for /usr/bin/env."""
    root = tmp_path / "el9"
    shutil.copytree(FIXTURES / "rpmdb" / "el9" / "var", root / "var")
    _write(root / "usr/lib/os-release", OS_RELEASE_EL9)
    (root / "etc").mkdir()
    (root / "etc/os-release").symlink_to("../usr/lib/os-release")
    _write(root / "etc/hostname", "image-builder-01\n")
    _write(root / "usr/bin/env", _elf_header(62))
    (root / "bin").symlink_to("usr/bin")
    return root


def _run_json(capsys: pytest.CaptureFixture[str], *argv: str) -> dict:
    rc = cli.main([*argv, "--json"])
    assert rc == 0
    return json.loads(capsys.readouterr().out)


# ---------------------------------------------------------------- package dbs


def test_parse_dpkg_status_matches_dpkg_query_w() -> None:
    # dpkg-query -W lists every stanza with a Version, including packages
    # removed with config files left (verified in debian:13).
    text = (
        "Package: libssl3t64\nStatus: install ok installed\nArchitecture: amd64\n"
        "Version: 3.5.1-1\nDescription: Secure Sockets Layer toolkit\n"
        " continuation line: Version: 9.9 must not be read\n\n"
        "Package: logrotate\nStatus: deinstall ok config-files\nVersion: 3.22.0-1\n\n"
        "Package: libc6\nStatus: install ok installed\nArchitecture: i386\n"
        "Version: 2.41-12\n\n"
        "Package: purged\nStatus: purge ok not-installed\n\n"
    )
    assert pkgs.parse_dpkg_status(text) == [
        {"name": "libssl3t64", "version": "3.5.1-1"},
        {"name": "logrotate", "version": "3.22.0-1"},
        {"name": "libc6", "version": "2.41-12"},
    ]


def test_parse_apk_installed() -> None:
    text = "C:Q1abc=\nP:musl\nV:1.2.5-r10\nA:x86_64\n\nP:libssl3\nV:3.5.5-r0\n\nP:noversion\n"
    assert pkgs.parse_apk_installed(text) == [
        {"name": "musl", "version": "1.2.5-r10"},
        {"name": "libssl3", "version": "3.5.5-r0"},
    ]


def test_parse_pacman_desc() -> None:
    text = "%NAME%\nopenssl\n\n%VERSION%\n3.6.0-1\n\n%BASE%\nopenssl\n"
    assert pkgs.parse_pacman_desc(text) == {"name": "openssl", "version": "3.6.0-1"}
    assert pkgs.parse_pacman_desc("%NAME%\nx\n") is None


@pytest.mark.parametrize(
    ("family", "rel", "content", "manager", "source", "expected"),
    [
        (
            "debian",
            "var/lib/dpkg/status",
            "Package: libssl3t64\nVersion: 3.5.1-1\n\nPackage: bash\nVersion: 5.2-1\n",
            "dpkg",
            "dpkg-status",
            2,
        ),
        (
            "alpine",
            "lib/apk/db/installed",
            "P:libssl3\nV:3.5.5-r0\n\nP:musl\nV:1.2.5-r10\n\nP:busybox\nV:1.37.0-r20\n",
            "apk",
            "apk-installed-db",
            3,
        ),
    ],
)
def test_non_rpm_inventory_under_prefix_is_in_process(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    no_subprocess: list[list[str]],
    family: str,
    rel: str,
    content: str,
    manager: str,
    source: str,
    expected: int,
) -> None:
    # Regression for --host-mount too: the CLI tools read the scanner's
    # own database, so under a prefix the tree's database is read directly.
    _write(tmp_path / rel, content)
    monkeypatch.setattr(pr._platform, "HOST_PREFIX", str(tmp_path))
    out = pkgs.scan_packages({"family": family})
    assert no_subprocess == []
    assert out["available"] is True
    assert (out["package_manager"], out["source"]) == (manager, source)
    assert out["db_root"] == "/" + rel
    assert out["total_packages"] == expected


def test_pacman_inventory_under_prefix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, no_subprocess: list[list[str]]
) -> None:
    for name, ver in (("openssl", "3.6.0-1"), ("glibc", "2.42-1")):
        _write(
            tmp_path / f"var/lib/pacman/local/{name}-{ver}/desc",
            f"%NAME%\n{name}\n\n%VERSION%\n{ver}\n",
        )
    monkeypatch.setattr(pr._platform, "HOST_PREFIX", str(tmp_path))
    out = pkgs.scan_packages({"family": "arch"})
    assert no_subprocess == []
    assert out["source"] == "pacman-local-db"
    assert out["total_packages"] == 2


def test_missing_prefixed_database_is_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, no_subprocess: list[list[str]]
) -> None:
    monkeypatch.setattr(pr._platform, "HOST_PREFIX", str(tmp_path))
    out = pkgs.scan_packages({"family": "debian"})
    assert out["available"] is False
    assert "/var/lib/dpkg/status" in out["reason"]
    assert no_subprocess == []


def test_live_non_rpm_inventory_still_uses_cli(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pr._platform, "HOST_PREFIX", "")
    monkeypatch.setattr(pkgs.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(
        pr._platform,
        "_run",
        lambda cmd, timeout=10: (0, "bash 5.2-1\nlibssl3t64 3.5.1-1\n"),
    )
    out = pkgs.scan_packages({"family": "debian"})
    assert out["package_manager"] == "dpkg-query"
    assert "source" not in out


# ---------------------------------------------------------------- arch / host


@pytest.mark.parametrize(
    ("header", "arch"),
    [
        (_elf_header(62), "x86_64"),
        (_elf_header(183), "aarch64"),
        (_elf_header(22, little=False), "s390x"),
        (_elf_header(21), "ppc64le"),
        (_elf_header(21, little=False), "ppc64"),
        (_elf_header(3, bits64=False), "i686"),
        (_elf_header(243), "riscv64"),
        (_elf_header(9999), None),
        (b"#!/bin/sh\n" + b"\0" * 20, None),
        (b"\x7fELF", None),
    ],
)
def test_elf_arch(header: bytes, arch: str | None) -> None:
    assert off.elf_arch(header) == arch


def test_tree_arch_follows_symlinks_inside_the_tree(
    el9_tree: Path, monkeypatch: pytest.MonkeyPatch, no_prefix: None
) -> None:
    (el9_tree / "usr/bin/env").unlink()
    _write(el9_tree / "usr/bin/sh", _elf_header(183))
    monkeypatch.setattr(pr._platform, "HOST_PREFIX", str(el9_tree))
    assert off.tree_arch() == "aarch64"  # via /bin -> usr/bin


def test_tree_arch_unknown_without_binaries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pr._platform, "HOST_PREFIX", str(tmp_path))
    assert off.tree_arch() == "unknown"


# ---------------------------------------------------------------- CLI rules


@pytest.mark.parametrize(
    "extra",
    [
        ["--host-mount", "/host"],
        ["--bench"],
        ["--bench-tls"],
        ["--scan-services"],
        ["--check", "good"],
        ["--check", "cnsa-2.0"],
        ["--fips-strict"],
        ["--recommend"],
    ],
)
def test_root_rejects_live_only_flags(
    el9_tree: Path,
    no_prefix: None,
    extra: list[str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["--root", str(el9_tree), *extra])
    assert exc.value.code == 2
    assert "--root scans a filesystem tree offline" in capsys.readouterr().err


def test_root_must_be_a_directory(
    tmp_path: Path, no_prefix: None, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["--root", str(tmp_path / "missing"), "--json"])
    assert exc.value.code == 2
    assert "is not a directory" in capsys.readouterr().err


# ---------------------------------------------------------------- report


def test_offline_report_reads_only_the_tree(
    el9_tree: Path,
    no_prefix: None,
    no_subprocess: list[list[str]],
    capsys: pytest.CaptureFixture[str],
) -> None:
    r = _run_json(
        capsys, "--root", str(el9_tree), "--scan-packages", "--scan-signing-keys"
    )
    assert no_subprocess == [], "offline scan ran the scanner's own binaries"
    assert r["scan_mode"]["mode"] == "offline_root"
    assert r["scan_mode"]["root"] == str(el9_tree.resolve())
    assert r["hostname"] == "image-builder-01"
    assert r["arch"] == "x86_64"
    assert r["os"] == "Red Hat Enterprise Linux 9.8 (Plow)"
    assert r["verdict"].startswith("NOT APPLICABLE")
    assert r["isa_tier"] == "not_applicable"
    assert r["exit_code"] == 0
    # Packages come from the tree's rpm database, in-process.
    assert r["packages"]["source"] == "rpmdb-sqlite"
    assert r["packages"]["total_packages"] == 5
    # OpenSSL: no capability probe, but the packaged version answers.
    assert r["openssl"]["not_applicable"] is True
    assert r["openssl"]["package"] == {"name": "openssl-libs", "version": "3.5.8"}
    assert r["openssl"]["pqc_native_expected"] is True
    # Every object-valued N/A section carries the marker.
    for name in r["scan_mode"]["not_applicable"]:
        value = r[name]
        if isinstance(value, dict) and value:
            assert value.get("not_applicable") is True, name
    assert r["ssh_pqc"]["not_applicable"] is True
    assert r["cnsa_2_0"]["not_applicable"] is True
    assert "configured" in r["ipsec_pqc"]
    # Exit code stays 0 (no readiness tier is computed).
    assert r["benchmark"] is None


def test_offline_flag_does_not_change_live_scans(no_prefix: None) -> None:
    rep = pr.report.Report()
    assert asdict(rep)["scan_mode"] is None


# ---------------------------------------------------------------- renderers


@pytest.fixture
def offline_report(el9_tree: Path, no_prefix: None, no_subprocess: list[list[str]]):
    args = cli.build_parser().parse_args(
        ["--root", str(el9_tree), "--scan-trust-store", "--scan-signing-keys"]
    )
    off.apply_root(cli.build_parser(), args)
    return cli.collect_report(args)


def test_text_and_markdown_mark_not_applicable(offline_report) -> None:
    text = pr.render.text.render_text(offline_report)
    assert "(offline tree)" in text
    assert "Not applicable offline:" in text
    assert "Cores:" not in text and "Tier:" not in text
    assert "openssl-libs 3.5.8" in text
    md = pr.render.text.render_markdown(offline_report)
    assert "offline tree" in md and "**Not applicable offline:**" in md


def test_sarif_marks_offline_and_raises_no_host_findings(offline_report) -> None:
    sarif = json.loads(pr.render.sarif.render_sarif(offline_report))
    run = sarif["runs"][0]
    assert run["properties"]["scan:mode"] == "offline_root"
    assert "cpu_model" in run["properties"]["scan:not_applicable"]
    host_rules = {"pqc-001", "pqc-002", "pqc-003", "pqc-005", "pqc-006", "pqc-007"}
    fired = {
        res["ruleId"].split("-")[0] + "-" + res["ruleId"].split("-")[1]
        for res in run["results"]
    }
    assert not fired & host_rules, f"host-only findings on a tree: {fired & host_rules}"


def test_cbom_subject_is_an_operating_system(offline_report) -> None:
    bom = json.loads(pr.render.cbom.render_cbom(offline_report))
    comp = bom["metadata"]["component"]
    assert comp["type"] == "operating-system"
    props = {p["name"]: p["value"] for p in comp["properties"]}
    assert props["scan:mode"] == "offline_root"


def test_prometheus_never_reports_a_tier_for_a_tree(offline_report) -> None:
    text = pr.render.prom.render_prometheus(offline_report)
    assert "pqc_readiness_offline_scan 1" in text
    assert 'pqc_readiness_verdict_tier{tier="excellent"} 1' not in text
    assert "pqc_readiness_isa_score" not in text
    assert "pqc_readiness_replace_required" not in text


def test_ndjson_and_spdx_mark_offline(offline_report) -> None:
    first = json.loads(pr.render.ndjson.render_ndjson(offline_report).splitlines()[0])
    assert first["unmapped"]["pqc_readiness"]["scan_mode"]["mode"] == "offline_root"
    spdx = pr.render.spdx.render_spdx(offline_report)
    assert "Offline filesystem tree" in spdx


def test_offline_berkeley_db_tree_runs_no_subprocess(
    tmp_path: Path,
    no_prefix: None,
    no_subprocess: list[list[str]],
    capsys: pytest.CaptureFixture[str],
) -> None:
    # On Berkeley DB / ndb, named lookups normally prefer the scanner's
    # `rpm -q`; offline, OpenSSL and NSS come from the in-process inventory.
    import gzip

    root = tmp_path / "el8"
    _write(
        root / "var/lib/rpm/Packages",
        gzip.decompress((FIXTURES / "rpmdb/el8-bdb/Packages.gz").read_bytes()),
    )
    _write(root / "etc/os-release", OS_RELEASE_EL9.replace("9.8", "8.10"))
    r = _run_json(capsys, "--root", str(root))
    assert no_subprocess == []
    assert r["nss"]["version"].startswith("3.124")
    assert r["nss"]["tool"] == "rpmdb (bdb)"


def test_offline_debian_tree_uses_dpkg_status(
    tmp_path: Path,
    no_prefix: None,
    no_subprocess: list[list[str]],
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = tmp_path / "deb"
    _write(root / "etc/os-release", OS_RELEASE_DEBIAN)
    _write(
        root / "var/lib/dpkg/status",
        "Package: libssl3t64\nStatus: install ok installed\nVersion: 3.5.1-1\n\n"
        "Package: openssl\nStatus: install ok installed\nVersion: 3.5.1-1\n",
    )
    _write(
        root / "usr/lib/ssl/openssl.cnf",
        "openssl_conf = openssl_init\n[openssl_init]\n",
    )
    r = _run_json(capsys, "--root", str(root), "--scan-packages")
    assert no_subprocess == []
    assert r["packages"]["source"] == "dpkg-status"
    assert r["openssl"]["package"] == {"name": "libssl3t64", "version": "3.5.1-1"}
    assert r["openssl"]["pqc_native_expected"] is True
    assert r["nss"]["not_applicable"] is True
