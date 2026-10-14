# SPDX-License-Identifier: Apache-2.0
"""Where the `openssl` section's facts come from (#228, #225).

Under --host-mount the `openssl` CLI on PATH is the scanner image's, and on
minimal hosts (OpenWrt, Buildroot) there is no CLI at all.  In both cases
the version and PQC capability must come from the host's package database
or libcrypto file, and the CLI-only fields must be null (unknown), never
the image's lists reported as the host's."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

import pqc_readiness as pr
from pqc_readiness import algorithms as _algorithms
from pqc_readiness import gap as _gap
from pqc_readiness import report as _report
from pqc_readiness import verdict as _verdict
from pqc_readiness.detect import config as _config
from pqc_readiness.detect import config_policy as _config_policy
from pqc_readiness.detect import openssl_host as _openssl_host
from pqc_readiness.render import prom as _prom
from pqc_readiness.render import sarif as _sarif
from pqc_readiness.render import text as _text

# What the UBI 10 scanner image's CLI reports (seen on OpenShift, #220).
IMAGE_KEMS = "  ML-KEM-512 @ default\n  ML-KEM-768 @ default\n  ML-KEM-1024 @ default\n"
IMAGE_GROUPS = "X25519MLKEM768:SecP384r1MLKEM1024:X25519:secp256r1\n"


def _libcrypto(root: Path, version: str, lib_dir: str = "usr/lib64") -> Path:
    """A libcrypto file carrying OpenSSL's embedded version string."""
    d = root / lib_dir
    d.mkdir(parents=True, exist_ok=True)
    f = d / "libcrypto.so.3"
    f.write_bytes(b"\x7fELF" + b"\0" * 64 + f"OpenSSL {version}  1 Jul 2026\0".encode())
    return f


@pytest.fixture
def image_cli(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    """An `openssl` CLI on PATH that answers like the scanner image's 3.5.8;
    returns the commands it was asked to run."""
    calls: list[list[str]] = []

    def run(cmd: list[str], timeout: int = 10) -> tuple[int, str]:
        calls.append(cmd)
        if cmd[:3] == ["openssl", "list", "-kem-algorithms"]:
            return 0, IMAGE_KEMS
        if cmd[:3] == ["openssl", "list", "-tls-groups"]:
            return 0, IMAGE_GROUPS
        return 0, ""

    monkeypatch.setattr(_config.shutil, "which", lambda n: f"/usr/bin/{n}")
    monkeypatch.setattr(
        pr._platform, "_openssl_version_text", lambda: (0, "OpenSSL 3.5.8 1 Jul 2026")
    )
    monkeypatch.setattr(pr._platform, "_run", run)
    return calls


@pytest.fixture
def host_mount(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    monkeypatch.setattr(pr._platform, "HOST_PREFIX", str(tmp_path))
    monkeypatch.setattr(pr._platform, "OFFLINE_ROOT", "")
    return tmp_path


def _report_with(openssl: dict[str, Any], **kw: Any) -> _report.Report:
    return _report.Report(openssl=openssl, hostname="node-1", **kw)


# --- #228: --host-mount -----------------------------------------------------


def test_host_mount_takes_version_from_host_package_not_image(
    host_mount: Path, image_cli: list[list[str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    # An EL 9.4 node (OpenSSL 3.2) scanned from the 3.5.8 image: the bug
    # reported it pqc_native with the image's ML-KEM groups.
    monkeypatch.setattr(
        _openssl_host,
        "openssl_package",
        lambda family: {"name": "openssl-libs", "version": "1:3.2.2-6.el9"},
    )
    o = _config.openssl_capability({"family": "rhel"})
    assert o["available"] is True
    assert o["version"] == "OpenSSL 1:3.2.2-6.el9"
    assert o["version_tuple"] == [3, 2, 2]
    assert o["pqc_native"] is False
    assert o["version_source"] == "package"
    assert o["package"] == {"name": "openssl-libs", "version": "1:3.2.2-6.el9"}
    assert o["scanner_cli_version"] == "OpenSSL 3.5.8 1 Jul 2026"
    assert o["cli_probe"]["available"] is False
    assert "scanner image's (OpenSSL 3.5.8" in o["cli_probe"]["reason"]
    for field in _config.CLI_ONLY_FIELDS:
        assert o[field] is None, field
    # The image's algorithm lists were never probed.
    assert not any(c[:2] == ["openssl", "list"] for c in image_cli)
    assert not _algorithms.openssl_cli_probed(o)


def test_host_mount_falls_back_to_host_libcrypto(
    host_mount: Path, image_cli: list[list[str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_openssl_host, "openssl_package", lambda family: None)
    _libcrypto(host_mount, "3.0.7")
    o = _config.openssl_capability({"family": "unknown"})
    assert o["version_source"] == "library"
    assert o["library"] == {"path": "/usr/lib64/libcrypto.so.3", "version": "3.0.7"}
    assert o["version_tuple"] == [3, 0, 7] and o["pqc_native"] is False


def test_host_mount_without_host_openssl_is_unavailable(
    host_mount: Path, image_cli: list[list[str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_openssl_host, "openssl_package", lambda family: None)
    o = _config.openssl_capability({"family": "unknown"})
    assert o["available"] is False
    assert o["reason"] == "no OpenSSL package or libcrypto found on the host"
    assert o["scanner_cli_version"].startswith("OpenSSL 3.5.8")


def test_host_mount_old_host_feeds_findings_gap_and_metrics(
    host_mount: Path, image_cli: list[list[str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        _openssl_host,
        "openssl_package",
        lambda family: {"name": "openssl-libs", "version": "3.2.2"},
    )
    o = _config.openssl_capability({"family": "rhel"})
    r = _report_with(o)
    ids = [f.rule_id for f in _sarif.build_findings(r)]
    assert "pqc-001-openssl-pre-3.5" in ids
    (f,) = [
        f for f in _sarif.build_findings(r) if f.rule_id == "pqc-001-openssl-pre-3.5"
    ]
    assert f.properties["openssl:version_source"] == "package"
    assert f.message.startswith("OpenSSL 3.2.2 is older than 3.5.0")
    # TLS capability comes from the host version, not from (null) groups.
    assert _gap.tls_capable({"openssl": o}) == (False, ["openssl.pqc_native"])
    # Unknown groups are left out of the metric rather than counted as 0.
    assert "key_exchange_groups{" not in _prom.render_prometheus(r).replace(
        'protocol="ssh"', ""
    )


def test_host_mount_new_host_is_capable_and_cnsa_says_not_probed(
    host_mount: Path, image_cli: list[list[str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        _openssl_host,
        "openssl_package",
        lambda family: {"name": "openssl-libs", "version": "3.5.5"},
    )
    o = _config.openssl_capability({"family": "rhel"})
    assert o["pqc_native"] is True
    assert _gap.tls_capable({"openssl": o}) == (True, ["openssl.pqc_native"])
    cnsa = _verdict.evaluate_cnsa_2_0(o, None)
    assert any("were not probed" in n for n in cnsa["notes"])
    assert not any("is not exposed by OpenSSL" in n for n in cnsa["notes"])
    # A crypto policy that keeps PQC out still counts as blocking a
    # capable library (pqc-008) when the groups weren't probed.
    policy = {"available": True, "pqc_enabled": {"tls_key_exchange": False}}
    assert _config_policy.policy_blocks_capable_pqc(policy, o) is True


def test_text_report_shows_source_and_not_probed(
    host_mount: Path, image_cli: list[list[str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        _openssl_host,
        "openssl_package",
        lambda family: {"name": "openssl-libs", "version": "3.2.2"},
    )
    r = _report_with(_config.openssl_capability({"family": "rhel"}))
    out = "\n".join(_text._render_text_openssl(r))
    assert "OpenSSL 3.2.2 (host package openssl-libs)" in out
    assert "PQC native:    no" in out
    assert "Algorithms and TLS groups not probed: --host-mount" in out
    assert "ML-KEM:" not in out


def test_fips_conflict_infers_pqc_exposure_from_host_version() -> None:
    o = {
        "available": True,
        "pqc_native": True,
        "kem_algorithms": None,
        "sig_algorithms": None,
        "cli_probe": {"available": False},
    }
    fips = {"kernel": True, "openssl_provider": False}
    assert _config.fips_pqc_conflict_check(fips, o)["in_conflict"] is True
    o["pqc_native"] = False
    assert _config.fips_pqc_conflict_check(fips, o)["in_conflict"] is False


def test_bench_uses_scanner_cli_lists_not_null_host_lists() -> None:
    from pqc_readiness import bench as _bench

    host_side = {
        "available": True,
        "kem_algorithms": None,
        "sig_algorithms": None,
        "cli_probe": {"available": False},
    }
    # None = unknown: run_benchmarks falls back to its own lookup.
    assert _bench._bench_provided_algorithms(host_side) is None


# --- #225: live host with libcrypto but no CLI ------------------------------


def test_live_host_without_cli_reports_library_version(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # OpenWrt 24.10.8: libopenssl3 3.0.22 installed, no openssl binary.
    monkeypatch.setattr(_config.shutil, "which", lambda n: None)
    monkeypatch.setattr(pr._platform, "HOST_PREFIX", "")
    monkeypatch.setattr(
        _openssl_host,
        "openssl_package",
        lambda family: {"name": "libopenssl3", "version": "3.0.22-r1"},
    )
    o = _config.openssl_capability({"family": "openwrt"})
    assert o["available"] is True
    assert o["version_source"] == "package"
    assert o["version_tuple"] == [3, 0, 22] and o["pqc_native"] is False
    assert o["cli_probe"]["reason"].startswith("openssl CLI not on PATH")
    assert "scanner_cli_version" not in o
    ids = [f.rule_id for f in _sarif.build_findings(_report_with(o))]
    assert "pqc-001-openssl-pre-3.5" in ids


def test_live_host_without_cli_or_library_keeps_old_shape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(_config.shutil, "which", lambda n: None)
    monkeypatch.setattr(pr._platform, "HOST_PREFIX", "")
    monkeypatch.setattr(_openssl_host, "openssl_package", lambda family: None)
    monkeypatch.setattr(_openssl_host, "openssl_library", lambda: None)
    assert _config.openssl_capability({"family": "openwrt"}) == {
        "available": False,
        "reason": "openssl not on PATH",
    }


def test_live_host_with_cli_still_probes_it(image_cli: list[list[str]]) -> None:
    o = _config.openssl_capability({"family": "rhel"})
    assert o["version_source"] == "cli"
    assert o["kem_algorithms"] == ["ML-KEM-1024", "ML-KEM-512", "ML-KEM-768"]
    assert "cli_probe" not in o and _algorithms.openssl_cli_probed(o)


def test_unparsed_host_version_raises_no_pqc_001(
    host_mount: Path, image_cli: list[list[str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    # A libcrypto with no version string: pqc_native is unknown (null), and
    # unknown must not be reported as "older than 3.5".
    monkeypatch.setattr(_openssl_host, "openssl_package", lambda family: None)
    monkeypatch.setattr(
        _openssl_host,
        "openssl_library",
        lambda: {"path": "/usr/lib64/libcrypto.so.3", "version": None},
    )
    o = _config.openssl_capability({"family": "unknown"})
    assert o["available"] is True and o["pqc_native"] is None
    assert o["version"] == "unknown"
    ids = [f.rule_id for f in _sarif.build_findings(_report_with(o))]
    assert "pqc-001-openssl-pre-3.5" not in ids
