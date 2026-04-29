# SPDX-License-Identifier: Apache-2.0
"""Per-feature `unavailable_in_container` annotation tests.

Issue #1 §4 acceptance promised that every detection function whose
result depends on /proc, /sys, /dev, /etc, lspci, or dmidecode would
annotate its output with `unavailable_in_container: true` and a
`reason` string when running inside a container without `--host-mount`.
Issue #38 documents that prior to this fix the literal string only
existed in a docstring.  These tests cover:

  - the helper `host_fs_unavailable_note`
  - inline annotation on a dict-returning probe (`detect_os`)
  - the canonical dict-returning sibling `detect_pci_accelerators`
  - `build_host_fs_detections_unavailable` map population
  - aggregator preservation of the flag for fleet rollups
"""
from __future__ import annotations

from typing import Any

import pytest

import pqc_readiness as pr


@pytest.fixture
def container_no_host_mount(monkeypatch: pytest.MonkeyPatch) -> None:
    """Simulate "running inside a container without --host-mount" by
    forcing detect_runtime_environment() to report container and clearing
    HOST_PREFIX.  Detection helpers should then emit the
    `unavailable_in_container` annotation."""
    monkeypatch.setattr(pr, "HOST_PREFIX", "")
    monkeypatch.setattr(
        pr,
        "detect_runtime_environment",
        lambda: {"environment": "container", "evidence": "test stub"},
    )


@pytest.fixture
def container_with_host_mount(monkeypatch: pytest.MonkeyPatch) -> None:
    """Simulate container + --host-mount.  Detection helpers should NOT
    emit the annotation because /host bind-mounts make the host fs
    visible to the container."""
    monkeypatch.setattr(pr, "HOST_PREFIX", "/host")
    monkeypatch.setattr(
        pr,
        "detect_runtime_environment",
        lambda: {"environment": "container", "evidence": "test stub"},
    )


@pytest.fixture
def bare_metal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pr, "HOST_PREFIX", "")
    monkeypatch.setattr(
        pr,
        "detect_runtime_environment",
        lambda: {"environment": "host", "evidence": "test stub"},
    )


# ---------------------------------------------------------------------------
# host_fs_unavailable_note — the central helper
# ---------------------------------------------------------------------------

def test_host_fs_unavailable_note_returns_none_on_bare_metal(
    bare_metal: None,
) -> None:
    assert pr.host_fs_unavailable_note("X probe", "/proc/X") is None


def test_host_fs_unavailable_note_returns_none_with_host_mount(
    container_with_host_mount: None,
) -> None:
    """--host-mount in effect: detection reads the bind-mounted host fs,
    so its result is trustworthy.  No annotation."""
    assert pr.host_fs_unavailable_note("X probe", "/proc/X") is None


def test_host_fs_unavailable_note_emits_flag_in_container(
    container_no_host_mount: None,
) -> None:
    note = pr.host_fs_unavailable_note(
        "PCI accelerator detection", "lspci output"
    )
    assert note is not None
    assert note["unavailable_in_container"] is True
    assert "PCI accelerator detection" in note["reason"]
    assert "lspci output" in note["reason"]
    assert "--host-mount" in note["reason"]


# ---------------------------------------------------------------------------
# detect_pci_accelerators — canonical example called out in issue #38
# ---------------------------------------------------------------------------

def test_detect_pci_accelerators_emits_flag_in_container(
    container_no_host_mount: None, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Per issue #38: `detect_pci_accelerators` is the canonical probe
    that depends on lspci output and /dev hints.  Inside a container
    without --host-mount it MUST surface the flag instead of silently
    returning an empty list (which is indistinguishable from "host has
    no PCI accelerators")."""
    monkeypatch.setattr(pr, "detect_accelerators", lambda: [])
    out = pr.detect_pci_accelerators()
    assert out["items"] == []
    assert out["unavailable_in_container"] is True
    assert "lspci" in out["reason"]


def test_detect_pci_accelerators_no_flag_on_bare_metal(
    bare_metal: None, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        pr, "detect_accelerators", lambda: [{"kind": "tpm", "name": "Test"}]
    )
    out = pr.detect_pci_accelerators()
    assert out["items"] == [{"kind": "tpm", "name": "Test"}]
    assert "unavailable_in_container" not in out
    assert "reason" not in out


def test_detect_pci_accelerators_no_flag_with_host_mount(
    container_with_host_mount: None, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When --host-mount is in effect the lspci output reflects the host
    (operator runs `chroot /host lspci`-equivalent paths via
    HOST_PREFIX), so no flag."""
    monkeypatch.setattr(pr, "detect_accelerators", lambda: [])
    out = pr.detect_pci_accelerators()
    assert "unavailable_in_container" not in out


# ---------------------------------------------------------------------------
# Inline annotation on dict-returning probes — detect_os
# ---------------------------------------------------------------------------

def test_detect_os_annotates_inline_in_container(
    container_no_host_mount: None, tmp_path: Any, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Inside a container without --host-mount, /etc/os-release is the
    container image's OS, not the host's.  detect_os() must annotate so
    consumers don't misreport the host distro."""
    # Stub /etc/os-release so _detect_os_impl returns a known dict.
    target = tmp_path / "etc" / "os-release"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        'ID=ubi9\nVERSION_ID="9.6"\nID_LIKE="rhel fedora"\n'
        'PRETTY_NAME="Red Hat Universal Base Image 9.6"\n'
    )
    # _detect_os_impl reads via host_path() which only redirects when
    # HOST_PREFIX is set; we keep HOST_PREFIX empty (matches the
    # "container without --host-mount" scenario) and instead monkey-patch
    # _detect_os_impl to a minimal known result so the test does not
    # depend on the test runner's own /etc/os-release.
    monkeypatch.setattr(
        pr,
        "_detect_os_impl",
        lambda: {
            "family": "rhel", "id": "ubi9", "version_id": "9.6",
            "version_codename": None, "pretty_name": "Red Hat UBI 9.6",
            "package_manager": None,
        },
    )
    out = pr.detect_os()
    assert out["family"] == "rhel"
    assert out["unavailable_in_container"] is True
    assert "/etc/os-release" in out["reason"]


def test_detect_os_no_flag_on_bare_metal(
    bare_metal: None, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        pr,
        "_detect_os_impl",
        lambda: {"family": "fedora", "id": "fedora", "version_id": "44"},
    )
    out = pr.detect_os()
    assert "unavailable_in_container" not in out


# ---------------------------------------------------------------------------
# build_host_fs_detections_unavailable — Report-level map
# ---------------------------------------------------------------------------

def test_build_host_fs_detections_unavailable_empty_on_bare_metal(
    bare_metal: None,
) -> None:
    assert pr.build_host_fs_detections_unavailable() == {}


def test_build_host_fs_detections_unavailable_empty_with_host_mount(
    container_with_host_mount: None,
) -> None:
    assert pr.build_host_fs_detections_unavailable() == {}


def test_build_host_fs_detections_unavailable_populated_in_container(
    container_no_host_mount: None,
) -> None:
    out = pr.build_host_fs_detections_unavailable()
    # Every catalogued probe should be present.
    expected = {
        "accelerators", "kernel_crypto_hw", "ktls", "fips", "tpm_pqc",
        "kernel_info", "os_release", "pkcs11_modules",
    }
    assert set(out) == expected
    for key, note in out.items():
        assert note["unavailable_in_container"] is True
        assert note["reason"], f"empty reason for {key}"


# ---------------------------------------------------------------------------
# Aggregator preserves the flag — required by issue #38 acceptance
# ---------------------------------------------------------------------------

def test_aggregator_counts_host_fs_detections_unavailable() -> None:
    """Issue #38 acceptance: 'fleet rollups can report X hosts had
    detection Y unavailable in container'.  Two of three reports flag
    `accelerators`; one flags `tpm_pqc`.  The rollup must surface those
    counts under host_fs_detections_unavailable_host_count."""
    reports = [
        {
            "schema_version": pr.SCHEMA_VERSION,
            "arch": "x86_64", "isa_tier": "good", "verdict": "GOOD",
            "cpu_model": "Test", "kernel_info": {"os_release_id": "rhel"},
            "runtime_environment": {"environment": "container"},
            "accelerators": [],
            "host_fs_detections_unavailable": {
                "accelerators": {
                    "unavailable_in_container": True, "reason": "..."
                },
                "tpm_pqc": {
                    "unavailable_in_container": True, "reason": "..."
                },
            },
            "replace_required": False,
        },
        {
            "schema_version": pr.SCHEMA_VERSION,
            "arch": "x86_64", "isa_tier": "good", "verdict": "GOOD",
            "cpu_model": "Test", "kernel_info": {"os_release_id": "rhel"},
            "runtime_environment": {"environment": "container"},
            "accelerators": [],
            "host_fs_detections_unavailable": {
                "accelerators": {
                    "unavailable_in_container": True, "reason": "..."
                },
            },
            "replace_required": False,
        },
        {
            "schema_version": pr.SCHEMA_VERSION,
            "arch": "x86_64", "isa_tier": "good", "verdict": "GOOD",
            "cpu_model": "Test", "kernel_info": {"os_release_id": "rhel"},
            "runtime_environment": {"environment": "host"},
            "accelerators": [],
            "host_fs_detections_unavailable": {},
            "replace_required": False,
        },
    ]
    out = pr.aggregate_reports(reports)
    counts = out["host_fs_detections_unavailable_host_count"]
    assert counts == {"accelerators": 2, "tpm_pqc": 1}


def test_aggregator_handles_missing_field_gracefully() -> None:
    """Reports written before this field existed must aggregate without
    error; the count map is simply empty."""
    reports = [
        {
            "schema_version": pr.SCHEMA_VERSION,
            "arch": "x86_64", "isa_tier": "good", "verdict": "GOOD",
            "cpu_model": "Test", "kernel_info": {"os_release_id": "rhel"},
            "runtime_environment": {"environment": "host"},
            "accelerators": [], "replace_required": False,
        },
    ]
    out = pr.aggregate_reports(reports)
    assert out["host_fs_detections_unavailable_host_count"] == {}


def test_aggregator_csv_includes_unavailable_group() -> None:
    rollup = {
        "total_hosts": 1, "replace_required_count": 0,
        "host_fs_detections_unavailable_host_count": {"accelerators": 1},
    }
    csv_text = pr.aggregate_to_csv(rollup)
    assert "host_fs_detections_unavailable_host_count,accelerators,1" in csv_text
