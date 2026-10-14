# SPDX-License-Identifier: Apache-2.0
"""Report hostname resolution (#220).

In a DaemonSet pod gethostname() is the pod name, so the report must take
the node name from PQC_HOSTNAME (downward API) or the host's /etc/hostname.
"""

from __future__ import annotations

import socket

import pqc_readiness as pr
from pqc_readiness import cli


def _host(monkeypatch, tmp_path, etc_hostname: str | None) -> None:
    if etc_hostname is not None:
        (tmp_path / "etc").mkdir()
        (tmp_path / "etc" / "hostname").write_text(etc_hostname)
    monkeypatch.setattr(pr._platform, "HOST_PREFIX", str(tmp_path))
    monkeypatch.setattr(socket, "gethostname", lambda: "pqc-readiness-x7k2p")
    monkeypatch.delenv("PQC_HOSTNAME", raising=False)


def test_env_wins(monkeypatch, tmp_path):
    _host(monkeypatch, tmp_path, "from-etc\n")
    monkeypatch.setenv("PQC_HOSTNAME", "worker-1")
    assert cli._report_hostname() == "worker-1"


def test_host_mount_uses_host_etc_hostname(monkeypatch, tmp_path):
    _host(monkeypatch, tmp_path, "crc\n")
    assert cli._report_hostname() == "crc"


def test_host_mount_without_etc_hostname_falls_back(monkeypatch, tmp_path):
    _host(monkeypatch, tmp_path, None)
    assert cli._report_hostname() == "pqc-readiness-x7k2p"


def test_blank_env_ignored_and_live_host_uses_gethostname(monkeypatch, tmp_path):
    _host(monkeypatch, tmp_path, "crc\n")
    monkeypatch.setattr(pr._platform, "HOST_PREFIX", "")
    monkeypatch.setenv("PQC_HOSTNAME", "  ")
    assert cli._report_hostname() == "pqc-readiness-x7k2p"
