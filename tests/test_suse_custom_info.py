# SPDX-License-Identifier: Apache-2.0
"""SUSE Multi-Linux Manager custom-info push example (#157).

Runs the script against a real local XML-RPC server implementing the Uyuni
API methods it calls (auth.login/logout, system.custominfo.listAllKeys/
createKey, system.getId, system.setCustomValues).  Not tested against a
real Multi-Linux Manager server.
"""

from __future__ import annotations

import importlib.util
import json
import threading
from pathlib import Path
from typing import Any
from xmlrpc.server import SimpleXMLRPCRequestHandler, SimpleXMLRPCServer

import pytest

SCRIPT = (
    Path(__file__).resolve().parent.parent
    / "deploy"
    / "suse-mlm"
    / "push-custom-info.py"
)
if not SCRIPT.exists():  # container test images ship tests/ but not deploy/
    pytest.skip("deploy/ not present", allow_module_level=True)
_spec = importlib.util.spec_from_file_location("push_custom_info", SCRIPT)
assert _spec and _spec.loader
pci = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pci)

REPORT = {
    "hostname": "sles-1",
    "verdict": "GOOD - production-capable in software",
    "schema_version": "1.5",
    "generated_at": "2026-10-14T00:00:00+00:00",
    "pqc_deployment_gap": {
        "protocols": {
            "tls": {"state": "deployed"},
            "ssh": {"state": "capable_not_configured"},
        },
        "gaps": ["ssh:capable_not_configured"],
    },
}
EVENTS = [
    {
        "class_uid": 2003,
        "finding_info": {"analytic": {"uid": "pqc-013-crypto-library-without-pqc"}},
    },
    {
        "class_uid": 2003,
        "finding_info": {"analytic": {"uid": "pqc-010-sshd-pqc-kex-not-offered"}},
    },
]


class _Handler(SimpleXMLRPCRequestHandler):
    rpc_paths = ("/rpc/api",)  # the manager's XML-RPC endpoint


class FakeMLM:
    def __init__(self, systems: dict[str, int]) -> None:
        self.systems = systems
        self.keys = {"existing_key"}
        self.values: dict[int, dict[str, str]] = {}
        self.sessions: set[str] = set()
        self.logged_out: list[str] = []

    def serve(self) -> tuple[SimpleXMLRPCServer, str]:
        srv = SimpleXMLRPCServer(
            ("127.0.0.1", 0),
            requestHandler=_Handler,
            logRequests=False,
            allow_none=False,
        )
        srv.register_function(self.login, "auth.login")
        srv.register_function(self.logout, "auth.logout")
        srv.register_function(self.list_keys, "system.custominfo.listAllKeys")
        srv.register_function(self.create_key, "system.custominfo.createKey")
        srv.register_function(self.get_id, "system.getId")
        srv.register_function(self.set_values, "system.setCustomValues")
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv, f"http://127.0.0.1:{srv.server_address[1]}/rpc/api"

    def login(self, user: str, password: str) -> str:
        assert (user, password) == ("api", "secret")
        self.sessions.add("s1")
        return "s1"

    def logout(self, session: str) -> int:
        self.logged_out.append(session)
        return 1

    def list_keys(self, session: str) -> list[dict[str, Any]]:
        assert session in self.sessions
        return [{"label": k, "description": ""} for k in sorted(self.keys)]

    def create_key(self, session: str, label: str, description: str) -> int:
        assert session in self.sessions and description
        self.keys.add(label)
        return 1

    def get_id(self, session: str, name: str) -> list[dict[str, Any]]:
        return (
            [{"id": self.systems[name], "name": name}] if name in self.systems else []
        )

    def set_values(self, session: str, sid: int, values: dict[str, str]) -> int:
        assert all(label in self.keys for label in values), "value for a missing key"
        self.values[sid] = values
        return 1


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    (tmp_path / "r.json").write_text(json.dumps(REPORT))
    (tmp_path / "f.ndjson").write_text("\n".join(json.dumps(e) for e in EVENTS) + "\n")
    monkeypatch.setenv("MLM_USER", "api")
    monkeypatch.setenv("MLM_PASSWORD", "secret")
    return tmp_path


def test_push_creates_missing_keys_and_sets_values(
    env: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    fake = FakeMLM({"sles-1": 1000010001})
    srv, url = fake.serve()
    monkeypatch.setenv("MLM_URL", url)
    try:
        rc = pci.main([str(env / "r.json"), str(env / "f.ndjson")])
    finally:
        srv.shutdown()
    assert rc == 0
    assert set(pci.KEYS) <= fake.keys
    v = fake.values[1000010001]
    assert v["pqc_gap_ssh"] == "capable_not_configured"
    assert v["pqc_gap_ipsec"] == "unknown"
    assert v["pqc_gap_count"] == "1"
    assert (
        v["pqc_failure_findings"] == "1"
    )  # pqc-013 only; pqc-010 isn't a failure rule
    assert fake.logged_out == ["s1"]
    out = capsys.readouterr()
    assert "secret" not in out.out + out.err


def test_unknown_system_fails_cleanly_and_still_logs_out(
    env: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    fake = FakeMLM({})
    srv, url = fake.serve()
    monkeypatch.setenv("MLM_URL", url)
    try:
        rc = pci.main([str(env / "r.json")])
    finally:
        srv.shutdown()
    assert rc == 1
    assert "exactly one system named 'sles-1'" in capsys.readouterr().err
    assert fake.logged_out == ["s1"] and fake.values == {}


def test_missing_credentials_is_a_usage_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    for k in ("MLM_URL", "MLM_USER", "MLM_PASSWORD"):
        monkeypatch.delenv(k, raising=False)
    assert pci.main([str(tmp_path / "r.json")]) == 2


def test_findings_not_supplied_are_marked_not_collected() -> None:
    assert pci.custom_values(REPORT, [])["pqc_failure_findings"] == "not collected"
