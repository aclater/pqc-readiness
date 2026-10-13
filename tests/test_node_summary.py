# SPDX-License-Identifier: Apache-2.0
"""Per-node summary publisher for the opt-in OpenShift overlay (#157).

The publisher talks to a real local HTTP server standing in for the
Kubernetes ConfigMap API, so create / replace / error handling goes over a
real socket.
"""

from __future__ import annotations

import http.server
import importlib.util
import json
import threading
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import pytest

SCRIPT = (
    Path(__file__).resolve().parent.parent
    / "deploy"
    / "openshift-summary"
    / "publish-node-summary.py"
)
if not SCRIPT.exists():  # container test images ship tests/ but not deploy/
    pytest.skip("deploy/ not present", allow_module_level=True)
_spec = importlib.util.spec_from_file_location("publish_node_summary", SCRIPT)
assert _spec and _spec.loader
pns = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pns)


def _event(uid: str) -> dict[str, Any]:
    return {"class_uid": 2003, "finding_info": {"analytic": {"uid": uid}}}


REPORT = {
    "hostname": "worker-1",
    "generated_at": "2026-10-14T00:00:00+00:00",
    "schema_version": "1.5",
    "verdict": "GOOD - production-capable in software",
    "exit_code": 1,
    "pqc_deployment_gap": {
        "protocols": {
            "tls": {"state": "capable_not_configured"},
            "ssh": {"state": "deployed"},
            "ipsec": {"state": "not_present"},
        },
        "gaps": ["tls:capable_not_configured", "client:/usr/bin/curl:not_capable"],
    },
}
EVENTS = [
    _event("pqc-008-crypto-policy-blocks-pqc"),
    _event("pqc-011-service-crypto-library-without-pqc"),
    _event("pqc-011-service-crypto-library-without-pqc"),
    _event("pqc-013-crypto-library-without-pqc"),
    _event("pqc-018-pqc-capability-undetermined"),  # not a failure
    {"class_uid": 5001, "device": {}},  # inventory event, ignored
]


def test_summary_is_flat_strings_with_gap_and_failure_counts() -> None:
    data = pns.build_summary(REPORT, EVENTS)
    assert all(isinstance(v, str) for v in data.values())
    assert data["gap_tls"] == "capable_not_configured"
    assert data["gap_ssh"] == "deployed"
    assert data["gap_ipsec"] == "not_present"
    assert data["gap_count"] == "2"
    assert data["capable_not_configured"] == "1"
    assert data["failure_findings"] == "3"  # 2 x pqc-011 + pqc-013; not 008 / 018
    assert json.loads(data["findings_by_rule"]) == {
        "pqc-008-crypto-policy-blocks-pqc": 1,
        "pqc-011-service-crypto-library-without-pqc": 2,
        "pqc-013-crypto-library-without-pqc": 1,
        "pqc-018-pqc-capability-undetermined": 1,
    }
    assert data["exit_code"] == "1"


def test_summary_of_a_report_without_gap_data_is_unknown_not_an_error() -> None:
    data = pns.build_summary({"hostname": "n"}, [])
    assert data["gap_tls"] == data["gap_ssh"] == data["gap_ipsec"] == "unknown"
    assert data["gap_count"] == "0" and data["failure_findings"] == "0"


@pytest.mark.parametrize(
    ("node", "expected"),
    [
        ("worker-1.example.com", "pqc-readiness-node-worker-1.example.com"),
        ("Worker_1", "pqc-readiness-node-worker-1"),
        ("--", "pqc-readiness-node-unknown"),
    ],
)
def test_configmap_name_is_dns1123(node: str, expected: str) -> None:
    assert pns.configmap_name(node) == expected


class _FakeAPI(http.server.BaseHTTPRequestHandler):
    store: dict[str, dict[str, Any]] = {}
    calls: list[tuple[str, str, str]] = []
    status_override: int | None = None

    def log_message(self, *a: Any) -> None:  # keep pytest output clean
        pass

    def _body(self) -> dict[str, Any]:
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n))

    def _reply(self, code: int, obj: dict[str, Any]) -> None:
        raw = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_PUT(self) -> None:  # noqa: N802
        self.calls.append(("PUT", self.path, self.headers.get("Authorization", "")))
        body = self._body()
        if self.status_override:
            return self._reply(self.status_override, {"kind": "Status"})
        name = self.path.rsplit("/", 1)[1]
        if name not in self.store:
            return self._reply(404, {"kind": "Status", "reason": "NotFound"})
        self.store[name] = body
        self._reply(200, body)

    def do_POST(self) -> None:  # noqa: N802
        self.calls.append(("POST", self.path, self.headers.get("Authorization", "")))
        body = self._body()
        self.store[body["metadata"]["name"]] = body
        self._reply(201, body)


@pytest.fixture
def api():  # type: ignore[no-untyped-def]
    _FakeAPI.store, _FakeAPI.calls, _FakeAPI.status_override = {}, [], None
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _FakeAPI)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def _opener(req: urllib.request.Request) -> Any:
    return urllib.request.urlopen(req, timeout=5)


def test_publish_creates_then_replaces(api: str) -> None:
    obj = pns.configmap(
        "pqc-readiness-node-w1", "pqc-readiness", pns.build_summary(REPORT, EVENTS)
    )
    assert pns.publish(obj, api, "tok", _opener) == "created"
    assert pns.publish(obj, api, "tok", _opener) == "replaced"
    methods = [c[0] for c in _FakeAPI.calls]
    assert methods == ["PUT", "POST", "PUT"]
    assert all(
        c[1].startswith("/api/v1/namespaces/pqc-readiness/configmaps")
        for c in _FakeAPI.calls
    )
    assert all(c[2] == "Bearer tok" for c in _FakeAPI.calls)
    stored = _FakeAPI.store["pqc-readiness-node-w1"]
    assert stored["metadata"]["labels"]["pqc-readiness/summary"] == "node"
    assert stored["data"]["gap_tls"] == "capable_not_configured"


def test_publish_surfaces_permission_errors(api: str) -> None:
    _FakeAPI.status_override = 403
    obj = pns.configmap("pqc-readiness-node-w1", "pqc-readiness", {"a": "b"})
    with pytest.raises(urllib.error.HTTPError) as e:
        pns.publish(obj, api, "tok", _opener)
    assert e.value.code == 403
    assert [c[0] for c in _FakeAPI.calls] == ["PUT"]  # no blind POST after a 403


def test_main_requires_downward_api_env(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("NODE_NAME", raising=False)
    monkeypatch.delenv("POD_NAMESPACE", raising=False)
    assert pns.main() == 1
    assert "NODE_NAME and POD_NAMESPACE are required" in capsys.readouterr().err


def test_main_reports_scan_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    fake = tmp_path / "pqc-readiness"
    fake.write_text("#!/bin/sh\nexit 2\n")
    fake.chmod(0o755)
    monkeypatch.setenv("NODE_NAME", "w1")
    monkeypatch.setenv("POD_NAMESPACE", "pqc-readiness")
    monkeypatch.setenv("PQC_READINESS_BIN", str(fake))
    assert pns.main() == 1
    assert "scan failed" in capsys.readouterr().err
