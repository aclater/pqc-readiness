# SPDX-License-Identifier: Apache-2.0
"""Package layout and the seams that keep parallel work collision-free (#80, #137).

- Tests patch the defining module; patching the package root is rejected.
- The root re-exports the public API as the very same objects.
- Flags and output formats come from per-module registrations, in a
  stable order, so adding one never edits a shared block.
"""

from __future__ import annotations

import argparse
import importlib

import pytest

import pqc_readiness as pr
from pqc_readiness import registry

LANE_MODULES = (
    "pqc_readiness.detect.config",
    "pqc_readiness.detect.certs",
    "pqc_readiness.detect.runtime",
    "pqc_readiness.detect.protocols",
    "pqc_readiness.detect.packages",
    "pqc_readiness.render.cbom",
    "pqc_readiness.render.sarif",
    "pqc_readiness.render.spdx",
    "pqc_readiness.render.text",
    "pqc_readiness.render.ndjson",
    "pqc_readiness.recommendation",
    "pqc_readiness.aggregate",
    "pqc_readiness._platform",
    "pqc_readiness.cli",
)


def test_patching_the_package_root_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(AssertionError, match="package root"):
        monkeypatch.setattr(pr, "render_cbom", lambda r: "x")
    with pytest.raises(AssertionError, match="package root"):
        monkeypatch.setattr("pqc_readiness.render_cbom", lambda r: "x")


def test_patching_the_defining_module_reaches_callers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cross-module calls go through the module (``_platform._run``), so one
    patch on the defining module is seen everywhere."""
    calls: list[list[str]] = []

    def fake_run(cmd: list[str], timeout: int = 10) -> tuple[int, str]:
        calls.append(cmd)
        return 0, "OpenSSH_9.9p1, OpenSSL 3.5.0"

    monkeypatch.setattr(pr._platform, "_run", fake_run)
    monkeypatch.setattr("shutil.which", lambda name: f"/usr/bin/{name}")
    pr.detect.protocols.detect_ssh_pqc("rhel")
    assert calls and calls[0][0] == "ssh"


def test_public_names_are_reexported_as_the_same_objects() -> None:
    assert pr.__all__, "package root must declare its public API"
    for name in pr.__all__:
        obj = getattr(pr, name)
        owner = getattr(obj, "__module__", None)
        if owner and owner.startswith("pqc_readiness."):
            assert getattr(importlib.import_module(owner), name) is obj, name


def test_mutable_state_is_not_reexported() -> None:
    assert "HOST_PREFIX" not in pr.__all__
    assert not hasattr(pr, "HOST_PREFIX")


@pytest.mark.parametrize("module", LANE_MODULES)
def test_lane_modules_exist(module: str) -> None:
    importlib.import_module(module)


def test_argument_hooks_build_the_documented_flag_order() -> None:
    ap = pr.build_parser()
    flags = [
        a.option_strings[-1]
        for a in ap._actions
        if a.option_strings and a.dest != "help"
    ]
    assert flags[:5] == ["--json", "--markdown", "--cbom", "--spdx", "--sarif"]
    assert flags[-2:] == ["--debug", "--version"]
    assert flags.index("--bench") < flags.index("--check") < flags.index("--quiet")
    assert (
        flags.index("--scan-trust-store")
        < flags.index("--host-mount")
        < flags.index("--recommend")
    )
    assert ap.prog == "pqc-readiness"


def test_every_registered_output_has_its_flag() -> None:
    ap = pr.build_parser()
    dests = {a.dest for a in ap._actions}
    for fmt in registry.outputs():
        assert fmt.dest in dests, fmt.dest


def test_output_precedence_matches_the_cli_contract() -> None:
    order = [f.dest for f in registry.outputs()]
    assert order == [
        "json",
        "cbom",
        "spdx",
        "sbom",
        "sarif",
        "prometheus",
        "ndjson",
        "markdown",
        "quiet",
    ]
    machine = {f.dest for f in registry.outputs() if f.machine_readable}
    assert machine == {
        "json",
        "cbom",
        "spdx",
        "sbom",
        "sarif",
        "prometheus",
        "ndjson",
        "markdown",
    }


def test_registry_rejects_duplicate_registrations() -> None:
    with pytest.raises(ValueError, match="registered twice"):
        registry.register_output(registry.OutputFormat("json", 99, lambda r: ""))

    def hook(ap: argparse.ArgumentParser) -> None:
        pass

    registry.register_arguments(999)(hook)
    try:
        with pytest.raises(ValueError, match="registered twice"):
            registry.register_arguments(998)(hook)
    finally:
        registry._ARGUMENT_HOOKS[:] = [
            h for h in registry._ARGUMENT_HOOKS if h[2] is not hook
        ]


def test_positive_int_rejects_zero_and_text() -> None:
    assert registry.positive_int("3") == 3
    for bad in ("0", "-1", "x"):
        with pytest.raises(argparse.ArgumentTypeError):
            registry.positive_int(bad)
