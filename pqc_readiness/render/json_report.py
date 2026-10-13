"""Plain JSON report output (--json): the Report dataclass as JSON."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict

from .. import registry as _registry
from .. import report as _report


def render_json(r: _report.Report) -> str:
    return json.dumps(asdict(r), indent=2)


@_registry.register_arguments(10)
def add_arguments(ap: argparse.ArgumentParser) -> None:
    """--json."""
    ap.add_argument("--json", action="store_true", help="emit JSON")


_registry.register_output(_registry.OutputFormat("json", 0, lambda r: render_json(r)))
