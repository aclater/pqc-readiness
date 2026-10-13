"""Operator-supplied inventory metadata (--inventory-metadata FILE, #144).

OMB M-23-02 asks for per-system items a host cannot know about itself:
the FISMA system identifier (item 1), FIPS 199 categorization (2), HVA
identifier (3), hosting model and provider (7), data lifecycle / time to
live (8) and notes (9).  The operator supplies them in a small JSON file;
the scanner validates it and carries it into the JSON report
(`inventory_metadata`) and the CBOM host component.

M-23-02 footnote 13: submit identifiers only, never names that reveal a
system's function or location.  The scanner cannot check that, so the
docs say it.

File format (every key optional; unknown keys are rejected so typos are
caught instead of silently dropped):

    {
      "fisma_system_id": "ABC-1234",
      "fips199_categorization": "Moderate",
      "hva_id": "HVA-0042",
      "hosting": {"model": "commercial-csp", "provider": "Example Cloud"},
      "data_lifecycle": {"records_categories": ["GRS 3.2"],
                         "time_to_live_years": 25},
      "notes": "free text"
    }
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from . import registry as _registry

# Large enough for any realistic file, small enough that a wrong path
# (a CBOM, a log) fails fast instead of being parsed.
MAX_BYTES = 64 * 1024

FIPS199_LEVELS: tuple[str, ...] = ("Low", "Moderate", "High")
# M-23-02 item 7: on premise, commercial CSP, government CSP, or hybrid.
# Every model except on-premises must name its provider(s).
HOSTING_MODELS: tuple[str, ...] = (
    "on-premises",
    "commercial-csp",
    "government-csp",
    "hybrid",
)

_STRING_KEYS: tuple[str, ...] = ("fisma_system_id", "hva_id", "notes")
_ALLOWED_KEYS: frozenset[str] = frozenset(
    (*_STRING_KEYS, "fips199_categorization", "hosting", "data_lifecycle")
)


class InventoryMetadataError(ValueError):
    """The metadata file is unreadable or does not match the format."""


def _require_str(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise InventoryMetadataError(f"{where} must be a non-empty string")
    return value.strip()


def _validate_hosting(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        raise InventoryMetadataError("hosting must be an object")
    extra = set(value) - {"model", "provider"}
    if extra:
        raise InventoryMetadataError(f"hosting: unknown key(s) {sorted(extra)}")
    model = value.get("model")
    if model not in HOSTING_MODELS:
        raise InventoryMetadataError(
            f"hosting.model must be one of {list(HOSTING_MODELS)}, got {model!r}"
        )
    out = {"model": str(model)}
    if model == "on-premises":
        if "provider" in value:
            out["provider"] = _require_str(value["provider"], "hosting.provider")
    else:
        out["provider"] = _require_str(
            value.get("provider"), f"hosting.provider (required for {model})"
        )
    return out


def _validate_lifecycle(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise InventoryMetadataError("data_lifecycle must be an object")
    extra = set(value) - {"records_categories", "time_to_live_years"}
    if extra:
        raise InventoryMetadataError(f"data_lifecycle: unknown key(s) {sorted(extra)}")
    out: dict[str, Any] = {}
    if "records_categories" in value:
        cats = value["records_categories"]
        if not isinstance(cats, list) or not cats:
            raise InventoryMetadataError(
                "data_lifecycle.records_categories must be a non-empty list"
            )
        out["records_categories"] = [
            _require_str(c, "data_lifecycle.records_categories[]") for c in cats
        ]
    if "time_to_live_years" in value:
        ttl = value["time_to_live_years"]
        # bool is an int subclass; reject it explicitly.
        if isinstance(ttl, bool) or not isinstance(ttl, (int, float)) or ttl < 0:
            raise InventoryMetadataError(
                "data_lifecycle.time_to_live_years must be a number >= 0"
            )
        out["time_to_live_years"] = ttl
    return out


def validate(data: Any) -> dict[str, Any]:
    """Return the normalised metadata dict, or raise InventoryMetadataError."""
    if not isinstance(data, dict):
        raise InventoryMetadataError("top level must be a JSON object")
    unknown = set(data) - _ALLOWED_KEYS
    if unknown:
        raise InventoryMetadataError(
            f"unknown key(s) {sorted(unknown)}; allowed: {sorted(_ALLOWED_KEYS)}"
        )
    out: dict[str, Any] = {}
    for key in _STRING_KEYS:
        if key in data:
            out[key] = _require_str(data[key], key)
    if "fips199_categorization" in data:
        raw = data["fips199_categorization"]
        level = raw.strip().capitalize() if isinstance(raw, str) else raw
        if level not in FIPS199_LEVELS:
            raise InventoryMetadataError(
                f"fips199_categorization must be one of {list(FIPS199_LEVELS)}, "
                f"got {raw!r}"
            )
        out["fips199_categorization"] = level
    if "hosting" in data:
        out["hosting"] = _validate_hosting(data["hosting"])
    if "data_lifecycle" in data:
        out["data_lifecycle"] = _validate_lifecycle(data["data_lifecycle"])
    # Keep the documented key order so output is stable across runs.
    order = (
        "fisma_system_id",
        "fips199_categorization",
        "hva_id",
        "hosting",
        "data_lifecycle",
        "notes",
    )
    return {k: out[k] for k in order if k in out}


def load(path: str) -> dict[str, Any]:
    """Read and validate a metadata file."""
    p = Path(path)
    try:
        size = p.stat().st_size
        if size > MAX_BYTES:
            raise InventoryMetadataError(
                f"{path}: {size} bytes exceeds the {MAX_BYTES}-byte limit"
            )
        data = json.loads(p.read_text(encoding="utf-8"))
    except OSError as e:
        raise InventoryMetadataError(f"{path}: {e.strerror or e}") from None
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise InventoryMetadataError(f"{path}: not valid JSON ({e})") from None
    return validate(data)


def _argparse_type(path: str) -> dict[str, Any]:
    try:
        return load(path)
    except InventoryMetadataError as e:
        raise argparse.ArgumentTypeError(str(e)) from None


# Slot 32: after --save / --output (31); this is per-run operator input.
@_registry.register_arguments(32)
def add_arguments(ap: argparse.ArgumentParser) -> None:
    """--inventory-metadata."""
    ap.add_argument(
        "--inventory-metadata",
        metavar="FILE",
        type=_argparse_type,
        default=None,
        help=(
            "JSON file of operator-supplied inventory facts the host can't "
            "know (FISMA ID, FIPS 199 level, HVA ID, hosting, data lifetime); "
            "carried into --json and --cbom"
        ),
    )
