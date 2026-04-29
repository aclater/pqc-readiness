# SPDX-License-Identifier: Apache-2.0
"""pytest configuration for pqc-readiness.

Adds the repo root to sys.path so the script (which lives at the repo
root and is named `pqc_readiness.py`) is importable as a module."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def _clear_openssl_version_cache() -> None:
    """`_openssl_version_text` is process-cached for runtime efficiency
    (audit C1). In tests, monkeypatching `_run` is invisible once the
    cache is hot — clear before every test so each one starts with a
    fresh subprocess invocation."""
    import pqc_readiness as pr
    pr._openssl_version_text.cache_clear()
