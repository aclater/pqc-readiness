# SPDX-License-Identifier: Apache-2.0
"""pytest configuration for pqc-readiness.

Imports the ``pqc_readiness`` package from the repo root, or from a built
zipapp when ``PQC_READINESS_PYZ`` points at one (CI runs the whole suite
both ways, #80). Subprocess tests run the CLI through ``PQC_CLI``.

Tests must patch the module that *defines* a name
(``monkeypatch.setattr(pr.detect.certs, "TRUST_STORE_DIRS", ...)``), never
the package root: the root only re-exports, so a patch there would
silently not reach the code under test. The ``monkeypatch`` fixture below
rejects such patches."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
PACKAGE_SRC = REPO_ROOT / "pqc_readiness"
PYZ = os.environ.get("PQC_READINESS_PYZ")
_IMPORT_ROOT = str(Path(PYZ).resolve()) if PYZ else str(REPO_ROOT)
if _IMPORT_ROOT not in sys.path:
    sys.path.insert(0, _IMPORT_ROOT)

# Command line for subprocess tests: the zipapp itself, or the package.
PQC_CLI: list[str] = (
    [sys.executable, _IMPORT_ROOT] if PYZ else [sys.executable, "-m", "pqc_readiness"]
)
PQC_ENV: dict[str, str] = {
    **os.environ,
    "PYTHONPATH": os.pathsep.join(
        p for p in (_IMPORT_ROOT, os.environ.get("PYTHONPATH", "")) if p
    ),
}

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def _clear_openssl_version_cache() -> None:
    """`_openssl_version_text` is process-cached for runtime efficiency
    (audit C1). In tests, monkeypatching `_run` is invisible once the
    cache is hot — clear before every test so each one starts with a
    fresh subprocess invocation."""
    import pqc_readiness as pr

    pr._platform._openssl_version_text.cache_clear()
    pr.detect.hardware._openssl_providers_verbose_text.cache_clear()
    pr.detect.packages._query_rpm_packages_cached.cache_clear()


def _reject_package_root(target: Any, args: tuple[Any, ...]) -> None:
    import pqc_readiness

    if target is pqc_readiness:
        name = args[0] if args else "?"
        raise AssertionError(
            f"monkeypatch on the pqc_readiness package root ({name!r}) does not reach the "
            "code under test; patch the defining module instead, e.g. "
            "pr.detect.certs or pr._platform"
        )
    if isinstance(target, str) and target.rpartition(".")[0] == "pqc_readiness":
        raise AssertionError(
            f"monkeypatch of {target!r} targets the package root; patch the defining module"
        )


@pytest.fixture
def monkeypatch(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    """pytest's monkeypatch, refusing patches on the package root (#80)."""
    real_setattr, real_delattr = monkeypatch.setattr, monkeypatch.delattr

    def setattr_(target: Any, *args: Any, **kwargs: Any) -> None:
        _reject_package_root(target, args)
        real_setattr(target, *args, **kwargs)

    def delattr_(target: Any, *args: Any, **kwargs: Any) -> None:
        _reject_package_root(target, args)
        real_delattr(target, *args, **kwargs)

    monkeypatch.setattr = setattr_  # type: ignore[method-assign]
    monkeypatch.delattr = delattr_  # type: ignore[method-assign]
    return monkeypatch
