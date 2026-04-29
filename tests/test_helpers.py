# SPDX-License-Identifier: Apache-2.0
"""Unit tests for module-level helpers in `pqc_readiness`.

Audit option C1 introduced `_openssl_version_text` — a memoized wrapper
over `_run(['openssl', 'version'])` that avoids three redundant
subprocess invocations on every default scan. The contract under test
here is the cache itself, not the underlying binary's output."""
from __future__ import annotations

from typing import Any

import pytest

import pqc_readiness as pr


def test_openssl_version_text_caches_subprocess_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The helper must invoke `_run` exactly once across multiple calls
    in the same process, regardless of how many call sites consume it."""
    calls: list[tuple[Any, ...]] = []

    def counting_run(cmd: list[str], timeout: int = 10) -> tuple[int, str]:
        calls.append((tuple(cmd), timeout))
        return 0, "OpenSSL 3.5.5 27 Jan 2026\n"

    # The autouse conftest fixture cleared the cache before this test.
    monkeypatch.setattr(pr, "_run", counting_run)

    first = pr._openssl_version_text()
    second = pr._openssl_version_text()
    third = pr._openssl_version_text()

    assert first == second == third == (0, "OpenSSL 3.5.5 27 Jan 2026\n")
    assert len(calls) == 1, (
        f"_openssl_version_text should invoke _run exactly once across "
        f"three calls, but recorded {len(calls)} invocations: {calls}"
    )
    # And the single invocation should preserve the documented argv + timeout.
    assert calls[0] == (("openssl", "version"), 5)


def test_openssl_version_text_cache_clear_resets_subprocess(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`.cache_clear()` is part of the public test contract documented
    in the helper's docstring — without it, monkeypatched _run would be
    invisible across tests."""
    calls: list[int] = []

    def counting_run(cmd: list[str], timeout: int = 10) -> tuple[int, str]:
        calls.append(1)
        return 0, "OpenSSL 3.5.5 27 Jan 2026\n"

    monkeypatch.setattr(pr, "_run", counting_run)

    pr._openssl_version_text()
    assert len(calls) == 1
    pr._openssl_version_text()
    assert len(calls) == 1  # cached

    pr._openssl_version_text.cache_clear()
    pr._openssl_version_text()
    assert len(calls) == 2  # subprocess re-invoked after cache_clear
