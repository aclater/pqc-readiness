# SPDX-License-Identifier: Apache-2.0
"""An unreadable host path degrades one detection, never the scan (#229).

On Python 3.9-3.12, Path.is_dir()/is_file()/exists()/is_symlink() raise on
EACCES (only ENOENT/ENOTDIR/EBADF/ELOOP are swallowed), and listing an
unreadable directory raises on every version.  Found on OpenShift: a pod
confined as container_t got EACCES under /host/etc and the whole scan
aborted in scan_trust_store."""

from __future__ import annotations

import ast
import errno
import json
import os
import shutil
from collections.abc import Iterator
from pathlib import Path

import pytest

import pqc_readiness as pr
from pqc_readiness import _platform, cli

DETECT = Path(pr.__file__).parent / "detect"
FIXTURES = Path(__file__).parent / "fixtures"
OS_RELEASE_EL9 = (
    'NAME="Red Hat Enterprise Linux"\nID="rhel"\nID_LIKE="fedora"\n'
    'VERSION_ID="9.8"\nPRETTY_NAME="Red Hat Enterprise Linux 9.8 (Plow)"\n'
)

needs_non_root = pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0,
    reason="root bypasses file permissions",
)


# ------------------------------------------------------------ the helpers


@pytest.fixture
def eacces_stat(monkeypatch: pytest.MonkeyPatch) -> None:
    """Python 3.9-3.12 semantics on any version: stat raises EACCES."""

    def deny(self: Path, *a: object, **kw: object) -> os.stat_result:
        raise PermissionError(errno.EACCES, "Permission denied", str(self))

    monkeypatch.setattr(Path, "stat", deny)
    monkeypatch.setattr(Path, "lstat", deny)


@pytest.mark.parametrize(
    "probe",
    [
        _platform.safe_is_dir,
        _platform.safe_is_file,
        _platform.safe_exists,
        _platform.safe_is_symlink,
    ],
)
def test_safe_probes_read_eacces_as_absent(probe: object, eacces_stat: None) -> None:
    assert probe("/host/etc/ssl/certs") is False  # type: ignore[operator]


def test_safe_probes_still_answer_normally(tmp_path: Path) -> None:
    f = tmp_path / "f"
    f.write_text("x")
    (tmp_path / "l").symlink_to(f)
    assert _platform.safe_is_dir(tmp_path) and not _platform.safe_is_dir(f)
    assert _platform.safe_is_file(f) and not _platform.safe_is_file(tmp_path)
    assert _platform.safe_exists(f) and not _platform.safe_exists(tmp_path / "nope")
    assert _platform.safe_is_symlink(tmp_path / "l") and not _platform.safe_is_symlink(
        f
    )
    assert _platform.safe_listdir(tmp_path) == sorted(os.listdir(tmp_path)) or set(
        _platform.safe_listdir(tmp_path)
    ) == {"f", "l"}
    assert {p.name for p in _platform.safe_iterdir(tmp_path)} == {"f", "l"}


def test_safe_listing_of_missing_dir_is_empty(tmp_path: Path) -> None:
    assert _platform.safe_listdir(tmp_path / "nope") == []
    assert _platform.safe_iterdir(tmp_path / "nope") == []


@needs_non_root
def test_safe_probes_on_a_real_unreadable_tree(tmp_path: Path) -> None:
    locked = tmp_path / "locked"
    (locked / "certs").mkdir(parents=True)
    locked.chmod(0)
    try:
        # stat of a child needs search permission on the parent: EACCES.
        assert _platform.safe_is_dir(locked / "certs") is False
        assert _platform.safe_listdir(locked) == []
        assert _platform.safe_iterdir(locked) == []
    finally:
        locked.chmod(0o755)


# ------------------------------------------------------------ the guard


def test_guarded_scan_turns_oserror_into_unavailable() -> None:
    def scanner() -> dict[str, object]:
        raise PermissionError(errno.EACCES, "Permission denied", "/host/etc/pki")

    out = _platform.guarded_scan("trust store", scanner)
    assert out["available"] is False
    assert "/host/etc/pki" in str(out["reason"])
    assert "Permission denied" in str(out["reason"])


def test_guarded_scan_lets_bugs_through() -> None:
    def scanner() -> dict[str, object]:
        raise KeyError("bug")

    with pytest.raises(KeyError):
        _platform.guarded_scan("x", scanner)


def test_guarded_scan_passes_results_through() -> None:
    assert _platform.guarded_scan(
        "x", lambda a, b=0: {"available": True, "n": a + b}, 1, b=2
    ) == {
        "available": True,
        "n": 3,
    }


# ------------------------------------------------------------ end to end


@pytest.fixture
def no_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pr._platform, "HOST_PREFIX", "")
    monkeypatch.setattr(pr._platform, "OFFLINE_ROOT", "")


def _write(path: Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data)


@pytest.fixture
def locked_tree(tmp_path: Path) -> Iterator[Path]:
    """An EL9-like tree whose crypto directories can't be read: some locked
    themselves (listing fails) and some under a locked parent (stat fails,
    the case that raises from Path.is_dir on 3.9-3.12)."""
    root = tmp_path / "el9"
    shutil.copytree(FIXTURES / "rpmdb" / "el9" / "var", root / "var")
    _write(root / "usr/lib/os-release", OS_RELEASE_EL9)
    _write(root / "etc/hostname", "locked-01\n")
    (root / "etc/os-release").symlink_to("../usr/lib/os-release")
    _write(root / "etc/ssl/certs/ca.pem", "not a cert\n")
    _write(root / "etc/pki/tls/certs/ca-bundle.crt", "not a cert\n")
    _write(root / "etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release", "key\n")
    _write(root / "etc/ssh/sshd_config", "KexAlgorithms mlkem768x25519-sha256\n")
    _write(root / "etc/krb5.conf", "[libdefaults]\n")
    _write(root / "etc/krb5.conf.d/crypto-policies", "[libdefaults]\n")
    _write(root / "etc/wireguard/wg0.conf", "[Interface]\n")
    _write(root / "etc/nginx/nginx.conf", "events {}\n")
    _write(root / "usr/lib64/libgnutls.so.30", "\0")
    locked = [
        root / "etc/ssl",  # parent of certs/: stat of etc/ssl/certs fails
        root / "etc/pki",
        root / "etc/ssh",
        root / "etc/krb5.conf.d",
        root / "etc/wireguard",
        root / "etc/nginx",
        root / "usr/lib64",
    ]
    for d in locked:
        d.chmod(0)
    try:
        yield root
    finally:
        for d in locked:
            d.chmod(0o755)


ALL_OFFLINE_SCANS = [
    "--scan-trust-store",
    "--scan-crypto-material",
    "--scan-packages",
    "--scan-signing-keys",
    "--scan-crypto-libraries",
    "--scan-kerberos",
    "--scan-tunnels",
    "--scan-dnssec",
    "--scan-service-configs",
]


@needs_non_root
def test_offline_scan_of_a_tree_with_unreadable_dirs_completes(
    locked_tree: Path, no_prefix: None, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = cli.main(["--root", str(locked_tree), *ALL_OFFLINE_SCANS, "--json"])
    assert rc == 0
    report = json.loads(capsys.readouterr().out)
    assert report["hostname"] == "locked-01"
    # Readable sections still report; locked ones degrade, they don't vanish.
    assert report["packages"]["available"] is True
    for key in ("trust_store", "signing_keys", "kerberos", "tunnels"):
        assert isinstance(report[key], dict), key


@needs_non_root
def test_host_mount_scan_with_unreadable_trust_store_completes(
    locked_tree: Path, no_prefix: None, capsys: pytest.CaptureFixture[str]
) -> None:
    """The reported case: --host-mount, and /host/etc/ssl is unreadable."""
    cli.main(["--host-mount", str(locked_tree), "--scan-trust-store", "--json"])
    # The exit code reflects the verdict (the stub tree reads as 0 GiB, so
    # POOR); completing with a parseable report is what's under test.
    report = json.loads(capsys.readouterr().out)
    assert isinstance(report["trust_store"], dict)


# ------------------------------------------------------------ static guard

_PROBES = {"is_dir", "is_file", "exists", "is_symlink", "iterdir"}
_LISTERS = {("os", "listdir"), ("os", "scandir")}
_HANDLED = {"OSError", "PermissionError", "Exception", "BaseException"}


def _handles_oserror(t: ast.Try) -> bool:
    for h in t.handlers:
        if h.type is None:
            return True
        names = h.type.elts if isinstance(h.type, ast.Tuple) else [h.type]
        if any(isinstance(n, ast.Name) and n.id in _HANDLED for n in names):
            return True
    return False


def _unguarded_probes(tree: ast.AST) -> list[tuple[int, str]]:
    found: list[tuple[int, str]] = []

    def walk(node: ast.AST, guarded: bool) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            guarded = False  # runs later, outside any enclosing try
        if isinstance(node, ast.Try):
            inner = guarded or _handles_oserror(node)
            for c in node.body:
                walk(c, inner)
            for c in [*node.handlers, *node.orelse, *node.finalbody]:
                walk(c, guarded)
            return
        if (
            not guarded
            and isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
        ):
            fn, owner = node.func, node.func.value
            owner_name = owner.id if isinstance(owner, ast.Name) else None
            if (owner_name, fn.attr) in _LISTERS:
                found.append((node.lineno, f"os.{fn.attr}"))
            elif fn.attr in _PROBES and owner_name not in ("_platform", "os"):
                found.append((node.lineno, f".{fn.attr}()"))
        for c in ast.iter_child_nodes(node):
            walk(c, guarded)

    walk(tree, False)
    return found


def test_detectors_probe_host_paths_safely() -> None:
    """Every is_dir/is_file/exists/is_symlink/iterdir/listdir/scandir in a
    detector is either a _platform.safe_* helper or sits inside a try that
    handles OSError (those sites report the error themselves)."""
    offenders = [
        f"{f.name}:{line}: {what}"
        for f in sorted(DETECT.glob("*.py"))
        for line, what in _unguarded_probes(ast.parse(f.read_text()))
    ]
    assert offenders == [], "use _platform.safe_* (see #229):\n" + "\n".join(offenders)
