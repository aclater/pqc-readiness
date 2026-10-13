# SPDX-License-Identifier: Apache-2.0
"""Package-signing key inventory (#153).

Fixture trees under tests/fixtures/signing_keys/ were copied from real
images (see the README there).  Expected values come from independent
tools run on the same files: `rpm -q gpg-pubkey` for the rpm databases,
`gpg --show-keys` for the apt and pacman keyrings, `openssl pkey` for
the apk keys, and rpm 6 (Sequoia) for the v6 ML-DSA-87+Ed448 key that
GnuPG 2.4 cannot read.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import json
import os
import shutil
import struct
from pathlib import Path

import pytest

import pqc_readiness as pr
from pqc_readiness.detect import protocols_signing as ps

FIX = Path(__file__).parent / "fixtures" / "signing_keys"

# Red Hat "release key 4": a v6 ML-DSA-87+Ed448 composite key (RFC 9980).
# Fingerprint as printed by `rpmkeys --list` (rpm 6.0.2, Fedora 44).
RH_PQC_FPR = "FCD355B305707A62DA143AB6E422397E50FE8467A2A95343D246D6276AFEDF8F"  # pragma: allowlist secret (public key fingerprint)


def _no_subprocess(cmd, timeout=None):  # noqa: ARG001
    raise AssertionError(f"unexpected subprocess: {cmd}")


@pytest.fixture
def host(monkeypatch, tmp_path):
    """Copy a fixture tree into tmp_path, decompress rpm databases, and
    point --host-mount at it.  Real subprocesses are forbidden."""

    def _use(name: str) -> Path:
        root = tmp_path / "root"
        shutil.copytree(FIX / name / "root", root, symlinks=True)
        for gz in list(root.rglob("*.gz")):
            gz.with_suffix("").write_bytes(gzip.decompress(gz.read_bytes()))
            gz.unlink()
        sysimage = root / "usr/lib/sysimage/rpm"
        if sysimage.is_dir() and not (root / "var/lib/rpm").exists():
            # EL10 / Fedora / SUSE: /var/lib/rpm is a relative symlink.
            (root / "var/lib").mkdir(parents=True, exist_ok=True)
            os.symlink("../../usr/lib/sysimage/rpm", root / "var/lib/rpm")
        monkeypatch.setattr(pr._platform, "HOST_PREFIX", str(root))
        monkeypatch.setattr(pr._platform, "_run", _no_subprocess)
        return root

    return _use


def _rpm_key_ids(name: str) -> list[str]:
    """Short key IDs from `rpm -q gpg-pubkey` (gpg-pubkey-<id>-<created>)."""
    return sorted(
        ln.split("-")[2]
        for ln in (FIX / name / "expected-rpm-q.txt").read_text().split()
    )


def _gpg_fprs(name: str) -> dict[str, tuple[int, int]]:
    """fingerprint -> (algorithm id, bits) from `gpg --show-keys --with-colons`."""
    out: dict[str, tuple[int, int]] = {}
    for ln in (FIX / name / "expected-fprs.txt").read_text().splitlines():
        fpr, algo, bits = ln.split()
        out[fpr] = (int(algo), int(bits))
    return out


# ---------------------------------------------------------------------------
# rpm families: every database format, verified against rpm itself
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "family", "backend"),
    [
        ("el10-sqlite", "rhel", "sqlite"),
        ("el8-bdb", "rhel", "bdb"),
        ("suse-ndb", "suse", "ndb"),
    ],
)
def test_rpm_imported_keys_match_rpm_q(host, name, family, backend) -> None:
    host(name)
    out = ps.scan_signing_keys({"family": family, "version_id": "10.2"})
    assert out["available"] is True
    ids = sorted(k["key_id"][-8:].lower() for k in out["keys"])
    assert ids == _rpm_key_ids(name)
    rpmdb = [s for s in out["sources"] if s["origin"] == "rpmdb"]
    assert len(rpmdb) == 1 and rpmdb[0]["source"].endswith(f"(rpmdb-{backend})")
    assert "/tmp" not in json.dumps(out)  # host prefix never leaks into output


def test_el10_red_hat_pqc_release_key(host) -> None:
    """RHEL 10.2's rpmdb trusts a v6 ML-DSA-87+Ed448 key alongside RSA."""
    host("el10-sqlite")
    out = ps.scan_signing_keys({"family": "rhel", "version_id": "10.2"})
    pqc = [k for k in out["keys"] if k["fingerprint"] == RH_PQC_FPR]
    assert len(pqc) == 1
    key = pqc[0]
    assert key["version"] == 6
    assert key["algorithm"] == "ML-DSA-87+Ed448"
    assert key["algorithm_id"] == 31
    assert key["signing_pqc_category"] == "hybrid"
    assert key["key_id"] == RH_PQC_FPR[:16]
    assert "release key 4" in key["uid"]
    assert out["summary"] == {
        "total": 3,
        "classical": 2,
        "hybrid": 1,
        "pure_pqc": 0,
        "all_classical": False,
    }
    rsa = [k for k in out["keys"] if k["algorithm"] == "RSA"]
    assert {k["bits"] for k in rsa} == {4096}


def test_el10_repo_gpgkey_sources(host) -> None:
    host("el10-sqlite")
    out = ps.scan_signing_keys({"family": "rhel", "version_id": "10.2"})
    repo = {s["source"]: s for s in out["sources"] if s["origin"] == "repo-gpgkey"}
    # enabled repo with a present file: parsed; its keys are the same as
    # the imported ones, so they de-duplicate onto them.
    ok = repo["/etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release"]
    assert ok["keys"] == 3 and "error" not in ok
    # enabled repo pointing at a missing file: surfaced, not skipped
    assert "missing" in repo["/etc/pki/rpm-gpg/RPM-GPG-KEY-missing"]["error"]
    # disabled repo: ignored
    assert "/etc/pki/rpm-gpg/RPM-GPG-KEY-not-there" not in repo
    assert out["summary"]["total"] == 3
    for key in out["keys"]:
        assert {o["origin"] for o in key["origins"]} == {"rpmdb", "repo-gpgkey"}


def test_rpm_cli_fallback_when_rpmdb_unreadable(host, monkeypatch) -> None:
    root = host("el8-bdb")
    (root / "var/lib/rpm/Packages").write_bytes(
        b"\0" * 12 + b"\x61\x15\x06\x00" + b"\0" * 64
    )
    armored = (
        FIX / "el10-sqlite/root/etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release"
    ).read_text()
    calls: list[list[str]] = []

    def fake_run(cmd, timeout=None):  # noqa: ARG001
        calls.append(cmd)
        return 0, armored

    monkeypatch.setattr(pr._platform, "_run", fake_run)
    out = ps.scan_signing_keys({"family": "rhel"})
    (cmd,) = calls
    assert cmd[:5] == ["rpm", "--root", str(root), "--dbpath", "/var/lib/rpm"]
    assert "gpg-pubkey" in cmd
    rpmdb = [s for s in out["sources"] if s["origin"] == "rpmdb"][0]
    assert rpmdb["source"].endswith("(rpm-cli)")
    assert out["summary"]["hybrid"] == 1


def test_rpm_family_without_any_database(host, monkeypatch) -> None:
    root = host("alpine")  # a tree with no rpm database at all
    assert not (root / "var/lib/rpm").exists()
    out = ps.scan_signing_keys({"family": "rhel"})
    assert out["available"] is True  # the source list explains what failed
    assert out["sources"][0]["origin"] == "rpmdb"
    assert "no rpm database" in out["sources"][0]["error"]
    assert out["keys"] == [] and out["summary"]["all_classical"] is False


# ---------------------------------------------------------------------------
# apt, pacman, apk
# ---------------------------------------------------------------------------


def test_debian_trusted_and_signed_by_match_gpg(host) -> None:
    host("debian13")
    out = ps.scan_signing_keys({"family": "debian"})
    expected = _gpg_fprs("debian13")
    got = {k["fingerprint"]: k for k in out["keys"]}
    assert set(got) == set(expected)
    for fpr, (algo, bits) in expected.items():
        assert got[fpr]["algorithm_id"] == algo
        if algo == 22:  # EdDSALegacy: gpg reports 255 bits for Ed25519
            assert got[fpr]["curve"] == "Ed25519" and bits == 255
        else:
            assert got[fpr]["bits"] == bits
    origins = {s["origin"] for s in out["sources"]}
    assert origins == {"apt-trusted", "apt-signed-by"}
    signed_by = [s for s in out["sources"] if s["origin"] == "apt-signed-by"]
    assert [s["source"] for s in signed_by] == [
        "/usr/share/keyrings/debian-archive-keyring.pgp"
    ]
    assert out["summary"]["all_classical"] is True


def test_apt_one_line_and_inline_deb822_signed_by(host) -> None:
    root = host("debian13")
    asc = (root / "etc/apt/trusted.gpg.d/debian-archive-trixie-stable.asc").read_text()
    shutil.rmtree(root / "etc/apt/trusted.gpg.d")
    (root / "etc/apt/sources.list.d/debian.sources").unlink()
    (root / "etc/apt/sources.list.d/extra.list").write_text(
        "deb [arch=amd64 signed-by=/usr/share/keyrings/debian-archive-keyring.pgp] "
        "http://deb.example/debian trixie main\n"
    )
    inline = "\n".join(
        " ." if not ln.strip() else " " + ln for ln in asc.strip().splitlines()
    )
    (root / "etc/apt/sources.list.d/inline.sources").write_text(
        "Types: deb\nURIs: http://deb.example/x\nSuites: x\nComponents: main\n"
        f"Signed-By:\n{inline}\n"
    )
    out = ps.scan_signing_keys({"family": "debian"})
    by_source = {s["source"]: s for s in out["sources"]}
    assert by_source["/usr/share/keyrings/debian-archive-keyring.pgp"]["keys"] > 0
    assert by_source["inline #1"]["keys"] == 1 and "error" not in by_source["inline #1"]


def test_pacman_trusted_keys_match_gpg(host) -> None:
    host("arch")
    out = ps.scan_signing_keys({"family": "arch"})
    expected = _gpg_fprs("arch")
    got = {k["fingerprint"]: k for k in out["keys"]}
    assert set(got) == set(expected)
    for fpr, (algo, _bits) in expected.items():
        assert got[fpr]["algorithm_id"] == algo
    eddsa = [k for k in out["keys"] if k["algorithm"] == "EdDSALegacy"]
    assert eddsa and all(k["curve"] == "Ed25519" for k in eddsa)


def test_pacman_untrusted_keys_are_dropped(host) -> None:
    root = host("arch")
    trusted = root / "usr/share/pacman/keyrings/archlinux-trusted"
    first = trusted.read_text().splitlines()[0]
    trusted.write_text(first + "\n")
    out = ps.scan_signing_keys({"family": "arch"})
    assert [k["fingerprint"] for k in out["keys"]] == [first.split(":")[0]]


def test_apk_rsa_keys(host) -> None:
    host("alpine")
    out = ps.scan_signing_keys({"family": "alpine"})
    # `openssl pkey -pubin -text`: three 2048-bit and two 4096-bit keys
    assert sorted(k["bits"] for k in out["keys"]) == [2048, 2048, 2048, 4096, 4096]
    assert all(k["algorithm"] == "RSA" for k in out["keys"])
    assert out["summary"]["all_classical"] is True


def test_apk_ml_dsa_key_is_pure_pqc(host) -> None:
    root = host("alpine-mldsa")
    out = ps.scan_signing_keys({"family": "alpine"})
    (key,) = out["keys"]
    assert key["algorithm"] == "ML-DSA-65"
    assert key["algorithm_oid"] == "2.16.840.1.101.3.4.3.18"
    assert key["signing_pqc_category"] == "pure_pqc"
    pem = (root / "etc/apk/keys/test-mldsa65.rsa.pub").read_text()
    der = base64.b64decode("".join(pem.strip().splitlines()[1:-1]))
    assert key["fingerprint"] == hashlib.sha256(der).hexdigest().upper()
    assert out["summary"]["pure_pqc"] == 1 and out["summary"]["all_classical"] is False


def test_unknown_family_unavailable() -> None:
    out = ps.scan_signing_keys({"family": "unknown"})
    assert out["available"] is False and "family=unknown" in out["reason"]


def test_corrupt_keyring_is_a_source_error_not_a_crash(host) -> None:
    root = host("debian13")
    (root / "etc/apt/trusted.gpg.d/broken.gpg").write_bytes(
        b"\x99\x01\x0d\x04"
    )  # truncated
    out = ps.scan_signing_keys({"family": "debian"})
    broken = [s for s in out["sources"] if s["source"].endswith("broken.gpg")]
    assert broken and "error" in broken[0] and broken[0]["keys"] == 0
    assert out["summary"]["total"] == 9


# ---------------------------------------------------------------------------
# OpenPGP parser units (RFC 9580 / RFC 9980)
# ---------------------------------------------------------------------------


def _v6_key(algo: int, material: bytes = b"\x00" * 32, tag: int = 6) -> bytes:
    body = bytes([6]) + struct.pack(">I", 1_760_000_000) + bytes([algo])
    body += struct.pack(">I", len(material)) + material
    return bytes([0xC0 | tag, len(body)]) + body


@pytest.mark.parametrize(
    ("algo", "name", "category"),
    [
        (30, "ML-DSA-65+Ed25519", "hybrid"),
        (31, "ML-DSA-87+Ed448", "hybrid"),
        (32, "SLH-DSA-SHAKE-128s", "pure_pqc"),
        (33, "SLH-DSA-SHAKE-128f", "pure_pqc"),
        (34, "SLH-DSA-SHAKE-256s", "pure_pqc"),
    ],
)
def test_rfc9980_signing_algorithms(algo, name, category) -> None:
    (key,) = ps.parse_openpgp_keys(_v6_key(algo))
    assert key["algorithm"] == name
    assert key["signing_pqc_category"] == category
    body = _v6_key(algo)[2:]
    expected = (
        hashlib.sha256(b"\x9b" + struct.pack(">I", len(body)) + body)
        .hexdigest()
        .upper()
    )
    assert key["fingerprint"] == expected and key["key_id"] == expected[:16]


def test_pqc_encryption_subkey_does_not_make_signing_key_pqc() -> None:
    """An ML-KEM subkey (id 35) protects encryption, not signatures."""
    data = _v6_key(27) + _v6_key(35, tag=14)
    (key,) = ps.parse_openpgp_keys(data)
    assert [s["algorithm"] for s in key["subkeys"]] == ["ML-KEM-768+X25519"]
    assert key["signing_pqc_category"] == "classical"


def test_pqc_signing_subkey_counts() -> None:
    (key,) = ps.parse_openpgp_keys(_v6_key(27) + _v6_key(30, tag=14))
    assert key["signing_pqc_category"] == "hybrid"


def test_armor_with_headers_and_surrounding_text() -> None:
    raw = (
        FIX / "el10-sqlite/root/etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release"
    ).read_bytes()
    keys = ps.parse_key_blob(
        b"Some preamble text.\n"
        + raw.replace(
            b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n",
            b"-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: test\nComment: x\n",
            1,
        )
    )
    assert len(keys) == 3


@pytest.mark.parametrize(
    "data",
    [b"\x00garbage", b"\x99\x00", b"\xc6\xff\x00\x00\x00\x50\x06", _v6_key(31)[:-5]],
)
def test_malformed_packets_raise_key_parse_error(data) -> None:
    with pytest.raises(ps.KeyParseError):
        ps.parse_openpgp_keys(data)


# ---------------------------------------------------------------------------
# Report, SARIF and text integration
# ---------------------------------------------------------------------------


def test_cli_flag_and_default_report_field() -> None:
    from pqc_readiness import cli

    args = cli.build_parser().parse_args(["--scan-signing-keys"])
    assert args.scan_signing_keys is True
    assert pr.Report().signing_keys == {}


def test_sarif_pqc_009_only_when_all_classical(host) -> None:
    host("el8-bdb")
    r = pr.Report(signing_keys=ps.scan_signing_keys({"family": "rhel"}))
    ids = [f.rule_id for f in pr.build_findings(r)]
    assert "pqc-009-classical-package-signing-keys" in ids
    finding = [f for f in pr.build_findings(r) if f.rule_id.startswith("pqc-009")][0]
    assert finding.level == "note"
    assert finding.properties["signing_keys:total"] == 2


def test_sarif_pqc_009_silent_with_pqc_key(host) -> None:
    host("el10-sqlite")
    r = pr.Report(
        signing_keys=ps.scan_signing_keys({"family": "rhel", "version_id": "10.2"})
    )
    assert all(not f.rule_id.startswith("pqc-009") for f in pr.build_findings(r))


def test_text_section_lists_keys(host) -> None:
    host("el10-sqlite")
    r = pr.Report(
        signing_keys=ps.scan_signing_keys({"family": "rhel", "version_id": "10.2"})
    )
    text = pr.render_text(r)
    assert "11. Package-signing keys" in text
    assert "ML-DSA-87+Ed448" in text and "hybrid=1" in text
