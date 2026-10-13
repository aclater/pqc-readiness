# SPDX-License-Identifier: Apache-2.0
"""Certificate parsing, crypto-material discovery and the private-key
policy (#108).

No real private key is ever committed or generated: key files are
assembled at test time from a PEM label (built from fragments so secret
scanners don't flag this source) around a random marker body, and every
output format is checked for that marker.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import shutil
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

import pqc_readiness as pr
from pqc_readiness.detect import certs_discovery as cd

FIXTURES = Path(__file__).parent / "fixtures" / "trust_store"
NOW = datetime(2026, 10, 13, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# DER builders (structurally valid, not cryptographically valid)
# ---------------------------------------------------------------------------


def _len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _len(len(value)) + value


def _oid(dotted: str) -> bytes:
    arcs = [int(a) for a in dotted.split(".")]
    out = bytearray([40 * arcs[0] + arcs[1]])
    for arc in arcs[2:]:
        chunk = [arc & 0x7F]
        arc >>= 7
        while arc:
            chunk.append(0x80 | (arc & 0x7F))
            arc >>= 7
        out.extend(reversed(chunk))
    return _tlv(0x06, bytes(out))


def _name(cn: str, org: str = "") -> bytes:
    rdns = b""
    if org:
        rdns += _tlv(0x31, _tlv(0x30, _oid("2.5.4.10") + _tlv(0x0C, org.encode())))
    rdns += _tlv(0x31, _tlv(0x30, _oid("2.5.4.3") + _tlv(0x0C, cn.encode())))
    return _tlv(0x30, rdns)


def _time(dt: datetime) -> bytes:
    if dt.year < 2050:
        return _tlv(0x17, dt.strftime("%y%m%d%H%M%SZ").encode())
    return _tlv(0x18, dt.strftime("%Y%m%d%H%M%SZ").encode())


def _rsa_spki(bits: int) -> bytes:
    modulus = (1 << (bits - 1)) | 1
    rsa_pub = _tlv(0x30, _tlv(0x02, b"\x00" + modulus.to_bytes(bits // 8, "big")) + _tlv(0x02, b"\x01\x00\x01"))
    alg = _tlv(0x30, _oid("1.2.840.113549.1.1.1") + b"\x05\x00")
    return _tlv(0x30, alg + _tlv(0x03, b"\x00" + rsa_pub))


def _ec_spki(curve_oid: str) -> bytes:
    alg = _tlv(0x30, _oid("1.2.840.10045.2.1") + _oid(curve_oid))
    return _tlv(0x30, alg + _tlv(0x03, b"\x00\x04" + b"\x01" * 64))


def build_cert(
    subject: str = "leaf.example",
    issuer: str = "Example CA",
    not_before: datetime = datetime(2025, 1, 1, tzinfo=timezone.utc),
    not_after: datetime = datetime(2027, 1, 1, tzinfo=timezone.utc),
    spki: bytes | None = None,
    basic_constraints_ca: bool | None = False,
    serial: int = 0x1234,
) -> bytes:
    exts = b""
    if basic_constraints_ca is not None:
        bc = _tlv(0x30, _tlv(0x01, b"\xff") if basic_constraints_ca else b"")
        exts = _tlv(0xA3, _tlv(0x30, _tlv(0x30, _oid("2.5.29.19") + _tlv(0x04, bc))))
    tbs = _tlv(
        0x30,
        _tlv(0xA0, _tlv(0x02, b"\x02"))
        + _tlv(0x02, serial.to_bytes(4, "big"))
        + _tlv(0x30, _oid("1.2.840.113549.1.1.11"))
        + (_name(issuer, "Example Org") if issuer == subject else _name(issuer))
        + _tlv(0x30, _time(not_before) + _time(not_after))
        + _name(subject, "Example Org")
        + (spki or _rsa_spki(2048))
        + exts,
    )
    sig_alg = _tlv(0x30, _oid("1.2.840.113549.1.1.11"))
    return _tlv(0x30, tbs + sig_alg + _tlv(0x03, b"\x00" + b"\x02" * 64))


def to_pem(der: bytes, label: str = "CERTIFICATE") -> str:
    b64 = base64.b64encode(der).decode()
    lines = "\n".join(b64[i : i + 64] for i in range(0, len(b64), 64))
    return f"-----BEGIN {label}-----\n{lines}\n-----END {label}-----\n"


# Label fragments: the joined strings exist only at run time.
_PRIV = "PRIVATE" + " " + "KEY"


def fake_key_pem(kind: str = "") -> tuple[str, bytes]:
    """A PEM block with a private-key label and a random marker body.
    Returns (pem_text, marker_bytes)."""
    marker = b"PQCR-MARKER-" + secrets.token_hex(16).encode()
    label = f"{kind} {_PRIV}".strip()
    return to_pem(marker * 4, label), marker


def _write(path: Path, text: str | bytes, mode: int = 0o600) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(text, str):
        path.write_text(text)
    else:
        path.write_bytes(text)
    path.chmod(mode)
    return path


@pytest.fixture(autouse=True)
def _no_host_prefix(monkeypatch) -> None:
    monkeypatch.setattr(pr._platform, "HOST_PREFIX", "")


# ---------------------------------------------------------------------------
# parse_certificate
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "algorithm", "size", "category"),
    [
        ("rsa-2048.pem", "RSA", 2048, "classical"),
        ("ec-p256.pem", "EC P-256", 256, "classical"),
        ("ml-dsa-65.pem", "ML-DSA-65", None, "pure_pqc"),
        ("slh-dsa-sha2-128s.pem", "SLH-DSA-SHA2-128s", None, "pure_pqc"),
    ],
)
def test_parse_real_openssl_certificates(name, algorithm, size, category) -> None:
    der = pr.detect.certs._certs_in_file(FIXTURES / name)[0]
    c = pr.parse_certificate(der)
    assert c["key_algorithm"] == algorithm
    assert c["key_size"] == size
    assert c["category"] == category
    assert c["sha256"] == hashlib.sha256(der).hexdigest()
    assert c["subject"].startswith("CN=pqc-readiness fixture")
    assert c["is_ca"] is True and c["role"] == "ca" and c["self_signed"] is True
    assert c["not_after"].startswith("2126-") and c["not_after"].endswith("+00:00")


def test_parse_leaf_fields_and_rfc4514_name() -> None:
    der = build_cert(subject="web, frontend", serial=0xABCD, spki=_rsa_spki(3072))
    c = pr.parse_certificate(der)
    assert c["role"] == "leaf" and c["is_ca"] is False and c["self_signed"] is False
    assert c["subject"] == "CN=web\\, frontend,O=Example Org"
    assert c["issuer"] == "CN=Example CA"
    assert c["serial"] == "0000abcd"
    assert c["key_size"] == 3072
    assert c["not_before"] == "2025-01-01T00:00:00+00:00"
    assert c["not_after"] == "2027-01-01T00:00:00+00:00"


def test_parse_generalizedtime_and_ec_curve() -> None:
    der = build_cert(
        not_after=datetime(2061, 6, 1, tzinfo=timezone.utc), spki=_ec_spki("1.3.132.0.34")
    )
    c = pr.parse_certificate(der)
    assert c["not_after"] == "2061-06-01T00:00:00+00:00"
    assert (c["key_algorithm"], c["key_size"]) == ("EC P-384", 384)


def test_v1_self_signed_without_basic_constraints_is_a_ca() -> None:
    der = build_cert(subject="Old Root", issuer="Old Root", basic_constraints_ca=None)
    assert pr.parse_certificate(der)["role"] == "ca"


def test_self_signed_leaf_with_ca_false_stays_leaf() -> None:
    der = build_cert(subject="localhost", issuer="localhost", basic_constraints_ca=False)
    c = pr.parse_certificate(der)
    assert c["self_signed"] is True and c["role"] == "leaf"


@pytest.mark.parametrize("cut", [1, 10, 40, 80, 120])
def test_truncated_certificate_raises_dererror_only(cut: int) -> None:
    der = build_cert()
    with pytest.raises(pr.DERError):
        pr.parse_certificate(der[: len(der) - cut])


# ---------------------------------------------------------------------------
# expiry buckets
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("not_after", "bucket"),
    [
        ("2026-10-12T00:00:00+00:00", "expired"),
        ("2026-10-20T00:00:00+00:00", "lt_30d"),
        ("2026-12-01T00:00:00+00:00", "lt_90d"),
        ("2027-06-01T00:00:00+00:00", "lt_1y"),
        ("2030-01-01T00:00:00+00:00", "gt_1y"),
    ],
)
def test_expiry_bucket(not_after: str, bucket: str) -> None:
    assert cd.expiry_bucket(not_after, NOW) == bucket


# ---------------------------------------------------------------------------
# scan_crypto_material
# ---------------------------------------------------------------------------


def _scan(root: Path, **kw: Any) -> dict[str, Any]:
    return cd.scan_crypto_material(paths=[str(root)], now=NOW, **kw)


def test_discovers_leaf_ca_keys_and_pairs_public_halves(tmp_path) -> None:
    leaf = build_cert(subject="www.example", spki=_rsa_spki(2048))
    _write(tmp_path / "certs/localhost.crt", to_pem(leaf), 0o644)
    key_pem, _ = fake_key_pem()
    _write(tmp_path / "private/localhost.key", key_pem)
    ca = build_cert(subject="Example CA", issuer="Example CA", basic_constraints_ca=True, spki=_ec_spki("1.2.840.10045.3.1.7"))
    _write(tmp_path / "ca/ca.pem", to_pem(ca), 0o644)
    combined = build_cert(subject="haproxy.example", spki=_ec_spki("1.3.132.0.34"))
    key2, _ = fake_key_pem("EC")
    _write(tmp_path / "haproxy/site.pem", to_pem(combined) + key2)

    r = _scan(tmp_path)
    assert r["available"] is True
    s = r["summary"]
    assert (s["certificates"], s["leaf_certificates"], s["ca_certificates"]) == (3, 2, 1)
    assert s["private_keys"] == 2
    keys = {k["path"].rsplit("/", 1)[-1]: k for k in r["private_keys"]}
    pk = keys["localhost.key"]
    assert pk["key_type"] == "PKCS#8"
    assert pk["public_half"]["key_algorithm"] == "RSA"
    assert pk["public_half"]["key_size"] == 2048
    assert pk["public_half"]["source"].endswith("(heuristic)")
    hk = keys["site.pem"]
    assert hk["key_type"] == "EC"
    assert hk["public_half"]["source"] == "certificate in the same file"
    assert hk["public_half"]["key_algorithm"] == "EC P-384"


def test_ambiguous_stem_gives_no_public_half(tmp_path) -> None:
    for d in ("a", "b"):
        _write(tmp_path / d / "server.crt", to_pem(build_cert(subject=f"{d}.example", serial=ord(d))), 0o644)
    key_pem, _ = fake_key_pem()
    _write(tmp_path / "server.key", key_pem)
    (k,) = _scan(tmp_path)["private_keys"]
    assert k["public_half"] is None


def test_private_key_permissions_and_encryption(tmp_path) -> None:
    open_pem, _ = fake_key_pem("RSA")
    _write(tmp_path / "open.key", open_pem, 0o644)
    enc_pem, _ = fake_key_pem("ENCRYPTED")
    _write(tmp_path / "enc.key", enc_pem, 0o600)
    keys = {Path(k["path"]).name: k for k in _scan(tmp_path)["private_keys"]}
    assert keys["open.key"]["world_readable"] is True and keys["open.key"]["mode"] == "0644"
    assert keys["open.key"]["key_type"] == "RSA" and keys["open.key"]["encrypted"] is False
    assert keys["enc.key"]["world_readable"] is False
    assert keys["enc.key"]["encrypted"] is True


def test_private_key_bytes_never_reach_any_output(tmp_path, monkeypatch) -> None:
    """The core policy test: a marker inside every key body must not appear
    in the JSON, nor in any renderer's output."""
    markers = []
    for i, kind in enumerate(("", "RSA", "EC", "OPENSSH", "ENCRYPTED")):
        pem, marker = fake_key_pem(kind)
        markers.append(marker)
        _write(tmp_path / f"k{i}.key", pem)
    leaf = build_cert(subject="k0")
    _write(tmp_path / "k0.crt", to_pem(leaf), 0o644)
    cm = _scan(tmp_path)
    assert cm["summary"]["private_keys"] == 5
    r = pr.Report(hostname="h", crypto_material=cm, trust_store={})
    outputs = [json.dumps(cm), pr.render_text(r), pr.render_markdown(r), pr.render_sarif(r), pr.render_spdx(r)]
    outputs += [pr.render_cbom(r, v) for v in ("1.6", "1.7")]
    blob = "\n".join(outputs).encode()
    for m in markers:
        assert m not in blob
        assert base64.b64encode(m * 4)[:24] not in blob


def test_file_cap_truncates_deterministically(tmp_path) -> None:
    for i in range(6):
        _write(tmp_path / f"c{i}.crt", to_pem(build_cert(serial=i + 1)), 0o644)
    r = _scan(tmp_path, max_files=4)
    assert r["truncated"] is True and r["files_examined"] == 4
    assert r["summary"]["certificates"] == 4
    assert _scan(tmp_path, max_files=4)["certificates"] == r["certificates"]


def test_symlinked_dirs_not_followed_and_file_links_deduplicated(tmp_path) -> None:
    outside = tmp_path / "outside"
    _write(outside / "secret.crt", to_pem(build_cert(subject="outside")), 0o644)
    root = tmp_path / "root"
    _write(root / "real.crt", to_pem(build_cert(subject="inside")), 0o644)
    os.symlink(outside, root / "linkdir")
    os.symlink(root / "real.crt", root / "alias.crt")
    r = _scan(root)
    subjects = [c["subject"] for c in r["certificates"]]
    assert subjects == ["CN=inside,O=Example Org"]
    assert r["files_examined"] == 1


def test_oversized_file_is_skipped(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(cd, "MAX_PEM_FILE_BYTES", 100)
    _write(tmp_path / "big.crt", to_pem(build_cert()), 0o644)
    assert _scan(tmp_path)["summary"]["certificates"] == 0


def test_host_mount_reads_host_tree_and_reroots_absolute_links(tmp_path, monkeypatch) -> None:
    host = tmp_path / "host"
    _write(host / "etc/pki/tls/certs/server.crt", to_pem(build_cert(subject="host-cert")), 0o644)
    # An absolute link on the host must resolve inside the host tree, not
    # in the scanner container's own filesystem.
    _write(host / "etc/pki/real/target.crt", to_pem(build_cert(subject="via-link", serial=9)), 0o644)
    os.symlink("/etc/pki/real/target.crt", host / "etc/pki/tls/certs/link.crt")
    monkeypatch.setattr(pr._platform, "HOST_PREFIX", str(host))
    r = cd.scan_crypto_material(paths=["/etc/pki"], now=NOW)
    assert r["scanned_paths"] == ["/etc/pki"]
    subjects = sorted(c["subject"] for c in r["certificates"])
    assert subjects == ["CN=host-cert,O=Example Org", "CN=via-link,O=Example Org"]
    paths = sorted(p for c in r["certificates"] for p in c["paths"])
    assert all(p.startswith("/etc/pki/") for p in paths)


def test_deadline_flags(tmp_path) -> None:
    _write(tmp_path / "a.crt", to_pem(build_cert(not_after=datetime(2031, 6, 1, tzinfo=timezone.utc))), 0o644)
    _write(tmp_path / "b.crt", to_pem(build_cert(serial=2, not_after=datetime(2036, 6, 1, tzinfo=timezone.utc))), 0o644)
    certs = sorted(_scan(tmp_path)["certificates"], key=lambda c: c["not_after"])
    assert [(c["valid_past_2030"], c["valid_past_2035"]) for c in certs] == [(True, False), (True, True)]


# ---------------------------------------------------------------------------
# Java keystores
# ---------------------------------------------------------------------------


def _jks(trusted: list[bytes], private_chain: list[bytes] | None = None, marker: bytes = b"") -> bytes:
    def utf(s: str) -> bytes:
        return struct.pack(">H", len(s)) + s.encode()

    entries = b""
    n = 0
    for i, der in enumerate(trusted):
        entries += struct.pack(">I", 2) + utf(f"ca{i}") + struct.pack(">Q", 0)
        entries += utf("X.509") + struct.pack(">I", len(der)) + der
        n += 1
    if private_chain is not None:
        enc = marker * 3
        entries += struct.pack(">I", 1) + utf("server") + struct.pack(">Q", 0)
        entries += struct.pack(">I", len(enc)) + enc + struct.pack(">I", len(private_chain))
        for der in private_chain:
            entries += utf("X.509") + struct.pack(">I", len(der)) + der
        n += 1
    body = struct.pack(">III", 0xFEEDFEED, 2, n) + entries
    return body + hashlib.sha1(body).digest()


def test_jks_trusted_and_private_entries_parsed_without_password(tmp_path) -> None:
    marker = b"PQCR-JKS-" + secrets.token_hex(8).encode()
    ca = build_cert(subject="Store CA", issuer="Store CA", basic_constraints_ca=True)
    leaf = build_cert(subject="app.example", serial=7)
    _write(tmp_path / "app.jks", _jks([ca], [leaf], marker), 0o640)
    r = _scan(tmp_path)
    (ks,) = r["keystores"]
    assert ks["store_type"] == "jks" and ks["listed"] is True
    assert ks["private_key_entries"] == 1 and ks["certificates_found"] == 2
    assert r["summary"]["certificates"] == 2
    assert marker not in json.dumps(r).encode()


def test_truncated_jks_is_reported_not_raised(tmp_path) -> None:
    data = _jks([build_cert()])
    _write(tmp_path / "broken.jks", data[:40], 0o644)
    (ks,) = _scan(tmp_path)["keystores"]
    assert ks["listed"] is False and ks["reason"].startswith("unparseable JKS")


def test_pkcs12_is_not_opened_except_cacerts_via_keytool(tmp_path, monkeypatch) -> None:
    _write(tmp_path / "client.p12", b"\x30\x82\x01\x00" + b"\x00" * 300, 0o600)
    calls: list[list[str]] = []
    pem = to_pem(build_cert(subject="jdk root", issuer="jdk root", basic_constraints_ca=True))

    def fake_run(cmd, timeout=None):  # noqa: ARG001
        calls.append(cmd)
        return 0, pem

    monkeypatch.setattr(pr._platform, "_run", fake_run)
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/" + name)
    _write(tmp_path / "jdk/lib/security/cacerts", b"\x30\x82\x02\x00" + b"\x00" * 600, 0o644)
    r = _scan(tmp_path)
    stores = {Path(k["path"]).name: k for k in r["keystores"]}
    assert stores["client.p12"]["listed"] is False
    assert stores["cacerts"]["listed"] is True and stores["cacerts"]["certificates_found"] == 1
    (cmd,) = calls  # only cacerts was opened, with the published default password
    assert "-storepass" in cmd and cmd[cmd.index("-storepass") + 1] == "changeit"


# ---------------------------------------------------------------------------
# trust_store.certificates contract (#138) and --host-mount regression
# ---------------------------------------------------------------------------


def test_trust_store_populates_cbom17_certificate_contract(tmp_path) -> None:
    shutil.copy(FIXTURES / "ml-dsa-65.pem", tmp_path / "ml.pem")
    ts = pr.scan_trust_store(dirs=[str(tmp_path)])
    (c,) = ts["certificates"]
    for key in ("sha256", "serial", "subject", "issuer", "not_before", "not_after", "category"):
        assert c[key]
    bom = json.loads(pr.render_cbom(pr.Report(hostname="h", trust_store=ts), "1.7"))
    refs = {comp["bom-ref"] for comp in bom["components"]}
    assert f"cert/sha256:{c['sha256']}" in refs


def test_trust_store_reads_host_dirs_under_host_mount(tmp_path, monkeypatch) -> None:
    """Regression: scan_trust_store ignored --host-mount and inventoried
    the scanner image's own /etc (#108)."""
    host = tmp_path / "host"
    (host / "etc/pki/tls/certs").mkdir(parents=True)
    shutil.copy(FIXTURES / "ec-p256.pem", host / "etc/pki/tls/certs/only-on-host.pem")
    monkeypatch.setattr(pr._platform, "HOST_PREFIX", str(host))
    ts = pr.scan_trust_store(dirs=["/etc/pki/tls/certs"])
    assert ts["scanned_dirs"] == ["/etc/pki/tls/certs"]
    assert ts["total_certs"] == 1


def test_cli_flags_parse(tmp_path) -> None:
    args = pr.cli.build_parser().parse_args(
        ["--scan-crypto-material", "--crypto-material-path", str(tmp_path), "--crypto-material-max-files", "9"]
    )
    assert args.scan_crypto_material is True
    assert args.crypto_material_path == [str(tmp_path)]
    assert args.crypto_material_max_files == 9


def test_collect_report_runs_scan_only_when_asked(tmp_path, monkeypatch) -> None:
    calls: list[tuple[Any, int]] = []

    def fake(paths=None, max_files=cd.CRYPTO_MATERIAL_MAX_FILES_DEFAULT, now=None):  # noqa: ARG001
        calls.append((paths, max_files))
        return {"available": True}

    monkeypatch.setattr(cd, "scan_crypto_material", fake)
    parser = pr.cli.build_parser()
    out = pr.cli.collect_report(parser.parse_args(["--crypto-material-path", str(tmp_path)]))
    assert out.crypto_material == {} and calls == []
    out = pr.cli.collect_report(parser.parse_args(["--scan-crypto-material", "--crypto-material-path", str(tmp_path)]))
    assert out.crypto_material == {"available": True}
    assert calls == [([str(tmp_path)], cd.CRYPTO_MATERIAL_MAX_FILES_DEFAULT)]
