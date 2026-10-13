# SPDX-License-Identifier: Apache-2.0
"""Boot chain inventory (--scan-boot-chain, #112).

Signature lists are built from the trust-store fixture certificates;
module signatures under tests/fixtures/boot_chain/ are real CMS
signatures made with OpenSSL 3.5.9 (RSA-4096/sha512 and ECDSA P-384
without signed attributes, the kernel's sign-file shape; ML-DSA-65 with
signed attributes, which OpenSSL 3.5 needs for ML-DSA CMS).  The keys were
throwaway and not kept.
"""

from __future__ import annotations

import json
import lzma
import struct
import uuid
from pathlib import Path

import pytest

import pqc_readiness as pr
from pqc_readiness.detect import certs as _certs
from pqc_readiness.detect import protocols_boot as pb

FIX = Path(__file__).parent / "fixtures"
SIGS = FIX / "boot_chain"
RELEASE = "7.2.9-200.fc44.x86_64"


def _der(name: str) -> bytes:
    return _certs._certs_in_file(FIX / "trust_store" / name)[0]


def _sig_list(sig_type: str, payloads: list[bytes]) -> bytes:
    """One EFI_SIGNATURE_LIST holding `payloads` (owner GUID prepended)."""
    size = 16 + max(len(p) for p in payloads)
    owner = uuid.UUID("77fa9abd-0359-4d32-bd60-28f4e78f784b").bytes_le
    body = b"".join(owner + p.ljust(size - 16, b"\0") for p in payloads)
    return (
        uuid.UUID(sig_type).bytes_le
        + struct.pack("<III", 28 + len(body), 0, size)
        + body
    )


def _efivar(root: Path, name: str, guid: str, data: bytes) -> None:
    d = root / "sys/firmware/efi/efivars"
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{name}-{guid}").write_bytes(b"\x07\x00\x00\x00" + data)


def _module(sig_name: str) -> bytes:
    sig = (SIGS / sig_name).read_bytes()
    trailer = struct.pack(">BBBBB3xI", 0, 0, pb.PKEY_ID_PKCS7, 0, 0, len(sig))
    return b"\x7fELF fake module" + sig + trailer + pb.MODULE_SIG_MAGIC


def _no_subprocess(cmd, timeout=None):  # noqa: ARG001
    raise AssertionError(f"unexpected subprocess: {cmd}")


@pytest.fixture
def host(monkeypatch, tmp_path):
    root = tmp_path / "root"
    (root / "proc/sys/kernel").mkdir(parents=True)
    (root / "proc/sys/kernel/osrelease").write_text(RELEASE + "\n")
    (root / "proc/cmdline").write_text("BOOT_IMAGE=/vmlinuz ro ima_appraise=log\n")
    monkeypatch.setattr(pr._platform, "HOST_PREFIX", str(root))
    monkeypatch.setattr(pr._platform, "_run", _no_subprocess)
    monkeypatch.setattr(pr._platform, "is_linux", lambda: True)
    return root


def _secure_boot_tree(root: Path, db_certs: list[bytes]) -> None:
    g, s = pb.EFI_GLOBAL_VARIABLE, pb.EFI_IMAGE_SECURITY_DATABASE
    _efivar(root, "SecureBoot", g, b"\x01")
    _efivar(root, "SetupMode", g, b"\x00")
    _efivar(root, "PK", g, _sig_list(pb.EFI_CERT_X509, [_der("rsa-2048.pem")]))
    _efivar(root, "KEK", g, _sig_list(pb.EFI_CERT_X509, [_der("ec-p256.pem")]))
    _efivar(root, "db", s, _sig_list(pb.EFI_CERT_X509, db_certs))
    _efivar(root, "dbx", s, _sig_list(pb.EFI_CERT_SHA256, [b"\x11" * 32, b"\x22" * 32]))


# ---------------------------------------------------------------------------
# EFI signature lists
# ---------------------------------------------------------------------------


def test_signature_lists_parse_certificates_hashes_and_unknown_types() -> None:
    data = (
        _sig_list(pb.EFI_CERT_X509, [_der("rsa-2048.pem"), _der("ml-dsa-65.pem")])
        + _sig_list(pb.EFI_CERT_SHA256, [b"\xaa" * 32])
        + _sig_list("0b6e5233-a65c-44c9-9407-d9ab83bfc8bd", [b"\x00" * 64])
    )
    out = pb.parse_signature_lists(data)
    assert [c["key_algorithm"] for c in out["certificates"]] == ["RSA", "ML-DSA-65"]
    assert [c["category"] for c in out["certificates"]] == ["classical", "pure_pqc"]
    assert out["sha256_hashes"] == 1
    assert out["other_entries"] == {"0b6e5233-a65c-44c9-9407-d9ab83bfc8bd": 1}
    assert out["errors"] == []


@pytest.mark.parametrize(
    "data",
    [
        b"\x00" * 20,  # shorter than a list header
        uuid.UUID(pb.EFI_CERT_X509).bytes_le + struct.pack("<III", 9999, 0, 100),
        uuid.UUID(pb.EFI_CERT_X509).bytes_le + struct.pack("<III", 60, 0, 8),
    ],
)
def test_malformed_signature_lists_report_errors_not_exceptions(data: bytes) -> None:
    out = pb.parse_signature_lists(data)
    assert out["errors"] and out["certificates"] == []


def test_corrupt_x509_entry_is_reported() -> None:
    out = pb.parse_signature_lists(_sig_list(pb.EFI_CERT_X509, [b"\x30\x82\xff\xff"]))
    assert out["certificates"] == [] and "unparsable X.509" in out["errors"][0]


# ---------------------------------------------------------------------------
# Secure Boot
# ---------------------------------------------------------------------------


def test_secure_boot_reads_every_database(host: Path) -> None:
    _secure_boot_tree(host, [_der("rsa-2048.pem"), _der("ec-p256.pem")])
    sb = pb.detect_secure_boot()
    assert sb["available"] and sb["enabled"] is True and sb["setup_mode"] is False
    dbs = sb["databases"]
    assert len(dbs["db"]["certificates"]) == 2
    assert dbs["dbx"]["sha256_hashes"] == 2
    assert dbs["MokList"] == {"present": False}


def test_mok_variables_copy_wins_over_runtime_variable(host: Path) -> None:
    _secure_boot_tree(host, [_der("rsa-2048.pem")])
    _efivar(
        host,
        "MokListRT",
        pb.SHIM_LOCK,
        _sig_list(pb.EFI_CERT_X509, [_der("rsa-2048.pem")]),
    )
    mok = host / "sys/firmware/efi/mok-variables"
    mok.mkdir(parents=True)
    (mok / "MokListRT").write_bytes(
        _sig_list(pb.EFI_CERT_X509, [_der("rsa-2048.pem"), _der("ec-p256.pem")])
    )
    db = pb.detect_secure_boot()["databases"]["MokList"]
    assert db["source"] == "mok-variables" and len(db["certificates"]) == 2


def test_bios_boot_is_unavailable(host: Path) -> None:
    sb = pb.detect_secure_boot()
    assert sb == {
        "available": False,
        "firmware": "bios",
        "reason": "no /sys/firmware/efi: legacy BIOS boot (no UEFI Secure Boot)",
    }


def test_shim_validation_disabled(host: Path) -> None:
    _secure_boot_tree(host, [_der("rsa-2048.pem")])
    _efivar(host, "MokSBStateRT", pb.SHIM_LOCK, b"\x01")
    assert pb.detect_secure_boot()["shim_validation_disabled"] is True


# ---------------------------------------------------------------------------
# Module signing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("sig", "algorithm", "digest", "key_size", "category"),
    [
        ("rsa4096.p7s", "RSA", "sha512", 4096, "classical"),
        ("ecdsa-p384.p7s", "ECDSA", "sha384", None, "classical"),
        ("mldsa65.p7s", "ML-DSA-65", "sha512", None, "pure_pqc"),
    ],
)
def test_module_signature_parsing(sig, algorithm, digest, key_size, category) -> None:
    out = pb.parse_module_signature(_module(sig))
    assert out is not None and out["parsed"] is True
    assert out["signature_algorithm"] == algorithm
    assert out["digest_algorithm"] == digest
    assert out["key_size"] == key_size
    assert out["category"] == category
    assert "module signing key" in out["signer"]


def test_unsigned_and_non_pkcs7_modules() -> None:
    assert pb.parse_module_signature(b"\x7fELF no signature") is None
    trailer = struct.pack(">BBBBB3xI", 1, 1, 1, 0, 0, 4)
    out = pb.parse_module_signature(
        b"\x7fELF" + b"sig!" + trailer + pb.MODULE_SIG_MAGIC
    )
    assert out == {"format": "id_type 1", "parsed": False}


def test_truncated_pkcs7_is_not_an_exception() -> None:
    sig = (SIGS / "rsa4096.p7s").read_bytes()[:100]
    trailer = struct.pack(">BBBBB3xI", 0, 0, 2, 0, 0, len(sig))
    out = pb.parse_module_signature(b"x" + sig + trailer + pb.MODULE_SIG_MAGIC)
    assert out is not None and out["parsed"] is False and out["reason"]


def _modules_tree(root: Path, sig: str, config: str) -> None:
    (root / "boot").mkdir()
    (root / f"boot/config-{RELEASE}").write_text(config)
    mdir = root / f"lib/modules/{RELEASE}"
    (mdir / "kernel/fs").mkdir(parents=True)
    (mdir / "kernel/fs/fake.ko.xz").write_bytes(lzma.compress(_module(sig)))
    (mdir / "modules.dep").write_text("kernel/fs/fake.ko.xz:\n")


def test_module_signing_reads_config_and_xz_module(host: Path) -> None:
    _modules_tree(
        host,
        "rsa4096.p7s",
        'CONFIG_MODULE_SIG=y\nCONFIG_MODULE_SIG_HASH="sha512"\n'
        "CONFIG_MODULE_SIG_KEY_TYPE_RSA=y\n# CONFIG_MODULE_SIG_KEY_TYPE_MLDSA_65 is not set\n",
    )
    mod = pb.detect_module_signing()
    assert mod["kernel_release"] == RELEASE
    assert mod["module_sig"] is True and mod["module_sig_hash"] == "sha512"
    assert mod["key_types_configured"] == ["RSA"]
    assert mod["sample_module"]["signature_algorithm"] == "RSA"
    assert mod["sample_module"]["key_size"] == 4096
    assert mod["pqc"] is False


def test_module_signing_falls_back_to_config_key_type(host: Path) -> None:
    (host / "boot").mkdir()
    (host / f"boot/config-{RELEASE}").write_text(
        "CONFIG_MODULE_SIG=y\nCONFIG_MODULE_SIG_KEY_TYPE_MLDSA_87=y\n"
    )
    mod = pb.detect_module_signing()
    assert mod["sample_module"] is None
    assert mod["key_types_configured"] == ["MLDSA_87"]
    assert mod["pqc"] is True


def test_ml_dsa_signed_module_is_pqc(host: Path) -> None:
    _modules_tree(host, "mldsa65.p7s", "CONFIG_MODULE_SIG_KEY_TYPE_MLDSA_65=y\n")
    assert pb.detect_module_signing()["pqc"] is True


# ---------------------------------------------------------------------------
# IMA / EVM, lockdown
# ---------------------------------------------------------------------------


def test_ima_policy_evm_and_certificates(host: Path) -> None:
    sec = host / "sys/kernel/security"
    (sec / "ima").mkdir(parents=True)
    (sec / "ima/policy").write_text(
        "measure func=BPRM_CHECK\nappraise func=BPRM_CHECK appraise_type=imasig\n"
    )
    (sec / "evm").write_text("2\n")
    (sec / "lockdown").write_text("none [integrity] confidentiality\n")
    (host / "etc/keys/ima").mkdir(parents=True)
    (host / "etc/keys/ima/test-ima.der").write_bytes(_der("ec-p256.pem"))
    ima = pb.detect_ima_evm()
    assert ima["policy"] == {
        "readable": True,
        "rules": 2,
        "measure_rules": 1,
        "appraise_rules": 1,
        "signature_required_rules": 1,
    }
    assert ima["evm_mode"] == 2
    assert ima["cmdline"] == {"ima_appraise": "log"}
    assert ima["certificates"][0]["key_algorithm"].startswith("EC")
    assert ima["certificates"][0]["path"] == "/etc/keys/ima/test-ima.der"
    assert pb.detect_lockdown() == "integrity"


# ---------------------------------------------------------------------------
# TPM
# ---------------------------------------------------------------------------


def _props_response(props: dict[int, int]) -> bytes:
    body = struct.pack(">BII", 0, pb.TPM2_CAP_TPM_PROPERTIES, len(props))
    body += b"".join(struct.pack(">II", k, v) for k, v in props.items())
    return struct.pack(">HII", 0x8001, 10 + len(body), 0) + body


def _algs_response(algs: list[int]) -> bytes:
    body = struct.pack(">BII", 0, pb.TPM2_CAP_ALGS, len(algs))
    body += b"".join(struct.pack(">HI", a, 0x24) for a in algs)
    return struct.pack(">HII", 0x8001, 10 + len(body), 0) + body


def test_get_capability_command_bytes() -> None:
    cmd = pb.tpm2_get_capability_command(pb.TPM2_CAP_ALGS, 0x00A0, 3)
    assert struct.unpack(">HIIIII", cmd) == (0x8001, 22, 0x17A, 0, 0xA0, 3)


def test_parse_capability_responses() -> None:
    rc, props = pb.parse_get_capability_response(
        _props_response({pb.TPM2_PT_REVISION: 185})
    )
    assert rc == 0 and props == [(pb.TPM2_PT_REVISION, 185)]
    rc, algs = pb.parse_get_capability_response(_algs_response([0x00A0, 0x00A1]))
    assert [a for a, _ in algs] == [0x00A0, 0x00A1]
    error = struct.pack(">HII", 0x8001, 10, 0x0000_0101)
    assert pb.parse_get_capability_response(error) == (0x101, [])
    with pytest.raises(ValueError):
        pb.parse_get_capability_response(_algs_response([0x00A0])[:-3])


def _tpm_tree(root: Path) -> None:
    (root / "sys/class/tpm/tpm0").mkdir(parents=True)
    (root / "sys/class/tpm/tpm0/tpm_version_major").write_text("2\n")


@pytest.mark.parametrize(
    ("algs", "revision", "expect"),
    [
        ([0x00A0, 0x00A1, 0x00A2], 185, ["ML-KEM", "ML-DSA", "HashML-DSA"]),
        ([], 159, []),
    ],
)
def test_tpm_capabilities(host: Path, monkeypatch, algs, revision, expect) -> None:
    _tpm_tree(host)
    (host / "dev").mkdir()
    (host / "dev/tpmrm0").write_bytes(b"")
    answers = [
        _props_response(
            {
                pb.TPM2_PT_FAMILY_INDICATOR: int.from_bytes(b"2.0\0", "big"),
                pb.TPM2_PT_REVISION: revision,
                pb.TPM2_PT_YEAR: 2025,
                pb.TPM2_PT_MANUFACTURER: int.from_bytes(b"IBM ", "big"),
            }
        ),
        _algs_response(algs),
    ]
    monkeypatch.setattr(pb, "_tpm_transact", lambda fd, cmd: answers.pop(0))
    tpm = pb.detect_tpm_capabilities()
    assert tpm["queried"] is True
    assert tpm["family"] == "2.0" and tpm["manufacturer"] == "IBM"
    assert tpm["spec_revision"] == f"{revision / 100:.2f}"
    assert tpm["pqc_algorithms"] == expect and tpm["pqc_capable"] is bool(expect)


def test_tpm_without_device_access(host: Path) -> None:
    _tpm_tree(host)
    tpm = pb.detect_tpm_capabilities()
    assert tpm["present"] is True and tpm["queried"] is False
    assert "cannot open" in tpm["reason"]


def test_no_tpm(host: Path) -> None:
    tpm = pb.detect_tpm_capabilities()
    assert tpm["present"] is False and tpm["queried"] is False


# ---------------------------------------------------------------------------
# Assembly, findings, outputs
# ---------------------------------------------------------------------------


def _full_host(host: Path) -> dict:
    _secure_boot_tree(host, [_der("rsa-2048.pem")])
    _modules_tree(host, "rsa4096.p7s", "CONFIG_MODULE_SIG_KEY_TYPE_RSA=y\n")
    return pb.scan_boot_chain()


def test_scan_boot_chain_summary_and_layers(host: Path) -> None:
    bc = _full_host(host)
    s = bc["summary"]
    assert s["secure_boot_certificates"] == 3
    assert s["secure_boot_all_classical"] is True
    assert s["secure_boot_algorithms"] == ["EC P-256", "RSA-2048"]
    assert s["classical_layers"] == ["secure_boot", "module_signing"]
    lines = pb.describe_classical_layers(bc)
    assert lines[0].startswith("Secure Boot trusts 3 certificates")
    assert lines[1] == "kernel modules are signed with RSA-4096 / sha512"


def test_pqc_db_certificate_clears_the_secure_boot_layer(host: Path) -> None:
    _secure_boot_tree(host, [_der("ml-dsa-65.pem")])
    bc = pb.scan_boot_chain()
    assert bc["summary"]["secure_boot_all_classical"] is False
    assert "secure_boot" not in bc["summary"]["classical_layers"]


def test_non_linux_is_unavailable(monkeypatch) -> None:
    monkeypatch.setattr(pr._platform, "is_linux", lambda: False)
    assert pb.scan_boot_chain() == {
        "available": False,
        "reason": "boot chain inventory is Linux-only",
    }


def test_sarif_finding_and_recommendation_caveat(host: Path) -> None:
    r = pr.Report(boot_chain=_full_host(host))
    finding = [
        f for f in pr.build_findings(r) if f.rule_id == "pqc-020-classical-boot-chain"
    ]
    assert len(finding) == 1 and finding[0].level == "note"
    assert finding[0].properties["boot_chain:classical_layers"] == [
        "secure_boot",
        "module_signing",
    ]
    rec = pr.recommend(r, policy="cnsa-2.0", role="firmware-signing")
    caveats = rec["recommendations"]["cnsa-2.0"]["caveats"]
    assert any("boot chain is classical" in c for c in caveats)


def test_no_finding_without_scan() -> None:
    ids = [f.rule_id for f in pr.build_findings(pr.Report())]
    assert "pqc-020-classical-boot-chain" not in ids


def test_text_section_and_json(host: Path) -> None:
    r = pr.Report(boot_chain=_full_host(host))
    text = pr.render_text(r)
    assert "13. Boot chain" in text and "Module signing:   RSA-4096 / sha512" in text
    assert json.loads(json.dumps(r.boot_chain))["available"] is True


def test_cli_flag_and_offline_refusal() -> None:
    args = pr.cli.build_parser().parse_args(["--scan-boot-chain"])
    assert args.scan_boot_chain is True
    assert pr.Report().boot_chain == {}
    assert (
        "scan_boot_chain",
        "--scan-boot-chain",
    ) in pr.detect.runtime_offline._INCOMPATIBLE_FLAGS
