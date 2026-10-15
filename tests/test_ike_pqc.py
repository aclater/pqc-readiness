# SPDX-License-Identifier: Apache-2.0
"""IKEv2 PQC key exchange in configured IPsec proposals (#154).

Fixture configs under tests/fixtures/ike/ use each implementation's
documented syntax (strongSwan swanctl.opt; Libreswan's algorithm parser
and its 5.4 test suite).  Real-host validation is in the PR.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import pqc_readiness as pr
from pqc_readiness.detect import protocols as protocols
from pqc_readiness.detect import protocols_ike as ike

FIX = Path(__file__).parent / "fixtures" / "ike"


def _no_subprocess(cmd, timeout=None):  # noqa: ARG001
    raise AssertionError(f"unexpected subprocess: {cmd}")


@pytest.fixture
def host(monkeypatch):
    def _use(name: str) -> Path:
        root = FIX / name
        monkeypatch.setattr(pr._platform, "HOST_PREFIX", str(root))
        monkeypatch.setattr(pr._platform, "_run", _no_subprocess)
        # A live host whose config files are sandboxed under the prefix:
        # the CLI (mocked per test) describes it, as on bare metal.
        monkeypatch.setattr(protocols, "_cli_describes_host", lambda: True)
        return root

    return _use


# ---------------------------------------------------------------------------
# Proposal classification, both dialects
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("proposal", "category", "mandatory", "primary", "additional"),
    [
        # strongSwan: keX_ = RFC 9370 additional key exchange
        (
            "aes256-sha384-x25519-ke1_mlkem768",
            "hybrid",
            True,
            ["Curve25519"],
            {"1": ["ML-KEM-768"]},
        ),
        # ke1_none makes the additional exchange optional
        (
            "aes256-sha384-x25519-ke1_mlkem768-ke1_none",
            "hybrid",
            False,
            ["Curve25519"],
            {"1": ["ML-KEM-768", "none"]},
        ),
        # ML-KEM as the only key exchange
        ("aes256gcm16-prfsha384-mlkem1024", "pure_pqc", True, ["ML-KEM-1024"], {}),
        # alternatives in one slot: a peer may pick x25519 alone
        (
            "aes256-sha384-x25519-mlkem768",
            "pure_pqc",
            False,
            ["Curve25519", "ML-KEM-768"],
            {},
        ),
        ("aes256-sha256-modp3072", "classical", False, ["MODP-3072"], {}),
        (
            "aes256-sha384-ecp384-ke1_mlkem1024!",
            "hybrid",
            True,
            ["ECP-384"],
            {"1": ["ML-KEM-1024"]},
        ),
        # Libreswan: ke= / addkeN= / + alternatives
        ("aes;ke=ml_kem_768", "pure_pqc", True, ["ML-KEM-768"], {}),
        (
            "aes128-sha2-dh31;addke1=ml_kem_1024",
            "hybrid",
            True,
            ["Curve25519"],
            {"1": ["ML-KEM-1024"]},
        ),
        (
            "aes;dh20;addke1=modp8192;addke2=ml_kem_768",
            "hybrid",
            True,
            ["ECP-384"],
            {"1": ["MODP-8192"], "2": ["ML-KEM-768"]},
        ),
        (
            "aes;dh20;addke1=ml_kem_768+none",
            "hybrid",
            False,
            ["ECP-384"],
            {"1": ["ML-KEM-768", "none"]},
        ),
        (
            "aes_gcm256-sha2_512+sha2_256-dh19+dh20",
            "classical",
            False,
            ["ECP-256", "ECP-384"],
            {},
        ),
        (
            "aes;modp8192;addke2=dh19;addke4=none;addke6=dh20",
            "classical",
            False,
            ["MODP-8192"],
            {"2": ["ECP-256"], "4": ["none"], "6": ["ECP-384"]},
        ),
    ],
)
def test_proposal_classification(
    proposal, category, mandatory, primary, additional
) -> None:
    r = ike.parse_ike_proposal(proposal)
    assert r["category"] == category
    assert r["pqc_mandatory"] is mandatory
    assert r["primary"] == primary
    assert r["additional"] == additional


@pytest.mark.parametrize("proposal", ["aes256-sha256", "default", "aes_gcm256-null"])
def test_proposal_without_key_exchange_is_unclassified(proposal) -> None:
    r = ike.parse_ike_proposal(proposal)
    assert r["category"] is None and "default" in r["note"]


@pytest.mark.parametrize(
    ("token", "method"),
    [
        ("mlkem768", "ML-KEM-768"),
        ("ml_kem_1024", "ML-KEM-1024"),
        ("ml-kem-512", "ML-KEM-512"),
        ("dh31", "Curve25519"),
        ("x448", "Curve448"),
        ("ecp384bp", "ECP-384-BP"),
        ("dh14", "MODP-2048"),
        ("aes256", None),
        ("sha2_512", None),
        ("prfsha384", None),
    ],
)
def test_key_exchange_tokens(token, method) -> None:
    assert ike._ke_method(token) == method


# ---------------------------------------------------------------------------
# Config files
# ---------------------------------------------------------------------------


def test_strongswan_swanctl_with_include(host) -> None:
    host("strongswan")
    out = ike.scan_ike_proposals()
    assert out["files"] == ["/etc/swanctl/swanctl.conf"]
    by_conn = {}
    for p in out["proposals"]:
        by_conn.setdefault((p["connection"], p["kind"]), []).append(p)
    hm = by_conn[("hybrid-mandatory", "ike")][0]
    assert hm["category"] == "hybrid" and hm["pqc_mandatory"] is True
    assert hm["source"] == "/etc/swanctl/swanctl.conf"
    child = by_conn[("hybrid-mandatory", "child")][0]
    assert child["child"] == "net" and child["category"] == "hybrid"
    # two proposals; the second has no ML-KEM, so PQC is optional
    opt = by_conn[("hybrid-optional", "ike")]
    assert [p["category"] for p in opt] == ["hybrid", "classical"]
    assert by_conn[("classical-only", "ike")][0]["category"] == "classical"
    assert by_conn[("defaults", "ike")][0]["category"] is None
    # include conf.d/*.conf, resolved relative to the including file
    pure = by_conn[("pure-mlkem", "ike")][0]
    assert pure["category"] == "pure_pqc"
    assert pure["source"] == "/etc/swanctl/conf.d/pure.conf"
    s = out["summary"]
    assert s["connections"] == 5
    assert s["connections_offering_pqc"] == 3
    assert s["connections_requiring_pqc"] == 2
    assert s["unclassified"] == 1


def test_libreswan_ipsec_conf_with_include(host) -> None:
    host("libreswan")
    out = ike.scan_ike_proposals()
    assert out["files"] == ["/etc/ipsec.conf"]
    ike_props = {p["connection"]: p for p in out["proposals"] if p["kind"] == "ike"}
    assert ike_props["hybrid"]["category"] == "hybrid"
    assert ike_props["hybrid"]["additional"] == {"1": ["ML-KEM-1024"]}
    assert ike_props["pure"]["category"] == "pure_pqc"
    assert ike_props["chained-classical"]["category"] == "classical"
    legacy = [p for p in out["proposals"] if p["connection"] == "legacy"]
    assert [(p["kind"], p["category"]) for p in legacy] == [
        ("ike", "classical"),
        ("ike", "classical"),
        ("child", "classical"),
    ]
    assert legacy[0]["source"] == "/etc/ipsec.d/legacy.conf"
    assert out["summary"]["connections_requiring_pqc"] == 2


def test_no_config_files(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(pr._platform, "HOST_PREFIX", str(tmp_path))
    out = ike.scan_ike_proposals()
    assert out["files"] == [] and out["proposals"] == []
    assert out["summary"]["ike_proposals"] == 0


def test_include_loop_terminates(monkeypatch, tmp_path) -> None:
    conf = tmp_path / "etc/swanctl/swanctl.conf"
    conf.parent.mkdir(parents=True)
    conf.write_text(
        "include swanctl.conf\nconnections {\n c {\n proposals = aes-x25519\n }\n}\n"
    )
    monkeypatch.setattr(pr._platform, "HOST_PREFIX", str(tmp_path))
    out = ike.scan_ike_proposals()
    assert out["proposals"]  # bounded recursion, no RecursionError


def test_standards_labels() -> None:
    std = {s["reference"]: s for s in ike.IKE_PQC_STANDARDS}
    assert std["RFC 9370"]["status"] == "final"
    mlkem = std["draft-ietf-ipsecme-ikev2-mlkem-09"]
    assert mlkem["status"] == "draft" and "35/36/37" in mlkem["note"]


# ---------------------------------------------------------------------------
# detect_ipsec_pqc integration
# ---------------------------------------------------------------------------


def test_detect_ipsec_pqc_attaches_configured(host, monkeypatch) -> None:
    host("strongswan")
    monkeypatch.setattr(protocols.shutil, "which", lambda name: None)
    out = protocols.detect_ipsec_pqc("rhel")
    assert out["available"] is False  # no daemon installed ...
    assert (
        out["configured"]["summary"]["connections_offering_pqc"] == 3
    )  # ... config still read


@pytest.mark.parametrize(
    ("version", "pqc"),
    [
        ("5.3.2", False),
        ("5.4", True),
        ("v5.4.1", True),
        ("6.0", True),
        ("4.15", False),
        (None, False),
    ],
)
def test_libreswan_pqc_by_version(monkeypatch, tmp_path, version, pqc) -> None:
    monkeypatch.setattr(protocols, "_cli_describes_host", lambda: True)
    monkeypatch.setattr(pr._platform, "HOST_PREFIX", str(tmp_path))
    monkeypatch.setattr(
        protocols.shutil,
        "which",
        lambda name: "/usr/sbin/ipsec" if name == "ipsec" else None,
    )
    text = f"Linux Libreswan {version} (XFRM) on 6.12" if version else "Linux Libreswan"
    monkeypatch.setattr(pr._platform, "_run", lambda cmd, timeout=None: (0, text))
    out = protocols.detect_ipsec_pqc("rhel")
    assert out["implementation"] == "libreswan"
    assert out["pqc"] is pqc


def test_text_report_names_stack_and_summarises_config(host) -> None:
    host("libreswan")
    r = pr.Report(
        ipsec_pqc={
            "available": True,
            "implementation": "libreswan",
            "pqc": True,
            "configured": ike.scan_ike_proposals(),
        }
    )
    text = pr.render_text(r)
    assert "Libreswan:     PQC support yes" in text
    assert "strongSwan:" not in text
    assert "ML-KEM offered by 2, required by 2" in text


# strongSwan 6.0.7 (Fedora 44) `swanctl --list-algs` key-exchange lines.
_SWANCTL_ALGS = """key-exchange:
  ECP_256[openssl]
  CURVE_25519[openssl]
  ML_KEM_512[openssl]
  ML_KEM_768[openssl]
  ML_KEM_1024[openssl]
"""


def test_strongswan_ml_kem_algs_detected(monkeypatch, tmp_path) -> None:
    """Regression: `\\bML[-_ ]?KEM\\b` never matched `ML_KEM_768` (the "_"
    after KEM is a word character), so PQC-capable strongSwan was
    reported as pqc=false on a real Fedora 44 host."""
    monkeypatch.setattr(protocols, "_cli_describes_host", lambda: True)
    monkeypatch.setattr(pr._platform, "HOST_PREFIX", str(tmp_path))
    monkeypatch.setattr(
        protocols.shutil,
        "which",
        lambda name: "/usr/sbin/swanctl" if name == "swanctl" else None,
    )
    monkeypatch.setattr(
        pr._platform, "_run", lambda cmd, timeout=None: (0, _SWANCTL_ALGS)
    )
    out = protocols.detect_ipsec_pqc("rhel")
    assert out["implementation"] == "strongswan"
    assert out["pqc"] is True
    assert out["evidence"] == "ML_KEM_512"


def test_capability_mismatch_when_stack_lacks_ml_kem(host, monkeypatch) -> None:
    """Rocky 10's Libreswan 5.3.2 rejects ke=ml_kem_768 / addke1=, so a
    config asking for ML-KEM is flagged rather than reported as PQC."""
    host("libreswan")
    monkeypatch.setattr(
        protocols.shutil,
        "which",
        lambda name: "/usr/sbin/ipsec" if name == "ipsec" else None,
    )
    monkeypatch.setattr(
        pr._platform, "_run", lambda cmd, timeout=None: (0, "Libreswan 5.3.2")
    )
    out = protocols.detect_ipsec_pqc("rhel")
    assert out["pqc"] is False
    mm = out["configured"]["capability_mismatch"]
    assert mm["connections"] == ["hybrid", "pure"]
    assert "libreswan" in mm["reason"]


def test_no_capability_mismatch_when_stack_supports_ml_kem(host, monkeypatch) -> None:
    host("libreswan")
    monkeypatch.setattr(
        protocols.shutil,
        "which",
        lambda name: "/usr/sbin/ipsec" if name == "ipsec" else None,
    )
    monkeypatch.setattr(
        pr._platform, "_run", lambda cmd, timeout=None: (0, "Libreswan 5.4.1")
    )
    out = protocols.detect_ipsec_pqc("rhel")
    assert out["pqc"] is True and "capability_mismatch" not in out["configured"]


def test_default_template_is_not_a_connection(monkeypatch, tmp_path) -> None:
    conf = tmp_path / "etc/ipsec.conf"
    conf.parent.mkdir(parents=True)
    conf.write_text(
        "conn %default\n\tike=aes-sha2-dh19+dh20\n\nconn real\n\tike=aes;ke=ml_kem_768\n"
    )
    monkeypatch.setattr(pr._platform, "HOST_PREFIX", str(tmp_path))
    s = ike.scan_ike_proposals()["summary"]
    assert s["ike_proposals"] == 2
    assert s["connections"] == 1 and s["connections_offering_pqc"] == 1
