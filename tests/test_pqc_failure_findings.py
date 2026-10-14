"""Findings for software that will fail at PQC (#193)."""

from __future__ import annotations

import json

import pqc_readiness as pr
from pqc_readiness.render import ndjson, sarif, text

U = "pqc-018-pqc-capability-undetermined"


def _report(**fields: object) -> pr.Report:
    return pr.Report(
        generated_at="2026-10-13T12:00:00+00:00",
        hostname="host.example",
        os="Rocky Linux 9.8",
        arch="x86_64",
        **fields,  # type: ignore[arg-type]
    )


def _ids(r: pr.Report) -> list[str]:
    return [f.rule_id for f in sarif.pqc_failure_findings(r)]


def _listener(port: int = 443, **over: object) -> dict[str, object]:
    base: dict[str, object] = {
        "protocol": "tcp",
        "family": "ipv4",
        "address": "0.0.0.0",
        "port": port,
        "process": "httpd",
        "exe": "/usr/sbin/httpd",
        "systemd_unit": "httpd.service",
        "crypto_libraries": [],
        "go": None,
    }
    base.update(over)
    return base


def _lib(
    capable: object, family: str = "openssl", version: str = "3.0.7"
) -> dict[str, object]:
    return {
        "family": family,
        "version": version,
        "path": "/lib/x.so",
        "library_pqc_capable": capable,
    }


# --- nothing scanned, nothing reported -------------------------------------


def test_empty_report_has_no_pqc_failure_findings() -> None:
    assert sarif.pqc_failure_findings(_report()) == []
    assert text._render_text_pqc_failures(_report()) == []


# --- services (pqc-011 / pqc-012) -------------------------------------------


def test_service_on_old_openssl_fails() -> None:
    r = _report(
        service_crypto_linkage={
            "available": True,
            "listeners": [_listener(crypto_libraries=[_lib(False)])],
        }
    )
    (f,) = sarif.pqc_failure_findings(r)
    assert f.rule_id == "pqc-011-service-crypto-library-without-pqc"
    assert "openssl 3.0.7" in f.message and "httpd.service" in f.message
    assert f.subject == "service:tcp/ipv4/443:/usr/sbin/httpd"


def test_service_library_without_threshold_is_undetermined_not_failing() -> None:
    r = _report(
        service_crypto_linkage={
            "available": True,
            "listeners": [_listener(crypto_libraries=[_lib(None, "gnutls", "3.8.13")])],
        }
    )
    assert _ids(r) == [U]


def test_service_on_pqc_library_and_no_crypto_is_silent() -> None:
    r = _report(
        service_crypto_linkage={
            "available": True,
            "listeners": [
                _listener(crypto_libraries=[_lib(True, version="3.5.5")]),
                _listener(port=111, process="rpcbind", exe="/usr/bin/rpcbind"),
            ],
        }
    )
    assert _ids(r) == []


def _go(
    version: str | None, default: str | None, reverts: list[str] | None = None
) -> dict[str, object]:
    return {
        "go_version": version,
        "main_module": "m",
        "default_hybrid_kex": default,
        "godebug_reverts": reverts or [],
    }


def test_go_service_versions_and_godebug() -> None:
    # Shapes as runtime_services.go_tls_kex_default emits them: a tlsmlkem=0
    # revert drops default_hybrid_kex to None and lists the revert (#111).
    cases = {
        "go1.22.5": (_go("go1.22.5", None), True),
        "kyber": (_go("go1.23.4", "X25519Kyber768Draft00"), True),
        "pre-1.18": (_go(None, None), True),
        "reverted": (_go("go1.26.0", None, ["tlsmlkem"]), True),
        "ok": (_go("go1.26.0", "X25519MLKEM768", ["tlskyber"]), False),
    }
    for name, (go, fails) in cases.items():
        r = _report(
            service_crypto_linkage={
                "available": True,
                "listeners": [_listener(port=8443, exe="/opt/a", go=go)],
            }
        )
        found = sarif.pqc_failure_findings(r)
        assert bool(found) is fails, name
        if fails:
            assert found[0].rule_id == "pqc-012-go-service-without-hybrid-mlkem"
    kyber = sarif.pqc_failure_findings(
        _report(
            service_crypto_linkage={
                "available": True,
                "listeners": [_listener(go=_go("go1.23.4", "X25519Kyber768Draft00"))],
            }
        )
    )
    assert "pre-standard" in kyber[0].message
    reverted = sarif.pqc_failure_findings(
        _report(
            service_crypto_linkage={
                "available": True,
                "listeners": [_listener(go=_go("go1.26.0", None, ["tlsmlkem"]))],
            }
        )
    )
    assert "tlsmlkem=0" in reverted[0].message


def test_unavailable_service_scan_reports_nothing() -> None:
    assert (
        _ids(_report(service_crypto_linkage={"available": False, "reason": "x"})) == []
    )


# --- libraries (pqc-013 / 014 / 018) ----------------------------------------


def test_library_capability_states() -> None:
    r = _report(
        crypto_libraries={
            "available": True,
            "libraries": {
                "libssh": {
                    "installed": True,
                    "version": "0.10.6",
                    "evidence": "binary",
                    "pqc_capable": False,
                },
                "libgcrypt": {
                    "installed": True,
                    "version": "1.11.0",
                    "evidence": "binary",
                    "pqc_capable": True,
                    "caveats": ["draft"],
                },
                "gnutls": {
                    "installed": True,
                    "version": "3.8.9",
                    "evidence": "version",
                    "pqc_capable": None,
                },
                "aws-lc": {
                    "installed": True,
                    "version": "1.60.0",
                    "evidence": "binary",
                    "pqc_capable": True,
                },
                "wolfssl": {"installed": False},
            },
        }
    )
    assert _ids(r) == [
        "pqc-013-crypto-library-without-pqc",
        "pqc-014-crypto-library-pre-standard-mlkem",
        U,
    ]


def test_toolchain_installs_are_judged_individually() -> None:
    r = _report(
        crypto_libraries={
            "available": True,
            "libraries": {
                "java": {
                    "installed": True,
                    "pqc_capable": True,
                    "installs": [
                        {
                            "path": "/usr/lib/jvm/java-17",
                            "version": "17.0.15",
                            "jca_ml_kem_ml_dsa": False,
                        },
                        {
                            "path": "/usr/lib/jvm/java-25",
                            "version": "25.0.1",
                            "jca_ml_kem_ml_dsa": True,
                        },
                    ],
                },
                "go": {
                    "installed": True,
                    "installs": [
                        {
                            "path": "/usr/lib/golang",
                            "version": "go1.22.2",
                            "tls_mlkem_default": False,
                        }
                    ],
                },
            },
        }
    )
    found = sarif.pqc_failure_findings(r)
    assert [f.subject for f in found] == [
        "library:java:/usr/lib/jvm/java-17",
        "library:go:/usr/lib/golang",
    ]
    assert "JDK 24" in found[0].message and "Go 1.24" in found[1].message


# --- IPsec (pqc-015 / 016 / 018) --------------------------------------------


def _prop(conn: str, category: str | None, kind: str = "ike") -> dict[str, object]:
    return {
        "proposal": "p",
        "connection": conn,
        "kind": kind,
        "source": "/etc/ipsec.conf",
        "category": category,
    }


def test_ipsec_connections() -> None:
    r = _report(
        ipsec_pqc={
            "available": True,
            "implementation": "libreswan",
            "configured": {
                "proposals": [
                    _prop("classical-only", "classical"),
                    _prop("hybrid", "hybrid"),
                    _prop("hybrid", "classical"),
                    _prop("defaulted", None),
                    _prop("%default", "classical"),
                    _prop("child-only", "classical", kind="child"),
                ],
                "capability_mismatch": {
                    "connections": ["hybrid"],
                    "reason": "rejects ML-KEM",
                },
            },
        }
    )
    found = sarif.pqc_failure_findings(r)
    assert [(f.rule_id, f.subject) for f in found] == [
        ("pqc-015-ipsec-mlkem-unsupported-by-stack", ""),
        ("pqc-016-ipsec-classical-only-ike", "ipsec:classical-only"),
        (U, "ipsec:defaulted"),
    ]


# --- bundled packages (pqc-017) ---------------------------------------------


def test_bundled_packages_definite_answers_only() -> None:
    bundled = [
        {
            "package": "java-1.8.0-openjdk-headless",
            "version": "1.8.0.452",
            "note": "Java",
        },
        {"package": "java-21-openjdk", "version": "21.0.7", "note": "Java"},
        {"package": "java-25-openjdk", "version": "25.0.1", "note": "Java"},
        {"package": "openjdk-17-jre-headless", "version": "17.0.15+6", "note": "Java"},
        {"package": "golang-go", "version": "2:1.22~2", "note": "Go"},
        {"package": "golang", "version": "1.25.3", "note": "Go"},
        {"package": "nodejs", "version": "20.19.0", "note": "Node.js"},
        {"package": "rust", "version": "1.89.0", "note": "Rust"},
    ]
    r = _report(packages={"available": True, "bundled_crypto": bundled})
    found = sarif.pqc_failure_findings(r)
    assert [f.subject for f in found] == [
        "package:java-1.8.0-openjdk-headless",
        "package:java-21-openjdk",
        "package:openjdk-17-jre-headless",
        "package:golang-go",
    ]
    assert found[0].properties["package:jdk_major"] == 8


def test_bundled_skips_runtimes_the_library_probe_already_judged() -> None:
    r = _report(
        packages={
            "available": True,
            "bundled_crypto": [
                {"package": "java-17-openjdk", "version": "17", "note": "x"}
            ],
        },
        crypto_libraries={
            "available": True,
            "libraries": {"java": {"installed": True, "installs": []}},
        },
    )
    assert _ids(r) == []


# --- offline --root (pqc-001 / 018) -----------------------------------------


def test_offline_tree_openssl_package() -> None:
    old = _report(
        scan_mode={"mode": "offline-root", "root": "/t"},
        openssl={
            "available": False,
            "package": {"name": "openssl-libs", "version": "3.0.7"},
            "pqc_native_expected": False,
        },
    )
    (f,) = sarif.pqc_failure_findings(old)
    assert f.rule_id == "pqc-001-openssl-pre-3.5" and "3.0.7" in f.message
    missing = _report(
        scan_mode={"mode": "offline-root"},
        openssl={"available": False, "package": None, "pqc_native_expected": None},
    )
    assert _ids(missing) == [U]
    new = _report(
        scan_mode={"mode": "offline-root"},
        openssl={
            "available": False,
            "package": {"name": "openssl-libs", "version": "3.5.5"},
            "pqc_native_expected": True,
        },
    )
    assert _ids(new) == []


def test_live_report_never_gets_offline_openssl_finding() -> None:
    r = _report(
        openssl={"available": True, "version": "OpenSSL 3.5.5", "pqc_native": True}
    )
    assert _ids(r) == []


# --- outputs ----------------------------------------------------------------


def test_sarif_and_ndjson_and_text_carry_the_findings() -> None:
    r = _report(
        service_crypto_linkage={
            "available": True,
            "listeners": [
                _listener(crypto_libraries=[_lib(False)]),
                _listener(port=8443, crypto_libraries=[_lib(False)]),
            ],
        }
    )
    log = json.loads(sarif.render_sarif(r, anchor="hosts/{hostname}.md"))
    results = log["runs"][0]["results"]
    assert [x["ruleId"] for x in results] == [
        "pqc-011-service-crypto-library-without-pqc"
    ] * 2
    fps = {x["partialFingerprints"][sarif.FINGERPRINT_KEY] for x in results}
    assert len(fps) == 2
    events = ndjson.events(r)
    assert {e["unmapped"]["pqc_readiness"].get("subject") for e in events[1:]} == {
        "service:tcp/ipv4/443:/usr/sbin/httpd",
        "service:tcp/ipv4/8443:/usr/sbin/httpd",
    }
    assert {e["finding_info"]["uid"] for e in events[1:]} == fps
    lines = "\n".join(text._render_text_pqc_failures(r))
    assert "Will fail at PQC" in lines and lines.count("pqc-011") == 2


def test_text_lists_undetermined_separately() -> None:
    r = _report(
        crypto_libraries={
            "available": True,
            "libraries": {
                "gnutls": {"installed": True, "version": "3.8.9", "pqc_capable": None}
            },
        }
    )
    lines = "\n".join(text._render_text_pqc_failures(r))
    assert "Could not determine (1" in lines


def test_host_level_fingerprints_unchanged() -> None:
    # Empty subject keeps the identity earlier releases emitted (#145).
    assert sarif.finding_fingerprint(
        "h", "pqc-001-openssl-pre-3.5"
    ) == sarif.finding_fingerprint("h", "pqc-001-openssl-pre-3.5", "")


# --- regressions found on real VMs (2026-10-13) ------------------------------


def test_pre3_openssl_soname_without_version_fails_not_undetermined() -> None:
    # AlmaLinux 8.10: sshd maps libcrypto.so.1.1.1k and no version string
    # was read; the soname alone proves OpenSSL 1.x.
    lib = {
        "family": "openssl",
        "version": None,
        "path": "/usr/lib64/libcrypto.so.1.1.1k",
        "library_pqc_capable": None,
    }
    r = _report(
        service_crypto_linkage={
            "available": True,
            "listeners": [_listener(port=22, crypto_libraries=[lib])],
        }
    )
    (f,) = sarif.pqc_failure_findings(r)
    assert f.rule_id == "pqc-011-service-crypto-library-without-pqc"
    assert "1.x (from soname)" in f.message
    assert f.properties["service:crypto_libraries"][0]["evidence"] == "soname"


def test_openssl3_soname_without_version_stays_undetermined() -> None:
    lib = {
        "family": "openssl",
        "version": None,
        "path": "/usr/lib64/libssl.so.3",
        "library_pqc_capable": None,
    }
    r = _report(
        service_crypto_linkage={
            "available": True,
            "listeners": [_listener(crypto_libraries=[lib])],
        }
    )
    assert _ids(r) == [U]


def test_service_gnutls_settled_by_library_probe_of_same_file() -> None:
    # Rocky 9.8 / Fedora 44: chronyd maps GnuTLS; the service probe has no
    # GnuTLS threshold, but --scan-crypto-libraries read that file.
    path = "/usr/lib64/libgnutls.so.30.40.3"
    lib = {
        "family": "gnutls",
        "version": "3.8.10",
        "path": path,
        "library_pqc_capable": None,
    }
    listeners = [_listener(protocol="udp", port=323, crypto_libraries=[lib])]
    capable = _report(
        service_crypto_linkage={"available": True, "listeners": listeners},
        crypto_libraries={
            "available": True,
            "libraries": {
                "gnutls": {
                    "installed": True,
                    "version": "3.8.10",
                    "files": [path],
                    "pqc_capable": True,
                }
            },
        },
    )
    assert _ids(capable) == []
    old = _report(
        service_crypto_linkage={"available": True, "listeners": listeners},
        crypto_libraries={
            "available": True,
            "libraries": {
                "gnutls": {
                    "installed": True,
                    "version": "3.6.16",
                    "files": ["/other"],
                    "pqc_capable": False,
                }
            },
        },
    )
    # Different file and version: not the library chronyd maps, so the
    # service stays undetermined; the installed old GnuTLS fails on its own.
    assert _ids(old) == ["pqc-013-crypto-library-without-pqc", U]


def test_listener_label_includes_address_so_v4_and_v6_differ() -> None:
    libs = [_lib(False)]
    r = _report(
        service_crypto_linkage={
            "available": True,
            "listeners": [
                _listener(
                    protocol="udp", port=323, address="127.0.0.1", crypto_libraries=libs
                ),
                _listener(
                    protocol="udp",
                    port=323,
                    family="ipv6",
                    address="::1",
                    crypto_libraries=libs,
                ),
            ],
        }
    )
    msgs = [f.message for f in sarif.pqc_failure_findings(r)]
    assert "udp 127.0.0.1:323" in msgs[0] and "udp [::1]:323" in msgs[1]


def test_offline_root_honours_scan_crypto_libraries(monkeypatch, tmp_path) -> None:
    # --scan-crypto-libraries was accepted with --root but silently ignored;
    # the library probe only reads files, so it now runs on the tree (#193).
    import argparse

    from pqc_readiness import _platform
    from pqc_readiness.detect import protocols_libraries, runtime_offline

    seen: list[str] = []

    def fake_scan(os_release=None):  # noqa: ARG001
        seen.append(_platform.HOST_PREFIX)
        return {
            "available": True,
            "libraries": {
                "libssh": {
                    "installed": True,
                    "version": "0.9.6",
                    "evidence": "binary",
                    "pqc_capable": False,
                }
            },
        }

    monkeypatch.setattr(protocols_libraries, "scan_crypto_libraries", fake_scan)
    _platform.set_offline_root(str(tmp_path))
    try:
        args = argparse.Namespace(
            scan_trust_store=False,
            scan_crypto_material=False,
            scan_packages=False,
            scan_signing_keys=False,
            scan_crypto_libraries=True,
            inventory_metadata=None,
        )
        r = runtime_offline.collect_offline_report(args)
    finally:
        _platform.set_offline_root("")
    assert seen == [str(tmp_path)]
    assert r.crypto_libraries["libraries"]["libssh"]["pqc_capable"] is False
    # The empty tree has no OpenSSL package and no libcrypto: OpenSSL is not
    # in the tree (as on OpenWrt, which ships Mbed TLS), so nothing to judge
    # (#217).  An OpenSSL whose version can't be read is still pqc-018.
    assert r.openssl["installed"] is False
    assert _ids(r) == ["pqc-013-crypto-library-without-pqc"]


def test_container_listener_is_named_by_container_and_pod() -> None:
    # #233: a Go service in a pod was reported as "crio-<64 hex>.scope".
    cid = "466fa36113125f83e8bdd28ce9e110580e1df56d009a5bb778f50bcf0afb8b59"  # pragma: allowlist secret
    lst = _listener(
        port=6443,
        family="ipv6",
        address="::",
        crypto_libraries=[],
        go={
            "go_version": "go1.25.3",
            # As the detection reports it: the revert clears the default.
            "default_hybrid_kex": None,
            "godebug_reverts": ["tlsmlkem"],
        },
    )
    lst.update(
        process="kube-apiserver",
        exe="/usr/bin/kube-apiserver",
        systemd_unit=f"crio-{cid}.scope",
        container={
            "runtime": "cri-o",
            "id": cid,
            "pod_uid": "96729e5171d4355063effb4f71b182d6",  # pragma: allowlist secret
            "pod_name": "kube-apiserver-crc",
            "pod_namespace": "openshift-kube-apiserver",
            "container_name": "kube-apiserver",
        },
    )
    r = _report(service_crypto_linkage={"available": True, "listeners": [lst]})
    (f,) = [x for x in sarif.pqc_failure_findings(r) if "6443" in x.message]
    assert (
        "kube-apiserver (pod openshift-kube-apiserver/kube-apiserver-crc)" in f.message
    )
    assert "crio-" not in f.message
    assert f.properties["service:pod_name"] == "kube-apiserver-crc"
    assert f.properties["service:container_id"] == cid


def test_container_without_names_falls_back_to_short_id_and_full_exe_name() -> None:
    cid = "a" * 64
    lst = _listener(port=10257, crypto_libraries=[_lib(False)])
    lst.update(
        # comm is cut at 15 characters; the executable has the full name.
        process="kube-controller",
        exe="/usr/bin/kube-controller-manager",
        container={
            "runtime": "cri-o",
            "id": cid,
            "pod_uid": None,
            "pod_name": None,
            "pod_namespace": None,
            "container_name": None,
        },
    )
    r = _report(service_crypto_linkage={"available": True, "listeners": [lst]})
    msg = sarif.pqc_failure_findings(r)[0].message
    assert "kube-controller-manager (container aaaaaaaaaaaa)" in msg
