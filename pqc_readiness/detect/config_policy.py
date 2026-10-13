"""System-wide crypto policy (crypto-policies) detection (#104).

On RHEL-family systems and newer SUSE releases the crypto-policies
framework is the master switch for which algorithms OpenSSL, GnuTLS,
NSS, OpenSSH and libreswan will negotiate.  A host can ship a
PQC-capable OpenSSL while the active policy keeps ML-KEM / ML-DSA out of
every back-end, so this probe reports what the policy *configures*,
alongside the capability probes that report what the libraries *can* do.

Everything is read from files, never from `update-crypto-policies`:
openSUSE Leap 16 / Tumbleweed ship the policy data without that tool,
and under --host-mount the container's binary would describe the image.

Measured on cloud-image VMs (2026-10-13, fixtures in
tests/fixtures/crypto_policies/):

* Rocky / Alma / Stream / Oracle Linux 9.8: DEFAULT enables **no** PQC in
  any back-end; the `PQ` module adds hybrid ML-KEM and ML-DSA.
* Rocky / Alma / Stream 10.2, Fedora 43 / 44, openSUSE Leap 16 /
  Tumbleweed: DEFAULT already enables hybrid ML-KEM groups and ML-DSA
  signatures; `TEST-PQ` adds pure ML-KEM and composite signatures, and
  `NO-PQ` removes PQC.
* Back-end files are absolute symlinks into
  /usr/share/crypto-policies/<POLICY>/, so they are resolved inside the
  host prefix rather than followed into the scanner container.
"""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any

from .. import _platform as _platform
from . import packages as _packages
from . import protocols as _protocols
from . import runtime as _runtime

log = logging.getLogger("pqc-readiness")

CRYPTO_POLICIES_DIR = "/etc/crypto-policies"
# Ubuntu's crypto-config (#170): /var/lib/crypto-config/profiles/current
# is a symlink to the active profile; each profile is a directory of
# per-application snippets (openssl.conf.d, gnutls.conf, nginx.conf.d,
# apt.conf.d, exim) plus metadata.json.  Measured on Ubuntu 26.04.1 with
# crypto-config 0.7.4-0ubuntu2 (2026-10-13): no shipped profile sets TLS
# groups, so PQC key exchange is left to the library default.
CRYPTO_CONFIG_DIR = "/var/lib/crypto-config"
_CRYPTO_CONFIG_SHARE = "/usr/share/crypto-config/profiles"
_OPENSSL_PROFILE_KEYS = (
    "MinProtocol",
    "MaxProtocol",
    "CipherString",
    "Ciphersuites",
    "Groups",
    "Curves",
    "SignatureAlgorithms",
)
_MODULE_DIRS = (
    "/usr/share/crypto-policies/policies/modules",
    "/etc/crypto-policies/policies/modules",
)

# Subpolicy modules that switch PQC on or off.  `PQ` is the EL9 name,
# `TEST-PQ` the EL10 / Fedora / SUSE one; `NO-PQ` removes PQC.
PQ_ENABLING_SUBPOLICIES = ("PQ", "TEST-PQ")
PQ_DISABLING_SUBPOLICIES = ("NO-PQ",)

# Back-end file -> what it configures.  Only these are parsed; the rest
# (bind, java, krb5, ...) carry no PQC algorithms today.
_BACKENDS = (
    "opensslcnf",
    "gnutls",
    "nss",
    "openssh",
    "opensshserver",
    "libreswan",
)

# PQC algorithm tokens as they appear in policy back-ends, across OpenSSL
# canonical names, oqs-provider aliases, GnuTLS and NSS spellings.
_PQC_KEM_TOKEN_RE = re.compile(r"ml[-_]?kem|kyber|sntrup|frodo|hqc", re.IGNORECASE)
_PQC_SIG_TOKEN_RE = re.compile(
    r"ml[-_]?dsa|slh[-_]?dsa|sphincs|falcon|fn[-_]?dsa", re.IGNORECASE
)
_CLASSICAL_TOKEN_RE = re.compile(
    r"x25519|x448|secp\d+|p\d{3}|nistp\d+|ed25519|ed448|rsa|pss|bp\d+|ecdsa",
    re.IGNORECASE,
)


def parse_policy_name(text: str) -> dict[str, Any]:
    """Split `DEFAULT:TEST-PQ:NO-SHA1` into base policy and subpolicies."""
    value = text.strip().splitlines()[0].strip() if text.strip() else ""
    parts = [p for p in value.split(":") if p]
    return {
        "active": value or None,
        "base_policy": parts[0] if parts else None,
        "subpolicies": parts[1:],
    }


def _classify_pqc(names: list[str], token_re: re.Pattern[str]) -> dict[str, list[str]]:
    """Bucket algorithm names into hybrid / pure PQC.  A name carrying a
    PQC token and a classical token (e.g. `X25519MLKEM768`,
    `p256_mldsa44`, `mlkem768x25519-sha256`) is hybrid; a PQC token alone
    is pure.  Classical names are left out; the full list stays in the
    back-end's own field."""
    hybrid: list[str] = []
    pure: list[str] = []
    for n in names:
        if not token_re.search(n):
            continue
        (hybrid if _CLASSICAL_TOKEN_RE.search(n) else pure).append(n)
    return {"hybrid": hybrid, "pure_pqc": pure}


def _split_tokens(value: str, seps: str) -> list[str]:
    out: list[str] = []
    for tok in re.split(f"[{re.escape(seps)}]", value):
        tok = tok.strip().lstrip("*?").strip()
        if tok:
            out.append(tok)
    return out


def parse_opensslcnf_backend(text: str) -> dict[str, Any]:
    """`Groups = *?X25519MLKEM768:?x25519_mlkem768/*X25519:...` and
    `SignatureAlgorithms = ?mldsa44:...`.  `*` marks a key share, `?`
    tolerates names the provider doesn't know, `/` separates key-share
    tuples; order (preference) is kept."""
    groups: list[str] = []
    sigalgs: list[str] = []
    for line in text.splitlines():
        m = re.match(r"\s*(Groups|SignatureAlgorithms)\s*=\s*(.*)$", line)
        if not m:
            continue
        toks = _split_tokens(m.group(2), ":/")
        (groups if m.group(1) == "Groups" else sigalgs).extend(toks)
    return {
        "groups": groups,
        "pqc_groups": _classify_pqc(groups, _PQC_KEM_TOKEN_RE),
        "signature_algorithms": sigalgs,
        "pqc_signature_algorithms": _classify_pqc(sigalgs, _PQC_SIG_TOKEN_RE),
    }


def parse_gnutls_backend(text: str) -> dict[str, Any]:
    """`tls-enabled-group = GROUP-X25519-MLKEM768` and
    `secure-sig = ML-DSA-65` lines."""
    groups = re.findall(r"^\s*tls-enabled-group\s*=\s*(\S+)", text, re.MULTILINE)
    groups = [g[len("GROUP-") :] if g.startswith("GROUP-") else g for g in groups]
    sigs = re.findall(r"^\s*secure-sig\s*=\s*(\S+)", text, re.MULTILINE)
    return {
        "groups": groups,
        "pqc_groups": _classify_pqc(groups, _PQC_KEM_TOKEN_RE),
        "signature_algorithms": sigs,
        "pqc_signature_algorithms": _classify_pqc(sigs, _PQC_SIG_TOKEN_RE),
    }


def parse_nss_backend(text: str) -> dict[str, Any]:
    """`config="disallow=ALL allow=HMAC-SHA256:...:mlkem768x25519:..."`."""
    # `allow=` must not match inside `disallow=ALL`.
    m = re.search(r"(?:^|[\s\"])allow=([^\s\"]+)", text)
    allowed = _split_tokens(m.group(1), ":") if m else []
    return {
        "allowed": allowed,
        "pqc_groups": _classify_pqc(allowed, _PQC_KEM_TOKEN_RE),
        "pqc_signature_algorithms": _classify_pqc(allowed, _PQC_SIG_TOKEN_RE),
    }


def parse_openssh_backend(text: str) -> dict[str, Any]:
    """`KexAlgorithms a,b,c` (client and server back-ends share the
    format on EL9.8 / EL10 / Fedora / SUSE 16); classified with the same
    three buckets as the `ssh -Q kex` probe."""
    kex: list[str] = []
    for m in re.finditer(
        r"(?:^|\s|-o)KexAlgorithms[ =]([^\s'\"]+)", text, re.MULTILINE
    ):
        kex.extend(k for k in m.group(1).split(",") if k)
    return {"kex": kex, "kex_groups": _protocols.classify_ssh_kex(kex)}


def parse_libreswan_backend(text: str) -> dict[str, Any]:
    """`ike=...` proposals.  No measured policy enables ML-KEM for IKE yet
    (EL10.2 TEST-PQ included); a PQC token here would be reported."""
    proposals = re.findall(r"^\s*ike=(\S+)", text, re.MULTILINE)
    tokens = [t for p in proposals for t in re.split(r"[,+\-;]", p) if t]
    return {
        "ike_proposals": proposals,
        "pqc_key_exchange": [t for t in tokens if _PQC_KEM_TOKEN_RE.search(t)],
    }


_PARSERS = {
    "opensslcnf": parse_opensslcnf_backend,
    "gnutls": parse_gnutls_backend,
    "nss": parse_nss_backend,
    "openssh": parse_openssh_backend,
    "opensshserver": parse_openssh_backend,
    "libreswan": parse_libreswan_backend,
}


def _read_host_file(path: str) -> str | None:
    """Read a host file, resolving symlinks inside the host prefix so an
    absolute link (back-ends point into /usr/share/crypto-policies) is
    never followed into the scanner container's own filesystem."""
    try:
        resolved = _packages.resolve_under_prefix(path, _platform.HOST_PREFIX)
    except _packages.RpmdbError as e:
        log.debug("crypto_policy: cannot resolve %s: %s", path, e)
        return None
    try:
        return _platform.host_path(resolved).read_text(errors="replace")
    except OSError as e:
        log.debug("crypto_policy: cannot read %s (-> %s): %s", path, resolved, e)
        return None


def _available_subpolicies() -> list[str]:
    names: set[str] = set()
    for d in _MODULE_DIRS:
        p = _platform.host_path(d)
        try:
            names.update(f.stem for f in p.glob("*.pmod"))
        except OSError as e:
            log.debug("crypto_policy: cannot list %s: %s", d, e)
    return sorted(names)


def _kernel_fips() -> bool | None:
    try:
        return (
            _platform.host_path("/proc/sys/crypto/fips_enabled").read_text().strip()
            == "1"
        )
    except OSError as e:
        log.debug("crypto_policy: cannot read fips_enabled: %s", e)
        return None


def _pqc_enabled(backends: dict[str, dict[str, Any]]) -> dict[str, bool | None]:
    """Per-protocol: does the active policy let PQC through?  None when the
    back-end that decides it is missing or unreadable."""

    def any_pqc(b: dict[str, Any] | None, *keys: str) -> bool | None:
        if not b or not b.get("readable"):
            return None
        return any(
            (b.get(k) or {}).get("hybrid") or (b.get(k) or {}).get("pure_pqc")
            for k in keys
        )

    ssl = backends.get("opensslcnf")
    ssh_client = backends.get("openssh")
    ssh_server = backends.get("opensshserver")
    ike = backends.get("libreswan")

    def ssh(b: dict[str, Any] | None) -> bool | None:
        if not b or not b.get("readable"):
            return None
        g = b.get("kex_groups") or {}
        return bool(g.get("hybrid") or g.get("pure_pqc"))

    return {
        "tls_key_exchange": any_pqc(ssl, "pqc_groups"),
        "tls_signatures": any_pqc(ssl, "pqc_signature_algorithms"),
        "ssh_key_exchange_client": ssh(ssh_client),
        "ssh_key_exchange_server": ssh(ssh_server),
        "ike_key_exchange": (
            bool(ike.get("pqc_key_exchange")) if ike and ike.get("readable") else None
        ),
    }


def _profile_label(resolved: str, profiles_dir: str) -> str:
    """`default`, `future`, or a namespaced `debian/test1`, from the
    resolved target of a profile symlink."""
    for base in (profiles_dir, _CRYPTO_CONFIG_SHARE):
        if resolved.startswith(base + "/"):
            return resolved[len(base) + 1 :]
    return os.path.basename(resolved)


def _list_host_dir(path: str) -> list[str] | None:
    try:
        resolved = _packages.resolve_under_prefix(path, _platform.HOST_PREFIX)
        return sorted(os.listdir(_platform.HOST_PREFIX + resolved))
    except (OSError, _packages.RpmdbError) as e:
        log.debug("crypto_policy: cannot list %s: %s", path, e)
        return None


def _crypto_config_profiles(profiles_dir: str) -> list[str]:
    """Profiles under profiles/: entries with a metadata.json, one level
    of namespacing allowed (Ubuntu ships `debian/test1`)."""
    out: list[str] = []
    for name in _list_host_dir(profiles_dir) or []:
        if name == "current":
            continue
        entries = _list_host_dir(f"{profiles_dir}/{name}") or []
        if "metadata.json" in entries:
            out.append(name)
            continue
        for sub in entries:
            if "metadata.json" in (
                _list_host_dir(f"{profiles_dir}/{name}/{sub}") or []
            ):
                out.append(f"{name}/{sub}")
    return out


def parse_crypto_config_openssl(sections: dict[str, dict[str, str]]) -> dict[str, Any]:
    """The TLS settings a crypto-config OpenSSL snippet sets, whatever its
    section names (Ubuntu's `legacy` and `future` snippets use different
    init sections), plus the @SECLEVEL and the PQC split of any Groups."""
    wanted = {k.lower(): k for k in _OPENSSL_PROFILE_KEYS}
    settings: dict[str, str] = {}
    for body in sections.values():
        for k, v in body.items():
            canon = wanted.get(k.lower())
            if canon and canon not in settings:
                settings[canon] = v
    m = re.search(r"@SECLEVEL=(\d)", settings.get("CipherString", ""))
    groups_text = settings.get("Groups") or settings.get("Curves")
    groups = [g for g in re.split(r"[:,\s]+", groups_text or "") if g]
    return {
        "settings": settings,
        "seclevel": int(m.group(1)) if m else None,
        "groups_configured": groups or None,
        "pqc_groups": _classify_pqc(groups, _PQC_KEM_TOKEN_RE) if groups else None,
    }


def detect_crypto_config() -> dict[str, Any] | None:
    """Ubuntu crypto-config state, or None when it isn't installed."""
    profiles_dir = f"{CRYPTO_CONFIG_DIR}/profiles"
    try:
        current = _packages.resolve_under_prefix(
            f"{profiles_dir}/current", _platform.HOST_PREFIX
        )
    except _packages.RpmdbError as e:
        log.debug("crypto_policy: cannot resolve crypto-config current: %s", e)
        return None
    if not os.path.isdir(_platform.HOST_PREFIX + current):
        return None
    from . import config_openssl as _config_openssl  # avoids an import cycle

    meta_text = _read_host_file(f"{profiles_dir}/current/metadata.json")
    try:
        meta = json.loads(meta_text) if meta_text else {}
    except ValueError as e:
        log.debug("crypto_policy: bad crypto-config metadata.json: %s", e)
        meta = {}
    parsed = _config_openssl.parse_openssl_cnf(
        f"{profiles_dir}/current/openssl.conf.d",
        _config_openssl._read,
        _config_openssl._list_dir,
    )
    openssl = parse_crypto_config_openssl(parsed["sections"])
    openssl["files"] = parsed["files"]
    pqc_groups = openssl["pqc_groups"]
    tls_kex: bool | None = (
        None
        if pqc_groups is None
        else bool(pqc_groups["pure_pqc"] or pqc_groups["hybrid"])
    )
    return {
        "available": True,
        "framework": "crypto-config",
        "active": _profile_label(current, profiles_dir),
        "available_profiles": _crypto_config_profiles(profiles_dir),
        "profile": {
            "summary": meta.get("summary"),
            "parent": meta.get("parent"),
        },
        "applications": [
            e
            for e in (_list_host_dir(f"{profiles_dir}/current") or [])
            if e != "metadata.json"
        ],
        "openssl": openssl,
        # crypto-config 0.7.4 configures neither OpenSSH nor IKE, and sets
        # TLS groups only if a profile does: None means the library /
        # daemon default applies, not that PQC is off.
        "pqc_enabled": {
            "tls_key_exchange": tls_kex,
            "tls_signatures": None,
            "ssh_key_exchange_client": None,
            "ssh_key_exchange_server": None,
            "ike_key_exchange": None,
        },
    }


def detect_crypto_policy() -> dict[str, Any]:
    """Report the active system-wide crypto policy and what it lets PQC do.

    Keys mirror the RHEL `crypto_policies` system role's facts where they
    overlap: `active` (role: crypto_policies_active),
    `available_subpolicies` (crypto_policies_available_subpolicies) and
    `reboot_required` (crypto_policies_reboot_required)."""
    state = _read_host_file(f"{CRYPTO_POLICIES_DIR}/state/current")
    configured_text = _read_host_file(f"{CRYPTO_POLICIES_DIR}/config")
    if state is None and configured_text is None:
        cc = detect_crypto_config()
        if cc is not None:
            note = _runtime._host_fs_note_for("crypto_policy")
            if note:
                cc.update(note)
            return cc
        out: dict[str, Any] = {
            "available": False,
            "reason": (
                "no system-wide crypto policy framework "
                f"({CRYPTO_POLICIES_DIR} and {CRYPTO_CONFIG_DIR} not found)"
            ),
        }
        note = _runtime._host_fs_note_for("crypto_policy")
        if note:
            out.update(note)
        return out

    configured_line = next(
        (
            ln.strip()
            for ln in (configured_text or "").splitlines()
            if ln.strip() and not ln.lstrip().startswith("#")
        ),
        None,
    )
    name = parse_policy_name(state if state is not None else configured_line or "")
    backends: dict[str, dict[str, Any]] = {}
    for b in _BACKENDS:
        text = _read_host_file(f"{CRYPTO_POLICIES_DIR}/back-ends/{b}.config")
        if text is None:
            backends[b] = {"readable": False}
            continue
        backends[b] = {"readable": True, **_PARSERS[b](text)}

    subs = name["subpolicies"]
    base = name["base_policy"]
    kernel_fips = _kernel_fips()
    reboot_required: bool | None
    if base is None or kernel_fips is None:
        reboot_required = None
    else:
        # The FIPS policy and kernel FIPS mode only change together across
        # a reboot (fips-mode-setup); a mismatch means one is pending.
        reboot_required = (base == "FIPS") != kernel_fips
    out = {
        "available": True,
        "framework": "crypto-policies",
        "active": name["active"],
        "base_policy": base,
        "subpolicies": subs,
        "configured": configured_line,
        # update-crypto-policies --is-applied compares the same two files.
        "applied": (
            None
            if state is None or configured_line is None
            else configured_line == (name["active"] or "")
        ),
        "available_subpolicies": _available_subpolicies(),
        "pq_subpolicies_active": [s for s in subs if s in PQ_ENABLING_SUBPOLICIES],
        "pq_disabled_by_subpolicy": [s for s in subs if s in PQ_DISABLING_SUBPOLICIES],
        "reboot_required": reboot_required,
        "pqc_enabled": _pqc_enabled(backends),
        "backends": backends,
    }
    note = _runtime._host_fs_note_for("crypto_policy")
    if note:
        out.update(note)
    return out


def policy_blocks_capable_pqc(
    crypto_policy: dict[str, Any], openssl: dict[str, Any]
) -> bool:
    """True when the OpenSSL build can do hybrid / pure ML-KEM TLS groups
    but the active policy keeps every PQC group out of the OpenSSL
    back-end: the "capable but not configured" case (#104, feeds #107)."""
    if not crypto_policy.get("available"):
        return False
    tg = openssl.get("tls_groups") or {}
    capable = bool(tg.get("hybrid") or tg.get("pure_pqc"))
    return (
        capable
        and (crypto_policy.get("pqc_enabled") or {}).get("tls_key_exchange") is False
    )


__all__ = [
    "PQ_DISABLING_SUBPOLICIES",
    "PQ_ENABLING_SUBPOLICIES",
    "detect_crypto_policy",
    "parse_gnutls_backend",
    "parse_libreswan_backend",
    "parse_nss_backend",
    "parse_openssh_backend",
    "parse_opensslcnf_backend",
    "parse_policy_name",
    "policy_blocks_capable_pqc",
]
