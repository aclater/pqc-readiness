"""FIPS mode and algorithm fence, FIPS interpretation, OpenSSL capability and TLS groups."""

from __future__ import annotations

import logging
import re
import shutil
from typing import Any

from .. import _platform as _platform
from ..detect import hardware as _hardware

log = logging.getLogger("pqc-readiness")


def parse_openssl_provider_records(text: str) -> dict[str, dict[str, str]]:
    """Parse `openssl list -providers -verbose` output into
    {provider_name: {field: value}}.

    Provider records are introduced by a 2-space-indented line containing
    just the provider name; field lines under that record are indented
    exactly 4 spaces and look like `    status: active`.  Deeper-indented
    lines (the `gettable provider parameters` listing) are ignored.
    """
    records: dict[str, dict[str, str]] = {}
    current: str | None = None
    for line in text.splitlines():
        m = re.match(r"^  (\S+)\s*$", line)
        if m:
            current = m.group(1).strip()
            records.setdefault(current, {})
            continue
        if current is None:
            continue
        f = re.match(r"^    (\S+):\s*(.*)$", line)
        if f:
            records[current][f.group(1).strip()] = f.group(2).strip()
    return records


def detect_fips_mode_from_providers_text(text: str) -> bool:
    """Return True iff `openssl list -providers -verbose` output lists a
    provider named exactly 'fips' with 'status: active'.  A FIPS provider
    that is loaded but inactive (status anything other than 'active') must
    NOT register as enabled — earlier regex-based detection conflated the
    two."""
    fips = parse_openssl_provider_records(text).get("fips") or {}
    return fips.get("status", "").lower() == "active"


def detect_fips_mode() -> dict[str, Any]:
    info: dict[str, Any] = {"kernel": False, "openssl_provider": False}
    try:
        info["kernel"] = (
            _platform.host_path("/proc/sys/crypto/fips_enabled").read_text().strip() == "1"
        )
    except OSError as e:
        log.debug("detect_fips_mode: cannot read /proc/sys/crypto/fips_enabled: %s", e)
    if shutil.which("openssl"):
        rc, out = _hardware._openssl_providers_verbose_text()
        if rc == 0:
            info["openssl_provider"] = detect_fips_mode_from_providers_text(out)
    note = _platform.host_fs_unavailable_note(
        "FIPS mode detection",
        "/proc/sys/crypto/fips_enabled and the in-container openssl binary",
    )
    if note:
        info.update(note)
    return info


# ---------------------------------------------------------------------------
# FIPS algorithm-fence check (rule pqc-007)
# ---------------------------------------------------------------------------
#
# "FIPS mode active" (kernel fips=1, FIPS provider loaded with status:
# active, crypto-policy FIPS) is not the same as "algorithm fence
# engaged" (the public OpenSSL interface is gated to a subset of the
# FIPS provider's algorithm list).  Distros that ship downstream
# FIPS-provider gating patches produce both; distros that rebuild from
# upstream sources without those patches inherit the former without
# the latter.  See docs/findings/fips-algorithm-fence.md.

_FENCE_KEM_RE = re.compile(r"ML-KEM-\d+")


_FENCE_SIG_RE = re.compile(r"ML-DSA-\d+|SLH-DSA-[A-Za-z0-9-]+")


def _fence_parse_algos(text: str, pattern: re.Pattern[str]) -> list[str]:
    return sorted({m.group(0) for m in pattern.finditer(text)})


def _fence_provider_algos(
    list_arg: str, pattern: re.Pattern[str], provider: str
) -> list[str] | None:
    if not shutil.which("openssl"):
        return None
    rc, out = _platform._run(
        ["openssl", "list", list_arg, "-provider", provider], timeout=5
    )
    if rc != 0:
        return None
    return _fence_parse_algos(out, pattern)


def fips_fence_check(fips: dict[str, Any]) -> dict[str, Any]:
    """Compare default-provider vs FIPS-provider algorithm visibility.

    Only meaningful when FIPS is active (kernel fips=1 AND OpenSSL FIPS
    provider loaded).  When inactive the check is skipped — the notion
    of an algorithm fence is undefined without a FIPS provider to
    fence against.

    Returns a dict with:
      - active: bool — was the check performed
      - algorithm_fence_engaged: bool — True iff every default-provider
        set is a (non-strict) subset of the corresponding FIPS-provider
        set.  False iff any default-provider set strictly contains
        algorithms the FIPS provider does not list.
      - algorithms_reachable_outside_fence: per-class lists.
      - skip_reason: str, populated when active is False.
    """
    out: dict[str, Any] = {
        "active": False,
        "algorithm_fence_engaged": False,
        "algorithms_reachable_outside_fence": {
            "kems": [],
            "signatures": [],
            "tls_groups": [],
        },
    }
    if not (fips.get("kernel") and fips.get("openssl_provider")):
        out["skip_reason"] = (
            "FIPS not active (kernel fips=1 and active OpenSSL FIPS "
            "provider both required for the fence check)"
        )
        return out
    out["active"] = True

    fence_engaged: list[bool] = []

    for list_arg, pattern, key in (
        ("-kem-algorithms", _FENCE_KEM_RE, "kems"),
        ("-signature-algorithms", _FENCE_SIG_RE, "signatures"),
    ):
        fips_algs = _fence_provider_algos(list_arg, pattern, "fips") or []
        default_algs = _fence_provider_algos(list_arg, pattern, "default") or []
        outside = sorted(set(default_algs) - set(fips_algs))
        out["algorithms_reachable_outside_fence"][key] = outside
        fence_engaged.append(not outside)

    rc_fips, fips_groups_text = _platform._run(
        ["openssl", "list", "-tls-groups", "-provider", "fips"], timeout=5
    )
    rc_def, default_groups_text = _platform._run(
        ["openssl", "list", "-tls-groups", "-provider", "default"], timeout=5
    )
    if rc_fips == 0 and rc_def == 0:
        fips_groups = set(parse_openssl_tls_groups(fips_groups_text))
        default_groups = set(parse_openssl_tls_groups(default_groups_text))
        outside_groups = sorted(default_groups - fips_groups)
        outside_classified = classify_tls_groups(outside_groups)
        outside_pqc = sorted(
            set(outside_classified.get("pure_pqc", []))
            | set(outside_classified.get("hybrid", []))
        )
        out["algorithms_reachable_outside_fence"]["tls_groups"] = outside_pqc
        fence_engaged.append(not outside_pqc)

    out["algorithm_fence_engaged"] = all(fence_engaged)
    return out


# ---------------------------------------------------------------------------
# FIPS / PQC interaction warning
# ---------------------------------------------------------------------------

# Family-specific notes appended to fips dict by interpret_fips().  The
# strings deliberately stop short of declaring the host FIPS-compliant —
# the script can detect what is enabled, but only the customer's
# compliance team can declare the certification valid for their use.
_FIPS_NOTES_BY_FAMILY: dict[str, str] = {
    "rhel": (
        "RHEL ships a Red Hat-validated FIPS provider.  ML-KEM/ML-DSA "
        "are not yet in the FIPS-validated set as of RHEL 10.0 — verify "
        "against the latest Red Hat FIPS bulletin before relying on PQC "
        "in FIPS-mandated workflows."
    ),
    "debian": (
        "Debian main does not ship a FIPS-certified OpenSSL provider.  "
        "If fips_enabled=1 here, a third-party module is in use — verify "
        "its certification status independently."
    ),
    "suse": (
        "SUSE ships a separately-validated FIPS module via SUSE Linux "
        "Enterprise.  ML-KEM/ML-DSA are not yet covered as of SLES 15 "
        "SP6; verify against the latest SUSE FIPS bulletin."
    ),
    "arch": "Arch does not provide a FIPS-validated OpenSSL build.",
    "alpine": "Alpine does not provide a FIPS-validated OpenSSL build.",
    "macos": "macOS does not expose Linux-style FIPS mode; this field reflects OpenSSL provider state only.",
    "unknown": "Cannot determine distribution-specific FIPS posture.",
}


# Distribution-vendor-certified FIPS provider sources, keyed by os_release.
# When the kernel reports fips_enabled=1 AND OpenSSL has an active fips
# provider AND the os_release matches one of these signatures, we set
# fips.distribution_certified=True with the vendor source attribution.
_DISTRO_CERTIFIED_FIPS: list[tuple[str, str | None, str]] = [
    # (family, id_match_or_None, vendor_source_label)
    ("rhel", None, "Red Hat-validated FIPS provider"),
    ("suse", None, "SUSE Linux Enterprise FIPS module"),
    # Ubuntu Pro ships a Canonical-built FIPS provider.  We can't
    # distinguish Ubuntu Pro from regular Ubuntu purely from os_release,
    # but the presence of an active FIPS provider on Ubuntu strongly
    # implies Pro (Universe/Main do not ship one).
    ("debian", "ubuntu", "Ubuntu Pro FIPS (Canonical) — assumed from active provider"),
]


def interpret_fips(
    fips: dict[str, Any], openssl: dict[str, Any], os_release: dict[str, Any]
) -> dict[str, Any]:
    """Augment the fips dict with family-aware certification context.

    distribution_certified is True only when the script has affirmative
    evidence of a vendor-certified FIPS provider being active: kernel
    fips_enabled=1 AND an active OpenSSL FIPS provider AND the
    os_release matches a known certified family.  Unknown / Debian /
    Arch / Alpine never claim certification — the script cannot verify
    a third-party FIPS module.
    """
    out = dict(fips)
    family = os_release.get("family", "unknown")
    id_ = os_release.get("id", "unknown")
    has_provider = bool(fips.get("openssl_provider"))
    kernel_on = bool(fips.get("kernel"))

    out["distribution_certified"] = False
    out["distribution_certified_source"] = None
    if has_provider and kernel_on:
        for fam, id_match, source in _DISTRO_CERTIFIED_FIPS:
            if family == fam and (id_match is None or id_ == id_match):
                out["distribution_certified"] = True
                out["distribution_certified_source"] = source
                break

    out["notes"] = _FIPS_NOTES_BY_FAMILY.get(family, _FIPS_NOTES_BY_FAMILY["unknown"])

    fence = fips_fence_check(out)
    out["algorithm_fence_engaged"] = fence["algorithm_fence_engaged"]
    out["algorithms_reachable_outside_fence"] = fence[
        "algorithms_reachable_outside_fence"
    ]
    out["fence_check_active"] = fence["active"]
    if "skip_reason" in fence:
        out["fence_check_skip_reason"] = fence["skip_reason"]

    return out


def fips_pqc_conflict_check(
    fips: dict[str, Any], openssl: dict[str, Any]
) -> dict[str, Any]:
    """Detect the case where a host is in kernel FIPS mode AND OpenSSL is
    advertising PQC algorithms via the non-FIPS default provider.  In this
    state ML-KEM/ML-DSA appear listed but are NOT usable in a FIPS-validated
    workflow (RHEL 9 / 10 FIPS provider does not yet include PQC)."""
    if not fips.get("kernel"):
        return {"in_conflict": False, "explanation": "Kernel FIPS mode not enabled."}
    has_pqc = bool(
        (openssl.get("kem_algorithms") or []) or (openssl.get("sig_algorithms") or [])
    )
    if not has_pqc:
        return {
            "in_conflict": False,
            "explanation": "FIPS mode active and no PQC algorithms exposed.",
        }
    if fips.get("openssl_provider"):
        return {
            "in_conflict": False,
            "explanation": (
                "FIPS provider is active and PQC algorithms are exposed.  "
                "Verify they are coming from a FIPS-validated provider before "
                "relying on them in regulated workflows."
            ),
        }
    return {
        "in_conflict": True,
        "explanation": (
            "Kernel FIPS mode is enabled but OpenSSL is exposing PQC algorithms via "
            "the default (non-FIPS) provider.  These algorithms are listed but would "
            "not be usable in a FIPS-validated workflow — RHEL 9/10 FIPS provider "
            "does not include ML-KEM/ML-DSA as of this writing.  Audit provider "
            "configuration before claiming PQC support in a FIPS-mandated environment."
        ),
    }


# ---------------------------------------------------------------------------
# OpenSSL capability inspection
# ---------------------------------------------------------------------------


def openssl_upgrade_path(
    version_tuple: list[int] | None, os_release: dict[str, Any] | None
) -> str | None:
    """Family-aware hint for getting a PQC-capable OpenSSL on this host.

    Empty when OpenSSL is already 3.5+ (nothing to upgrade) or when we
    cannot resolve the distro.  Strings deliberately stop at fact —
    the field architect plans the upgrade, the script just inventories.
    """
    if version_tuple and tuple(version_tuple[:2]) >= (3, 5):
        return None
    if not os_release:
        return None
    family = os_release.get("family", "unknown")
    id_ = os_release.get("id", "unknown")
    ver = (os_release.get("version_id") or "").split(".")
    major = ver[0] if ver and ver[0] else None

    if family == "rhel":
        # RHEL 8 / Rocky 8 / AlmaLinux 8 ship OpenSSL 1.1.1, which has no
        # PQC primitives at all — distinct from EL9's 3.0/3.2 path.  The
        # RHEL 8 customer also has to opt into the AppStream python3.9+
        # module just to invoke this script (default Python is 3.6, which
        # cannot parse modern type-hint syntax used here), so the hint
        # carries both facts.  The wrapper shell launcher at the repo
        # root does the runtime fallback to a usable interpreter.
        if id_ == "rhel" and major == "8":
            return (
                "RHEL 8 base channel ships OpenSSL 1.1.1; PQC requires "
                "OpenSSL 3.5+, available in RHEL 10 or a Red Hat-supported "
                "channel with newer crypto.  The script itself requires "
                "Python 3.9+ — enable the `python39` (or higher) AppStream "
                "module: `dnf module install python39`."
            )
        if id_ in {"rocky", "almalinux", "centos", "ol"} and major == "8":
            return (
                "EL8-class distributions ship OpenSSL 1.1.1; PQC requires "
                "OpenSSL 3.5+, available in the EL10 release of this "
                "distribution or a backport channel.  The script itself "
                "requires Python 3.9+ via the `python39` (or higher) "
                "AppStream module: `dnf module install python39`."
            )
        if id_ == "rhel" and major and int(major) <= 9:
            return (
                "RHEL 9 base channel ships OpenSSL 3.0/3.2; PQC requires "
                "RHEL 10 or a Red Hat-supported channel with newer crypto."
            )
        if id_ == "fedora" and major and int(major) < 41:
            return (
                f"Fedora {major} predates OpenSSL 3.5; upgrade to Fedora 41 or newer."
            )
        if id_ in {"rocky", "almalinux", "centos", "ol"} and major and int(major) <= 9:
            return (
                "EL9-class distributions ship OpenSSL 3.0/3.2; PQC requires "
                "the EL10 release of this distribution or a backport channel."
            )
    elif family == "debian":
        if id_ == "debian":
            if major == "12":
                return (
                    "Debian 12 (bookworm) ships OpenSSL 3.0; OpenSSL 3.5 is "
                    "available in trixie or bookworm-backports."
                )
            if major and int(major) < 12:
                return (
                    "Pre-bookworm Debian ships OpenSSL 1.1.x; upgrade to "
                    "Debian 12 + backports or newer."
                )
        elif id_ == "ubuntu" and major and major.isdigit():
            # Advice names LTS releases only: interim releases reach EOL
            # after nine months and would rot this string (#121).
            # Verified against the archive: noble (24.04) carries only
            # OpenSSL 3.0.x in main/updates with no 3.5 build anywhere;
            # resolute (26.04 LTS) ships OpenSSL 3.5.x in main.
            if int(major) >= 26:
                return (
                    "Ubuntu 26.04 LTS and later ship OpenSSL 3.5 in main, "
                    "but this host reports an older OpenSSL; check for "
                    "held, pinned or third-party OpenSSL packages "
                    "(`apt-cache policy openssl libssl3t64`) and apply "
                    "pending updates."
                )
            if major == "24":
                return (
                    "Ubuntu 24.04 LTS ships OpenSSL 3.0 and its archive "
                    "carries no OpenSSL 3.5 build; PQC requires Ubuntu "
                    "26.04 LTS or later, which ships OpenSSL 3.5 in main."
                )
            return (
                f"Ubuntu {os_release.get('version_id')} predates OpenSSL 3.5 "
                "in the Ubuntu archive; PQC requires Ubuntu 26.04 LTS or "
                "later, which ships OpenSSL 3.5 in main."
            )
    elif family == "suse":
        return (
            "SLES 15 SP6 ships OpenSSL 3.0; OpenSSL 3.5 is available via "
            "SUSE Package Hub.  Verify FIPS validation status before swapping."
        )
    elif family == "alpine":
        return (
            "Alpine ships OpenSSL via the apk repository.  Edge channel "
            "carries 3.5+; verify against the host's apk repo configuration."
        )
    elif family == "arch":
        return "Arch rolls forward; `pacman -Syu` should bring OpenSSL 3.5+."
    return None


# TLS group classification.
#
# Pure PQC groups expose a single PQC KEM with no classical fallback;
# hybrid groups concatenate a classical group with a PQC KEM (the IETF
# transitional design — draft-ietf-tls-hybrid-design).  OpenSSL 3.5
# ships X25519MLKEM768 as the default and clients/servers negotiating
# PQC today are almost always using a hybrid; the distinction matters
# for compliance reporting and for transitional-deployment guidance.
#
# Anything that matches a recognised classical group name (named EC
# curves, FFDHE groups, brainpool) is bucketed as "classical".  Names
# that match no catalog are dropped rather than silently miscategorised.
_PURE_PQC_TLS_GROUP_RE = re.compile(r"^MLKEM\d+$")


_HYBRID_TLS_GROUP_RE = re.compile(r"^(?:X(?:25519|448)MLKEM\d+|SecP\d+r1MLKEM\d+)$")


_CLASSICAL_TLS_GROUP_RE = re.compile(
    r"^(?:secp\d+[kr]\d+|prime\d+v\d+|x25519|x448|ffdhe\d+|"
    r"brainpoolP\d+r\d+(?:tls13)?|sect\d+\w+)$",
    re.IGNORECASE,
)


def parse_openssl_tls_groups(text: str) -> list[str]:
    """Extract canonical group identifiers from `openssl list -tls-groups`.

    OpenSSL emits this list in two formats depending on flags / version:

      Colon-separated (current `-tls1_3` form, single line):
          secp256r1:secp384r1:x25519:MLKEM768:X25519MLKEM768

      One-per-line with optional alias info in parens (older form):
          secp256r1 (P-256, prime256v1)
          MLKEM768
          X25519MLKEM768

    We accept both.  Header lines like `TLS 1.3 group support:` end with
    `:` and contain whitespace — those are dropped before tokenisation.
    Ordering is preserved so callers can surface OpenSSL's preference
    order if desired.
    """
    out: list[str] = []
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        # Header rows: end with `:` AND have inner whitespace (e.g.
        # "TLS 1.3 group support:").  Group rows in either format do
        # not match this shape.
        if s.endswith(":") and " " in s:
            continue
        for tok in s.split(":"):
            tok = tok.strip()
            if not tok:
                continue
            # Alias-form rows include trailing parenthesised info; take
            # the leading whitespace-delimited token only.
            head = tok.split()[0]
            if re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]+", head):
                out.append(head)
    return out


def classify_tls_groups(group_names: list[str]) -> dict[str, list[str]]:
    """Split a flat list of TLS group names into pure_pqc / hybrid /
    classical buckets.  Names that match no catalog are dropped (rather
    than lumped into classical) so the report stays honest about what
    we don't recognise yet.  Each bucket is returned sorted and deduped."""
    pure: set[str] = set()
    hybrid: set[str] = set()
    classical: set[str] = set()
    for name in group_names:
        if _HYBRID_TLS_GROUP_RE.match(name):
            hybrid.add(name)
        elif _PURE_PQC_TLS_GROUP_RE.match(name):
            pure.add(name)
        elif _CLASSICAL_TLS_GROUP_RE.match(name):
            classical.add(name)
    return {
        "pure_pqc": sorted(pure),
        "hybrid": sorted(hybrid),
        "classical": sorted(classical),
    }


def openssl_capability(os_release: dict[str, Any] | None = None) -> dict[str, Any]:
    if not shutil.which("openssl"):
        return {"available": False, "reason": "openssl not on PATH"}
    out: dict[str, Any] = {"available": True}
    rc, ver = _platform._openssl_version_text()
    out["version"] = ver.strip() if rc == 0 else "unknown"
    m = re.search(r"OpenSSL\s+(\d+)\.(\d+)\.(\d+)", out["version"])
    out["version_tuple"] = (
        [int(m.group(1)), int(m.group(2)), int(m.group(3))] if m else None
    )
    out["pqc_native"] = bool(out["version_tuple"]) and tuple(
        out["version_tuple"][:2]
    ) >= (3, 5)
    rc, kems = _platform._run(["openssl", "list", "-kem-algorithms"], timeout=5)
    out["kem_algorithms"] = (
        sorted({a for a in re.findall(r"ML-KEM-\d+", kems)}) if rc == 0 else []
    )
    rc, sigs = _platform._run(["openssl", "list", "-signature-algorithms"], timeout=5)
    out["sig_algorithms"] = (
        sorted({a for a in re.findall(r"ML-DSA-\d+|SLH-DSA-[A-Za-z0-9-]+", sigs)})
        if rc == 0
        else []
    )
    rc, groups = _platform._run(["openssl", "list", "-tls-groups", "-tls1_3"], timeout=5)
    if rc != 0:
        rc, groups = _platform._run(["openssl", "list", "-tls-groups"], timeout=5)
    all_group_names = parse_openssl_tls_groups(groups) if rc == 0 else []
    classified = classify_tls_groups(all_group_names)
    out["tls_groups"] = classified
    # Back-compat: tls_pqc_groups was historically the pure-PQC + hybrid
    # union.  Aggregator/JSON consumers may key off it; new consumers
    # should prefer the explicit tls_groups split above.
    out["tls_pqc_groups"] = sorted(
        set(classified["pure_pqc"]) | set(classified["hybrid"])
    )
    rc, providers = _hardware._openssl_providers_verbose_text()
    out["providers"] = (
        sorted(parse_openssl_provider_records(providers)) if rc == 0 else []
    )
    out["upgrade_path"] = openssl_upgrade_path(out["version_tuple"], os_release)
    return out
