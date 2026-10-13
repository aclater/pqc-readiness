"""WireGuard and OpenVPN post-quantum posture (--scan-tunnels, #113).

* **WireGuard** uses a Curve25519 Noise_IK handshake.  Its only
  post-quantum mitigation is the optional per-peer pre-shared key, which
  WireGuard's protocol page describes as the extra symmetric layer "for,
  say, post-quantum resistance" (https://www.wireguard.com/protocol/).
  Sources: wg-quick (``/etc/wireguard/*.conf``), systemd-networkd
  (``.netdev`` ``[WireGuardPeer]``), NetworkManager keyfiles
  (``[wireguard-peer.<key>]``) and, as root, ``wg show all
  preshared-keys`` for the running interfaces.  Only the *presence* of a
  pre-shared key is recorded: the value is never stored or emitted.
* **OpenVPN**'s control channel is TLS.  ``tls-groups`` is passed to
  OpenSSL only when configured (src/openvpn/ssl.c); unset, the OpenSSL
  default groups apply, which on OpenSSL >= 3.5 put hybrid ML-KEM first
  unless the system policy or openssl.cnf says otherwise.  Hybrid ML-KEM
  groups are TLS 1.3 only, so ``tls-version-max 1.2`` rules them out.
  ``tls-crypt`` / ``tls-crypt-v2`` / ``tls-auth`` add a pre-shared
  symmetric key around the handshake and are reported as such.
"""

from __future__ import annotations

import argparse
import logging
import re
import shutil
from pathlib import Path
from typing import Any

from .. import _platform as _platform
from .. import registry as _registry
from . import config as _config
from . import packages as _packages

log = logging.getLogger("pqc-readiness")

MAX_CONFIG_BYTES = 1024 * 1024
MAX_CONFIGS = 200

WIREGUARD_DIRS = ("/etc/wireguard",)
NETWORKD_DIRS = (
    "/etc/systemd/network",
    "/run/systemd/network",
    "/usr/lib/systemd/network",
)
NM_DIRS = ("/etc/NetworkManager/system-connections",)
OPENVPN_GLOBS = (
    "/etc/openvpn/*.conf",
    "/etc/openvpn/server/*.conf",
    "/etc/openvpn/client/*.conf",
    "/etc/openvpn/*.ovpn",
    "/etc/openvpn/client/*.ovpn",
)


def _host_file(path: str) -> Path:
    resolved = _packages.resolve_under_prefix(path, _platform.HOST_PREFIX)
    return Path(_platform.HOST_PREFIX + resolved)


def _list_checked(
    directory: str, suffixes: tuple[str, ...]
) -> tuple[list[str], str | None]:
    """(config paths, error).  error is set when the directory exists but
    can't be listed: distributions ship /etc/wireguard 0700 and
    /etc/openvpn/{server,client} 0750, so an unprivileged scan sees nothing
    there, which is "unknown", not "not configured" (#113)."""
    try:
        d = _host_file(directory)
        if not d.is_dir():
            return [], None
        names = sorted(e.name for e in d.iterdir() if e.name.endswith(suffixes))
    except PermissionError as e:
        log.debug("tunnels: cannot list %s: %s", directory, e)
        return [], f"{e.strerror} (needs root)"
    except (OSError, _packages.RpmdbError) as e:
        log.debug("tunnels: cannot list %s: %s", directory, e)
        return [], None
    return [f"{directory}/{n}" for n in names[:MAX_CONFIGS]], None


def _list(directory: str, suffixes: tuple[str, ...]) -> list[str]:
    return _list_checked(directory, suffixes)[0]


def _read(path: str) -> tuple[str | None, str | None]:
    """(text, error) for a host config file."""
    try:
        p = _host_file(path)
        if p.stat().st_size > MAX_CONFIG_BYTES:
            return None, "larger than 1 MiB"
        return p.read_text(errors="replace"), None
    except PermissionError as e:
        return None, f"{e.strerror} (needs root)"
    except (OSError, _packages.RpmdbError) as e:
        return None, str(e)


# ---------------------------------------------------------------------------
# WireGuard
# ---------------------------------------------------------------------------


def _ini_sections(text: str) -> list[tuple[str, dict[str, str]]]:
    """[Section] key = value blocks in order (repeated sections kept)."""
    out: list[tuple[str, dict[str, str]]] = []
    cur: dict[str, str] | None = None
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(";"):
            continue
        m = re.match(r"^\[([^\]]+)\]$", line)
        if m:
            cur = {}
            out.append((m.group(1).strip(), cur))
            continue
        if cur is None or "=" not in line:
            continue
        k, v = line.split("=", 1)
        cur[k.strip().lower()] = v.strip()
    return out


def parse_wg_quick(text: str) -> list[dict[str, Any]]:
    """Peers of a wg-quick config: [Peer] blocks and PSK presence."""
    peers = []
    for name, kv in _ini_sections(text):
        if name.lower() == "peer":
            peers.append({"preshared_key": bool(kv.get("presharedkey"))})
    return peers


def parse_networkd_netdev(text: str) -> list[dict[str, Any]] | None:
    """Peers of a systemd-networkd WireGuard .netdev, or None when the
    file defines some other kind of netdev."""
    sections = _ini_sections(text)
    if not any(
        n.lower() == "netdev" and kv.get("kind", "").lower() == "wireguard"
        for n, kv in sections
    ):
        return None
    return [
        {"preshared_key": bool(kv.get("presharedkey") or kv.get("presharedkeyfile"))}
        for n, kv in sections
        if n.lower() == "wireguardpeer"
    ]


def parse_nm_keyfile(text: str) -> list[dict[str, Any]] | None:
    """Peers of a NetworkManager WireGuard keyfile, or None for other
    connection types.  A PSK held by an agent (preshared-key-flags with
    bit 0x1 'agent-owned' or 0x2 'not saved') counts as present."""
    sections = _ini_sections(text)
    if not any(
        n.lower() == "connection" and kv.get("type", "").lower() == "wireguard"
        for n, kv in sections
    ):
        return None
    peers = []
    for n, kv in sections:
        if not n.lower().startswith("wireguard-peer."):
            continue
        flags = kv.get("preshared-key-flags", "0")
        try:
            agent = int(flags) & 0x3 != 0
        except ValueError:
            agent = False
        peers.append({"preshared_key": bool(kv.get("preshared-key")) or agent})
    return peers


def parse_wg_show_psk(text: str) -> dict[str, dict[str, int]]:
    """`wg show all preshared-keys`: per interface {peers, with_psk}.  Each
    line is `iface<TAB>peer-pubkey<TAB>psk-or-(none)`; the psk column is
    only compared with '(none)', never kept."""
    out: dict[str, dict[str, int]] = {}
    for line in text.splitlines():
        cols = line.split("\t")
        if len(cols) != 3:
            continue
        iface = out.setdefault(cols[0], {"peers": 0, "with_psk": 0})
        iface["peers"] += 1
        if cols[2].strip() not in ("(none)", ""):
            iface["with_psk"] += 1
    return out


def _wg_running() -> dict[str, Any]:
    if _platform.HOST_PREFIX or _platform.OFFLINE_ROOT:
        return {
            "queried": False,
            "reason": "not a live host namespace (--host-mount / --root)",
        }
    if not shutil.which("wg"):
        return {"queried": False, "reason": "wg not on PATH"}
    rc, out = _platform._run(["wg", "show", "all", "preshared-keys"], timeout=5)
    if rc != 0:
        return {"queried": False, "reason": f"wg show failed (rc={rc}; needs root)"}
    return {"queried": True, "interfaces": parse_wg_show_psk(out)}


def scan_wireguard() -> dict[str, Any]:
    configs: list[dict[str, Any]] = []
    wg_paths: list[str] = []
    for d in WIREGUARD_DIRS:
        found, err = _list_checked(d, (".conf",))
        wg_paths += found
        if err:
            # WireGuard-specific directory: an unlistable one is an unread
            # WireGuard config set, reported as such (not as "no WireGuard").
            configs.append(
                {"path": d, "source": "wg-quick", "readable": False, "reason": err}
            )
    for path in wg_paths:
        text, err = _read(path)
        entry: dict[str, Any] = {"path": path, "source": "wg-quick"}
        if text is None:
            entry.update(readable=False, reason=err)
        else:
            entry.update(readable=True, peers=parse_wg_quick(text))
        configs.append(entry)
    for path in [p for d in NETWORKD_DIRS for p in _list(d, (".netdev",))]:
        text, err = _read(path)
        if text is None:
            configs.append(
                {
                    "path": path,
                    "source": "systemd-networkd",
                    "readable": False,
                    "reason": err,
                }
            )
            continue
        peers = parse_networkd_netdev(text)
        if peers is not None:
            configs.append(
                {
                    "path": path,
                    "source": "systemd-networkd",
                    "readable": True,
                    "peers": peers,
                }
            )
    for path in [p for d in NM_DIRS for p in _list(d, (".nmconnection",))]:
        text, err = _read(path)
        if text is None:
            configs.append(
                {
                    "path": path,
                    "source": "networkmanager",
                    "readable": False,
                    "reason": err,
                }
            )
            continue
        peers = parse_nm_keyfile(text)
        if peers is not None:
            configs.append(
                {
                    "path": path,
                    "source": "networkmanager",
                    "readable": True,
                    "peers": peers,
                }
            )
    # Unreadable NetworkManager / networkd files may not even be WireGuard;
    # only report them when nothing readable was found.
    readable = [c for c in configs if c.get("readable")]
    running = _wg_running()
    peer_count = sum(len(c.get("peers") or []) for c in readable)
    without = sum(
        1 for c in readable for p in c.get("peers") or [] if not p["preshared_key"]
    )
    if running.get("queried"):
        r_peers = sum(i["peers"] for i in running["interfaces"].values())
        r_without = sum(
            i["peers"] - i["with_psk"] for i in running["interfaces"].values()
        )
        if r_peers:
            peer_count, without = max(peer_count, r_peers), max(without, r_without)
    return {
        "configs": configs,
        "running": running,
        "summary": {
            "configured": bool(readable) or bool(running.get("interfaces")),
            "peers": peer_count,
            "peers_without_psk": without,
            "unreadable_configs": [
                c["path"]
                for c in configs
                if not c.get("readable") and c["source"] == "wg-quick"
            ],
        },
    }


# ---------------------------------------------------------------------------
# OpenVPN
# ---------------------------------------------------------------------------

_OPENVPN_KEYS = (
    "tls-groups",
    "ecdh-curve",
    "tls-version-min",
    "tls-version-max",
    "tls-crypt",
    "tls-crypt-v2",
    "tls-auth",
    "data-ciphers",
    "cipher",
    "secret",
)


def parse_openvpn_config(text: str) -> dict[str, Any]:
    """The directives that decide the control channel's key exchange.  Inline
    <tls-crypt> / <tls-auth> / <secret> blocks count as the directive;
    their contents are skipped."""
    found: dict[str, Any] = {}
    in_block: str | None = None
    for raw in text.splitlines():
        line = raw.strip()
        m = re.match(r"^<(/?)([\w-]+)>$", line)
        if m:
            name = m.group(2).lower()
            if m.group(1):
                in_block = None
            else:
                in_block = name
                if name in ("tls-crypt", "tls-crypt-v2", "tls-auth", "secret"):
                    found[name] = "inline"
            continue
        if in_block or not line or line[0] in "#;":
            continue
        parts = line.split()
        key = parts[0].lower()
        if key in _OPENVPN_KEYS:
            if key in ("tls-crypt", "tls-crypt-v2", "tls-auth", "secret"):
                found[key] = "file"
            else:
                found[key] = " ".join(parts[1:2])
        elif key in ("client", "server", "mode"):
            found.setdefault("role", "client" if key == "client" else "server")
    return found


def _openvpn_entry(path: str, d: dict[str, Any]) -> dict[str, Any]:
    groups = [g for g in (d.get("tls-groups") or "").split(":") if g]
    max_v = d.get("tls-version-max")
    tls13 = not (max_v and max_v.split()[0] in ("1.0", "1.1", "1.2"))
    if "secret" in d:
        # Static-key mode: a pre-shared symmetric key, no public-key exchange
        # to harvest, so PQC key exchange doesn't apply.
        kex = "static-key"
        pqc: bool | None = None
    elif not groups:
        kex = "openssl-default"
        pqc = None  # follows openssl.cnf / crypto policy; see `openssl`
    else:
        buckets = _config.classify_tls_groups(groups)
        kex = "configured"
        pqc = bool(buckets["hybrid"] or buckets["pure_pqc"])
    if not tls13 and kex != "static-key":
        pqc = False
    return {
        "path": path,
        "readable": True,
        "role": d.get("role"),
        "tls_groups": groups or None,
        "tls_version_min": d.get("tls-version-min"),
        "tls_version_max": max_v,
        "control_channel_psk": next(
            (k for k in ("tls-crypt-v2", "tls-crypt", "tls-auth") if k in d), None
        ),
        "static_key_mode": "secret" in d,
        "data_ciphers": d.get("data-ciphers") or d.get("cipher"),
        "key_exchange": kex,
        "pqc_key_exchange": pqc,
    }


OPENVPN_DIRS = ("/etc/openvpn", "/etc/openvpn/server", "/etc/openvpn/client")


def scan_openvpn() -> dict[str, Any]:
    base = Path(_platform.HOST_PREFIX or "/")
    paths: list[str] = []
    configs: list[dict[str, Any]] = []
    for d in OPENVPN_DIRS:
        _, err = _list_checked(d, (".conf", ".ovpn"))
        if err:
            configs.append({"path": d, "readable": False, "reason": err})
    for pattern in OPENVPN_GLOBS:
        for p in sorted(base.glob(pattern.lstrip("/"))):
            host = "/" + str(p.relative_to(base))
            if host not in paths:
                paths.append(host)
    for path in paths[:MAX_CONFIGS]:
        text, err = _read(path)
        if text is None:
            configs.append({"path": path, "readable": False, "reason": err})
            continue
        configs.append(_openvpn_entry(path, parse_openvpn_config(text)))
    version = None
    try:
        inv = _packages.query_rpm_named(("openvpn",))
        pkgs = inv.get("packages") or []
        version = pkgs[0].get("version") if pkgs else None
    except Exception as e:  # noqa: BLE001 - any package-db failure means "unknown"
        log.debug("tunnels: openvpn version lookup failed: %s", e)
    readable = [c for c in configs if c.get("readable")]
    return {
        "configs": configs,
        "version": version,
        "summary": {
            "configured": bool(configs),
            "without_pqc": [
                c["path"] for c in readable if c["pqc_key_exchange"] is False
            ],
            "follows_openssl_default": [
                c["path"] for c in readable if c["key_exchange"] == "openssl-default"
            ],
        },
    }


# ---------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------


def describe_wireguard(t: dict[str, Any]) -> str | None:
    """pqc-032 message, or None."""
    s = ((t.get("wireguard") or {}).get("summary")) or {}
    without, total = s.get("peers_without_psk") or 0, s.get("peers") or 0
    if not without:
        return None
    return (
        f"{without} of {total} WireGuard peers have no pre-shared key, so their "
        "traffic is protected only by the Curve25519 handshake "
        "(harvest-now-decrypt-later)"
    )


def describe_openvpn(t: dict[str, Any]) -> list[str]:
    """pqc-033 messages, one per OpenVPN config that can't do PQC."""
    out = []
    for c in ((t.get("openvpn") or {}).get("configs")) or []:
        if not c.get("readable") or c.get("pqc_key_exchange") is not False:
            continue
        max_v = c.get("tls_version_max")
        if max_v and max_v.split()[0] in ("1.0", "1.1", "1.2"):
            why = f"tls-version-max {max_v} (hybrid ML-KEM groups need TLS 1.3)"
        else:
            why = (
                "tls-groups "
                + ":".join(c.get("tls_groups") or [])
                + " has no ML-KEM group"
            )
        out.append(f"{c['path']}: {why}")
    return out


def scan_tunnels() -> dict[str, Any]:
    wg = scan_wireguard()
    ovpn = scan_openvpn()
    if (
        not wg["summary"]["configured"]
        and not ovpn["summary"]["configured"]
        and not wg["summary"]["unreadable_configs"]
    ):
        return {
            "available": False,
            "reason": "no WireGuard or OpenVPN configuration found",
        }
    out: dict[str, Any] = {"available": True, "wireguard": wg, "openvpn": ovpn}
    note = _platform.host_fs_unavailable_note(
        "Tunnel inventory",
        "/etc/wireguard, /etc/openvpn, systemd-networkd and NetworkManager configs",
    )
    if note:
        out.update(note)
    return out


@_registry.register_arguments(55)
def add_arguments(ap: argparse.ArgumentParser) -> None:
    ap.add_argument(
        "--scan-tunnels",
        action="store_true",
        help=(
            "inventory WireGuard peers' pre-shared keys (presence only) and "
            "OpenVPN TLS key-exchange settings"
        ),
    )
