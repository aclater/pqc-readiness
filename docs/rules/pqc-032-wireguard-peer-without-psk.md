# pqc-032-wireguard-peer-without-psk

**Default level:** warning

## What it detects

`--scan-tunnels` found WireGuard peers configured without a pre-shared key.
Peers are read from wg-quick configs (`/etc/wireguard/*.conf`, root-only),
systemd-networkd `.netdev` files with `Kind=wireguard`, NetworkManager
WireGuard keyfiles and, as root on a live host, `wg show all preshared-keys`.
Only the presence of a key is recorded; key values are never stored or
emitted.

## Why it matters

WireGuard's handshake is Curve25519 (Noise_IK). Traffic recorded today can
be decrypted once a cryptographically relevant quantum computer can break
that exchange (harvest-now-decrypt-later). WireGuard's only post-quantum
mitigation is the optional per-peer pre-shared key, which is mixed into the
key derivation:

- WireGuard protocol documentation: "If an additional layer of
  symmetric-key crypto is required (for, say, post-quantum resistance),
  WireGuard also supports an optional pre-shared key that is mixed into the
  public key cryptography." <https://www.wireguard.com/protocol/>

## Remediation

- Generate a pre-shared key per peer pair (`wg genpsk`), distribute it over
  an existing secure channel, and set `PresharedKey =` in both peers'
  `[Peer]` sections (wg-quick), `PresharedKey=` / `PresharedKeyFile=` in
  `[WireGuardPeer]` (systemd-networkd), or `preshared-key` in the
  NetworkManager keyfile (`nmcli connection modify`).
- A static PSK protects against a future quantum attacker only while it
  stays secret; rotate it, or use a tool that refreshes it with a
  post-quantum key exchange.

## False positives and limitations

- wg-quick configs are readable only by root; without root they are listed
  as unreadable and their peers aren't counted.
- Under `--host-mount` / `--root` the running-interface query is skipped
  and only configuration files are read.

## Related

[pqc-033](pqc-033-openvpn-classical-key-exchange.md),
[pqc-016](pqc-016-ipsec-classical-only-ike.md).
