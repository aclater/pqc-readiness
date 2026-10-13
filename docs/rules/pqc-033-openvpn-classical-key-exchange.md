# pqc-033-openvpn-classical-key-exchange

**Default level:** warning

## What it detects

`--scan-tunnels` read an OpenVPN configuration under `/etc/openvpn` whose
control-channel key exchange can't be post-quantum:

- `tls-groups` is set and lists no ML-KEM group (hybrid or pure), or
- `tls-version-max` is 1.2 or lower: hybrid ML-KEM TLS groups exist only in
  TLS 1.3.

Configurations that leave `tls-groups` unset inherit OpenSSL's default
groups (`key_exchange: openssl-default`); those are judged by the OpenSSL
and crypto-policy checks ([pqc-001](pqc-001-openssl-pre-3.5.md),
[pqc-008](pqc-008-crypto-policy-blocks-pqc.md)), not by this rule.
Static-key mode (`secret`) has no public-key exchange and is not flagged.

## Why it matters

OpenVPN's control channel is TLS, and the session keys for the tunnel come
from it. A classical-only key exchange can be recorded now and broken later
(harvest-now-decrypt-later).

- TLS 1.3 hybrid ML-KEM groups (X25519MLKEM768 and others):
  RFC 10024, **final**.
- `tls-crypt` / `tls-crypt-v2` / `tls-auth` wrap the handshake in a
  pre-shared symmetric key and are reported in `control_channel_psk`; they
  add protection but don't replace a post-quantum key exchange.

## Remediation

- Remove `tls-groups` to follow the system defaults on OpenSSL 3.5 or later
  (hybrid ML-KEM first), or list an ML-KEM group first, e.g.
  `tls-groups X25519MLKEM768:X25519`.
- Remove `tls-version-max 1.2`, or raise it to 1.3.
- Both ends need OpenSSL 3.5 or later (or a PQC-capable provider) for the
  hybrid group to be negotiated.

## False positives and limitations

- Only `/etc/openvpn` configs are read; configs elsewhere, or passed on the
  command line, are not seen.
- `tls-groups` set through a `config` include isn't followed.

## Related

[pqc-032](pqc-032-wireguard-peer-without-psk.md),
[pqc-008](pqc-008-crypto-policy-blocks-pqc.md).
