# pqc-021-service-config-blocks-pqc

**Default level:** warning

## What it detects

A server daemon's own TLS configuration keeps hybrid ML-KEM key exchange
out, although the host's TLS library can negotiate it
(`--scan-service-configs`, implied by `--scan-services`; works with
`--root`). One result per endpoint, from `service_tls_config`:

- **A group list without an ML-KEM group.** nginx `ssl_ecdh_curve` /
  `ssl_conf_command Groups`, Apache `SSLOpenSSLConfCmd Groups|Curves`,
  HAProxy `curves` / `ssl-default-bind-curves`, stunnel `curves`, Postfix
  `tls_eecdh_auto_curves`, Dovecot `ssl_curve_list`, PostgreSQL
  `ssl_groups`, OpenLDAP `TLSECName`, Squid `tls-dh=curve:`.
- **A classical list compiled into the service** and used when nothing is
  configured: Postfix before 3.11, stunnel built before its OpenSSL 3.5
  support (read from the binary), PostgreSQL 18's `ssl_groups` default
  `X25519:prime256v1`.
- **A service that can only use one elliptic curve:** PostgreSQL before
  18 (`ssl_ecdh_curve`, default `prime256v1`). ML-KEM needs PostgreSQL 18.
- **TLS 1.3 disabled** (protocol list or maximum below 1.3). Hybrid ML-KEM
  groups exist only in TLS 1.3.

A service's own group list overrides the system crypto policy in both
directions. Measured 2026-10-14 on booted cloud images, with a client
offering `X25519MLKEM768`:

| Service setting | Rocky 9.8 (DEFAULT policy) | CentOS Stream 10, Fedora 44, Ubuntu 26.04, Leap 16 |
| --- | --- | --- |
| nginx, no `ssl_ecdh_curve` | X25519 | X25519MLKEM768 |
| nginx `ssl_ecdh_curve X25519:prime256v1` | X25519 | X25519 |
| nginx `ssl_ecdh_curve X25519MLKEM768:X25519` | X25519MLKEM768 | X25519MLKEM768 |
| Postfix 3.5 to 3.10, packaged default | X25519 | X25519 |
| stunnel 5.71 / 5.72 / 5.74, no `curves` | X25519 | X25519 (Stream 10, Leap 16); X25519MLKEM768 (Fedora 44, Ubuntu 26.04) |
| PostgreSQL 13 / 16, packaged default | prime256v1 | prime256v1 (Stream 10) |
| PostgreSQL 18, packaged default | | X25519 |
| PostgreSQL 18 `ssl_groups = 'X25519MLKEM768:X25519'` | | X25519MLKEM768 |

Endpoints whose library is NSS (389 Directory Server) or the JDK (Tomcat
with JSSE) follow those libraries' defaults and are not judged here.

## Why it matters

Turning on PQC in the system crypto policy, or upgrading OpenSSL, does not
reach these services: they keep negotiating classical key exchange, so
their sessions stay exposed to harvest-now-decrypt-later. Fleet-wide
policy changes report success while these endpoints stay classical.

- RFC 10024, ML-KEM hybrid groups for TLS 1.3 (`X25519MLKEM768`,
  `SecP256r1MLKEM768`, `SecP384r1MLKEM1024`), **final**:
  <https://www.rfc-editor.org/rfc/rfc10024>
- NIST IR 8547, *Transition to Post-Quantum Cryptography Standards*,
  **draft** (initial public draft):
  <https://csrc.nist.gov/pubs/ir/8547/ipd>

## Remediation

Add a hybrid group in front of the service's list, or remove the setting
so the TLS library default applies (then check pqc-008 for the policy):

| Service | Setting |
| --- | --- |
| nginx | `ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;` |
| Apache httpd | `SSLOpenSSLConfCmd Groups X25519MLKEM768:X25519:prime256v1` |
| HAProxy | `curves X25519MLKEM768:X25519:P-256` on the bind line, or `ssl-default-bind-curves` in `global` |
| stunnel | `curves = X25519MLKEM768:X25519:P-256` (needed until the package is built with stunnel 5.76+ against OpenSSL 3.5) |
| Postfix | `tls_eecdh_auto_curves =` and `tls_ffdhe_auto_groups =` (both empty, Postfix 3.10+), which hands the choice to OpenSSL's configuration, or a `tls_eecdh_auto_curves` list starting with `X25519MLKEM768` |
| PostgreSQL 18+ | `ssl_groups = 'X25519MLKEM768:X25519:prime256v1'`, then `SELECT pg_reload_conf()` |
| PostgreSQL 13 to 17 | upgrade to PostgreSQL 18; `ssl_ecdh_curve` takes one elliptic curve only |
| Dovecot | `ssl_curve_list = X25519MLKEM768:X25519:P-256` or leave it empty |
| OpenLDAP | `olcTLSECName: X25519MLKEM768:X25519:prime256v1` |

Re-run the scan: the endpoint's `pqc_key_exchange` becomes `true` and, with
`--scan-services`, the service moves to `deployed` in
`pqc_deployment_gap.services`.

## False positives and limitations

- The rule judges the configuration file, not the running process: a
  service that hasn't been reloaded since its configuration changed still
  negotiates what it loaded.
- Built-in defaults come from the installed version (Postfix, PostgreSQL)
  or the binary (stunnel). Without a package database (some `--root`
  trees) the version is unknown and the endpoint is reported as following
  the library default.
- Per-application settings outside the parsed daemons (application
  servers' own TLS code, language runtimes) are not covered; supply
  endpoint observations (`--aggregate --observations`) to see what
  clients actually negotiate.
- PostgreSQL data directories are readable by `postgres` only; an
  unprivileged scan lists them under `unreadable`.

## Related

[pqc-008](pqc-008-crypto-policy-blocks-pqc.md),
[pqc-020](pqc-020-pqc-capable-not-configured.md),
[pqc-011](pqc-011-service-crypto-library-without-pqc.md);
`docs/json-output.md` (`service_tls_config`, `pqc_deployment_gap`).
