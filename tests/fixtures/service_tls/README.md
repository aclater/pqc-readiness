# Service TLS configuration fixtures (#216)

Captured 2026-10-14 from official cloud images booted under QEMU/KVM (images
verified against the publishers' SHA-256 checksums), with the server packages
installed from each distribution's own repositories. The files are the
packaged defaults, copied before anything was changed.

| Directory | Image | Files |
| --- | --- | --- |
| `rocky9/` | Rocky Linux 9.8 GenericCloud | httpd.conf and ssl.conf (httpd 2.4.62), Postfix 3.5.25 main.cf / master.cf, Dovecot 2.3.16 dovecot.conf and conf.d, HAProxy 2.8 haproxy.cfg, nginx 1.20 nginx.conf |
| `ubuntu2604/` | Ubuntu 26.04 server cloudimg | PostgreSQL 18 postgresql.conf (ships `ssl = on` with the snakeoil certificate), Postfix 3.10.6 main.cf / master.cf, nginx 1.28 nginx.conf, HAProxy 3.2 haproxy.cfg |
| `leap16/` | openSUSE Leap 16.0 Minimal-VM | stunnel 5.74 stunnel.conf, Squid 6.12 squid.conf |
| `fedora44/` | Fedora Cloud Base 44 | Tomcat server.xml, Valkey 9.0 valkey.conf |

`vm-variants/` holds the exact configuration the validation runs added on
top of those defaults (test certificate under `/etc/pqct`). Each daemon was
then probed with
`openssl s_client -groups X25519MLKEM768:X25519:secp256r1` (with
`OPENSSL_CONF=/dev/null`, so the client offers ML-KEM on every host):

| Endpoint | Rocky 9.8 (DEFAULT policy) | Stream 10 | Fedora 44 | Ubuntu 26.04 | Leap 16.0 |
| --- | --- | --- | --- | --- | --- |
| nginx 8443, no group setting | X25519 | X25519MLKEM768 | X25519MLKEM768 | X25519MLKEM768 | (did not start) |
| nginx 8444, `ssl_ecdh_curve X25519:prime256v1` | X25519 | X25519 | X25519 | X25519 | (did not start) |
| nginx 8445, `ssl_ecdh_curve X25519MLKEM768:X25519` | **X25519MLKEM768** | X25519MLKEM768 | X25519MLKEM768 | X25519MLKEM768 | (did not start) |
| Apache 9443, no group setting | (port 80 taken) | (port 80 taken) | (port 80 taken) | (port 80 taken) | X25519MLKEM768 |
| Apache 9444, `SSLOpenSSLConfCmd Groups X25519:prime256v1` | | | | | X25519 |
| HAProxy 7443, no curves | X25519 | X25519MLKEM768 | X25519MLKEM768 | X25519MLKEM768 | X25519MLKEM768 |
| HAProxy 7444, `curves X25519:P-256` | X25519 | X25519 | X25519 | X25519 | X25519 |
| stunnel 6443, no curves | X25519 | X25519 (5.72, built with OpenSSL 3.2) | X25519MLKEM768 | X25519MLKEM768 | X25519 (5.74) |
| stunnel 6444, `curves = X25519:P-256` | X25519 | X25519 | X25519 | X25519 | X25519 |
| Squid 3443 https_port | X25519 | X25519MLKEM768 | X25519MLKEM768 | X25519MLKEM768 | X25519MLKEM768 |
| Postfix 25, packaged default | X25519 (3.5) | X25519 (3.8) | X25519 (3.10) | X25519 (3.10) | TLS 1.3, group shown as `<NULL>` (3.10) |
| Postfix 2525, `-o tls_eecdh_auto_curves=X25519,prime256v1` | X25519 | X25519 | X25519 | X25519 | TLS 1.3, group shown as `<NULL>` |
| Dovecot 993 | X25519 | X25519MLKEM768 | (2.4 config not started) | (2.4 config not started) | (2.4 config not started) |
| PostgreSQL 5432, packaged default | prime256v1 (13) | prime256v1 (16) | X25519 (18) | X25519 (18) | X25519 (18) |
| PostgreSQL 5432, `ssl_groups = 'X25519MLKEM768:X25519'` (18) | | | X25519MLKEM768 | X25519MLKEM768 | X25519MLKEM768 |
| MariaDB 3306 | X25519 (10.5) | X25519MLKEM768 (10.11) | X25519MLKEM768 (11.8) | | X25519MLKEM768 (11.8) |
| Redis / Valkey 6380 | X25519 (Redis 6.2) | X25519MLKEM768 (Valkey 8.1) | X25519MLKEM768 (Valkey 9.0) | X25519MLKEM768 (Redis 8.0) | |
| OpenLDAP 389 StartTLS | | | X25519MLKEM768 | X25519MLKEM768 | |
| Tomcat 8843 (JSSE, OpenJDK 25) | | | X25519MLKEM768 | | |

`postconf -d tls_eecdh_auto_curves` printed the classical list
`X25519 X448 prime256v1 secp...` on all five; PostgreSQL reported
`ssl_ecdh_curve=prime256v1` (13, 16) and `ssl_groups=X25519:prime256v1` (18).

`stunnel/*.bin` are byte excerpts holding stunnel's compiled
`DEFAULT_CURVES` / `DEFAULT_CURVES_FIPS` strings (src/options.c, stunnel
5.82): the OpenSSL 3.5 build string seen in the Ubuntu 26.04 binary
(`strings /usr/bin/stunnel4`), and the pre-3.5 string.
