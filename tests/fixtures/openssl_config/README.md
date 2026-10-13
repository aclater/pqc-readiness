# OpenSSL configuration fixtures (#106)

Captured 2026-10-13.  Config files are verbatim; crypto-policies back-ends
are the dereferenced files from `tests/fixtures/crypto_policies/`.

| Fixture | Source | Notes |
| --- | --- | --- |
| `el9-default` | Rocky Linux 9.8 GenericCloud VM | `/etc/pki/tls/openssl.d` is empty on the host (`.keep` only preserves the directory) |
| `el10-default` | Rocky Linux 10.2 GenericCloud VM | as above |
| `fedora44-oqs` | `quay.io/fedora/fedora:44` container + liboqs 0.16.0 and oqs-provider 0.12.0 built from upstream tags, activated by `openssl.d/oqsprovider.conf`; `pkcs11-provider.conf` from the Fedora 44 cloud VM (all lines commented out, as shipped) | `openssl-output/` holds that container's `openssl list` output.  Fedora 44's `openssl` obsoletes `oqsprovider < 0.9.0`, so a source build was the only way to get a loaded third-party PQC provider |
| `leap16-default` | openSUSE Leap 16.0 Minimal VM | `/etc/ssl/openssl.cnf` |
| `debian13-stock` | `docker.io/library/debian:13` container, OpenSSL 3.5.7 | no `ssl_conf`: built-in defaults apply; `/usr/lib/ssl/openssl.cnf` is a symlink to this file on the host |
| `ubuntu2604-stock` | `docker.io/library/ubuntu:26.04` container, OpenSSL 3.5.5 | as Debian |
