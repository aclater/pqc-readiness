# Package-signing key fixtures (#153)

Host trees (`<name>/root/…`) copied from real images on 2026-10-13. Only
public keys; the rpm databases are gzipped and decompressed into a
temporary host root by `tests/test_signing_keys.py`.

| Dir | Built from | How | Expected values |
| --- | --- | --- | --- |
| `el10-sqlite/` | `registry.access.redhat.com/ubi10/ubi` (RHEL 10.2, rpm 4.19.1.1) | `rpmkeys --root /tmp/r --import /etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release`; copied `rpmdb.sqlite`, the key file, and a test `.repo` (one enabled, one disabled, one enabled-but-missing `gpgkey`) | `expected-rpm-q.txt` = `rpm --root /tmp/r -q gpg-pubkey`. Includes Red Hat release key 4, a v6 ML-DSA-87+Ed448 key whose fingerprint was confirmed with `rpmkeys --list` under rpm 6.0.2 (Fedora 44). |
| `el8-bdb/` | `registry.access.redhat.com/ubi8/ubi` (rpm 4.14.3) | same, Berkeley DB `Packages` | `expected-rpm-q.txt` |
| `suse-ndb/` | `registry.opensuse.org/opensuse/leap:16.0` (rpm 4.20.1) | two keys from `/usr/lib/rpm/gnupg/keys/` imported; ndb `Packages.db` | `expected-rpm-q.txt` |
| `debian13/` | `docker.io/library/debian:13` | `/etc/apt/sources.list.d`, `/etc/apt/trusted.gpg.d`, `/usr/share/keyrings/debian-archive-keyring.pgp` | `expected-fprs.txt` = fingerprint, algorithm, bits from `gpg --show-keys --with-colons` |
| `arch/` | `docker.io/library/archlinux:latest` | `/usr/share/pacman/keyrings`; `archlinux.gpg` trimmed to the 5 keys in `archlinux-trusted` (original packets, re-armored) | `expected-fprs.txt` (gpg) |
| `alpine/` | `docker.io/library/alpine:3.22` | `/etc/apk/keys` | bit sizes from `openssl pkey -pubin -text` (asserted in the test) |
| `alpine-mldsa/` | generated | `openssl genpkey -algorithm ML-DSA-65 \| openssl pkey -pubout` (OpenSSL 3.5); the private key was never written | fingerprint = SHA-256 of the DER (asserted in the test) |
