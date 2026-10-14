# Debian 13 dpkg tree (#257, #243)

A host root with a real `dpkg` status database, for offline `--root` scans.

| File | Source |
| --- | --- |
| `var/lib/dpkg/status` | `/var/lib/dpkg/status` from `docker.io/library/debian:13` at `sha256:913f6706df59a68922d1dd08f78c2476560a8d367897200a6005b00e5f67c2d5` (captured 2026-10-14), cut to 7 whole stanzas, unedited |
| `etc/os-release` | `/etc/os-release` from the same image |
| `expected-dpkg-query.txt` | `dpkg-query -W -f '${Package} ${Version} ${Architecture}\n'` in the same image, filtered to those 7 packages |

The stanzas kept are the crypto libraries in the base image (`libssl3t64`,
`openssl-provider-legacy`, `libnettle8t64`, `libhogweed6t64`) plus packages
whose versions exercise purl encoding: `+` (`bash 5.2.37-2+b10`,
`base-files 13.8+deb13u7`) and an epoch with `+` (`bsdutils
1:2.41.5-0+deb13u1`).
