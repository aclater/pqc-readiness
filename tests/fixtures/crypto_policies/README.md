# crypto-policies fixtures (#104)

Captured 2026-10-13 from official cloud images booted under QEMU/KVM
(images verified against publisher SHA-256 checksums):

| Fixture | Source image | State |
| --- | --- | --- |
| `el9-default` | Rocky Linux 9.8 GenericCloud | stock `DEFAULT` |
| `el9-pq` | Rocky Linux 9.8 GenericCloud | after `update-crypto-policies --set DEFAULT:PQ` |
| `el10-default` | Rocky Linux 10.2 GenericCloud | stock `DEFAULT` |
| `el10-test-pq` | Rocky Linux 10.2 GenericCloud | after `update-crypto-policies --set DEFAULT:TEST-PQ` |
| `fedora44-default` | Fedora Cloud Base Generic 44-1.7 | stock `DEFAULT` |
| `leap16-default` | openSUSE Leap 16.0 Minimal VM (Cloud) | stock `DEFAULT` (no `update-crypto-policies` installed) |

On the hosts, `etc/crypto-policies/back-ends/*.config` are absolute
symlinks into `/usr/share/crypto-policies/<POLICY>/`; here they are the
dereferenced file contents.  Only the back-ends the probe parses are kept.
Module directories hold empty `*.pmod` files named after the modules the
host shipped (the probe only lists names).  `SOURCE-os-release.txt` is the
host's `PRETTY_NAME`.
