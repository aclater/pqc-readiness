# OpenSSH build strings (#247)

Offline `--root` scans read the key exchange methods compiled into a tree's
OpenSSH build from its binaries (`pqc_readiness/detect/openssh_build.py`).
These fixtures are cut from real `sshd-session` binaries so the tests don't
have to commit 1 MiB+ executables.

Each `sshd-session.strings` holds every NUL-terminated string in the real
binary that contains `sha` or a comma and only lower-case name characters
(`[a-z0-9@.,-]`), in their original order, NUL-joined. That keeps the kex
name table and the default proposal lists, plus the cipher, MAC and
signature lists that the scanner must not mistake for kex lists.

Expected values come from the same booted image:

- `ssh-Q-kex.txt`: `ssh -Q kex`
- `sshd-T-defaults-kex.txt`: the `kexalgorithms` line of
  `sudo sshd -T -f /dev/null -o HostKey=<first host key>`, i.e. the build's
  compiled-in default (keyword lower-cased; OpenSSH 10.5 prints
  `KexAlgorithms`)

Captured 2026-10-14 by booting each cloud image (overlay disk, 2 vCPU,
cloud-init seed) and copying the binary out over SSH.

| Directory | Image (sha256 verified against the publisher) | Binary | OpenSSH |
| --- | --- | --- | --- |
| `rocky9` | Rocky-9-GenericCloud-Base-9.8-20260525.0.x86_64.qcow2 (`92c206cc…`) | `/usr/libexec/openssh/sshd-session` | 9.9p1 |
| `fedora44` | Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2 (`28680fe5…`) | `/usr/libexec/openssh/sshd-session` | 10.2p1 |
| `ubuntu2604` | ubuntu-26.04-server-cloudimg-amd64-release-20260927.img (`88006518…`) | `/usr/lib/openssh/sshd-session` | 10.2p1 Ubuntu-2ubuntu3.6 |
| `leap16` | Leap-16.0-Minimal-VM.x86_64-Cloud-Build18.75.qcow2 (`71930479…`) | `/usr/libexec/ssh/sshd-session` | 10.0 |
| `tumbleweed` | openSUSE-Tumbleweed-Minimal-VM.x86_64-1.0.0-Cloud-Snapshot20261011.qcow2 (`69eb7c39…`) | `/usr/libexec/ssh/sshd-session` | 10.5 |

The EL-family binaries (`rocky9`, `fedora44`) carry more than one kex list
(the default plus FIPS and ML-KEM-only lists), so the compiled-in default
can't be read from them; the others carry exactly one, equal to
`sshd-T-defaults-kex.txt`.

`../ubuntu2604/` holds that image's `/etc/ssh/sshd_config` and drop-in
(configuration only, no keys), its `sshd -T` and `ssh -Q kex`: the case
where nothing sets KexAlgorithms.
