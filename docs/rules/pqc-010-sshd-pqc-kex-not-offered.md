# pqc-010-sshd-pqc-kex-not-offered

**Default level:** warning (note when PQC is offered but not first)

## What it detects

The installed OpenSSH supports a post-quantum hybrid key exchange
(`ssh -Q kex` lists `mlkem768x25519-sha256`, `mlkem1024nistp384-sha384` or
`sntrup761x25519-sha512`), but sshd's effective `KexAlgorithms` offers none
of them (`sshd.pqc_offered` is false). SSH sessions to this host use only
classical key exchange. The host is capable but not configured.

At level **note**, a PQC method is offered but a classical one is preferred
(`sshd.pqc_first` is false), so clients that also support PQC still get it,
but only if they don't share the classical method sshd lists first.

## Why it matters

SSH session keys recorded today can be decrypted once a cryptographically
relevant quantum computer exists (harvest-now-decrypt-later). Offering a
hybrid key exchange removes that exposure for every client that supports it,
with a configuration change only.

- RFC 10042, ML-KEM hybrid key exchange in SSH (`mlkem768x25519-sha256`,
  `mlkem768nistp256-sha256`, `mlkem1024nistp384-sha384`), **final**
  (Informational): <https://www.rfc-editor.org/rfc/rfc10042>
- RFC 9941, `sntrup761x25519-sha512`, **final** (Informational):
  <https://www.rfc-editor.org/rfc/rfc9941>
- CNSA 2.0 accepts only ML-KEM-1024; of these, only
  `mlkem1024nistp384-sha384` is CNSA 2.0-eligible
  (`sshd.kex_references[*].cnsa_2_0`).

## Remediation

sshd takes `KexAlgorithms` from the first place that sets it. On every
measured distro that is the system crypto policy's OpenSSH server back-end
(`/etc/crypto-policies/back-ends/opensshserver.config`), reached through
`/etc/ssh/sshd_config.d/`.

- **RHEL 9 family:** measured on Rocky Linux 9.8, `DEFAULT` keeps sshd to
  classical key exchange (`curve25519-sha256` first). Run
  `update-crypto-policies --set DEFAULT:PQ` and restart `sshd`. The same
  change also addresses [pqc-008](pqc-008-crypto-policy-blocks-pqc.md).
- **RHEL 10 family and Fedora:** on Rocky Linux 10.2, AlmaLinux 10.2,
  CentOS Stream 10 and Fedora 44, `DEFAULT` already offers
  `mlkem768x25519-sha256` first. If the rule fires, look for a `NO-PQ`
  subpolicy or a local `KexAlgorithms` line that overrides the policy.
- **SUSE:** openSUSE Leap 16.0 offers `sntrup761x25519-sha512` first, then
  `mlkem768x25519-sha256`; no finding.
- **Without a crypto-policy framework (Debian / Ubuntu):** set
  `KexAlgorithms` in a file under `/etc/ssh/sshd_config.d/` that sorts
  before any other file setting it (the first value wins), listing a PQC
  hybrid first, then restart `sshd`.

Check the result with `sshd -T | grep ^kexalgorithms`.

## False positives and limitations

- Without root or under `--host-mount`, sshd's config files are parsed
  instead of running `sshd -T`. That reproduced `sshd -T` exactly on every
  measured distro, but options inside `Match` blocks are ignored, and a
  `KexAlgorithms` set relative to OpenSSH's built-in default (`+`, `-`,
  `^`) can't be resolved, so no finding is raised then.
- OpenSSH's PQC support is taken from the `ssh` client binary
  (`ssh_pqc`); the client and sshd ship in the same OpenSSH build on every
  measured distro.
- Host keys stay classical (no post-quantum host key type exists in
  OpenSSH yet); `sshd.host_keys` inventories them for later rotation.

## Related

[pqc-008](pqc-008-crypto-policy-blocks-pqc.md); `docs/json-output.md` (`sshd`, `ssh_pqc`).
