# pqc-020-pqc-capable-not-configured

**Default level:** warning (note when it only restates pqc-008 / pqc-010)

## What it detects

The per-host deployment-gap verdict (`pqc_deployment_gap`, #107) found at
least one protocol or listening service in the `capable_not_configured`
state: the software can negotiate a post-quantum key exchange, but its
configuration keeps it classical.

- **TLS:** the system OpenSSL offers hybrid ML-KEM groups
  (`openssl.tls_groups`), but the crypto policy or OpenSSL's default groups
  leave them out.
- **SSH:** the installed OpenSSH supports a PQC key exchange, but sshd's
  effective `KexAlgorithms` offers none.
- **IPsec:** the installed strongSwan / Libreswan supports ML-KEM, but no
  configured connection proposes it (or, without configured connections,
  the policy's IKE setting excludes it).
- **Services** (with `--scan-services`): a listening process whose
  verdict differs from its host's, e.g. it bundles a PQC-capable library
  the system OpenSSL isn't, and the TLS default keeps PQC out. Services
  that merely follow the host default (`follows_host_default`) are not
  listed again: on Rocky Linux 9.8 and Fedora 44, `httpd` on port 80,
  `rpcbind` and `systemd-resolved` map a TLS library without speaking TLS
  on those ports. Go binaries are judged by their own crypto/tls default,
  which ignores the system policy.
- **Outbound clients** (with `--scan-processes`, #202): a client process
  group whose verdict differs from its host's. Measured on a Fedora 44
  VM (2026-10-13): a Go 1.26 client started with `GODEBUG=tlsmlkem=0` is
  listed; the same binary without it, and `openssl s_client`, follow the
  host and are not.

One result per host lists everything in that state
(`properties.gap:protocols`, `properties.gap:services`,
`properties.gap:clients`). It is a **note**
when the only gaps are the host-level TLS and SSH ones, which
[pqc-008](pqc-008-crypto-policy-blocks-pqc.md) and
[pqc-010](pqc-010-sshd-pqc-kex-not-offered.md) already report in detail,
and a **warning** when it adds IPsec, individual services or client
process groups.

## Why it matters

This is the cheapest gap a migration can close: no upgrade, no new
hardware, only configuration. Until it is closed, sessions on these
protocols remain exposed to harvest-now-decrypt-later even though the
software is ready.

- NIST IR 8547, *Transition to Post-Quantum Cryptography Standards*,
  **draft** (initial public draft):
  <https://csrc.nist.gov/pubs/ir/8547/ipd>
- RFC 10024, ML-KEM hybrid groups for TLS 1.3 (`X25519MLKEM768`,
  `SecP256r1MLKEM768`, `SecP384r1MLKEM1024`), **final**:
  <https://www.rfc-editor.org/rfc/rfc10024>
- RFC 10042, ML-KEM hybrid key exchange in SSH, **final**
  (Informational): <https://www.rfc-editor.org/rfc/rfc10042>
- RFC 9370, additional key exchanges in IKEv2, **final**; ML-KEM in IKEv2
  is still an IETF **draft** (see `ipsec_pqc.configured.standards`).

## Remediation

Work through `pqc_deployment_gap.gaps`; each entry names a protocol or
service.

- **TLS and SSH on the RHEL 9 family:** `update-crypto-policies --set
  DEFAULT:PQ`, then restart the affected services (sshd, web servers).
  Details per distro: [pqc-008](pqc-008-crypto-policy-blocks-pqc.md) for
  TLS, [pqc-010](pqc-010-sshd-pqc-kex-not-offered.md) for SSH.
- **TLS without a crypto-policy framework (Debian / Ubuntu):** OpenSSL 3.5
  prefers hybrid ML-KEM by default; look for a `Groups` / `Curves` line in
  `openssl.cnf` or an application config that overrides it.
- **IPsec:** add an ML-KEM additional key exchange to the IKE proposal of
  each connection (strongSwan `swanctl.conf` proposals, Libreswan `ike=`),
  keeping a classical proposal while peers migrate. Check
  `ipsec_pqc.configured.proposals` afterwards.
- **Services:** a service that sets its own TLS groups (web server,
  database, application config) needs the hybrid group added there; the
  system default does not reach it.

Re-run the scan; the item moves to `deployed`.

## False positives and limitations

- `configured` is the host default (crypto policy, OpenSSL default
  groups, sshd's effective config). An application that sets its own TLS
  groups may differ; supply endpoint observations to the aggregator
  (`--observations`) to see what clients actually negotiate.
- A service's `kind: tls` means the process maps a TLS library, not that
  the port speaks TLS (e.g. mDNS on `udp/5353` in a process that links
  one).
- When either judgement is unknown, the state is `unknown`, never
  `capable_not_configured`, so this rule does not fire on missing
  evidence.

## Related

[pqc-008](pqc-008-crypto-policy-blocks-pqc.md),
[pqc-010](pqc-010-sshd-pqc-kex-not-offered.md); `docs/json-output.md`
(`pqc_deployment_gap`).
