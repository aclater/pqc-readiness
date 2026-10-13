# pqc-008-crypto-policy-blocks-pqc

**Default level:** warning

## What it detects

The installed OpenSSL offers hybrid or pure ML-KEM TLS 1.3 groups, but the
active system-wide crypto policy lists none of them in its OpenSSL back-end
(`crypto_policy.pqc_enabled.tls_key_exchange` is false). Applications that
use the system default never negotiate PQC. The host is capable but not
configured.

## Why it matters

This is the cheapest PQC gain available, because it needs a configuration
change, not new software or hardware. It covers harvest-now-decrypt-later
exposure on TLS key exchange.

- RFC 10024, hybrid ML-KEM groups for TLS 1.3 (X25519MLKEM768 =
  0x11EC, etc.), **final** (Proposed Standard): <https://www.rfc-editor.org/rfc/rfc10024>
- draft-ietf-tls-mlkem, pure ML-KEM groups, **draft** (in the RFC Editor
  queue): <https://datatracker.ietf.org/doc/draft-ietf-tls-mlkem/>
- CNSA 2.0 accepts only ML-KEM-1024. X25519MLKEM768 does not satisfy it;
  SecP384r1MLKEM1024 does (NSA CNSA 2.0 FAQ v2.1, **final**).

## Remediation

- **RHEL 9 family:** measured on Rocky Linux 9.8 and AlmaLinux 9.8 cloud
  images, `DEFAULT` enables no PQC. Run
  `update-crypto-policies --set DEFAULT:PQ` and restart services (or
  reboot). On the same images the finding cleared afterwards.
- **RHEL 10 family and Fedora:** on Rocky Linux 10.2 and Fedora 44,
  `DEFAULT` already enables PQC. RHEL 10.0 needs the
  `crypto-policies-pq-preview` package and the `TEST-PQ` subpolicy. Check
  that no `NO-PQ` subpolicy is set (`update-crypto-policies --show`).
- **SUSE:** openSUSE Leap 16.0's `DEFAULT` enables PQC. If the rule fires,
  check the active policy and its subpolicies the same way.
- **Debian / Ubuntu:** there is no `crypto-policies` framework, so the rule
  doesn't fire. Ubuntu 26.04's own framework (`crypto-config`) isn't read
  yet (issue #170).

With Ansible, the RHEL `crypto_policies` system role sets the policy
fleet-wide.

## False positives and limitations

- Services with their own TLS configuration (explicit `Groups` /
  `Curves` settings) may enable or disable PQC independently of the system
  policy. `openssl.config` and `--scan-services` help find them.
- The policy change takes effect when services restart.

## Related

[pqc-001](pqc-001-openssl-pre-3.5.md); `docs/json-output.md` (`crypto_policy`, `openssl.config`).
