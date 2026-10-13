# pqc-004-classical-only-trust-store

**Default level:** note

## What it detects

`--scan-trust-store` found at least one certificate, but none uses a PQC
signature (ML-DSA, SLH-DSA) or a composite or hybrid signature.
Certificates are classified from the OIDs in their DER encoding,
independent of the installed OpenSSL. If the scan was capped
(`--trust-store-max-certs`), the message says how many were inspected.

## Why it matters

A host only validates a pure-PQC or composite certificate chain if it
trusts a matching root. Trust-store rotation is slow and fleet-wide, so it
needs to be planned ahead of server-side certificate migration.

- RFC 9881, ML-DSA in X.509, **final**.
- draft-ietf-lamps-pq-composite-sigs, composite ML-DSA, **draft** (in the
  RFC Editor queue): <https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/>
- FIPS 204 (ML-DSA) / FIPS 205 (SLH-DSA), **final**.

## Remediation

This is informational today, because few public PQC roots exist yet.

- **RHEL family and Fedora:** add PQC or composite roots under
  `/etc/pki/ca-trust/source/anchors/` and run `update-ca-trust`.
- **Debian / Ubuntu:** put roots in `/usr/local/share/ca-certificates/` and
  run `update-ca-certificates`.
- **SUSE:** put roots in `/etc/pki/trust/anchors/` and run
  `update-ca-certificates`.

Private PKI operators should issue a PQC or composite root and distribute
it through configuration management before re-issuing leaf certificates.

## False positives and limitations

- The rule only fires when certificates were found. An empty or unreadable
  trust store produces no finding.
- A capped scan may have stopped before reaching a PQC certificate. Raise
  `--trust-store-max-certs` to confirm.

## Related

`--scan-crypto-material` reports the host's own leaf certificates and keys.
