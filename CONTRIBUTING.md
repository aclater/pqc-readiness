# Contributing to pqc-readiness

## Third-party product references

This project does not name specific competing products in issues, pull
request descriptions, documentation, or code. Justifications anchor on
the underlying standards (NIST, IETF, OASIS, CycloneDX, SPDX, IANA), not
on what other tools do.

The reason is concrete: naming products creates trademark exposure,
invites disparagement disputes, and signals a competitive stance the
project has not taken. Standards bodies and their publications are
neutral; product names are not.

### Examples

Unacceptable:

> We should emit SARIF because Tool-X emits SARIF.

> Align field names with Tool-Y's schema where there is overlap.

> Borrow the methodology from Tool-Z.

Acceptable:

> SARIF (OASIS standard) is the standard exchange format for
> code-scanning and security findings. Most security tooling consumes
> it.

> Align field names with the established cryptographic inventory schemas
> (CycloneDX 1.6 cryptographic-assets, NIST IR 8547) where conventions
> exist.

> Use TLS handshake-level measurement as specified in RFC 8446.

### What this rule does *not* forbid

Standards-body publications and registries are fair game and should be
cited explicitly:

- NIST FIPS 203 / 204 / 205, NIST IR 8547, CNSA 2.0
- IETF drafts and RFCs (TLS hybrid design, composite signatures, etc.)
- OASIS SARIF
- CycloneDX, SPDX
- IANA registries

### Lint

The rule is enforced by `scripts/check-no-third-party-refs.sh` and the
`no-third-party-refs` GitHub Actions workflow. The forbidden-pattern
list is the single source of truth at `scripts/forbidden-refs.txt`; if a
new product name needs to be reserved, extend that file in a PR.

Run locally before committing:

    bash scripts/check-no-third-party-refs.sh

Exit codes: 0 clean, 1 forbidden references found, 2 configuration
error.
