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

## README is part of the feature

`README.md` is the discovery surface for this tool. A flag, top-level
JSON field, output format, or behavioural change that is not in the
README does not exist as far as a customer reading the repo is
concerned. PRs that add or change any of the following must update the
README in the same PR:

- Any new or renamed flag accepted by `pqc_readiness.py` (anything that
  appears in `./pqc_readiness.py --help`).
- Any new or renamed top-level key in the `--json`, `--ansible`,
  `--cbom`, `--sarif`, `--recommend`, or `--aggregate` outputs.
- Any new output format (a new `--<something>` that emits a distinct
  serialization).
- Any change to the `--help` text that affects the documented behaviour
  of an existing flag.
- Any change to exit codes.
- Any change that affects the `--ansible` output, the privilege /
  `become` model the script depends on, or the example playbooks under
  `deploy/ansible/` must keep [`docs/ansible.md`](docs/ansible.md) and
  the playbooks in sync in the same PR.

The README must, at minimum, name the flag or field and describe its
purpose in one sentence. Detailed reference may live in a linked file
under `docs/` (for example `docs/scope.md`,
`docs/recommendation-policies.md`, `docs/ansible.md`), but the README
must point at it.

Verifying coverage locally:

    ./pqc_readiness.py --help > /tmp/help.txt
    ./pqc_readiness.py --json > /tmp/sample.json
    # Each flag in /tmp/help.txt must appear in README.md.
    # Each top-level key in /tmp/sample.json must appear in README.md
    # or in a doc the README cross-references.

PR review will reject feature changes whose README delta is empty.
