# Review guide: pqc-readiness

pqc-readiness is a read-only post-quantum cryptography readiness scanner for
Linux hosts and offline filesystem trees. Review pull requests against the
project rules below, in addition to general correctness and security.
[CLAUDE.md](../CLAUDE.md) and [CONTRIBUTING.md](../CONTRIBUTING.md) hold the
full rules.

## What matters most

- **Read only.** The scanner must never change the host it scans. Flag any
  write, chmod, service restart, or database open that could create or modify
  files (for example a SQLite connection opened without read-only/immutable
  flags, or anything that writes a WAL or `-shm` file in a scanned tree).
- **Untrusted input.** Every file the scanner reads (configs, package
  databases, certificates, `/proc` entries, an offline `--root` tree) may be
  malformed or hostile. Flag unbounded reads, path traversal out of `--root`,
  symlinks followed out of the scanned tree, unchecked `struct.unpack`
  lengths, and parsing that can raise on bad input and abort the whole scan.
- **Python 3.9 floor, standard library only.** Flag syntax or stdlib APIs
  newer than 3.9 without a fallback (for example `match`, `X | Y` type unions
  evaluated at runtime, `tomllib`), and any new runtime dependency. numpy is
  the only optional import.
- **Findings for PQC failures.** When code can tell that software or a
  configuration can't do PQC, it should emit a SARIF/NDJSON finding, not only
  a JSON field.
- **Least privilege in deploy/.** OpenShift and Kubernetes manifests drop all
  capabilities and mount host paths read-only. Extra privilege belongs in an
  opt-in overlay with its justification documented next to it.

## Project conventions to check

- Feature PRs don't change `SCHEMA_VERSION`; JSON output changes are additive.
- A new or changed flag, top-level JSON key, output format or exit code
  updates README.md in the same PR. A new SARIF rule has a page under
  `docs/rules/` and an index row.
- Every bug fix comes with a regression test that would have caught it.
- Test fixtures come from real systems, with provenance in the fixture
  directory's README.
- Docs and code name no third-party products; tools are described by category
  and justifications cite standards (NIST, IETF, CycloneDX, SPDX, OASIS, IANA).
- Container images and manifests pin versions (never `:latest`), run as
  non-root, and prefer Red Hat UBI base images.

## Don't comment on

- Formatting, import order or type-annotation style: ruff and mypy --strict
  enforce these in CI.
- Use of SHA-1 or other weak algorithms where the code is *detecting* or
  *reporting* them, or where a standard mandates them (for example RFC 9580 v4
  key fingerprints). Detecting weak cryptography is the product.
