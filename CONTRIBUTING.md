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

- Any new or renamed flag accepted by `pqc-readiness` (anything that
  appears in `pqc-readiness --help`).
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

    ./pqc-readiness --help > /tmp/help.txt
    ./pqc-readiness --json > /tmp/sample.json
    # Each flag in /tmp/help.txt must appear in README.md.
    # Each top-level key in /tmp/sample.json must appear in README.md
    # or in a doc the README cross-references.

PR review will reject feature changes whose README delta is empty.

## Code layout

The tool is the `pqc_readiness/` package (stdlib only, Python 3.9+),
shipped as the single-file zipapp `dist/pqc-readiness.pyz` (`make dist`).
Modules follow the lanes in the roadmap issue (#137), so parallel work
touches different files:

| Module | Owns |
|---|---|
| `detect/hardware.py` | CPU, memory, ISA tiers, accelerators, TPM, kernel crypto, kTLS |
| `detect/config.py` | FIPS mode and algorithm fence, OpenSSL capability and TLS groups |
| `detect/osinfo.py` | OS identity, install hints, kernel info |
| `detect/protocols.py` | OpenSSH, IPsec, NSS |
| `detect/certs.py` | trust-store certificates |
| `detect/runtime.py` | container vs host, host-filesystem availability |
| `detect/packages.py` | package inventory, rpm database readers |
| `verdict.py`, `bench.py`, `aggregate.py`, `recommendation.py` | scoring, benchmarks, fleet rollup, recommendations |
| `render/` | one module per output format (`text`, `cbom`, `sarif`, `spdx`, `json_report`) |
| `report.py`, `algorithms.py` | the `Report` dataclass, schema version, algorithm tables |
| `_platform.py` | `_run`, `host_path`, `HOST_PREFIX`: shared runtime primitives |
| `registry.py`, `cli.py` | flag / output-format registries, CLI entry point |

Rules that keep PRs from colliding:

- **Adding a flag:** decorate an `add_arguments(parser)` function in
  *your* module with `@registry.register_arguments(order)`; pick an
  unused slot (see `registry.py`). Never edit `cli.build_parser()`.
- **Adding an output format:** a new `render/<name>.py` that registers
  its flag and `registry.register_output(OutputFormat(...))`. Never edit
  `cli.render_output()`.
- **Calling another module:** go through the module
  (`_platform._run(...)`, `_hardware.detect_isa(...)`), as the existing
  code does, so each name has one binding.
- **Patching in tests:** patch the module that defines the name
  (`monkeypatch.setattr(pr.detect.certs, "TRUST_STORE_DIRS", ...)`). The
  package root only re-exports; `tests/conftest.py` rejects patches on it.
- **Golden fixture:** after an intended JSON change run `make golden`;
  resolve fixture conflicts by re-running it, not by hand-merging.
- **Schema version:** feature PRs add fields and their
  `docs/json-output.md` rows; the wave's release PR bumps
  `SCHEMA_VERSION` (#137).

Checks: `make lint typecheck test test-pyz check-readme`.
