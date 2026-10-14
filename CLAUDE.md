# CLAUDE.md: pqc-readiness

Instructions for coding agents working in this repository. Read
[README.md](README.md), [CONTRIBUTING.md](CONTRIBUTING.md) and
[docs/testing.md](docs/testing.md) before changing anything.

## What this project is

A host-level post-quantum cryptography readiness scanner for Linux. It reads a
host (or an offline filesystem tree) and reports PQC capability, configuration,
the gap between them, findings for anything that will fail at PQC, and
performance. Outputs: text, markdown, JSON, CycloneDX CBOM, SPDX, SBOM, SARIF,
OCSF NDJSON, Prometheus, Ansible facts.

### Product principles

- **Stay on Python, standard library only.** No runtime dependencies (numpy is
  optional). A rewrite in another language has been considered and rejected;
  performance comes from reading data directly (e.g. the in-process rpm
  database readers), not from changing language.
- **Python 3.9 is the floor** (EL8 AppStream `python39`). Don't use language or
  stdlib features newer than 3.9 without a fallback.
- **Read only.** The scanner never changes the host. It writes a file only when
  asked (`--save`, `--output`).
- **Flag anything that will fail at PQC.** If a detection can tell that software
  or configuration can't do PQC, emit a SARIF/NDJSON finding, not just a JSON
  field. Defaults stay least-privilege; extra visibility comes through opt-in
  flags and opt-in deployment overlays.
- **Name no third-party products** in code, docs, issues or PRs. Describe tools
  by category and anchor justifications on standards (NIST, IETF, CycloneDX,
  SPDX, OASIS, IANA). Enforced by `scripts/check-no-third-party-refs.sh` with
  `scripts/forbidden-refs.txt`; see CONTRIBUTING.md for what is allowed.

## Layout

| Path | What |
| --- | --- |
| `pqc_readiness/` | The package. `detect/` probes, `render/` output formats, `cli.py`, `report.py` (holds `SCHEMA_VERSION`), `gap.py`, `aggregate.py`, `observations.py`. CONTRIBUTING.md has the module table. |
| `pqc-readiness` | Launcher shell script: picks Python 3.9+, runs the zipapp or the package |
| `scripts/build_zipapp.py` | Builds `dist/pqc-readiness.pyz`, the single-file release artifact |
| `tests/`, `tests/fixtures/` | pytest suite; fixtures captured from real hosts, each directory's README records provenance |
| `docs/` | Reference docs; `docs/rules/` has one page per SARIF rule |
| `deploy/` | Quadlet, OpenShift DaemonSet and overlays, Ansible playbooks, integration samples |
| `Containerfile.{ubi10,ubi8,debian}` | Container images (not published; see #212) |

## Checks to run before every PR

Use the dev venv in the main clone (`~/git/pqc-readiness/.venv`) if the clone
you're in has none. `make` may not be installed; the plain commands are:

```bash
python -m pytest tests/ -q
ruff check pqc_readiness/ scripts/ tests/
mypy --strict pqc_readiness
pre-commit run --all-files
bash scripts/check-readme-flags.sh          # every --help flag is in README.md
bash scripts/check-no-third-party-refs.sh
python scripts/build_zipapp.py && PQC_READINESS_PYZ=dist/pqc-readiness.pyz python -m pytest tests/ -q
```

The golden report (`tests/fixtures/golden/stubbed-host-report.json`) fails the
suite on any JSON output change. Regenerate it only for an intended change:

```bash
PQC_WRITE_GOLDEN=1 python -m pytest tests/test_main_decompose.py -q -k golden
```

Probe changes must also be run on booted cloud images before merging (the VM
matrix in [docs/testing.md](docs/testing.md#booted-vm-matrix)). Unit tests
against fixtures are not enough for detection logic.

## Change rules

- **Schema version.** Feature PRs never bump `SCHEMA_VERSION`; only release
  PRs do, and JSON changes must be additive within a release.
- **Docs ship with the feature.** A new or changed flag, top-level JSON key,
  output format or exit code updates README.md in the same PR (README names it
  in one line; detail goes in `docs/`). A new SARIF rule needs its page under
  `docs/rules/` and an index row; tests enforce both.
- **Release notes** go in `CHANGELOG.md`. The README's *Latest release* section
  holds only a short summary of the newest release.
- **Fixtures come from real systems.** Capture from verified vendor images and
  record the source in the fixture directory's README. Expected values should
  come from the distribution's own tools (`rpm -qa`, `sshd -T`, ...).
- **Every bug fix includes a regression test** that would have caught it.
- **Shared files are append-only** when several lanes work in parallel (README
  sections, CHANGELOG, docs indexes, `forbidden-refs.txt`): add, don't reorder.
- **Waves and lanes.** Parallel work follows the roadmap in issue #137: one
  agent per module lane (`lane:` labels), no two agents in the same lane.

## Versions, images and security

- **Verify every version from a primary source** before using it (registry,
  PyPI, GitHub releases API: `gh api repos/<owner>/<repo>/releases/latest`).
  Don't use versions from memory. If you can't verify one, say so.
- **Prefer Red Hat UBI** base images (`registry.access.redhat.com/ubi10`).
  Pin tags; never `:latest` in Containerfiles, quadlets or manifests.
- **Containers run as non-root** (UID 1001) with a HEALTHCHECK; `ubi*-minimal`
  has no `curl`, so health checks use Python.
- **OpenShift manifests stay least-privilege:** drop all capabilities, read-only
  host mounts, no privileged pods. Anything more is an opt-in overlay with its
  justification documented.
- Never commit secrets; `detect-secrets` runs in pre-commit and CI.
- Prefer Podman and quadlets; prefer rpm/dnf packages over pip on Fedora.

## Workflow

- **Clones.** The permanent clone is `~/git/pqc-readiness`. Do PR work in
  `~/git-work/<issue>-<description>/` and delete it after the PR merges.
- **Every task starts with a GitHub issue.** Check for an existing one first.
  Claim it with a comment ("🤖 Claude Code picking up this issue.") and log
  plan, decisions, obstacles and test results there. All agents use the same
  GitHub account, so the comment, not the assignee, marks ownership; skip an
  issue another agent has claimed unless it is marked blocked or abandoned.
- **Labels:** `priority: …`, `type: …`, `lane: …`, `effort: S|M|L`,
  `agent: …`.
- **Commits** reference the issue (`fix(detect): … (fixes #N)`), explain why,
  and make one logical change each. Git identity is per repo: Adam Clater
  <aclater@gmail.com>. Commits end with the `Co-Authored-By:` trailer for the
  model in use.
- **PRs** say `Closes #N` or `Refs #N`. Wait for CI to finish; merge only when
  every check passes. Never force-push a shared branch.
- **Work autonomously.** Don't ask for confirmation: decide, log the decision
  in the issue, continue. Fix failing tests and CI yourself. File new bugs as
  issues and keep going. Stop only when an action risks irreversible data loss,
  and explain why in the issue.
- **Host hygiene.** Don't run `podman … prune` or delete anything outside your
  own work directories.
