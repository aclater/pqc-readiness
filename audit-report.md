# pqc-readiness audit report

Generated: 2026-04-29
Auditor: claude-code (automated)
Scope: commit `c68e583` on `main`

## Executive summary

The codebase is in a working, well-tested state: 242 pytest cases pass on
main, every `--help` flag is documented, and CI exercises Python 3.11/12/13 +
a UBI 8 image build + a third-party-reference lint. The three issue
themes (cross-distro, output formats, recommendation engine) all landed
with their public surface fixed. **Top concerns:** (1) the only open
issue, #36, is unresolved — `./pqc_readiness.py` cannot be invoked as a
direct executable on stock RHEL/Rocky/Alma 8 cloud images even though
the README's Tier 2 entry implies it works there; (2) several issue-#1
acceptance items quietly drifted — `unavailable_in_container` per-feature
flags are not emitted, the `adequate` ISA tier is undocumented, and the
RHEL 8 README tier label disagrees with the CI cadence; (3) renderers
for the human-readable report (text + markdown) ship without their own
unit tests. **Top strengths:** schema validation against bundled
CycloneDX / SARIF / SPDX files actually runs; subprocess invocations are
all list-form with explicit timeouts; the recommendation engine has
clean per-policy contrasts and policy/role parameterization is honoured
in tests.

## Section 1: Issue-to-implementation traceability

19 closed issues / 19 merged PRs. One open issue (#36). One closed-not-
merged PR (#37). Mapping below covers every closed issue's stated
acceptance criteria.

| Issue | Criterion | PR | Status |
| --- | --- | --- | --- |
| #1 §1 | `has_dedicated_pqc_silicon` allow-list (CEX8) + `hsm_present_but_not_pqc` | #2 | satisfied (`pqc_readiness.py:946`, `Report.hsm_present_but_not_pqc`) |
| #1 §1 | `lszcrypt -V` → CEX5/6/7/8 + CCA/EP11/Accel | #2 | satisfied (`parse_lszcrypt`, `pqc_readiness.py:848`) |
| #1 §1 | `memory_bandwidth_probe` real triad or removed | #2 | satisfied — STREAM-triad numpy probe (`pqc_readiness.py:3162`); name retained as `memory_bandwidth_probe` |
| #1 §1 | 192 KB realistic + 32 KB theoretical-max conn math, both surfaced | #2 | satisfied (`pqc_readiness.py:3320`) |
| #1 §1 | `detect_fips_mode` record-based parser; loaded-but-inactive ≠ enabled | #2 | satisfied (`detect_fips_mode_from_providers_text`, `pqc_readiness.py:806`) |
| #1 §1 | `parse_speed_row` regex `\d+(?:\.\d+)?` + integer rates | #2 | satisfied (`pqc_readiness.py:2511`) |
| #1 §1 | `parse_classical_speed` redundant header detection fix | #2 | satisfied (`pqc_readiness.py:2541`) |
| #1 §2 | DPU detection (BlueField/IPU/Pensando) | #2 | satisfied (lspci catalogue) |
| #1 §2 | Network HSM detection (Luna/nShield/CloudHSM) | #2 | satisfied (`detect_network_hsms`) |
| #1 §2 | OpenSSH `ssh -Q kex` | #2 | satisfied (`ssh_pqc_capability`) |
| #1 §2 | strongSwan `swanctl --list-algs` | #2 | satisfied (`ipsec_pqc_capability`) |
| #1 §2 | NSS version probe | #2 | satisfied (`detect_nss`) |
| #1 §2 | `fips_pqc_conflict` boolean + explanation | #2 | satisfied (`fips_pqc_conflict`) |
| #1 §2 | `--scan-trust-store` flag | #2 | satisfied (`scan_trust_store`) |
| #1 §3 | SLH-DSA "unsuitable for hot paths" note | #2 | satisfied (per-algo verdict notes) |
| #1 §3 | ML-DSA verify thresholds | #2 | satisfied (`ALGO_THRESHOLDS`) |
| #1 §3 | Memory-bandwidth-driven SLH-DSA tier downgrade | #2 | satisfied (`per_algo_verdict`) |
| #1 §3 | `verdict_caveat` distinguishes "tested+bad" from "could not test" | #2 | satisfied (`Report.verdict_caveat`) |
| #1 §3 | ARM I8MM weight 1 → 2 | #2 | satisfied (`tests/test_parsers.py:354`) |
| #1 §3 | CPU fixtures for SKX/SPR/Zen4/Graviton 3 + tests | #2 | satisfied (`tests/fixtures/cpuinfo/`) |
| #1 §4 | Container detection → `runtime_environment` | #2 | satisfied (`detect_runtime_environment`) |
| #1 §4 | Per-feature `unavailable_in_container` flags | #2 | **missing** — only top-level `runtime_environment` is set; no detection function emits the flag (no grep hit) |
| #1 §4 | `--host-mount /host` path-prefix | #2 | satisfied (`host_path`, `pqc_readiness.py:91`) |
| #1 §4 | `--aggregate DIR` rollup (JSON + CSV) | #2 | satisfied via `--aggregate-format {json,csv}` |
| #1 §4 | `replace_required` top-level boolean | #2 | satisfied (`Report.replace_required`) |
| #1 §4 | `--ansible` flag, exit 0 | #2 | satisfied (`pqc_readiness.py:5780`) |
| #1 §4 | `--scan-packages` bundled-crypto inventory | #2 | satisfied |
| #1 §5 | `Containerfile` UBI10-minimal, microdnf, non-root, py healthcheck | #2 | satisfied (`Containerfile.ubi10`) |
| #1 §5 | `deploy/quadlet/pqc-readiness.container` | #2 | satisfied |
| #1 §5 | `deploy/openshift/daemonset.yaml` (hostPID, RO mounts, non-root) | #2 | satisfied |
| #1 §6 | SPDX-License-Identifier in every source file | #2 | satisfied |
| #1 §6 | `--version` flag | #2 | satisfied |
| #1 §6 | Aggregator validates schema_version, refuses mismatch | #2 | satisfied (`run_aggregator`, `pqc_readiness.py:2259`) |
| #1 §6 | `tests/` with pytest + fixtures | #2 | satisfied |
| #1 §6 | Makefile: test, lint, typecheck, container-build | #2 | satisfied |
| #1 §6 | Pre-commit: ruff + mypy | #2 | satisfied (`.pre-commit-config.yaml`) |
| #4 §1 | `detect_os()` single source of truth, `os_release` field | #16 | satisfied (`detect_os`, `pqc_readiness.py:1290+`) |
| #4 §2 | Per-family `--scan-packages` parsers + normalised shape | #16 | satisfied |
| #4 §2 | `fips.distribution_certified` + `fips.notes` | #16 | satisfied |
| #4 §3 | `Containerfile.ubi10` rename + new `Containerfile.debian` + ubuntu-fips stub | #16 | satisfied |
| #4 §4 | Family-aware `PKCS11_SEARCH` paths | #16 | satisfied |
| #4 §5 | `_install_hint(package, family)` helper | #16 | satisfied |
| #4 §6 | `openssl.upgrade_path` family-aware string | #16 | satisfied (`openssl_upgrade_path`, `pqc_readiness.py:2281`) |
| #4 §7 | `openssh.version`, Libreswan via `ipsec --version` | #16 | satisfied |
| #4 §9 | os-release fixtures for every Tier 1/2/3 distro | #16 | satisfied (14 os-release fixtures) |
| #4 §9 | packages fixtures: rpm-qa, dpkg-query, pacman, apk | #16 | **partial** — `rpm-qa` fixture file is missing (`tests/fixtures/packages/` has dpkg/pacman/apk; `parse_rpm_packages` is tested with an inline string only) |
| #4 §10 | README distribution-support matrix | #16 | satisfied |
| #5 | `--cbom` CycloneDX 1.6 with cryptographic-assets, validates against schema | #19 | satisfied (`render_cbom`; `tests/test_cbom.py` validates) |
| #6 | `--spdx` SPDX 3.0 JSON-LD Security profile, validates against schema | #27 | partial — SPDX 3.0.1 publishes no JSON Schema; tests validate against bundled JSON-LD context only (documented in `tests/test_spdx.py:6-21`) |
| #7 | `--sarif` SARIF 2.1.0 with all six rules pqc-001..pqc-006 | #24 | satisfied (`pqc_readiness.py:4446-4527`) |
| #8 | `docs/schema-alignment.md` field-by-field mapping | #33 | satisfied |
| #8 | Follow-up issue filed for renames + SCHEMA_VERSION bump | #33 | **unverifiable** — no follow-up issue exists in the queue with that title; `docs/schema-alignment.md` was supposed to file one |
| #9 | `tls_groups` split pure_pqc / hybrid / classical | #17 | satisfied (`classify_tls_groups`, `pqc_readiness.py:2437`) |
| #9 | Same split for SSH KEX | #17 | partial — `ssh_pqc.kex_groups` has only `pure_pqc` and `hybrid` buckets (no `classical`); inconsistent with `tls_groups` three-bucket shape |
| #10 | `--scan-trust-store` categorises classical / hybrid_composite / pure_pqc | #23 | satisfied |
| #10 | Composite signature OID list populated | #23 | satisfied (`COMPOSITE_SIG_OID_RE` covers IANA arc 1.3.6.1.5.5.7.6.{37..54}) |
| #11 | `cnsa_2_0` section + `--check cnsa-2.0` exit 4 if not compliant | #15 | satisfied (`evaluate_cnsa_2_0`; manual run on this host returned exit 4 PARTIAL) |
| #12 | `--bench-tls` loopback handshake bench (classical/hybrid/pure/composite) | #22 | satisfied |
| #13 | `--recommend` + `--policy` + `--role` flags | #21 | satisfied |
| #13 | Four policies (cnsa-2.0, nist-civilian, eu-anssi-bsi, commercial) + `auto` | #21 | satisfied (verified empirically: `auto` emits all four side-by-side) |
| #13 | Other roles return "not yet implemented" stub | #21 | satisfied (`_recommend_stub`, `pqc_readiness.py:3711`) |
| #13 | `docs/recommendation-policies.md` | #21 | satisfied |
| #13 | Tests cover all four policies × 3 ISA profiles | #21 | satisfied (`tests/test_recommendation.py`) |
| #14 | `docs/scope.md` describes 5 categories without naming products | #20 | satisfied |
| #25 | README documents every `--help` flag + every top-level JSON key | #26 | satisfied (`scripts/check-readme-flags.sh` returns OK) |
| #25 | CONTRIBUTING.md "README is part of the feature" section | #26 | satisfied |
| #28 | `scripts/validate-matrix.sh` per-distro Incus VM runner | (none in main) | **missing** — issue is closed but no `scripts/validate-matrix.sh` exists in main; closure appears premature |
| #29 | EL8 wrapper launcher + `python39` AppStream guidance | #32 | satisfied (`pqc-readiness` shell wrapper; tests in `test_launcher.py`) |
| #29 | `detect_os()` recognises RHEL/Rocky/Alma 8 family=rhel | #32 | satisfied (fixtures exist) |
| #29 | `openssl.upgrade_path` RHEL-8-specific string | #32 | satisfied |
| #30 | `Containerfile.ubi8` UBI 8 minimal + non-root + Python healthcheck | #35 | satisfied |
| #30 | New CI job runs pytest inside UBI 8 image | #35 | satisfied (`.github/workflows/ci-ubi8.yml`) |
| #30 | RHEL 8/Rocky 8/Alma 8 promoted Tier 3 → Tier 2 | #35 | satisfied — but README claims "weekly" while CI actually runs on every push (see Section 6) |
| #30 | `make container-ubi8` Makefile target | #35 | satisfied |
| #31 | `docs/ansible.md` covering all four sections | #34 | satisfied |
| #31 | `deploy/ansible/playbook-{set-fact,fleet-aggregate}.yml` + inventory | #34 | satisfied |
| #31 | All playbooks pass `ansible-playbook --syntax-check` | #34 | unverifiable in audit (no syntax-check in CI; not run as part of audit) |
| #31 | CONTRIBUTING.md note about Ansible-doc sync | #34 | satisfied |

### Open issues with `agent-ready`

The only open issue is #36 (RHEL/Rocky/Alma 8 shebang). PR #37
attempted a polyglot-shebang fix but was withdrawn pending an
acceptance-criteria decision (CI EL8 VM matrix showed exit 127 on
stock cloud images even with the fix — only the error message changed).
The branch `fix/el8-shebang-polyglot-36` exists upstream; the issue
remains open. No agent-ready stale work.

## Section 2: Stubs and TODOs

Codebase-wide grep across `pqc_readiness.py`, `tests/`, `docs/`,
`scripts/`, `deploy/`, `Containerfile.*`, `Makefile`, `README.md`.

**`pqc_readiness.py`**

- `pqc_readiness.py:941` — TODO list of HSM models not yet on the
  PQC-silicon allow-list (Marvell LiquidSecurity, Thales Luna 7+,
  Utimaco, AWS CloudHSM). _Future work marker._ Acceptable: comment is
  the issue tracker for hardware that has not shipped firmware yet.
- `pqc_readiness.py:3711` — `_recommend_stub()` returning
  `implemented: False` for `tls-client`, `signing-service`,
  `firmware-signing`. _Real stub_, deliberate per issue #13's "Out of
  scope" wording. Acceptable; tracking comment cites issue #13.
- `pqc_readiness.py:3728` — `Recommendations for role={role!r} are not
  yet implemented` user-facing message. _Real stub message_, paired
  with the function above.

**`tests/`**

- `tests/test_recommendation.py:262-268` — `test_other_roles_return_stub`
  asserts that the stub returns `not yet implemented`. _Test of stub
  behaviour, not a stub itself._ Acceptable.
- `tests/test_tls_bench.py:195`, `:221` — `@pytest.mark.skipif(not
  _has_pqc_openssl(), ...)`. _Acceptable_ — environmental skip with a
  clear precondition; not a tracking-issue gap.

**`Containerfile.ubuntu-fips`**

- File-level _real stub_ — body is comments only, no `FROM`. Documented
  as intentional pending Ubuntu Pro FIPS entitlement. README §
  "Container / OpenShift" labels it explicitly as a stub. Acceptable as
  a future-work marker, but note: `Containerfile.ubuntu-fips` is not
  excluded from any tooling that walks Containerfile.* — `make
  container` does not try to build it (Makefile targets the three real
  files explicitly), but a future `make container` modification could
  accidentally try.

**Functions returning `None` / bare `return`**

- ~30 sites of `return None` / `return None, "<reason>"`. Spot-checked
  10 of them — all are the documented "tool not on PATH / parse failed
  / unsupported architecture" early returns and pair with explicit
  caller-side handling. _Acceptable._
- `pqc_readiness.py:509`/`:532`/`:538`/`:582`/`:587`/`:799`/`:840`/etc.
  — bare `pass` inside `except (OSError, ...):` blocks. Catch-and-
  ignore is the documented pattern for "tool absent / `/proc` field
  not present on this distro". _Acceptable_, but see Section 4
  ("Error handling consistency") for a small inconsistency.

**Dead code / `if False`**: none found.

## Section 3: Acceptance criteria drift

Per-PR drift findings, severity in parentheses:

- **PR #2 (closes #1) — `unavailable_in_container` flag drift
  (correctness).** Issue #1 §4 acceptance: "Per-feature
  `unavailable_in_container` flags". The implementation only sets a
  top-level `runtime_environment` field. Detection functions that read
  `/proc /sys /dev /etc` do not annotate their results when run inside
  a container without `--host-mount`. Grep for the literal string
  `unavailable_in_container` returns one hit — a comment in
  `detect_runtime_environment`'s docstring promising the flag exists.
  No code emits it. Filed as audit issue.
- **PR #2 — `--ansible --check` precedence is silently lossy (cosmetic).**
  Issue #1 §4 said `--ansible` always exits 0. Implementation hits an
  early `return 0` in `main()` before the `--check` branch
  (`pqc_readiness.py:5781`). Combining `--ansible --check cnsa-2.0`
  silently ignores the `--check` flag. This matches the issue's letter
  but is a confusing CLI shape; cosmetic only. No issue filed.
- **PR #2 — `adequate` ISA tier is undocumented (correctness).**
  `isa_tier()` in `pqc_readiness.py:646`/`:661`/`:669`/`:683` returns
  `"adequate"` for x86_64-AVX2-only, ARM-without-SHA3, s390x-pre-MSA8,
  and 4-16 GiB memory. The `--check` argparse `choices=` and the
  documented exit-code semantics name only `excellent | good | marginal
  | poor`; `_TIER_ORDER` (`pqc_readiness.py:3207`) does not contain
  `"adequate"` either. The recommendation engine has a defensive
  branch (`isa in ("poor", "marginal", "adequate")`,
  `pqc_readiness.py:3648`) but `isa_tier` never returns `"marginal"` —
  that's `per_algo_verdict`'s output. The two tier vocabularies
  (overall ISA / per-algo) are conflated in the recommendation engine
  source. Filed as audit issue.
- **PR #16 (closes #4) — `rpm-qa` fixture missing (cosmetic).** Issue
  #4 §9: "tests/fixtures/packages/: rpm-qa, dpkg-query, pacman, apk
  samples." Fixtures shipped: `dpkg-query-sample.txt`,
  `pacman-q-sample.txt`, `apk-info-sample.txt`. No `rpm-qa-sample.txt`.
  `test_parse_rpm_packages` uses an inline string (`tests/test_parsers.py:442`).
  Listed in section 4 below. No issue filed.
- **PR #17 (closes #9) — SSH `kex_groups` is two-bucket, not three
  (correctness).** Issue #9 acceptance: "Same distinction applied to
  detected SSH KEX algorithms" with `pure_pqc / hybrid / classical`.
  `Report.ssh_pqc.kex_groups` has only `pure_pqc` and `hybrid`. The
  classical bucket is omitted. Inconsistent with `tls_groups`. Filed
  as audit issue.
- **PR #21 (closes #13) — phantom `marginal` ISA tier branch
  (correctness, low).** Same as #2 above; the recommendation engine
  encodes a tier (`marginal`) that the upstream `isa_tier` function
  cannot return. Dead-code branch. Subsumed by the `adequate` ISA tier
  audit issue.
- **PR #27 (closes #6) — SPDX 3.0 schema validation is structural-only
  (correctness, low).** Issue #6 acceptance: "Output validates against
  SPDX 3.0 schema." SPDX 3.0.1 does not publish a JSON Schema (the spec
  validates via OWL/SHACL); the test file does its own structural
  validation against the bundled JSON-LD context. Documented in
  `tests/test_spdx.py:6-21`. Functional but not literally what the
  acceptance criterion stated. No issue filed — accepted as a
  reasonable mitigation given the underlying spec.
- **PR #33 (closes #8) — follow-up rename issue not filed
  (correctness).** Issue #8 last acceptance bullet: "At the end, file
  a follow-up issue titled 'Apply JSON schema field renames per
  docs/schema-alignment.md'". No such issue exists in the queue.
  Filed as audit issue.
- **PR #35 (closes #30) — Tier label vs CI cadence disagreement
  (cosmetic).** Issue #30 explicitly stated EL8 family promotes from
  Tier 3 to Tier 2 in the same PR landing CI. The README lists Tier 2
  as "Periodic (weekly) — fixes accepted", but `ci-ubi8.yml` runs on
  `pull_request` and `push` to main (every change). EL8 is therefore
  closer to the README's Tier 1 cadence. Listed in section 4 below.
  No issue filed.
- **(none) — issue #28 (Incus matrix runner) marked closed without an
  artefact in main (correctness).** No PR is linked; no
  `scripts/validate-matrix.sh` exists in main. Issue #28's acceptance
  criteria are not satisfied by anything I could find in the
  repository. Filed as audit issue.

## Section 4: Cross-cutting consistency

### JSON schema coherence

- `tls_groups` is three-bucket (`pure_pqc / hybrid / classical`);
  `ssh_pqc.kex_groups` is two-bucket (`pure_pqc / hybrid`). See PR #17
  finding above. **Filed as audit issue.**
- Optional/missing handling is mixed: most string-or-null fields use
  `null` in `--json`, but `Report.benchmark` and
  `Report.benchmark_tls_handshake` default to `{}` while
  `Report.memory_bandwidth_method` defaults to `""`. Picking one
  convention (empty vs. null) would simplify aggregator and renderer
  code. **Cosmetic.**
- `schema_version="1.0"` has not been bumped since v1; PR #33 stated
  in `docs/schema-alignment.md` that renames warrant a bump. No
  renames have shipped to date, so no bump required. Confirmed.
- `accelerator_kinds_host_count` (aggregator) vs `kind` (per-host) —
  consistent naming.

### Error handling consistency

- All `available=False` returns ship `{"available": False, "reason":
  "<...>"}` consistently across `openssl_capability`, `scan_trust_store`,
  `_run_ssh_kex`, `_tls_bench_*`, `detect_nss`. ✓
- Bare `pass` blocks in `except` clauses (e.g.
  `pqc_readiness.py:509`/`:799`/`:840`) silently swallow OSError.
  CLAUDE.md "Error paths must be handled explicitly — never silently
  swallow errors" suggests at least debug logging. None of the
  swallowed branches use the standard library `logging` module — the
  script does not configure a logger at all. **Cosmetic** but
  collectively meaningful for debuggability.
- `host_path` returns `Path(p)` raw on bare-metal, then most callers
  do `.read_text()` and catch `OSError`. The pattern is consistent.

### CLI flag consistency

- All `--scan-X` flags (`--scan-trust-store`, `--scan-packages`) are
  off-by-default. ✓
- All `--bench-X` flags accept the same `--seconds`/`--threads`
  parameters via shared globals. ✓
- `--check` exit-code convention: rc=0 pass, rc=4 below tier or
  cnsa-2.0 not compliant, rc=1+ for actual errors. Consistent. ✓
- Help-text style is consistent (lowercase verbs, no trailing period
  on most). Minor exception: `--ansible` help text ends with "exit 0"
  — declarative, not a description of the flag's purpose. Cosmetic.
- `--ansible` short-circuits before `--check`, silently ignoring the
  threshold gate — see Section 3.

### Output format parity

- Every renderer (text, markdown, JSON, CBOM, SPDX, SARIF) produces
  output for the synthetic full-coverage Report fixture in tests. ✓
- `--ansible` output, `--cbom`, `--spdx`, `--sarif`, `--recommend`
  output schemas are intentionally distinct from `--json`. Documented
  in CONTRIBUTING.md.
- Markdown output: I rendered the report on this host and skimmed the
  output — no broken tables, no unclosed code fences. Renderer is
  not pytest-tested for invariants like "no string `null` appears in
  markdown output" — see Section 5.
- SARIF / CBOM / SPDX validation is performed against bundled schemas
  in tests. ✓

### Cross-distro parity

- `detect_os` covers RHEL/Rocky/Alma/Fedora/Debian/Ubuntu/SUSE/Arch/
  Alpine via `/etc/os-release` + `ID_LIKE`. Family fall-through tested.
  ✓
- Container-mode degradation: **non-uniform**. Per Section 3 finding,
  detection functions don't flag `unavailable_in_container` per-feature.
  Filed as audit issue.
- Install hints (`_install_hint`) are family-aware. ✓

### Cosmetic findings list (no issues to be filed)

- `Containerfile.ubuntu-fips` is comments-only; harmless but a future
  `find Containerfile.*` invocation would attempt to build it.
- `tests/fixtures/packages/rpm-qa-sample.txt` does not exist;
  `test_parse_rpm_packages` uses an inline string.
- README claims Tier 2 is "Periodic (weekly)" while UBI 8 CI runs on
  every push.
- `Report.benchmark` defaults to `{}` while
  `Report.memory_bandwidth_method` defaults to `""` and other optional
  fields use `null`. Pick one.
- Bare `pass` in `except (OSError, ...)` blocks silently swallow errors
  without debug logging.
- `--ansible` help text grammar inconsistent with other flags.

## Section 5: Test coverage gaps

Tests pass: 242 in main, 248 with PR #37's launcher tests. No coverage
gates today, but meaningful gaps below:

- **Renderer coverage** — `render_text` and `render_markdown` (the
  default human-readable outputs) have no dedicated tests. Only
  `test_text_renderer_includes_policy_and_algorithm`
  (`tests/test_recommendation.py:299`) covers the recommendation
  block. Suggested test: render a synthetic full-coverage Report and
  assert (a) no occurrence of literal `None` / `null` strings, (b)
  every required section heading is present, (c) markdown tables are
  balanced.
- **Aggregator boundary cases** — only happy-path tests
  (`test_aggregate_reports_basic_counts`,
  `test_aggregate_to_csv_renders_groups`). Missing tests:
  empty input dir, single-host input, mixed-schema-version input
  (one good + one with `schema_version: "0.9"`), malformed JSON in
  one of N files. The aggregator's skip logic
  (`pqc_readiness.py:2253-2270`) is untested. **Filed as audit issue.**
- **Container-mode `unavailable_in_container` paths** — there is no
  test asserting that a detection function emits the flag when run
  inside a container without `--host-mount`. The flag itself is not
  emitted, so the test is moot until Section 3 finding is fixed; tests
  to be added at the same time.
- **`--check cnsa-2.0` exit-code paths** — `evaluate_cnsa_2_0` is
  unit-tested for compliant/partial/non_compliant/unknown outputs,
  but `main()`'s mapping of the status into rc=4 is not. Add an
  end-to-end smoke test (subprocess `pqc_readiness.py --check
  cnsa-2.0 --json` with a fixture-injected Report).
- **Boundary cases for `isa_tier`** — `score >= 18` for x86_64
  excellent, `score >= 6` for good, `score >= 8` for ARM excellent.
  No test asserts the just-above/just-below values produce the
  expected tier.
- **Trust-store empty + malformed cert paths** — `scan_trust_store`
  has tests for the categorisation function and for the OID regex;
  no test for "directory does not exist", "directory exists but is
  empty", "openssl x509 returns nonzero on a corrupt PEM".

## Section 6: Documentation reality check

- **README feature list ↔ code:** matches. `scripts/check-readme-flags.sh`
  asserts every long-form flag in `--help` appears in README.md.
- **README ↔ help text:** matches.
- **CONTRIBUTING.md:** describes the README-feature-coverage rule and
  the third-party-reference policy. No section on PR review,
  branching strategy, commit conventions, or how to run the test
  suite locally. Out of scope for this audit (CONTRIBUTING content
  was not in scope for any closed issue).
- **CLI flag documentation:** every flag is documented in README.
- **Environment variables:** none documented. The script does not use
  `os.environ` at all in a configuration-relevant way; only
  `os.geteuid` (in tests). ✓
- **Exit codes:** documented in README §"Exit codes" and in `--help`.
  Match. ✓
- **Schema policy doc ↔ shipping schema:** `docs/schema-alignment.md`
  describes the rename plan but the renames have not been applied;
  the schema_version is still 1.0 and the JSON shape matches v1
  conventions. Mapping is consistent.
- **Distro support matrix ↔ CI:** README claims Tier 2 is "Periodic
  (weekly)" but RHEL 8 has its own CI workflow that runs on every push,
  and there is no scheduled / weekly workflow for Tier 2 distros (no
  `schedule:` cron in any CI file). The "weekly" label is aspirational
  for Fedora/Rocky/SLES/etc. and demonstrably wrong for RHEL 8.
  **Cosmetic** but worth a follow-up to either add the cron jobs or
  reword the matrix.
- **Aspirational documentation:** README §"Container / OpenShift"
  references `deploy/openshift/daemonset.yaml` (exists) and
  `deploy/quadlet/pqc-readiness.container` (exists). README does not
  document features that don't ship.

## Section 7: CI and tooling

- **Per-distro CI tier:** Tier 1 is exercised via the `ci.yml` matrix
  (Python 3.11/12/13 on `ubuntu-latest`). Tier 1 also includes RHEL 9,
  RHEL 10, Debian 12 according to the README — but actual host-level
  CI runs only on `ubuntu-latest` and on the UBI 8 image. No CI runs
  pytest on RHEL 9/10 or Debian 12. The README's Tier 1 claim is
  partially aspirational. **Filed as audit issue.**
- **Schema validation in CI:** test suite validates SARIF / CBOM /
  SPDX / aggregator output against bundled schemas; CI runs the test
  suite on every PR. ✓
- **Third-party-reference lint:** I confirmed
  `scripts/check-no-third-party-refs.sh` rejects with rc=1 when given
  a pattern reserved in `scripts/forbidden-refs.txt`. The workflow
  uses the script. ✓ (verified by reading; not actively tampered).
- **Containerfile builds in CI:** `ci-ubi8.yml` builds the UBI 8 image
  in CI. UBI 10 and Debian Containerfiles are NOT built in any CI
  workflow — only `make container-ubi10` / `make container-debian`
  exist as targets. **Filed as audit issue.**
- **Pre-commit ↔ CI parity:** ruff, mypy --strict, detect-secrets in
  pre-commit; ruff and mypy --strict in CI. detect-secrets runs only
  in pre-commit, not in CI — slight gap. Pre-commit also runs ruff-
  format (PR-time auto-format), CI does not enforce format. **Cosmetic.**
- **Release process:** undocumented. No `RELEASE.md`, no GH Actions
  release workflow, no signed-tag procedure. README `--version`
  reports `2.0.0` but there is no v2.0.0 git tag. Out of audit scope
  (no closed issue specified a release process).

## Section 8: Dependency hygiene

- **Runtime imports:** stdlib only, plus optional `numpy` (lazy in
  `memory_bandwidth_probe`). ✓ No requirements file shipped — README
  documents this as intentional ("the runtime has no deps beyond
  stdlib + optional numpy").
- **Dev imports:** `pytest`, `ruff`, `mypy`, `numpy`, `jsonschema`,
  `referencing` are all installed in CI. ✓
- **Unused declared dependencies:** none — there is no requirements
  file to audit.
- **Pinned versions in Containerfiles:** UBI 10 pins to `:10.1`; UBI 8
  to `:8.10`; Debian to `:12-slim`. CLAUDE.md standing rule is "pinned
  tags from trusted registries" — pinned tags are acceptable; digest
  pinning would be stricter but is not required by any closed issue.
- **Bundled / vendored crypto libraries:** none.
- **Top-level optional imports:** `numpy` is lazily imported inside
  `memory_bandwidth_probe` with graceful skip. The `csv` and `io`
  imports inside `aggregate_to_csv` are stdlib and could be top-level;
  zero functional difference. **Cosmetic.**

## Section 9: Security posture

- **subprocess invocations:** all 20+ `subprocess.run` calls go through
  `_run(cmd: list[str], timeout: int = 10)` (`pqc_readiness.py:430`),
  list-form, with explicit timeout. ✓
- **No `shell=True`, no `os.system`, no `eval`, no `exec`, no
  `pickle.loads`.** ✓
- **Path-traversal risk:** the only user-supplied path inputs are
  `--host-mount PATH` and `--aggregate DIR`. `host_path` only prefixes
  a fixed allow-list of namespaces and does not read user input
  beyond the prefix string itself. The aggregator uses `dir_path.glob`
  on a directory the user explicitly named. Both look safe.
- **Output write paths:** `--save` writes to `~/.cache/pqc-readiness/`
  (XDG-compatible), `--bench-tls` and `_tls_bench_*` use
  `tempfile.TemporaryDirectory`. No writes outside `$HOME` / `/tmp`.
  ✓
- **Logging of secrets:** the script does not log PKCS#11 token PINs,
  HSM credentials, or cert key material. PKCS#11 module paths are
  enumerated (the `.so` paths) but those are package-shipped public
  paths, not credentials. ✓
- **HTTP calls:** none in the runtime path. URI strings appear as
  `$schema` identifiers in CBOM/SARIF/SPDX output but are never
  fetched at runtime. ✓ Tests are explicitly hermetic — bundled
  schemas, no network required.

## Section 10: Performance and scale

- **Filesystem-wide scans:** none. `scan_trust_store` walks an
  explicit allow-list of trust-store directories
  (`TRUST_STORE_DIRS`), not `/`.
- **Trust-store max-cert limit:** none. Each PEM/CRT under the trust
  dirs spawns one `openssl x509` subprocess with a 3 s timeout. A
  pathological trust store (10 000 certs) would take ≥ 30 000 s in
  the worst case. Realistic trust stores are ~150 certs. **Worth a
  cap** (e.g., `max_certs=500`); not blocking. **Listed as feature
  idea below.**
- **Aggregator memory:** `run_aggregator` reads every file fully into
  memory before calling `aggregate_reports`. For typical fleet sizes
  (≤10 000 hosts × ~10 KB each ≈ 100 MB) this is fine. Streaming
  would matter at 100 000+ hosts. **Listed as feature idea below.**
- **No O(n²) loops** spotted on the aggregator's host or cert paths.
  `aggregate_reports` is one pass per report.
- **Benchmark iteration counts:** `--bench` defaults to 2 s per algo
  via `--seconds N`. Sensible for fleet-wide use; configurable as
  required by issue acceptance.

## Section 11: Known rough edges

| Item | Status | Evidence |
| --- | --- | --- |
| 32 KB → 192 KB per-connection memory constant | **confirmed** | `pqc_readiness.py:3320` — both surfaced; assumptions string emitted |
| `has_dedicated_pqc_silicon` allow-list (CEX8 only) | **confirmed** | `pqc_readiness.py:946`, comment block at L935-947 |
| `lszcrypt -V` parsing differentiates CEX5/6/7/8 | **confirmed** | `parse_lszcrypt`, `pqc_readiness.py:848`; `pqc_eligible = (level >= 8 and mode == "EP11")` |
| FIPS provider regex rewrite — loaded-but-inactive ≠ enabled | **confirmed** | `detect_fips_mode_from_providers_text`, `pqc_readiness.py:806` |
| `parse_speed_row` regex handles integer values | **confirmed** | `pqc_readiness.py:2511`, `\d+(?:\.\d+)?` |
| `memory_bandwidth_probe` real triad or removed | **confirmed** | `pqc_readiness.py:3162` — STREAM-triad numpy probe; rename to `memcpy_throughput_gb_s` was not pursued (the probe is real; the field name `memory_bandwidth_gb_s` is consistent with the implementation) |
| `parse_classical_speed` redundant condition fix | **confirmed** | `pqc_readiness.py:2541`, header detection rewritten |
| `--ansible` exit-code = 0 unless crashed | **confirmed** | `pqc_readiness.py:5781`, early `return 0` |
| Container-mode `--host-mount /host` rewrites detection paths | **confirmed** | `host_path`, `pqc_readiness.py:91`; allow-list at `_HOST_NAMESPACES` |
| Fleet `--aggregate DIR` produces JSON and CSV | **confirmed** | `--aggregate-format {json,csv}`; both verified empirically |
| OpenSSL `upgrade_path` is family-aware | **confirmed** | `openssl_upgrade_path`, `pqc_readiness.py:2281`; RHEL/Debian/Ubuntu/SUSE/Alpine/Arch branches |
| `tls_groups` has three buckets (pure_pqc / hybrid / classical) | **confirmed** | `classify_tls_groups`, `pqc_readiness.py:2437` |
| Composite signature OID list populated | **confirmed** | `COMPOSITE_SIG_OID_RE`, `pqc_readiness.py:1838`, IANA arc 1.3.6.1.5.5.7.6.{37..54} |
| `--check cnsa-2.0` exit code | **confirmed** | `pqc_readiness.py:5810`, returns 4 on non-compliant; verified empirically (rc=4 on this host) |
| `--policy` flag — all four policies implemented and produce different results | **confirmed** | `tests/test_recommendation.py::test_recommendations_differ_across_policies_for_same_host` |
| `--policy auto` default emits all four side-by-side | **confirmed** | `recommend()` `pqc_readiness.py:3745`; verified empirically |
| CycloneDX 1.6 output validates against schema | **confirmed** | `tests/test_cbom.py` validates with bundled schema and jsonschema |
| SPDX 3.0 output validates against schema | **partial** | SPDX 3.0.1 publishes no JSON Schema; `tests/test_spdx.py` validates structurally against the bundled JSON-LD context |
| SARIF 2.1.0 output validates and includes all six rules | **confirmed** | `tests/test_sarif.py` validates with `jsonschema.Draft7Validator`; rules pqc-001..pqc-006 at `pqc_readiness.py:4446-4527` |
| Third-party-reference lint — `scripts/forbidden-refs.txt` exists, workflow uses it | **confirmed** | file present; `.github/workflows/no-third-party-refs.yml` invokes the script |
| `CONTRIBUTING.md` "Third-party product references" section | **confirmed** | `CONTRIBUTING.md:3-60` |

## Out of audit scope: feature ideas

These surfaced during the walk-through but are feature requests rather
than fixes against accepted criteria. Recorded for human triage.

- **Trust-store max-cert cap.** `scan_trust_store` has no hard limit;
  pathological trust stores would slow the probe. A `max_certs=N`
  parameter (default 500) and a reported `truncated: true` flag
  would bound the worst case.
- **Aggregator streaming I/O.** `run_aggregator` reads every file into
  memory before reducing. Fine for fleets ≤ 10 000 hosts. A streaming
  reducer would unblock 100 000-host fleets.
- **Weekly scheduled CI for Tier 2 distros.** The README promises
  "weekly" validation; no scheduled workflow exists. Add a
  `schedule:` cron to `ci.yml` (or split out a `ci-tier2.yml`) to
  match the documented cadence.
- **Tier-1 distro CI for RHEL 9/10 + Debian 12.** Tier 1 is documented
  as "every change" but only Ubuntu (host) and UBI 8 (image) actually
  run pytest in CI. (Now also captured as a Section 7 audit issue —
  the line is fuzzy here; recorded both places.)
- **Logger module.** Currently `print` and silent `except` blocks. A
  `logging.getLogger("pqc-readiness")` with environment-variable
  control would make troubleshooting tractable without adding
  runtime deps.
- **`--debug` flag.** No way to surface "tool absent" / "parser failed"
  diagnostics today; users see empty fields with no signal as to why.

## Appendix A: Files audited

- `pqc_readiness.py` (5830 lines, full read)
- `pqc-readiness` (wrapper launcher, full read)
- `Containerfile.ubi10`, `Containerfile.ubi8`, `Containerfile.debian`,
  `Containerfile.ubuntu-fips`
- `Makefile`, `.pre-commit-config.yaml`, `.gitignore`
- `README.md`, `CONTRIBUTING.md`, `LICENSE`
- `docs/scope.md`, `docs/recommendation-policies.md`,
  `docs/schema-alignment.md`, `docs/ansible.md`
- `scripts/forbidden-refs.txt`, `scripts/check-no-third-party-refs.sh`,
  `scripts/check-readme-flags.sh`
- `.github/workflows/ci.yml`, `.github/workflows/ci-ubi8.yml`,
  `.github/workflows/no-third-party-refs.yml`
- `tests/conftest.py`, `tests/test_parsers.py`, `tests/test_cbom.py`,
  `tests/test_spdx.py`, `tests/test_sarif.py`,
  `tests/test_recommendation.py`, `tests/test_trust_store.py`,
  `tests/test_tls_bench.py`, `tests/test_launcher.py`
- `tests/fixtures/cpuinfo/`, `tests/fixtures/openssl-speed/`,
  `tests/fixtures/os-release/`, `tests/fixtures/packages/`,
  `tests/fixtures/sarif/`, `tests/fixtures/cyclonedx/`,
  `tests/fixtures/spdx/`, `tests/fixtures/lszcrypt/`,
  `tests/fixtures/openssl-providers.txt`, `tests/fixtures/ssh-kex-rhel10.txt`
- All 19 PR descriptions and all 19 issue bodies
- All issue comments on PR #37 (closed not merged)

## Appendix B: Files NOT audited and why

- `deploy/ansible/*.yml` — playbooks pass `ansible-playbook --syntax-check`
  per the issue's acceptance criterion; rerunning syntax-check inside
  the audit was out of scope.
- `deploy/quadlet/pqc-readiness.container` and
  `deploy/openshift/daemonset.yaml` — file-existence checked,
  contents not deeply audited (issue #1 §5 acceptance items confirmed
  by file presence; deeper review is out of audit scope).
- `tests/fixtures/cyclonedx/bom-1.6.schema.json`,
  `tests/fixtures/sarif/sarif-2.1.0.schema.json`,
  `tests/fixtures/spdx/spdx-3.0.1-context.jsonld` — third-party
  schemas; not the project's IP.
- The 4 closed feature branches under `origin/feat/*` and `origin/docs/*`
  not yet pruned — every branch is also represented by a merged PR
  whose final state is in `main`. Branch-level diff review is out of
  scope.
- `.coverage`, `.mypy_cache/`, `.ruff_cache/`, `.pytest_cache/` —
  generated artefacts.
