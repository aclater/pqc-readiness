# Uploading host findings to a code-scanning platform

`--sarif` emits SARIF 2.1.0 that validates against the OASIS schema and
suits generic security pipelines and SARIF viewers. Code-scanning
platforms need more than the schema requires, because they were built for
source files. `--sarif-anchor PATH` adds those fields (#145). Without the
flag, `--sarif` output is unchanged.

## What `--sarif-anchor` adds

| Field | Value | Why |
|---|---|---|
| `results[].locations[]` | `physicalLocation.artifactLocation.uri` = `PATH`, `region.startLine` = 1 | Code-scanning upload requires a file location for every result. Host findings have none, so `PATH` names a stand-in file. |
| `results[].partialFingerprints` | `pqcReadinessHostRule/v1`: the first 32 hex characters of SHA-256(hostname, rule ID) | Lets the platform tell a recurring finding from a new one. The same condition on the same host keeps one alert, which closes when the condition clears. |
| `runs[].automationDetails.id` | `pqc-readiness/<hostname>/<generated_at>` | The platform reads this as `category/run-id`, where the category is everything before the last `/`. Each host gets its own category, so one host's upload never closes another host's alerts. |
| `tool.driver.rules[].properties.security-severity` | A score, with tags `security` and `post-quantum-cryptography` | Marks the rules as security results and sets their severity label. |

`{hostname}` in `PATH` is replaced with the scanned host's name. A `/` in
a hostname, which is never legal, is replaced with `_`, so a host can't
direct its findings into another directory.

### Severity scores

Scores use the CVSS v3.1 qualitative bands that code scanning applies to
`security-severity`: low 0.1–3.9, medium 4.0–6.9, high 7.0–8.9, critical
9.0–10.0
([CVSS v3.1](https://www.first.org/cvss/v3.1/specification-document#Qualitative-Severity-Rating-Scale)).
These are readiness findings, not exploitable vulnerabilities, so none is
critical.

| Rule | Score | Band |
|---|---|---|
| `pqc-002-fips-pqc-conflict` | 7.5 | high |
| `pqc-007-fips-without-algorithm-fence` | 7.5 | high |
| `pqc-001-openssl-pre-3.5` | 5.3 | medium |
| `pqc-006-no-network-hsm-pqc-firmware` | 4.3 | medium |
| `pqc-003-no-pqc-isa-support` | 4.0 | medium |
| `pqc-004-classical-only-trust-store` | 3.1 | low |
| `pqc-005-slh-dsa-in-tls-context` | 2.0 | low |

## The fleet-repository pattern

1. Create a repository, or a directory in an existing one, holding one
   file per host. Its content doesn't matter; a short description of the
   host is enough:

   ```
   hosts/web01.example.com.md
   hosts/db01.example.com.md
   ```

2. On each host, or from the fleet aggregator's collection point, render
   the findings:

   ```bash
   pqc-readiness --sarif --sarif-anchor 'hosts/{hostname}.md' --output "$HOST.sarif"
   ```

3. Upload each file against the fleet repository, using the platform's
   SARIF upload action or API. Each host's run lands in its own category
   (`pqc-readiness/<hostname>`).

The anchor path must exist in the repository at the commit you upload
against, or the platform can't show the alert on a file.

## Limits to plan for

GitHub's
[SARIF support reference](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning)
documents these limits, checked 2026-10-13:
- up to 10 MB per gzip-compressed upload;
- 25,000 results per run, of which only the top 5,000 by severity are
  kept;
- 25,000 rules per run.

pqc-readiness emits at most one result per rule per host, so one host's
log is far below these limits.

## Not verified

The fingerprint key name `pqcReadinessHostRule/v1` follows the SARIF
convention that producers name their own keys. GitHub's documentation
describes `partialFingerprints` but doesn't say how it treats custom key
names. If your platform deduplicates poorly, report it in an issue.
