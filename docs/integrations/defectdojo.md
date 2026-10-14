# DefectDojo

DefectDojo is a findings and vulnerability management platform. This
page records how it handles the scanner's outputs, as observed in real
imports, and how to import. Tracking issue: #147.

## Summary

| Output | DefectDojo parser | Result |
|---|---|---|
| `--sarif` | `SARIF` | **Works.** One finding per SARIF result |
| `--cbom` (CycloneDX 1.7 or 1.6) | `CycloneDX Scan` | Accepted (`201`) but **0 findings**: the parser only imports CycloneDX *vulnerabilities* |

Observed on 2026-10-13 with DefectDojo **3.4.100** (official compose
file, run under podman). Full API responses are on #147.

**Send SARIF to DefectDojo, not the CBOM.** DefectDojo has no component
or cryptographic-asset inventory view, so the CBOM adds nothing there.

## What the SARIF findings look like

- **Title:** the SARIF result message, title-cased.
- **`vuln_id_from_tool`:** the rule ID, e.g. `pqc-004-classical-only-trust-store`.
- **Severity:** SARIF `note` becomes **Info** and `warning` becomes **Medium**.
- **Type:** findings are marked static.
- **Empty fields:** with plain `--sarif`, `file_path`, `component_name`
  and `unique_id_from_tool` are empty, because that output has no
  `locations` or fingerprints.

### Known issue: findings churn on re-import

DefectDojo deduplicates SARIF findings on a hash of title, CWE, line,
file path and description. Some messages contain counts, such as the
number of trust-store certificates scanned, so a changed count looks
like a new finding:

| Re-import of plain `--sarif` into the same test (2026-10-13) | Result |
|---|---|
| Identical file | 2 findings untouched (correct) |
| Same findings, but a count in a message changed (396 → 401) | **1 finding closed and 1 created** |

`--sarif-anchor PATH` (#145, [recipe](../sarif-code-scanning.md)) adds a
location and a per-host, per-rule `partialFingerprints` value to every
result. DefectDojo's SARIF parser (source checked 2026-10-14) stores the
anchor as `file_path` and the fingerprint as `unique_id_from_tool`.
Its default SARIF deduplication still hashes the description, which
contains the message, so expect findings that carry counts to churn
unless the instance deduplicates SARIF on `unique_id_from_tool`. The
anchored output has **not** been re-imported into a live instance.

## Importing

Create an API v2 key for a non-admin user with import rights.

```bash
pqc-readiness --sarif --sarif-anchor 'hosts/{hostname}' --scan-trust-store --output host.sarif

curl -sf "$DD_URL/api/v2/import-scan/" \
  -H "Authorization: Token $DD_API_KEY" \
  -F scan_type=SARIF -F file=@host.sarif \
  -F auto_create_context=true \
  -F product_type_name=pqc-readiness \
  -F product_name="$(hostname -f)" \
  -F engagement_name=pqc-readiness \
  -F minimum_severity=Info -F active=true -F verified=false
# -> 201, {"test_id": N, "statistics": {...}}
```

For later scans of the same host, use `POST /api/v2/reimport-scan/`
with `test=<test_id>`. DefectDojo then closes findings that disappeared,
instead of creating duplicates.

## Recommendations

- Use **one product per host**. Plain `--sarif` findings carry no host
  identity of their own (no location or component), so the product is
  what tells hosts apart. With `--sarif-anchor 'hosts/{hostname}'` the
  hostname is also in each finding's file path.
- Use **re-import, not import**, for recurring scans. Its open/closed
  history is the useful signal.
- For inventory and verdicts, use the scanner's JSON, the fleet
  aggregator, or an SBOM/CBOM-oriented platform. See
  [dependency-track.md](dependency-track.md).
