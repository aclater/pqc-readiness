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
- **Empty fields:** `file_path`, `component_name` and `unique_id_from_tool`
  are empty, because the scanner's SARIF has no `locations` or
  fingerprints yet.

### Known issue: findings churn on re-import

With no fingerprints, DefectDojo identifies a finding by a hash of its
title. Some titles contain counts, such as the number of trust-store
certificates scanned.

| Re-import into the same test | Result |
|---|---|
| Identical file | 2 findings untouched (correct) |
| Same findings, but a count in a message changed (396 → 401) | **1 finding closed and 1 created** |

#145 tracks the fix: `partialFingerprints` keyed on host and rule, plus
stable messages. Until it lands, expect findings that carry counts to be
closed and re-opened on each re-scan.

## Importing

Create an API v2 key for a non-admin user with import rights.

```bash
pqc-readiness --sarif --scan-trust-store --output host.sarif

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

- Use **one product per host**. The findings carry no host identity of
  their own (no location or component), so the product is what tells
  hosts apart.
- Use **re-import, not import**, for recurring scans. Its open/closed
  history is the useful signal.
- For inventory and verdicts, use the scanner's JSON, the fleet
  aggregator, or an SBOM/CBOM-oriented platform. See
  [dependency-track.md](dependency-track.md).
