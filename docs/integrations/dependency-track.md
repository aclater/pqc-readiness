# Dependency-Track

Dependency-Track is an SBOM-oriented component analysis platform. This
page records how it handles the `--cbom` output, as observed in real
uploads, and how to upload. Tracking issue: #147.

## Summary

| Dependency-Track | CycloneDX 1.7 CBOM | CycloneDX 1.6 CBOM | Crypto details kept |
|---|---|---|---|
| **5.2.0** (v5 line) | Accepted, all components stored | Accepted, all components stored | **No.** Only the asset name and the free-form `properties` |
| **4.14.5** (v4 line) | **Upload returns 200, processing fails, 0 components** | Same as 1.7 | — |

Observed on 2026-10-13 with `ghcr.io/dependencytrack/apiserver:5.2.0`
(PostgreSQL 17) and `docker.io/dependencytrack/apiserver:4.14.5`.
Full API responses are on #147.

Upstream tracks full CBOM support as open enhancements
([#6191](https://github.com/DependencyTrack/dependency-track/issues/6191),
[#3145](https://github.com/DependencyTrack/dependency-track/issues/3145),
milestone 5.x). Re-test when those ship.

## What you see in 5.2.0

- Every component from the CBOM appears with the classifier
  `CRYPTOGRAPHIC_ASSET` (55 components for a 1.7 CBOM on a Fedora 44
  host, 53 for 1.6). The project records `lastBomImportFormat:
  "CycloneDX 1.7"`.
- The `cryptoProperties` block is **not stored**. That block holds the
  primitive, OID, parameter set, NIST quantum security level and
  certificate details. The component API returns only name and
  classifier, and re-exporting the project, even at `version=1.7`, gives
  `cryptoProperties` on none of the components. Free-form component
  `properties` (`detectedBy`, `source`) are kept.
- There are no crypto-specific views or endpoints in the v1 or v2 API.
- The CBOM has no `dependencies` section, so the server logs a harmless
  warning that the dependency graph is incomplete.

So Dependency-Track 5.2.0 is useful as a **list of the cryptographic
assets each host exposes**, searchable by name across projects. It is
not a full crypto inventory. Keep the scanner's own JSON or CBOM as the
authoritative record. #175 tracks mirroring the key crypto facts into
`properties`, so that they survive the upload.

## What happens in 4.14.5

The upload API answers `200` with a token, so the client sees success.
Background processing then fails with
`IllegalArgumentException: No enum constant
org.dependencytrack.model.Classifier.CRYPTOGRAPHIC_ASSET`. The project
is created with **zero components**, and the token endpoint only reports
`{"processing":false}`. 4.x cannot ingest a CBOM that contains
cryptographic assets. #175 tracks an output profile without crypto
assets for consumers like this.

## Uploading

Use an API key from a team that has the `BOM_UPLOAD` and
`PROJECT_CREATION_UPLOAD` permissions. Don't use the admin account.

```bash
pqc-readiness --cbom --scan-trust-store --scan-packages --output host.cbom.json

python3 - host.cbom.json "$(hostname -f)" > upload.json <<'EOF'
import base64, json, sys
bom = open(sys.argv[1], "rb").read()
print(json.dumps({
    "projectName": sys.argv[2],      # one project per host
    "projectVersion": "cbom",
    "autoCreate": True,
    "bom": base64.b64encode(bom).decode(),
}))
EOF

curl -sf -X PUT "$DT_URL/api/v1/bom" \
  -H "X-Api-Key: $DT_API_KEY" -H "Content-Type: application/json" \
  --data @upload.json
# -> {"token": "...", "projectUuid": "..."}   (projectUuid on 5.x)
```

Then check processing:

- **5.x:** `GET /api/v1/event/token/{token}` returns
  `{"processing": false, "status": "COMPLETED"}`.
- **4.x:** `GET /api/v1/bom/token/{token}` returns only
  `{"processing": false}`, including on failure. Confirm with
  `GET /api/v1/component/project/{uuid}`: on 4.14.5 the
  `X-Total-Count` header is `0`.

`--cbom-version 1.6` behaves the same as 1.7 on both lines.

## Recommendations

- Use **5.x**. 4.x cannot ingest this CBOM.
- Use **one project per host** (`projectName` = FQDN), so assets can be
  compared across the fleet.
- For per-algorithm detail, or a verdict, use the scanner's JSON or the
  fleet aggregator (`--aggregate`).
