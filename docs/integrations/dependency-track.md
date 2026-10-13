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
authoritative record. `--cbom-interop dependency-track` (below) mirrors
the key crypto facts into `properties`, so that they survive the upload.

## What happens in 4.14.5

The upload API answers `200` with a token, so the client sees success.
Background processing then fails with
`IllegalArgumentException: No enum constant
org.dependencytrack.model.Classifier.CRYPTOGRAPHIC_ASSET`. The project
is created with **zero components**, and the token endpoint only reports
`{"processing":false}`. 4.x cannot ingest a CBOM that contains
cryptographic assets. #175 tracks an output profile without crypto
assets for consumers like this: `--cbom-interop sbom-only` (below).

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

## `--cbom-interop` (#175)

Two opt-in output shapes make the CBOM useful in Dependency-Track despite
the behaviour above. The default (`none`) output is unchanged.

| Mode | What it emits | 5.2.0 | 4.14.5 |
|---|---|---|---|
| `none` (default) | Cryptographic assets only | Stored; crypto details dropped | **Rejected, 0 components** |
| `dependency-track` | Cryptographic assets, with the key crypto details mirrored into `pqc-readiness:crypto:*` properties, plus library components with purls and a `dependencies` graph (`provides` links each library to its assets) | **Stored, mirrored details kept**, libraries and purls stored, dependency graph complete | **Rejected, 0 components** |
| `sbom-only` | Library components with purls only | Stored (libraries only) | **Stored (libraries only)** |

Measured on 2026-10-13 against `ghcr.io/dependencytrack/apiserver:5.2.0`
(PostgreSQL 17) and `docker.io/dependencytrack/apiserver:4.14.5`, with a
Fedora 44 host's CBOM (`--scan-packages --scan-trust-store
--scan-crypto-material`), in both CycloneDX 1.7 and 1.6. In 5.2.0 the
1.7 `dependency-track` BOM kept all 458 components (453 cryptographic
assets, 5 libraries) and all 3,047 mirrored properties through a
re-export, which 5.2.0 writes as CycloneDX 1.5 without
`cryptoProperties`. The test suite pins this with a real 5.2.0 export
(`tests/fixtures/dependency-track/`).

Mirrored properties, when present on the asset: `assetType`, `primitive`,
`algorithmFamily`, `parameterSetIdentifier`, `nistQuantumSecurityLevel`,
`executionEnvironment`, `implementationPlatform`, `protocolType`,
`relatedCryptoMaterialType`, `certificateSha256`, `subjectName`,
`issuerName`, `notValidAfter`, `certificateState`, and `classification`
(`pure-pqc` / `hybrid` / `classical`). `cryptoProperties` stays the
authoritative field.

Library components:

- Stacks the scanner probed get a `pkg:generic` purl with the detected
  version, for example `pkg:generic/openssl@3.5.9` (the loaded library's
  version when it differs from the CLI's) and `pkg:generic/openssh@10.2p1`.
- Crypto-bearing distribution packages found by `--scan-packages` get a
  distro purl, for example
  `pkg:rpm/fedora/python3@3.14.8?distro=fedora-44`.
- Versions are upstream versions without the distro release, so treat
  these purls as identification, not as input for exact-build
  vulnerability matching.

## Recommendations

- Use **5.x** with `--cbom-interop dependency-track`.
- On **4.x**, only `--cbom-interop sbom-only` ingests; it carries the
  libraries but none of the cryptographic assets.
- Use **one project per host** (`projectName` = FQDN), so assets can be
  compared across the fleet.
- For per-algorithm detail, or a verdict, use the scanner's JSON or the
  fleet aggregator (`--aggregate`).
