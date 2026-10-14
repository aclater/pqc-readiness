# Output formats

| Flag | Format | Use case |
| --- | --- | --- |
| (default) | Coloured text report | Operator console |
| `--markdown` | Markdown | Pasting into tickets |
| `--json` | Stable JSON schema | Fleet aggregation, automation |
| `--cbom` | CycloneDX 1.7 CBOM (`--cbom-version 1.6` for 1.6) | Cryptographic inventory pipelines |
| `--spdx` | SPDX 3.0 JSON-LD | SPDX-native tooling |
| `--sbom` | Plain CycloneDX 1.6 package SBOM: one component per installed OS package, with purls, no crypto assets ([integrations/sbom-graph-tools.md](integrations/sbom-graph-tools.md)) | SBOM / supply-chain graph tools that don't understand crypto assets |
| `--sarif` | SARIF 2.1.0 findings | Code-scanning / security pipelines |
| `--ndjson` | OCSF 1.9.0 events, one JSON object per line ([field reference](json-output.md#--ndjson-events), [SIEM recipes](siem-ndjson.md)) | SIEM / log pipelines |
| `--prometheus` | Prometheus text format | node_exporter textfile collector, fleet dashboards ([prometheus.md](prometheus.md)) |
| `--ansible` | `ansible_facts` wrapper | Ansible `set_fact` |
| `--recommend` | Policy-aware recommendation | Algorithm selection per host |

The output flags are views of the same probe run; pass one per run. If
several are given, `--ansible` wins, then `--recommend`, then the first of
`--json`, `--cbom`, `--spdx`, `--sbom`, `--sarif`, `--prometheus`,
`--ndjson`, `--markdown` and `--quiet`; the others are ignored. Detection logic is shared — a
new detection rule shows up in every output format without per-renderer
changes.

**JSON.** Stable, schema-versioned host inventory. The full top-level
field reference, the `--ansible` wrapper shape, and the
`--recommend --json` variant are documented in
[json-output.md](json-output.md). For schema interoperation
with CycloneDX, see [schema-alignment.md](schema-alignment.md).

**CBOM.** `--cbom` emits a [CycloneDX 1.7](https://cyclonedx.org/docs/1.7/json/)
Cryptographic Bill of Materials; `--cbom-version 1.6` emits
[CycloneDX 1.6](https://cyclonedx.org/docs/1.6/json/) exactly as earlier
releases did. Each detected source — ISA features, accelerators, OpenSSL
primitives, OpenSSH KEX, IPsec, PKCS#11 modules, trust-store summary —
becomes a `cryptographic-asset` component with `assetType`,
`algorithmProperties` where applicable, and a
`detectedBy: pqc-readiness@<version>` provenance property. 1.7 output
adds:

- `algorithmFamily` from the CycloneDX 1.7 algorithm registry (ML-KEM,
  ML-DSA, SLH-DSA, LMS, XMSS). Families the registry doesn't define yet
  (HQC, FN-DSA, FrodoKEM, Classic McEliece, BIKE) are reported in a
  `pqc-readiness:algorithmFamily` property marked
  `not-in-cyclonedx-1.7-registry`. Hybrid groups such as
  X25519MLKEM768 have no single family.
- TLS and SSH `protocol` components that link the key-exchange groups
  they can negotiate through `relatedCryptographicAssets`.
- `certificate` assets keyed by SHA-256 fingerprint, one per unique
  certificate from `--scan-trust-store` and `--scan-crypto-material`
  (merged when a certificate is in both). Properties record
  `certificate:role` (`ca` / `leaf`), `certificate:source`
  (`trust-store` / `host-filesystem`) and the discovered
  `crypto_material:path` values. Certificates are a 1.7-only projection;
  `--cbom-version 1.6` output is unchanged.
- Crypto `library` components from `--scan-crypto-libraries` (GnuTLS,
  libgcrypt, libssh, wolfSSL, AWS-LC, JDKs, Go), with a distro purl when
  the package is known. Each library `provides` the PQC algorithms found
  in its binary; those algorithm assets carry the library as `group`.
  Listening processes from `--scan-services` become `application`
  components that depend on the crypto library they actually map
  (OpenSSL, NSS, GnuTLS, a static Go runtime, …), with one
  `service:endpoint` property per listener. 1.7-only; nothing is added
  unless those scans run.

Both versions validate against the official schemas bundled under
[`tests/fixtures/cyclonedx/`](../tests/fixtures/cyclonedx/). NIST IR 8547, the US transition guidance,
is still an [initial public draft](https://csrc.nist.gov/pubs/ir/8547/ipd).

**SPDX.** `--spdx` emits an [SPDX 3.0.1](https://spdx.github.io/spdx-spec/v3.0.1/)
JSON-LD document with `core` + `software` + `security` profile
conformance. The shared canonical asset list is projected as
`software_Package` / `security_Vulnerability` elements wrapped in a
`software_Sbom`. JSON-LD is fully type-checked: every `type` and
property is a term in the canonical SPDX 3.0.1 context, and every
reference resolves within the document.

**SARIF.** `--sarif` emits [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
findings under stable rule IDs, each with a `helpUri` pointing at its page in
[rules/](rules/README.md), a default level, and short and full descriptions.
The rules fall into four groups:

- `pqc-001`–`pqc-010`: host capability and configuration (OpenSSL older than
  3.5, FIPS and PQC conflicts, no PQC-capable ISA, classical-only trust store,
  SLH-DSA offered for TLS, HSMs without PQC firmware, FIPS without an
  algorithm fence, a crypto policy that keeps PQC out, classical
  package-signing keys, sshd not offering PQC key exchange first).
- `pqc-011`–`pqc-018`: software that will fail at PQC (services, Go binaries,
  crypto libraries, IPsec stacks and bundled crypto that can't do it, and
  capability that could not be determined).
- `pqc-020`–`pqc-021`: PQC-capable software configured to stay classical,
  and services whose own TLS configuration keeps ML-KEM out.
- `pqc-030`–`pqc-034`: the boot chain, Kerberos, WireGuard, OpenVPN and DNSSEC.

Output validates against the official SARIF 2.1.0 schema. For code-scanning
platforms, add `--sarif-anchor` ([recipe](sarif-code-scanning.md)).

**Recommendations.** `--recommend` produces a host-specific PQC
algorithm recommendation under one of four policies (`cnsa-2.0`,
`nist-civilian`, `eu-anssi-bsi`, `commercial`); `--policy auto`
(default) emits all four side by side. The authority, source
document, and engine-encoded position for each policy are catalogued
in [recommendation-policies.md](recommendation-policies.md).
The `--recommend --json` document shape is in
[json-output.md](json-output.md#recommend-json-variant).

**Ansible.** `--ansible` wraps the JSON schema in
`{ansible_facts: {pqc_readiness: …}}` and always exits 0 so a play
never marks a host as failed on the verdict. Because of that,
`--ansible` takes precedence over `--check` and `--fips-strict`: they
can be combined with it, but their exit-code gates are ignored and a
warning is printed on stderr. Gate in the play on the JSON instead
(e.g. `pqc_readiness.cnsa_2_0.status`). Runnable playbooks
(`set_fact`, fleet aggregation), the `become` / privilege model, and
the fact shape downstream tasks rely on are in
[ansible.md](ansible.md); the playbooks themselves live
under [`deploy/ansible/`](../deploy/ansible/).
