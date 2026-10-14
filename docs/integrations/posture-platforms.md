# Cryptographic posture platforms

Cryptographic posture and inventory platforms collect crypto assets from many
sources (network sensors, endpoint agents, code scanners, certificate managers)
and import CycloneDX CBOMs. This page explains how to feed them `pqc-readiness`
CBOMs: what the documents contain, which options to use, how to join them with
CBOMs from other tools, and how to collect them across a fleet.

What `pqc-readiness` adds to such a platform is the host's side of the picture:
what each host *can* do (OpenSSL, OpenSSH and library capability, CPU and
accelerators) and what its configuration *allows*, which network and code
sources can't see.

**Tested on 2026-10-14** with pqc-readiness 2.2.0 on a Fedora 44 host and an
exported UBI 10.2 rootfs (`--root`), CycloneDX CLI 0.33.1 (checksum verified
against the release asset), and the CycloneDX 1.6 and 1.7 JSON schemas bundled
in `tests/fixtures/cyclonedx/`. See [What was tested](#what-was-tested).

## What the CBOM contains

Each run describes one host. The host is `metadata.component`
(`bom-ref: host/<hostname>`, type `device`; `operating-system` for an offline
`--root` scan) with `host:os`, `host:arch` and `host:cpu_model` properties.
Every component carries `detectedBy: pqc-readiness@<version>`.

| Scan flag | Components added (CycloneDX 1.7) | bom-ref pattern |
| --- | --- | --- |
| (always) | Algorithms OpenSSL and OpenSSH offer: ML-KEM, ML-DSA, SLH-DSA, TLS hybrid and pure-PQC groups, SSH key exchanges | `openssl/kem/<name>`, `openssl/sig/<name>`, `openssl/tls-hybrid/<group>`, `openssl/tls-pure-pqc/<group>`, `ssh/kex/hybrid/<name>` |
| (always) | Protocols with `relatedCryptographicAssets` linking the groups each can negotiate; the IPsec stack when one is installed | `protocol/tls`, `protocol/ssh`, `ipsec/<implementation>` |
| (always) | CPU instruction-set features, accelerators, TPM, PKCS#11 modules | `isa/<flag>`, `accel/<n>/<name>`, `tpm/<name>`, `pkcs11/<n>` |
| `--scan-trust-store` | One `certificate` per unique CA certificate, plus a trust-store summary | `cert/sha256:<fingerprint>`, `trust-store/summary` |
| `--scan-crypto-material` | Certificates found on the filesystem (leaf and CA), merged with trust-store ones that share a fingerprint; every path in `crypto_material:path` properties | `cert/sha256:<fingerprint>` |
| `--scan-crypto-libraries` | `library` components with a distribution purl (`rpm`, `deb`, `apk` or `alpm` by family), the PQC algorithms each library embeds, and `provides` links from library to algorithm | `pkg:rpm/<distro>/<name>@<version>?distro=<id>-<version>`, `library/<lib>/<kind>/<name>` |
| `--scan-services` | One `application` per listening service (named by systemd `.service` unit, else executable path), with `service:endpoint` properties and `dependsOn` the crypto library it maps | `service/<unit-or-exe>`; libraries it maps that no other scan reported get `pkg:generic/<name>@<version>` |

Certificates carry the CycloneDX 1.7 certificate fields: SHA-256 `fingerprint`,
`serialNumber`, subject and issuer, validity dates and `certificateState`, plus
`certificate:role` (`ca` / `leaf`) and `certificate:source` (`trust-store` /
`host-filesystem`) properties.

The other scans (`--scan-packages`, `--scan-signing-keys`, `--scan-processes`,
`--scan-boot-chain`, `--scan-kerberos`, `--scan-tunnels`, `--scan-dnssec`) add
no CBOM components. Their results reach a platform through `--json`, `--sarif`
or `--ndjson` instead. Private keys and Java keystores found by
`--scan-crypto-material` are reported in JSON only (as metadata), never in the
CBOM.

## Choosing options

| Your importer | Use | Why |
| --- | --- | --- |
| Accepts CycloneDX 1.7 | `--cbom` (1.7 is the default) | Certificates, libraries, services and protocol links exist only in 1.7 |
| Accepts only CycloneDX 1.6 | `--cbom --cbom-version 1.6` | Algorithms, protocols and the trust-store summary only; no certificate, library or service components |
| Drops `cryptoProperties` it doesn't understand | add `--cbom-interop dependency-track` | Mirrors the crypto details into `pqc-readiness:crypto:*` properties and adds library components with purls ([details](dependency-track.md)) |
| Rejects `cryptographic-asset` components (SBOM-only importers) | `--cbom-interop sbom-only` | Emits only library components (with purls) and service components |
| US federal reporting | add `--cbom-profile federal-draft` | Adds `federal:*` properties (function, quantum-vulnerable, migration deadline, M-23-02 item coverage, TLS 1.3 status). **Draft:** the document says so in `federal:profile:status`, and the profile will be remapped when CISA and NIST publish the minimum CBOM elements (EO 14412, due around March 2027) |
| Needs system identifiers | add `--inventory-metadata FILE` | Puts operator-supplied facts (FISMA system ID, FIPS 199 categorization, hosting, HVA ID, data lifecycle) on the host component as `inventory:*` properties ([format](../json-output.md#inventory_metadata)) |

`--cbom-interop` and `--cbom-profile` work with both 1.6 and 1.7.

Run as root, with the scans whose components you want:

```bash
sudo pqc-readiness --cbom \
  --scan-trust-store --scan-crypto-material \
  --scan-crypto-libraries --scan-services \
  --output /var/tmp/pqc-readiness.cdx.json
```

## Identifiers for de-duplication

On an unchanged host, two runs produce the same components with the same
bom-refs and identical content. Only `serialNumber` (a new `urn:uuid` per run)
and `metadata.timestamp` change, and `version` is always `1`. So:

- **Treat each document as the current state of one host.** Key the import on
  the host component's bom-ref (`host/<hostname>`) and replace the host's
  previous document instead of appending to it.
- **Don't de-duplicate on `serialNumber`.** It identifies the run, not the host.
- **Component bom-refs are stable across runs** and safe as keys within a host:
  certificates by fingerprint, algorithms and protocols by name, services by
  systemd unit or executable path, libraries by purl (the purl changes when the
  library is upgraded, which is the point).

**Offline scans have no hostname.** Every `--root` CBOM is `host/unknown`, so
name each one before importing several images side by side. The helper in
[`deploy/cbom/cbom_tools.py`](../../deploy/cbom/cbom_tools.py) renames the host
and its dependency edges:

```bash
pqc-readiness --root ./rootfs --cbom --scan-trust-store --scan-crypto-libraries > image.cdx.json
python3 deploy/cbom/cbom_tools.py name-host image.cdx.json image-named.cdx.json ubi10-2-1791893534
```

## Joining with other CBOMs

The same bom-ref can mean different things in documents from different tools,
and different tools name the same asset differently. Join on the identifiers
the assets carry, not on bom-refs.

| Join | Key in the pqc-readiness CBOM | Notes |
| --- | --- | --- |
| Certificates seen on the network or in code | `cryptoProperties.certificateProperties.fingerprint` (SHA-256, hex) | Exact match. Matches tell you which host holds the certificate an endpoint presents |
| Packages in an SBOM (`--sbom` or another tool's) | Library `purl`: type, namespace, name and upstream version | **Not an exact purl match.** CBOM library purls carry the upstream version without release, arch or epoch (`pkg:rpm/fedora/gnutls@3.8.13?distro=fedora-44`); package SBOMs carry the full version (`pkg:rpm/fedora/gnutls@3.8.13-1.fc44?arch=x86_64&distro=fedora-44`). Stacks the scanner probes directly (OpenSSL, NSS, OpenSSH, Java runtimes, Go) get `pkg:generic` purls with no package to match |
| A host's own `--sbom` | `metadata.component.bom-ref` | `--cbom` and `--sbom` from the same host share `host/<hostname>` |
| Network endpoints | `service:endpoint` properties (`tcp/<address>:<port>`) on service components | For endpoint-level joins, the JSON report and [endpoint observations](../endpoint-observations.md) carry more detail |

`cbom_tools.py` implements the first two joins:

```console
$ python3 deploy/cbom/cbom_tools.py join-certificates host.cdx.json network.cdx.json
9a6ec012e1a7da9dbe34194d478ad7c0db1822fb071df12981496ed104384113	C=ES,O=ACCV,OU=PKIACCV,CN=ACCVRAIZ1
1 of 2 certificates found on the host

$ python3 deploy/cbom/cbom_tools.py join-packages host.cdx.json host.sbom.json
pkg:rpm/fedora/gnutls@3.8.13?distro=fedora-44	pkg:rpm/fedora/gnutls@3.8.13-1.fc44?arch=i686&distro=fedora-44 pkg:rpm/fedora/gnutls@3.8.13-1.fc44?arch=x86_64&distro=fedora-44
pkg:generic/java@25.0.4.1	no package match
pkg:rpm/fedora/libgcrypt@1.12.2?distro=fedora-44	pkg:rpm/fedora/libgcrypt@1.12.2-1.fc44?arch=x86_64&distro=fedora-44
pkg:rpm/fedora/libssh@0.12.2?distro=fedora-44	pkg:rpm/fedora/libssh@0.12.2-1.fc44?arch=i686&distro=fedora-44 pkg:rpm/fedora/libssh@0.12.2-1.fc44?arch=x86_64&distro=fedora-44
```

## Merging documents

Most platforms import one CBOM per host; prefer that. If an importer needs a
single fleet document, merge with the CycloneDX CLI's **hierarchical** merge,
then repair its output:

```bash
cyclonedx merge --hierarchical --name fleet --version 2026-10-14 \
  --input-files host-a.cdx.json host-b.cdx.json \
  --output-file fleet.cdx.json --output-format json --output-version v1_7
python3 deploy/cbom/cbom_tools.py repair-merge fleet.cdx.json fleet-fixed.cdx.json
cyclonedx validate --input-file fleet-fixed.cdx.json --input-version v1_7 --fail-on-errors
```

- **Don't use a flat merge for several hosts.** Hosts share certificates and
  algorithms, so a flat merge of two hosts produced 384 duplicate bom-refs in
  testing. CycloneDX requires bom-refs to be unique within a document.
- A hierarchical merge nests each host under its own component and prefixes
  every bom-ref with `<host-name>@<version>:` (e.g.
  `fw13pro@:cert/sha256:…`). Join on fingerprints and purls, not bom-refs.
- CycloneDX CLI 0.33.1 writes two defects that `repair-merge` fixes:
  - `relatedCryptoMaterialProperties` gains `"state": "null"` and `"size": 0`,
    which the 1.7 schema rejects. This also happens with a plain
    `cyclonedx convert` of a single valid CBOM.
  - The hierarchical merge prefixes `dependsOn` entries but not `provides`
    entries, leaving every library-to-algorithm link dangling.

After `repair-merge`, the merged document of two hosts validated, kept all 880
input components and had no dangling references.

## Collecting across a fleet

Write one CBOM per host, named by host, to a place the importer reads (a shared
directory, an object store bucket or an upload API):

- **Ansible:**
  [`deploy/ansible/playbook-cbom-collect.yml`](../../deploy/ansible/playbook-cbom-collect.yml)
  runs `--cbom --output` on every target (with `become`) and fetches
  `<inventory_hostname>.cdx.json` to the controller.
- **systemd quadlet or OpenShift DaemonSet:** the shipped units write JSON
  (`--save`). Change the command to `--cbom … --output <volume>/<host>.cdx.json`
  with the scan flags you need ([deployment](../deployment.md)).
- Upload with whatever your platform accepts. The CBOM is a plain JSON file;
  `pqc-readiness` itself never sends data anywhere.

## What not to expect

- **No observed traffic.** The CBOM lists what a host can negotiate and what
  its configuration allows, not what it negotiated. A protocol's algorithms are
  the groups OpenSSL or OpenSSH offer. Whether PQC is actually on by default is
  in the JSON report's `pqc_deployment_gap`, not in the CBOM. Combine with a
  network source for observed use.
- **No findings or risk scores.** Findings are SARIF/NDJSON
  ([rules](../rules/README.md)); import them into the platform's findings
  feature if it has one.
- **Property names are mostly not namespaced.** Most component properties use
  short prefixes (`detectedBy`, `certificate:*`, `crypto_material:*`,
  `trust_store:*`, `isa:*`, `service:*`, `host:*`, `inventory:*`), the
  interoperability and library properties use `pqc-readiness:*`, and the
  federal profile uses `federal:*`. If your platform merges properties from
  several tools, map them by `detectedBy`.
- **Offline scans** (`--root`) contain no CPU, accelerator, OpenSSL-runtime or
  service components, only what the tree's files show.

## What was tested

All on 2026-10-14, pqc-readiness 2.2.0:

- **Validated with CycloneDX CLI 0.33.1 and the bundled JSON schemas:** live
  CBOMs in 1.7 and 1.6, `--cbom-interop dependency-track` and `sbom-only`,
  `--cbom-profile federal-draft`, `--inventory-metadata`, a `--root` scan of a
  UBI 10.2 rootfs, `--sbom`, a renamed offline CBOM, and the repaired
  hierarchical merge of a live and an offline CBOM.
- **Checked against output:** every bom-ref pattern, property name and option
  effect in this page; run-to-run stability (two runs on the same host:
  identical components and bom-refs, different `serialNumber`); the
  certificate and package joins against a real host CBOM and `--sbom`.
- **Run:** `playbook-cbom-collect.yml` against localhost with
  `ansible-core 2.21.5` (fetched CBOM validated); `cbom_tools.py` under Python
  3.9 (UBI 8) and 3.14; unit tests in `tests/test_cbom_tools.py`.
- **Not tested:** import into a commercial posture platform; the network-side
  CBOM in the join example was constructed for the test, not produced by a
  network scanner.
