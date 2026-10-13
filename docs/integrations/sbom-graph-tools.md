# Plain SBOM for supply-chain graph tools (`--sbom`)

Some SBOM and supply-chain graph tools ingest CycloneDX package components
but not cryptographic assets. They either reject a CBOM or flatten every
crypto asset into a generic "package", which pollutes their graph. GUAC
v1.1.0 is one example: its CycloneDX parser handles container, file and
operating-system components specially and treats everything else,
including `cryptographic-asset`, as a generic package (#157).

For those tools, `--sbom` emits a separate, plain SBOM:

- CycloneDX **1.6**, for compatibility with consumers that predate 1.7. It
  uses no 1.7-only fields.
- One `operating-system` component (from `/etc/os-release`).
- One `library` component per installed OS package, identified by a
  [purl](https://github.com/package-url/purl-spec): `pkg:rpm/…`,
  `pkg:deb/…`, `pkg:apk/…` or `pkg:alpm/…`, with the os-release `ID` as
  the vendor namespace and `arch`, `epoch` and `distro` qualifiers where
  known.
- rpm's `gpg-pubkey` pseudo-packages are left out; they're trust anchors,
  not software (`--scan-signing-keys` reports them).
- **No cryptographic assets.** Use `--cbom` for those.

The package list comes from the same in-process readers as
`--scan-packages`, so `--host-mount` (DaemonSet / quadlet) and `--root`
(offline image trees) are honoured.

```bash
pqc-readiness --sbom --output host.sbom.json
pqc-readiness --root /mnt/image-rootfs --sbom --output image.sbom.json
```

## Validation

| Check | Result (2026-10-14) |
|---|---|
| `cyclonedx-cli validate --input-version v1_6 --fail-on-errors` (CycloneDX CLI 0.33.1 container) | Passes on a Fedora 44 host (2,376 components) |
| Package list vs the system's own tooling | Matches `rpm -qa` (Fedora 44), `dpkg-query -W` (Debian, 78/78) and `apk info -v` (Alpine, 16/16) |
| Ingestion into a running graph-tool instance | **Not tested here** |

## Using both outputs

Feed the plain SBOM to package-graph tools and the CBOM to
cryptographic-inventory tools. Both carry the same host `bom-ref`
(`host/<hostname>`), so the two documents can be joined per host.
