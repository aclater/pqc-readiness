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
- One `operating-system` component (from `/etc/os-release`; on a Yocto
  image without one, from `/etc/buildinfo`).
- One `library` component per installed OS package, identified by a
  [purl](https://github.com/package-url/purl-spec): `pkg:rpm/…`,
  `pkg:deb/…`, `pkg:apk/…` or `pkg:alpm/…`, with the os-release `ID` as
  the vendor namespace and `arch`, `epoch` and `distro` qualifiers where
  known.
- Families without a package tool (OpenWrt, Yocto, unknown IDs) are read
  from whichever package database the tree has:

  | Database | purl | Why |
  |---|---|---|
  | opkg (OpenWrt ≤ 24.10, Yocto `package_ipk`) | `pkg:generic/<vendor>/<name>@<version>` | purl-spec defines no opkg type; the vendor is the os-release `ID` (or `/etc/buildinfo` `DISTRO`) |
  | apk (OpenWrt 25.12) | `pkg:apk/openwrt/<name>@<version>` | the apk type names `openwrt` as a vendor |
  | rpm in a Yocto image | `pkg:yocto/<recipe>@<PV>` | the spec's `yocto` type identifies the recipe (BPN, PV); the recipe comes from the package's SOURCERPM tag. Binary packages from one recipe share its purl, and their `bom-ref`s add `#<package>`. The layer (the type's optional namespace) isn't recorded in an image, so it's omitted |

  A Yocto image is recognised by `/etc/buildinfo` (the `image-buildinfo`
  class) or os-release `ID=poky`. Packages that get no purl (an rpm tree
  with neither os-release nor a Yocto marker has no vendor namespace) are
  counted in the `pqc-readiness:sbom:packages-without-purl` property.
- Purls are written in the canonical form of ECMA-427 (the purl
  standard), clause 5.4: letters, digits, `. - _ ~` and `:` stay as they
  are and everything else is percent-encoded, so `+` becomes `%2B`
  (`pkg:deb/debian/bash@5.2.37-2%2Bb10?distro=debian-13`) and a Debian
  epoch keeps its colon (`bsdutils@1:2.41.5-0%2Bdeb13u1`). `--cbom` uses
  the same purls for the same packages, so the two documents join by
  string comparison (#243, #257).
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
| Embedded trees (`--root`, #227) | OpenWrt 24.10.8: matches `opkg list-installed` (129/129). OpenWrt 25.12.5: matches `apk info -v` (136/136). Yocto 6.0.3 `core-image-full-cmdline`: matches the image's `.manifest` (444/444 names and versions), 123 recipe purls. All three pass `cyclonedx-cli validate --input-version v1_6 --fail-on-errors` (0.33.1) |
| Ingestion into a running graph-tool instance | **Not tested here** |

## Using both outputs

Feed the plain SBOM to package-graph tools and the CBOM to
cryptographic-inventory tools. Both carry the same host `bom-ref`
(`host/<hostname>`), so the two documents can be joined per host.
