# Deploying pqc-readiness

How to run the scanner beyond a one-off command: as a single file copied to
hosts, in containers, as a systemd quadlet, as an OpenShift DaemonSet, against
offline images, and how to roll the results up across a fleet. For Ansible,
see [ansible.md](ansible.md).

## Single-file deployment

The tool is a stdlib-only Python package. `make dist` (or
`python3 scripts/build_zipapp.py`) builds `dist/pqc-readiness.pyz`, one
executable file with no dependencies. Copy it, with or without the
`pqc-readiness` wrapper, to any host with Python 3.9+ and run it:

```bash
make dist
scp dist/pqc-readiness.pyz pqc-readiness host:/usr/local/bin/
ssh host /usr/local/bin/pqc-readiness --json
```

Debugging on a target host: `python3 -m zipfile -l pqc-readiness.pyz`
lists the modules, and `python3 -m zipfile -e pqc-readiness.pyz /tmp/pqc`
extracts them for reading or `grep`.

## Containers, OpenShift and Kubernetes

Each release publishes signed images to GitHub Container Registry, built from
the Containerfiles below with the release's own `pqc-readiness.pyz`:

| Image | Base |
| --- | --- |
| `ghcr.io/aclater/pqc-readiness:<version>` (also `<version>-ubi10`) | UBI 10, the default |
| `ghcr.io/aclater/pqc-readiness:<version>-ubi8` | UBI 8, Python 3.9 |
| `ghcr.io/aclater/pqc-readiness:<version>-debian` | Debian 12 |
| `ghcr.io/aclater/pqc-readiness-services:<version>` | UBI 10 plus the `--scan-services` file capabilities ([overlay](openshift-services-overlay.md)) |

`<version>` is the release version without the `v` (for example `2.2.0`). The
quadlet and DaemonSet reference the current release by tag. Version tags are
never moved and there is no floating tag. In production, pin by digest: each
release's `container-images.txt` asset lists every image by digest.

Every image is signed with cosign (keyless, from the release workflow) and
carries two registry attestations: SLSA build provenance, and a CycloneDX
package SBOM that this scanner generated from the image's own root filesystem.
(The 2.2.0 `pqc-readiness-services` image got its SBOM attestation after
release, through the workflow's attest-only mode, #251.)
Verify before rollout:

```bash
cosign verify ghcr.io/aclater/pqc-readiness@sha256:<digest> \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/aclater/pqc-readiness/\.github/workflows/release-images\.yml@'
gh attestation verify oci://ghcr.io/aclater/pqc-readiness@sha256:<digest> --repo aclater/pqc-readiness
```

Use cosign v3 or newer. The release workflow signs with cosign v3, which
stores signatures in the new bundle format; cosign v2 reports `no signatures
found`. `gh attestation verify` checks the SLSA provenance by default; add
`--predicate-type https://cyclonedx.org/bom` to check the SBOM attestation.

To build your own image instead (for example on a different base), use the
Containerfiles directly and push to your registry.

The shipped quadlet and DaemonSet run the basic scan with `--bench`; the
services overlay adds `--scan-services`, which also reads each daemon's own
TLS configuration (`--scan-service-configs`) from the node's read-only `/etc`
and `/usr` mounts. PostgreSQL data directories aren't mounted, so PostgreSQL
endpoints aren't covered there. None of them runs the other `--scan-*`
inventories. To collect packages, certificates, signing keys or crypto
libraries from every node, add those flags to the quadlet's `Exec=` or the
DaemonSet's `command`.

Containerfiles ship for each supported base image:

| File | Base | Use case |
| --- | --- | --- |
| `Containerfile.ubi10` | `registry.access.redhat.com/ubi10/ubi-minimal:10.2` | RHEL / Fedora fleets; default |
| `Containerfile.ubi8` | `registry.access.redhat.com/ubi8/ubi-minimal:8.10` | RHEL 8 / Rocky 8 / AlmaLinux 8 |
| `Containerfile.debian` | `docker.io/library/debian:12-slim` | Debian / Ubuntu fleets |

```bash
make container           # build all three images
make container-ubi10     # UBI 10 only
make container-ubi8      # UBI 8 only
make container-debian    # Debian only
```

All images run as non-root UID 1001 with a Python-only HEALTHCHECK
(`ubi*-minimal` lacks `curl`).

`deploy/quadlet/pqc-readiness.container` is a systemd quadlet that
runs the probe daily against the host.

`deploy/openshift/daemonset.yaml` is the fleet DaemonSet — non-root,
hostPID, custom SCC dropping all capabilities, read-only host bind
mounts of `/proc /sys /dev /etc /usr` and the rpm database directory
`/var/lib/rpm`. That rpm mount covers every layout, because on EL10,
Fedora and SUSE `/var/lib/rpm` is a symlink to `/usr/lib/sysimage/rpm`
and the bind mount follows it. `/usr` is mounted whole (#187) because the
paths the probe reads there (`/usr/lib/os-release`, the crypto-policies
back-ends in `/usr/share/crypto-policies`, SUSE's vendor sshd config in
`/usr/etc/ssh`) exist only on some distros, and a missing narrower source
either stops the pod (`type: Directory`), gets created on the node by
CRI-O (untyped hostPath), or makes podman refuse to start. The quadlet
mounts the same paths, so it no longer needs editing on Debian/Ubuntu.
Both DaemonSets (and the Kubernetes, RKE2 and K3s variants built from
them in `deploy/kubernetes`) also mount the kubelet's `/var/log/containers`
read-only (#233): the probe lists its entries
(`<pod>_<namespace>_<container>-<id>.log`) to name the pod and container
behind each listener, and opens no file. The entries are symlinks into
`/var/log/pods`, which is not mounted, so no log content is reachable.
The quadlet doesn't need this mount: a host without a kubelet has no such
directory, and listeners in containers there are named by runtime and ID.
Inside the pod
the host root is mounted at `/host` and the probe is invoked with
`--host-mount /host` so its reads target the node, not the container
image.

Deploy it with `oc apply -k deploy/openshift`, which creates the
`pqc-readiness` namespace, ServiceAccount, SCC and DaemonSet. Reports go to
an `emptyDir` in the pod, pruned after `PQC_RETENTION_DAYS` (default 7):
a `hostPath` output directory is created `root:root 0755` by the kubelet and
the non-root pod can't write to it. Collect reports with the
[per-node summary overlay](integrations/openshift-node-summaries.md), with
`oc exec`, or by swapping the volume for a PVC on RWX storage. The DaemonSet
sets `PQC_HOSTNAME` from `spec.nodeName`, so reports name the node rather
than the pod. A live run on OpenShift 4.22 is recorded in
[examples/openshift-4.22-live.md](examples/openshift-4.22-live.md).

For `--scan-services` on OpenShift, deploy the opt-in least-privilege variant in [`deploy/openshift/services/`](openshift-services-overlay.md) instead (adds only `CAP_SYS_PTRACE` + `CAP_DAC_READ_SEARCH`).
For per-node summary ConfigMaps that ACM governance policies and Compliance
Operator CEL rules can evaluate, apply the opt-in overlay with
`oc apply -k deploy/openshift-summary` ([details](integrations/openshift-node-summaries.md);
it adds a token and a ConfigMap-only Role, nothing else).

### Kubernetes, RKE2, K3s and Rancher

`deploy/kubernetes` runs the same DaemonSets on plain Kubernetes, RKE2 and
K3s, including clusters managed by Rancher. It reuses `deploy/openshift`
through kustomize, so the pod is identical: UID 1001, no capabilities,
`allowPrivilegeEscalation: false`, seccomp `RuntimeDefault`, a read-only root
filesystem and read-only host mounts. Two things change:

- **No SCC.** The SecurityContextConstraints object is dropped. The namespace's
  Pod Security Admission labels admit the pod instead: `enforce: privileged`,
  because hostPID and hostPath mounts are outside the Baseline profile. That is
  the PSA level name, not a privileged container, and the labels apply to this
  namespace only.
- **`/var/lib` instead of `/var/lib/rpm`.** Kubernetes fleets mix rpm, dpkg,
  apk and pacman nodes, and a `type: Directory` hostPath that's missing on a
  node keeps the pod off that node. `/var/lib` exists everywhere and holds
  every package database the scanner reads. It is mounted read-only with
  `recursiveReadOnly: Enabled`, which needs Kubernetes 1.33 or newer and a
  runtime and kernel that support it (containerd 2.0 or CRI-O 1.30 or newer, Linux 5.12 or newer). Remove that
  one field on older clusters; the mount stays read-only.

```bash
kubectl apply -k deploy/kubernetes             # base DaemonSet
kubectl apply -k deploy/kubernetes/services    # or: the --scan-services variant instead
```

On a Rancher-managed cluster, apply the same kustomization with the
cluster's kubeconfig from Rancher, or point a Fleet `GitRepo` at
`deploy/kubernetes`. The services variant's file capabilities work the same
under containerd as under CRI-O: containerd also leaves the ambient set
empty, so only the dedicated interpreter gains its two capabilities.

The pods need nothing from the node beyond a working cluster. Two node
prerequisites of RKE2 itself turned up on minimal cloud images, and both
break pod networking for every workload, not just this one: the `iptables`
command (Canal's port-mapping plugin runs it; Rocky Linux 10 and openSUSE
Leap 16 cloud images ship without it; install `iptables-nft` or `iptables`),
and on EL10 the `xt_conntrack` and `xt_comment` modules, which are in
`kernel-modules-extra`. A live run on a Rancher-managed RKE2 cluster with
Rocky Linux 10 and openSUSE Leap 16 nodes is recorded in
[examples/rancher-rke2-live.md](examples/rancher-rke2-live.md).

For Ansible-based deployments see [ansible.md](ansible.md)
and the runnable playbooks under [`deploy/ansible/`](../deploy/ansible/).

## Scanning images offline

`--root PATH` inventories a filesystem tree without running anything from it
(#152). Use it for container images, golden images and disk images before they
are deployed:

```bash
# Container image: export its rootfs, then scan the tree.
mkdir rootfs && podman export "$(podman create registry.access.redhat.com/ubi10/ubi)" | tar -x -C rootfs
pqc-readiness --root rootfs --scan-packages --scan-trust-store \
  --scan-crypto-material --scan-signing-keys --json
```

| | `--host-mount PATH` | `--root PATH` |
|---|---|---|
| Subject | A **live** host whose `/proc`, `/sys`, `/etc`… are bind-mounted into the scanner's container | A **filesystem tree** with no running kernel behind it |
| CPU, memory, accelerators, kernel, kTLS, FIPS mode, services, benchmarks | Read from the host | Not applicable (marked in every output format) |
| OpenSSL / SSH / IPsec capability | Probed with the scanner's tools | Not applicable; OpenSSL's version comes from the tree's package database (or, with none, from the version string in its `libcrypto`) and its defaults from the tree's `openssl.cnf`; IPsec proposals from the tree's config files |
| Packages, certificates, keys, crypto policy, signing keys, service TLS configuration | Read from the host | Read from the tree |
| Verdict | Readiness tier and exit code 0–3 | `NOT APPLICABLE - offline filesystem scan`, exit code 0 |

Package databases are read in-process for every format the matrix covers (rpm
SQLite / Berkeley DB / ndb, dpkg `status`, apk, pacman), so the scanner never
runs the tree's binaries or its own package tools against the tree. Checked
against the in-image `rpm -qa` / `dpkg-query -W` on UBI 8, UBI 9, UBI 10,
Fedora 44, Debian 13 and openSUSE Leap 16 container images: identical package
lists, and no subprocess runs during the scan. Scanning a disk image needs it
mounted read-only first (e.g. `guestmount --ro`), which usually requires root.

### Embedded images

OpenWrt, Yocto and Buildroot images are scanned the same way; extract the
rootfs tarball and pass `--root` (#217):

```bash
mkdir rootfs && tar -xzf openwrt-24.10.8-x86-64-rootfs.tar.gz -C rootfs
pqc-readiness --root rootfs --scan-packages --scan-crypto-libraries --sarif
```

- **Package database.** When the distribution has no registered package tool
  (OpenWrt, Yocto, unknown IDs), the scanner reads whichever database the tree
  has: rpm, dpkg, apk, opkg (`/usr/lib/opkg/status` on OpenWrt up to 24.10,
  `/var/lib/opkg/status` on Yocto `package_ipk` images) or pacman. OpenWrt 25.12
  and later use apk.
- **No package database** (Buildroot, Yocto images without
  `package-management`): crypto library and OpenSSL versions come from the
  library files themselves, from the version string each embeds (`OpenSSL
  3.5.7`, `GnuTLS 3.8.12`, `Libgcrypt 1.12.1`) or, for Mbed TLS, from the file
  name (`libmbedtls.so.3.6.6`). Nothing in the tree is run.
- **Mbed TLS** is OpenWrt's default TLS stack and common across embedded
  images. No released Mbed TLS or TF-PSA-Crypto offers ML-KEM or ML-DSA yet,
  so an installed Mbed TLS raises [pqc-013](rules/pqc-013-crypto-library-without-pqc.md).
- A tree with no OpenSSL at all reports `openssl.installed: false` and raises
  no OpenSSL finding.

Validated against the images' own tools on OpenWrt 24.10.8 (opkg) and 25.12.5
(apk), the Yocto 6.0.3 prebuilt `core-image-full-cmdline` (rpm) and
`core-image-minimal` (no package database), a Yocto 6.0.3 `package_ipk` build
and a Buildroot 2026.08 build; see the [fixture README](../tests/fixtures/embedded/README.md).

## Fleet aggregation

`--aggregate DIR` reads every `*.json` produced by `--save` (or by the
DaemonSet output volume) and emits a fleet rollup: counts by arch,
OS, ISA tier, verdict, runtime environment, and accelerator kind, plus
unique CPU models and a `replace_required_count`.

```bash
pqc-readiness --aggregate /var/lib/pqc-readiness                       # JSON
pqc-readiness --aggregate /var/lib/pqc-readiness --aggregate-format csv  # CSV
```

Files with mismatched `schema_version` land under `skipped` with a
reason rather than being silently merged.

To see what endpoints actually negotiate, add `--observations FILE`:
records from any network-side source, in a small neutral format, are
matched to the hosts and to the listening services found by
`--scan-services`, and each endpoint is labelled capable / configured /
observed. See [endpoint-observations.md](endpoint-observations.md).
