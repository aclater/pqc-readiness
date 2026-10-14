# Example output: live Rancher-managed RKE2 cluster (v2.2.0)

> **Example output, not a support statement.** This page records what the Kubernetes manifests and `pqc-readiness` did on a live two-node RKE2 cluster managed by Rancher, on 2026-10-14. It shows the deployment working end to end and what two stock cloud-image nodes report. Results will change as the distributions update.

The lab ran on one AMD Ryzen AI 9 HX 370 host, in three rootless KVM guests on a private L2 segment:

| Role | OS | Kernel | vCPU / memory | Kubernetes |
| --- | --- | --- | --- | --- |
| Rancher management cluster | Ubuntu 26.04.1 LTS | `7.0.0-34-generic` | 4 / 8 GiB | RKE2 v1.36.4+rke2r1, Rancher v2.15.2, cert-manager v1.21.2 |
| Downstream: etcd, control plane, worker | Rocky Linux 10.2 | `6.12.0-211.16.1.el10_2.0.1` | 2 / 6 GiB | RKE2 v1.36.4+rke2r1, containerd 2.3.4 |
| Downstream: worker | openSUSE Leap 16.0 | `6.12.0-160000.38-default` | 2 / 4 GiB | RKE2 v1.36.4+rke2r1, containerd 2.3.4 |

The downstream cluster was created in Rancher as a custom cluster and both nodes registered with Rancher's node command. The manifests were applied through Rancher: the downstream kubeconfig came from the Rancher API (`generateKubeconfig`), so every `kubectl` call went through Rancher's cluster proxy.

## Summary

| Check | Result |
| --- | --- |
| `kubectl apply -k deploy/kubernetes` on a fresh cluster | Namespace, ServiceAccount and DaemonSet created; a pod running on each node; no Pod Security Admission warnings |
| `kubectl apply -k deploy/kubernetes/services` (instead of the base) | Running on both nodes; 0 unreadable processes; 41 of 42 (Rocky) and 30 of 31 (Leap) listeners attributed |
| Package inventory through the portable `/var/lib` mount | 448 packages (Rocky, `rpmdb-sqlite`) and 383 (Leap, `rpmdb-ndb`), the same counts as `rpm -qa` on each node |
| Crypto library versions | Match the nodes' packages exactly (below) |
| Report `hostname` | Node name (`ds-rocky`, `ds-leap`) with the branch build; the pod name with the published 2.2.0 image, which predates the `PQC_HOSTNAME` fix ([#220](https://github.com/aclater/pqc-readiness/issues/220)) |
| Deployment gap, both nodes | TLS `deployed`, SSH `deployed`, IPsec `not_present`: no gaps |
| Node verdicts | Rocky `MARGINAL` (exit 2), Leap `POOR` (exit 3). Both come from the lab VMs' memory (5.5 and 3.8 GiB against the 16 GiB threshold for the generic role), not from the crypto stack |

## Pod security, verified on the live pods

Identical on both nodes:

| | Base DaemonSet | Services variant |
| --- | --- | --- |
| Admitted by | Pod Security Admission, `enforce: privileged` on the `pqc-readiness` namespace only | same |
| User | UID 1001, GID 0 | UID 1001, GID 0 |
| Capabilities (`CapEff` / `CapBnd`) | none / none | none on the shell; the dedicated interpreter has `CapEff` `0x80004` (`CAP_DAC_READ_SEARCH`, `CAP_SYS_PTRACE`); the system `python3` has none |
| `NoNewPrivs` | 1 | 0 (required for file capabilities) |
| Seccomp | `RuntimeDefault` (mode 2) | `RuntimeDefault` (mode 2) |
| Root filesystem, host mounts | read-only (`touch` fails with `Read-only file system` on `/usr`, `/host/etc`, `/host/var/lib`) | read-only |

**containerd and file capabilities.** The services image was designed against CRI-O, which never sets ambient capabilities for a non-root process. containerd 2.3 behaves the same here: the shell's ambient set is empty, the bounding set is exactly the two capabilities, and only the interpreter with file capabilities gains them.

## Node prerequisites found on the way

None of these is specific to `pqc-readiness`. Each broke pod networking for every workload on the node, and the cluster wasn't usable until it was fixed. They're listed because minimal cloud images are a common way to build lab and edge nodes.

| Symptom | Cause | Fix |
| --- | --- | --- |
| Canal's `install-cni` can't reach the service IP `10.43.0.1`; kube-proxy errors | The Rocky Linux 10 cloud image has no `xt_conntrack` / `xt_comment` modules. On EL10 they're in `kernel-modules-extra`, not `kernel-modules` | `dnf install kernel-modules-extra-$(uname -r)`, plus `/etc/modules-load.d/rke2.conf` listing `overlay br_netfilter xt_conntrack xt_comment` |
| Pods stuck in `ContainerCreating`: `no IP addresses available in range set` | Canal's port-mapping plugin runs the `iptables` command, which neither the Rocky 10 nor the Leap 16 cloud image ships. Each sandbox failed after its IP was assigned and never released it, so the node's 254 pod addresses ran out | `dnf install iptables-nft` (Rocky) and `zypper install iptables` (Leap), then clear the stale reservations in `/var/lib/cni/networks/k8s-pod-network` |
| Rancher's `cattle-cluster-agent` can't resolve the Rancher hostname | The lab has no DNS; the nodes use `/etc/hosts`, which pods don't see | A `hostAliases` entry on the agent Deployment, Rancher's documented workaround for clusters without DNS |

## What the nodes report

Full scan with the branch build, run inside each services pod with the capability-carrying interpreter: `--host-mount /host` plus every `--scan-*` flag, `--bench --bench-tls --seconds 1`, then the same scans with `--sarif`. The [method](#how-this-was-run) has the exact commands.

### Crypto stack and deployment gap

| | Rocky Linux 10.2 | openSUSE Leap 16.0 |
| --- | --- | --- |
| OpenSSL | `3.5.5`, PQC-capable, from the node's package (`version_source: package`). The scan run for this page reported the image's `3.5.8`; see below | `3.5.0`, PQC-capable, from the node's package. The first run reported `3.5.8` |
| OpenSSH | `9.9p1` (matches the node, by coincidence) | Reported as `9.9p1`, the image's; the node has `10.0p2` ([#256](https://github.com/aclater/pqc-readiness/issues/256)) |
| Crypto policy | `DEFAULT`, which enables hybrid ML-KEM for TLS | `DEFAULT` (crypto-policies), same |
| TLS / SSH / IPsec gap | `deployed` / `deployed` / `not_present` | `deployed` / `deployed` / `not_present` |
| GnuTLS | 3.8.10, PQC-capable | 3.8.10, PQC-capable |
| libgcrypt | 1.11.0: ML-KEM present, but versions before 1.11.1 upstream implement the draft Kyber, which doesn't interoperate with final ML-KEM ([`pqc-014`](../rules/pqc-014-crypto-library-pre-standard-mlkem.md)) | 1.12.1, PQC-capable |
| libssh | 0.12.0, PQC-capable | 0.11.5, no ML-KEM / ML-DSA ([`pqc-013`](../rules/pqc-013-crypto-library-without-pqc.md)) |
| Packages | 448 (`rpmdb-sqlite`) | 383 (`rpmdb-ndb`) |
| Trust store | 390 CA certificates, all classical | 121 CA certificates, all classical |
| Package-signing keys | 1, RSA 4096 | 6, RSA 4096 and one RSA 2048 |
| Per-service TLS config (`--scan-service-configs`) | none of the supported daemons configured | none |

Both distributions ship PQC on by default, so neither node has a deployment gap. That matches the Rocky 10 and Leap 16 VMs in the [cross-OS matrix](os-matrix-2026-10.md). The library findings are what separates them: Rocky's libgcrypt predates final ML-KEM, and Leap's libssh has no PQC.

**OpenSSL and OpenSSH versions under `--host-mount`.** The full scan above ran before [#228](https://github.com/aclater/pqc-readiness/issues/228) was fixed, and reported the scanner image's OpenSSL `3.5.8` on both nodes. Rerun with the fix on the same pods, the base DaemonSet reports the nodes' own versions (`3.5.5` and `3.5.0`, `version_source: package`) and keeps the image's in `openssl.scanner_cli_version`. The verdicts didn't change, because all three versions are PQC-capable. The OpenSSH version still comes from the image ([#256](https://github.com/aclater/pqc-readiness/issues/256)), which is why Leap shows `9.9p1`.

### Listening services (`--scan-services`)

| | Rocky Linux 10.2 | openSUSE Leap 16.0 |
| --- | --- | --- |
| Listeners | 42: 36 Go, 3 OpenSSL, 2 GnuTLS, 1 without a crypto library | 31: 26 Go, 2 OpenSSL, 2 GnuTLS, 1 without a crypto library |
| Unattributed | 1 | 1 |
| Processes scanned / unreadable | 199 / 0 | 250 / 0 |

Most listeners are RKE2's own: etcd, kubelet, kube-proxy, CoreDNS, Traefik, Canal and the Rancher agent. Every crypto-linked listener is `deployed`.

### SARIF findings

6 results on each node:

| Rule | Rocky | Leap |
| --- | ---: | ---: |
| [`pqc-004-classical-only-trust-store`](../rules/pqc-004-classical-only-trust-store.md) | 1 | 1 |
| [`pqc-005-slh-dsa-in-tls-context`](../rules/pqc-005-slh-dsa-in-tls-context.md) | 1 | 1 |
| [`pqc-009-classical-package-signing-keys`](../rules/pqc-009-classical-package-signing-keys.md) | 1 | 1 |
| [`pqc-013-crypto-library-without-pqc`](../rules/pqc-013-crypto-library-without-pqc.md) | | 1 |
| [`pqc-014-crypto-library-pre-standard-mlkem`](../rules/pqc-014-crypto-library-pre-standard-mlkem.md) | 1 | |
| [`pqc-030-classical-boot-chain`](../rules/pqc-030-classical-boot-chain.md) | 1 | 1 |
| [`pqc-031-kerberos-weak-enctypes`](../rules/pqc-031-kerberos-weak-enctypes.md) | 1 | 1 |

### Benchmarks

Single-thread `openssl speed`, 1 s per test, inside the pod (scanner image's OpenSSL 3.5.8), per core:

| Algorithm | Operation | Rocky | Leap |
| --- | --- | ---: | ---: |
| ML-KEM-768 | decaps/s | 31,411 | 25,200 |
| ML-DSA-65 | sign/s / verify/s | 1,246 / 6,405 | 1,336 / 7,069 |
| SLH-DSA-SHA2-128s | sign/s | 4.0 | 4.2 |

Loopback TLS 1.3 handshakes (`--bench-tls`, 29 per group):

| Group | Rocky: handshakes/s, median TTFB, bytes | Leap: handshakes/s, median TTFB, bytes |
| --- | --- | --- |
| `x25519` | 129.1, 7.48 ms, 2,931 | 193.7, 4.99 ms, 2,425 |
| `X25519MLKEM768` | 95.9, 8.61 ms, 6,282 | 143.7, 7.06 ms, 4,645 |
| `MLKEM768` | 116.1, 7.90 ms, 5,717 | 218.4, 4.22 ms, 5,714 |

The guests have 2 vCPUs each and share the host with the management cluster, so the absolute numbers are low and noisy; the ratios between groups are the useful part.

## How this was run

- **Lab.** Three persistent KVM guests from the distributions' cloud images, started rootless under a shared vCPU budget, joined by a multicast L2 segment (`10.77.0.0/24`).
- **Management cluster.** RKE2 on the Ubuntu guest, then cert-manager and Rancher from their Helm charts.
- **Downstream cluster.** Created in Rancher as a custom cluster (`provisioning.cattle.io/v1` `Cluster`, RKE2 v1.36.4+rke2r1); Rocky registered with `--etcd --controlplane --worker`, Leap with `--worker`, both with `--address` and `--internal-address` on the lab segment.
- **Base.** `kubectl apply -k deploy/kubernetes`, then `kubectl -n pqc-readiness rollout status ds/pqc-readiness`.
- **Services variant.** `kubectl -n pqc-readiness delete ds/pqc-readiness`, then `kubectl apply -k deploy/kubernetes/services`.
- **Posture.** `kubectl exec` into each pod: `id`, `/proc/self/status` (`CapEff`, `CapBnd`, `CapAmb`, `NoNewPrivs`, `Seccomp`), and `touch` on the root filesystem and each host mount. In the services pod, the same `/proc/self/status` read through `/usr/local/libexec/pqc-readiness/python3 -I` and through the system `python3`.
- **Inventory.** `pqc-readiness --host-mount /host --scan-packages --json` in each base pod, compared with `rpm -qa | wc -l` and `rpm -q` on the node.
- **Full node scan.** The branch zipapp was streamed into each services pod (`kubectl exec -i … -- sh -c 'cat > /tmp/p.pyz' < dist/pqc-readiness.pyz`) and run with `/usr/local/libexec/pqc-readiness/python3 -I /tmp/p.pyz --host-mount /host` and `--json --scan-packages --scan-trust-store --scan-crypto-material --scan-signing-keys --scan-services --scan-service-configs --scan-boot-chain --scan-crypto-libraries --scan-kerberos --scan-processes --scan-tunnels --scan-dnssec --bench --bench-tls --seconds 1`, then the same scans with `--sarif`.
- **#228 recheck.** The zipapp built from main after the #228 fix, streamed into each base pod and run with `python3 -I /tmp/p.pyz --host-mount /host --json`.
- **Image.** `ghcr.io/aclater/pqc-readiness:2.2.0` (`sha256:97ccf9a1…`) and `ghcr.io/aclater/pqc-readiness-services:2.2.0`, as referenced by the manifests.
