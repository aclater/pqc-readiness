# Example output: live OpenShift 4.22 node (v2.2.0)

> **Example output, not a support statement.** This page records what the shipped OpenShift manifests and `pqc-readiness` v2.2.0 did on a live single-node OpenShift cluster on 2026-10-14. It shows the deployment working end to end and what one stock RHCOS node reports. Results will change as OpenShift updates RHCOS.

The cluster was OpenShift Local (CRC 2.64.0) running **OpenShift 4.22.14** (Kubernetes 1.35.6, CRI-O 1.35.7). The single node runs **Red Hat Enterprise Linux CoreOS 9.8** (kernel `5.14.0-687.46.1.el9_8`), with 8 vCPUs and 24 GiB of memory, on an AMD Ryzen AI 9 HX 370 host. Nothing on the node was configured before the scan. Every manifest was applied exactly as the docs say, starting from a cluster with no `pqc-readiness` objects.

## Summary

| Check | Result |
| --- | --- |
| `oc apply -k deploy/openshift` on a fresh cluster | Admitted and running under `pqc-readiness-scc`, after three manifest fixes ([below](#deployment-bugs-found-and-fixed)) |
| Services overlay (`deploy/openshift/services/services.yaml`) | Admitted under `pqc-readiness-services-scc`; all 122 listeners attributed, 0 unreadable processes |
| Summary overlay (`oc apply -k deploy/openshift-summary`) | ConfigMap `pqc-readiness-node-crc` published after the first probe |
| Compliance Operator 1.10.0 CEL `CustomRule` | `Ready`; the suite ran and reported `NON-COMPLIANT` (the node has 2 deployment gaps) |
| ACM governance policy | Not run. ACM is too heavy for a single-node local cluster, and a server-side dry run needs the ACM CRDs. Schema-validated in CI instead |
| Image signatures (`cosign verify`, cosign v3.1.3) | Both images verified; the SLSA provenance attestation verified for both |
| Node verdict | `GOOD - production-capable in software`, exit code 1: TLS and SSH are both `capable_not_configured` |

## Pod security, verified on the live pods

| | Base DaemonSet | Services overlay |
| --- | --- | --- |
| SCC that admitted the pod (`openshift.io/scc`) | `pqc-readiness-scc` | `pqc-readiness-services-scc` |
| User | UID 1001, GID 0 | UID 1001, GID 0 |
| Capabilities (`CapEff` / `CapBnd`) | none / none | none on the shell / `CAP_DAC_READ_SEARCH` and `CAP_SYS_PTRACE` only (bounding `0x80004`), carried by the interpreter's file capabilities |
| `NoNewPrivs` | 1 | 0 (required for file capabilities) |
| Seccomp | `RuntimeDefault` (mode 2) | `RuntimeDefault` (mode 2) |
| Root filesystem, host mounts | read-only (`touch` fails with `Read-only file system`) | read-only |
| SELinux type | `spc_t` (see below) | `spc_t` |

**SELinux.** CRI-O runs containers that share the host PID namespace with the SELinux type `spc_t`, not `container_t`. The scanner needs that. With the same pod run without `hostPID` (`container_t`), SELinux denies reads under `/host/etc`, and v2.2.0 aborts on the first one ([#229](https://github.com/aclater/pqc-readiness/issues/229)). The SCC, non-root UID, empty capability set, seccomp and read-only mounts are what bound the pod.

**Least privilege for the SCCs.** Both SCCs grant access through their `users:` list, which RBAC queries such as `oc adm policy who-can use scc` and `oc auth can-i` don't see. Check the SCC and the admitted pod directly:

```bash
oc get scc pqc-readiness-services-scc -o jsonpath='{.users}{"\n"}'
# ["system:serviceaccount:pqc-readiness:pqc-readiness-services"]
oc -n pqc-readiness get pods -o custom-columns=POD:.metadata.name,SCC:.metadata.annotations.openshift\\.io/scc
```

## Deployment bugs found and fixed

Each of these broke the documented steps on a fresh cluster. All are fixed in the manifests on this page's branch ([#220](https://github.com/aclater/pqc-readiness/issues/220)).

| Symptom | Cause | Fix |
| --- | --- | --- |
| `oc apply -k deploy/openshift` fails: `namespaces "pqc-readiness" not found` | Nothing created the namespace | `deploy/openshift/namespace.yaml`, with Pod Security Admission labels set to `privileged` (the SCC is the control) |
| DaemonSet creates no pods: `unable to validate against any security context constraint` | The pod requests seccomp `RuntimeDefault`, and an SCC without `seccompProfiles` forbids every profile | `seccompProfiles: [runtime/default]` on the base SCC |
| The probe crashes: `PermissionError: '/var/lib/pqc-readiness/.cache'` | kubelet creates the `hostPath` output directory `root:root 0755`, so UID 1001 can't write it | An `emptyDir` output (256 MiB) in both DaemonSets, pruned after `PQC_RETENTION_DAYS` (7) |
| Report `hostname` and the summary's `node` are the pod name (`pqc-readiness-5mcqv`) | The pod has its own UTS namespace, so `gethostname()` is the pod name | The scanner reads `PQC_HOSTNAME`, then the host's `/etc/hostname` under `--host-mount`; both DaemonSets set `PQC_HOSTNAME` from `spec.nodeName`. Verified live: both paths report `crc` |
| The DaemonSet header told operators to apply `serviceaccount.yaml` and `scc.yaml`, which don't exist | Stale comment | Points at `oc apply -k deploy/openshift` |

## What the node reports

Full scan with the branch build, run inside the services pod with the capability-carrying interpreter: `--host-mount /host` plus every `--scan-*` flag, `--bench --bench-tls --seconds 1`. Then the same scans with `--sarif`, then `--recommend --policy auto`. The [method](#how-this-was-run) has the exact commands.

### Crypto stack and deployment gap

| | |
| --- | --- |
| OpenSSL | Reported as `3.5.8`, native ML-KEM / ML-DSA / SLH-DSA. **That is the scanner image's OpenSSL, not the node's.** The node's `libcrypto`, as linked by sshd and haproxy, is `3.5.5`. Both are PQC-capable, so the verdict holds here. Fixed in [#228](https://github.com/aclater/pqc-readiness/issues/228): run on the same pod and node, the fixed scanner reports `OpenSSL 3.5.5` with `version_source: package` (the node's `openssl-libs`), and leaves the algorithm lists `null` because the CLI is the image's |
| Crypto policy | `DEFAULT`, no subpolicies; PQC disabled for TLS, SSH and IKE |
| OpenSSL default groups | `X25519 secp256r1 X448 secp521r1 secp384r1 ffdhe2048…8192`: no hybrid groups |
| sshd | Offers only classical key exchange (`curve25519-sha256`, ECDH, DH group exchange), although the installed OpenSSH supports `mlkem768x25519-sha256` |
| TLS gap | `capable_not_configured` |
| SSH gap | `capable_not_configured` |
| IPsec gap | `not_present` |
| FIPS | kernel FIPS off |
| Crypto libraries | GnuTLS 3.8.10 (PQC-capable), libgcrypt 1.10.0 and libssh 0.10.4 (no ML-KEM / ML-DSA) |
| Packages | 597, read in-process from the rpm database (`rpmdb-sqlite`) |

On RHEL 9.8 the code can do PQC but the default policy keeps it off, so the node is `capable_not_configured` for both TLS and SSH. That matches the RHEL 9.8 VMs in the [cross-OS matrix](os-matrix-2026-10.md).

### Listening services (`--scan-services`)

122 listeners: 104 Go, 22 OpenSSL, 2 GnuTLS, none unattributed. Most of the Go services are OpenShift's own control plane (kube-rbac-proxy, etcd, CoreDNS, ovnkube, operators).

The SARIF findings on services are the interesting part:

| Rule | Listener | Finding |
| --- | --- | --- |
| [`pqc-012`](../rules/pqc-012-go-service-without-hybrid-mlkem.md) | `[::]:6443` (kube-apiserver) | `tlsmlkem=0` turns hybrid ML-KEM off |
| `pqc-012` | `127.0.0.1:9091` (same container) | `tlsmlkem=0` |
| `pqc-012` | `127.0.0.1:9537`, `192.168.127.2:40993` (`crio.service`) | `tlsmlkem=0`, built with go1.25.14 |
| `pqc-012` | `[::]:9898` | Built with go1.20.12, which has no hybrid key exchange |
| [`pqc-011`](../rules/pqc-011-service-crypto-library-without-pqc.md) | `[::]:9898` | Also links OpenSSL 1.x |

So on this release the API server and the container runtime negotiate classical TLS even though their Go toolchain supports `X25519MLKEM768`. Findings name containers by their `crio-<id>.scope` unit ([#233](https://github.com/aclater/pqc-readiness/issues/233) tracks naming them by pod).

### Certificates, keys and boot chain

| | |
| --- | --- |
| Trust store | 390 CA certificates, all classical ([`pqc-004`](../rules/pqc-004-classical-only-trust-store.md)) |
| Certificates on disk | 396; 74 expired; 255 classical certificates valid past 2030; one pure-PQC CA: `LVFS CA 2025PQ` (ML-DSA-87, `/etc/pki/fwupd/`) |
| Private keys | none readable by the scanner |
| Package-signing keys | 2, both RSA 4096 (Red Hat release key 2, auxiliary key 3) ([`pqc-009`](../rules/pqc-009-classical-package-signing-keys.md)) |
| Boot chain | UEFI, classical chain ([`pqc-030`](../rules/pqc-030-classical-boot-chain.md)); no TPM in the VM |
| Kerberos | crypto-policies config permits SHA-1 enctypes ([`pqc-031`](../rules/pqc-031-kerberos-weak-enctypes.md)) |
| Tunnels, DNSSEC | none configured |

### SARIF findings

16 results across 11 rules:

| Rule | Count |
| --- | ---: |
| [`pqc-012-go-service-without-hybrid-mlkem`](../rules/pqc-012-go-service-without-hybrid-mlkem.md) | 5 |
| [`pqc-013-crypto-library-without-pqc`](../rules/pqc-013-crypto-library-without-pqc.md) | 2 |
| [`pqc-004-classical-only-trust-store`](../rules/pqc-004-classical-only-trust-store.md) | 1 |
| [`pqc-005-slh-dsa-in-tls-context`](../rules/pqc-005-slh-dsa-in-tls-context.md) | 1 |
| [`pqc-008-crypto-policy-blocks-pqc`](../rules/pqc-008-crypto-policy-blocks-pqc.md) | 1 |
| [`pqc-009-classical-package-signing-keys`](../rules/pqc-009-classical-package-signing-keys.md) | 1 |
| [`pqc-010-sshd-pqc-kex-not-offered`](../rules/pqc-010-sshd-pqc-kex-not-offered.md) | 1 |
| [`pqc-011-service-crypto-library-without-pqc`](../rules/pqc-011-service-crypto-library-without-pqc.md) | 1 |
| [`pqc-020-pqc-capable-not-configured`](../rules/pqc-020-pqc-capable-not-configured.md) | 1 |
| [`pqc-030-classical-boot-chain`](../rules/pqc-030-classical-boot-chain.md) | 1 |
| [`pqc-031-kerberos-weak-enctypes`](../rules/pqc-031-kerberos-weak-enctypes.md) | 1 |

The base DaemonSet, with no capabilities, can't read RHCOS's `0600` `sshd_config`, so `pqc-010` only fires from the services overlay. The base report also gives the wrong reason for it ([#232](https://github.com/aclater/pqc-readiness/issues/232)).

### Benchmarks

Single-thread `openssl speed`, 1 s per test, inside the pod (scanner image's OpenSSL 3.5.8):

| Algorithm | Operation | ops/s |
| --- | --- | ---: |
| ML-KEM-768 | encaps / decaps | 46,379 / 28,795 |
| ML-DSA-65 | sign / verify | 1,485 / 8,181 |
| SLH-DSA-SHA2-128s | sign / verify | 4.4 / 4,365 |
| RSA-2048 | sign / verify | 4,686 / 83,459 |
| ECDH (X25519) | derive | 45,175 |

Loopback TLS 1.3 handshakes (`--bench-tls`, 29 per group):

| Group | Handshakes/s | Median TTFB | Bytes on the wire |
| --- | ---: | ---: | ---: |
| `x25519` | 179.3 | 4.75 ms | 1,755 |
| `X25519MLKEM768` | 165.8 | 5.57 ms | 4,476 |
| `MLKEM768` | 162.0 | 5.89 ms | 3,887 |

## Per-node summary and the Compliance Operator

The summary overlay published this ConfigMap after the first probe. The `node` value is from v2.2.0, before the hostname fix; with the fix it is `crc`:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: pqc-readiness-node-crc
  namespace: pqc-readiness
  labels:
    app.kubernetes.io/name: pqc-readiness
    pqc-readiness/summary: node
data:
  node: pqc-readiness-g9xd2
  generated_at: "2026-10-14T09:16:33+00:00"
  schema_version: "1.6"
  verdict: GOOD - production-capable in software
  exit_code: "1"
  gap_tls: capable_not_configured
  gap_ssh: capable_not_configured
  gap_ipsec: not_present
  gap_count: "2"
  gaps: |-
    tls:capable_not_configured
    ssh:capable_not_configured
  capable_not_configured: "2"
  failure_findings: "0"
  findings_by_rule: '{"pqc-005-slh-dsa-in-tls-context": 1, "pqc-008-crypto-policy-blocks-pqc": 1, "pqc-020-pqc-capable-not-configured": 1}'
```

Compliance Operator 1.10.0 was installed from `redhat-operators` (channel `stable`), then `deploy/openshift-summary/compliance-customrule.yaml` was applied unchanged:

```text
customrule.compliance.openshift.io/pqc-readiness-no-node-gaps     Ready
tailoredprofile.compliance.openshift.io/pqc-readiness             READY
scansettingbinding.compliance.openshift.io/pqc-readiness          READY
compliancesuite.compliance.openshift.io/pqc-readiness             DONE    NON-COMPLIANT
compliancecheckresult  pqc-readiness-custom-pqc-readiness-no-node-gaps   FAIL   medium
```

The rule fails because `gap_count` is `"2"`. The passing path (no gaps, no summaries) was not exercised on the cluster; the CEL expression's pass cases are covered by the cel-python tests.

## Image signatures

```bash
cosign verify ghcr.io/aclater/pqc-readiness@sha256:97ccf9a177391b4e0509be3469e55df7529703902e1aa1721e0d74be83e5bb80 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/aclater/pqc-readiness/\.github/workflows/release-images\.yml@'
```

| Image (2.2.0) | Digest | cosign v3.1.3 | SLSA provenance | CycloneDX SBOM attestation |
| --- | --- | --- | --- | --- |
| `pqc-readiness` | `sha256:97ccf9a1…` | verified | verified | verified (133 components) |
| `pqc-readiness-services` | `sha256:fe4d0f3e…` | verified | verified | **missing** ([#230](https://github.com/aclater/pqc-readiness/issues/230)) |

cosign v2 reports `no signatures found` for both images: the release workflow signs with cosign v3, which stores signatures in the new bundle format. Use cosign v3 or newer.

## How this was run

- **Cluster.** `crc setup && crc start` with 8 vCPUs, 24 GiB, OpenShift 4.22.14.
- **Base.** `oc apply -k deploy/openshift`, then `oc -n pqc-readiness rollout status ds/pqc-readiness`.
- **Services overlay.** `oc apply -f deploy/openshift/services/services.yaml`, running alongside the base DaemonSet.
- **Summaries.** `oc apply -k deploy/openshift-summary` (patches the base DaemonSet in place).
- **Compliance Operator.** Namespace `openshift-compliance`, an `OperatorGroup` targeting it, and a `Subscription` to `compliance-operator` from `redhat-operators`; then `oc apply -f deploy/openshift-summary/compliance-customrule.yaml`.
- **Full node scan.** The branch zipapp was streamed into the services pod (`oc exec -i … < dist/pqc-readiness.pyz`; the image has no `tar`, so `oc cp` doesn't work) and run with `/usr/local/libexec/pqc-readiness/python3`, the interpreter that carries the file capabilities:
  `--host-mount /host --json --scan-packages --scan-trust-store --scan-crypto-material --scan-signing-keys --scan-services --scan-boot-chain --scan-crypto-libraries --scan-kerberos --scan-processes --scan-tunnels --scan-dnssec --bench --bench-tls --seconds 1`, then the same scans with `--sarif`, then `--host-mount /host --recommend --policy auto`.
- **Signatures.** `cosign verify` (cosign v3.1.3 container) and `gh attestation verify oci://…` with `--predicate-type https://slsa.dev/provenance/v1` and `https://cyclonedx.org/bom`.
