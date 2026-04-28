# pqc-readiness

Host-level Post-Quantum Cryptography readiness assessment.

`pqc-readiness` inspects a host and reports whether it can run NIST PQC
primitives (ML-KEM, ML-DSA, SLH-DSA) at production speed in software, or
whether it requires a dedicated cryptographic accelerator. Output is a
stable JSON schema designed for fleet inventory aggregation.

## Audience

Field architects and customer infrastructure teams. The tool is intended
for use during EU MoD / NATO and other regulated-environment PQC
migration engagements. It runs on bare metal RHEL 8/9/10, in containers
(podman/quadlet), and as a privileged DaemonSet on OpenShift.

## What it detects

1. **CPU instruction-set support for PQC** — AVX-512 family (VBMI/IFMA/
   VAES/GFNI) on x86_64; ARMv8 crypto extensions (SHA-3, SVE2, I8MM) on
   aarch64; CPACF MSA8/MSA9 and Crypto Express level on s390x.
2. **Cryptographic accelerators** — PCI HSMs (Marvell, Thales Luna,
   Utimaco, IBM CEX), DPUs (BlueField, IPU, Pensando), TPMs, network
   HSMs detected by client config, AWS Nitro, Intel QAT.
3. **OS / library plumbing** — `/proc/crypto` hardware drivers, kernel
   TLS, kernel FIPS mode, OpenSSL ≥ 3.5 PQC algorithms and TLS 1.3
   hybrid groups, OpenSSH `ssh -Q kex`, strongSwan algorithm list, NSS.
4. **Production suitability** — per-algorithm tier with measured
   throughput, host capacity estimate, and a top-level `replace_required`
   flag for fleet planning.

## Quick start

```bash
./pqc_readiness.py                    # human-readable report
./pqc_readiness.py --bench            # include OpenSSL microbench
./pqc_readiness.py --json             # stable JSON for aggregation
./pqc_readiness.py --markdown         # markdown for tickets
./pqc_readiness.py --ansible          # ansible_facts wrapper
./pqc_readiness.py --aggregate ./out  # roll up many --save outputs
```

## Container / OpenShift

See `deploy/quadlet/pqc-readiness.container` for a systemd quadlet, and
`deploy/openshift/daemonset.yaml` for a fleet DaemonSet. The container
image builds on `registry.access.redhat.com/ubi10/ubi-minimal` and runs
as a non-root user with read-only host mounts.

## License

Apache-2.0. See `LICENSE`.
