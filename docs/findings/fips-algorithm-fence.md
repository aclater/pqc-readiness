# FIPS mode does not always engage an algorithm fence

## Summary

A 12-VM fleet test (three minor versions across the RHEL-family distros, two arches' worth of distros, six combinations × two FIPS states) showed that the kernel `fips=1` flag and a FIPS-preset crypto-policy do *not*, by themselves, gate which cryptographic algorithms are reachable through the public OpenSSL interface. The gating is supplied by downstream patches in the OpenSSL build itself. Distros that rebuild from upstream sources without inheriting those patches expose the full upstream algorithm set — including PQC algorithms that are not part of the active FIPS provider's validated list — even with FIPS mode active and the FIPS provider loaded.

## Observed behavior

In FIPS-active configurations (kernel `fips=1`, FIPS provider loaded with `status: active`, crypto-policy `FIPS`), the count of PQC algorithms reachable via `openssl list ... -provider default` differed by build origin:

| OpenSSL build origin | PQC KEMs visible | PQC signature algorithms visible | X25519MLKEM768 hybrid TLS group |
| --- | ---: | ---: | --- |
| Distro that ships downstream FIPS-provider gating patches | 0 | 0 | not reachable |
| Distro that rebuilds from upstream sources without those patches | 3 | 15 | reachable |

The "rebuild" rows expose ML-KEM, the full ML-DSA suite, and the full SLH-DSA SHAKE/SHA2 suite via the *default* provider while FIPS is active. These algorithms are not part of any FIPS 140-3 validated module's algorithm boundary as of this writeup; the operator's expectation that FIPS mode prevents non-validated algorithm calls is not what the system enforces.

## Mechanism

OpenSSL 3.x splits cryptographic implementations into providers. The FIPS provider is a separately-built shared library whose algorithm list is fixed at build time to the set the validation covers. The default provider exposes whatever is compiled in.

Two distinct things are commonly conflated as "FIPS mode":

1. **FIPS mode active.** Kernel `fips_enabled=1`, `update-crypto-policies --set FIPS`, FIPS provider loaded with `status: active`. This is the state most operators check.
2. **Algorithm fence engaged.** The default provider's reachable algorithm list is restricted to (a subset of) the FIPS provider's list. Calls to non-validated algorithms via the public interface fail or are not exposed.

Upstream OpenSSL ships (1) but not (2). Downstream RHEL OpenSSL applies a series of patches — most notably restricting the algorithms registered through the default provider when FIPS mode is active — that produce (2). Distros that rebuild from RHEL's sources but do not carry those patches inherit (1) without (2).

The kernel `fips=1` flag and the crypto-policy preset are independent of provider construction. They affect kernel crypto and policy-driven defaults; they do not modify which algorithms a provider exposes.

## Implication

An application running on a build without the gating patches can call PQC algorithms (ML-KEM, ML-DSA, SLH-DSA) successfully while the host self-reports FIPS mode active. Whether this constitutes a compliance violation is a question for the operator's compliance authority — FIPS 140-3 module validation is about the module, not the surrounding distribution. But there is a meaningful gap between what an operator asserting "this fleet runs in FIPS mode" usually intends and what the system actually enforces. The gap is invisible without explicitly enumerating the default provider's algorithm list and comparing it against the FIPS provider's.

## Reproduction

Tooling and infrastructure: the [`distro-matrix`](https://github.com/aclater/distro-matrix) `spawn-fleet.sh` script with `--fips` boots the fleet and emits an Ansible inventory. The fleet manifest used here:

```
# alias    count
rhel-10    1
rebuild-distro-10  1
```

Run, where `<rebuild-alias>` is the alias for a distro that rebuilds from upstream sources without the downstream FIPS-provider gating patches:

```bash
./scripts/spawn-fleet.sh \
  --manifest fleet.tsv \
  --memory 18432 \
  --vcpus 2 \
  --fips \
  --workdir ./fleet-fips/

ansible -i ./fleet-fips/inventory.ini all -m script \
  -a "./pqc_readiness.py --json" > raw.json

# Then inspect each host's report:
jq '.fips, [.openssl.kems_pqc | length], [.openssl.signatures_pqc | length]' \
  ./fleet-fips/<host>/result.json
```

Expected output on the RHEL host: `kems_pqc` length 0, `signatures_pqc` length 0, `fips.openssl_provider: true`. Expected output on the rebuild host: `kems_pqc` length 3, `signatures_pqc` length 15, `fips.openssl_provider: true`.

Bypassing the fleet entirely, the divergence reproduces in one shell on either host once FIPS is active:

```bash
diff \
  <(openssl list -kem-algorithms -provider fips    | sort) \
  <(openssl list -kem-algorithms -provider default | sort)
```

On a host with the gating patches the diff is empty (or only contains FIPS-validated algorithms in both columns). On a rebuild host the default-provider column lists ML-KEM-512/768/1024 in addition to the FIPS-provider's set.

## Mitigation

Three options, in increasing order of operational invasiveness:

1. **Run `pqc_readiness.py --fips-strict`.** This enumerates the FIPS provider's algorithm list and the default provider's algorithm list with FIPS active and exits non-zero (rc=4) if the latter is a strict superset of the former. Use it as a CI gate or fleet check rather than relying on `fips_enabled=1` alone.
2. **Run on a distribution that ships the downstream FIPS-provider gating patches.** RHEL is the reference; verify per-release before assuming a given build carries them.
3. **Audit the application's algorithm calls explicitly.** If the application is the only consumer of OpenSSL on the host, gating at the application layer (allowlist of algorithm OIDs / TLS groups) is independent of what the provider exposes. This is the most invasive option and the most reliable; it does not rely on the distribution or OpenSSL build for enforcement.

Whether any of these are required depends on the operator's compliance regime and threat model. The point of this finding is that the choice exists and is not visible by inspecting `fips_enabled` alone.

## References

- NIST FIPS 140-3 (validation framework): https://csrc.nist.gov/pubs/fips/140-3/final
- OpenSSL provider model: https://docs.openssl.org/3.5/man7/provider/
- IANA TLS Supported Groups (X25519MLKEM768 et al.): https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8
- `pqc_readiness.py --fips-strict` design and rationale: tracked in repository issues; see the README's CLI flags section.
