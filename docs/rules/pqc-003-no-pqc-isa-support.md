# pqc-003-no-pqc-isa-support

**Default level:** warning

## What it detects

`replace_required` is true. The host's ISA tier is `poor`, and no dedicated
PQC silicon or PQC-capable accelerator (HSM, network HSM, offload engine)
was detected.

The finding carries `isa:tier`, `isa:score` and `isa:reason`.

## Why it matters

ML-KEM and ML-DSA are practical in software on hosts with modern SIMD
(AVX2/AVX-512 on x86_64, ARMv8 crypto extensions, CPACF on s390x). On a
`poor` host, software PQC is too slow for production handshake or signing
rates. Without an accelerator the host can't be made PQC-ready by software
changes alone, so plan a hardware refresh or offload.

- NIST IR 8547, deprecation of quantum-vulnerable algorithms, **draft**:
  <https://csrc.nist.gov/pubs/ir/8547/ipd>. Its timeline sets the refresh
  horizon.

## Remediation

These steps are the same on every distribution, because the limit is the
hardware:

- Confirm with `--bench` (OpenSSL microbench) and `--bench-tls` (loopback
  handshake). The verdict uses measured rates when a benchmark ran.
- Plan replacement, or move the workload to hardware with a better ISA tier.
- Alternatively, offload PQC to an HSM or accelerator that supports ML-KEM
  / ML-DSA. The scanner then detects it, and the finding clears.

## False positives and limitations

- In a VM the guest may see a reduced CPU flag set. Check the hypervisor's
  CPU model (for example host-passthrough) before concluding the hardware
  is unsuitable.
- Accelerators that the scanner doesn't recognise are not counted.

## Related

`isa_tier`, `isa_score` and `isa_reason` in the [JSON reference](../json-output.md#top-level-keys).
