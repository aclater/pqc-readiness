# pqc-006-no-network-hsm-pqc-firmware

**Default level:** warning

## What it detects

A network-attached HSM client integration is installed (found through its
client configuration), but the appliance isn't flagged as PQC-capable. The
finding lists the detected integrations.

## Why it matters

Workloads that keep keys in an HSM can only move to ML-KEM / ML-DSA keys
once the appliance firmware and client libraries support them. Firmware
upgrade cycles on HSM appliances are long and change-controlled.

- FIPS 203 / 204 / 205, **final**.
- CNSA 2.0 timeline (NSA, **final**):
  - software/firmware signing: support and prefer CNSA 2.0 algorithms by
    2025, use them exclusively by 2030;
  - traditional networking equipment: support and prefer by 2026, use
    exclusively by 2030.

  Source: <https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF>

## Remediation

These steps are the same on every distribution:

- Check the appliance vendor's firmware release notes for ML-KEM / ML-DSA
  support and FIPS 140-3 validation status.
- Upgrade the client libraries and PKCS#11 module on hosts to versions
  that expose the PQC mechanisms.
- Re-run the scan. The finding clears once the integration reports PQC
  capability.

## False positives and limitations

- The scanner reads client configuration, not the appliance. A PQC-capable
  appliance whose client doesn't advertise it will still trigger the rule.

## Related

[pqc-003](pqc-003-no-pqc-isa-support.md).
