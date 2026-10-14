# pqc-018-pqc-capability-undetermined

**Default level:** note. One result per subject.

## What it detects

Software the scanner found but cannot judge from the evidence it has:

- a listening service's crypto library whose family has no verified PQC
  version threshold yet (`library_pqc_capable` is `null`);
- an installed library with no readable file whose PQC support depends on
  build options (GnuTLS, wolfSSL), or with no version;
- a JDK or Go install without a readable version;
- an IPsec connection whose IKE proposals rely on the implementation's
  default key exchange;
- an offline `--root` tree with no OpenSSL library package;
- a WireGuard config, OpenVPN config or DNSSEC signing config
  (`named.conf`) that couldn't be read. These are root-only on common
  distributions, and an unread config is not evidence that nothing is
  exposed.

## Why it matters

Silence would read as "fine". Reporting the gap keeps the inventory honest:
these need a manual check before a migration plan counts them as PQC-ready.

## Remediation

Check the subject by hand: the library's changelog or `strings` output for
`ML-KEM` / `MLKEM` names, the IPsec daemon's documented default proposals,
the image's OpenSSL, or the unreadable config (re-run the scan as root).
Making the configuration explicit (for example an explicit IKE proposal)
turns this into a definite result on the next scan.

## False positives and limitations

By design this rule never says something fails; it only says the scanner
could not tell.

## Related

[pqc-011](pqc-011-service-crypto-library-without-pqc.md), [pqc-013](pqc-013-crypto-library-without-pqc.md),
[pqc-016](pqc-016-ipsec-classical-only-ike.md).
