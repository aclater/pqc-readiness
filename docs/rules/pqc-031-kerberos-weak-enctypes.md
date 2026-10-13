# pqc-031-kerberos-weak-enctypes

**Default level:** warning (note when only 128-bit enctypes or PKINIT are the concern)

## What it detects

`--scan-kerberos` read the host's Kerberos configuration and keytabs and
found at least one of:

- **Deprecated enctypes (warning):** DES, 3DES or RC4 enctypes are allowed
  by `permitted_enctypes` / `default_tkt_enctypes` / `default_tgs_enctypes`
  or a KDC's `supported_enctypes`, or exist as keytab keys. With no
  `permitted_enctypes` set, MIT krb5's built-in default still includes
  `des3-cbc-sha1` and `arcfour-hmac`, and the finding says so.
- **128-bit enctypes (note):** AES-128 or Camellia-128 enctypes are
  permitted, or the keytab holds only 128-bit keys.
- **Classical PKINIT (note):** a PKINIT identity is configured. PKINIT
  uses RSA or (EC)DH today.

## Why it matters

Kerberos tickets and keys are symmetric, so the quantum risk is Grover's
algorithm: a 128-bit key keeps about 64-bit security. Deprecated enctypes
are weak against classical attacks already.

- IANA Kerberos Encryption Type Numbers, **final**: DES and RC4-export
  deprecated by RFC 6649; 3DES and RC4 by RFC 8429.
  <https://www.iana.org/assignments/kerberos-parameters/>
- CNSA 2.0 (NSA, **final**): AES-256 is the only approved symmetric cipher:
  <https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF>
- Post-quantum PKINIT: **individual Internet-Draft only**
  (draft-bokovoy-kitten-pkinit-pqc), not an IETF standard.

## Remediation

- **RHEL family and Fedora:** the system crypto policy writes
  `/etc/crypto-policies/back-ends/krb5.config`. `FUTURE` (or a custom
  subpolicy) drops 128-bit enctypes; `DEFAULT` already removes DES / 3DES
  / RC4. Re-key keytabs afterwards (`ipa-getkeytab` / `kadmin ktadd -e`)
  so old-enctype keys are gone.
- **Other distributions:** set
  `permitted_enctypes = aes256-cts-hmac-sha384-192 aes256-cts-hmac-sha1-96`
  in `[libdefaults]`, and the matching `supported_enctypes` on the KDC,
  then re-key service principals.
- **Active Directory realms:** check `msDS-SupportedEncryptionTypes` on
  the service accounts before removing RC4 / AES-128, or authentication
  to those services will fail.
- **PKINIT:** no post-quantum replacement is standardised yet; track the
  IETF kitten working group and keep PKINIT certificates short-lived.

## False positives and limitations

- `allowed` is what the configuration permits, not what the KDC actually
  issues. A deprecated enctype the KDC never uses is still flagged, because
  permitting it allows downgrades.
- Keytabs are root-only; without root they are listed as unreadable and
  their enctypes aren't counted.
- Heimdal-specific settings are read with MIT's rules.

## Related

[pqc-008](pqc-008-crypto-policy-blocks-pqc.md).
