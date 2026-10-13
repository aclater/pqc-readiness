# pqc-012-go-service-without-hybrid-mlkem

**Default level:** warning. One result per listening Go service.

## What it detects

With `--scan-services`, a listening Go binary (found from its embedded build
information) will not offer the standard hybrid `X25519MLKEM768` key exchange
by default:

- built with Go older than 1.24 (`go.default_hybrid_kex` is `null`, or the
  pre-standard `X25519Kyber768Draft00` on Go 1.23), or
- `tlsmlkem=0` appears in `go.godebug_reverts` (the binary's
  `DefaultGODEBUG` or the process's `GODEBUG` environment variable).

## Why it matters

Go programs carry their own `crypto/tls`; the host's OpenSSL and crypto
policy do not affect them. A service built with an old toolchain stays
classical however modern the OS is. The Kyber draft that Go 1.23 offered does
not interoperate with standard ML-KEM peers.

- Go 1.24 release notes (X25519MLKEM768 on by default; Kyber draft removed),
  **final**: <https://go.dev/doc/go1.24>
- Go 1.23 release notes (X25519Kyber768Draft00): <https://go.dev/doc/go1.23>
- GODEBUG settings (`tlsmlkem`): <https://go.dev/doc/godebug>
- RFC 10024 (`X25519MLKEM768`), **final**: <https://www.rfc-editor.org/rfc/rfc10024>

## Remediation

Rebuild the program with Go 1.24 or later and redeploy; remove
`tlsmlkem=0` from `GODEBUG` (environment, `//go:debug` directives or the
module's `godebug` block) unless an incompatible peer still requires it. On
every distribution the fix is the application's build, not an OS package.
If the program sets `tls.Config.CurvePreferences` explicitly, add
`tls.X25519MLKEM768` there.

## False positives and limitations

- Programs that set `CurvePreferences` themselves may offer ML-KEM even on
  older defaults, or none on newer ones; the scanner reads build information,
  not runtime TLS configuration. Confirm with an endpoint observation
  (`--observations`).
- Binaries without build information (built before Go 1.18) are reported as
  failing, since no such toolchain offered ML-KEM.

## Related

[pqc-011](pqc-011-service-crypto-library-without-pqc.md), [pqc-013](pqc-013-crypto-library-without-pqc.md).
