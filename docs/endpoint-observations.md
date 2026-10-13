# Endpoint observations

`pqc-readiness` inspects a host from the inside. It reports what the
host's libraries **can** negotiate and what its policy **allows**. A
network-side tool sees the other half: what an endpoint **actually
negotiated** with a client. `--aggregate DIR --observations FILE` joins
the two (#149), so a fleet rollup can say, per listening service, "the
library supports hybrid ML-KEM and the policy allows it, but a client
was handed X25519 anyway".

This document defines the record format, explains how records are
matched to hosts, and gives guidance for writing an adapter.

## Record format

Schema 1.0, published as JSON Schema in
[`schemas/endpoint-observation-1.0.schema.json`](schemas/endpoint-observation-1.0.schema.json).
A file is either:

- an **envelope** object, whose records inherit its version:

  ```json
  {
    "observation_schema_version": "1.0",
    "observations": [
      {
        "observed_at": "2026-10-13T11:00:00Z",
        "protocol": "tls",
        "fqdn": "web01.example.com",
        "port": 443,
        "negotiated_group": "X25519MLKEM768",
        "certificate_sha256": "…64 hex…",
        "source": {"category": "active-endpoint-scan", "name": "my-adapter", "version": "0.3"}
      }
    ]
  }
  ```

- or **JSON Lines**, one self-describing record per line, each with its
  own `observation_schema_version`.

| Key | Required | Meaning |
| --- | --- | --- |
| `observation_schema_version` | yes, unless inherited from an envelope | `MAJOR.MINOR`. This scanner reads `1.x`. |
| `observed_at` | yes | RFC 3339 date-time with an offset. |
| `protocol` | yes | `tls`, `ssh` (TCP); `quic`, `dtls`, `ikev2` (UDP). |
| `transport` | no | `tcp` / `udp`. If present it must agree with `protocol`. |
| `fqdn` | `fqdn` or `ip` | DNS name the tool connected to. |
| `ip` | `fqdn` or `ip` | IPv4 or IPv6 address the tool connected to. |
| `port` | yes | 1–65535. |
| `sni` | no | TLS `server_name` sent, when it differs from `fqdn` or only `ip` is known. |
| `negotiated_group` | no | TLS/QUIC/DTLS named group (IANA name, or codepoint such as `0x11EC`); SSH key exchange method; IKEv2 initial key exchange. Without it the record joins but is classed `unknown`. |
| `additional_key_exchanges` | no | IKEv2: RFC 9370 additional key exchanges (e.g. `mlkem768`). |
| `offered_groups` | no | Groups the endpoint accepted when probed. Informational. |
| `tls_version` | no | Negotiated TLS version. Informational. |
| `certificate_sha256` | no | SHA-256 of the leaf certificate DER. Secondary join key. |
| `id` | no | The producer's own identifier, echoed in the output. |
| `source` | yes | `{category, name?, version?}`; see below. |
| `x-*` | no | Producer extensions, always allowed and ignored. |

`source.category` describes the kind of evidence, so consumers can weigh
it without the repository naming any product:

| Category | Kind of producer |
| --- | --- |
| `active-endpoint-scan` | A tool that connected to the endpoint and recorded the handshake. |
| `passive-network-sensor` | A sensor that observed handshakes on the wire. |
| `edge-or-proxy-log` | A CDN, load balancer or reverse proxy logging what it negotiated with the origin or client. |
| `client-telemetry` | Clients reporting the groups their connections used. |
| `manual` | Hand-entered or one-off `openssl s_client` style checks. |

Within major version 1, new minor versions only add optional keys: a
`1.1` record with a key this scanner doesn't know is accepted and the
key ignored. A `2.x` file is rejected.

## How records are matched

Each valid record is matched to at most one host report, trying the
strongest key first:

1. **`fqdn`** equals the report's `hostname` (case-insensitive, trailing dot ignored).
2. **`sni`** equals the report's `hostname`.
3. **`ip`** equals the address of a listener bound to a *specific*
   address in that host's `service_crypto_linkage`.
4. **Short name**: the first label of `fqdn` or `sni` equals the first
   label of the report's `hostname`.
5. **`certificate_sha256`** matches a certificate found on the host
   (`crypto_material` or `trust_store` certificates).

When a tier finds more than one host, the certificate fingerprint is used
to narrow it (basis `fqdn+certificate`, etc.). If that doesn't leave
exactly one, the record is `ambiguous` and lists the candidates; it is
never attributed to a guess.

On the matched host, the record is joined to a listener from
`--scan-services` with the same transport and port, bound to a wildcard
or specific address (a specific bind must be on the observed `ip`). A
listener in another network namespace still matches, with a note that it
is reachable only through port mapping. Loopback-only listeners never
match.

Each matched endpoint gets three labels, plus the deployment-gap `state`
derived from the first two by the same rules as the host's own
`pqc_deployment_gap` (#107), so an endpoint's state can't disagree with its
host's:

- **capable**: for TLS, QUIC and DTLS, the listener's crypto library
  version ships hybrid ML-KEM, or it is a Go binary whose default offers
  it. For SSH, the host's OpenSSH lists an ML-KEM key exchange. For IKEv2,
  the IPsec stack supports ML-KEM.
- **configured**: TLS uses the system crypto policy (`crypto_policy.pqc_enabled.tls_key_exchange`),
  falling back to the OpenSSL default groups, except for Go listeners,
  which ignore the system policy. SSH uses sshd's effective
  `KexAlgorithms` (`sshd.pqc_offered`), falling back to the policy's
  server setting. IKEv2 uses whether any configured connection offers ML-KEM.
  These are host defaults, not per-service settings.
- **observed**: `pure_pqc`, `hybrid`, `classical` or `unknown`, from
  `negotiated_group`.

The rollup counts endpoints per `{protocol, state, observed}`
(`observations.by_gap_state`). The combinations that need attention:
`deployed` but observed `classical` (a client, proxy or per-application
setting is holding it back) and `capable_not_configured` observed
`classical` (the configuration gap is live on the wire).

An observation made more than `--observations-max-age-days` (default 7)
before or after the matched host's report is flagged `stale`. It is still
joined, but a consumer should not treat it as current evidence.

The rollup format is documented under
[`--aggregate` observations join](json-output.md#--aggregate-observations-join).

## Writing an adapter

Keep adapters outside this repository: they convert one tool's output
into records and nothing else. By category:

- **Active endpoint scanners:** emit one record per target and port, using
  the name you connected to as `fqdn`, the `server_name` you sent as
  `sni`, and the group the server selected as `negotiated_group`. If the
  tool enumerated accepted groups, put them in `offered_groups` too.
  Include the leaf certificate's SHA-256; it rescues matches when DNS
  names differ from hostnames.
- **Passive sensors and proxy logs:** use the server's address as `ip`,
  the SNI from the ClientHello as `sni`, and the timestamp of the
  handshake as `observed_at`.
- **SSH:** set `protocol: ssh` and the agreed key exchange method as
  `negotiated_group`.
- **IKEv2:** set the initial key exchange as `negotiated_group` and any
  RFC 9370 additional exchanges in `additional_key_exchanges`.

Validate output against the JSON Schema before handing it over;
`--aggregate` also lists any record it rejects, with the reason, under
`observations.invalid`.

## Limitations

- Reports carry no list of the host's interface addresses, so an
  `ip`-only record matches only a listener bound to that specific
  address. Most services bind the wildcard, so include `fqdn` or `sni`,
  or the certificate fingerprint, whenever you have them.
- "Configured" reflects host-wide defaults. Per-service settings (an
  `httpd` `SSLOpenSSLConfCmd Groups`, an `sshd` `KexAlgorithms` line) are
  not read yet; sshd's effective configuration is #105.
- The join reads `service_crypto_linkage`, so hosts need
  `--scan-services`. Without it, records match the host
  (`no_service_scan`) but not a listener.
