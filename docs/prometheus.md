# Prometheus metrics (`--prometheus`)

`--prometheus` emits the host report in the Prometheus text exposition
format, for node_exporter's
[textfile collector](https://github.com/prometheus/node_exporter#textfile-collector).
node_exporter reads every `*.prom` file in the directory given by
`--collector.textfile.directory` and exposes the metrics with the rest of
the host's data. The scanner never listens on a port.

```bash
pqc-readiness --prometheus --output /var/lib/node_exporter/textfile_collector/pqc_readiness.prom
```

`--output` replaces the file atomically: it writes a temp file in the same
directory and then renames it. node_exporter therefore never reads a
half-written file, which the textfile collector requires. The file keeps
an existing file's mode; a new file gets `0666 & ~umask`, so node_exporter
running as another user can read it.

## Conventions

- **Gauges only, prefix `pqc_readiness_`.** Each run describes the host's
  current state.
- **Bounded labels only:** `tier`, `protocol`, `kind`, `layer`, `status`,
  `category`, `version`, `schema`. No hostnames, certificate subjects or
  algorithm lists, so cardinality doesn't grow with the fleet.
  node_exporter adds `instance`.
- **Missing means unknown.** A series is omitted, not set to 0, when its
  probe was unavailable (no OpenSSL, `--scan-packages` not given, FIPS
  check skipped). Use `absent()` or `or vector(0)` in queries accordingly.
- **No sample timestamps.** The textfile collector doesn't support them, so
  the run time is its own gauge, `pqc_readiness_last_run_timestamp_seconds`.
- **State sets:** for `*_tier` and `cnsa_2_0_status`, every possible value is
  emitted, and the current one is 1.

## Metrics

| Metric | Labels | Meaning | Present when |
|---|---|---|---|
| `pqc_readiness_info` | `version`, `schema` | Always 1. Scanner version and JSON `schema_version`. | always |
| `pqc_readiness_verdict_tier` | `tier` = excellent / good / marginal / poor | Overall readiness tier, as a state set. | always |
| `pqc_readiness_isa_tier` | `tier` | CPU instruction-set tier, as a state set. | ISA tier known |
| `pqc_readiness_isa_score` | — | Weighted score of PQC-relevant CPU features (JSON `isa_score`). | ISA score known |
| `pqc_readiness_replace_required` | — | 1 when the host can't be made PQC-ready in software: poor ISA, and no PQC silicon or accelerator. | always on a real run |
| `pqc_readiness_openssl_pqc_native` | — | 1 when OpenSSL exposes NIST PQC algorithms natively (3.5+). | OpenSSL found |
| `pqc_readiness_key_exchange_groups` | `protocol` = tls / ssh, `kind` = pure_pqc / hybrid / classical | Number of groups the host's library offers. | OpenSSL / ssh found |
| `pqc_readiness_hybrid_kex_available` | `protocol` = tls / ssh | 1 when at least one hybrid PQC key exchange is offered. | OpenSSL / ssh found |
| `pqc_readiness_nss_pqc_capable` | — | 1 when the installed NSS supports PQC (3.108+). | NSS found |
| `pqc_readiness_fips_mode` | `layer` = kernel / openssl_provider | 1 when FIPS mode is active at that layer. | FIPS probe ran |
| `pqc_readiness_fips_algorithm_fence_engaged` | — | 1 when FIPS mode actually limits OpenSSL to the FIPS provider's algorithms. See [findings/fips-algorithm-fence.md](findings/fips-algorithm-fence.md). | FIPS active in both layers |
| `pqc_readiness_cnsa_2_0_status` | `status` = compliant / partial / non_compliant / unknown | CNSA 2.0 evaluation, as a state set. | CNSA evaluation ran |
| `pqc_readiness_trust_store_certificates` | `category` = classical / hybrid_composite / pure_pqc | Unique trust-store certificates. | `--scan-trust-store` |
| `pqc_readiness_trust_store_truncated` | — | 1 when `--trust-store-max-certs` stopped the scan early. | `--scan-trust-store` |
| `pqc_readiness_packages` | — | Installed packages. | `--scan-packages` |
| `pqc_readiness_bundled_crypto_packages` | — | Installed packages that bundle their own crypto implementation. | `--scan-packages` |
| `pqc_readiness_last_run_timestamp_seconds` | — | Unix time the report was generated. | always |

These describe what the host *can* do (capability). They don't say what a
running service negotiates; see the JSON report and
[scope.md](scope.md) for that distinction.

## Deployment

- **Quadlet:** a quadlet takes one `Exec=`, and `--save` and `--output` are
  mutually exclusive, so metrics come from a sibling unit. See the comment in
  [`deploy/quadlet/pqc-readiness.container`](../deploy/quadlet/pqc-readiness.container).
  Mount the textfile directory with the shared SELinux label (`,z`), because
  node_exporter's container reads it too.
- **OpenShift DaemonSet:** set `PQC_PROM_FILE` and mount the directory
  node_exporter reads. The commented example is in
  [`deploy/openshift/daemonset.yaml`](../deploy/openshift/daemonset.yaml).
  Each loop iteration then also writes metrics; that run skips `--bench`,
  because the metrics don't use benchmark results.
- **Timers / cron on bare metal:** run with `--prometheus --output <dir>/pqc_readiness.prom`
  on the same schedule as the JSON report.

## Example queries

```promql
# Hosts per readiness tier
count by (tier) (pqc_readiness_verdict_tier == 1)

# Share of hosts that can offer hybrid TLS key exchange
avg(pqc_readiness_hybrid_kex_available{protocol="tls"})

# Hosts whose report is older than two days (the timer stopped?)
time() - pqc_readiness_last_run_timestamp_seconds > 2 * 86400

# Hosts that need hardware replacement for PQC
pqc_readiness_replace_required == 1
```

## Grafana

[`grafana/pqc-readiness-dashboard.json`](grafana/pqc-readiness-dashboard.json)
is an importable fleet dashboard: tiers, hybrid TLS/SSH share, replacements,
stale reports, CNSA 2.0 status, trust-store categories and a per-host table.
It is written at dashboard `schemaVersion` 39, which Grafana migrates forward
on import. Every panel query was checked against a real Prometheus scraping
node_exporter's textfile collector.
