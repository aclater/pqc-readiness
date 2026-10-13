# SUSE Multi-Linux Manager custom system info

[`deploy/suse-mlm/push-custom-info.py`](../../deploy/suse-mlm/push-custom-info.py)
stores a host's results as Multi-Linux Manager (upstream: Uyuni) **Custom
System Info** (#157). The values show on the system's page and Salt states
can read them from pillar (`custom_info:<key>`), for example to target PQC
remediation.

```bash
pqc-readiness --json > host.json
pqc-readiness --ndjson > host.ndjson
MLM_URL=https://mlm.example.com/rpc/api MLM_USER=api MLM_PASSWORD=... \
  deploy/suse-mlm/push-custom-info.py host.json host.ndjson
```

It creates any missing keys, finds the system by the report's hostname (or
`--system-name`), and sets:

| Key | Value |
|---|---|
| `pqc_verdict`, `pqc_schema_version`, `pqc_generated_at` | From the report |
| `pqc_gap_tls`, `pqc_gap_ssh`, `pqc_gap_ipsec` | `pqc_deployment_gap` state per protocol |
| `pqc_gap_count` | Number of deployment gaps |
| `pqc_failure_findings` | Findings for software that will fail at PQC (`pqc-011` … `pqc-017`); `not collected` without the NDJSON file |

It uses the XML-RPC API methods `auth.login`, `system.custominfo.listAllKeys`,
`system.custominfo.createKey`, `system.getId`, `system.setCustomValues` and
`auth.logout`, as given in the Uyuni API reference. It needs only the Python
standard library. Credentials come from the environment and are never
printed. TLS verification uses the system trust store, or `MLM_CA_FILE`.

## What was tested

| Check (2026-10-14) | Result |
|---|---|
| Against a local XML-RPC server implementing those methods (`tests/test_suse_custom_info.py`) | Keys created, values set, logout always called, unknown system rejected, password never printed |
| **Against a real Multi-Linux Manager / Uyuni server** | **Not tested** |
