# Sending `--ndjson` findings to a SIEM

`--ndjson` writes one JSON event per line (#146):
- one OCSF **Device Inventory Info** event (class 5001) per host;
- one OCSF **Compliance Finding** event (class 2003) per matched rule.

The field reference is in [json-output.md](json-output.md#--ndjson-events).
The scanner only writes a file (or stdout). Shipping it is left to the
collector you already run, so the scanner needs no credentials and no
outbound network access.

```bash
pqc-readiness --ndjson --output /var/lib/pqc-readiness/findings.ndjson
```

`--output` replaces the file atomically. Point a file-tailing collector at
it, or ship it after each run from the quadlet timer or DaemonSet.

Two IDs matter downstream:
- **`finding_info.uid`** is stable for a host + rule across runs. Use it
  to deduplicate and to correlate tickets; it is identical to the
  `--sarif-anchor` fingerprint.
- **`metadata.uid`** identifies one emitted event. Use it to drop
  duplicates if a file is shipped twice.

The recipes below show each platform's ingestion shape. They follow the
vendors' documentation as of 2026-10-13 but have **not** been run against
live tenants; check limits for your plan.

## Splunk (HTTP Event Collector)

HEC's event endpoint takes an envelope with `time` (epoch **seconds**),
`host`, `source`, `sourcetype`, optional `index`, and the payload in
`event`. Wrap each line:

```bash
jq -c '{time: (.time / 1000), host: .device.hostname, source: "pqc-readiness",
        sourcetype: "pqc_readiness:ocsf", event: .}' findings.ndjson |
  curl -sS "https://splunk.example.com:8088/services/collector/event" \
       -H "Authorization: Splunk $HEC_TOKEN" --data-binary @-
```

HEC accepts several envelopes concatenated in one request body. Suggested
search-time fields: `class_uid`, `severity`, `compliance.control`,
`finding_info.uid`.

## Microsoft Sentinel (Logs Ingestion API)

The Logs Ingestion API takes a JSON **array** per call (1 MB maximum per
call), routed by a data collection rule (DCR) into a custom table. The
table name must end in `_CL`. The calling identity needs the *Monitoring
Metrics Publisher* role on the DCR.

DCR excerpt: the stream declaration, plus a transform into a
`PqcReadiness_CL` table.

```json
{
  "streamDeclarations": {
    "Custom-PqcReadiness": {
      "columns": [
        {"name": "time", "type": "long"},
        {"name": "class_uid", "type": "int"},
        {"name": "severity", "type": "string"},
        {"name": "message", "type": "string"},
        {"name": "device", "type": "dynamic"},
        {"name": "finding_info", "type": "dynamic"},
        {"name": "compliance", "type": "dynamic"},
        {"name": "metadata", "type": "dynamic"},
        {"name": "unmapped", "type": "dynamic"}
      ]
    }
  },
  "dataFlows": [{
    "streams": ["Custom-PqcReadiness"],
    "destinations": ["workspace"],
    "outputStream": "Custom-PqcReadiness_CL",
    "transformKql": "source | extend TimeGenerated = unixtime_milliseconds_todatetime(time), Hostname = tostring(device.hostname), Control = tostring(compliance.control), FindingUid = tostring(finding_info.uid)"
  }]
}
```

Send a batch:

```bash
jq -s -c '.' findings.ndjson |
  curl -sS -X POST \
    "$DCE/dataCollectionRules/$DCR_IMMUTABLE_ID/streams/Custom-PqcReadiness?api-version=2023-01-01" \
    -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" --data-binary @-
```

`$TOKEN` is an Entra ID token for `https://monitor.azure.com`.

## Elastic (ECS)

Ship the file with a log-file input (for example Elastic Agent's custom
logs integration) that parses each line as JSON. Then map the OCSF fields
to ECS in an ingest pipeline. Mapping, with field names checked against
ECS 9.5.0:

| OCSF field | ECS field | Notes |
|---|---|---|
| `time` | `@timestamp` | Milliseconds since the epoch. |
| `device.hostname` | `host.name` | |
| `device.os.name` | `host.os.full` | |
| `message` | `message` | |
| `severity_id` | `event.severity` | Numeric. |
| `metadata.uid` | `event.id` | One emitted event. |
| `class_uid` 5001 / 2003 | `event.kind` | `asset` / `state` (a posture finding, not an alert). |
| class 5001 / 2003 | `event.category` | `host` / `configuration`; `event.type`: `info`. |
| `compliance.control` | `rule.id`, `rule.name` | |
| `finding_info.uid` | `rule.uuid` | Stable per host + rule. |
| `finding_info.desc` | `rule.description` | |
| `finding_info.src_url` | `rule.reference` | |
| `metadata.product.name` / `vendor_name` | `observer.product` / `observer.vendor` | |

ECS has no field for a PQC key-exchange group, so keep `unmapped` as an
object field (for example `pqc_readiness.*`) for dashboards.

```json
{
  "description": "pqc-readiness OCSF NDJSON -> ECS",
  "processors": [
    {"date": {"field": "time", "formats": ["UNIX_MS"], "target_field": "@timestamp"}},
    {"set": {"field": "host.name", "copy_from": "device.hostname"}},
    {"set": {"field": "host.os.full", "copy_from": "device.os.name", "ignore_empty_value": true}},
    {"set": {"field": "event.severity", "copy_from": "severity_id"}},
    {"set": {"field": "event.id", "copy_from": "metadata.uid"}},
    {"set": {"field": "event.kind", "value": "asset", "if": "ctx.class_uid == 5001"}},
    {"set": {"field": "event.kind", "value": "state", "if": "ctx.class_uid == 2003"}},
    {"set": {"field": "event.category", "value": ["host"], "if": "ctx.class_uid == 5001"}},
    {"set": {"field": "event.category", "value": ["configuration"], "if": "ctx.class_uid == 2003"}},
    {"set": {"field": "event.type", "value": ["info"]}},
    {"set": {"field": "rule.id", "copy_from": "compliance.control", "ignore_empty_value": true}},
    {"set": {"field": "rule.name", "copy_from": "compliance.control", "ignore_empty_value": true}},
    {"set": {"field": "rule.uuid", "copy_from": "finding_info.uid", "ignore_empty_value": true}},
    {"set": {"field": "rule.description", "copy_from": "finding_info.desc", "ignore_empty_value": true}},
    {"set": {"field": "rule.reference", "copy_from": "finding_info.src_url", "ignore_empty_value": true}},
    {"set": {"field": "observer.product", "copy_from": "metadata.product.name"}},
    {"set": {"field": "observer.vendor", "copy_from": "metadata.product.vendor_name"}},
    {"rename": {"field": "unmapped.pqc_readiness", "target_field": "pqc_readiness", "ignore_missing": true}}
  ]
}
```

## OCSF-native destinations

Destinations that ingest OCSF directly can take the lines as-is. The
events validate against the OCSF 1.9.0 schemas for classes 2003 and 5001
(base classes, no profiles), and CI checks this.
