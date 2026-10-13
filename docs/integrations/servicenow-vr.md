# ServiceNow Vulnerability Response

This recipe feeds pqc-readiness findings into ServiceNow Vulnerability
Response (VR). Each finding becomes a Vulnerable Item on the host's CI,
and the same Vulnerable Item is updated on later runs. It uses only the
platform's documented import path: an import set table, the Import Set
REST API, and a transform map. No ServiceNow app is required.

> **Test status.** No ServiceNow instance was available. The converter
> (`deploy/servicenow/ndjson_to_import_set.py`) is tested against real
> `--ndjson` output (`tests/test_servicenow_import_set.py`). The import
> set, transform map and `onBefore` script below follow ServiceNow's
> published documentation, cited inline, but have **not** been run on an
> instance. Try them on a sub-production instance first.

## How the pieces fit

```
pqc-readiness --ndjson ──► ndjson_to_import_set.py ──► POST /api/now/import/u_pqc_readiness_import/insertMultiple
                                                          │
                                                 transform map (coalesce on u_correlation_id)
                                                          ▼
                       sn_vul_third_party_entry (one per rule) ◄── sn_vul_vulnerable_item (one per host + rule + subject)
```

- **Third-Party Vulnerability Entry** (`sn_vul_third_party_entry`): one
  per pqc-readiness rule, e.g. `pqc-011-service-crypto-library-without-pqc`.
  This is the "vulnerability" definition. Its description and link come
  from the rule.
- **Vulnerable Item** (`sn_vul_vulnerable_item`): one per finding.
  `finding_info.uid` from the NDJSON event is the correlation ID. It is
  stable for host + rule (+ subject, for per-service and per-library
  rules such as `pqc-011` to `pqc-017`) across runs, so a re-import
  updates the item instead of opening a new one. The same ID is the
  SARIF `partialFingerprints` value with `--sarif-anchor`.
- **Configuration item:** matched on hostname. Use your CMDB's
  identification rules if hostnames aren't unique.

ServiceNow's own third-party VR integrations work the same way: import
set tables plus transform maps, with an `onBefore` script that creates
the Third-Party Entry and Detection records when they don't exist. See
the field mappings in ServiceNow's published VR integration references
(`markdown/security-management/vulnerability-response/` in the
ServiceNow/ServiceNowDocs repository).

## 1. Staging table

Create an import set table (it extends `sys_import_set_row`) named
`u_pqc_readiness_import` with these string columns. The converter fills
exactly these names:

| Column | From the NDJSON finding event |
|---|---|
| `u_correlation_id` | `finding_info.uid`: coalesce key, stable across runs |
| `u_rule_id` | `compliance.control`, e.g. `pqc-010-sshd-pqc-kex-not-offered` |
| `u_title` | `finding_info.title` |
| `u_description` | `finding_info.desc` |
| `u_message` | `message`: the host-specific detail, e.g. which service and library |
| `u_rule_url` | `finding_info.src_url`: the rule page under `docs/rules/` |
| `u_severity` / `u_severity_id` | OCSF `severity` / `severity_id` |
| `u_status` | `compliance.status` |
| `u_hostname` | `device.hostname` |
| `u_os` | `device.os.name` |
| `u_last_found` | event `time`, as `yyyy-MM-dd HH:mm:ss` UTC |
| `u_scanner_version` | `metadata.product.version` |
| `u_event_uid` | `metadata.uid`: per run, for de-duplicating replays |
| `u_properties` | `unmapped.pqc_readiness.properties`, as compact JSON |

The Import Set API "accepts only name-value pairs of String data types"
(ServiceNow Import Set API reference), so the converter sends every
value as a string. Lists and objects are JSON-encoded.

By default `insertMultiple` maps request keys to column **labels**. To
map by column name as the converter sends them, add an entry for the
staging table in **REST Insert Multiples** `[sys_rest_insert_multiple]`
with **Column mapping** set to *Column name*. That is per the same
reference.

## 2. Send the findings

```bash
pqc-readiness --ndjson --scan-services --scan-crypto-libraries \
              --output /var/lib/pqc-readiness/findings.ndjson

python3 deploy/servicenow/ndjson_to_import_set.py /var/lib/pqc-readiness/findings.ndjson |
while read -r body; do
  curl -sS --fail -u "$SN_USER:$SN_PASSWORD" \
       -H 'Content-Type: application/json' -H 'Accept: application/json' \
       -X POST "https://$SN_INSTANCE.service-now.com/api/now/import/u_pqc_readiness_import/insertMultiple" \
       --data-binary "$body"
done
```

- Each output line is one request body, `{"records": [...]}`, with up to
  100 rows by default (`--batch N`).
- Access is BasicAuth or your instance's OAuth. Table ACLs are enforced,
  per the Import Set API's security notes. Use a dedicated integration
  user that can only write this staging table.
- Keep credentials out of the repository and of quadlet files. Read them
  from a root-only environment file or a secrets manager.

## 3. Transform map (`u_pqc_readiness_import` → `sn_vul_vulnerable_item`)

| Source field | Target field | Notes |
|---|---|---|
| `u_correlation_id` | a correlation field on the VIT (e.g. a custom `u_pqc_correlation_id`, or your instance's source-ID field) | **Coalesce = true** |
| `u_hostname` | `cmdb_ci` | Reference lookup on the CI's name or FQDN |
| `u_last_found` | `last_found` | |
| `u_message` | work notes or a description field | Host-specific detail |
| `u_severity` | your risk or severity input | Map to your VR scoring; pqc-readiness severities are OCSF levels |

An `onBefore` script ensures the Third-Party Entry exists and links it.
This is untested; adapt the field names to your VR version:

```javascript
(function runTransformScript(source, map, log, target) {
  var entry = new GlideRecord('sn_vul_third_party_entry');
  if (!entry.get('id', source.u_rule_id)) {
    entry.initialize();
    entry.setValue('id', source.u_rule_id);
    entry.setValue('name', source.u_title);
    entry.setValue('summary', source.u_description);
    entry.insert();
  }
  target.setValue('vulnerability', entry.getUniqueValue());
})(source, map, log, target);
```

## 4. Closing fixed findings

When a host is remediated, the finding simply stops appearing. There's
no "fixed" event. Two options:
- Use your VR configuration that closes Vulnerable Items not re-found
  within N days, keyed on `last_found`. Run the scanner on a fixed
  schedule (quadlet timer, DaemonSet) so `last_found` stays meaningful.
- Or, after each host's import, close that host's items from this source
  whose `last_found` is older than the run. The host's Device Inventory
  event (class 5001) carries the run time if you want to drive this from
  the NDJSON.

## Field notes

- **Undetermined vs failing:** `pqc-018` means the scanner couldn't tell,
  not that the software fails. Map it to a lower state or a separate
  queue so it doesn't count as a confirmed vulnerability.
- **Fleet scale:** one Vulnerable Item per host + rule + subject. A host
  with many non-PQC services yields one item per service, which is the
  point: each is a separate fix.
