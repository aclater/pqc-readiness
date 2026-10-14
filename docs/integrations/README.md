# Integrations

Recipes for getting `pqc-readiness` output into other platforms. Each page
says what was tested, on which version and date, and what wasn't.

| Platform | Output used | Page | Tested against a live instance |
|---|---|---|---|
| Dependency-Track | `--cbom`, `--cbom-interop` | [dependency-track.md](dependency-track.md) | Yes: 5.2.0 and 4.14.5 |
| DefectDojo | `--sarif` | [defectdojo.md](defectdojo.md) | Yes: 3.4.100 (plain `--sarif`); `--sarif-anchor` output not re-imported |
| ServiceNow Vulnerability Response | `--ndjson` | [servicenow-vr.md](servicenow-vr.md) | No: converter tested, instance steps not run |
| Event-Driven Ansible | `--ndjson` | [event-driven-ansible.md](event-driven-ansible.md) | Rulebook run in `ansible-rulebook`; not in an AAP controller |
| SUSE Multi-Linux Manager / Uyuni | `--json`, `--ndjson` | [suse-multi-linux-manager.md](suse-multi-linux-manager.md) | No: tested against a local XML-RPC stand-in |
| ACM and Compliance Operator | per-node summary ConfigMaps | [openshift-node-summaries.md](openshift-node-summaries.md) | No: manifests validated, not run on a cluster |
| SBOM and supply-chain graph tools | `--sbom` | [sbom-graph-tools.md](sbom-graph-tools.md) | No: schema-validated only |
| Cryptographic posture platforms (CBOM importers) | `--cbom` | [posture-platforms.md](posture-platforms.md) | No: CBOMs, joins and merges validated with the CycloneDX CLI and schemas; no platform import |

Related recipes elsewhere in `docs/`:

- SIEM ingestion of `--ndjson`: [siem-ndjson.md](../siem-ndjson.md)
- Prometheus and Grafana: [prometheus.md](../prometheus.md)
- Ansible playbooks: [ansible.md](../ansible.md)
- Code-scanning upload of `--sarif`: [sarif-code-scanning.md](../sarif-code-scanning.md)
- Joining network-side observations: [endpoint-observations.md](../endpoint-observations.md)
