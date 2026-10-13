# Event-Driven Ansible

[`deploy/eda/pqc-readiness-rulebook.yml`](../../deploy/eda/pqc-readiness-rulebook.yml)
reacts to `--ndjson` findings (#157). Post each NDJSON line to its webhook
source:

```bash
pqc-readiness --ndjson | while read -r l; do
  curl -s -H 'Content-Type: application/json' -d "$l" http://eda.example:5000/endpoint
done
```

| Finding | Action |
|---|---|
| `pqc-008` (system crypto policy blocks PQC) | Runs [`playbook-pq-subpolicy.yml`](../../deploy/ansible/playbook-pq-subpolicy.yml) against that host, which applies the `PQ` (or RHEL 10.0 `TEST-PQ`) subpolicy through the `crypto_policies` system role |
| `pqc-011` … `pqc-017` (software that will fail at PQC) | Runs your notification / ticketing playbook (`pqc_notify_playbook`); these need upgrades, not configuration |
| `pqc-020` (PQC-capable but not configured) | Same notification playbook |

Pass the two playbook paths with `--vars` (`pqc_remediation_playbook`,
`pqc_notify_playbook`). Each action receives `pqc_finding_host` (the
finding's `device.hostname`); notifications also get `pqc_finding_rule`
and `pqc_finding_message`.

## What was tested

| Check (2026-10-14) | Result |
|---|---|
| Rulebook run in `quay.io/ansible/ansible-rulebook:v1.3.2` with the `ansible.eda` webhook source; four findings POSTed | `pqc-008` ran the remediation playbook for its host; `pqc-013` and `pqc-020` ran the notification playbook; an unrelated `pqc-005` triggered nothing |
| `playbook-pq-subpolicy.yml` in a Rocky Linux 9 container (ansible-core 2.15, `fedora.linux_system_roles`) | Policy `DEFAULT` → `DEFAULT:PQ`; the scanner then reports TLS and SSH PQC enabled; a second run changes nothing |
| Against Event-Driven Ansible controller in AAP | **Not tested** |
