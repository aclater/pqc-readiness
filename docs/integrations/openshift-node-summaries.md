# Per-node summaries for ACM and the Compliance Operator

The opt-in overlay in [`deploy/openshift-summary/`](../../deploy/openshift-summary/)
makes the fleet DaemonSet publish one small ConfigMap per node,
`pqc-readiness-node-<node>` in the `pqc-readiness` namespace. Cluster
policy engines can then evaluate PQC readiness without parsing full
reports (#157).

```bash
oc apply -k deploy/openshift-summary     # base DaemonSet + summary overlay
```

## What the overlay changes

| | Base (`deploy/openshift`) | Summary overlay |
|---|---|---|
| Service-account token | not mounted (`automountServiceAccountToken: false`) | mounted |
| RBAC | none | `Role` limited to `configmaps` (`get`, `create`, `update`) in `pqc-readiness` |
| Probe loop | unchanged; `PQC_SUMMARY_HOOK` unset | runs `publish-node-summary.py` after each probe |
| Pod security, host mounts, capabilities | as base | unchanged |

The base keeps no API access at all. Kubernetes RBAC can't restrict `create`
by object name, so the Role can create any ConfigMap in the dedicated
`pqc-readiness` namespace and nothing else. The overlay is a sibling
directory, not a subdirectory, because kustomize doesn't allow an overlay
inside its base.

## Summary keys

ConfigMap `data` values are strings, labelled `pqc-readiness/summary: node`.

| Key | Meaning |
|---|---|
| `node`, `generated_at`, `schema_version` | Where and when, from the report |
| `verdict`, `exit_code` | The readiness verdict |
| `gap_tls`, `gap_ssh`, `gap_ipsec` | `pqc_deployment_gap.protocols.*.state` (`deployed`, `capable_not_configured`, `configured_not_capable`, `not_capable`, `unknown`, `not_present`) |
| `gap_count`, `gaps` | Number of entries in `pqc_deployment_gap.gaps`, and the entries (newline-separated) |
| `capable_not_configured` | How many gaps a configuration change would close |
| `failure_findings` | Findings for software that will fail at PQC (rules `pqc-011` … `pqc-017`) |
| `findings_by_rule` | JSON object: finding count per rule ID |

## ACM governance policy

[`acm-policy.yaml`](../../deploy/openshift-summary/acm-policy.yaml) is an
`inform` Policy with a ConfigurationPolicy that is non-compliant when any
summary reports TLS or SSH as `capable_not_configured` or `not_capable`.
Unnamed `mustnothave` objects match every summary ConfigMap carrying those
values. Bind it with your own Placement and PlacementBinding.

## Compliance Operator CEL rule

[`compliance-customrule.yaml`](../../deploy/openshift-summary/compliance-customrule.yaml)
contains a `CustomRule` (CEL, Tech Preview from Compliance Operator 1.8),
plus a TailoredProfile and ScanSettingBinding that run it. It fails when any
summary has a non-zero `gap_count` or `failure_findings`. With no summaries
yet it passes, because `all()` over an empty list is true.

## What was tested

| Check (2026-10-14) | Result |
|---|---|
| `kustomize build` (v5.8.3) of the overlay | 6 objects; the script ConfigMap name hash propagates to the DaemonSet volume |
| kubeconform v0.8.0 `-strict` on the built overlay | valid (the SCC is skipped, as for the base) |
| kubeconform `-strict` on the ACM and Compliance Operator samples, using schemas from the upstream CRDs (Compliance Operator v1.8.2, ACM policy controllers v0.20.1) | valid, including the ConfigurationPolicy embedded in the Policy; a misspelt field is rejected |
| CEL expression evaluated with cel-python 0.5.0 against sample ConfigMaps | fails on a gap or failing software, ignores unlabelled ConfigMaps, passes with none |
| Publisher against a local HTTP server standing in for the ConfigMap API (`tests/test_node_summary.py`) | create, replace and 403 paths |
| Live on single-node OpenShift 4.22.14 (RHCOS 9.8) with Compliance Operator 1.10.0 | Overlay applied with `oc apply -k`; `pqc-readiness-node-crc` published after the first probe; the `CustomRule` became `Ready` and the suite reported `NON-COMPLIANT` (2 gaps). See [examples/openshift-4.22-live.md](../examples/openshift-4.22-live.md) |
| **ACM on a real cluster** | **Not tested** (too heavy for a single-node cluster; needs the ACM CRDs even for a server-side dry run) |

CI runs the same kustomize and kubeconform checks
(`.github/workflows/ci-openshift-manifests.yml`).
