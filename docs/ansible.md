# Running pqc-readiness from Ansible

`pqc-readiness` ships an `--ansible` flag that wraps the standard
[`--json`](json-output.md) output in
`{ansible_facts: {pqc_readiness: ...}}` and always exits 0, so the
probe slots into a normal Ansible facts pipeline. This document is the
runnable, copy-pasteable guide to that workflow: ad-hoc invocation,
playbooks for `set_fact` and fleet aggregation, the privilege model,
and the field shape downstream tasks can rely on.

Because `--ansible` always exits 0, it takes precedence over `--check`
and `--fips-strict`: passing either alongside it prints a `warning:` on
stderr and has no effect on the exit code. Gate in the play instead,
e.g. `failed_when: pqc_readiness.cnsa_2_0.status != "compliant"`.

The example playbooks live under
[`deploy/ansible/`](../deploy/ansible/) and pass
`ansible-playbook --syntax-check` with `ansible-core 2.21.5`.

## Ad-hoc invocation

The `script` module from `ansible.builtin` ships the single-file zipapp
(`dist/pqc-readiness.pyz`, built with `make dist`) to each target and
runs it. The simplest version emits the standard JSON
schema and registers the result on the controller:

```bash
ansible all -i inventory.ini \
  -m ansible.builtin.script \
  -a "/path/to/pqc-readiness.pyz --json"
```

If your invocation form on the targets is the
[`pqc-readiness` wrapper launcher](../README.md#quick-start) (the
RHEL-8-safe entry point), ship it alongside the zipapp. The
wrapper finds the highest available Python 3.9+ on the target's PATH.

For a one-shot fact harvest into the controller's variable cache,
swap `--json` for `--ansible` and feed the result into `set_fact`:

```bash
ansible all -i inventory.ini \
  -m ansible.builtin.script \
  -a "/path/to/pqc-readiness.pyz --ansible" \
  --tree /tmp/pqc/
```

`--tree /tmp/pqc/` writes one JSON file per host so you can inspect
the raw output. To set the facts in-flight, use the playbook below.

## Playbook: `set_fact` from `--ansible`

[`deploy/ansible/playbook-set-fact.yml`](../deploy/ansible/playbook-set-fact.yml)
runs the probe against the `pqc_targets` group, decodes the
`--ansible` envelope, and exposes the report as the `pqc_readiness`
host fact. A follow-up task uses the fact to print the verdict.

```yaml
- name: Probe PQC readiness across the fleet and capture facts
  hosts: pqc_targets
  gather_facts: false
  tasks:
    - name: Run pqc-readiness with --ansible
      ansible.builtin.script:
        cmd: ../../dist/pqc-readiness.pyz --ansible
      register: pqc_raw
      changed_when: false

    - name: Set pqc_readiness facts from probe output
      ansible.builtin.set_fact:
        pqc_readiness: "{{ (pqc_raw.stdout | from_json).ansible_facts.pqc_readiness }}"

    - name: Print the verdict for each host
      ansible.builtin.debug:
        msg: >-
          {{ inventory_hostname }}: {{ pqc_readiness.verdict }}
          (isa_tier={{ pqc_readiness.isa_tier }},
          openssl.pqc_native={{ pqc_readiness.openssl.pqc_native }},
          replace_required={{ pqc_readiness.replace_required }})
```

Once `pqc_readiness` is set, downstream tasks can branch on it
without re-running the probe. Examples:

```yaml
- name: Open a migration ticket for hosts that need accelerator help
  ansible.builtin.debug:
    msg: "Open ticket: {{ inventory_hostname }} requires accelerator (verdict={{ pqc_readiness.verdict }})"
  when: pqc_readiness.replace_required

- name: Flag CNSA 2.0 non-compliance
  ansible.builtin.debug:
    msg: "{{ inventory_hostname }} CNSA 2.0 status: {{ pqc_readiness.cnsa_2_0.status }}"
  when: pqc_readiness.cnsa_2_0.status != 'compliant'
```

Run it:

```bash
ansible-playbook -i deploy/ansible/inventory.example.ini \
  deploy/ansible/playbook-set-fact.yml
```

## Playbook: fleet aggregation

[`deploy/ansible/playbook-fleet-aggregate.yml`](../deploy/ansible/playbook-fleet-aggregate.yml)
runs the probe on every target, fetches the JSON to the controller,
and runs `pqc-readiness --aggregate DIR` over the collection to
produce the same fleet rollup the OpenShift DaemonSet workflow
produces. The two phases live in the same playbook:

```yaml
- name: Phase 1 — run the probe on every target and emit JSON
  hosts: pqc_targets
  gather_facts: false
  vars:
    rollup_dir: "{{ playbook_dir }}/.rollup"
  tasks:
    - ansible.builtin.script: { cmd: "../../dist/pqc-readiness.pyz --json" }
      register: pqc_raw
      changed_when: false
      failed_when: pqc_raw.rc not in [0, 1, 2, 3]  # 0-3 are verdicts, not failures
    - ansible.builtin.copy:
        content: "{{ pqc_raw.stdout }}"
        dest: /var/tmp/pqc-readiness.json
        mode: "0644"
      changed_when: false
    - ansible.builtin.fetch:
        src: /var/tmp/pqc-readiness.json
        dest: "{{ rollup_dir }}/{{ inventory_hostname }}.json"
        flat: true

- name: Phase 2 — controller-side aggregation
  hosts: controller
  gather_facts: false
  vars:
    rollup_dir: "{{ playbook_dir }}/.rollup"
  tasks:
    - ansible.builtin.shell:
        cmd: "{{ playbook_dir }}/../../pqc-readiness --aggregate {{ rollup_dir }} > {{ rollup_dir }}/fleet-rollup.json"
        changed_when: true
```

Output:

- `<rollup_dir>/<hostname>.json` — one per target.
- `<rollup_dir>/fleet-rollup.json` — counts by arch, OS, ISA tier,
  verdict, runtime environment and accelerator kind, the unique CPU
  models, `replace_required_count` and the fleet `pqc_deployment_gap`
  rollup. Field reference:
  [`--aggregate` rollup](json-output.md#--aggregate-rollup).

## Playbook: CBOM collection

[`deploy/ansible/playbook-cbom-collect.yml`](../deploy/ansible/playbook-cbom-collect.yml)
writes a CycloneDX 1.7 CBOM on every target with `--cbom --output` and
fetches it to `<cbom_dir>/<inventory_hostname>.cdx.json` on the controller,
one file per host, ready for a CBOM importer. It runs with `become` so the
scan sees every service and key (`-e pqc_become=false` to skip). Verdict exit
codes 0–3 don't fail the task. See
[integrations/posture-platforms.md](integrations/posture-platforms.md) for
what to do with the files.

## Aligning with the `crypto_policies` system role

The RHEL `crypto_policies` system role (linux-system-roles, v1.9.0)
reports the system policy as `crypto_policies_*` facts. The scanner's
`crypto_policy` object uses the same names for the same facts, so one
can be checked against, or fed into, the other:

| Role fact | pqc-readiness field | Notes |
|---|---|---|
| `crypto_policies_active` | `pqc_readiness.crypto_policy.active` | e.g. `DEFAULT:PQ` |
| `crypto_policies_available_subpolicies` | `pqc_readiness.crypto_policy.available_subpolicies` | |
| `crypto_policies_reboot_required` | `pqc_readiness.crypto_policy.reboot_required` | |
| `crypto_policies_available_policies` | — | not collected by the scanner |
| *(role input)* `crypto_policies_policy` | `base_policy` + `subpolicies` | build the value to set from these |

The scanner deliberately does **not** emit top-level `crypto_policies_*`
facts: on hosts where the role also runs, those would shadow the role's own
facts. Read them under `pqc_readiness.crypto_policy` instead.

The scanner adds what the role does not report: whether the active policy
actually lets each protocol use PQC (`crypto_policy.pqc_enabled`), which is
what SARIF rule `pqc-008` flags.
[`deploy/ansible/playbook-pq-subpolicy.yml`](../deploy/ansible/playbook-pq-subpolicy.yml)
closes that gap with the role. On hosts where the policy blocks PQC, it
appends the `PQ` subpolicy, or `TEST-PQ` on RHEL 10.0 (preview module),
keeping existing subpolicies, and leaves rebooting to you
(`crypto_policies_reboot_ok: false`).

## Privilege requirements

The default probe (no `--scan-*` flags, which is what the example
playbooks run) does *not* need `become: yes` for the headline readiness
signal. ISA detection, OpenSSL inspection, kernel TLS / FIPS state,
SSH PQC kex enumeration, IPsec checks, NSS, accelerator enumeration
via `lspci -nn`, the `/proc/crypto` and `/proc/cpuinfo` reads, and
the trust-store scan all work as an unprivileged user on every Linux
distribution this script targets. `--ansible` mode itself works
without become.

Two fields of the default probe change when you escalate:

| Field | Without become | With become |
| --- | --- | --- |
| `tpm_pqc.pqc_advertised` | absent — `tpm_pqc.note` is `"tpm2_getcap failed"` and `tpm_pqc.raw` shows `Failed to open ... /dev/tpmrm0: Permission denied` | populated boolean (almost always `false`; TPM 2.0 specs do not yet mandate PQC) |
| `sshd.source` | `config files`: the scanner follows `sshd_config` and its `Include` chain. Where `sshd_config` is readable only by root, as on RHEL-family hosts, `sshd` reports what it could read | `sshd -T`, the server's exact effective configuration |

The reason is concrete: `tpm2_getcap algorithms` opens
`/dev/tpmrm0`, which is restricted to root or members of the `tss`
group on every modern distribution. Granting access via `tss` group
membership is a per-host policy decision that lives outside this
script.

In practice: leave the probe at `become: false` for routine inventory
runs, and escalate when you need TPM PQC capability data or sshd's exact
effective key exchange. The `playbook-set-fact.yml` example exposes this
as a `become_for_tpm` variable that defaults to `false` and can be
flipped per run:

```bash
ansible-playbook -i inventory.ini deploy/ansible/playbook-set-fact.yml \
  --extra-vars become_for_tpm=true
```

The opt-in `--scan-*` flags have their own needs. `--scan-services`
and `--scan-processes` see other users' processes only as root (or with
`CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH`); `--scan-boot-chain` reads
the TPM's PQC support only as root or a `tss` group member; and
`--scan-tunnels` reads NetworkManager WireGuard profiles only as root.
Add `become: true` to the probe task when you pass them. The script
never calls `dmidecode` or `lspci -vvv`, and never writes anywhere on
the target.

## Sample `ansible_facts.pqc_readiness` shape

The fact tree under `pqc_readiness` mirrors the standard `--json`
schema documented in [`docs/json-output.md`](json-output.md).
Downstream tasks should rely on these keys:

```yaml
pqc_readiness:
  verdict: "EXCELLENT - software PQC at production speed"
  isa_tier: "excellent"
  replace_required: false
  openssl:
    version: "OpenSSL 3.5.5 27 Jan 2026 (Library: OpenSSL 3.5.5 27 Jan 2026)"
    pqc_native: true
  tpm_pqc:
    present: true
    tools: true
    note: "tpm2_getcap failed"          # without become; pqc_advertised: false with become
  cnsa_2_0:
    status: "partial"                    # or "compliant" / "non_compliant" / "unknown"
    kem_compliant: true
    signature_compliant: true
  schema_version: "1.6"
```

The full key list is stable within a major `schema_version` (`1.x`);
minor bumps only add fields or normalise absent values to `null`. Top-level
keys that consumers most often branch on:

- `verdict` — coarse one-liner.
- `isa_tier` — one of `excellent` / `good` / `marginal` / `poor`.
- `replace_required` — boolean for fleet planning.
- `openssl.pqc_native` — whether the host's OpenSSL ≥ 3.5 PQC
  primitives are available.
- `cnsa_2_0.status` — `compliant` / `partial` / `non_compliant` /
  `unknown`.
- `exit_code` — the exit code the probe would return outside the
  `--ansible` wrapper, for compatibility with `--check TIER`.

## Versions validated

The example playbooks pass `ansible-playbook --syntax-check` with
`ansible-core 2.21.5` (checked 2026-10-14).

Either run `ansible --version` to confirm parity with your runtime,
or update the version in this section if you adapt the playbooks for
an older `ansible-core` build.

## Out of scope

This document and the example playbooks deliberately do not cover:

- A full Ansible Collection or Galaxy role — the `script` module is
  enough for the use case.
- AAP / Automation Controller / Tower job template definitions.
- Custom inventory plugins.
- `ansible-lint` integration in CI.

If a customer engagement needs any of those, file a separate issue —
each is a multi-day deliverable on its own.
