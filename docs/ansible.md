# Running pqc-readiness from Ansible

`pqc-readiness` ships an `--ansible` flag that wraps the standard
[`--json`](../README.md#json-output---json) output in
`{ansible_facts: {pqc_readiness: ...}}` and always exits 0, so the
probe slots into a normal Ansible facts pipeline. This document is the
runnable, copy-pasteable guide to that workflow: ad-hoc invocation,
playbooks for `set_fact` and fleet aggregation, the privilege model,
and the field shape downstream tasks can rely on.

The example playbooks live under
[`deploy/ansible/`](../deploy/ansible/) and have been validated
against `ansible-core 2.20.5`.

## Ad-hoc invocation

The `script` module from `ansible.builtin` ships the script to each
target and runs it. The simplest version emits the standard JSON
schema and registers the result on the controller:

```bash
ansible all -i inventory.ini \
  -m ansible.builtin.script \
  -a "/path/to/pqc_readiness.py --json"
```

If your invocation form on the targets is the
[`pqc-readiness` wrapper launcher](../README.md#quick-start) (the
RHEL-8-safe entry point), substitute it for `pqc_readiness.py`. The
wrapper finds the highest available Python 3.9+ on the target's PATH.

For a one-shot fact harvest into the controller's variable cache,
swap `--json` for `--ansible` and feed the result into `set_fact`:

```bash
ansible all -i inventory.ini \
  -m ansible.builtin.script \
  -a "/path/to/pqc_readiness.py --ansible" \
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
        cmd: ../../pqc_readiness.py --ansible
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
and runs `pqc_readiness.py --aggregate DIR` over the collection to
produce the same fleet rollup the OpenShift DaemonSet workflow
produces. The two phases live in the same playbook:

```yaml
- name: Phase 1 — run the probe on every target and emit JSON
  hosts: pqc_targets
  gather_facts: false
  vars:
    rollup_dir: "{{ playbook_dir }}/.rollup"
  tasks:
    - ansible.builtin.script: { cmd: "../../pqc_readiness.py --json" }
      register: pqc_raw
      changed_when: false
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
        cmd: "{{ playbook_dir }}/../../pqc_readiness.py --aggregate {{ rollup_dir }} > {{ rollup_dir }}/fleet-rollup.json"
        changed_when: true
```

Output:

- `<rollup_dir>/<hostname>.json` — one per target.
- `<rollup_dir>/fleet-rollup.json` — counts by arch, OS, ISA tier,
  verdict, runtime environment, accelerator kind; unique CPU model
  list; `replace_required_count`. Same schema as
  [README ## Aggregation](../README.md#aggregation-1).

## Privilege requirements

The probe does *not* need `become: yes` for the headline readiness
signal. ISA detection, OpenSSL inspection, kernel TLS / FIPS state,
SSH PQC kex enumeration, IPsec checks, NSS, accelerator enumeration
via `lspci -nn`, the `/proc/crypto` and `/proc/cpuinfo` reads, and
the trust-store scan all work as an unprivileged user on every Linux
distribution this script targets. `--ansible` mode itself works
without become.

The one field that goes from "unknown" to populated when you escalate
is `tpm_pqc.pqc_advertised`:

| Field | Without become | With become |
| --- | --- | --- |
| `tpm_pqc.pqc_advertised` | absent — `tpm_pqc.note` is `"tpm2_getcap failed"` and `tpm_pqc.raw` shows `Failed to open ... /dev/tpmrm0: Permission denied` | populated boolean (almost always `false`; TPM 2.0 specs do not yet mandate PQC) |

The reason is concrete: `tpm2_getcap algorithms` opens
`/dev/tpmrm0`, which is restricted to root or members of the `tss`
group on every modern distribution. Granting access via `tss` group
membership is a per-host policy decision that lives outside this
script.

In practice: leave the probe at `become: false` for routine inventory
runs. Escalate only when you specifically need TPM PQC capability data
— the difference is one boolean. The `playbook-set-fact.yml` example
exposes this as a `become_for_tpm` variable that defaults to `false`
and can be flipped per run:

```bash
ansible-playbook -i inventory.ini deploy/ansible/playbook-set-fact.yml \
  --extra-vars become_for_tpm=true
```

Other root-only paths are not exercised by the default probe. The
script does not call `dmidecode`, does not invoke `lspci -vvv`, and
does not require write access anywhere on the target.

## Sample `ansible_facts.pqc_readiness` shape

The fact tree under `pqc_readiness` mirrors the standard `--json`
schema [documented in the README](../README.md#json-output---json).
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
    status: "partial"                    # or "compliant" / "non-compliant"
    kem_compliant: true
    signature_compliant: true
  schema_version: "1.0"
```

The full key list is stable across `schema_version: "1.0"`. Top-level
keys that consumers most often branch on:

- `verdict` — coarse one-liner.
- `isa_tier` — one of `excellent` / `good` / `marginal` / `poor`.
- `replace_required` — boolean for fleet planning.
- `openssl.pqc_native` — whether the host's OpenSSL ≥ 3.5 PQC
  primitives are available.
- `cnsa_2_0.status` — `compliant` / `partial` / `non-compliant`.
- `exit_code` — the exit code the probe would return outside the
  `--ansible` wrapper, for compatibility with `--check TIER`.

## Versions validated

The example playbooks were validated with:

```text
ansible-playbook --syntax-check
ansible-core 2.20.5
```

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
