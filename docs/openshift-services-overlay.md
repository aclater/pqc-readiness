# OpenShift: opt-in overlay for `--scan-services`

`--scan-services` (#111) maps every listening socket on the node to the
process, unit and crypto library behind it. To do that for **other
users'** processes it reads `/proc/<pid>/{maps,fd/*,exe,root,environ}`.
The base DaemonSet (`deploy/openshift/daemonset.yaml`) is deliberately
least-privilege: no capabilities. Run there, `--scan-services` lists the
listeners but reports most processes under `unreadable_pids`.

`deploy/openshift/services/` is the **opt-in** alternative (#181). Deploy
it *instead of* the base DaemonSet where service attribution is wanted. The
base manifests stay unchanged; `tests/test_openshift_manifests.py` pins
them to "no capabilities".

| File | Purpose |
|---|---|
| `services/services.yaml` | ServiceAccount, SCC and DaemonSet (`pqc-readiness-services*`) |
| `services/Containerfile` | Image variant: the base image plus one file-capability interpreter |
| `services/verify-file-caps.py` | Runtime check of the capability model, also run in CI |

## What it grants, and why

The pod still runs non-root (UID 1001) with a read-only root filesystem,
read-only host mounts, RuntimeDefault seccomp, no host network and no
privileged container. On top of the base it grants three things:

1. **`CAP_SYS_PTRACE`.** Each of the files above is gated by a ptrace
   access-mode `PTRACE_MODE_READ_FSCREDS` check
   ([proc_pid_maps(5)](https://man7.org/linux/man-pages/man5/proc_pid_maps.5.html),
   [proc_pid_fd(5)](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html),
   [proc_pid_exe(5)](https://man7.org/linux/man-pages/man5/proc_pid_exe.5.html),
   [proc_pid_root(5)](https://man7.org/linux/man-pages/man5/proc_pid_root.5.html),
   [proc_pid_environ(5)](https://man7.org/linux/man-pages/man5/proc_pid_environ.5.html)).
   A caller with a different UID passes that check only with
   `CAP_SYS_PTRACE` in its **effective** set
   ([ptrace(2), "Ptrace access mode checking", steps 3–5](https://man7.org/linux/man-pages/man2/ptrace.2.html)).
2. **`CAP_DAC_READ_SEARCH`.** It bypasses read and search permission
   checks ([capabilities(7)](https://man7.org/linux/man-pages/man7/capabilities.7.html)).
   That lets the probe traverse other users' `/proc/<pid>/fd` directories
   (mode 0500) and read root-only library files through `/proc/<pid>/root`.
3. **`allowPrivilegeEscalation: true`.** This is the non-obvious one:
   - Kubernetes `capabilities.add` does **not** reach a non-root process's
     effective set. Linux clears the permitted and effective sets on the
     UID 0 → non-zero transition, and CRI-O deliberately leaves the
     ambient set empty
     ([kubernetes#56374](https://github.com/kubernetes/kubernetes/issues/56374),
     [KEP-2763](https://github.com/kubernetes/enhancements/blob/master/keps/sig-security/2763-ambient-capabilities/README.md),
     [cri-o#1558](https://github.com/cri-o/cri-o/pull/1558),
     [Red Hat Developer, 2026-10-05](https://developers.redhat.com/articles/2026/10/05/why-your-non-root-container-dropped-its-capabilities-and-how-to-fix-it)).
   - The services image therefore carries a **dedicated copy** of the
     interpreter, `/usr/local/libexec/pqc-readiness/python3`, with file
     capabilities `cap_sys_ptrace,cap_dac_read_search=ep`.
   - The kernel ignores file capabilities when `no_new_privs` is set, and
     `allowPrivilegeEscalation: false` sets it.
   - The escalation is bounded. The container drops ALL capabilities and
     adds back only these two, so they are the whole bounding set and no
     binary in the image can gain anything else.
   - The system `/usr/bin/python3` carries no capabilities.
   - The capability-bearing interpreter is mode 0750 (root, group 0) and
     is invoked with `-I` (isolated mode: no `PYTHON*` environment
     variables, user site directory or current directory on the path).

**Not granted:** `/proc/<pid>/map_files/*` (libraries deleted by an
upgrade) needs `CAP_SYS_ADMIN` or `CAP_CHECKPOINT_RESTORE`
([proc_pid_map_files(5)](https://man7.org/linux/man-pages/man5/proc_pid_map_files.5.html)).
Those entries stay counted as unreadable rather than widening the grant.

The SCC follows the pattern of OpenShift's own `restricted-v2`:
`requiredDropCapabilities: [ALL]`, with named capabilities allowed to be
added explicitly.

## Deploy

Each release publishes `ghcr.io/aclater/pqc-readiness-services:<version>`,
built on the release's UBI 10 image and signed with cosign
([deployment.md](deployment.md#containers-and-openshift) shows how to verify
it). `services.yaml` references the current release; pin it by digest from the
release's `container-images.txt` in production.

```bash
oc apply -f deploy/openshift/namespace.yaml   # if the base is not deployed
oc apply -f deploy/openshift/services/services.yaml
# optional: run only this variant on each node
oc -n pqc-readiness delete ds/pqc-readiness --ignore-not-found
```

The overlay runs fine next to the base DaemonSet; delete the base if one scan
per node is enough. Least-privilege check: the SCC grants access through its
`users:` list, which `oc adm policy who-can` and `oc auth can-i` don't see.
Check the SCC and the pods it admitted directly:

```bash
oc get scc pqc-readiness-services-scc -o jsonpath='{.users}{"\n"}'
# ["system:serviceaccount:pqc-readiness:pqc-readiness-services"]
oc -n pqc-readiness get pods \
  -o custom-columns=POD:.metadata.name,SCC:.metadata.annotations.openshift\\.io/scc
```

To build the image yourself instead:

```bash
python3 scripts/build_zipapp.py
podman build --format=docker -t pqc-readiness:ubi10 -f Containerfile.ubi10 .
podman build --format=docker -t pqc-readiness:ubi10-services \
  --build-arg BASE=localhost/pqc-readiness:ubi10 \
  -f deploy/openshift/services/Containerfile .
# push to your registry and set the DaemonSet image to it (pin by digest)
```

If the SCC does not admit the two capabilities, the pod fails to start
(`exec … Operation not permitted`). It never silently scans with less.

## Podman and quadlet

Podman **does** populate the ambient set for non-root containers given
`--cap-add`. So a non-root quadlet only needs
`AddCapability=SYS_PTRACE DAC_READ_SEARCH`; no special image is
required. This was observed on Fedora 44 with podman: the system
interpreter alone attributed every listener. A quadlet running as root
already sees all processes.

## Verification

| Check | Result |
|---|---|
| **CRI-O-equivalent capability model** (CI job `services-image`; local podman). Non-root after `setuid`, empty ambient set, both caps in the bounding set. | The file-capability interpreter reads another UID's `maps` with `CapEff=0x80004` (bits 2 and 19 only). System `python3`: EACCES, `CapEff=0`. |
| **Caps missing from the bounding set** | exec fails with EPERM, so the setup fails closed |
| **`no_new_privs` set** | No capabilities, EACCES. This is why `allowPrivilegeEscalation: true` is required. |
| **SELinux** (Fedora 44 VM, enforcing, `container-selinux`, rootful podman, `container_t`, `--pid=host`, host `/proc` mounted read-only) | 12 of 12 host listeners attributed; **0 AVC denials** |
| **Manifests** | kubeconform `-strict` with the OpenShift 4.15 SCC schema (CI job `manifests`) |

**Not verified:** a real OpenShift/RHCOS cluster with CRI-O. RHCOS ships
the same `container-selinux` policy family as Fedora, but cluster-specific
SELinux and MCS settings should be confirmed on first deployment. Check
`ausearch -m AVC` on a node, and confirm `service_crypto_linkage.summary`
attributes listeners.

**Note:** the base SCC omits `priority` and `readOnlyRootFilesystem`. The
strict 4.15 schema marks both required, although the API server defaults
them. The base is left unchanged by this work, and CI validates it with
the SCC kind skipped.
