"""Build docs/examples/os-matrix-*.md from a cross-OS scan (JSON + SARIF per host).

usage: python3 scripts/os_matrix_page.py <results-dir> <previous-page.md> <out.md>

<results-dir> layout:
  vm/<alias>/result.json, vm/<alias>/result-b.json   distro-matrix run-matrix.sh
      results-dir, run with --scanner-args '--json ...' and --compare-args
      '--sarif ...' (result-b.json is the SARIF run)
  ubi/rhel{8,9,10}/result.json, result.sarif         RHEL UBI container runs

The previous page is parsed for the "Changes since" table. The generated page
has CHANGES_NOTES_PLACEHOLDER and METHOD_PLACEHOLDER markers to fill in by
hand. See docs/testing.md and docs/examples/os-matrix-2026-10.md (method).
"""

import json
import re
import sys
from pathlib import Path

S = Path(sys.argv[1])
OLD = Path(sys.argv[2]).read_text()
OUT = Path(sys.argv[3])

# Page order and sources, same 20 hosts as the v2.2.0 page.
HOSTS = [
    ("rhel8", "ubi"),
    ("rhel9", "ubi"),
    ("rhel10", "ubi"),
    ("rocky8", "vm"),
    ("rocky9", "vm"),
    ("rocky10", "vm"),
    ("alma8", "vm"),
    ("alma9", "vm"),
    ("alma10", "vm"),
    ("ol8", "vm"),
    ("ol9", "vm"),
    ("stream9", "vm"),
    ("stream10", "vm"),
    ("fedora43", "vm"),
    ("fedora44", "vm"),
    ("al2023", "vm"),
    ("ubuntu2604", "vm"),
    ("leap156", "vm"),
    ("leap16", "vm"),
    ("tumbleweed", "vm"),
]


def load(alias, kind):
    if kind == "ubi":
        d = S / "ubi" / alias
        return json.loads((d / "result.json").read_text()), json.loads(
            (d / "result.sarif").read_text()
        )
    d = S / "vm" / alias
    return json.loads((d / "result.json").read_text()), json.loads(
        (d / "result-b.json").read_text()
    )


def g(o, path, default=None):
    for k in path.split("."):
        if not isinstance(o, dict):
            return default
        o = o.get(k)
    return default if o is None else o


def name(r, kind):
    osr = r.get("os_release") or {}
    if kind == "ubi":
        return f"Red Hat Enterprise Linux {osr.get('version_id')} (UBI container)"
    return osr.get("pretty_name") or osr.get("id")


STATE = {
    "deployed": "✅ deployed",
    "capable_not_configured": "⚠️ capable, off",
    "not_capable": "❌ not capable",
    "not_present": "— not present",
    "configured_not_capable": "⛔ configured, not capable",
    "unknown": "? unknown",
}


def ver(v):
    m = re.search(r"\d+\.\d+\.\d+[a-z]?", v or "")
    return m.group(0) if m else (v or "n/a")


def crypto_row(r, kind):
    sb = g(r, "boot_chain.secure_boot", {})
    if kind == "ubi":
        fw = "container"
    elif sb.get("firmware") == "uefi" or sb.get("available"):
        fw = "UEFI, SB on" if sb.get("enabled") else "UEFI, SB off"
    else:
        fw = "BIOS"
    o = r.get("openssl") or {}
    ossl = ver(o.get("version")) + ("" if o.get("pqc_native") else " (no PQC)")
    s = r.get("ssh_pqc") or {}
    pk = s.get("pqc_kex") or []
    kind_kex = (
        "ML-KEM" if any("mlkem" in k for k in pk) else ("sntrup only" if pk else "none")
    )
    sshv = f"{s.get('version') or 'n/a'} ({kind_kex})"
    cp = r.get("crypto_policy") or {}
    pol = cp.get("active") if cp.get("available") else "none"
    hyb = g(o, "config.pqc_key_exchange_by_default")
    if hyb is None:
        hyb = g(cp, "pqc_enabled.tls_key_exchange")
    hybs = "yes" if hyb else "no"
    p = g(r, "pqc_deployment_gap.protocols", {})
    st = [
        STATE.get(g(p, f"{x}.state"), g(p, f"{x}.state") or "n/a")
        for x in ("tls", "ssh", "ipsec")
    ]
    sd = r.get("sshd") or {}
    if not sd.get("available"):
        kex = "unknown"
    elif sd.get("pqc_first"):
        kex = "PQC first"
    elif sd.get("pqc_offered"):
        kex = "PQC offered"
    else:
        kex = "classical"
    return [fw, ossl, sshv, pol, hybs, *st, kex]


def findings(sarif):
    out = []
    rules = {}
    for run in sarif.get("runs", []):
        for rule in g(run, "tool.driver", {}).get("rules", []):
            rules[rule["id"]] = g(rule, "shortDescription.text", rule["id"])
        for res in run.get("results", []):
            out.append(
                (res.get("level", "warning"), res["ruleId"], g(res, "message.text", ""))
            )
    return out, rules


def compliance_row(r, f):
    libs = g(r, "crypto_libraries.libraries", {})
    inst = {n: v for n, v in libs.items() if v.get("installed")}
    cap = [n for n, v in inst.items() if v.get("pqc_capable")]
    nop = [n for n, v in inst.items() if not v.get("pqc_capable")]
    pl = f"{len(cap)}/{len(inst)}" + (f" (no PQC: {', '.join(nop)})" if nop else "")
    cnsa = g(r, "cnsa_2_0.status", "n/a")
    fips = "on" if g(r, "fips.kernel") else "off"
    pk = r.get("packages") or {}
    pkgs = (
        f"{pk.get('total_packages')} ({pk.get('source')})"
        if pk.get("available")
        else "n/a"
    )
    ts = r.get("trust_store") or {}
    tstore = (
        f"{ts.get('total_certs')} / {(ts.get('pqc_certs') or 0) + (ts.get('hybrid_certs') or 0)}"
        if ts.get("available")
        else "n/a"
    )
    sk = g(r, "signing_keys.summary", {})
    if sk:
        keys = (
            f"{sk.get('total')}, all classical"
            if sk.get("all_classical")
            else f"{sk.get('total')}, {sk.get('hybrid')} hybrid, {sk.get('pure_pqc')} PQC"
        )
    else:
        keys = "n/a"
    bs = g(r, "boot_chain.summary", {})
    n = bs.get("secure_boot_certificates") or 0
    fwk = g(r, "boot_chain.secure_boot.firmware")
    if (
        fwk == "bios"
        and g(r, "runtime_environment.container") is not True
        and not r.get("_container")
    ):
        sb = "n/a (BIOS boot)"
    else:
        sb = (
            f"{n} ({', '.join(bs.get('secure_boot_algorithms') or [])})"
            if n
            else "none"
        )
    k = r.get("kerberos") or {}
    if not k.get("available"):
        krb = "n/a"
    elif g(k, "summary.deprecated_enctypes"):
        krb = "deprecated allowed"
    elif g(k, "summary.aes128_enctypes"):
        krb = "AES-128 allowed"
    else:
        krb = "AES-256 only"
    e = sum(1 for lv, *_ in f if lv == "error")
    w = sum(1 for lv, *_ in f if lv == "warning")
    nn = sum(1 for lv, *_ in f if lv == "note")
    return [pl, cnsa, fips, pkgs, tstore, keys, sb, krb, f"{e} / {w} / {nn}"]


def num(x, dec=0):
    if x is None:
        return "n/a"
    return f"{x:,.{dec}f}"


def perf_row(r):
    b = r.get("benchmark") or {}
    pq = b.get("pqc") or {}
    cl = b.get("classical") or {}
    t = {
        s.get("group"): s.get("handshakes_per_sec")
        for s in g(r, "benchmark_tls_handshake.suites", []) or []
    }
    x, h, p = t.get("x25519"), t.get("X25519MLKEM768"), t.get("MLKEM768")
    diff = f"{(h - x) / x * 100:+.0f}%" if x and h else "n/a"
    return [
        num(g(pq, "ML-KEM-768.encaps/s")),
        num(g(pq, "ML-KEM-768.decaps/s")),
        num(g(pq, "ML-DSA-65.sign/s")),
        num(g(pq, "ML-DSA-65.verify/s")),
        num(g(pq, "SLH-DSA-SHA2-128s.sign/s"), 1),
        num(g(cl, "rsa2048.sign/s")),
        num(g(cl, "ecdh.op/s")),
        num(x),
        num(h),
        num(p),
        diff,
    ]


def old_table(heading):
    """Parse a table from the v2.2.0 page into {host: cells}."""
    sec = OLD.split(f"## {heading}", 1)[1].split("\n## ", 1)[0]
    rows = {}
    for line in sec.splitlines():
        m = re.match(r"\| \*\*(.+?)\*\* \| (.*) \|$", line)
        if m:
            rows[m.group(1)] = [c.strip() for c in m.group(2).split(" | ")]
    return rows


data = []
for alias, kind in HOSTS:
    r, sarif = load(alias, kind)
    if kind == "ubi":
        r["_container"] = True
    f, rules = findings(sarif)
    data.append(
        {
            "alias": alias,
            "kind": kind,
            "name": name(r, kind),
            "r": r,
            "f": f,
            "rules": rules,
        }
    )

ALLRULES = {}
for d in data:
    ALLRULES.update(d["rules"])

L = []
w = L.append
N = len(data)
date = data[3]["r"].get("generated_at", "")[:10]
w("# Example output: cross-OS scan matrix (v2.4.0)\n")
w(
    f"> **Example output, not a support statement.** This page records what `pqc-readiness` v2.4.0 reported on {N} stock Linux images on {date}. It shows what the scanner produces across distributions and what each distribution ships out of the box. Results will change as distributions update their packages. Distribution support tiers are in the [README](../../README.md#distribution-support).\n"
)
w(
    "Every image was scanned **unmodified**, apart from installing a supported Python where the image lacked one. The [method](#how-this-was-run) section lists the exact flags and VM sizing. [What changed since the v2.2.0 run](#changes-since-the-v220-run) explains the differences from the previous version of this page.\n"
)

# summary
nat = sum(1 for d in data if g(d["r"], "openssl.pqc_native"))
tlsd = sum(
    1 for d in data if g(d["r"], "pqc_deployment_gap.protocols.tls.state") == "deployed"
)
sshd_ = sum(
    1 for d in data if g(d["r"], "pqc_deployment_gap.protocols.ssh.state") == "deployed"
)
cnc = sum(
    1
    for d in data
    if "capable_not_configured"
    in (
        g(d["r"], "pqc_deployment_gap.protocols.tls.state"),
        g(d["r"], "pqc_deployment_gap.protocols.ssh.state"),
    )
)
nf = sum(len(d["f"]) for d in data)
nr = len({rid for d in data for _, rid, _ in d["f"]})
w("## Summary\n")
w("| Measure | Hosts |\n| --- | ---: |")
w(f"| Ship OpenSSL with native ML-KEM / ML-DSA | {nat} / {N} |")
w(f"| Offer hybrid PQC in TLS by default (`deployed`) | {tlsd} / {N} |")
w(f"| Offer PQC key exchange in SSH by default (`deployed`) | {sshd_} / {N} |")
w(
    f"| PQC-capable but configured to stay classical (`capable_not_configured`) | {cnc} / {N} |"
)
w(f"| SARIF findings raised | {nf} across {nr} rules |\n")

groups = {"on": [], "policy": [], "none": []}
for d in data:
    tls = g(d["r"], "pqc_deployment_gap.protocols.tls.state")
    groups[
        "on"
        if tls == "deployed"
        else "policy"
        if tls == "capable_not_configured"
        else "none"
    ].append(d["name"])
w("The hosts fall into three groups:\n")
w(f"- **PQC on by default for TLS:** {', '.join(groups['on'])}.")
w(
    f"- **PQC-capable OpenSSL, but the default crypto policy keeps TLS classical** ([`pqc-008`](../rules/pqc-008-crypto-policy-blocks-pqc.md), [`pqc-020`](../rules/pqc-020-pqc-capable-not-configured.md)): {', '.join(groups['policy'])}."
)
w(
    f"- **OpenSSL cannot do PQC in TLS** ([`pqc-001`](../rules/pqc-001-openssl-pre-3.5.md)): {', '.join(groups['none'])}.\n"
)
classical_keys = [d for d in data if g(d["r"], "signing_keys.summary.all_classical")]
nonc = [
    d["name"]
    for d in data
    if g(d["r"], "signing_keys.summary")
    and not g(d["r"], "signing_keys.summary.all_classical")
]
w(
    f"{len(classical_keys)} of {N} hosts trust only classical package-signing keys ([`pqc-009`](../rules/pqc-009-classical-package-signing-keys.md)); the exception{'s are' if len(nonc) > 1 else ' is'} {', '.join(nonc)}, whose package-signing keys include a hybrid (PQC) key. Every VM boots through a classical chain ([`pqc-030`](../rules/pqc-030-classical-boot-chain.md)).\n"
)

# crypto stack
w("## Crypto stack and deployment gap\n")
w(
    "The TLS, SSH and IPsec columns are the per-protocol `pqc_deployment_gap.protocols.*.state` verdict ([JSON reference](../json-output.md)). `sshd kex` is the effective server configuration from `sshd -T`. Since v2.3.0 the OpenSSL and OpenSSH versions are read from the host's own packages or binaries (`version_source`), not from whatever command-line tool happens to be on `PATH`.\n"
)
w(
    "| OS | Firmware | OpenSSL | OpenSSH (PQC kex) | Crypto policy | Hybrid TLS default | TLS | SSH | IPsec | sshd kex |"
)
w("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |")
CR = {}
for d in data:
    row = crypto_row(d["r"], d["kind"])
    CR[d["name"]] = row
    w(f"| **{d['name']}** | " + " | ".join(row) + " |")
w("")

w("## Compliance and inventory\n")
w(
    "`PQC libs` is PQC-capable / installed crypto libraries. `Trust store` is total certificates / PQC or hybrid certificates. `Findings` is errors / warnings / notes.\n"
)
w(
    "| OS | PQC libs | CNSA 2.0 | FIPS kernel | Packages (source) | Trust store | Pkg signing keys | Secure Boot certs | Kerberos | Findings E/W/N |"
)
w("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |")
CO = {}
for d in data:
    row = compliance_row(d["r"], d["f"])
    CO[d["name"]] = row
    w(f"| **{d['name']}** | " + " | ".join(row) + " |")
w("")

# findings matrix
w("## Findings matrix\n")
w(
    "`E` error, `W` warning, `N` note, `·` not raised. Column keys are listed under the table. Each rule links to its help page.\n"
)
w("| Rule | " + " | ".join(str(i) for i in range(1, N + 1)) + " | Hosts |")
w("| --- | " + " | ".join(":-:" for _ in range(N)) + " | ---: |")
for rid in sorted({rid for d in data for _, rid, _ in d["f"]}):
    cells, hosts = [], 0
    for d in data:
        lv = [lv for lv, r_, _ in d["f"] if r_ == rid]
        if lv:
            hosts += 1
            cells.append("E" if "error" in lv else "W" if "warning" in lv else "N")
        else:
            cells.append("·")
    short = rid.split("-")[0] + "-" + rid.split("-")[1]
    w(
        f"| [`{short}`](../rules/{rid}.md) {ALLRULES.get(rid, '')} | "
        + " | ".join(cells)
        + f" | {hosts} |"
    )
w("")
w(
    "Columns: "
    + "; ".join(f"**{i}** {d['name']}" for i, d in enumerate(data, 1))
    + ".\n"
)

# performance
cpu = data[3]["r"].get("cpu_model", "the test host")
w("## Performance\n")
w(
    f"Single-thread `openssl speed` (1 s per test) and the loopback TLS 1.3 handshake benchmark (`--bench --bench-tls`), in operations per second. Every host ran on the same CPU ({cpu}), so the differences come from each distribution's OpenSSL build. Up to four VMs ran at once under the host's VM budget, which adds noise. The RHEL container rows ran without virtualization or that contention, so their numbers run higher and should not be compared with the VM rows. Hosts without native PQC in OpenSSL have no PQC numbers.\n"
)
w(
    "| OS | ML-KEM-768 encaps | ML-KEM-768 decaps | ML-DSA-65 sign | ML-DSA-65 verify | SLH-DSA-128s sign | RSA-2048 sign | ECDH | TLS x25519 | TLS X25519MLKEM768 | TLS MLKEM768 | Hybrid vs classical |"
)
w(
    "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"
)
for d in data:
    w(f"| **{d['name']}** | " + " | ".join(perf_row(d["r"])) + " |")
w("")

# changes since v2.2.0
oc, oo = (
    old_table("Crypto stack and deployment gap"),
    old_table("Compliance and inventory"),
)
CH = [
    "Firmware",
    "OpenSSL",
    "OpenSSH (PQC kex)",
    "Crypto policy",
    "Hybrid TLS default",
    "TLS",
    "SSH",
    "IPsec",
    "sshd kex",
]
CHC = [
    "PQC libs",
    "CNSA 2.0",
    "FIPS kernel",
    "Packages (source)",
    "Trust store",
    "Pkg signing keys",
    "Secure Boot certs",
    "Kerberos",
    "Findings E/W/N",
]
w("## Changes since the v2.2.0 run\n")
w(
    "The previous version of this page recorded v2.2.0 on 2026-10-14, on the same image builds. Cells that changed, excluding package counts (which move with every image update) and the firmware-dependent Firmware and Secure Boot certs columns (see below):\n"
)
w("| OS | Field | v2.2.0 | v2.4.0 |\n| --- | --- | --- | --- |")
changes = 0
for d in data:
    for heads, old, new in ((CH, oc, CR), (CHC, oo, CO)):
        o = old.get(d["name"])
        n = new[d["name"]]
        if not o:
            continue
        for h, a, b in zip(heads, o, n):
            if a != b and h not in (
                "Packages (source)",
                "Firmware",
                "Secure Boot certs",
            ):
                w(f"| {d['name']} | {h} | {a} | {b} |")
                changes += 1
if not changes:
    w("| (none) | | | |")
w("")
w("CHANGES_NOTES_PLACEHOLDER\n")

# findings by OS
w("## Findings by OS\n")
for d in data:
    w("<details>")
    w(f"<summary><b>{d['name']}</b>: {len(d['f'])} findings</summary>\n")
    order = {"error": 0, "warning": 1, "note": 2}
    for lv, rid, msg in sorted(d["f"], key=lambda x: (order.get(x[0], 3), x[1])):
        w(f"- **{lv}** `{rid}`: {msg}")
    w("\n</details>\n")

w("## How this was run\n")
w("METHOD_PLACEHOLDER")
OUT.write_text("\n".join(L) + "\n")
print(f"wrote {OUT}: {N} hosts, {nf} findings, {changes} changed cells")
