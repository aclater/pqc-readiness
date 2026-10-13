"""Verify the services image's file-capability interpreter behaves as the
#181 overlay assumes.  Run as root inside the image, with SYS_PTRACE and
DAC_READ_SEARCH in the bounding set (as the overlay SCC allows):

    podman run --rm --user 0 --cap-drop ALL \\
      --cap-add SETUID,SETGID,KILL,SYS_PTRACE,DAC_READ_SEARCH \\
      -v ./deploy/openshift/services:/t:ro --entrypoint /usr/bin/python3 \\
      IMAGE /t/verify-file-caps.py

It starts a process as UID 2000, then, as the probe user (UID 1001, GID 0)
with an empty ambient set (as CRI-O leaves it), reads that process's
/proc/<pid>/maps through (a) the capability-bearing interpreter, which
must succeed with exactly CAP_SYS_PTRACE + CAP_DAC_READ_SEARCH effective,
and (b) the system python3, which must be denied.  Exits non-zero on any
deviation.
"""

import os
import subprocess
import sys
import time

CAPPED = "/usr/local/libexec/pqc-readiness/python3"
SYSTEM = os.path.realpath("/usr/bin/python3")
# CAP_DAC_READ_SEARCH = bit 2, CAP_SYS_PTRACE = bit 19.
EXPECTED_CAPEFF = (1 << 2) | (1 << 19)


def drop_to_probe() -> None:
    os.setgroups([])
    os.setgid(0)
    os.setuid(1001)


def attempt(interp: str, pid: int) -> tuple[bool, int]:
    code = (
        "import sys\n"
        "eff = [l.split()[1] for l in open('/proc/self/status') if l.startswith('CapEff')][0]\n"
        "try:\n"
        f"    open('/proc/{pid}/maps').read(64); ok = 1\n"
        "except PermissionError:\n"
        "    ok = 0\n"
        "print(ok, eff)\n"
    )
    out = subprocess.run(
        [interp, "-I", "-c", code],
        preexec_fn=drop_to_probe,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    return out[0] == "1", int(out[1], 16)


def main() -> int:
    target = subprocess.Popen(
        ["/bin/sleep", "60"], preexec_fn=lambda: (os.setgid(2000), os.setuid(2000))
    )
    try:
        time.sleep(0.3)
        capped_ok, capped_eff = attempt(CAPPED, target.pid)
        system_ok, system_eff = attempt(SYSTEM, target.pid)
    finally:
        target.kill()
    print(f"capped interpreter: read={capped_ok} CapEff={capped_eff:#x}")
    print(f"system interpreter: read={system_ok} CapEff={system_eff:#x}")
    failures = []
    if not capped_ok:
        failures.append("capped interpreter could not read another UID's maps")
    if capped_eff != EXPECTED_CAPEFF:
        failures.append(f"capped CapEff {capped_eff:#x} != {EXPECTED_CAPEFF:#x}")
    if system_ok or system_eff:
        failures.append("system python3 gained access or capabilities")
    for f in failures:
        print("FAIL:", f)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
