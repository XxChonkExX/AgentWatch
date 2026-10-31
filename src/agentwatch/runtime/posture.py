"""Posture analysis: turn a snapshot diff into Lane-A findings.

Every finding names its rule and carries the diff evidence. Severity escalates
only on deterministic conditions (bind address, risky port, temp-path
execution, kernel change). There is no heuristic "maliciousness" score.

The operator's own tools run on this host too. A new process is not a threat;
it is a line item. The report says so.
"""

from __future__ import annotations

import re

from ..core.schema import Evidence, Finding, LANE_DETERMINISTIC
from ..detectors.rules import AW_P001, AW_P002, AW_P003, AW_P004, AW_P005, AW_P006

# Deterministic risk markers for AW-P004.
TEMP_HINTS = ("\\temp\\", "/tmp/", "/dev/shm/", "\\appdata\\local\\temp\\", "/var/tmp/")
LOLBINS = {
    "rundll32.exe", "regsvr32.exe", "mshta.exe", "wmic.exe", "bitsadmin.exe",
    "certutil.exe", "installutil.exe", "msbuild.exe", "cscript.exe",
    "wscript.exe", "forfiles.exe", "pcalua.exe", "msdt.exe",
}
OBFUSCATION_MARKERS = re.compile(
    r"(-enc(odedcommand)?\b|-e\s+[A-Za-z0-9+/=]{40,}|frombase64string|"
    r"\biex\b|invoke-expression|downloadstring|-windowstyle hidden|-w hidden|"
    r"\b-nop\b|\b-noprofile\b.*\b-w\b|bypass|certutil.*-decode)",
    re.I,
)
RISKY_PORTS = {4444, 1337, 31337, 6666, 5555, 2222, 9001, 1080, 8888}
ALL_INTERFACES = ("0.0.0.0", "::", "", "*")


def _finding(rule, target, detail, severity=None, note="") -> Finding:
    ev = [Evidence(path=target, note=note)] if note else []
    return Finding(
        rule_id=rule.rule_id,
        lane=LANE_DETERMINISTIC,
        severity=severity or rule.severity,
        title=rule.title,
        target=target,
        detail=detail,
        evidence=ev,
        rule_version=rule.version,
        reproduce="aw posture --baseline <baseline.json>",
    )


def is_loopback(addr: str) -> bool:
    a = (addr or "").strip().lower()
    return a in ("127.0.0.1", "::1", "localhost") or a.startswith("127.")


def suspicious_reasons(proc) -> list:
    reasons = []
    exe = (proc.exe or "").replace("/", "\\").lower()
    cmd = proc.cmdline or ""
    exe_fwd = (proc.exe or "").replace("\\", "/").lower()
    if any(h.replace("/", "\\") in exe for h in TEMP_HINTS) or any(
        h in exe_fwd for h in ("/tmp/", "/dev/shm/", "/var/tmp/")
    ):
        reasons.append("executes from a temp/user-writable path")
    name = (proc.name or "").lower()
    if name in LOLBINS and OBFUSCATION_MARKERS.search(cmd):
        reasons.append("LOLBin %s with obfuscated/quiet arguments" % name)
    elif OBFUSCATION_MARKERS.search(cmd):
        reasons.append("command line carries an obfuscation/encoded marker")
    return reasons


def analyze(diff: dict, snapshot, allow_ports=(), allow_processes=(),
            ignore_loopback: bool = True, scan_all_processes: bool = False) -> list:
    allow_ports = set(allow_ports or ())
    allow_processes = {(p or "").lower() for p in (allow_processes or ())}
    findings: list = []

    for lst in diff.get("added_listeners", []):
        if lst.port in allow_ports:
            continue
        sev = "high" if str(lst.addr) in ALL_INTERFACES else "medium"
        if lst.port in RISKY_PORTS:
            sev = "high"
        findings.append(
            _finding(
                AW_P001,
                "listener:%s/%d" % (lst.proto, lst.port),
                "%s %s:%d is listening (pid %s)" % (lst.proto, lst.addr, lst.port, lst.pid or "?"),
                severity=sev,
                note="new listener not in baseline",
            )
        )

    for c in diff.get("added_connections", []):
        if ignore_loopback and is_loopback(c.remote_addr):
            continue
        findings.append(
            _finding(
                AW_P002,
                "conn:%s:%d->%s:%d" % (c.proto, c.local_port, c.remote_addr, c.remote_port),
                "%s connection to %s:%d" % (c.proto, c.remote_addr, c.remote_port),
                note="new outbound connection not in baseline",
            )
        )

    new_procs = list(diff.get("added_processes", []))
    if scan_all_processes:
        new_procs = list(snapshot.processes)
    seen_suspicious = set()
    for p in new_procs:
        if (p.name or "").lower() in allow_processes or (p.exe or "").lower() in allow_processes:
            continue
        findings.append(
            _finding(
                AW_P003,
                "process:%s:%d" % (p.name, p.pid),
                "%s (pid %d) exe=%s" % (p.name, p.pid, p.exe or "?"),
            )
        )
        reasons = suspicious_reasons(p)
        if reasons:
            key = (p.name or "").lower()
            if key in seen_suspicious:
                continue
            seen_suspicious.add(key)
            findings.append(
                _finding(
                    AW_P004,
                    "process:%s:%d" % (p.name, p.pid),
                    "%s (pid %d): %s" % (p.name, p.pid, "; ".join(reasons)),
                    severity="high",
                    note="cmdline: %s" % (p.cmdline or "")[:300],
                )
            )

    for d in diff.get("added_drivers", []):
        findings.append(
            _finding(
                AW_P005,
                "driver:%s" % d.name,
                "driver/module %s loaded (path=%s state=%s)" % (d.name, d.path or "?", d.state or "?"),
                note="new kernel driver/module not in baseline",
            )
        )

    for ch in diff.get("changed_images", []):
        findings.append(
            _finding(
                AW_P006,
                "process:%s" % ch["name"],
                "%s: image replaced at %s (sha %s.. -> %s..)"
                % (ch["name"], ch["identity"], ch["from"][:12], ch["to"][:12]),
                severity="high",
                note="binary replaced at a known path",
            )
        )

    return findings
