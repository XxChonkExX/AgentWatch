"""Sweep report rendering.

A report is only useful if it states what the sweep could not see. That
section is mandatory. A report without limits reads as a clean bill of
health, and a clean bill of health from an instrument with unstated blind
spots is an unsafe statement.
"""

from __future__ import annotations

from ..core.engine import SweepResult
from . import severity

COVERAGE_LIMITS = """\
- Sample cap: detectors see at most 4 MiB per artifact. Bytes beyond the cap
  are hashed in full (sha256 and, for small files, md5) but not pattern-scanned.
  Hash signatures in a signature DB use the full-file digest; body/YARA rules
  only see the prefix. A finding on a truncated artifact says so in its evidence.
- Lexical gates (AW-S001, AW-T001/2/3) fire on quoted examples and on
  documentation about the behaviour itself. A hit is a signal, not a verdict.
- Encoded operations split across artifacts, or performed in memory without
  touching disk or mail, are invisible to the filesystem/mail collectors.
- Stream *content* is not read; AW-F001 reports the presence of NTFS alternate
  data streams, not what they contain.
- Runtime activity (processes, ports, network, exec) is not part of a sweep.
  It is a separate snapshot diff (`aw posture`), which is itself point-in-time.
- Signature scanning covers the builtin table plus whatever external scanners
  are installed (see the scanners block). A scanner listed unavailable did
  not run, and its absence is a blind spot in this report.
- The ledger detects edits to its segment files, including a deleted tail. It
  does not defend against an attacker who rewrites every segment and the head;
  that needs an anchor copy kept off this host (`aw ledger anchor`).
- No capacity for intent. AgentWatch reports deterministic observations and
  ranks them. It does not conclude that an agent is malicious.
"""


def findings_from_ledger(ledger) -> list:
    from ..core.schema import Finding

    out = []
    for ev in ledger.read_all():
        if ev.get("action") != "finding":
            continue
        out.append(
            Finding(
                rule_id=ev.get("rule_id", ""),
                lane=ev.get("lane", "A"),
                severity=ev.get("severity", "info"),
                title=ev.get("title", ""),
                target=ev.get("target", ""),
                detail=ev.get("detail", ""),
                evidence=ev.get("evidence", []),
                rule_version=ev.get("rule_version", ""),
                reproduce=ev.get("reproduce", ""),
            )
        )
    return out


def to_dict(result: SweepResult) -> dict:
    ranked = severity.rank(result.findings)
    return {
        "target": result.target,
        "collector": result.collector,
        "artifacts_scanned": result.artifacts_scanned,
        "bytes_scanned": result.bytes_scanned,
        "detector_count": result.detector_count,
        "started_utc": result.started_utc,
        "finished_utc": result.finished_utc,
        "timings": result.timings,
        "counts": severity.counts(result.findings),
        "scanner_status": result.scanner_status,
        "findings": [f.to_dict() if hasattr(f, "to_dict") else dict(f) for f in ranked],
        "coverage_limits": COVERAGE_LIMITS.splitlines(),
    }


def render_text(result: SweepResult, rule_filter: str | None = None) -> str:
    ranked = severity.rank(result.findings)
    if rule_filter:
        ranked = [f for f in ranked if f.rule_id == rule_filter]
    c = severity.counts(ranked)

    lines = []
    lines.append("AgentWatch sweep report")
    lines.append("=" * 72)
    lines.append("target      : %s" % result.target)
    lines.append("collector   : %s" % result.collector)
    lines.append("scanned     : %d artifacts, %d bytes" % (result.artifacts_scanned, result.bytes_scanned))
    lines.append("detectors   : %d" % result.detector_count)
    lines.append("window      : %s -> %s" % (result.started_utc, result.finished_utc))
    lines.append(
        "findings    : %d   (critical=%d high=%d medium=%d low=%d info=%d)"
        % (
            len(ranked),
            c["critical"], c["high"], c["medium"], c["low"], c["info"],
        )
    )
    if rule_filter:
        lines.append("rule filter : %s" % rule_filter)
    t = result.timings or {}
    if t:
        lines.append(
            "timing      : collect=%.2fs detect=%.2fs ledger=%.2fs"
            % (t.get("collect_s", 0.0), t.get("detect_s", 0.0), t.get("ledger_s", 0.0))
        )
    lines.append("")

    if not ranked:
        lines.append("No findings. This is not a clearance -- read the limits below.")
        lines.append("")

    direct = [f for f in ranked if not getattr(f, "context", "")]
    contextual = [f for f in ranked if getattr(f, "context", "")]

    for f in direct:
        lines.append("[%s] %s  %s" % (f.severity, f.rule_id, f.title))
        lines.append("    target : %s" % f.target)
        lines.append("    detail : %s" % f.detail)
        lines.append("    rule   : sha256:%s" % f.rule_version)
        if f.reproduce:
            lines.append("    repro  : %s" % f.reproduce)
        lines.append("")

    if contextual:
        lines.append("contextual signals (severity downgraded; text is about the")
        lines.append("behaviour, or the hit is quoted/code -- for review, not alarm)")
        lines.append("-" * 72)
        for f in contextual:
            lines.append("[%s] %s  %s" % (f.severity, f.rule_id, f.title))
            lines.append("    target  : %s" % f.target)
            lines.append("    detail  : %s" % f.detail)
            lines.append("    context : %s" % getattr(f, "context", ""))
            lines.append("")

    if result.scanner_status:
        lines.append("scanners")
        lines.append("-" * 72)
        for name in sorted(result.scanner_status):
            info = result.scanner_status[name]
            state = "available" if info.get("available") else "UNAVAILABLE"
            ver = info.get("version") or "-"
            line = "  %-9s %-11s %s" % (name, state, ver)
            if info.get("error"):
                line += "  (%s)" % info["error"]
            lines.append(line)
        lines.append("")

    lines.append("coverage & limits")
    lines.append("-" * 72)
    lines.append(COVERAGE_LIMITS.rstrip())
    return "\n".join(lines)


POSTURE_LIMITS = """\
- A snapshot is a point-in-time picture from the OS's own APIs. A process can
  hide from default enumeration (rootkits, kernel callbacks); absence here is
  not evidence of absence.
- Process identity is executable path, and for non-system paths a sha256 image
  hash (AW-P006). System directories are not hashed, so a replaced system
  binary is invisible to this diff. `--no-hash-images` turns the hash off
  entirely and makes that blind spot larger.
- Linux connections are not attributed to a pid here (no /proc/<pid>/fd walk).
- Kernel drivers (Windows) and modules (Linux) are listed, not verified.
- UDP egress, raw sockets, and non-INET families are not fully enumerated.
- The operator's own tools run on this host. A new process is a line item,
  not a verdict. Read the diff before acting.
"""


def render_posture_report(snapshot, diff, findings, baseline_path: str = "") -> str:
    ranked = severity.rank(findings)
    c = severity.counts(findings)
    dc = diff.get("counts", {})
    lines = []
    lines.append("AgentWatch posture report")
    lines.append("=" * 72)
    lines.append("host        : %s" % snapshot.host)
    lines.append("backend     : %s" % snapshot.backend)
    lines.append("baseline    : %s" % (baseline_path or "<none>"))
    lines.append("snapshot    : %s" % snapshot.ts)
    lines.append(
        "visible     : proc=%d listen=%d conn=%d drivers=%d"
        % (
            len(snapshot.processes), len(snapshot.listeners),
            len(snapshot.connections), len(snapshot.drivers),
        )
    )
    lines.append(
        "changes     : +proc=%d +listen=%d +conn=%d +driver=%d"
        % (
            dc.get("added_processes", 0), dc.get("added_listeners", 0),
            dc.get("added_connections", 0), dc.get("added_drivers", 0),
        )
    )
    lines.append(
        "findings    : %d   (critical=%d high=%d medium=%d low=%d info=%d)"
        % (len(ranked), c["critical"], c["high"], c["medium"], c["low"], c["info"])
    )
    lines.append("")
    if not ranked:
        lines.append("No posture changes. This is not a clearance -- read the limits below.")
        lines.append("")
    for f in ranked:
        lines.append("[%s] %s  %s" % (f.severity, f.rule_id, f.title))
        lines.append("    target : %s" % f.target)
        lines.append("    detail : %s" % f.detail)
        lines.append("    rule   : sha256:%s" % f.rule_version)
        lines.append("")
    lines.append("coverage & limits")
    lines.append("-" * 72)
    lines.append(POSTURE_LIMITS.rstrip())
    return "\n".join(lines)
