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
  are hashed in full but not pattern-scanned.
- Lexical gates (AW-S001, AW-T001/2/3) fire on quoted examples and on
  documentation about the behaviour itself. A hit is a signal, not a verdict.
- Encoded operations split across artifacts, or performed in memory without
  touching disk or mail, are invisible to the M0 filesystem/mail collectors.
- Stream *content* is not read in M0; AW-F001 reports the presence of NTFS
  alternate data streams, not what they contain.
- Runtime activity (processes, ports, network, exec) is not collected in M0.
  That is the M2/M4 milestone; until then, "hidden danger" claims are out of
  scope and are not made.
- The ledger detects edits to the ledger file. It does not defend against an
  attacker who rewrites the entire chain; external anchoring is not yet built.
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
        "counts": severity.counts(result.findings),
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
    lines.append("")

    if not ranked:
        lines.append("No findings. This is not a clearance -- read the limits below.")
        lines.append("")

    for f in ranked:
        lines.append("[%s] %s  %s" % (f.severity, f.rule_id, f.title))
        lines.append("    target : %s" % f.target)
        lines.append("    detail : %s" % f.detail)
        lines.append("    rule   : sha256:%s" % f.rule_version)
        if f.reproduce:
            lines.append("    repro  : %s" % f.reproduce)
        lines.append("")

    lines.append("coverage & limits")
    lines.append("-" * 72)
    lines.append(COVERAGE_LIMITS.rstrip())
    return "\n".join(lines)
