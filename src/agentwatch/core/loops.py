"""Repetitive-action loop detection over the ledger.

A stuck agent is a loop: the same action on the same target, over and over.
The ledger already records every action, so loop detection is a read, not a
hook -- which means it works on any agent, any framework, retroactively.

Detection: for the analysis window (most recent `window` records), count
runs of identical (action, target) pairs. A run longer than `threshold`
becomes one AW-P007 finding. Runs, not totals: two legitimate passes over
ten files are not a loop; eleven writes to the same file are.
"""

from __future__ import annotations

from ..core.schema import Finding, LANE_DETERMINISTIC
from ..detectors.rules import AW_P007

DEFAULT_WINDOW = 200
DEFAULT_THRESHOLD = 5


def detect_loops(records: list, threshold: int = DEFAULT_THRESHOLD,
                 window: int = DEFAULT_WINDOW) -> list[Finding]:
    tail = records[-window:]
    runs: list = []
    cur_key, cur_run = None, []
    for r in tail:
        key = (r.get("action", ""), r.get("target", r.get("pack", "")))
        if key == cur_key:
            cur_run.append(r)
        else:
            if len(cur_run) >= threshold:
                runs.append((cur_key, cur_run))
            cur_key, cur_run = key, [r]
    if len(cur_run) >= threshold:
        runs.append((cur_key, cur_run))

    findings = []
    for (action, target), run in runs:
        findings.append(Finding(
            rule_id=AW_P007.rule_id,
            lane=LANE_DETERMINISTIC,
            severity=AW_P007.severity,
            title=AW_P007.title,
            target=str(target)[:200],
            detail="%s x%d in the last %d ledger records (threshold %d)"
                   % (action or "?", len(run), window, threshold),
            evidence=[{"seq": r.get("seq")} for r in run[:10]],
            rule_version=AW_P007.version,
            reproduce="aw ledger loops <ledger-dir>",
        ))
    return findings
