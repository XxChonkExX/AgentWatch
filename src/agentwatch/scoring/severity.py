"""Severity ladder and finding ranking.

Frozen ladder: info < low < medium < high < critical. Ranking is
deterministic: severity first, then rule id, then target, then detail. Two
identical sweeps produce identical order, which is what makes a diff between
two reports meaningful.
"""

from __future__ import annotations

from typing import Iterable

from ..core.schema import SEVERITY_ORDER, SEVERITY_RANK


def rank(findings: Iterable) -> list:
    return sorted(
        findings,
        key=lambda f: (
            -SEVERITY_RANK.get(f.severity, 0),
            f.rule_id,
            f.target,
            f.detail,
        ),
    )


def counts(findings: Iterable) -> dict:
    out = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        out[f.severity] = out.get(f.severity, 0) + 1
    return out


def worst(findings: Iterable) -> str:
    best = 0
    for f in findings:
        best = max(best, SEVERITY_RANK.get(f.severity, 0))
    return SEVERITY_ORDER[best]


def at_or_above(findings: Iterable, threshold: str) -> list:
    floor = SEVERITY_RANK.get(threshold, 0)
    return [f for f in findings if SEVERITY_RANK.get(f.severity, 0) >= floor]
