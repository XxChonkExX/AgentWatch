"""Detector contract and shared helpers.

A detector receives one Artifact and returns Findings. It must not mutate the
Artifact, read other artifacts, or reach the network. Lane A only in M0: every
result here must reproduce bit-for-bit from the artifact bytes.
"""

from __future__ import annotations

from typing import Iterable, Optional, Sequence

from ..core.hashing import hash_bytes
from ..core.schema import Artifact, Evidence, Finding, Rule


class Detector:
    name = "detector"
    rule: Rule

    def run(self, artifact: Artifact) -> list[Finding]:
        raise NotImplementedError

    @staticmethod
    def finding(
        rule: Rule,
        artifact: Artifact,
        detail: str,
        evidence: Optional[list] = None,
        severity: Optional[str] = None,
    ) -> Finding:
        return Finding(
            rule_id=rule.rule_id,
            lane=rule.lane,
            severity=severity or rule.severity,
            title=rule.title,
            target=artifact.path,
            detail=detail,
            evidence=evidence or [],
            rule_version=rule.version,
            reproduce=f'aw sweep --rule {rule.rule_id} "{artifact.path}"',
        )


def _excerpt_evidence(artifact: Artifact, text: str, start: int, end: int, note: str) -> Evidence:
    chunk = text[start:end]
    return Evidence(
        path=artifact.path,
        span=(start, end),
        excerpt_hash=hash_bytes(chunk.encode("utf-8", "ignore")),
        note=note,
    )


def pattern_findings(
    detector: Detector,
    artifact: Artifact,
    rule: Rule,
    patterns: Sequence,
    text_only: bool = True,
) -> list[Finding]:
    """Run (regex, label, severity) tuples over artifact.text.

    Emits one finding per pattern that fires, carrying the hit count and the
    offset of the first hit. Order-stable: patterns are evaluated in order.
    """
    if text_only and not artifact.is_text:
        return []
    text = artifact.text or ""
    out: list[Finding] = []
    for rx, label, severity in patterns:
        matches = list(rx.finditer(text))
        if not matches:
            continue
        first = matches[0]
        evidence = [_excerpt_evidence(artifact, text, first.start(), first.end(), label)]
        detail = "%s x%d (first at offset %d)" % (label, len(matches), first.start())
        out.append(detector.finding(rule, artifact, detail, evidence, severity=severity))
    return out
