"""Covert whitespace channel.

Whitespace used as a carrier rather than layout. Three deterministic signals:
heavy trailing-whitespace patterns, long internal space/tab runs, and exotic
Unicode space characters. Low severity by design; repeated/consistent
patterns are the evidence, not a single occurrence.
"""

from __future__ import annotations

import re

from ..core.schema import Artifact, Evidence, Finding
from .base import Detector
from .rules import AW_C001

# Trailing runs of exactly two spaces are the CommonMark hard-line-break and
# are legitimate in markdown. Only runs of three or more count as a channel.
TRAILING_RE = re.compile(r"[ \t]{3,}$", re.M)
# 8 consecutive spaces is ordinary markdown/code alignment. A covert channel
# needs a longer run than formatting produces, so the bar is 16.
RUN_RE = re.compile(r"[ \t]{16,}")
UNICODE_SPACES = (
    {0x00A0, 0x1680, 0x202F, 0x205F, 0x3000, 0x2028, 0x2029}
    | set(range(0x2000, 0x200B))
)
TRAILING_MIN_LINES = 5
TRAILING_MIN_CHARS = 40
RUN_MIN_COUNT = 5
UNICODE_SPACE_MIN = 3


class CovertWhitespaceDetector(Detector):
    name = "covert.whitespace"
    rule = AW_C001

    def run(self, artifact: Artifact) -> list[Finding]:
        if not artifact.is_text:
            return []
        text = artifact.text or ""
        out: list[Finding] = []

        lines = text.splitlines()
        trailing = [ln for ln in lines if TRAILING_RE.search(ln)]
        total = sum(len(TRAILING_RE.search(ln).group(0)) for ln in trailing)
        if len(trailing) >= TRAILING_MIN_LINES and total >= TRAILING_MIN_CHARS:
            detail = "trailing whitespace on %d lines (%d chars total)" % (len(trailing), total)
            ev = [Evidence(path=artifact.path, note="trailing-whitespace")]
            out.append(self.finding(self.rule, artifact, detail, ev))

        runs = RUN_RE.findall(text)
        if len(runs) >= RUN_MIN_COUNT:
            detail = "%d internal whitespace run(s) of 8+ chars" % len(runs)
            ev = [Evidence(path=artifact.path, note="whitespace-run")]
            out.append(self.finding(self.rule, artifact, detail, ev))

        exotic = [c for c in text if ord(c) in UNICODE_SPACES]
        if len(exotic) >= UNICODE_SPACE_MIN:
            detail = "%d exotic Unicode space character(s)" % len(exotic)
            ev = [Evidence(path=artifact.path, note="unicode-space")]
            out.append(self.finding(self.rule, artifact, detail, ev))

        return out
