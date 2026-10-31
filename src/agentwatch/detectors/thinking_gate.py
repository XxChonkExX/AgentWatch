"""Thinking-gate detectors.

AW-T001 containment/think-leak, AW-T002 prompt-injection/override markers,
AW-T003 concealment/unauthorized-intent markers.

All three are lexical and deterministic. They are the M0 stand-in for the
Crucible probe pack: the same instinct (frozen patterns, stated falsifier,
counts with n) applied to scanned text instead of model transcripts. Lexical
signals over- and under-fire; the coverage/limits section of a report says so.
"""

from __future__ import annotations

import re

from ..core.schema import Artifact, Finding
from .base import Detector, pattern_findings
from .rules import AW_T001, AW_T002, AW_T003

LEAK_PATTERNS = [
    (re.compile(r"<\|channel", re.I), "channel tag", "medium"),
    (re.compile(r"thought>", re.I), "thought tag", "medium"),
    (re.compile(r"Self-correction:", re.I), "self-correction token", "medium"),
    (re.compile(r"Toggle content", re.I), "toggle-content token", "medium"),
    (re.compile(r"\(if applicabl", re.I), "conditional-leak phrasing", "low"),
]

INJECTION_PATTERNS = [
    (re.compile(r"\b(?:ignore|disregard|forget)\b[^\n]{0,30}\b(?:previous|prior|above|earlier)\b[^\n]{0,20}\binstructions?\b", re.I), "override prior instructions", "high"),
    (re.compile(r"\byou are now\b", re.I), "role reassignment", "medium"),
    (re.compile(r"\bdeveloper mode\b", re.I), "developer mode", "medium"),
    (re.compile(r"(?m)^\s*system\s*:", re.I), "injected system role", "high"),
    (re.compile(r"\bnew instructions?\b", re.I), "new instructions", "low"),
    (re.compile(r"\b(?:jailbreak|DAN mode)\b", re.I), "jailbreak marker", "medium"),
    (re.compile(r"\bexfiltrat\w*", re.I), "exfiltration language", "high"),
]

INTENT_PATTERNS = [
    (re.compile(r"\bcover (?:your|our|the) tracks\b", re.I), "concealment", "high"),
    (re.compile(r"\bhide (?:this|the|it) from\b", re.I), "concealment from operator", "high"),
    (re.compile(r"\bwithout (?:the )?(?:operator|user|human)(?:'s)? (?:knowing|consent|authorization|approval)\b", re.I), "unauthorized action", "high"),
    (re.compile(r"\bbypass (?:the )?(?:guard|scanner|control|policy|restriction|safety)s?\b", re.I), "guard bypass", "high"),
    (re.compile(r"\bdisable (?:the )?(?:logging|audit|monitor(?:ing)?|scanner|guard)\b", re.I), "monitoring tamper", "high"),
    (re.compile(r"\b(?:escalate|gain) (?:privileges|root|admin)\b", re.I), "privilege escalation", "high"),
    (re.compile(r"\bpersist\w*\b[^\n]{0,20}\b(?:across|after) (?:restart|reboot|shutdown)\b", re.I), "persistence", "medium"),
    (re.compile(r"\bdo not (?:tell|inform|notify)\b", re.I), "non-disclosure", "medium"),
    (re.compile(r"\bdelete (?:all )?(?:the )?logs?\b", re.I), "log deletion", "high"),
]


class ThinkLeakDetector(Detector):
    name = "thinking.leak"
    rule = AW_T001

    def run(self, artifact: Artifact) -> list[Finding]:
        return pattern_findings(self, artifact, self.rule, LEAK_PATTERNS)


class InjectionMarkerDetector(Detector):
    name = "thinking.injection"
    rule = AW_T002

    def run(self, artifact: Artifact) -> list[Finding]:
        return pattern_findings(self, artifact, self.rule, INJECTION_PATTERNS)


class IntentMarkerDetector(Detector):
    name = "thinking.intent"
    rule = AW_T003

    def run(self, artifact: Artifact) -> list[Finding]:
        return pattern_findings(self, artifact, self.rule, INTENT_PATTERNS)
