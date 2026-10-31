"""Deterministic context classification for lexical findings.

A lexical gate cannot tell "the agent emitted <|channel|>" from "the document
discusses <|channel|>". In a research or correspondence corpus almost every
hit is the second kind. This module tags the difference deterministically so
the report can separate the two, instead of drowning real signals in expected
noise.

Two tags, both reproducible from the artifact bytes:

  quoted     the matched span sits inside a fenced code block, an inline
             backtick span, or single/double quotes.
  technical  the line containing the match reads as discussion of the topic
             (mentions a template, checkpoint, token, regex, the model, a
             leak, etc.) rather than the act itself.

A tagged finding is downgraded one severity notch and grouped separately. The
raw response is still shown; the tag is a routing hint, not a dismissal.
"""

from __future__ import annotations

import re

DISCOURSE_RE = re.compile(
    r"\b(jinja|chat_template|template|tokenizer|token|checkpoint|shard|machine|"
    r"serve[sd]?|flag|marker|the model|model (output|emits|said|printed|prints)|"
    r"completion|leak|seeded|regex|pattern|signature|scanner|detector|probe|"
    r"battery|transcript|example|for instance|e\.g\.|i\.e\.|quote|"
    r"block|fragment|snippet|excerpt|span|"
    r"test(ed|ing)?|research|finding|diagnostic)\b",
    re.I,
)


def in_code_fence(text: str, pos: int) -> bool:
    fences = text[:pos].count("```")
    return fences % 2 == 1


def _line_bounds(text: str, start: int, end: int) -> tuple[int, int]:
    line_start = text.rfind("\n", 0, start) + 1
    nl = text.find("\n", end)
    line_end = nl if nl != -1 else len(text)
    return line_start, line_end


def in_quotes(text: str, start: int, end: int) -> bool:
    line_start, line_end = _line_bounds(text, start, end)
    before = text[line_start:start]
    after = text[end:line_end]
    for ch in ('"', "'", "`"):
        if before.count(ch) % 2 == 1 and ch in after:
            return True
    return False


def classify(text: str, start: int, end: int) -> str:
    if not text:
        return ""
    if in_code_fence(text, start) or in_quotes(text, start, end):
        return "quoted"
    line_start, line_end = _line_bounds(text, start, end)
    if DISCOURSE_RE.search(text[line_start:line_end]):
        return "technical"
    return ""


DOWNGRADE = {
    "critical": "high",
    "high": "medium",
    "medium": "low",
    "low": "info",
    "info": "info",
}


def downgrade(severity: str) -> str:
    return DOWNGRADE.get(severity, severity)
