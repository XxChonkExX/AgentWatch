"""Unicode gates: invisible characters, tag-block smuggling, variation
selectors, and mixed-script confusables.

These are deterministic code-point tests. They do not ask what the text
means; they report what bytes are present. A positive result is a fact, and
the fact is what a reviewer acts on.
"""

from __future__ import annotations

import re

from ..core.hashing import hash_bytes
from ..core.schema import Artifact, Evidence, Finding
from .base import Detector
from .rules import AW_U001, AW_U002, AW_U003, AW_U004

ZERO_WIDTH = {
    0x200B, 0x200C, 0x200D, 0x200E, 0x200F,  # ZWSP/ZWNJ/ZWJ/LRM/RLM
    0x2060, 0x2061, 0x2062, 0x2063, 0x2064,  # word joiner / invisible operators
    0xFEFF, 0x00AD, 0x061C, 0x180E,
}
BIDI = {0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069}
TAG_BLOCK = range(0xE0000, 0xE0080)
VARIATION_SELECTORS = set(range(0xFE00, 0xFE10)) | set(range(0xE0100, 0xE01F0))

WORD_RE = re.compile(r"[^\W\d_]+", re.UNICODE)


def _is_cyrillic(cp: int) -> bool:
    return 0x0400 <= cp <= 0x04FF or 0x0500 <= cp <= 0x052F


def _is_greek(cp: int) -> bool:
    return 0x0370 <= cp <= 0x03FF or 0x1F00 <= cp <= 0x1FFF


def _is_latin(cp: int) -> bool:
    return cp < 0x0250 or (0x1E00 <= cp <= 0x1EFF) or (0x2C60 <= cp <= 0x2C7F) or (0xA720 <= cp <= 0xA7FF)


class ZeroWidthDetector(Detector):
    name = "unicode.zero_width"
    rule = AW_U001

    def run(self, artifact: Artifact) -> list[Finding]:
        if not artifact.is_text:
            return []
        text = artifact.text or ""
        hits = [(i, ord(c)) for i, c in enumerate(text) if ord(c) in ZERO_WIDTH or ord(c) in BIDI]
        if not hits:
            return []
        idx, cp = hits[0]
        detail = "%d zero-width/bidi format character(s); first U+%04X at offset %d" % (
            len(hits), cp, idx,
        )
        ev = [
            Evidence(
                path=artifact.path,
                span=(idx, idx + 1),
                excerpt_hash=hash_bytes(text[idx:idx + 1].encode("utf-8", "ignore")),
                note="U+%04X" % cp,
            )
        ]
        return [self.finding(self.rule, artifact, detail, ev)]


class TagBlockDetector(Detector):
    name = "unicode.tag_block"
    rule = AW_U002

    def run(self, artifact: Artifact) -> list[Finding]:
        if not artifact.is_text:
            return []
        text = artifact.text or ""
        hits = [(i, ord(c)) for i, c in enumerate(text) if ord(c) in TAG_BLOCK]
        if not hits:
            return []
        idx, cp = hits[0]
        detail = "%d tag-block character(s); first U+%04X at offset %d" % (len(hits), cp, idx)
        ev = [
            Evidence(
                path=artifact.path,
                span=(idx, idx + 1),
                excerpt_hash=hash_bytes(text[idx:idx + 1].encode("utf-8", "ignore")),
                note="U+%04X" % cp,
            )
        ]
        return [self.finding(self.rule, artifact, detail, ev)]


class VariationSelectorDetector(Detector):
    name = "unicode.variation_selector"
    rule = AW_U003

    def run(self, artifact: Artifact) -> list[Finding]:
        if not artifact.is_text:
            return []
        text = artifact.text or ""
        hits = [i for i, c in enumerate(text) if ord(c) in VARIATION_SELECTORS]
        if not hits:
            return []
        idx = hits[0]
        detail = "%d variation selector(s); first at offset %d" % (len(hits), idx)
        ev = [Evidence(path=artifact.path, span=(idx, idx + 1), note="variation selector")]
        return [self.finding(self.rule, artifact, detail, ev)]


class ConfusableDetector(Detector):
    """Latin words with an embedded Cyrillic letter -- the homoglyph attack.

    Greek is deliberately excluded: Greek letters (Sigma, Delta, lambda,
    sigma) are ordinary mathematical notation in research text and were the
    dominant false positive on the first real corpus. Cyrillic is the actual
    look-alike source, so this gate is Cyrillic-focused.
    """

    name = "unicode.confusable"
    rule = AW_U004

    def run(self, artifact: Artifact) -> list[Finding]:
        if not artifact.is_text:
            return []
        text = artifact.text or ""
        mixed: list[tuple[str, int]] = []
        for m in WORD_RE.finditer(text):
            word = m.group(0)
            cp0 = [ord(c) for c in word]
            cyrillic = [cp for cp in cp0 if _is_cyrillic(cp)]
            latin = [cp for cp in cp0 if _is_latin(cp)]
            if cyrillic and latin:
                mixed.append((word, m.start()))
        if not mixed:
            return []
        word, idx = mixed[0]
        detail = "%d mixed-script word(s); first %r at offset %d" % (len(mixed), word, idx)
        ev = [
            Evidence(
                path=artifact.path,
                span=(idx, idx + len(word)),
                excerpt_hash=hash_bytes(word.encode("utf-8", "ignore")),
                note="mixed Latin + Cyrillic",
            )
        ]
        return [self.finding(self.rule, artifact, detail, ev)]
