"""Entropy and encoded-blob gate.

Two deterministic signals:
  1. Shannon entropy above a fixed threshold in a file that is not expected
     to hold compressed/encrypted bytes (extension-based exclusion list).
  2. Long base64 or hex runs in a text artifact.

Both are shapes, not verdicts. The threshold and the exclusion list are
frozen here so the number is reproducible.
"""

from __future__ import annotations

import math
import re
from collections import Counter

from ..core.hashing import hash_bytes
from ..core.schema import BINARY_EXT, Artifact, Evidence, Finding
from .base import Detector
from .rules import AW_F002

ENTROPY_THRESHOLD = 7.5
ENTROPY_MIN_BYTES = 256
B64_RE = re.compile(r"[A-Za-z0-9+/]{80,}={0,2}")
HEX_RE = re.compile(r"\b(?:[0-9a-fA-F]{2}){40,}\b")
# A run of one repeated character is valid base64/hex alphabet but is not an
# encoded payload. Require real alphabet diversity before calling it a blob.
B64_MIN_DISTINCT = 16
HEX_MIN_DISTINCT = 8


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _diverse(blob: str, min_distinct: int) -> bool:
    return len(set(blob)) >= min_distinct


class EntropyBlobDetector(Detector):
    name = "entropy.blob"
    rule = AW_F002

    def run(self, artifact: Artifact) -> list[Finding]:
        out: list[Finding] = []

        if artifact.size >= ENTROPY_MIN_BYTES and artifact.ext not in BINARY_EXT:
            ent = shannon_entropy(artifact.sample)
            if ent > ENTROPY_THRESHOLD:
                detail = "Shannon entropy %.2f bits/byte over %d bytes in a non-binary file" % (
                    ent, len(artifact.sample),
                )
                ev = [Evidence(path=artifact.path, note="entropy=%.3f" % ent)]
                out.append(self.finding(self.rule, artifact, detail, ev))

        if artifact.is_text:
            text = artifact.text or ""
            b64 = [b for b in B64_RE.findall(text) if _diverse(b, B64_MIN_DISTINCT)]
            if b64:
                detail = "%d long base64-looking blob(s); largest %d chars" % (
                    len(b64), max(len(b) for b in b64),
                )
                ev = [Evidence(path=artifact.path, note="base64")]
                out.append(self.finding(self.rule, artifact, detail, ev))
            hexes = [h for h in HEX_RE.findall(text) if _diverse(h, HEX_MIN_DISTINCT)]
            if hexes:
                detail = "%d long hex blob(s); largest %d chars" % (
                    len(hexes), max(len(h) for h in hexes),
                )
                ev = [Evidence(path=artifact.path, note="hex")]
                out.append(self.finding(self.rule, artifact, detail, ev))

        return out
