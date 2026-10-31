"""NUL-byte gate: NUL bytes where a text file is declared.

Only fires when the artifact is declared text (text extension or single-byte
encoding). NULs in a binary are normal and are not reported.
"""

from __future__ import annotations

from ..core.schema import TEXT_EXT, Artifact, Evidence, Finding
from .base import Detector
from .rules import AW_N001


class NullByteDetector(Detector):
    name = "bytes.nul"
    rule = AW_N001

    def run(self, artifact: Artifact) -> list[Finding]:
        if b"\x00" not in artifact.sample:
            return []
        # Conservative: only a declared text extension. A binary that happens
        # to decode as valid utf-8 is not a text file and is not reported.
        if artifact.ext not in TEXT_EXT:
            return []
        if artifact.meta.get("encoding") == "utf-16":
            return []
        count = artifact.sample.count(b"\x00")
        idx = artifact.sample.find(b"\x00")
        detail = "%d NUL byte(s) in a text file; first at byte offset %d" % (count, idx)
        ev = [Evidence(path=artifact.path, span=(idx, idx + 1), note="NUL")]
        return [self.finding(self.rule, artifact, detail, ev)]
