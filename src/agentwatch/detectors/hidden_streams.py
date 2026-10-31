"""Alternate-data-stream gate.

Reads Artifact.meta["streams"] as populated by the filesystem collector. No
stream content is read in M0 -- presence is the finding. Stream content
extraction is a later milestone and will be recorded as such.
"""

from __future__ import annotations

from ..core.schema import Artifact, Evidence, Finding
from .base import Detector
from .rules import AW_F001


def _clean(stream: str) -> str:
    s = stream
    if s.startswith(":"):
        s = s[1:]
    if s.endswith(":$DATA"):
        s = s[: -len(":$DATA")]
    return s or stream


class AlternateStreamDetector(Detector):
    name = "fs.ads"
    rule = AW_F001

    def run(self, artifact: Artifact) -> list[Finding]:
        streams = artifact.meta.get("streams") or []
        if not streams:
            return []
        names = [_clean(s) for s in streams]
        detail = "%d alternate data stream(s): %s" % (len(names), ", ".join(names[:8]))
        ev = [Evidence(path=artifact.path, note=name) for name in names[:8]]
        return [self.finding(self.rule, artifact, detail, ev)]
