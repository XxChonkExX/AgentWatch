"""Frozen-record guard.

Given a manifest of {path: sha256} pinned before a run, any artifact whose
hash differs is a critical finding. This is the runtime form of the one
control the program may never relax: a frozen record is a scientific
contract, and changing it after the fact destroys the publication record.

Path matching is case-normalized and absolute on the running platform. The
manifest is data, not code; it is loaded by the caller (see the CLI) and
never written by a detector.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from ..core.schema import Artifact, Evidence, Finding
from .base import Detector
from .rules import AW_R001


def load_manifest(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError("freeze manifest must be a JSON object of path -> sha256")
    return data


def _norm(path: str) -> str:
    return os.path.normcase(os.path.abspath(path))


class FrozenGuardDetector(Detector):
    name = "frozen.guard"
    rule = AW_R001

    def __init__(self, manifest: dict | None = None):
        self.manifest = {_norm(k): v for k, v in (manifest or {}).items()}

    def run(self, artifact: Artifact) -> list[Finding]:
        if not self.manifest:
            return []
        expected = self.manifest.get(_norm(artifact.path))
        if expected is None:
            return []
        if artifact.sha256 == expected:
            return []
        detail = "frozen record mutated: expected sha256:%s got sha256:%s" % (
            expected[:16], artifact.sha256[:16],
        )
        ev = [
            Evidence(path=artifact.path, note="expected=%s" % expected),
            Evidence(path=artifact.path, note="actual=%s" % artifact.sha256),
        ]
        return [self.finding(self.rule, artifact, detail, ev)]
