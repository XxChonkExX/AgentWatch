"""ClamAV bridge.

Wraps `clamscan` (or `clamdscan`) if present on PATH. The signature database
version is captured per hit so a match can be reproduced against the same
signatures. If ClamAV is absent, this scanner reports unavailable and is
listed as a blind spot in the report -- it is never silently skipped.
"""

from __future__ import annotations

import os
import shutil
import subprocess

from .base import ScanHit, Scanner
from .proc import run_on_bytes


class ClamAVScanner(Scanner):
    name = "clamav"

    def __init__(self, binary: str | None = None):
        # binary="" is the explicit "disabled" sentinel (live_av=False).
        if binary is not None:
            self.binary = binary or None
        else:
            self.binary = shutil.which("clamscan") or shutil.which("clamdscan")

    def available(self) -> bool:
        return bool(self.binary)

    def version(self) -> str | None:
        if not self.binary:
            return None
        try:
            proc = subprocess.run(
                [self.binary, "--version"], capture_output=True, text=True, timeout=15
            )
            lines = (proc.stdout or "").strip().splitlines()
            return lines[0] if lines else None
        except Exception:
            return None

    def scan_bytes(self, data: bytes, name: str) -> list[ScanHit]:
        if not self.available():
            return []
        suffix = os.path.splitext(name)[1] or ".bin"
        _, out, _ = run_on_bytes(
            lambda p: [self.binary, "--no-summary", "--stdout", p],
            data,
            suffix=suffix,
        )
        hits: list[ScanHit] = []
        for line in (out or "").splitlines():
            if " FOUND" not in line:
                continue
            signature = line.rsplit(":", 1)[-1]
            signature = signature.rsplit(" FOUND", 1)[0].strip() or "unknown"
            hits.append(
                ScanHit(
                    scanner=self.name,
                    signature=signature,
                    severity="critical",
                    detail="ClamAV match: %s" % signature,
                    version=self.version() or "",
                )
            )
        return hits
