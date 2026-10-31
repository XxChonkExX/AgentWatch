"""Windows Defender bridge.

Wraps MpCmdRun.exe (the Defender command-line scanner shipped with Windows)
if present. Exit code 2 is Defender's "threats found"; that is the only
trigger -- output text is not matched, because the clean scan also prints the
word "found". The signature version is captured for reproducibility.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess

from .base import ScanHit, Scanner
from .proc import run_on_bytes

DEFAULT_MPCMDRUN = (
    r"C:\Program Files\Windows Defender\MpCmdRun.exe",
    r"C:\Program Files\Microsoft Security Client\MpCmdRun.exe",
)


class DefenderScanner(Scanner):
    name = "defender"

    def __init__(self, binary: str | None = None):
        # binary="" (empty string) is the explicit "disabled" sentinel used by
        # default_scanners(live_av=False); None means auto-discover.
        if binary is not None:
            self.binary = binary or None
        else:
            self.binary = (
                next((c for c in DEFAULT_MPCMDRUN if os.path.isfile(c)), None)
                or shutil.which("MpCmdRun.exe")
            )

    def available(self) -> bool:
        return bool(self.binary) and os.path.isfile(self.binary)

    def version(self) -> str | None:
        if not self.binary:
            return None
        try:
            proc = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                 "(Get-MpComputerStatus).AntivirusSignatureVersion"],
                capture_output=True, text=True, timeout=45,
            )
            version = (proc.stdout or "").strip()
            return ("sig " + version) if version else None
        except Exception:
            return None

    def scan_bytes(self, data: bytes, name: str) -> list[ScanHit]:
        if not self.available():
            return []
        suffix = os.path.splitext(name)[1] or ".bin"
        code, out, err = run_on_bytes(
            lambda p: [self.binary, "-Scan", "-ScanType", "3", "-File", p],
            data, suffix=suffix, timeout=240,
        )
        if code != 2:
            return []
        text = (out or "") + (err or "")
        m = re.search(r"Name:\s*(.+)", text)
        signature = m.group(1).strip() if m else "DefenderThreat"
        return [
            ScanHit(
                scanner=self.name,
                signature=signature,
                severity="critical",
                detail="Windows Defender detection: %s" % signature,
                version=self.version() or "",
            )
        ]
