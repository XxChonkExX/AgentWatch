"""YARA bridge.

Wraps the `yara` CLI against a rules directory (default: `rules/yara`). If
the CLI or the rules are absent, the scanner reports unavailable. Rule
matches default to severity `high`; a rule can raise its own severity once
meta parsing lands (stated as a limit today).
"""

from __future__ import annotations

import os
import shutil
import subprocess

from .base import ScanHit, Scanner
from .proc import run_on_bytes


class YaraScanner(Scanner):
    name = "yara"

    def __init__(self, rules_dir: str | None = None, binary: str | None = None):
        # binary="" is the explicit "disabled" sentinel (live_av=False).
        if binary is not None:
            self.binary = binary or None
        else:
            self.binary = shutil.which("yara") or shutil.which("yara64")
        self.rules_dir = rules_dir

    def rule_files(self) -> list[str]:
        if not self.rules_dir or not os.path.isdir(self.rules_dir):
            return []
        out: list[str] = []
        for root, _dirs, files in os.walk(self.rules_dir):
            for f in files:
                if f.lower().endswith((".yar", ".yara")):
                    out.append(os.path.join(root, f))
        return sorted(out)

    def available(self) -> bool:
        return bool(self.binary) and bool(self.rule_files())

    def version(self) -> str | None:
        if not self.binary:
            return None
        try:
            proc = subprocess.run(
                [self.binary, "--version"], capture_output=True, text=True, timeout=15
            )
            text = (proc.stdout or proc.stderr or "").strip().splitlines()
            return text[0] if text else None
        except Exception:
            return None

    def scan_bytes(self, data: bytes, name: str) -> list[ScanHit]:
        if not self.available():
            return []
        files = self.rule_files()
        _, out, _ = run_on_bytes(
            lambda p: [self.binary, "-r"] + files + [p],
            data,
            suffix=".bin",
        )
        hits: list[ScanHit] = []
        for line in (out or "").splitlines():
            line = line.strip()
            if not line or "error:" in line.lower():
                continue
            rule = line.split()[0]
            hits.append(
                ScanHit(
                    scanner=self.name,
                    signature=rule,
                    severity="high",
                    detail="YARA rule match: %s" % rule,
                    version=self.version() or "",
                )
            )
        return hits
