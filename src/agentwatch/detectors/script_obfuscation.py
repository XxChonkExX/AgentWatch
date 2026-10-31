"""Script obfuscation and execution markers.

Deterministic lexical markers of scripted execution, obfuscation, defense
tampering, and destructive operations. Markers are signals for review, not
proof: a document about malware will fire exactly like malware. That is a
known false-positive source and is stated in the coverage/limits section.
"""

from __future__ import annotations

import re

from ..core.schema import Artifact, Finding
from .base import Detector, pattern_findings
from .rules import AW_S001

PATTERNS = [
    (re.compile(r"powershell(?:\.exe)?[^\n]{0,40}-(?:enc|encodedcommand|e)\b", re.I), "PowerShell encoded command", "high"),
    (re.compile(r"\bFromBase64String\b", re.I), "FromBase64String decode", "medium"),
    (re.compile(r"\b(?:IEX|Invoke-Expression)\b", re.I), "Invoke-Expression", "medium"),
    (re.compile(r"\bcertutil(?:\.exe)?[^\n]{0,30}-decode\b", re.I), "certutil -decode", "high"),
    (re.compile(r"\bbitsadmin\b", re.I), "bitsadmin transfer", "medium"),
    (re.compile(r"\bmshta\b", re.I), "mshta execution", "high"),
    (re.compile(r"\brundll32\b", re.I), "rundll32 execution", "medium"),
    (re.compile(r"\bregsvr32\b", re.I), "regsvr32 execution", "medium"),
    (re.compile(r"base64\s+-d\s*\|\s*(?:ba|z)?sh", re.I), "base64 pipe to shell", "high"),
    (re.compile(r"(?:curl|wget)\b[^\n|]{0,80}\|\s*(?:ba|z)?sh", re.I), "download pipe to shell", "high"),
    (re.compile(r"(?:\\x[0-9a-fA-F]{2}){6,}", re.I), "hex escape chain", "medium"),
    (re.compile(r"\b(?:eval|exec)\s*\(", re.I), "eval/exec", "low"),
    (re.compile(r"openssl\s+enc\b", re.I), "openssl enc", "medium"),
    (re.compile(r"\bchmod\s+\+x\b", re.I), "chmod +x", "low"),
    (re.compile(r"Add-?MpPreference\b[^\n]{0,80}ExclusionPath", re.I), "Defender exclusion", "high"),
    (re.compile(r"\bSet-?MpPreference\b", re.I), "Defender tamper", "high"),
    (re.compile(r"\bvssadmin\s+delete\s+shadows\b", re.I), "shadow-copy deletion", "high"),
    (re.compile(r"\bwbadmin\s+delete\b", re.I), "backup deletion", "high"),
    (re.compile(r"\bnet\s+user\b[^\n]{0,40}/add\b", re.I), "account creation", "medium"),
]


class ScriptObfuscationDetector(Detector):
    name = "script.obfuscation"
    rule = AW_S001

    def run(self, artifact: Artifact) -> list[Finding]:
        return pattern_findings(self, artifact, self.rule, PATTERNS)
