"""Scanner detector: turns scanner hits into Lane-A findings and reports
scanner availability so an absent scanner is a stated blind spot.

Builtin hits map to AW-M001, signature-file hits to AW-M003, and everything
else (ClamAV/YARA/Defender) to AW-M002. Per-hit severity comes from the
scanner (a webshell marker is not the same as a known-malware signature).
"""

from __future__ import annotations

from ..core.schema import Evidence
from ..detectors.base import Detector
from ..detectors.rules import AW_M001, AW_M002, AW_M003
from .builtin import BuiltinSignatureScanner
from .clamav import ClamAVScanner
from .defender import DefenderScanner
from .sigfile import SigFileScanner
from .yara import YaraScanner

DEFAULT_MAX_SCAN_BYTES = 64 << 20

# Which rule a scanner's hit maps to.
_RULE_BY_SCANNER = {
    "builtin": AW_M001,
    "sigfile": AW_M003,
}


def default_scanners(rules_dir: str | None = None, sig_dir: str | None = None,
                     live_av: bool = True) -> list:
    """Assemble the scanner pack.

    live_av=False constructs the external engines (Defender, ClamAV, YARA)
    disabled. Tests MUST pass live_av=False: the fixtures contain real
    malware signatures, and a live engine will correctly detect and
    quarantine them (demonstrated: Defender flagged our webshell fixture as
    Backdoor:PHP/Remoteshell.B). Production sweeps default to live engines.
    """
    # binary="" is the disable sentinel; None means auto-discover.
    disabled = None if live_av else ""
    return [
        BuiltinSignatureScanner(),
        SigFileScanner(sig_dir),
        DefenderScanner(binary=disabled),
        ClamAVScanner(binary=disabled),
        YaraScanner(rules_dir, binary=disabled),
    ]


class ScannerDetector(Detector):
    name = "scanner.signatures"
    rule = AW_M001

    def __init__(self, scanners=None, rules_dir: str | None = None, sig_dir: str | None = None,
                 live_av: bool = True, max_scan_bytes: int = DEFAULT_MAX_SCAN_BYTES):
        self.scanners = scanners if scanners is not None else default_scanners(rules_dir, sig_dir, live_av)
        self.max_scan_bytes = max_scan_bytes

    def status(self) -> dict:
        out: dict = {}
        for s in self.scanners:
            try:
                out[s.name] = {"available": bool(s.available()), "version": s.version()}
            except Exception as exc:  # a broken scanner is unavailable, not fatal
                out[s.name] = {"available": False, "version": None, "error": str(exc)}
        return out

    def run(self, artifact) -> list:
        if artifact.meta.get("error") or artifact.size == 0:
            return []
        if artifact.size > self.max_scan_bytes:
            return []
        out = []
        for s in self.scanners:
            if not s.available():
                continue
            try:
                hits = s.scan_bytes(artifact.sample, artifact.name)
            except Exception:
                continue
            for h in hits:
                rule = _RULE_BY_SCANNER.get(s.name, AW_M002)
                ev = [Evidence(path=artifact.path, note="%s @ %s" % (h.signature, h.version or "?"))]
                out.append(self.finding(rule, artifact, h.detail, ev, severity=h.severity))
        return out
