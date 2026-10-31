"""ScannerBridge: interface to virus/signature scanners.

AgentWatch does not write an antivirus engine. It wraps one (ClamAV), wraps a
signature matcher (YARA), and ships a small deterministic builtin matcher so
the capability exists with zero dependencies. Every scanner reports its
version so a hit is reproducible against a named signature set.

A scanner that is not installed is reported as unavailable, never silently
skipped. An absent scanner in a clean report is a stated blind spot.
"""

from .base import ScanHit, Scanner
from .detector import ScannerDetector, default_scanners

__all__ = ["ScanHit", "Scanner", "ScannerDetector", "default_scanners"]
