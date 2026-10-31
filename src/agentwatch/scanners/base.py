"""Scanner contract.

A Scanner answers one question deterministically: does this byte sequence
match a known signature? It does not judge intent and does not decide policy.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class ScanHit:
    scanner: str
    signature: str
    severity: str
    detail: str
    version: str = ""


class Scanner(ABC):
    name = "scanner"

    def available(self) -> bool:
        """True if this scanner can actually run on this machine."""
        raise NotImplementedError

    def version(self) -> str | None:
        """Signature-set / engine version, for reproducibility. None if N/A."""
        return None

    @abstractmethod
    def scan_bytes(self, data: bytes, name: str) -> list[ScanHit]:
        """Return hits for a byte sequence. Must never raise on clean input."""
        raise NotImplementedError
