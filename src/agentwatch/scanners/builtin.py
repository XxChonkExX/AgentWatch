"""Builtin signature scanner. Zero dependencies, always available."""

from __future__ import annotations

from ..core.hashing import hash_obj, short
from .base import ScanHit, Scanner
from .signatures import SIGNATURES


class BuiltinSignatureScanner(Scanner):
    name = "builtin"

    def available(self) -> bool:
        return True

    def version(self) -> str:
        # Hash the table in a JSON-serializable form (bytes -> hex) so the
        # signature-set fingerprint is stable and reproducible.
        table = [[sid, pattern.hex(), severity, ci] for sid, pattern, severity, ci in SIGNATURES]
        return "builtin-" + short(hash_obj(table))

    def scan_bytes(self, data: bytes, name: str) -> list[ScanHit]:
        hits: list[ScanHit] = []
        lowered = data.lower()
        for sig_id, pattern, severity, case_insensitive in SIGNATURES:
            hay = lowered if case_insensitive else data
            needle = pattern.lower() if case_insensitive else pattern
            if needle in hay:
                hits.append(
                    ScanHit(
                        scanner=self.name,
                        signature=sig_id,
                        severity=severity,
                        detail="builtin signature match: %s" % sig_id,
                        version=self.version(),
                    )
                )
        return hits
