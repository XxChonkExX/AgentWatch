"""Signature-file scanner.

Runs open-format signature databases (see sigdb.py) from a directory. If the
directory is missing or empty, the scanner is unavailable and the report says
so. Match severity is critical for a hash signature and high for a body
signature.
"""

from __future__ import annotations

from .base import ScanHit, Scanner
from .sigdb import SignatureDatabase


class SigFileScanner(Scanner):
    name = "sigfile"

    def __init__(self, sig_dir: str | None = None):
        self.sig_dir = sig_dir
        self._db: SignatureDatabase | None = None

    def _load(self) -> SignatureDatabase:
        if self._db is None:
            db = SignatureDatabase()
            if self.sig_dir:
                db.load_dir(self.sig_dir)
            self._db = db
        return self._db

    def reload(self) -> None:
        self._db = None

    def available(self) -> bool:
        return self._load().count() > 0

    def version(self) -> str | None:
        db = self._load()
        if db.count() == 0:
            return None
        return "sigdb-%dh-%db-%s" % (db.hash_count, db.body_count, db.fingerprint())

    def scan_bytes(self, data: bytes, name: str) -> list[ScanHit]:
        db = self._load()
        if db.count() == 0:
            return []
        hits = []
        for sig, kind, severity in db.match(data):
            hits.append(
                ScanHit(
                    scanner=self.name,
                    signature=sig,
                    severity=severity,
                    detail="%s signature-file match: %s" % (kind, sig),
                    version=self.version() or "",
                )
            )
        return hits
