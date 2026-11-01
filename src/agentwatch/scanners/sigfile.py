"""Signature-file scanner.

Runs open-format signature databases (see sigdb.py) from a directory. If the
directory is missing or empty, the scanner is unavailable and the report says
so. Match severity is critical for a hash signature and high for a body
signature.

Hash signatures prefer the collector's full-file hash (sha256 from the
artifact, md5 when the file is small enough to hash cheaply). Body
signatures run on the capped sample, as before.
"""

from __future__ import annotations

from .base import ScanHit, Scanner
from .sigdb import SignatureDatabase


class SigFileScanner(Scanner):
    name = "sigfile"

    def __init__(self, sig_dir: str | None = None, binary: str | None = None):
        # binary is accepted for API parity with the other scanners but is
        # unused: this scanner is pure Python and needs no external tool.
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
        for sig, kind, severity in db.match_bytes(data):
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

    def scan_artifact(self, artifact) -> list[ScanHit]:
        db = self._load()
        if db.count() == 0:
            return []
        meta = getattr(artifact, "meta", {}) or {}
        hits = []
        for sig, kind, severity in db.match_artifact(
            artifact.sample,
            getattr(artifact, "size", len(artifact.sample)),
            getattr(artifact, "sha256", None),
            meta.get("md5"),
        ):
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
