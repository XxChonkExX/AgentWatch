"""Hash-chained append-only ledger.

The ledger is the system of record. Every sweep, read, and finding becomes a
record whose hash covers the record before it, so any edit, deletion, or
reordering breaks the chain at a stated sequence number.

Scope of the guarantee: this detects tampering with the ledger *file*. It is
not a defense against an attacker who can rewrite the whole file including
the genesis and every link; that requires an external anchor (a signed head,
a second box, or cold storage). M0 records; anchoring is a later milestone.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator

from .hashing import GENESIS, hash_obj


class LedgerError(Exception):
    pass


class Ledger:
    FILENAME = "ledger.jsonl"

    def __init__(self, dir_path: str):
        self.dir = Path(dir_path)
        self.path = self.dir / self.FILENAME

    @classmethod
    def init(cls, dir_path: str) -> "Ledger":
        led = cls(dir_path)
        led.dir.mkdir(parents=True, exist_ok=True)
        if not led.path.exists():
            led.path.write_bytes(b"")
        return led

    def _last(self) -> tuple[int, str]:
        if not self.path.exists():
            return (0, GENESIS)
        last = None
        with open(self.path, "r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    last = line
        if last is None:
            return (0, GENESIS)
        ev = json.loads(last)
        return (int(ev["seq"]), ev["hash"])

    def append(self, event: dict) -> dict:
        seq, prev = self._last()
        rec = dict(event)
        rec["seq"] = seq + 1
        rec["prev"] = prev
        rec["hash"] = hash_obj(rec)
        line = json.dumps(rec, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
        with open(self.path, "a", encoding="utf-8", newline="\n") as fh:
            fh.write(line + "\n")
        return rec

    def read_all(self) -> Iterator[dict]:
        if not self.path.exists():
            return
        with open(self.path, "r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    yield json.loads(line)

    def get(self, seq: int) -> dict | None:
        for ev in self.read_all():
            if ev.get("seq") == seq:
                return ev
        return None

    def verify(self) -> tuple[bool, list[str]]:
        problems: list[str] = []
        prev = GENESIS
        expected = 1
        if not self.path.exists():
            return (False, ["ledger file missing: %s" % self.path])
        with open(self.path, "r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, start=1):
                if not line.strip():
                    continue
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError as exc:
                    problems.append("line %d: malformed JSON (%s)" % (lineno, exc))
                    continue
                if ev.get("seq") != expected:
                    problems.append(
                        "line %d: seq=%r expected=%d" % (lineno, ev.get("seq"), expected)
                    )
                if ev.get("prev") != prev:
                    problems.append("line %d: prev link broken at seq=%r" % (lineno, ev.get("seq")))
                body = {k: v for k, v in ev.items() if k != "hash"}
                recomputed = hash_obj(body)
                if recomputed != ev.get("hash"):
                    problems.append("line %d: hash mismatch at seq=%r" % (lineno, ev.get("seq")))
                prev = ev.get("hash")
                expected = int(ev.get("seq", expected)) + 1
        return (not problems, problems)
