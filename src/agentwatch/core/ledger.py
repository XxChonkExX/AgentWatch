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

    def anchor_head(self) -> dict:
        """Return an anchor document for the current chain head.

        The anchor is the external anchor promised in the module docstring:
        stored somewhere else than the ledger (another box, cold storage, a
        signed file), it makes a full-file rewrite detectable, because the
        rewritten chain will not end at the anchored seq/hash.
        """
        records = [r for r in self.read_all()]
        if not records:
            return {"seq": 0, "hash": GENESIS, "anchored_utc": _utcnow(), "records": 0}
        last = records[-1]
        return {
            "seq": int(last["seq"]),
            "hash": last["hash"],
            "anchored_utc": _utcnow(),
            "records": len(records),
        }

    def verify_anchor(self, anchor: dict) -> tuple[bool, list[str]]:
        problems: list[str] = []
        records = [r for r in self.read_all()]
        seq = int(anchor.get("seq", 0))
        if seq == 0:
            if records:
                problems.append("anchor is genesis but ledger has %d record(s)" % len(records))
            return (not problems, problems)
        if len(records) < seq:
            problems.append(
                "ledger truncated: anchor seq=%d but only %d record(s) present"
                % (seq, len(records))
            )
            return (False, problems)
        at = next((r for r in records if int(r.get("seq", -1)) == seq), None)
        if at is None:
            problems.append("no record at anchored seq=%d" % seq)
            return (False, problems)
        if at.get("hash") != anchor.get("hash"):
            problems.append(
                "anchor mismatch at seq=%d: anchored=%s actual=%s"
                % (seq, str(anchor.get("hash"))[:16], str(at.get("hash"))[:16])
            )
        return (not problems, problems)


def _utcnow() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
