"""Hash-chained append-only ledger.

The ledger is the system of record. Every sweep, read, and finding becomes a
record whose hash covers the record before it, so any edit, deletion, or
reordering breaks the chain at a stated sequence number.

Concurrency: a single-writer lock (platform file lock) serializes append and
verify. `fsync` is called after every write so a crash does not leave a
partial last line. The lock file and the head index are created in the ledger
directory; they are not the record.

Scaling: `_last()` reads a small sidecar head index (`head.json`) under the
lock instead of scanning the whole ledger. `verify()` still scans the whole
file -- verification is an explicit, infrequent operation.

Trust: this detects edits to the ledger *file*. It does not defend against an
attacker who rewrites the entire chain; that requires an external anchor
(`aw ledger anchor` + `aw ledger verify --anchor`).
"""

from __future__ import annotations

import contextlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from .hashing import GENESIS, hash_obj


class LedgerError(Exception):
    pass


class _FileLock:
    def __init__(self, path: Path):
        self.path = path

    @contextlib.contextmanager
    def acquire(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fh = open(self.path, "w")
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(fh.fileno(), msvcrt.LK_LOCK, 1)
            else:
                import fcntl

                fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            yield
        finally:
            try:
                if os.name == "nt":
                    import msvcrt

                    msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass
            fh.close()


class Ledger:
    FILENAME = "ledger.jsonl"
    HEADFILE = "head.json"
    LOCKFILE = "ledger.lock"

    def __init__(self, dir_path: str):
        self.dir = Path(dir_path)
        self.path = self.dir / self.FILENAME
        self.head_path = self.dir / self.HEADFILE
        self.lock_path = self.dir / self.LOCKFILE
        self._lock = _FileLock(self.lock_path)

    @classmethod
    def init(cls, dir_path: str) -> "Ledger":
        led = cls(dir_path)
        led.dir.mkdir(parents=True, exist_ok=True)
        if not led.path.exists():
            led.path.write_bytes(b"")
        if not led.head_path.exists():
            led._write_head(0, GENESIS)
        return led

    def _write_head(self, seq: int, digest: str) -> None:
        with open(self.head_path, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"seq": seq, "hash": digest}, sort_keys=True) + "\n")
            fh.flush()
            os.fsync(fh.fileno())

    def _read_head(self) -> tuple[int, str] | None:
        if not self.head_path.exists():
            return None
        try:
            doc = json.loads(self.head_path.read_text(encoding="utf-8"))
            return int(doc["seq"]), doc["hash"]
        except (json.JSONDecodeError, KeyError, ValueError):
            return None

    def _scan_last(self) -> tuple[int, str]:
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

    def _last(self) -> tuple[int, str]:
        head = self._read_head()
        if head is not None:
            # Validate head against the actual tail; heal if they diverge.
            scanned = self._scan_last()
            if scanned == head:
                return head
        return self._scan_last()

    def append(self, event: dict) -> dict:
        with self._lock.acquire():
            seq, prev = self._last()
            rec = dict(event)
            rec["seq"] = seq + 1
            rec["prev"] = prev
            rec["hash"] = hash_obj(rec)
            line = json.dumps(rec, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
            with open(self.path, "a", encoding="utf-8", newline="\n") as fh:
                fh.write(line + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            self._write_head(rec["seq"], rec["hash"])
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
        with self._lock.acquire(), open(self.path, "r", encoding="utf-8") as fh:
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
        # heal head index from the verified tail
        if not problems:
            self._write_head(expected - 1, prev)
        return (not problems, problems)

    def anchor_head(self) -> dict:
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
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
