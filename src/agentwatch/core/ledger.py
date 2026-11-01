"""Hash-chained append-only ledger.

The ledger is the system of record. Every sweep, read, and finding becomes a
record whose hash covers the record before it, so any edit, deletion, or
reordering breaks the chain at a stated sequence number.

Concurrency: a single-writer file lock serializes append and verify. `fsync`
runs after every record write and every head write, so a crash does not leave
a partial last line. Until an explicit writer queue exists, "one writer at a
time" is a hard assumption of this design, enforced by the lock file.

Scaling: records live in numbered segment files (`ledger_000000.jsonl`,
`ledger_000001.jsonl`, ...), SEGMENT_SIZE records each. The segment for a
sequence number is arithmetic -- `(seq - 1) // SEGMENT_SIZE` -- so append and
`get()` are O(SEGMENT_SIZE), not O(n). `head.json` caches the last seq/hash so
append does not have to trust a full scan; it is validated against the tail of
the active segment on every append and healed if they disagree.

Trust: this detects edits to the ledger *files*. It does not defend against an
attacker who rewrites every segment and the head together; that requires an
external anchor (`aw ledger anchor` + `aw ledger verify --anchor`). A head
index ahead of the chain is reported as truncation, which is the one case the
chain alone cannot see.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from .hashing import GENESIS, hash_obj

SEGMENT_SIZE = 1000
SEGMENT_PREFIX = "ledger_"
SEGMENT_SUFFIX = ".jsonl"
LEGACY_NAME = "ledger.jsonl"
HEADFILE = "head.json"
LOCKFILE = "ledger.lock"

_SEGMENT_RE = re.compile(r"^%s(\d+)%s$" % (SEGMENT_PREFIX, re.escape(SEGMENT_SUFFIX)))


class LedgerError(Exception):
    pass


class _FileLock:
    """Exclusive lock across processes, via a sidecar file.

    POSIX uses flock; Windows uses msvcrt.locking on one byte. The lock file is
    not a record; it may be deleted while no process holds it.
    """

    def __init__(self, path: Path):
        self.path = path

    @contextlib.contextmanager
    def acquire(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fh = open(self.path, "a+b")
        try:
            if os.name == "nt":
                import msvcrt

                fh.seek(0)
                msvcrt.locking(fh.fileno(), msvcrt.LK_LOCK, 1)
            else:
                import fcntl

                fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            yield
        finally:
            try:
                if os.name == "nt":
                    import msvcrt

                    fh.seek(0)
                    msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass
            fh.close()


def _segment_index(name: str) -> int | None:
    m = _SEGMENT_RE.match(name)
    return int(m.group(1)) if m else None


class Ledger:
    def __init__(self, dir_path: str):
        self.dir = Path(dir_path)
        self.head_path = self.dir / HEADFILE
        self.lock_path = self.dir / LOCKFILE
        self._lock = _FileLock(self.lock_path)
        self._migrate_legacy()
        self.path = self._segment_for_seq(1)

    @classmethod
    def init(cls, dir_path: str) -> "Ledger":
        led = cls(dir_path)
        led.dir.mkdir(parents=True, exist_ok=True)
        first = led._segment_for_seq(1)
        if not first.exists():
            first.write_bytes(b"")
        if not led.head_path.exists():
            led._write_head(0, GENESIS)
        return led

    # ---------------------------------------------------------------- segments

    def _segment_for_seq(self, seq: int) -> Path:
        idx = (max(int(seq), 1) - 1) // SEGMENT_SIZE
        return self.dir / ("%s%06d%s" % (SEGMENT_PREFIX, idx, SEGMENT_SUFFIX))

    def _segments(self) -> list[Path]:
        files = sorted(
            p for p in self.dir.glob("%s*%s" % (SEGMENT_PREFIX, SEGMENT_SUFFIX))
            if _segment_index(p.name) is not None
        )
        if files:
            return files
        legacy = self.dir / LEGACY_NAME
        if legacy.exists():
            return [legacy]
        return []

    def _migrate_legacy(self) -> None:
        """Rename a pre-segmentation `ledger.jsonl` into slot zero, once."""
        legacy = self.dir / LEGACY_NAME
        if not legacy.exists():
            return
        if list(self.dir.glob("%s*%s" % (SEGMENT_PREFIX, SEGMENT_SUFFIX))):
            return
        try:
            legacy.rename(self._segment_for_seq(1))
        except OSError:
            pass

    # ------------------------------------------------------------------- head

    def _read_head(self) -> tuple[int, str] | None:
        if not self.head_path.exists():
            return None
        try:
            doc = json.loads(self.head_path.read_text(encoding="utf-8"))
            return int(doc["seq"]), str(doc["hash"])
        except (json.JSONDecodeError, KeyError, ValueError, TypeError):
            return None

    def _write_head(self, seq: int, digest: str) -> None:
        with open(self.head_path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(json.dumps({"seq": seq, "hash": digest}, sort_keys=True) + "\n")
            fh.flush()
            os.fsync(fh.fileno())

    def _scan_last(self) -> tuple[int, str]:
        for p in reversed(self._segments()):
            if not p.exists():
                continue
            last = None
            with open(p, "r", encoding="utf-8") as fh:
                for line in fh:
                    if line.strip():
                        last = line
            if last is None:
                continue
            ev = json.loads(last)
            return (int(ev["seq"]), ev["hash"])
        return (0, GENESIS)

    def _last(self) -> tuple[int, str]:
        """Tail seq/hash. Trusts head.json only when it matches the tail."""
        scanned = self._scan_last()
        head = self._read_head()
        if head is not None and head == scanned:
            return head
        return scanned

    # ----------------------------------------------------------------- append

    def append(self, event: dict) -> dict:
        with self._lock.acquire():
            self.dir.mkdir(parents=True, exist_ok=True)
            seq, prev = self._last()
            rec = dict(event)
            rec["seq"] = seq + 1
            rec["prev"] = prev
            rec["hash"] = hash_obj(rec)
            line = json.dumps(rec, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
            target = self._segment_for_seq(rec["seq"])
            with open(target, "a", encoding="utf-8", newline="\n") as fh:
                fh.write(line + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            self.path = target
            self._write_head(rec["seq"], rec["hash"])
            return rec

    # ------------------------------------------------------------------- read

    def read_all(self) -> Iterator[dict]:
        for p in self._segments():
            if not p.exists():
                continue
            with open(p, "r", encoding="utf-8") as fh:
                for line in fh:
                    if line.strip():
                        yield json.loads(line)

    def get(self, seq: int) -> dict | None:
        seq = int(seq)
        if seq < 1:
            return None
        p = self._segment_for_seq(seq)
        if p.exists():
            with open(p, "r", encoding="utf-8") as fh:
                for line in fh:
                    if not line.strip():
                        continue
                    ev = json.loads(line)
                    if ev.get("seq") == seq:
                        return ev
            return None
        # Migrated or non-canonical layout: fall back to a full scan.
        for ev in self.read_all():
            if ev.get("seq") == seq:
                return ev
        return None

    # ----------------------------------------------------------------- verify

    def verify(self) -> tuple[bool, list[str]]:
        problems: list[str] = []
        prev = GENESIS
        expected = 1
        segs = self._segments()
        if not segs:
            return (False, ["no ledger segments found in %s" % self.dir])
        for p in segs:
            if not p.exists():
                problems.append("missing segment: %s" % p.name)
                continue
            idx = _segment_index(p.name)
            with open(p, "r", encoding="utf-8") as fh:
                for lineno, line in enumerate(fh, start=1):
                    if not line.strip():
                        continue
                    try:
                        ev = json.loads(line)
                    except json.JSONDecodeError as exc:
                        problems.append("%s:%d: malformed JSON (%s)" % (p.name, lineno, exc))
                        continue
                    if ev.get("seq") != expected:
                        problems.append(
                            "%s:%d: seq=%r expected=%d" % (p.name, lineno, ev.get("seq"), expected)
                        )
                    if idx is not None and (expected - 1) // SEGMENT_SIZE != idx:
                        problems.append(
                            "%s:%d: seq=%d belongs in segment %06d"
                            % (p.name, lineno, expected, (expected - 1) // SEGMENT_SIZE)
                        )
                    if ev.get("prev") != prev:
                        problems.append("%s:%d: prev link broken at seq=%r" % (p.name, lineno, ev.get("seq")))
                    body = {k: v for k, v in ev.items() if k != "hash"}
                    if hash_obj(body) != ev.get("hash"):
                        problems.append("%s:%d: hash mismatch at seq=%r" % (p.name, lineno, ev.get("seq")))
                    prev = ev.get("hash")
                    expected = int(ev.get("seq", expected)) + 1
        last = expected - 1
        head = self._read_head()
        if head is not None and head[0] > last:
            # A tail deletion leaves a valid prefix; only the head notices.
            problems.append(
                "ledger truncated: head.json says seq=%d, chain ends at seq=%d" % (head[0], last)
            )
        if not problems:
            with self._lock.acquire():
                self._write_head(last, prev)
        return (not problems, problems)

    # ----------------------------------------------------------------- anchor

    def anchor_head(self) -> dict:
        seq, digest = self._last()
        return {
            "seq": seq,
            "hash": digest,
            "anchored_utc": _utcnow(),
            "records": seq,
        }

    def verify_anchor(self, anchor: dict) -> tuple[bool, list[str]]:
        problems: list[str] = []
        seq = int(anchor.get("seq", 0))
        if seq == 0:
            last, _digest = self._last()
            if last:
                problems.append("anchor is genesis but ledger has %d record(s)" % last)
            return (not problems, problems)
        last, _digest = self._last()
        if last < seq:
            problems.append(
                "ledger truncated: anchor seq=%d but chain ends at %d" % (seq, last)
            )
            return (False, problems)
        at = self.get(seq)
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
