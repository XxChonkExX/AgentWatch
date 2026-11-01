"""Hash-chained append-only ledger, segmented for scale.

The ledger is the system of record. Every sweep, read, and finding becomes a
record whose hash covers the record before it, so any edit, deletion, or
reordering breaks the chain at a stated sequence number.

Concurrency: a single-writer lock (platform file lock) serializes append and
verify. `fsync` is called after every write so a crash does not leave a
partial last line.

Scaling: records are stored in numbered segment files (ledger_000000.jsonl,
...). A small head index (head.json) records the active segment and the last
seq/hash, so append is O(1) instead of O(n). `verify()` and `read_all()`
still scan the segments, but segments are bounded (SEGMENT_SIZE records) and
the work is linear in total records -- verification is an explicit,
infrequent operation. `get(seq)` picks the segment by its recorded range.

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

SEGMENT_SIZE = 1000
SEGMENT_PREFIX = "ledger_"
SEGMENT_SUFFIX = ".jsonl"
LEGACY_NAME = "ledger.jsonl"
HEADFILE = "head.json"
LOCKFILE = "ledger.lock"
MANIFEST = "segments.json"


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
    def __init__(self, dir_path: str):
        self.dir = Path(dir_path)
        self.head_path = self.dir / HEADFILE
        self.lock_path = self.dir / LOCKFILE
        self.manifest_path = self.dir / MANIFEST
        self._lock = _FileLock(self.lock_path)
        self._migrate_legacy()
        self.path = self._active_segment()

    @classmethod
    def init(cls, dir_path: str) -> "Ledger":
        led = cls(dir_path)
        led.dir.mkdir(parents=True, exist_ok=True)
        if not led._segments():
            led._new_segment()
        if not led.head_path.exists():
            led._write_head(0, GENESIS, led._segments()[0].name)
        if not led.manifest_path.exists():
            led._write_manifest()
        return led

    # ---------------------------------------------------------------- segments

    def _segment_paths(self) -> list[Path]:
        files = sorted(self.dir.glob("%s*%s" % (SEGMENT_PREFIX, SEGMENT_SUFFIX)))
        if files:
            return files
        legacy = self.dir / LEGACY_NAME
        if legacy.exists():
            return [legacy]
        return []

    def _segments(self) -> list[Path]:
        return self._segment_paths()

    def _new_segment(self) -> Path:
        idx = len(self._segment_paths())
        # skip any legacy slot
        while True:
            name = "%s%06d%s" % (SEGMENT_PREFIX, idx, SEGMENT_SUFFIX)
            p = self.dir / name
            if not p.exists():
                break
            idx += 1
        p.write_bytes(b"")
        return p

    def _migrate_legacy(self) -> None:
        legacy = self.dir / LEGACY_NAME
        if not legacy.exists():
            return
        if list(self.dir.glob("%s*%s" % (SEGMENT_PREFIX, SEGMENT_SUFFIX))):
            return
        target = self.dir / "ledger_000000.jsonl"
        try:
            legacy.rename(target)
        except OSError:
            return

    def _active_segment(self) -> Path:
        segs = self._segments()
        if not segs:
            return self.dir / "ledger_000000.jsonl"
        last = segs[-1]
        try:
            n = sum(1 for _ in open(last, "r", encoding="utf-8") if _.strip())
        except OSError:
            n = 0
        if n >= SEGMENT_SIZE:
            return self._new_segment()
        return last

    def _read_manifest(self) -> dict:
        if not self.manifest_path.exists():
            return {"segments": []}
        try:
            return json.loads(self.manifest_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {"segments": []}

    def _write_manifest(self) -> None:
        segs = self._segments()
        entries = []
        for p in segs:
            first, last, fh, lh = self._segment_range(p)
            entries.append({
                "file": p.name,
                "first": first,
                "last": last,
                "first_hash": fh,
                "last_hash": lh,
            })
        tmp = self.manifest_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps({"segments": entries}, sort_keys=True, indent=2), encoding="utf-8")
        with open(tmp, "w", encoding="utf-8") as f:
            pass
        os.replace(tmp, self.manifest_path)

    def _segment_range(self, p: Path) -> tuple:
        first = last = 0
        fh = lh = None
        if not p.exists():
            return (0, 0, None, None)
        with open(p, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                ev = json.loads(line)
                if first == 0:
                    first = int(ev["seq"])
                    fh = ev["hash"]
                last = int(ev["seq"])
                lh = ev["hash"]
        return (first, last, fh, lh)

    def _read_head(self) -> tuple[int, str, str] | None:
        if not self.head_path.exists():
            return None
        try:
            doc = json.loads(self.head_path.read_text(encoding="utf-8"))
            return int(doc["seq"]), doc["hash"], doc.get("segment", "")
        except (json.JSONDecodeError, KeyError, ValueError):
            return None

    def _write_head(self, seq: int, digest: str, segment: str) -> None:
        with open(self.head_path, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"seq": seq, "hash": digest, "segment": segment}, sort_keys=True) + "\n")
            fh.flush()
            os.fsync(fh.fileno())

    def _scan_last(self) -> tuple[int, str]:
        segs = self._segments()
        if not segs:
            return (0, GENESIS)
        last_seg = segs[-1]
        last = None
        with open(last_seg, "r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    last = line
        if last is None:
            # empty last segment; walk back
            for p in reversed(segs[:-1]):
                with open(p, "r", encoding="utf-8") as fh:
                    for line in fh:
                        if line.strip():
                            last = line
                if last:
                    break
        if last is None:
            return (0, GENESIS)
        ev = json.loads(last)
        return (int(ev["seq"]), ev["hash"])

    def _last(self) -> tuple[int, str]:
        head = self._read_head()
        if head is not None:
            scanned = self._scan_last()
            if scanned == head[:2]:
                return head[:2]
        return self._scan_last()

    # ------------------------------------------------------------------ append

    def append(self, event: dict) -> dict:
        with self._lock.acquire():
            self.dir.mkdir(parents=True, exist_ok=True)
            if not self._segments():
                self._new_segment()
            self.path = self._active_segment()
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
            # rotate if full
            try:
                n = sum(1 for _ in open(self.path, "r", encoding="utf-8") if _.strip())
            except OSError:
                n = 0
            if n >= SEGMENT_SIZE:
                self.path = self._new_segment()
            self._write_head(rec["seq"], rec["hash"], self.path.name)
            self._write_manifest()
            return rec

    # -------------------------------------------------------------------- read

    def read_all(self) -> Iterator[dict]:
        for p in self._segments():
            if not p.exists():
                continue
            with open(p, "r", encoding="utf-8") as fh:
                for line in fh:
                    if line.strip():
                        yield json.loads(line)

    def get(self, seq: int) -> dict | None:
        # find segment by manifest range, else scan
        manifest = self._read_manifest()
        for e in manifest.get("segments", []):
            if e.get("first", 0) <= seq <= e.get("last", 0):
                p = self.dir / e["file"]
                if not p.exists():
                    break
                with open(p, "r", encoding="utf-8") as fh:
                    for line in fh:
                        if line.strip():
                            ev = json.loads(line)
                            if ev.get("seq") == seq:
                                return ev
                return None
        for ev in self.read_all():
            if ev.get("seq") == seq:
                return ev
        return None

    # ------------------------------------------------------------------ verify

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
                    if ev.get("prev") != prev:
                        problems.append("%s:%d: prev link broken at seq=%r" % (p.name, lineno, ev.get("seq")))
                    body = {k: v for k, v in ev.items() if k != "hash"}
                    recomputed = hash_obj(body)
                    if recomputed != ev.get("hash"):
                        problems.append("%s:%d: hash mismatch at seq=%r" % (p.name, lineno, ev.get("seq")))
                    prev = ev.get("hash")
                    expected = int(ev.get("seq", expected)) + 1
        if not problems:
            self._write_head(expected - 1, prev, self.path.name)
            self._write_manifest()
        return (not problems, problems)

    # ------------------------------------------------------------------ anchor

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
