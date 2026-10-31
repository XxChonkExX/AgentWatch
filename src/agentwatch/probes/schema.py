"""Probe pack schema: probes, transcripts, and freeze semantics.

A pack is a frozen instrument. Its probes are ordered and hashed; the hash is
recorded in a sidecar `.frozen.json`. Editing a frozen pack is the one thing
the program may never do (MODEL_ONBOARDING section 3) -- add a new pack
instead.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone

from ..core.hashing import hash_obj


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True)
class Probe:
    pid: str
    kind: str
    prompt: str | None = None
    messages: tuple | None = None
    expect: str = ""
    gold: str = ""
    tags: tuple = ()

    def to_messages(self) -> list:
        if self.messages:
            return [dict(m) for m in self.messages]
        return [{"role": "user", "content": self.prompt or ""}]

    def last_user_text(self) -> str:
        msgs = self.to_messages()
        for m in reversed(msgs):
            if m.get("role") == "user":
                return m.get("content", "")
        return self.prompt or ""

    def to_dict(self) -> dict:
        d = {"pid": self.pid, "kind": self.kind}
        if self.messages:
            d["messages"] = [dict(m) for m in self.messages]
        else:
            d["prompt"] = self.prompt or ""
        if self.expect:
            d["expect"] = self.expect
        if self.gold:
            d["gold"] = self.gold
        if self.tags:
            d["tags"] = list(self.tags)
        return d

    @staticmethod
    def from_dict(d: dict) -> "Probe":
        msgs = d.get("messages")
        if msgs is not None:
            msgs = tuple({"role": m.get("role", "user"), "content": m.get("content", "")} for m in msgs)
        return Probe(
            pid=d["pid"],
            kind=d["kind"],
            prompt=d.get("prompt"),
            messages=msgs,
            expect=d.get("expect", ""),
            gold=d.get("gold", ""),
            tags=tuple(d.get("tags", ())),
        )


@dataclass
class ProbePack:
    probes: tuple
    path: str = ""
    sha256: str = ""
    name: str = ""

    @classmethod
    def load(cls, path: str) -> "ProbePack":
        probes = []
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                probes.append(Probe.from_dict(json.loads(line)))
        pack = cls(probes=tuple(probes), path=path, name=os.path.splitext(os.path.basename(path))[0])
        pack.sha256 = pack.compute_hash()
        return pack

    def compute_hash(self) -> str:
        return hash_obj([p.to_dict() for p in self.probes])

    def counts(self) -> dict:
        out: dict = {}
        for p in self.probes:
            out[p.kind] = out.get(p.kind, 0) + 1
        return dict(sorted(out.items()))

    def sidecar_path(self) -> str:
        return self.path + ".frozen.json"

    def freeze(self, provenance: str = "") -> dict:
        doc = {
            "pack": self.name,
            "sha256": self.sha256 or self.compute_hash(),
            "n": len(self.probes),
            "counts": self.counts(),
            "frozen_utc": utcnow(),
            "provenance": provenance,
        }
        with open(self.sidecar_path(), "w", encoding="utf-8", newline="\n") as fh:
            json.dump(doc, fh, indent=2, sort_keys=True)
            fh.write("\n")
        return doc

    def verify(self) -> tuple[bool, list[str]]:
        problems: list[str] = []
        if not os.path.exists(self.sidecar_path()):
            return (False, ["no freeze sidecar for %s" % self.path])
        with open(self.sidecar_path(), "r", encoding="utf-8") as fh:
            doc = json.load(fh)
        current = self.compute_hash()
        if doc.get("sha256") != current:
            problems.append("pack hash mismatch: frozen=%s current=%s" % (doc.get("sha256"), current))
        if doc.get("counts") != self.counts():
            problems.append("per-kind counts differ from frozen sidecar")
        if doc.get("n") != len(self.probes):
            problems.append("probe count differs from frozen sidecar")
        return (not problems, problems)


@dataclass
class Transcript:
    pid: str
    kind: str
    output: str
    prompt: str = ""
    arm: str = "anon"
    model: str = ""
    params: dict = field(default_factory=dict)
    ts: str = ""

    def to_dict(self) -> dict:
        return {
            "pid": self.pid,
            "kind": self.kind,
            "output": self.output,
            "prompt": self.prompt,
            "arm": self.arm,
            "model": self.model,
            "params": self.params,
            "ts": self.ts,
        }

    @staticmethod
    def from_dict(d: dict) -> "Transcript":
        return Transcript(
            pid=d["pid"],
            kind=d["kind"],
            output=d.get("output", ""),
            prompt=d.get("prompt", ""),
            arm=d.get("arm", "anon"),
            model=d.get("model", ""),
            params=d.get("params", {}),
            ts=d.get("ts", ""),
        )


def read_transcripts(path: str) -> list:
    out = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(Transcript.from_dict(json.loads(line)))
    return out


def write_transcripts(path: str, transcripts: list) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        for t in transcripts:
            fh.write(json.dumps(t.to_dict(), sort_keys=True, ensure_ascii=True) + "\n")
