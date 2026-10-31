#!/usr/bin/env python3
"""Import Crucible battery transcripts into AgentWatch probe transcripts.

The Crucible scar-battery transcript schema (pid, kind, prompt, gold, output)
maps directly onto AgentWatch's Transcript; this adapter just renames the arm
from the filename and writes per-arm files that `aw probe score` accepts.

Zero inference, zero GPU: this scores outputs that already exist.

Usage:
  python examples/import_transcripts.py FILE.jsonl [FILE.jsonl ...] --out-dir DIR
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from agentwatch.probes.schema import Transcript, write_transcripts  # noqa: E402


def arm_from_filename(path: str) -> str:
    base = os.path.splitext(os.path.basename(path))[0]
    base = re.sub(r"^\d{8}T\d{6}Z?_[^_]+_", "", base)  # date + box
    base = re.sub(r"^\d+_", "", base)                  # run number
    base = re.sub(r"^transcripts_", "", base)          # battery prefix
    return base or "arm"


def main() -> int:
    ap = argparse.ArgumentParser(description="import crucible transcripts for aw probe score")
    ap.add_argument("files", nargs="+")
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    written = []
    kinds: dict = {}
    for path in args.files:
        arm = arm_from_filename(path)
        ts = []
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not r.get("output"):
                    continue
                kinds[r.get("kind", "?")] = kinds.get(r.get("kind", "?"), 0) + 1
                ts.append(Transcript(
                    pid=r.get("pid", ""),
                    kind=r.get("kind", ""),
                    output=r.get("output", ""),
                    prompt=r.get("prompt", ""),
                    arm=arm,
                ))
        out = os.path.join(args.out_dir, arm + ".jsonl")
        write_transcripts(out, ts)
        written.append((arm, len(ts), out))
        print("%-16s %4d transcripts -> %s" % (arm, len(ts), out))

    print("\nkinds seen:", dict(sorted(kinds.items())))
    print("\nnext: aw probe score %s\\*.jsonl --ref official" % args.out_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
