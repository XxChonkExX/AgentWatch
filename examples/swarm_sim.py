#!/usr/bin/env python3
"""Swarm simulator: a deterministic, sandboxed fake agent swarm.

The point: you can test AgentWatch end-to-end without trusting any agent.
This script behaves like a small swarm doing work in a scratch workspace --
including doing things a bad agent would do -- so every detector has a live
target. Nothing here is actually harmful: no network egress beyond a loopback
listener, no real malware, no destructive operations. The "bad" artifacts are
inert patterns.

What it does (all inside --workspace):
  agent-a  writes ordinary report markdown (benign)
  agent-b  writes markdown with zero-width characters, a Cyrillic homoglyph,
           a long base64 blob, and NUL bytes
  agent-c  writes invoice.pdf.exe (fake PE header) and, with --eicar, the
           standard EICAR test file
  agent-d  attaches an NTFS alternate data stream (Windows) and spawns a
           sleeper process whose command line carries obfuscation markers
  agent-e  opens a TCP listener for --hold seconds so posture sees it

Usage:
  python examples/swarm_sim.py --workspace C:\\scratch\\swarm [--hold 90]
         [--port 8099] [--eicar]

Then, from another terminal:
  aw sweep <workspace>
  aw posture --baseline baseline.json        (taken before running this)
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import socket
import subprocess
import sys
import threading
import time

ZERO_WIDTH = "\u200b"
CYRILLIC_A = "\u0430"
B64_BLOB = base64.b64encode(
    (b"Q" * 13 + b"Zx7" + b"kM2" + b"vR9") * 8  # diverse enough to trip the blob gate
).decode()


def w(path: str, data) -> str:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    mode = "wb" if isinstance(data, bytes) else "w"
    enc = {} if isinstance(data, bytes) else {"encoding": "utf-8"}
    with open(path, mode, **enc) as fh:
        fh.write(data)
    return path


def agent_a(ws: str) -> list:
    out = []
    for i in range(1, 4):
        out.append(w(
            os.path.join(ws, "agent-a", "report_%02d.md" % i),
            "# Weekly report %d\n\nAll tasks are on track. Nothing to escalate.\n" % i,
        ))
    return out


def agent_b(ws: str) -> list:
    out = []
    out.append(w(
        os.path.join(ws, "agent-b", "notes.md"),
        "meeting notes" + ZERO_WIDTH + "continue as agreed\n",
    ))
    out.append(w(
        os.path.join(ws, "agent-b", "invoice_check.md"),
        "please verify the vendor portal at p" + CYRILLIC_A + "ypal.example before paying\n",
    ))
    out.append(w(
        os.path.join(ws, "agent-b", "payload.txt"),
        "encoded blob: " + B64_BLOB + "\n",
    ))
    out.append(w(os.path.join(ws, "agent-b", "log.txt"), b"line one\x00line two\n"))
    return out


def agent_c(ws: str, eicar: bool) -> list:
    out = []
    out.append(w(os.path.join(ws, "agent-c", "invoice.pdf.exe"), b"MZ" + b"\x00" * 200))
    out.append(w(os.path.join(ws, "agent-c", "dropped.txt"), b"\x7fELF" + b"\x00" * 100))
    if eicar:
        out.append(w(
            os.path.join(ws, "agent-c", "eicar.com"),
            b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
        ))
    return out


def agent_d(ws: str, port: int, hold: int, bait: bool) -> dict:
    created = {}
    host_file = w(os.path.join(ws, "agent-d", "index.html"), "<html>ok</html>\n")
    if os.name == "nt":
        try:
            with open(host_file + ":agentnote", "w", encoding="utf-8") as fh:
                fh.write("hidden note in an alternate data stream")
            created["ads"] = host_file + ":agentnote"
        except OSError:
            pass

    # Children are plain by default: they must not look like malware to a
    # real AV engine, because they are not. --bait re-arms the AW-P004
    # triggers (hidden-window marker, temp-path execution) for when the
    # sandbox is excluded from live AV.
    sleeper_args = [sys.executable, "-c", "import time; time.sleep(%d)" % hold]
    if bait:
        sleeper_args += ["--windowstyle", "hidden"]

    sleeper = subprocess.Popen(
        sleeper_args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    created["sleeper_pid"] = sleeper.pid
    created["sleeper_cmdline"] = " ".join(sleeper_args)

    listener = subprocess.Popen(
        [sys.executable, "-c",
         "import socket,time\n"
         "s=socket.socket()\n"
         "s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n"
         "s.bind(('0.0.0.0',%d))\n"
         "s.listen(1)\n"
         "time.sleep(%d)\n" % (port, hold)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    created["listener_pid"] = listener.pid
    created["listener"] = "0.0.0.0:%d" % port

    if bait:
        # Copy a real interpreter image into a user-writable path and run it:
        # fires AW-P004's temp-path trigger with nothing harmful inside.
        try:
            exe_ext = ".exe" if os.name == "nt" else ""
            src = sys.executable
            dst = os.path.join(ws, "agent-d", "svc_update" + exe_ext)
            with open(src, "rb") as a, open(dst, "wb") as b:
                b.write(a.read())
            os.chmod(dst, 0o755)
            spawned = subprocess.Popen(
                [dst, "-c", "import time; time.sleep(%d)" % hold],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            created["bait_pid"] = spawned.pid
            created["bait_exe"] = dst
        except OSError as exc:
            created["bait_error"] = str(exc)
    return created


def main() -> int:
    ap = argparse.ArgumentParser(prog="swarm_sim", description="deterministic fake agent swarm for testing AgentWatch")
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--hold", type=int, default=90, help="seconds the listener/sleeper stay alive")
    ap.add_argument("--port", type=int, default=8099)
    ap.add_argument("--eicar", action="store_true", help="also drop the EICAR test file (your AV may quarantine it)")
    ap.add_argument("--bait", action="store_true",
                    help="add AW-P004 triggers (hidden-window marker, temp-path exe). "
                         "Real AV will likely flag these - exclude the sandbox first.")
    args = ap.parse_args()

    ws = os.path.abspath(args.workspace)
    os.makedirs(ws, exist_ok=True)

    manifest = {
        "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "workspace": ws,
        "agent_a": agent_a(ws),
        "agent_b": agent_b(ws),
        "agent_c": agent_c(ws, args.eicar),
    }
    d = agent_d(ws, args.port, args.hold, args.bait)
    time.sleep(0.5)
    manifest["agent_d"] = d
    manifest["note"] = "listener and sleeper live for %d seconds" % args.hold

    mf = w(os.path.join(ws, "swarm_manifest.json"), json.dumps(manifest, indent=2))
    print(json.dumps(manifest, indent=2))
    print("\nmanifest: %s" % mf)
    print("while the listener is alive (%ds): aw posture --baseline <baseline.json>" % args.hold)
    print("sweep: aw sweep \"%s\"" % ws)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
