"""Canary tokens: deterministic exfil proof.

A canary is a unique random string planted where sensitive data lives. If the
canary shows up anywhere else -- another file, a report, a network destination,
a ledger record -- then the data around it moved. No model judgement required.

The registry stores a keyed digest (HMAC-SHA256) of each canary, never the
canary itself, so a leaked registry does not hand an attacker the bait.
Matching is exact substring over artifact text.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from pathlib import Path

REGISTRY_NAME = "canaries.json"
PREFIX = "AWCANARY"


def make_canary(namespace: str = "default") -> str:
    return "%s-%s-%s" % (PREFIX, secrets.token_hex(4), secrets.token_hex(4))


def canary_digest(token: str, key: bytes) -> str:
    return hmac.new(key, token.encode("utf-8"), hashlib.sha256).hexdigest()[:24]


def new_key() -> bytes:
    return secrets.token_bytes(32)


def plant(workspace: str, count: int = 3, key: bytes | None = None) -> dict:
    """Write canary files into a workspace and a registry beside them.

    The registry lives in the workspace under .agentwatch/. `key` (hex) is
    stored in the registry because the operator needs it to re-derive digests;
    protect the registry like the data it guards.
    """
    ws = Path(workspace)
    ws.mkdir(parents=True, exist_ok=True)
    reg_dir = ws / ".agentwatch"
    reg_dir.mkdir(exist_ok=True)
    key = key or new_key()
    entries = []
    for i in range(count):
        token = make_canary()
        digest = canary_digest(token, key)
        target = ws / ("sensitive_" + str(i + 1) + ".md")
        target.write_text(
            "internal record %d\n\napi key: %s\n\n do not copy this file.\n" % (i + 1, token),
            encoding="utf-8",
        )
        entries.append({"digest": digest, "planted_in": str(target)})
    registry = {
        "key": key.hex(),
        "canaries": entries,
        "note": "digests only; tokens live in the planted files",
    }
    (reg_dir / REGISTRY_NAME).write_text(json.dumps(registry, indent=2, sort_keys=True), encoding="utf-8")
    return registry


def load_registry(workspace: str) -> dict | None:
    p = Path(workspace) / ".agentwatch" / REGISTRY_NAME
    if not p.exists():
        return None
    return json.loads(p.read_text(encoding="utf-8"))


def registry_tokens(registry: dict) -> list[str]:
    """Re-derive matchable tokens. Requires the planted files to read back."""
    key = bytes.fromhex(registry["key"])
    tokens = []
    for e in registry.get("canaries", []):
        planted = Path(e["planted_in"])
        if not planted.exists():
            continue
        text = planted.read_text(encoding="utf-8", errors="replace")
        for word in text.split():
            if word.startswith(PREFIX + "-"):
                if canary_digest(word, key) == e["digest"]:
                    tokens.append(word)
                break
    return tokens
