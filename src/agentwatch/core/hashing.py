"""Canonical hashing helpers.

House rule: a digest computed on one box must equal the digest computed on
another. All structured hashing goes through canonical JSON -- sorted keys,
no insignificant whitespace, ASCII-escaped -- so ordering and platform do
not move the number.

Nothing here is clever. It is deliberately boring, because a hash that
cannot be reproduced is not evidence.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

GENESIS = "0" * 64

_CHUNK = 1 << 20


def canonical_bytes(obj: Any) -> bytes:
    """Deterministic byte serialization of a JSON-able object."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_obj(obj: Any) -> str:
    return sha256_hex(canonical_bytes(obj))


def hash_bytes(data: bytes) -> str:
    return sha256_hex(data)


def hash_file(path: str, chunk: int = _CHUNK) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


def short(digest: str, n: int = 16) -> str:
    return digest[:n]
