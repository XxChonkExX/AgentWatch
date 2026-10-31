"""Loader for open signature formats.

AgentWatch does not ship a signature database. Third-party databases carry
their own licenses and go stale; bundling them is a maintenance and legal
problem. Instead this loader reads the widely published open formats, so an
operator can drop files into a `signatures/` directory and get real coverage:

  *.hdb / *.mdb   ClamAV MD5 hash signatures   (md5:size:name)
  *.hsb           ClamAV SHA256 hash signatures (sha256:size:name)
  *.ndb           ClamAV body signatures        (name:target:offset:hex[:min:max])

Sources and licenses are listed in signatures/README.md. Files are never
committed to this repository.
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass

from ..core.hashing import hash_obj, short

_HEX = set("0123456789abcdefABCDEF")


@dataclass
class HashEntry:
    algo: str  # "md5" | "sha256"
    digest: str
    size: int
    name: str


@dataclass
class BodyEntry:
    name: str
    target: str
    offset: object  # None (anywhere) | int (absolute) | ("eof", n)
    regex: "re.Pattern"

    def match(self, data: bytes) -> bool:
        if self.offset is None:
            return self.regex.search(data) is not None
        if isinstance(self.offset, int):
            return self.regex.match(data, self.offset) is not None
        if isinstance(self.offset, tuple) and self.offset[0] == "eof":
            n = self.offset[1]
            return any(m.end() == len(data) - n for m in self.regex.finditer(data))
        return self.regex.search(data) is not None


def _hex_to_regex(hexstr: str):
    """ClamAV hex body signature -> bytes regex. Supports ?? wildcards and
    * gaps. Unknown tokens become wildcards rather than failing the whole
    signature."""
    segments = hexstr.strip().split("*")
    parts = []
    for seg in segments:
        tokens = []
        i = 0
        while i + 1 < len(seg) + 1 and i + 2 <= len(seg):
            tok = seg[i:i + 2]
            i += 2
            if tok == "??":
                tokens.append(b".")
            elif all(c in _HEX for c in tok):
                tokens.append(re.escape(bytes([int(tok, 16)])))
            else:
                tokens.append(b".")
        parts.append(b"".join(tokens))
    if not parts:
        return None
    pattern = b"[\\s\\S]*".join(parts)
    try:
        return re.compile(pattern, re.DOTALL)
    except re.error:
        return None


def _parse_offset(spec: str):
    spec = (spec or "*").strip()
    if spec in ("*", ""):
        return None
    if spec.isdigit():
        return int(spec)
    m = re.match(r"(?:EOF|EP)\s*([+-])\s*(\d+)", spec, re.I)
    if m:
        n = int(m.group(2))
        if spec.upper().startswith("EOF"):
            return ("eof", n if m.group(1) == "-" else -n)
        return max(0, n if m.group(1) == "+" else -n)
    return None


class SignatureDatabase:
    def __init__(self):
        self.hash_entries: list[HashEntry] = []
        self.body_entries: list[BodyEntry] = []
        self.files: list[str] = []

    @property
    def hash_count(self) -> int:
        return len(self.hash_entries)

    @property
    def body_count(self) -> int:
        return len(self.body_entries)

    def count(self) -> int:
        return self.hash_count + self.body_count

    def fingerprint(self) -> str:
        return short(hash_obj({
            "h": sorted(e.digest for e in self.hash_entries)[:4096],
            "b": sorted(e.name for e in self.body_entries)[:4096],
            "n": self.count(),
        }), 8)

    def load_dir(self, path: str) -> "SignatureDatabase":
        if not path or not os.path.isdir(path):
            return self
        for root, _dirs, files in os.walk(path):
            for fn in sorted(files):
                fp = os.path.join(root, fn)
                low = fn.lower()
                try:
                    if low.endswith((".hdb", ".mdb")):
                        self._load_hashes(fp, "md5")
                    elif low.endswith(".hsb"):
                        self._load_hashes(fp, "sha256")
                    elif low.endswith(".ndb"):
                        self._load_ndb(fp)
                except OSError:
                    continue
        return self

    def _load_hashes(self, path: str, algo: str) -> None:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                fields = line.split(":", 2)
                if len(fields) < 3:
                    continue
                digest, size, name = fields[0].strip().lower(), fields[1].strip(), fields[2].strip()
                if not all(c in _HEX for c in digest):
                    continue
                try:
                    size_i = int(size) if size.isdigit() else -1
                except ValueError:
                    size_i = -1
                self.hash_entries.append(HashEntry(algo, digest, size_i, name))
        self.files.append(path)

    def _load_ndb(self, path: str) -> None:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                fields = line.split(":")
                if len(fields) < 4:
                    continue
                name, target, offset_spec, hexsig = fields[0], fields[1], fields[2], fields[3]
                rx = _hex_to_regex(hexsig)
                if rx is None:
                    continue
                self.body_entries.append(BodyEntry(name, target, _parse_offset(offset_spec), rx))
        self.files.append(path)

    def match(self, data: bytes):
        """Yield (signature_name, kind, severity). kind in {hash, body}."""
        size = len(data)
        md5 = hashlib.md5(data).hexdigest()
        sha256 = hashlib.sha256(data).hexdigest()
        for e in self.hash_entries:
            if e.size not in (-1, size):
                continue
            if (e.algo == "md5" and e.digest == md5) or (e.algo == "sha256" and e.digest == sha256):
                yield (e.name, "hash", "critical")
        for e in self.body_entries:
            if e.match(data):
                yield (e.name, "body", "high")
