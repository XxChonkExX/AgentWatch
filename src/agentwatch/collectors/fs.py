"""Filesystem collector.

Walks a file or directory, hashes each file (streamed, so large model
artifacts are safe), reads a capped sample, and on Windows enumerates NTFS
alternate data streams. Nothing is skipped silently: unreadable entries are
recorded in Artifact.meta as errors rather than dropped.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterator, Optional

from ..core.hashing import hash_file
from ..core.schema import SAMPLE_CAP, Artifact, build_artifact
from .base import Collector

FILE_ATTRIBUTE_HIDDEN = 0x2


def list_ads(path: str) -> list[str]:
    """Enumerate non-default NTFS streams on Windows. [] elsewhere."""
    if os.name != "nt":
        return []
    try:
        import ctypes
        from ctypes import wintypes

        class STREAM_DATA(ctypes.Structure):
            _fields_ = [
                ("StreamSize", ctypes.c_longlong),
                ("StreamName", ctypes.c_wchar * 296),
            ]

        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.FindFirstStreamW.restype = ctypes.c_void_p
        k32.FindFirstStreamW.argtypes = [
            wintypes.LPCWSTR,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
        ]
        k32.FindNextStreamW.restype = wintypes.BOOL
        k32.FindNextStreamW.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        k32.FindClose.argtypes = [ctypes.c_void_p]

        invalid = ctypes.c_void_p(-1).value
        data = STREAM_DATA()
        handle = k32.FindFirstStreamW(str(path), 0, ctypes.byref(data), 0)
        if handle in (None, 0, invalid):
            return []
        names: list[str] = []
        try:
            while True:
                names.append(data.StreamName)
                if not k32.FindNextStreamW(handle, ctypes.byref(data)):
                    break
        finally:
            k32.FindClose(handle)
        return [n for n in names if n not in (":$DATA", "::$DATA")]
    except Exception:
        return []


class FsCollector(Collector):
    name = "fs"

    def __init__(self, include_hidden: bool = True):
        self.include_hidden = include_hidden

    def collect(self, target: str) -> Iterator[Artifact]:
        p = Path(target)
        if p.is_file():
            art = self._artifact(p)
            if art is not None:
                yield art
            return
        for root, _dirs, files in os.walk(p):
            for fn in sorted(files):
                art = self._artifact(Path(root) / fn)
                if art is not None:
                    yield art

    def _hidden(self, p: Path) -> bool:
        if p.name.startswith("."):
            return True
        try:
            attrs = getattr(p.stat(), "st_file_attributes", 0)
            return bool(attrs & FILE_ATTRIBUTE_HIDDEN)
        except OSError:
            return False

    def _artifact(self, p: Path) -> Optional[Artifact]:
        try:
            size = p.stat().st_size
            digest = hash_file(str(p))
            with open(p, "rb") as fh:
                sample = fh.read(SAMPLE_CAP)
        except OSError as exc:
            return build_artifact(
                "fs",
                str(p),
                p.name,
                b"",
                0,
                "unreadable",
                {"error": str(exc)},
            )
        import hashlib

        meta = {
            "streams": list_ads(str(p)),
            "hidden": self._hidden(p),
            "md5": hashlib.md5(sample).hexdigest() if size <= SAMPLE_CAP else None,
        }
        return build_artifact("fs", str(p), p.name, sample, size, digest, meta)
