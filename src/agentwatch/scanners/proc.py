"""Subprocess helper for external scanners.

Writes the bytes to a temporary file, runs an argv built by the caller, and
always removes the temp file. No shell is involved: argv is a list, so a
filename can never be interpreted as a command.
"""

from __future__ import annotations

import os
import subprocess
import tempfile


def run_on_bytes(argv_fn, data: bytes, suffix: str = ".bin", timeout: int = 120):
    fd, path = tempfile.mkstemp(suffix=suffix)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        proc = subprocess.run(
            argv_fn(path),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return proc.returncode, proc.stdout, proc.stderr
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
