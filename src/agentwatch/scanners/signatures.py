"""Builtin signature table.

Small, curated, deterministic. Each entry is (id, pattern bytes, severity,
case-insensitive). The EICAR test string is included so the pipeline can be
exercised end-to-end without shipping anything harmful.

This is not a replacement for ClamAV. It catches high-signal markers, not the
long tail. That is stated wherever these hits appear.
"""

from __future__ import annotations

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

# (signature id, pattern, severity, case_insensitive)
SIGNATURES: tuple[tuple[str, bytes, str, bool], ...] = (
    ("eicar.test.file", EICAR, "high", False),
    ("webshell.eval_post", b"eval($_post", "high", True),
    ("webshell.eval_get", b"eval($_get", "high", True),
    ("webshell.system_get", b"system($_get", "high", True),
    ("webshell.passthru", b"passthru(", "medium", True),
    ("reverse_shell.dev_tcp", b"/dev/tcp/", "high", True),
    ("reverse_shell.nc_exec", b"nc -e /bin/sh", "high", True),
    ("reverse_shell.pty_spawn", b"pty.spawn(", "medium", True),
    ("miner.stratum", b"stratum+tcp://", "medium", True),
    ("miner.xmrig", b"xmrig", "medium", True),
    ("lolbin.certutil_urlcache", b"certutil -urlcache", "high", True),
)
