"""Runtime collectors.

Backends, chosen automatically (or forced with --backend):

  psutil   if the psutil package is importable (optional extra, most robust)
  windows  PowerShell CIM + Get-Net* cmdlets (no dependencies)
  linux    /proc parsing (no dependencies)

The /proc-network parser and the PowerShell JSONL parser are pure functions
so they are unit-tested without touching a live host. A collector never
judges; it only observes.
"""

from __future__ import annotations

import json
import os
import subprocess

from .schema import (
    ConnInfo,
    DriverInfo,
    ListenerInfo,
    ProcessInfo,
    RuntimeSnapshot,
    utcnow,
)


# ---------------------------------------------------------------------------
# Linux /proc parsers (pure, testable)
# ---------------------------------------------------------------------------

def _decode_ipv4(hexaddr: str) -> str:
    b = bytes.fromhex(hexaddr)
    return ".".join(str(x) for x in reversed(b))


def _decode_ipv6(hexaddr: str) -> str:
    # Linux stores /proc/net/tcp6 addresses as four 32-bit words in host
    # (little-endian) byte order. Reverse each word's bytes, then read the
    # full 16 bytes in network order.
    b = bytes.fromhex(hexaddr)
    words = [b[i:i + 4][::-1] for i in range(0, 16, 4)]
    raw = b"".join(words)
    return ":".join("%02x%02x" % (raw[i], raw[i + 1]) for i in range(0, 16, 2))


def parse_proc_net(text: str, proto: str, is_v6: bool):
    """Parse /proc/net/{tcp,tcp6,udp,udp6}. Returns (listeners, connections)."""
    decode = _decode_ipv6 if is_v6 else _decode_ipv4
    listeners, conns = [], []
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 4 or ":" not in parts[1]:
            continue
        lh, lp = parts[1].rsplit(":", 1)
        rh, rp = parts[2].rsplit(":", 1)
        try:
            lport = int(lp, 16)
            rport = int(rp, 16)
            laddr = decode(lh)
            raddr = decode(rh)
        except (ValueError, IndexError):
            continue
        st = parts[3].upper()
        if proto == "tcp" and st == "0A":
            listeners.append(ListenerInfo("tcp", laddr, lport, 0))
        elif proto == "udp":
            listeners.append(ListenerInfo("udp", laddr, lport, 0))
        elif proto == "tcp" and st == "01":
            conns.append(ConnInfo("tcp", laddr, lport, raddr, rport, "ESTABLISHED", 0))
    return listeners, conns


def parse_proc_modules(text: str):
    drivers = []
    for line in text.splitlines():
        parts = line.split()
        if parts:
            drivers.append(DriverInfo(parts[0], "", parts[3] if len(parts) > 3 else ""))
    return drivers


class LinuxCollector:
    name = "linux"

    def collect(self) -> RuntimeSnapshot:
        processes = self._processes()
        listeners, conns = [], []
        for path, proto, v6 in (
            ("/proc/net/tcp", "tcp", False),
            ("/proc/net/tcp6", "tcp", True),
            ("/proc/net/udp", "udp", False),
            ("/proc/net/udp6", "udp", True),
        ):
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            except OSError:
                continue
            ls, cs = parse_proc_net(text, proto, v6)
            listeners.extend(ls)
            conns.extend(cs)
        drivers = []
        try:
            with open("/proc/modules", "r", encoding="utf-8", errors="replace") as fh:
                drivers = parse_proc_modules(fh.read())
        except OSError:
            pass
        return RuntimeSnapshot(
            host=self._host(),
            ts=utcnow(),
            backend=self.name,
            processes=tuple(processes),
            listeners=tuple(listeners),
            connections=tuple(conns),
            drivers=tuple(drivers),
        )

    def _host(self) -> str:
        try:
            return os.uname().nodename
        except Exception:
            return "linux"

    def _processes(self):
        out = []
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            pid = int(entry)
            try:
                with open("/proc/%d/stat" % pid, "r", encoding="utf-8", errors="replace") as fh:
                    stat = fh.read()
                rp = stat.rfind(")")
                comm = stat[stat.find("(") + 1:rp]
                rest = stat[rp + 2:].split()
                ppid = int(rest[1])
            except (OSError, ValueError, IndexError):
                continue
            try:
                with open("/proc/%d/cmdline" % pid, "rb") as fh:
                    cmdline = fh.read().replace(b"\x00", b" ").decode("utf-8", "replace").strip()
            except OSError:
                cmdline = ""
            try:
                exe = os.readlink("/proc/%d/exe" % pid)
            except OSError:
                exe = ""
            out.append(ProcessInfo(pid, ppid, comm, exe, cmdline))
        return out


# ---------------------------------------------------------------------------
# Windows backend (PowerShell, no dependencies)
# ---------------------------------------------------------------------------

PS_PROCESSES = (
    "Get-CimInstance Win32_Process | ForEach-Object { "
    "[pscustomobject]@{pid=$_.ProcessId;ppid=$_.ParentProcessId;name=$_.Name;"
    "exe=$_.ExecutablePath;cmdline=$_.CommandLine} | ConvertTo-Json -Compress }"
)
PS_LISTEN = (
    "Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | ForEach-Object { "
    "[pscustomobject]@{proto='tcp';addr=$_.LocalAddress;port=$_.LocalPort;pid=$_.OwningProcess} | "
    "ConvertTo-Json -Compress }; "
    "Get-NetUDPEndpoint -ErrorAction SilentlyContinue | ForEach-Object { "
    "[pscustomobject]@{proto='udp';addr=$_.LocalAddress;port=$_.LocalPort;pid=$_.OwningProcess} | "
    "ConvertTo-Json -Compress }"
)
PS_CONNS = (
    "Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | ForEach-Object { "
    "[pscustomobject]@{proto='tcp';laddr=$_.LocalAddress;lport=$_.LocalPort;"
    "raddr=$_.RemoteAddress;rport=$_.RemotePort;state=[string]$_.State;pid=$_.OwningProcess} | "
    "ConvertTo-Json -Compress }"
)
PS_DRIVERS = (
    "Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue | ForEach-Object { "
    "[pscustomobject]@{name=$_.Name;path=$_.PathName;state=[string]$_.State} | "
    "ConvertTo-Json -Compress }"
)


def parse_ps_jsonl(text: str) -> list:
    rows = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def _int(v, default=0):
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


class WindowsCollector:
    name = "windows"

    def collect(self) -> RuntimeSnapshot:
        processes = []
        for r in self._ps(PS_PROCESSES):
            processes.append(
                ProcessInfo(
                    _int(r.get("pid")), _int(r.get("ppid")),
                    r.get("name") or "", r.get("exe") or "", r.get("cmdline") or "",
                )
            )
        listeners = []
        for r in self._ps(PS_LISTEN):
            listeners.append(
                ListenerInfo(
                    r.get("proto") or "tcp", r.get("addr") or "", _int(r.get("port")), _int(r.get("pid"))
                )
            )
        conns = []
        for r in self._ps(PS_CONNS):
            conns.append(
                ConnInfo(
                    r.get("proto") or "tcp", r.get("laddr") or "", _int(r.get("lport")),
                    r.get("raddr") or "", _int(r.get("rport")), r.get("state") or "", _int(r.get("pid")),
                )
            )
        drivers = []
        for r in self._ps(PS_DRIVERS):
            drivers.append(DriverInfo(r.get("name") or "", r.get("path") or "", r.get("state") or ""))
        return RuntimeSnapshot(
            host=os.environ.get("COMPUTERNAME", "windows"),
            ts=utcnow(),
            backend=self.name,
            processes=tuple(processes),
            listeners=tuple(listeners),
            connections=tuple(conns),
            drivers=tuple(drivers),
        )

    def _ps(self, script: str) -> list:
        exe = "powershell"
        try:
            proc = subprocess.run(
                [exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
                capture_output=True, text=True, timeout=60,
            )
        except (OSError, subprocess.TimeoutExpired):
            return []
        return parse_ps_jsonl(proc.stdout or "")


# ---------------------------------------------------------------------------
# psutil backend (optional)
# ---------------------------------------------------------------------------

class PsutilCollector:
    name = "psutil"

    def collect(self) -> RuntimeSnapshot:
        import psutil

        processes = []
        for p in psutil.process_iter(["pid", "ppid", "name", "exe", "cmdline"]):
            info = p.info
            processes.append(
                ProcessInfo(
                    _int(info.get("pid")), _int(info.get("ppid")), info.get("name") or "",
                    info.get("exe") or "", " ".join(info.get("cmdline") or []),
                )
            )
        listeners, conns = [], []
        try:
            for c in psutil.net_connections(kind="inet"):
                if c.laddr is None:
                    continue
                proto = "tcp" if c.type == 1 else "udp"  # SOCK_STREAM=1, SOCK_DGRAM=2
                if c.status == psutil.CONN_LISTEN:
                    listeners.append(ListenerInfo(proto, c.laddr.ip, c.laddr.port, c.pid or 0))
                elif c.status == psutil.CONN_ESTABLISHED and c.raddr:
                    conns.append(ConnInfo(proto, c.laddr.ip, c.laddr.port, c.raddr.ip, c.raddr.port, "ESTABLISHED", c.pid or 0))
        except Exception:
            pass
        drivers = []
        try:
            for name in os.listdir("/sys/module") if os.path.isdir("/sys/module") else []:
                drivers.append(DriverInfo(name, "", "loaded"))
        except Exception:
            pass
        return RuntimeSnapshot(
            host=os.environ.get("COMPUTERNAME") or os.environ.get("HOSTNAME") or "host",
            ts=utcnow(),
            backend=self.name,
            processes=tuple(processes),
            listeners=tuple(listeners),
            connections=tuple(conns),
            drivers=tuple(drivers),
        )


SYSTEM_EXE_PREFIXES = (
    "c:/windows/", "c:/program files/windowsapps/",
    "/usr/bin/", "/usr/lib/", "/usr/sbin/", "/bin/", "/sbin/", "/lib/",
    "/lib64/", "/usr/share/",
)


def is_system_exe(path: str) -> bool:
    p = (path or "").replace("\\", "/").lower()
    return any(p.startswith(pref) for pref in SYSTEM_EXE_PREFIXES)


def attach_image_hashes(snapshot: RuntimeSnapshot) -> RuntimeSnapshot:
    """Fill ProcessInfo.image_sha256 for non-system executables, hashing each
    distinct path once. System executables are skipped (cheap, low-value, and
    they churn across OS updates); user/third-party binaries are the targets.
    """
    from ..core.hashing import hash_file

    cache: dict = {}
    patched = []
    for p in snapshot.processes:
        digest = p.image_sha256
        exe = p.exe
        if exe and not is_system_exe(exe) and os.path.isfile(exe):
            key = exe.lower()
            if key not in cache:
                try:
                    cache[key] = hash_file(exe)
                except OSError:
                    cache[key] = ""
            digest = cache[key] or digest
        patched.append(ProcessInfo(p.pid, p.ppid, p.name, p.exe, p.cmdline, digest))
    return RuntimeSnapshot(
        host=snapshot.host, ts=snapshot.ts, backend=snapshot.backend,
        processes=tuple(patched), listeners=snapshot.listeners,
        connections=snapshot.connections, drivers=snapshot.drivers,
        meta=snapshot.meta,
    )


def collect_snapshot(backend: str = "auto", hash_images: bool = True) -> RuntimeSnapshot:
    if backend == "psutil":
        snap = PsutilCollector().collect()
    elif backend == "windows":
        snap = WindowsCollector().collect()
    elif backend == "linux":
        snap = LinuxCollector().collect()
    else:
        try:
            import psutil  # noqa: F401
            snap = PsutilCollector().collect()
        except Exception:
            snap = WindowsCollector().collect() if os.name == "nt" else LinuxCollector().collect()
    return attach_image_hashes(snap) if hash_images else snap
