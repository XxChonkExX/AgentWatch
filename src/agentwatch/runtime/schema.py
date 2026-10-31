"""Runtime snapshot model.

A snapshot is a deterministic, serializable picture of the host's visible
surface: processes, listening endpoints, established connections, and loaded
kernel drivers/modules. Posture analysis is a diff between two snapshots, so
the format is stable and hashed.

Nothing here is a judgement. A snapshot is a fact about the host at a moment.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

from ..core.hashing import hash_obj


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def norm_path(p: str) -> str:
    return (p or "").replace("\\", "/").lower()


@dataclass(frozen=True)
class ProcessInfo:
    pid: int
    ppid: int
    name: str
    exe: str = ""
    cmdline: str = ""

    def identity(self) -> str:
        return norm_path(self.exe) or (self.name or "").lower()

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class ListenerInfo:
    proto: str
    addr: str
    port: int
    pid: int = 0

    def identity(self) -> tuple:
        return (self.proto, self.addr, self.port)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class ConnInfo:
    proto: str
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    state: str = ""
    pid: int = 0

    def identity(self) -> tuple:
        return (self.proto, self.local_port, self.remote_addr, self.remote_port)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class DriverInfo:
    name: str
    path: str = ""
    state: str = ""

    def identity(self) -> str:
        return (self.name or "").lower()

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class RuntimeSnapshot:
    host: str = ""
    ts: str = ""
    backend: str = ""
    processes: tuple = ()
    listeners: tuple = ()
    connections: tuple = ()
    drivers: tuple = ()
    meta: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "ts": self.ts,
            "backend": self.backend,
            "processes": [p.to_dict() for p in self.processes],
            "listeners": [x.to_dict() for x in self.listeners],
            "connections": [c.to_dict() for c in self.connections],
            "drivers": [d.to_dict() for d in self.drivers],
            "meta": self.meta,
        }

    @staticmethod
    def from_dict(d: dict) -> "RuntimeSnapshot":
        return RuntimeSnapshot(
            host=d.get("host", ""),
            ts=d.get("ts", ""),
            backend=d.get("backend", ""),
            processes=tuple(ProcessInfo(**p) for p in d.get("processes", [])),
            listeners=tuple(ListenerInfo(**x) for x in d.get("listeners", [])),
            connections=tuple(ConnInfo(**c) for c in d.get("connections", [])),
            drivers=tuple(DriverInfo(**x) for x in d.get("drivers", [])),
            meta=d.get("meta", {}),
        )

    def hash(self) -> str:
        return hash_obj(self.to_dict())

    def counts(self) -> dict:
        return {
            "processes": len(self.processes),
            "listeners": len(self.listeners),
            "connections": len(self.connections),
            "drivers": len(self.drivers),
        }
