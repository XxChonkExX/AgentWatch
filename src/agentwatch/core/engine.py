"""Sweep engine: collectors -> artifacts -> detectors -> findings.

The engine is deliberately thin. It owns no detection logic and no scoring;
it only sequences work and, when a ledger is attached, writes the session and
its findings into the record.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable, Sequence

from .ledger import Ledger
from .schema import Finding


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class SweepResult:
    target: str
    collector: str
    artifacts_scanned: int
    bytes_scanned: int
    detector_count: int
    findings: list[Finding] = field(default_factory=list)
    started_utc: str = ""
    finished_utc: str = ""
    scanner_status: dict = field(default_factory=dict)
    timings: dict = field(default_factory=dict)


class SweepEngine:
    def __init__(self, detectors: Sequence, ledger: Ledger | None = None):
        self.detectors = list(detectors)
        self.ledger = ledger

    def _scanner_status(self) -> dict:
        status: dict = {}
        for detector in self.detectors:
            fn = getattr(detector, "status", None)
            if not callable(fn):
                continue
            try:
                status.update(fn())
            except Exception as exc:
                status[getattr(detector, "name", "scanner")] = {
                    "available": False,
                    "version": None,
                    "error": str(exc),
                }
        return status

    def sweep(self, collector, target: str) -> SweepResult:
        started = utcnow()
        timings = {"collect_s": 0.0, "detect_s": 0.0, "ledger_s": 0.0}
        ledger = self.ledger

        def record(rec: dict) -> None:
            if ledger is None:
                return
            t0 = time.perf_counter()
            ledger.append(rec)
            timings["ledger_s"] += time.perf_counter() - t0

        record(
            {
                "action": "sweep_start",
                "target": target,
                "collector": getattr(collector, "name", "unknown"),
                "detectors": len(self.detectors),
            }
        )

        findings: list[Finding] = []
        artifacts = 0
        total_bytes = 0

        stream = collector.collect(target)
        while True:
            t0 = time.perf_counter()
            try:
                artifact = next(stream)
            except StopIteration:
                timings["collect_s"] += time.perf_counter() - t0
                break
            timings["collect_s"] += time.perf_counter() - t0

            artifacts += 1
            total_bytes += artifact.size
            record(
                {
                    "action": "read",
                    "source": artifact.kind,
                    "target": artifact.path,
                    "target_sha256": artifact.sha256,
                    "size": artifact.size,
                }
            )
            t0 = time.perf_counter()
            for detector in self.detectors:
                for finding in detector.run(artifact):
                    findings.append(finding)
                    rec = finding.to_dict()
                    rec["action"] = "finding"
                    rec["artifact_sha256"] = artifact.sha256
                    record(rec)
            timings["detect_s"] += time.perf_counter() - t0

        finished = utcnow()
        scanner_status = self._scanner_status()
        result = SweepResult(
            target=target,
            collector=getattr(collector, "name", "unknown"),
            artifacts_scanned=artifacts,
            bytes_scanned=total_bytes,
            detector_count=len(self.detectors),
            findings=findings,
            started_utc=started,
            finished_utc=finished,
            scanner_status=scanner_status,
            timings={k: round(v, 4) for k, v in timings.items()},
        )
        record(
            {
                "action": "sweep_end",
                "target": target,
                "artifacts": artifacts,
                "findings": len(findings),
                "scanner_status": scanner_status,
            }
        )
        return result


def iter_findings(artifacts: Iterable, detectors: Sequence) -> Iterable[Finding]:
    for artifact in artifacts:
        for detector in detectors:
            yield from detector.run(artifact)
