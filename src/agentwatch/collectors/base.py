"""Collector contract.

A collector observes a target and yields Artifacts. It does not judge. All
judgement lives in detectors, so a collector can be swapped (filesystem today,
ETW/eBPF later) without moving a single threshold.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterator

from ..core.schema import Artifact


class Collector(ABC):
    name = "base"

    @abstractmethod
    def collect(self, target: str) -> Iterator[Artifact]:
        raise NotImplementedError
