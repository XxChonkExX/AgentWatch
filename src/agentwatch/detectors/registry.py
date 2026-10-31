"""Assemble the M0 detector pack.

Order is fixed so a sweep reproduces its finding order. FrozenGuard is
parameterised by a caller-supplied manifest; every other detector is
stateless and deterministic.
"""

from __future__ import annotations

from .covert_channel import CovertWhitespaceDetector
from .entropy_blob import EntropyBlobDetector
from .frozen_guard import FrozenGuardDetector
from .hidden_streams import AlternateStreamDetector
from .magic_mismatch import MagicMismatchDetector
from .null_bytes import NullByteDetector
from .rules import ALL_RULES, RULES
from .script_obfuscation import ScriptObfuscationDetector
from .thinking_gate import (
    InjectionMarkerDetector,
    IntentMarkerDetector,
    ThinkLeakDetector,
)
from .unicode_gates import (
    ConfusableDetector,
    TagBlockDetector,
    VariationSelectorDetector,
    ZeroWidthDetector,
)


def build_detectors(
    freeze_manifest: dict | None = None,
    rules_dir: str | None = None,
    sig_dir: str | None = None,
    scanners=None,
) -> list:
    # Imported here to keep the detector package importable without the
    # scanners package and vice versa.
    from ..scanners.detector import ScannerDetector

    return [
        ZeroWidthDetector(),
        TagBlockDetector(),
        VariationSelectorDetector(),
        ConfusableDetector(),
        NullByteDetector(),
        AlternateStreamDetector(),
        EntropyBlobDetector(),
        MagicMismatchDetector(),
        ScriptObfuscationDetector(),
        CovertWhitespaceDetector(),
        ScannerDetector(scanners=scanners, rules_dir=rules_dir, sig_dir=sig_dir),
        FrozenGuardDetector(freeze_manifest),
        ThinkLeakDetector(),
        InjectionMarkerDetector(),
        IntentMarkerDetector(),
    ]


__all__ = ["build_detectors", "ALL_RULES", "RULES"]
