"""Record types shared across AgentWatch.

Two immutable record families:

  Artifact  -- something a collector observed and handed to detectors.
  Finding   -- a detector's claim about an artifact.

And one rule contract:

  Rule      -- the frozen identity of a detector's gate. A finding that
               cannot name its rule, lane, version, and falsifier is an
               anecdote, not a result.

Lane doctrine (see docs/METHOD.md):
  Lane A (deterministic) reproduces bit-for-bit and MAY condemn.
  Lane B (advisory) carries a model stamp and MAY ONLY rank/route to review.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Optional

SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}

LANE_DETERMINISTIC = "A"
LANE_ADVISORY = "B"

# Extensions that are expected to contain arbitrary binary bytes. High
# entropy inside these is not evidence; high entropy inside a text file is.
BINARY_EXT = {
    ".zip", ".gz", ".tgz", ".7z", ".rar", ".xz", ".bz2", ".zst",
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico", ".tif", ".tiff",
    ".pdf", ".mp3", ".mp4", ".mov", ".avi", ".mkv", ".wav", ".flac", ".ogg",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".gguf", ".safetensors", ".pt", ".pth", ".onnx", ".bin", ".npy", ".npz",
    ".so", ".dll", ".dylib", ".exe", ".sys", ".obj", ".o", ".a", ".lib",
}

TEXT_EXT = {
    ".txt", ".md", ".markdown", ".rst", ".log", ".csv", ".tsv",
    ".json", ".jsonl", ".ndjson", ".yaml", ".yml", ".toml", ".ini", ".cfg",
    ".xml", ".html", ".htm", ".eml", ".mbox", ".ics", ".vcf",
    ".py", ".ps1", ".psm1", ".bat", ".cmd", ".sh", ".bash", ".zsh",
    ".js", ".mjs", ".cjs", ".ts", ".vbs", ".vbe", ".jse", ".wsf", ".hta",
    ".php", ".rb", ".pl", ".lua", ".sql", ".c", ".h", ".cpp", ".hpp", ".rs",
    ".go", ".java", ".cs", ".kt",
}

SCRIPT_EXT = {
    ".ps1", ".psm1", ".bat", ".cmd", ".sh", ".bash", ".zsh",
    ".js", ".mjs", ".cjs", ".vbs", ".vbe", ".jse", ".wsf", ".hta", ".py",
}

EXEC_EXT = {
    ".exe", ".scr", ".com", ".pif", ".cpl", ".msi", ".msp", ".dll",
    ".sys", ".ocx", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse",
    ".wsf", ".hta", ".lnk", ".jar", ".apk", ".elf", ".so",
}

SAMPLE_CAP = 4 << 20  # 4 MiB max handed to any detector


@dataclass(frozen=True)
class Rule:
    """Frozen identity of a deterministic (Lane A) gate."""

    rule_id: str
    lane: str
    severity: str
    title: str
    description: str
    falsifier: str
    version: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Artifact:
    """An observed unit handed to detectors.

    sample is a capped prefix of the bytes; size is the true size.
    text is the decoded sample when the artifact is text-like, else None.
    meta carries collector-specific fields (streams, headers, encoding...).
    """

    kind: str
    path: str
    name: str
    size: int
    sha256: str
    sample: bytes
    text: Optional[str] = None
    meta: dict = field(default_factory=dict)

    @property
    def ext(self) -> str:
        import os

        return os.path.splitext(self.name)[1].lower()

    @property
    def is_text(self) -> bool:
        return self.text is not None


@dataclass
class Evidence:
    path: str
    span: Optional[tuple] = None
    excerpt_hash: Optional[str] = None
    note: str = ""

    def to_dict(self) -> dict:
        d = {"path": self.path}
        if self.span is not None:
            d["span"] = list(self.span)
        if self.excerpt_hash is not None:
            d["excerpt_hash"] = self.excerpt_hash
        if self.note:
            d["note"] = self.note
        return d


@dataclass
class Finding:
    rule_id: str
    lane: str
    severity: str
    title: str
    target: str
    detail: str
    evidence: list = field(default_factory=list)
    rule_version: str = ""
    reproduce: str = ""
    # "quoted" if the hit is inside code/backticks/quotes, "technical" if the
    # containing line reads as discussion of the topic rather than the act.
    # A non-empty context downgrades severity one notch and groups the finding
    # separately in the report. It is a deterministic, reproducible tag.
    context: str = ""

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "lane": self.lane,
            "severity": self.severity,
            "title": self.title,
            "target": self.target,
            "detail": self.detail,
            "evidence": [e.to_dict() if hasattr(e, "to_dict") else e for e in self.evidence],
            "rule_version": self.rule_version,
            "reproduce": self.reproduce,
            "context": self.context,
        }


def decode_sample(sample: bytes) -> tuple[Optional[str], Optional[str]]:
    """Return (text, encoding). encoding is None for binary-forward samples.

    Single-byte encodings only (utf-8 / ascii). utf-16 is detected by BOM and
    decoded, but then reported as its own encoding so NUL bytes are not
    mistaken for tampering.
    """
    if not sample:
        return "", "utf-8"
    if sample[:2] in (b"\xff\xfe", b"\xfe\xff"):
        try:
            return sample.decode("utf-16"), "utf-16"
        except UnicodeDecodeError:
            pass
    for enc in ("utf-8", "ascii"):
        try:
            return sample.decode(enc), enc
        except UnicodeDecodeError:
            continue
    return None, None


def build_artifact(
    kind: str,
    path: str,
    name: str,
    sample: bytes,
    size: int,
    sha256: str,
    meta: dict | None = None,
) -> Artifact:
    """Assemble an Artifact from an already-hashed sample.

    Hashing is the collector's job (it may stream a large file). This factory
    only decodes the sample and records provenance.
    """
    text, encoding = decode_sample(sample)
    m = dict(meta or {})
    m["encoding"] = encoding
    m["truncated"] = size > SAMPLE_CAP
    return Artifact(
        kind=kind,
        path=path,
        name=name,
        size=size,
        sha256=sha256,
        sample=sample,
        text=text,
        meta=m,
    )
