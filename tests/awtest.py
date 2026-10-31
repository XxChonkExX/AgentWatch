"""Shared test helpers. Not part of the product."""

import os

from agentwatch.core.hashing import hash_bytes
from agentwatch.core.schema import SAMPLE_CAP, build_artifact

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def packs_dir():
    return os.path.join(ROOT, "src", "agentwatch", "probes", "packs")


def pack_path(name):
    return os.path.join(packs_dir(), name + ".jsonl")


def art(name, data, kind="fs", **meta):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return build_artifact(
        kind=kind,
        path=meta.pop("path", name),
        name=name,
        sample=data[:SAMPLE_CAP],
        size=len(data),
        sha256=hash_bytes(data),
        meta=meta,
    )


def ids(findings):
    return [f.rule_id for f in findings]
