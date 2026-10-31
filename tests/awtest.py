"""Shared test helpers. Not part of the product."""

from agentwatch.core.hashing import hash_bytes
from agentwatch.core.schema import SAMPLE_CAP, build_artifact


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
