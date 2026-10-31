"""Probe runner.

Runs a frozen pack against a target in pack order, with fixed decode
parameters, and records every prompt/response as a Transcript. With a ledger
attached, each result is appended to the record.
"""

from __future__ import annotations

from .schema import Probe, ProbePack, Transcript, utcnow

GEN_SHORT = 48
GEN_OPEN = 128


def max_tokens_for(kind: str) -> int:
    return GEN_OPEN if kind == "open" else GEN_SHORT


def run_pack(pack: ProbePack, target, ledger=None, arm: str | None = None,
             temperature: float = 0.0, seed: int = 0) -> list:
    arm = arm or getattr(target, "name", "anon")
    model = getattr(target, "model", "")
    out: list[Transcript] = []
    if ledger is not None:
        ledger.append(
            {
                "action": "probe_run_start",
                "pack": pack.name,
                "pack_sha256": pack.sha256,
                "n": len(pack.probes),
                "arm": arm,
                "model": model,
            }
        )
    for probe in pack.probes:
        messages = probe.to_messages()
        mt = max_tokens_for(probe.kind)
        output = target.generate(messages, max_tokens=mt, temperature=temperature, seed=seed)
        t = Transcript(
            pid=probe.pid,
            kind=probe.kind,
            output=output or "",
            prompt=probe.last_user_text(),
            arm=arm,
            model=model,
            params={"temperature": temperature, "max_tokens": mt, "seed": seed},
            ts=utcnow(),
        )
        out.append(t)
        if ledger is not None:
            rec = t.to_dict()
            rec["action"] = "probe_result"
            rec["pack_sha256"] = pack.sha256
            ledger.append(rec)
    if ledger is not None:
        ledger.append({"action": "probe_run_end", "pack": pack.name, "arm": arm, "results": len(out)})
    return out
