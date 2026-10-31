"""Payload builders for the API layer.

Everything here is plain Python returning plain dicts/strings, so the whole
API surface is testable without a web framework. app.py stays thin: parse the
request, call a builder, return the result.
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone

from .. import __version__
from ..detectors.frozen_guard import load_manifest
from ..detectors.registry import RULES, build_detectors
from ..probes.runner import run_pack
from ..probes.schema import ProbePack, read_transcripts
from ..probes.scoring import render_review_sheet, score_arms
from ..probes.targets import OpenAICompatTarget
from ..runtime.collect import collect_snapshot
from ..runtime.diff import diff_snapshots
from ..runtime.posture import analyze as posture_analyze
from ..runtime.schema import RuntimeSnapshot
from ..core.engine import SweepEngine
from ..core.ledger import Ledger
from ..scoring import report as report_mod
from ..scoring import severity as severity_mod

HERE = os.path.dirname(os.path.abspath(__file__))
PACKS_DIR = os.path.normpath(os.path.join(HERE, "..", "probes", "packs"))
STATIC_DIR = os.path.join(HERE, "static")


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def health_payload(ledger_dir: str | None = None) -> dict:
    return {
        "status": "ok",
        "version": __version__,
        "rules": len(RULES),
        "ledger": ledger_dir or None,
        "ts": utcnow(),
    }


def rules_payload() -> list:
    return [RULES[rid].to_dict() for rid in sorted(RULES)]


def scanner_status_payload(rules_dir: str | None = None, sig_dir: str | None = None) -> dict:
    detectors = build_detectors(None, rules_dir=rules_dir, sig_dir=sig_dir)
    status = {}
    for d in detectors:
        fn = getattr(d, "status", None)
        if callable(fn):
            status.update(fn())
    return status


def sweep_payload(target: str, kind: str | None = None, ledger_dir: str | None = None,
                  freeze: str | None = None, rules_dir: str | None = None,
                  sig_dir: str | None = None, rule_filter: str | None = None) -> dict:
    freeze_manifest = load_manifest(freeze) if freeze else None
    detectors = build_detectors(freeze_manifest, rules_dir=rules_dir, sig_dir=sig_dir)
    ledger = Ledger(ledger_dir) if ledger_dir else None
    from ..cli.main import pick_collector

    engine = SweepEngine(detectors, ledger=ledger)
    result = engine.sweep(pick_collector(target, kind), target)
    payload = report_mod.to_dict(result)
    payload["generated_utc"] = utcnow()
    return payload


def snapshot_payload(backend: str = "auto", out: str | None = None) -> dict:
    snap = collect_snapshot(backend)
    written = None
    if out:
        with open(out, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(snap.to_dict(), fh, indent=2, sort_keys=True)
            fh.write("\n")
        written = out
    return {
        "host": snap.host,
        "backend": snap.backend,
        "ts": snap.ts,
        "sha256": snap.hash(),
        "counts": snap.counts(),
        "written": written,
    }


def posture_payload(baseline: str, backend: str = "auto", force: bool = False,
                    allow_ports=(), allow_process=(), include_loopback: bool = False,
                    scan_all: bool = False, ledger_dir: str | None = None) -> dict:
    with open(baseline, "r", encoding="utf-8") as fh:
        base = RuntimeSnapshot.from_dict(json.load(fh))
    resolved = backend
    if resolved == "auto":
        try:
            import psutil  # noqa: F401
            resolved = "psutil"
        except Exception:
            resolved = "windows" if os.name == "nt" else "linux"
    if base.backend and base.backend != resolved and not force:
        return {
            "error": "backend mismatch: baseline=%s current=%s (use force to override)"
                     % (base.backend, resolved),
            "baseline_backend": base.backend,
            "current_backend": resolved,
        }
    cur = collect_snapshot(backend)
    diff = diff_snapshots(base, cur)
    findings = posture_analyze(
        diff, cur,
        allow_ports=allow_ports, allow_processes=allow_process,
        ignore_loopback=not include_loopback, scan_all_processes=scan_all,
    )
    if ledger_dir:
        Ledger(ledger_dir).append({
            "action": "posture",
            "baseline": baseline,
            "baseline_sha256": base.hash(),
            "current_sha256": cur.hash(),
            "counts": diff.get("counts", {}),
            "findings": [f.to_dict() for f in findings],
        })
    return {
        "host": cur.host,
        "backend": cur.backend,
        "ts": cur.ts,
        "baseline_sha256": base.hash(),
        "current_sha256": cur.hash(),
        "visible": cur.counts(),
        "changes": diff.get("counts", {}),
        "counts": severity_mod.counts(findings),
        "findings": [f.to_dict() for f in severity_mod.rank(findings)],
        "coverage_limits": report_mod.POSTURE_LIMITS.splitlines(),
        "generated_utc": utcnow(),
    }


def packs_payload(packs_dir: str | None = None) -> list:
    d = packs_dir or PACKS_DIR
    out = []
    if not os.path.isdir(d):
        return out
    for fn in sorted(os.listdir(d)):
        if not fn.endswith(".jsonl"):
            continue
        path = os.path.join(d, fn)
        try:
            pack = ProbePack.load(path)
        except Exception as exc:
            out.append({"name": fn, "error": str(exc)})
            continue
        frozen = os.path.exists(pack.sidecar_path())
        out.append({
            "name": pack.name,
            "path": pack.path,
            "sha256": pack.sha256,
            "n": len(pack.probes),
            "counts": pack.counts(),
            "frozen": frozen,
        })
    return out


def probe_run_payload(pack_name: str, target_url: str, model: str = "local",
                      arm: str | None = None, limit: int | None = None,
                      api_key: str | None = None, out_dir: str | None = None,
                      packs_dir: str | None = None) -> dict:
    path = _resolve_pack(pack_name, packs_dir)
    pack = ProbePack.load(path)
    if limit and limit > 0:
        pack = ProbePack(probes=pack.probes[:limit], path=pack.path, name=pack.name, sha256=pack.sha256)
    target = OpenAICompatTarget(target_url, model, api_key=api_key)
    results = run_pack(pack, target, arm=arm or target.name)
    out_dir = out_dir or tempfile.gettempdir()
    out = os.path.join(out_dir, "transcripts_%s_%s.jsonl" % (pack.name, results[0].arm if results else "arm"))
    from ..probes.schema import write_transcripts

    write_transcripts(out, results)
    return {
        "pack": pack.name,
        "pack_sha256": pack.sha256,
        "n": len(results),
        "target": target.name,
        "transcripts": out,
        "generated_utc": utcnow(),
    }


def probe_score_payload(transcripts: list, ref: str | None = None) -> dict:
    arms = {}
    for path in transcripts:
        ts = read_transcripts(path)
        if not ts:
            continue
        arms[ts[0].arm] = ts
    report = score_arms(arms, ref=ref)
    report["generated_utc"] = utcnow()
    return report


def review_payload(pack_name: str, transcripts: str, packs_dir: str | None = None) -> dict:
    pack = ProbePack.load(_resolve_pack(pack_name, packs_dir))
    ts = read_transcripts(transcripts)
    return {"sheet": render_review_sheet(pack, ts), "n": len(ts)}


def ledger_recent_payload(ledger_dir: str, limit: int = 100) -> dict:
    led = Ledger(ledger_dir)
    records = list(led.read_all())
    total = len(records)
    ok, problems = led.verify()
    return {
        "total": total,
        "chain_ok": ok,
        "problems": problems[:10],
        "records": list(reversed(records[-limit:])),
    }


def _resolve_pack(name: str, packs_dir: str | None = None) -> str:
    p = name
    if os.path.isfile(p):
        return p
    d = packs_dir or PACKS_DIR
    for cand in (os.path.join(d, name + ".jsonl"), os.path.join(d, name)):
        if os.path.isfile(cand):
            return cand
    raise FileNotFoundError("pack not found: %s" % name)
