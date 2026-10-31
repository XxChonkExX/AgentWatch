"""`aw` - AgentWatch command line.

M0 surface: ledger init/verify, sweep, rule list/test, serve.

Exit codes: 0 clean, 1 findings at or above --fail-on (default: none, so a
sweep never fails a pipeline unless asked), 2 usage error.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .. import __version__
from ..collectors.fs import FsCollector
from ..collectors.mail import MailCollector
from ..core.engine import SweepEngine
from ..core.ledger import Ledger
from ..detectors.frozen_guard import load_manifest
from ..detectors.registry import RULES, build_detectors
from ..probes.runner import run_pack
from ..probes.schema import ProbePack, read_transcripts, write_transcripts
from ..probes.scoring import render_probe_report, render_review_sheet, score_arms
from ..probes.targets import OpenAICompatTarget, RecordedTarget
from ..runtime.collect import collect_snapshot
from ..runtime.diff import diff_snapshots
from ..runtime.posture import analyze as posture_analyze
from ..runtime.schema import RuntimeSnapshot
from ..scoring import report as report_mod
from ..scoring import severity


def _repo_root() -> Path:
    # .../AgentWatch/src/agentwatch/cli/main.py -> .../AgentWatch
    return Path(__file__).resolve().parents[3]


def pick_collector(target: str, kind: str | None):
    """Choose a collector.

    Directories default to filesystem so a mixed workspace is fully swept;
    a directory is treated as mail only when it is a Maildir (cur/ or new/).
    Point `--kind mail` at a flat directory of .eml files to get attachment
    parsing, which the filesystem collector does not do.
    """
    p = Path(target)
    if kind == "fs":
        return FsCollector()
    if kind == "mail":
        return MailCollector()
    if p.is_dir() and ((p / "cur").is_dir() or (p / "new").is_dir()):
        return MailCollector()
    if p.is_file() and p.suffix.lower() in (".eml", ".mbox"):
        return MailCollector()
    return FsCollector()


def run_falsifier(falsifier: str) -> bool:
    import unittest

    path, _, testname = falsifier.partition("::")
    root = _repo_root()
    testfile = root / path
    if not testfile.exists():
        print("falsifier not found: %s" % testfile)
        return False
    src = str(root / "src")
    if src not in sys.path:
        sys.path.insert(0, src)
    loader = unittest.TestLoader()
    suite = loader.discover(str(testfile.parent), pattern=testfile.name)

    def flatten(s):
        for t in s:
            if isinstance(t, unittest.TestSuite):
                yield from flatten(t)
            else:
                yield t

    tests = [t for t in flatten(suite) if getattr(t, "_testMethodName", "") == testname]
    if not tests:
        tests = list(flatten(suite))
    result = unittest.TextTestRunner(verbosity=2, stream=sys.stdout).run(
        unittest.TestSuite(tests)
    )
    return result.wasSuccessful()


def cmd_ledger_init(args) -> int:
    led = Ledger.init(args.dir)
    print("ledger initialised: %s" % led.path)
    return 0


def cmd_ledger_verify(args) -> int:
    led = Ledger(args.dir)
    ok, problems = led.verify()
    if ok:
        n = sum(1 for _ in led.read_all())
        print("OK: %d record(s), chain intact" % n)
    else:
        print("TAMPERED: %d problem(s)" % len(problems))
        for p in problems:
            print("  " + p)
    if args.anchor:
        with open(args.anchor, "r", encoding="utf-8") as fh:
            anchor = json.load(fh)
        aok, aproblems = led.verify_anchor(anchor)
        if aok:
            print("OK: chain head matches anchor at seq=%s" % anchor.get("seq"))
        else:
            ok = False
            print("ANCHOR MISMATCH:")
            for p in aproblems:
                print("  " + p)
    return 0 if ok else 1


def cmd_ledger_anchor(args) -> int:
    led = Ledger(args.dir)
    doc = led.anchor_head()
    out = args.out or os.path.join(args.dir, "head.json")
    with open(out, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(doc, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print("anchored: seq=%s hash=%s -> %s" % (doc["seq"], doc["hash"][:16], out))
    print("store this file somewhere the ledger cannot reach (second box, cold storage).")
    return 0


def _default_rules_dir(args) -> str | None:
    if getattr(args, "rules_dir", None):
        return args.rules_dir
    candidate = _repo_root() / "rules" / "yara"
    return str(candidate) if candidate.is_dir() else None


def _default_sig_dir(args) -> str | None:
    if getattr(args, "sig_dir", None):
        return args.sig_dir
    candidate = _repo_root() / "signatures"
    return str(candidate) if candidate.is_dir() else None


def cmd_sweep(args) -> int:
    freeze = load_manifest(args.freeze) if args.freeze else None
    detectors = build_detectors(
        freeze,
        rules_dir=_default_rules_dir(args),
        sig_dir=_default_sig_dir(args),
        live_av=not args.no_live_av,
    )
    ledger = Ledger.init(args.ledger) if args.ledger else None
    collector = pick_collector(args.target, args.kind)
    engine = SweepEngine(detectors, ledger=ledger)
    result = engine.sweep(collector, args.target)

    if args.json:
        print(json.dumps(report_mod.to_dict(result), indent=2, sort_keys=True))
    else:
        print(report_mod.render_text(result, rule_filter=args.rule))

    if args.fail_on != "none":
        flagged = severity.at_or_above(result.findings, args.fail_on)
        return 1 if flagged else 0
    return 0


def cmd_rule_list(args) -> int:
    print("%-9s %-9s %-9s %s" % ("rule", "lane", "severity", "title"))
    for rid in sorted(RULES):
        r = RULES[rid]
        print("%-9s %-9s %-9s %s" % (r.rule_id, r.lane, r.severity, r.title))
    return 0


def cmd_rule_test(args) -> int:
    targets = []
    if args.rule == "all":
        targets = [r.falsifier for r in RULES.values()]
    else:
        if args.rule not in RULES:
            print("unknown rule: %s" % args.rule)
            return 2
        targets = [RULES[args.rule].falsifier]
    ok = True
    for falsifier in targets:
        print("== %s" % falsifier)
        ok = run_falsifier(falsifier) and ok
    return 0 if ok else 1


def cmd_serve(args) -> int:
    try:
        from ..api.app import create_app
    except ImportError:
        print("serve requires the api extra: pip install -e .[api]")
        return 2
    import uvicorn

    freeze = load_manifest(args.freeze) if args.freeze else None
    app = create_app(
        ledger_dir=args.ledger,
        freeze_manifest=freeze,
        rules_dir=_default_rules_dir(args),
        sig_dir=_default_sig_dir(args),
    )
    if args.open:
        import threading
        import webbrowser

        threading.Timer(1.2, lambda: webbrowser.open("http://%s:%d/" % (args.host, args.port))).start()
    print("AgentWatch dashboard: http://%s:%d/  (Ctrl+C to stop)" % (args.host, args.port))
    uvicorn.run(app, host=args.host, port=args.port)
    return 0


def _packs_dir() -> Path:
    return _repo_root() / "src" / "agentwatch" / "probes" / "packs"


def _resolve_pack(name: str) -> str:
    p = Path(name)
    if p.is_file():
        return str(p)
    for cand in (_packs_dir() / (name + ".jsonl"), _packs_dir() / name):
        if cand.is_file():
            return str(cand)
    raise SystemExit("pack not found: %s (looked in %s)" % (name, _packs_dir()))


def cmd_probe_list(args) -> int:
    pack = ProbePack.load(_resolve_pack(args.pack))
    print("pack    : %s" % pack.name)
    print("path    : %s" % pack.path)
    print("sha256  : %s" % pack.sha256)
    print("probes  : %d" % len(pack.probes))
    for kind, n in pack.counts().items():
        print("  %-20s %d" % (kind, n))
    if args.verbose:
        for p in pack.probes:
            print("  %-24s %-16s %s" % (p.pid, p.kind, p.last_user_text()[:60]))
    return 0


def cmd_probe_freeze(args) -> int:
    pack = ProbePack.load(_resolve_pack(args.pack))
    doc = pack.freeze(provenance=args.provenance or "")
    print("frozen: %s" % pack.sidecar_path())
    print("sha256: %s" % doc["sha256"])
    print("n     : %d" % doc["n"])
    return 0


def cmd_probe_verify(args) -> int:
    pack = ProbePack.load(_resolve_pack(args.pack))
    ok, problems = pack.verify()
    if ok:
        print("OK: %s matches frozen sidecar (%d probes)" % (pack.name, len(pack.probes)))
        return 0
    print("FROZEN-PACK MISMATCH:")
    for p in problems:
        print("  " + p)
    return 1


def cmd_probe_run(args) -> int:
    pack = ProbePack.load(_resolve_pack(args.pack))
    if args.recorded:
        ts = read_transcripts(args.recorded)
        target = RecordedTarget({t.prompt: t.output for t in ts}, name=args.arm or "recorded")
    elif args.target_url:
        target = OpenAICompatTarget(args.target_url, args.model or "local", api_key=args.api_key)
    else:
        print("probe run needs --target-url URL --model M, or --recorded FILE")
        return 2
    ledger = Ledger.init(args.ledger) if args.ledger else None
    results = run_pack(pack, target, ledger=ledger, arm=args.arm)
    out = args.out or ("transcripts_%s_%s.jsonl" % (pack.name, results[0].arm if results else "arm"))
    write_transcripts(out, results)
    print("ran %d probes against %s -> %s" % (len(results), target.name, out))
    return 0


def cmd_probe_score(args) -> int:
    arms: dict = {}
    for path in args.transcripts:
        ts = read_transcripts(path)
        arm = ts[0].arm if ts else Path(path).stem
        arms[arm] = ts
    report = score_arms(arms, ref=args.ref)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(render_probe_report(report))
    return 0


def cmd_probe_review(args) -> int:
    pack = ProbePack.load(_resolve_pack(args.pack))
    ts = read_transcripts(args.transcripts)
    print(render_review_sheet(pack, ts))
    return 0


def cmd_snapshot(args) -> int:
    snap = collect_snapshot(args.backend, hash_images=args.hash_images)
    if args.out:
        with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(snap.to_dict(), fh, indent=2, sort_keys=True)
            fh.write("\n")
    if args.json:
        print(json.dumps(snap.to_dict(), indent=2, sort_keys=True))
    else:
        c = snap.counts()
        print("snapshot    : host=%s backend=%s ts=%s" % (snap.host, snap.backend, snap.ts))
        print("visible     : proc=%d listen=%d conn=%d drivers=%d" % (
            c["processes"], c["listeners"], c["connections"], c["drivers"]))
        print("sha256      : %s" % snap.hash()[:32])
        if args.out:
            print("written     : %s" % args.out)
    return 0


def cmd_posture(args) -> int:
    with open(args.baseline, "r", encoding="utf-8") as fh:
        base = RuntimeSnapshot.from_dict(json.load(fh))
    # Cheap pre-check before any collection: backends see different worlds
    # (driver model, address rendering). Diffing across them manufactures
    # findings.
    resolved = args.backend
    if resolved == "auto":
        try:
            import psutil  # noqa: F401
            resolved = "psutil"
        except Exception:
            resolved = "windows" if os.name == "nt" else "linux"
    if base.backend and base.backend != resolved and not args.force:
        print("backend mismatch: baseline=%s current=%s (use --force to override)"
              % (base.backend, resolved))
        return 2
    cur = collect_snapshot(args.backend, hash_images=args.hash_images)
    diff = diff_snapshots(base, cur)
    findings = posture_analyze(
        diff,
        cur,
        allow_ports=args.allow_port,
        allow_processes=args.allow_process,
        ignore_loopback=not args.include_loopback,
        scan_all_processes=args.scan_all,
    )
    ledger = Ledger.init(args.ledger) if args.ledger else None
    if ledger is not None:
        ledger.append({
            "action": "posture",
            "baseline": args.baseline,
            "baseline_sha256": base.hash(),
            "current_sha256": cur.hash(),
            "counts": diff.get("counts", {}),
            "findings": [f.to_dict() for f in findings],
        })
    if args.json:
        print(json.dumps({
            "baseline_sha256": base.hash(),
            "current_sha256": cur.hash(),
            "diff_counts": diff.get("counts", {}),
            "findings": [f.to_dict() for f in findings],
        }, indent=2, sort_keys=True))
    else:
        print(report_mod.render_posture_report(cur, diff, findings, baseline_path=args.baseline))
    if args.fail_on != "none":
        flagged = severity.at_or_above(findings, args.fail_on)
        return 1 if flagged else 0
    return 0


def cmd_ledger_loops(args) -> int:
    from agentwatch.core.loops import detect_loops

    led = Ledger(args.dir)
    findings = detect_loops(list(led.read_all()), threshold=args.threshold, window=args.window)
    if not findings:
        print("no action loops in the last %d records" % args.window)
        return 0
    for f in findings:
        print("[%s] %s  %s" % (f.severity, f.rule_id, f.title))
        print("    target : %s" % f.target)
        print("    detail : %s" % f.detail)
    return 0


def cmd_canary_plant(args) -> int:
    from agentwatch.core.canary import plant

    reg = plant(args.workspace, count=args.count)
    print("planted %d canary(ies) in %s" % (len(reg["canaries"]), args.workspace))
    print("registry: %s" % os.path.join(args.workspace, ".agentwatch", "canaries.json"))
    print("if any canary appears outside this workspace, data moved. check with:")
    print("  aw canary check <other-dir-or-ledger> --registry \"%s\"" %
          os.path.join(args.workspace, ".agentwatch", "canaries.json"))
    return 0


def cmd_canary_check(args) -> int:
    from agentwatch.core.canary import registry_tokens, load_registry
    from agentwatch.core.schema import build_artifact
    from agentwatch.core.hashing import hash_bytes

    registry = load_registry(args.registry) if os.path.isdir(args.registry) else json.load(open(args.registry, encoding="utf-8"))
    tokens = registry_tokens(registry)
    if not tokens:
        print("no readable canaries in registry (planted files moved or removed)")
        return 2
    hits = []
    p = Path(args.target)
    if p.is_file():
        text = p.read_text(encoding="utf-8", errors="replace")
        for tok in tokens:
            if tok in text:
                hits.append((str(p), tok))
    elif p.is_dir():
        for root, _d, files in os.walk(p):
            for fn in files:
                fp = os.path.join(root, fn)
                try:
                    text = open(fp, "r", encoding="utf-8", errors="replace").read()
                except OSError:
                    continue
                for tok in tokens:
                    if tok in text and ".agentwatch" not in fp:
                        hits.append((fp, tok))
    else:
        for ev in Ledger(args.target).read_all():
            blob = json.dumps(ev, ensure_ascii=True)
            for tok in tokens:
                if tok in blob:
                    hits.append(("ledger seq=%s" % ev.get("seq"), tok))
    if not hits:
        print("OK: no canary leakage into %s" % args.target)
        return 0
    print("CANARY LEAKED: %d hit(s)" % len(hits))
    for where, tok in hits[:20]:
        print("  %s -> %s (digest %s)" % (where, tok[:12] + "...", hash_bytes(tok.encode())[:12]))
    return 1


def cmd_otel_serve(args) -> int:
    from agentwatch.collectors.otel import make_server

    led = Ledger.init(args.ledger)
    print("OTLP/HTTP receiver on http://%s:%d (POST /v1/traces) -> ledger %s" % (args.host, args.port, led.path))
    print("point any OTel exporter's OTLP/HTTP endpoint here; Ctrl+C to stop")
    server = make_server(args.host, args.port, led)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="aw", description="AgentWatch: deterministic monitoring for agent swarms.")
    p.add_argument("--version", action="version", version="agentwatch %s" % __version__)
    sub = p.add_subparsers(dest="command", required=True)

    lp = sub.add_parser("ledger", help="ledger operations")
    lsub = lp.add_subparsers(dest="ledger_command", required=True)
    li = lsub.add_parser("init", help="create a ledger")
    li.add_argument("dir")
    li.set_defaults(func=cmd_ledger_init)
    lv = lsub.add_parser("verify", help="verify a ledger chain")
    lv.add_argument("dir")
    lv.add_argument("--anchor", default=None, help="head.json from `ledger anchor`")
    lv.set_defaults(func=cmd_ledger_verify)
    la = lsub.add_parser("anchor", help="write an anchor document for the chain head")
    la.add_argument("dir")
    la.add_argument("--out", default=None)
    la.set_defaults(func=cmd_ledger_anchor)

    sw = sub.add_parser("sweep", help="sweep a path or mailbox")
    sw.add_argument("target")
    sw.add_argument("--kind", choices=["fs", "mail"], default=None)
    sw.add_argument("--ledger", default=None, help="ledger directory to record into")
    sw.add_argument("--freeze", default=None, help="freeze manifest JSON (path -> sha256)")
    sw.add_argument("--rules-dir", default=None, help="YARA rules directory (default: rules/yara)")
    sw.add_argument("--sig-dir", default=None, help="signature DB directory (default: signatures/)")
    sw.add_argument("--no-live-av", action="store_true",
                    help="disable live external AV engines (Defender/ClamAV/YARA) for this sweep")
    sw.add_argument("--rule", default=None, help="only show findings for this rule id")
    sw.add_argument("--json", action="store_true")
    sw.add_argument(
        "--fail-on",
        choices=["none", "info", "low", "medium", "high", "critical"],
        default="none",
    )
    sw.set_defaults(func=cmd_sweep)

    rp = sub.add_parser("rule", help="rule registry")
    rsub = rp.add_subparsers(dest="rule_command", required=True)
    rl = rsub.add_parser("list", help="list rules")
    rl.set_defaults(func=cmd_rule_list)
    rt = rsub.add_parser("test", help="run a rule's falsifier ('all' for every rule)")
    rt.add_argument("rule")
    rt.set_defaults(func=cmd_rule_test)

    sv = sub.add_parser("serve", help="run the local dashboard/API")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8018)
    sv.add_argument("--ledger", default=None)
    sv.add_argument("--freeze", default=None)
    sv.add_argument("--rules-dir", default=None)
    sv.add_argument("--sig-dir", default=None)
    sv.add_argument("--open", action="store_true", help="open the dashboard in a browser")
    sv.set_defaults(func=cmd_serve)

    pp = sub.add_parser("probe", help="probe packs: run, score, review, freeze")
    psub = pp.add_subparsers(dest="probe_command", required=True)

    pl = psub.add_parser("list", help="list probes in a pack")
    pl.add_argument("pack")
    pl.add_argument("-v", "--verbose", action="store_true")
    pl.set_defaults(func=cmd_probe_list)

    pf = psub.add_parser("freeze", help="write the frozen sidecar for a pack")
    pf.add_argument("pack")
    pf.add_argument("--provenance", default=None)
    pf.set_defaults(func=cmd_probe_freeze)

    pv = psub.add_parser("verify", help="verify a pack against its frozen sidecar")
    pv.add_argument("pack")
    pv.set_defaults(func=cmd_probe_verify)

    pr = psub.add_parser("run", help="run a pack against a target")
    pr.add_argument("pack")
    pr.add_argument("--target-url", default=None, help="OpenAI-compatible base URL")
    pr.add_argument("--model", default=None)
    pr.add_argument("--api-key", default=None)
    pr.add_argument("--recorded", default=None, help="replay outputs from a transcripts file")
    pr.add_argument("--arm", default=None)
    pr.add_argument("--out", default=None)
    pr.add_argument("--ledger", default=None)
    pr.set_defaults(func=cmd_probe_run)

    ps = psub.add_parser("score", help="score one or more transcripts files")
    ps.add_argument("transcripts", nargs="+")
    ps.add_argument("--ref", default=None)
    ps.add_argument("--json", action="store_true")
    ps.set_defaults(func=cmd_probe_score)

    pv2 = psub.add_parser("review", help="emit a human-review sheet")
    pv2.add_argument("pack")
    pv2.add_argument("transcripts")
    pv2.set_defaults(func=cmd_probe_review)

    sn = sub.add_parser("snapshot", help="capture a runtime snapshot (baseline)")
    sn.add_argument("--out", default=None, help="write snapshot JSON here")
    sn.add_argument("--backend", choices=["auto", "psutil", "windows", "linux"], default="auto")
    sn.add_argument("--hash-images", action="store_true", help="sha256 each distinct process image (slower; enables AW-P006)")
    sn.add_argument("--json", action="store_true")
    sn.set_defaults(func=cmd_snapshot)

    po = sub.add_parser("posture", help="diff current host against a baseline")
    po.add_argument("--baseline", required=True)
    po.add_argument("--backend", choices=["auto", "psutil", "windows", "linux"], default="auto")
    po.add_argument("--ledger", default=None)
    po.add_argument("--allow-port", action="append", type=int, default=[])
    po.add_argument("--allow-process", action="append", default=[])
    po.add_argument("--include-loopback", action="store_true")
    po.add_argument("--scan-all", action="store_true", help="suspicion-check every process, not just new ones")
    po.add_argument("--force", action="store_true", help="diff even if baseline backend differs")
    po.add_argument("--hash-images", action="store_true", help="sha256 process images this pass (needs baseline taken the same way for AW-P006)")
    po.add_argument("--fail-on", choices=["none", "info", "low", "medium", "high", "critical"], default="none")
    po.add_argument("--json", action="store_true")
    po.set_defaults(func=cmd_posture)

    lw = lsub.add_parser("loops", help="detect repetitive action loops in the ledger")
    lw.add_argument("dir")
    lw.add_argument("--threshold", type=int, default=5)
    lw.add_argument("--window", type=int, default=200)
    lw.set_defaults(func=cmd_ledger_loops)

    cp = sub.add_parser("canary", help="canary tokens: deterministic exfil proof")
    csub = cp.add_subparsers(dest="canary_command", required=True)
    cpl = csub.add_parser("plant", help="plant canaries in a workspace")
    cpl.add_argument("workspace")
    cpl.add_argument("--count", type=int, default=3)
    cpl.set_defaults(func=cmd_canary_plant)
    cck = csub.add_parser("check", help="check a target dir or ledger for leaked canaries")
    cck.add_argument("target")
    cck.add_argument("--registry", required=True, help="canaries.json (or its workspace dir)")
    cck.set_defaults(func=cmd_canary_check)

    ot = sub.add_parser("otel", help="OTLP ingest receiver")
    osu = ot.add_subparsers(dest="otel_command", required=True)
    ose = osu.add_parser("serve", help="accept OTLP/HTTP traces into the ledger")
    ose.add_argument("--port", type=int, default=4318)
    ose.add_argument("--host", default="127.0.0.1")
    ose.add_argument("--ledger", required=True)
    ose.set_defaults(func=cmd_otel_serve)

    return p


def _configure_stdio() -> None:
    """Make console output survive non-cp1252 findings.

    Findings legitimately contain exotic code points (that is the point of
    AW-U004). A Windows console defaulting to cp1252 would crash on them, so
    stdout/stderr are pinned to utf-8 with backslashreplace as the floor.
    """
    for name in ("stdout", "stderr"):
        stream = getattr(sys, name, None)
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="backslashreplace")
            except Exception:
                pass


def main(argv: list | None = None) -> int:
    _configure_stdio()
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
