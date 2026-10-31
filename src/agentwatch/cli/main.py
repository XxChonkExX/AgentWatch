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
        return 0
    print("TAMPERED: %d problem(s)" % len(problems))
    for p in problems:
        print("  " + p)
    return 1


def _default_rules_dir(args) -> str | None:
    if getattr(args, "rules_dir", None):
        return args.rules_dir
    candidate = _repo_root() / "rules" / "yara"
    return str(candidate) if candidate.is_dir() else None


def cmd_sweep(args) -> int:
    freeze = load_manifest(args.freeze) if args.freeze else None
    detectors = build_detectors(freeze, rules_dir=_default_rules_dir(args))
    ledger = Ledger(args.ledger) if args.ledger else None
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
    )
    uvicorn.run(app, host=args.host, port=args.port)
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
    lv.set_defaults(func=cmd_ledger_verify)

    sw = sub.add_parser("sweep", help="sweep a path or mailbox")
    sw.add_argument("target")
    sw.add_argument("--kind", choices=["fs", "mail"], default=None)
    sw.add_argument("--ledger", default=None, help="ledger directory to record into")
    sw.add_argument("--freeze", default=None, help="freeze manifest JSON (path -> sha256)")
    sw.add_argument("--rules-dir", default=None, help="YARA rules directory (default: rules/yara)")
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
    sv.set_defaults(func=cmd_serve)

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
