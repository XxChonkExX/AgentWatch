import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import context  # noqa: F401

from agentwatch.collectors.fs import FsCollector  # noqa: E402
from agentwatch.core.engine import SweepEngine  # noqa: E402
from agentwatch.core.ledger import Ledger  # noqa: E402
from agentwatch.detectors.registry import build_detectors  # noqa: E402
from agentwatch.scoring import report as report_mod  # noqa: E402


def _make_dir():
    d = tempfile.mkdtemp()
    with open(os.path.join(d, "clean.txt"), "w", encoding="utf-8") as fh:
        fh.write("hello world\n")
    with open(os.path.join(d, "sneaky.txt"), "w", encoding="utf-8") as fh:
        fh.write("hidden\u200bchar")
    return d


class Engine(unittest.TestCase):
    def test_sweep_finds_and_reports(self):
        d = _make_dir()
        engine = SweepEngine(build_detectors())
        result = engine.sweep(FsCollector(), d)
        ids = [f.rule_id for f in result.findings]
        self.assertIn("AW-U001", ids)
        text = report_mod.render_text(result)
        self.assertIn("coverage & limits", text)
        self.assertIn("AW-U001", text)

    def test_sweep_records_ledger(self):
        d = _make_dir()
        led = Ledger.init(tempfile.mkdtemp())
        engine = SweepEngine(build_detectors(), ledger=led)
        engine.sweep(FsCollector(), d)
        ok, problems = led.verify()
        self.assertTrue(ok, problems)
        actions = [e["action"] for e in led.read_all()]
        self.assertIn("sweep_start", actions)
        self.assertIn("finding", actions)
        self.assertIn("sweep_end", actions)

    def test_report_json_shape(self):
        d = _make_dir()
        engine = SweepEngine(build_detectors())
        result = engine.sweep(FsCollector(), d)
        payload = report_mod.to_dict(result)
        self.assertIn("findings", payload)
        self.assertIn("counts", payload)
        self.assertIn("coverage_limits", payload)
        self.assertIn("scanner_status", payload)
        self.assertIn("builtin", payload["scanner_status"])


if __name__ == "__main__":
    unittest.main()
