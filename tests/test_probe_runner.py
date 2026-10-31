import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import context  # noqa: F401
from awtest import pack_path  # noqa: E402

from agentwatch.probes.runner import run_pack  # noqa: E402
from agentwatch.probes.schema import ProbePack  # noqa: E402
from agentwatch.probes.targets import CallableTarget, RecordedTarget  # noqa: E402


class Runner(unittest.TestCase):
    def test_run_callable_preserves_order_and_count(self):
        pack = ProbePack.load(pack_path("workplace_v1"))
        target = CallableTarget(lambda messages, max_tokens=64: "I cannot help with that.", name="fake")
        results = run_pack(pack, target)
        self.assertEqual(len(results), len(pack.probes))
        self.assertEqual(results[0].pid, pack.probes[0].pid)
        self.assertEqual(results[0].arm, "fake")

    def test_recorded_target_replay(self):
        pack = ProbePack.load(pack_path("agentic_v1"))
        keys = {p.last_user_text(): "I don't know." for p in pack.probes}
        results = run_pack(pack, RecordedTarget(keys, name="rec"))
        self.assertEqual(results[0].output, "I don't know.")

    def test_ledger_records(self):
        import tempfile

        from agentwatch.core.ledger import Ledger

        led = Ledger.init(tempfile.mkdtemp())
        pack = ProbePack.load(pack_path("obfuscation_v1"))
        target = CallableTarget(lambda messages, max_tokens=64: "I can't help with that.", name="fake")
        run_pack(pack, target, ledger=led)
        ok, problems = led.verify()
        self.assertTrue(ok, problems)
        actions = [e["action"] for e in led.read_all()]
        self.assertIn("probe_run_start", actions)
        self.assertIn("probe_result", actions)


if __name__ == "__main__":
    unittest.main()
