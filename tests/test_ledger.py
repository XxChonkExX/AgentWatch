import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import context  # noqa: F401

from agentwatch.core.ledger import Ledger  # noqa: E402


class LedgerChain(unittest.TestCase):
    def test_append_and_verify(self):
        d = tempfile.mkdtemp()
        led = Ledger.init(d)
        led.append({"action": "read", "target": "a"})
        led.append({"action": "finding", "rule_id": "AW-U001"})
        ok, problems = led.verify()
        self.assertTrue(ok, problems)
        self.assertEqual(len(problems), 0)
        records = list(led.read_all())
        self.assertEqual([r["seq"] for r in records], [1, 2])
        self.assertEqual(records[1]["prev"], records[0]["hash"])

    def test_tamper_detected(self):
        d = tempfile.mkdtemp()
        led = Ledger.init(d)
        led.append({"action": "read", "target": "a"})
        led.append({"action": "read", "target": "b"})
        # Edit the first record's content without recomputing hashes.
        with open(led.path, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
        rec = json.loads(lines[0])
        rec["target"] = "tampered"
        lines[0] = json.dumps(rec, sort_keys=True, separators=(",", ":")) + "\n"
        with open(led.path, "w", encoding="utf-8", newline="\n") as fh:
            fh.writelines(lines)
        ok, problems = led.verify()
        self.assertFalse(ok)
        self.assertTrue(problems)

    def test_reordering_detected(self):
        d = tempfile.mkdtemp()
        led = Ledger.init(d)
        for i in range(3):
            led.append({"action": "read", "target": str(i)})
        with open(led.path, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
        lines = [lines[1], lines[0], lines[2]]
        with open(led.path, "w", encoding="utf-8", newline="\n") as fh:
            fh.writelines(lines)
        ok, problems = led.verify()
        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()
