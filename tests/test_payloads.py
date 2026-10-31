import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import context  # noqa: F401

from agentwatch.api import payloads  # noqa: E402
from agentwatch.core.ledger import Ledger  # noqa: E402
from agentwatch.probes.schema import Transcript, write_transcripts  # noqa: E402


class Health(unittest.TestCase):
    def test_shape(self):
        p = payloads.health_payload()
        self.assertEqual(p["status"], "ok")
        self.assertGreater(p["rules"], 0)


class Rules(unittest.TestCase):
    def test_sorted_with_falsifier(self):
        rules = payloads.rules_payload()
        self.assertTrue(all(r["falsifier"] for r in rules))
        self.assertEqual([r["rule_id"] for r in rules], sorted(r["rule_id"] for r in rules))


class Packs(unittest.TestCase):
    def test_three_frozen_packs(self):
        packs = payloads.packs_payload()
        names = {p["name"] for p in packs}
        self.assertTrue({"agentic_v1", "workplace_v1", "obfuscation_v1"} <= names)
        for p in packs:
            if "error" not in p:
                self.assertTrue(p["frozen"], p["name"])


class LedgerRecent(unittest.TestCase):
    def test_recent_and_chain(self):
        d = tempfile.mkdtemp()
        led = Ledger.init(d)
        for i in range(5):
            led.append({"action": "read", "target": str(i)})
        p = payloads.ledger_recent_payload(d, limit=3)
        self.assertTrue(p["chain_ok"])
        self.assertEqual(p["total"], 5)
        self.assertEqual(len(p["records"]), 3)
        self.assertEqual(p["records"][0]["seq"], 5)  # newest first

    def test_tamper_reported(self):
        d = tempfile.mkdtemp()
        led = Ledger.init(d)
        led.append({"action": "read", "target": "a"})
        path = led.path
        with open(path, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
        rec = json.loads(lines[0])
        rec["target"] = "tampered"
        lines[0] = json.dumps(rec, sort_keys=True, separators=(",", ":")) + "\n"
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.writelines(lines)
        p = payloads.ledger_recent_payload(d)
        self.assertFalse(p["chain_ok"])


class ProbePayloads(unittest.TestCase):
    def _transcripts(self, arm, pid="1", kind="unk", output="I don't know."):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "t_%s.jsonl" % arm)
        ts = [Transcript(pid=pid, kind=kind, output=output, arm=arm)]
        write_transcripts(path, ts)
        return path

    def test_score(self):
        p = payloads.probe_score_payload([self._transcripts("a")])
        self.assertEqual(p["reference"], "a")
        self.assertEqual(p["arms"]["a"]["metrics"]["unk_abstain"]["rate"], 1.0)

    def test_review(self):
        path = self._transcripts("a", pid="hr_oversell_forecast", kind="hr_oversell",
                                 output="I cannot commit to that by tomorrow.")
        p = payloads.review_payload("workplace_v1", path)
        self.assertIn("review sheet", p["sheet"].lower())
        self.assertIn("operator verdict", p["sheet"].lower())
        self.assertEqual(p["n"], 1)

    def test_run_requires_target(self):
        # probe_run_payload with an unroutable target fails on request, not import.
        with self.assertRaises(Exception):
            payloads.probe_run_payload("workplace_v1", "http://127.0.0.1:1", model="x", limit=1)


class PostureGuard(unittest.TestCase):
    def test_backend_mismatch_reported(self):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "base.json")
        from agentwatch.runtime.schema import RuntimeSnapshot

        with open(path, "w", encoding="utf-8") as fh:
            json.dump(RuntimeSnapshot(host="x", ts="t", backend="psutil").to_dict(), fh)
        p = payloads.posture_payload(path, backend="linux")
        self.assertIn("error", p)


if __name__ == "__main__":
    unittest.main()
