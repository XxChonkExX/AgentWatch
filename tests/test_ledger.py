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


class Segmentation(unittest.TestCase):
    def test_rotation_and_cross_segment_chain(self):
        d = tempfile.mkdtemp()
        led = Ledger.init(d)
        for i in range(1005):
            led.append({"action": "read", "target": str(i)})
        ok, problems = led.verify()
        self.assertTrue(ok, problems)
        self.assertEqual(sum(1 for _ in led.read_all()), 1005)
        # at least two segment files
        segs = [p for p in os.listdir(d) if p.startswith("ledger_") and p.endswith(".jsonl")]
        self.assertGreaterEqual(len(segs), 2)
        # get works across segments
        self.assertEqual(led.get(1)["target"], "0")
        self.assertEqual(led.get(1005)["target"], "1004")
        self.assertEqual(led.get(1000)["target"], "999")
        self.assertIsNone(led.get(1006))
        self.assertIsNone(led.get(0))

    def test_segments_are_arithmetic(self):
        d = tempfile.mkdtemp()
        led = Ledger.init(d)
        for i in range(1001):
            led.append({"action": "read", "target": str(i)})
        self.assertEqual(
            sorted(p for p in os.listdir(d) if p.startswith("ledger_")),
            ["ledger_000000.jsonl", "ledger_000001.jsonl"],
        )
        self.assertEqual(sum(1 for _ in open(os.path.join(d, "ledger_000000.jsonl"))), 1000)
        self.assertEqual(sum(1 for _ in open(os.path.join(d, "ledger_000001.jsonl"))), 1)

    def test_head_index_used(self):
        d = tempfile.mkdtemp()
        led = Ledger.init(d)
        led.append({"action": "read", "target": "a"})
        # head.json exists and matches
        import json
        head = json.loads(open(os.path.join(d, "head.json")).read())
        self.assertEqual(head["seq"], 1)
        self.assertEqual(set(head), {"seq", "hash"})
        # _last via head
        self.assertEqual(led._last(), (1, head["hash"]))

    def test_tail_deletion_detected(self):
        # The chain alone cannot see a truncated tail; the head index can.
        d = tempfile.mkdtemp()
        led = Ledger.init(d)
        for i in range(1002):
            led.append({"action": "read", "target": str(i)})
        os.remove(os.path.join(d, "ledger_000001.jsonl"))
        ok, problems = led.verify()
        self.assertFalse(ok)
        self.assertTrue(any("truncated" in p for p in problems), problems)

    def test_misplaced_record_detected(self):
        d = tempfile.mkdtemp()
        led = Ledger.init(d)
        for i in range(1002):
            led.append({"action": "read", "target": str(i)})
        # Move seq=1001 into the wrong segment file; the chain links still hold.
        seg0 = os.path.join(d, "ledger_000000.jsonl")
        seg1 = os.path.join(d, "ledger_000001.jsonl")
        with open(seg1, "r", encoding="utf-8") as fh:
            line = fh.readline()
        with open(seg1, "w", encoding="utf-8", newline="\n") as fh:
            pass
        with open(seg0, "a", encoding="utf-8", newline="\n") as fh:
            fh.write(line)
        ok, problems = led.verify()
        self.assertFalse(ok)
        self.assertTrue(any("belongs in segment" in p for p in problems), problems)

    def test_missing_ledger_is_not_a_pass(self):
        d = tempfile.mkdtemp()
        ok, problems = Ledger(d).verify()
        self.assertFalse(ok)
        self.assertTrue(any("no ledger segments" in p for p in problems), problems)


class Anchoring(unittest.TestCase):
    def test_anchor_round_trip(self):
        d = tempfile.mkdtemp()
        led = Ledger.init(d)
        for i in range(3):
            led.append({"action": "read", "target": str(i)})
        anchor = led.anchor_head()
        self.assertEqual(anchor["seq"], 3)
        self.assertEqual(anchor["records"], 3)
        ok, problems = led.verify_anchor(anchor)
        self.assertTrue(ok, problems)

        # Later records do not invalidate an anchor of an earlier head.
        led.append({"action": "read", "target": "later"})
        ok, problems = led.verify_anchor(anchor)
        self.assertTrue(ok, problems)

    def test_anchor_detects_rewritten_chain(self):
        d = tempfile.mkdtemp()
        led = Ledger.init(d)
        for i in range(3):
            led.append({"action": "read", "target": str(i)})
        anchor = led.anchor_head()

        # A different, internally consistent chain: same length, other content.
        other = Ledger.init(tempfile.mkdtemp())
        for i in range(3):
            other.append({"action": "read", "target": "rewritten-%d" % i})
        ok, problems = other.verify_anchor(anchor)
        self.assertFalse(ok, "a rewritten chain must not match the anchor")
        self.assertTrue(any("anchor mismatch" in p for p in problems), problems)

    def test_anchor_detects_truncation(self):
        d = tempfile.mkdtemp()
        led = Ledger.init(d)
        for i in range(3):
            led.append({"action": "read", "target": str(i)})
        anchor = led.anchor_head()

        # Drop the tail and rewrite the head index to match: the chain is a
        # valid prefix, so only the anchor can see the loss.
        seg = os.path.join(d, "ledger_000000.jsonl")
        with open(seg, "r", encoding="utf-8") as fh:
            lines = fh.readlines()[:2]
        with open(seg, "w", encoding="utf-8", newline="\n") as fh:
            fh.writelines(lines)
        with open(os.path.join(d, "head.json"), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(json.dumps({"seq": 2, "hash": json.loads(lines[-1])["hash"]}, sort_keys=True) + "\n")

        self.assertTrue(led.verify()[0], "the truncated prefix is internally valid")
        ok, problems = led.verify_anchor(anchor)
        self.assertFalse(ok)
        self.assertTrue(any("truncated" in p for p in problems), problems)

    def test_anchor_cli_does_not_clobber_head_index(self):
        import contextlib
        import io

        from agentwatch.cli.main import cmd_ledger_anchor

        d = tempfile.mkdtemp()
        led = Ledger.init(d)
        led.append({"action": "read", "target": "a"})
        args = type("A", (), {"dir": d, "out": None})()
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cmd_ledger_anchor(args), 0)
        head = json.loads(open(os.path.join(d, "head.json"), encoding="utf-8").read())
        self.assertEqual(set(head), {"seq", "hash"})
        anchors = os.listdir(os.path.join(d, "anchors"))
        self.assertEqual(anchors, ["anchor_seq000001.json"])
        doc = json.loads(open(os.path.join(d, "anchors", anchors[0]), encoding="utf-8").read())
        self.assertEqual(doc["seq"], 1)
        self.assertIn("anchored_utc", doc)
        # ledger still verifies after writing the anchor
        ok, problems = led.verify()
        self.assertTrue(ok, problems)


def _append_worker(spec):
    """Module-level so it can be pickled by the spawn start method."""
    d, n, tag = spec
    from agentwatch.core.ledger import Ledger

    led = Ledger(d)
    for i in range(n):
        led.append({"action": "read", "target": "%s-%d" % (tag, i)})


class Concurrency(unittest.TestCase):
    def test_parallel_appends_keep_one_chain(self):
        import multiprocessing as mp

        d = tempfile.mkdtemp()
        Ledger.init(d)
        specs = [(d, 20, "w%d" % i) for i in range(4)]
        ctx = mp.get_context("spawn")
        with ctx.Pool(len(specs)) as pool:
            pool.map(_append_worker, specs)

        led = Ledger(d)
        ok, problems = led.verify()
        self.assertTrue(ok, problems)
        seqs = [r["seq"] for r in led.read_all()]
        self.assertEqual(seqs, list(range(1, 81)))
        self.assertEqual(led.anchor_head()["records"], 80)


if __name__ == "__main__":
    unittest.main()
