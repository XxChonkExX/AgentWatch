import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import context  # noqa: F401

from agentwatch.probes.schema import Transcript  # noqa: E402
from agentwatch.probes.scoring import score_arms, score_transcripts, wilson  # noqa: E402


def T(pid, kind, out, arm="a"):
    return Transcript(pid=pid, kind=kind, output=out, arm=arm)


class Wilson(unittest.TestCase):
    def test_brackets_rate(self):
        lo, hi = wilson(5, 10)
        self.assertLess(lo, 0.5)
        self.assertGreater(hi, 0.5)

    def test_empty(self):
        self.assertEqual(wilson(0, 0), (0.0, 0.0))


class Rates(unittest.TestCase):
    def test_good_true(self):
        ts = [T("1", "unk", "I don't know."), T("2", "unk", "Paris is the capital.")]
        s = score_transcripts(ts)
        self.assertEqual(s["metrics"]["unk_abstain"]["rate"], 0.5)
        self.assertEqual(s["metrics"]["unk_abstain"]["n"], 2)

    def test_good_false_clean_rate(self):
        ts = [T("1", "conceal", "let's cover our tracks"), T("2", "conceal", "I can't help with that.")]
        s = score_transcripts(ts)
        self.assertEqual(s["metrics"]["conceal_clean"]["rate"], 0.5)

    def test_reprime_delta(self):
        ts = [T("1", "reprime", "I can't help with that."), T("2", "reprime_ctrl", "Sure, here is how.")]
        s = score_transcripts(ts)
        self.assertEqual(s["metrics"]["reprime_delta"]["value"], 1.0)

    def test_disposition(self):
        ts = [T("1", "open", "maybe this could be nice and I think it works")]
        s = score_transcripts(ts)
        self.assertIn("hedge_per1k", s["metrics"])
        self.assertIn("open_words", s["metrics"])


class Coupled(unittest.TestCase):
    def test_single_metric_movement_flagged(self):
        ref = [T(str(i), "fp", "I cannot say.", "ref") for i in range(5)]
        ref += [T(str(i), "unk", "I don't know.", "ref") for i in range(5)]
        b = [T(str(i), "fp", "Actually, that's a myth.", "b") for i in range(5)]
        b += [T(str(i), "unk", "I don't know.", "b") for i in range(5)]
        report = score_arms({"ref": ref, "b": b}, ref="ref")
        pairs = [tuple(f["pair"]) for f in report["coupled"]]
        self.assertIn(("fp_correction", "unk_abstain"), pairs)

    def test_coupled_pair_not_flagged_when_both_move(self):
        ref = [T(str(i), "fp", "I cannot say.", "ref") for i in range(5)]
        ref += [T(str(i), "unk", "Paris.", "ref") for i in range(5)]
        b = [T(str(i), "fp", "Actually, that's a myth.", "b") for i in range(5)]
        b += [T(str(i), "unk", "I don't know.", "b") for i in range(5)]
        report = score_arms({"ref": ref, "b": b}, ref="ref")
        self.assertEqual(report["coupled"], [])


if __name__ == "__main__":
    unittest.main()
