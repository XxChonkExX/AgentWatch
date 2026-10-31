import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import context  # noqa: F401

from agentwatch.probes.degen import channel_hit, judge, nonlatin_share, rep4, verdict  # noqa: E402

CLEAN = [
    "Rainbows appear when sunlight enters raindrops and bends into its component colors across the sky.",
    "A patient detective follows a cold trail through a foggy coastal town and finds the ledger hidden.",
    "Keeping a journal with a fixed morning hour builds the habit better than waiting for inspiration.",
    "The quiet forest path smelled of pine needles while the river murmured somewhere past the ridge.",
]


class Degen(unittest.TestCase):
    def test_rep4_high_on_repeat(self):
        self.assertGreater(rep4("the cat sat on the mat " * 20), 0.0)

    def test_rep4_none_when_short(self):
        self.assertIsNone(rep4("too short to score"))

    def test_channel_hit(self):
        self.assertTrue(channel_hit("output <|channel|> reasoning here"))
        self.assertFalse(channel_hit("plain answer"))

    def test_nonlatin(self):
        self.assertGreater(nonlatin_share("Привет как дела у тебя сегодня"), 0.25)

    def test_judge_clean_passes(self):
        j = judge(CLEAN)
        self.assertEqual(verdict(j), "passes gate")

    def test_judge_channel_trips(self):
        j = judge(["<|channel|> leaked"] * 10)
        self.assertTrue(j["channel_trip"])
        self.assertIn("NOT SCOREABLE", verdict(j))

    def test_judge_langmix_trips(self):
        j = judge(["Привет как дела у тебя сегодня друг"] * 12)
        self.assertTrue(j["langmix_trip"])


if __name__ == "__main__":
    unittest.main()
