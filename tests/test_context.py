import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import context  # noqa: F401

from agentwatch.detectors.context import classify, downgrade  # noqa: E402


class Context(unittest.TestCase):
    def test_quoted_backtick(self):
        t = "see `<|channel>thought` in the log"
        i = t.index("<|channel")
        self.assertEqual(classify(t, i, i + 10), "quoted")

    def test_quoted_double(self):
        t = 'the reviewer said "<|channel>thought" loudly'
        i = t.index("<|channel")
        self.assertEqual(classify(t, i, i + 10), "quoted")

    def test_fenced_code(self):
        t = "intro\n```\ncover your tracks\n```\nend"
        i = t.index("cover")
        self.assertEqual(classify(t, i, i + 5), "quoted")

    def test_technical_line(self):
        t = "the model emits <|channel> in its chat_template output"
        i = t.index("<|channel")
        self.assertEqual(classify(t, i, i + 10), "technical")

    def test_plain_line(self):
        t = "I will now proceed with the operation"
        i = t.index("proceed")
        self.assertEqual(classify(t, i, i + 7), "")

    def test_downgrade(self):
        self.assertEqual(downgrade("medium"), "low")
        self.assertEqual(downgrade("info"), "info")


if __name__ == "__main__":
    unittest.main()
