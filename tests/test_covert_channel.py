import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import context  # noqa: F401
from awtest import art, ids  # noqa: E402

from agentwatch.detectors.covert_channel import CovertWhitespaceDetector  # noqa: E402


class CovertWhitespace(unittest.TestCase):
    def test_trailing_positive(self):
        text = "\n".join("line %d          " % i for i in range(8))
        findings = CovertWhitespaceDetector().run(art("notes.txt", text))
        self.assertIn("AW-C001", ids(findings))

    def test_unicode_space_positive(self):
        text = "a\u00a0b\u2003c\u3000d"
        findings = CovertWhitespaceDetector().run(art("notes.txt", text))
        self.assertIn("AW-C001", ids(findings))

    def test_whitespace_negative(self):
        self.assertEqual(CovertWhitespaceDetector().run(art("notes.txt", "clean\nlines\nhere")), [])

    def test_markdown_hard_break_negative(self):
        # Two trailing spaces is the CommonMark hard line break, not a channel.
        text = "\n".join("line %d  " % i for i in range(10))
        self.assertEqual(CovertWhitespaceDetector().run(art("notes.md", text)), [])

    def test_internal_run_formatting_negative(self):
        # 8-space runs are ordinary alignment, not a covert channel.
        text = "col A        col B        col C        col D"
        self.assertEqual(CovertWhitespaceDetector().run(art("table.md", text)), [])

    def test_internal_run_channel_positive(self):
        text = ("x" + " " * 20 + "y\n") * 6
        self.assertIn("AW-C001", ids(CovertWhitespaceDetector().run(art("t.txt", text))))


if __name__ == "__main__":
    unittest.main()
