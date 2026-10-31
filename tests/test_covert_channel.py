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


if __name__ == "__main__":
    unittest.main()
