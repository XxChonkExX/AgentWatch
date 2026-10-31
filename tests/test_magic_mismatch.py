import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import context  # noqa: F401
from awtest import art, ids  # noqa: E402

from agentwatch.detectors.magic_mismatch import MagicMismatchDetector  # noqa: E402


class MagicMismatch(unittest.TestCase):
    def test_magic_positive(self):
        findings = MagicMismatchDetector().run(art("invoice.pdf", b"MZ" + b"\x00" * 128))
        self.assertIn("AW-F003", ids(findings))
        self.assertEqual(findings[0].severity, "critical")

    def test_double_extension_positive(self):
        findings = MagicMismatchDetector().run(art("photo.jpg.exe", b"hello world"))
        hits = [f for f in findings if f.severity == "high"]
        self.assertTrue(hits)

    def test_shebang_low(self):
        findings = MagicMismatchDetector().run(art("notes.txt", b"#!/bin/sh\n"))
        self.assertIn("AW-F003", ids(findings))

    def test_magic_negative(self):
        self.assertEqual(MagicMismatchDetector().run(art("readme.txt", "plain text")), [])


if __name__ == "__main__":
    unittest.main()
