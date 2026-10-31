import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import context  # noqa: F401
from awtest import art, ids  # noqa: E402

from agentwatch.detectors.null_bytes import NullByteDetector  # noqa: E402


class NullBytes(unittest.TestCase):
    def test_nul_positive(self):
        findings = NullByteDetector().run(art("log.txt", b"before\x00after"))
        self.assertIn("AW-N001", ids(findings))

    def test_nul_negative_clean_text(self):
        self.assertEqual(NullByteDetector().run(art("log.txt", b"clean text")), [])

    def test_nul_negative_binary(self):
        # NULs in a declarately-binary file are normal.
        self.assertEqual(NullByteDetector().run(art("blob.bin", b"\x00\x01\x02")), [])


if __name__ == "__main__":
    unittest.main()
