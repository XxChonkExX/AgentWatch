import base64
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import context  # noqa: F401
from awtest import art, ids  # noqa: E402

from agentwatch.detectors.entropy_blob import EntropyBlobDetector, shannon_entropy  # noqa: E402


class EntropyBlob(unittest.TestCase):
    def test_entropy_positive(self):
        findings = EntropyBlobDetector().run(art("data.txt", os.urandom(1024)))
        self.assertIn("AW-F002", ids(findings))

    def test_entropy_negative_low(self):
        self.assertEqual(EntropyBlobDetector().run(art("data.txt", "a" * 1024)), [])

    def test_entropy_negative_binary_ext(self):
        # High entropy in a .zip is expected and not reported.
        self.assertEqual(EntropyBlobDetector().run(art("archive.zip", os.urandom(1024))), [])

    def test_base64_positive(self):
        blob = base64.b64encode(b"The quick brown fox jumps over the lazy dog. " * 20).decode()
        findings = EntropyBlobDetector().run(art("data.txt", blob))
        self.assertIn("AW-F002", ids(findings))

    def test_base64_negative_repeated_char(self):
        # "a" * 1024 is valid base64 alphabet but has no alphabet diversity.
        self.assertEqual(EntropyBlobDetector().run(art("data.txt", "a" * 1024)), [])

    def test_entropy_math(self):
        self.assertAlmostEqual(shannon_entropy(b"AAAA"), 0.0, places=6)


if __name__ == "__main__":
    unittest.main()
