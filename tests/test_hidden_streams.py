import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import context  # noqa: F401

from agentwatch.collectors.fs import FsCollector  # noqa: E402
from agentwatch.detectors.hidden_streams import AlternateStreamDetector  # noqa: E402


class AlternateStreams(unittest.TestCase):
    def test_no_streams_no_finding(self):
        # An artifact with no recorded streams never fires.
        from awtest import art

        self.assertEqual(AlternateStreamDetector().run(art("plain.txt", "data")), [])

    def test_meta_streams_fire(self):
        from awtest import art, ids

        findings = AlternateStreamDetector().run(art("host.txt", "data", streams=[":secret:$DATA"]))
        self.assertIn("AW-F001", ids(findings))

    @unittest.skipUnless(os.name == "nt", "NTFS alternate data streams are Windows-only")
    def test_ads_positive_on_disk(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "host.txt")
        with open(p, "w", encoding="utf-8") as fh:
            fh.write("visible")
        with open(p + ":secret", "w", encoding="utf-8") as fh:
            fh.write("hidden payload")
        artifacts = list(FsCollector().collect(p))
        self.assertEqual(len(artifacts), 1)
        findings = AlternateStreamDetector().run(artifacts[0])
        self.assertTrue(any(f.rule_id == "AW-F001" for f in findings))


if __name__ == "__main__":
    unittest.main()
