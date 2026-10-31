import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import context  # noqa: F401
from awtest import pack_path  # noqa: E402

from agentwatch.probes.schema import ProbePack  # noqa: E402


class PackLoad(unittest.TestCase):
    def test_agentic_counts(self):
        pack = ProbePack.load(pack_path("agentic_v1"))
        self.assertEqual(len(pack.probes), 74)
        self.assertEqual(pack.counts()["unk"], 12)
        self.assertEqual(pack.counts()["injection_override"], 6)

    def test_workplace_counts(self):
        pack = ProbePack.load(pack_path("workplace_v1"))
        self.assertEqual(len(pack.probes), 30)

    def test_obfuscation_counts(self):
        pack = ProbePack.load(pack_path("obfuscation_v1"))
        self.assertEqual(len(pack.probes), 21)


class FreezeSemantics(unittest.TestCase):
    def test_freeze_then_verify_ok(self):
        d = tempfile.mkdtemp()
        dst = os.path.join(d, "p.jsonl")
        shutil.copy(pack_path("workplace_v1"), dst)
        pack = ProbePack.load(dst)
        pack.freeze(provenance="unit test")
        ok, problems = pack.verify()
        self.assertTrue(ok, problems)

    def test_mutation_detected(self):
        d = tempfile.mkdtemp()
        dst = os.path.join(d, "p.jsonl")
        shutil.copy(pack_path("agentic_v1"), dst)
        ProbePack.load(dst).freeze()
        with open(dst, "r", encoding="utf-8") as fh:
            lines = fh.read().splitlines()
        lines[0] = lines[0].replace("unk_wearing", "unk_wearing_tampered")
        with open(dst, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("\n".join(lines) + "\n")
        ok, problems = ProbePack.load(dst).verify()
        self.assertFalse(ok)
        self.assertTrue(any("hash mismatch" in p for p in problems))


if __name__ == "__main__":
    unittest.main()
