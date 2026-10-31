import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import context  # noqa: F401

from agentwatch.core.hashing import hash_bytes  # noqa: E402
from agentwatch.detectors.frozen_guard import FrozenGuardDetector  # noqa: E402


class FrozenGuard(unittest.TestCase):
    def test_frozen_positive(self):
        target = os.path.abspath("frozen_preregistration.md")
        manifest = {target: hash_bytes(b"original contents")}
        from awtest import art

        artifact = art(
            "frozen_preregistration.md",
            b"tampered contents",
            path=target,
        )
        findings = FrozenGuardDetector(manifest).run(artifact)
        self.assertEqual([f.rule_id for f in findings], ["AW-R001"])
        self.assertEqual(findings[0].severity, "critical")

    def test_frozen_negative_when_matching(self):
        target = os.path.abspath("frozen.md")
        payload = b"frozen contents"
        manifest = {target: hash_bytes(payload)}
        from awtest import art

        artifact = art("frozen.md", payload, path=target)
        self.assertEqual(FrozenGuardDetector(manifest).run(artifact), [])

    def test_frozen_negative_when_untracked(self):
        from awtest import art

        manifest = {os.path.abspath("other.md"): hash_bytes(b"x")}
        artifact = art("free.md", b"anything")
        self.assertEqual(FrozenGuardDetector(manifest).run(artifact), [])


if __name__ == "__main__":
    unittest.main()
