import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import context  # noqa: F401
from awtest import art, ids  # noqa: E402

from agentwatch.scanners.base import ScanHit, Scanner  # noqa: E402
from agentwatch.scanners.detector import ScannerDetector  # noqa: E402
from agentwatch.scanners.signatures import EICAR  # noqa: E402


class Builtin(unittest.TestCase):
    def test_builtin_eicar_positive(self):
        findings = ScannerDetector(live_av=False).run(art("sample.txt", b"prefix " + EICAR + b" suffix"))
        self.assertIn("AW-M001", ids(findings))

    def test_builtin_negative(self):
        self.assertEqual(ScannerDetector(live_av=False).run(art("clean.txt", b"hello world")), [])

    def test_webshell_marker_positive(self):
        findings = ScannerDetector(live_av=False).run(art("shell.php", b"<?php eval($_POST['x']); ?>"))
        self.assertIn("AW-M001", ids(findings))


class FakeScanner(Scanner):
    name = "fake"

    def available(self):
        return True

    def version(self):
        return "fake-1"

    def scan_bytes(self, data, name):
        if b"BOOM" in data:
            return [ScanHit(self.name, "fake.sig", "critical", "fake hit", "fake-1")]
        return []


class UnavailableScanner(Scanner):
    name = "ghost"

    def available(self):
        return False

    def scan_bytes(self, data, name):
        raise AssertionError("unavailable scanner must not be called")


class Wiring(unittest.TestCase):
    def test_external_scanner_wiring(self):
        findings = ScannerDetector(scanners=[FakeScanner()]).run(art("x.bin", b"BOOM"))
        self.assertEqual([f.rule_id for f in findings], ["AW-M002"])
        self.assertEqual(findings[0].severity, "critical")

    def test_unavailable_no_hits_and_status(self):
        det = ScannerDetector(scanners=[UnavailableScanner()])
        self.assertEqual(det.run(art("x.bin", b"BOOM")), [])
        self.assertFalse(det.status()["ghost"]["available"])

    def test_status_reports_builtin(self):
        self.assertTrue(ScannerDetector(live_av=False).status()["builtin"]["available"])

    def test_live_av_disabled_means_external_engines_off(self):
        st = ScannerDetector(live_av=False).status()
        self.assertFalse(st["defender"]["available"])
        self.assertFalse(st["clamav"]["available"])
        self.assertFalse(st["yara"]["available"])
        self.assertTrue(st["builtin"]["available"])


if __name__ == "__main__":
    unittest.main()
