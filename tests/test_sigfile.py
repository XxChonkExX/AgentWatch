import hashlib
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import context  # noqa: F401
from awtest import art  # noqa: E402

from agentwatch.scanners.sigfile import SigFileScanner  # noqa: E402

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


class SignatureFiles(unittest.TestCase):
    def test_hash_signature_positive(self):
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "ex.hdb"), "w", encoding="utf-8") as fh:
            fh.write("%s:%d:Eicar-Test\n" % (hashlib.md5(EICAR).hexdigest(), len(EICAR)))
        sc = SigFileScanner(d)
        self.assertTrue(sc.available())
        hits = sc.scan_bytes(EICAR, "sample.txt")
        self.assertTrue(any(h.signature == "Eicar-Test" and h.severity == "critical" for h in hits))

    def test_sha256_signature_positive(self):
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "ex.hsb"), "w", encoding="utf-8") as fh:
            fh.write("%s:%d:Sha-Test\n" % (hashlib.sha256(EICAR).hexdigest(), len(EICAR)))
        hits = SigFileScanner(d).scan_bytes(EICAR, "s.txt")
        self.assertTrue(any(h.signature == "Sha-Test" for h in hits))

    def test_hash_signature_negative(self):
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "ex.hdb"), "w", encoding="utf-8") as fh:
            fh.write("%s:68:Other\n" % ("0" * 32))
        self.assertEqual(SigFileScanner(d).scan_bytes(b"clean bytes", "x.txt"), [])

    def test_ndb_body_positive(self):
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "ex.ndb"), "w", encoding="utf-8") as fh:
            fh.write("Test.Sig:0:*:%s\n" % b"MALWAREMARKER".hex())
        hits = SigFileScanner(d).scan_bytes(b"..MALWAREMARKER..", "x.bin")
        self.assertTrue(any(h.signature == "Test.Sig" and h.severity == "high" for h in hits))

    def test_ndb_wildcard(self):
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "ex.ndb"), "w", encoding="utf-8") as fh:
            fh.write("Test.Wild:0:*:4d414c??415245\n")  # MAL?ARE (7 bytes)
        hits = SigFileScanner(d).scan_bytes(b"MALZARE", "x.bin")
        self.assertTrue(any(h.signature == "Test.Wild" for h in hits))

    def test_empty_dir_unavailable(self):
        d = tempfile.mkdtemp()
        sc = SigFileScanner(d)
        self.assertFalse(sc.available())
        self.assertEqual(sc.scan_bytes(b"anything", "x"), [])

    def test_detector_maps_to_m003(self):
        from agentwatch.scanners.detector import ScannerDetector

        d = tempfile.mkdtemp()
        with open(os.path.join(d, "ex.hdb"), "w", encoding="utf-8") as fh:
            fh.write("%s:%d:Eicar-Test\n" % (hashlib.md5(EICAR).hexdigest(), len(EICAR)))
        det = ScannerDetector(scanners=[SigFileScanner(d)])
        findings = det.run(art("sample.txt", EICAR))
        self.assertEqual(findings[0].rule_id, "AW-M003")


if __name__ == "__main__":
    unittest.main()
