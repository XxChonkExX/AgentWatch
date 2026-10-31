import contextlib
import io
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import context  # noqa: F401
from awtest import pack_path  # noqa: E402

from agentwatch.cli.main import main  # noqa: E402


class Cli(unittest.TestCase):
    def test_ledger_init_verify(self):
        d = tempfile.mkdtemp()
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertEqual(main(["ledger", "init", d]), 0)
            self.assertEqual(main(["ledger", "verify", d]), 0)
        self.assertIn("OK", buf.getvalue())

    def test_rule_list(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertEqual(main(["rule", "list"]), 0)
        self.assertIn("AW-U001", buf.getvalue())

    def test_rule_falsifier(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(["rule", "test", "AW-U001"])
        self.assertEqual(rc, 0)

    def test_sweep_fail_on(self):
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "a.txt"), "w", encoding="utf-8") as fh:
            fh.write("x\u200by")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(["sweep", d, "--fail-on", "medium", "--no-live-av"])
        self.assertEqual(rc, 1)
        self.assertIn("AW-U001", buf.getvalue())

    def test_sweep_clean_exit_zero(self):
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "a.txt"), "w", encoding="utf-8") as fh:
            fh.write("nothing to see here\n")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(["sweep", d, "--fail-on", "medium", "--no-live-av"])
        self.assertEqual(rc, 0)

    def test_probe_list(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(["probe", "list", "agentic_v1"])
        self.assertEqual(rc, 0)
        self.assertIn("sha256", buf.getvalue())

    def test_probe_freeze_and_verify(self):
        import shutil

        d = tempfile.mkdtemp()
        dst = os.path.join(d, "p.jsonl")
        shutil.copy(pack_path("workplace_v1"), dst)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertEqual(main(["probe", "freeze", dst]), 0)
            self.assertEqual(main(["probe", "verify", dst]), 0)
        self.assertIn("OK", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
