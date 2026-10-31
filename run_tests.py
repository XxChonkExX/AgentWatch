#!/usr/bin/env python3
"""Run the AgentWatch test suite with no third-party dependencies.

    python run_tests.py

Equivalent to `python -m unittest discover -s tests` with src/ on the path.
"""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, os.path.join(ROOT, "tests"))

if __name__ == "__main__":
    suite = unittest.TestLoader().discover(os.path.join(ROOT, "tests"))
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)
