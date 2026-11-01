"""Falsifiers for the CI workflow files themselves.

A workflow that GitHub cannot parse reports zero jobs and no log, which looks
like a silent pass in a status list. These tests are cheap structural checks,
not a YAML validator: they catch the two mistakes that actually happened here.

1. `${{ matrix.X }}` referencing a key the matrix does not define.
2. A list literal where a step input expects a scalar (setup-python's
   `python-version` is one version per job; the versions belong in the matrix).
"""

from __future__ import annotations

import os
import re
import unittest

WORKFLOW_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".github", "workflows"
)


def _workflows() -> list[tuple[str, str]]:
    if not os.path.isdir(WORKFLOW_DIR):
        return []
    out = []
    for name in sorted(os.listdir(WORKFLOW_DIR)):
        if name.endswith((".yml", ".yaml")):
            with open(os.path.join(WORKFLOW_DIR, name), "r", encoding="utf-8") as fh:
                out.append((name, fh.read()))
    return out


def _matrix_keys(text: str) -> set[str]:
    keys: set[str] = set()
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if line.strip() != "matrix:":
            continue
        indent = len(line) - len(line.lstrip())
        for nxt in lines[i + 1 :]:
            if not nxt.strip():
                continue
            cur = len(nxt) - len(nxt.lstrip())
            if cur <= indent:
                break
            m = re.match(r"\s+([A-Za-z0-9_-]+):", nxt)
            if m:
                keys.add(m.group(1))
    return keys


def _enclosing_keys(lines: list[str], idx: int) -> list[str]:
    """Keys of the blocks enclosing line `idx`, innermost first."""
    chain: list[str] = []
    limit = len(lines[idx]) - len(lines[idx].lstrip())
    for line in reversed(lines[:idx]):
        if not line.strip():
            continue
        ind = len(line) - len(line.lstrip())
        if ind >= limit:
            continue
        m = re.match(r"\s*([A-Za-z0-9_$-]+):", line)
        if m:
            chain.append(m.group(1))
        limit = ind
    return chain


class Workflows(unittest.TestCase):
    def test_workflow_dir_present(self):
        self.assertTrue(_workflows(), "no workflow files found; CI would never run")

    def test_matrix_references_are_defined(self):
        for name, text in _workflows():
            keys = _matrix_keys(text)
            refs = set(re.findall(r"matrix\.([A-Za-z0-9_-]+)", text))
            missing = refs - keys
            self.assertFalse(
                missing,
                "%s references undefined matrix key(s): %s (defined: %s)"
                % (name, sorted(missing), sorted(keys)),
            )

    def test_no_list_where_scalar_expected(self):
        pat = re.compile(r"python-version:\s*\[")
        for name, text in _workflows():
            lines = text.splitlines()
            for i, line in enumerate(lines):
                if not pat.search(line):
                    continue
                # A list is correct inside the matrix, wrong inside a step's
                # `with:` block, where setup-python takes one version.
                if "matrix" in _enclosing_keys(lines, i):
                    continue
                self.fail(
                    "%s:%d: python-version must be a scalar; put the list in the "
                    "matrix and reference ${{ matrix.python-version }}"
                    % (name, i + 1)
                )

    def test_top_level_keys(self):
        for name, text in _workflows():
            for key in ("name:", "on:", "jobs:"):
                self.assertIn(
                    "\n" + key, "\n" + text, "%s is missing a top-level %r" % (name, key)
                )


if __name__ == "__main__":
    unittest.main()
