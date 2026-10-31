import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import context  # noqa: F401
from awtest import art, ids  # noqa: E402

from agentwatch.detectors.unicode_gates import (  # noqa: E402
    ConfusableDetector,
    TagBlockDetector,
    VariationSelectorDetector,
    ZeroWidthDetector,
)


class ZeroWidth(unittest.TestCase):
    def test_zero_width_positive(self):
        findings = ZeroWidthDetector().run(art("note.txt", "hello\u200bworld"))
        self.assertIn("AW-U001", ids(findings))

    def test_zero_width_negative(self):
        self.assertEqual(ZeroWidthDetector().run(art("note.txt", "hello world")), [])


class TagBlock(unittest.TestCase):
    def test_tag_block_positive(self):
        hidden = "".join(chr(0xE0000 + ord(c)) for c in "secret")
        findings = TagBlockDetector().run(art("note.txt", "x" + hidden))
        self.assertIn("AW-U002", ids(findings))

    def test_tag_block_negative(self):
        self.assertEqual(TagBlockDetector().run(art("note.txt", "plain")), [])


class VariationSelector(unittest.TestCase):
    def test_variation_selector_positive(self):
        findings = VariationSelectorDetector().run(art("note.txt", "A\uFE00\uFE01B"))
        self.assertIn("AW-U003", ids(findings))

    def test_variation_selector_negative(self):
        self.assertEqual(VariationSelectorDetector().run(art("note.txt", "AB")), [])


class Confusable(unittest.TestCase):
    def test_confusable_positive(self):
        findings = ConfusableDetector().run(art("note.txt", "p\u0430ypal.com"))
        self.assertIn("AW-U004", ids(findings))

    def test_confusable_negative(self):
        self.assertEqual(ConfusableDetector().run(art("note.txt", "paypal.com")), [])

    def test_confusable_greek_math_negative(self):
        # Greek letters are ordinary math notation, not homoglyphs.
        self.assertEqual(ConfusableDetector().run(art("note.txt", "the \u0394PPL and \u03bbI terms")), [])


if __name__ == "__main__":
    unittest.main()
