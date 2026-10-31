import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import context  # noqa: F401

from agentwatch.core import canary  # noqa: E402
from agentwatch.core.loops import detect_loops  # noqa: E402
from agentwatch.core.ledger import Ledger  # noqa: E402
from agentwatch.collectors.otel import otlp_json_to_events, make_server  # noqa: E402


class Canary(unittest.TestCase):
    def test_canary_detected(self):
        d = tempfile.mkdtemp()
        reg = canary.plant(d, count=2)
        tokens = canary.registry_tokens(reg)
        self.assertEqual(len(tokens), 2)
        # the canary "leaked" into another file
        leak = os.path.join(d, "elsewhere.md")
        with open(leak, "w", encoding="utf-8") as fh:
            fh.write("here is the key: " + tokens[0] + "\n")
        self.assertIn(tokens[0], open(leak, encoding="utf-8").read())

    def test_digest_does_not_leak_token(self):
        token = canary.make_canary()
        blob = json.dumps(canary.canary_digest(token, b"k"))
        self.assertNotIn(token, blob)

    def test_registry_digest_verification(self):
        d = tempfile.mkdtemp()
        reg = canary.plant(d, count=1)
        tokens = canary.registry_tokens(reg)
        # tampered registry (wrong digest) yields no tokens
        reg["canaries"][0]["digest"] = "0" * 24
        self.assertEqual(canary.registry_tokens(reg), [])


class LedgerLoops(unittest.TestCase):
    def test_loop_detected(self):
        led = Ledger.init(tempfile.mkdtemp())
        for _ in range(6):
            led.append({"action": "write", "target": "same.txt"})
        led.append({"action": "write", "target": "other.txt"})
        findings = detect_loops(list(led.read_all()))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "AW-P007")
        self.assertIn("x6", findings[0].detail)

    def test_distinct_actions_not_a_loop(self):
        led = Ledger.init(tempfile.mkdtemp())
        for i in range(6):
            led.append({"action": "write", "target": "f%d.txt" % i})
        self.assertEqual(detect_loops(list(led.read_all())), [])

    def test_threshold(self):
        led = Ledger.init(tempfile.mkdtemp())
        for _ in range(4):
            led.append({"action": "read", "target": "same.txt"})
        self.assertEqual(detect_loops(list(led.read_all()), threshold=5), [])
        self.assertEqual(len(detect_loops(list(led.read_all()), threshold=4)), 1)


class OtlpIngest(unittest.TestCase):
    BODY = {
        "resourceSpans": [{
            "resource": {"attributes": [{"key": "service.name",
                                          "value": {"stringValue": "my-swarm"}}]},
            "scopeSpans": [{
                "spans": [{
                    "name": "chat qwen2.5",
                    "trace_id": "abc", "span_id": "def",
                    "time_unix_nano": 1730000000000000000,
                    "attributes": [
                        {"key": "gen_ai.request.model", "value": {"stringValue": "qwen2.5-1.5b"}},
                        {"key": "gen_ai.prompt", "value": {"stringValue": "hello world"}},
                    ],
                }],
            }],
        }],
    }

    def test_mapping(self):
        events = otlp_json_to_events(self.BODY)
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev["agent_id"], "my-swarm")
        self.assertEqual(ev["model"], "qwen2.5-1.5b")
        self.assertEqual(ev["action"], "span")
        self.assertEqual(ev["ts"], "2024-10-27T03:33:20Z")

    def test_receiver_writes_ledger(self):
        led = Ledger.init(tempfile.mkdtemp())
        server = make_server("127.0.0.1", 0, led)
        port = server.server_address[1]
        import threading

        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        try:
            from urllib import request

            req = request.Request(
                "http://127.0.0.1:%d/v1/traces" % port,
                data=json.dumps(self.BODY).encode(),
                headers={"Content-Type": "application/json"},
            )
            with request.urlopen(req, timeout=5) as resp:
                self.assertEqual(resp.status, 200)
        finally:
            server.shutdown()
        records = list(led.read_all())
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["agent_id"], "my-swarm")
        ok, problems = led.verify()
        self.assertTrue(ok, problems)


if __name__ == "__main__":
    unittest.main()
