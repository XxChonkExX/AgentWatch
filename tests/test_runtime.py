import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import context  # noqa: F401

from agentwatch.runtime.schema import (  # noqa: E402
    ConnInfo,
    DriverInfo,
    ListenerInfo,
    ProcessInfo,
    RuntimeSnapshot,
)
from agentwatch.runtime.diff import diff_snapshots  # noqa: E402
from agentwatch.runtime.posture import analyze, suspicious_reasons  # noqa: E402
from agentwatch.runtime.collect import parse_proc_net, parse_proc_modules, parse_ps_jsonl  # noqa: E402


def snap(processes=(), listeners=(), connections=(), drivers=()):
    return RuntimeSnapshot(
        host="test", ts="2026-10-31T00:00:00Z", backend="synthetic",
        processes=tuple(processes), listeners=tuple(listeners),
        connections=tuple(connections), drivers=tuple(drivers),
    )


def P(pid, name, exe="", cmdline="", ppid=0):
    return ProcessInfo(pid=pid, ppid=ppid, name=name, exe=exe, cmdline=cmdline)


def ids(findings):
    return [f.rule_id for f in findings]


class Diff(unittest.TestCase):
    def test_new_process_detected(self):
        self.test_new_process = None
        base = snap(processes=[P(1, "a.exe", "C:/a.exe")])
        cur = snap(processes=[P(1, "a.exe", "C:/a.exe"), P(2, "b.exe", "C:/b.exe")])
        d = diff_snapshots(base, cur)
        self.assertEqual(d["counts"]["added_processes"], 1)
        self.assertEqual(d["added_processes"][0].name, "b.exe")

    def test_removal_detected(self):
        base = snap(processes=[P(1, "a.exe", "C:/a.exe"), P(2, "b.exe", "C:/b.exe")])
        cur = snap(processes=[P(1, "a.exe", "C:/a.exe")])
        d = diff_snapshots(base, cur)
        self.assertEqual(d["counts"]["removed_processes"], 1)

    def test_identity_case_and_slashes(self):
        base = snap(processes=[P(1, "a.exe", "C:\\Tools\\a.exe")])
        cur = snap(processes=[P(9, "a.exe", "c:/tools/A.exe")])
        d = diff_snapshots(base, cur)
        self.assertEqual(d["counts"]["added_processes"], 0)


class Posture(unittest.TestCase):
    def test_new_listener(self):
        base = snap(listeners=[ListenerInfo("tcp", "127.0.0.1", 80)])
        cur = snap(listeners=[ListenerInfo("tcp", "127.0.0.1", 80), ListenerInfo("tcp", "0.0.0.0", 9999)])
        f = analyze(diff_snapshots(base, cur), cur)
        self.assertIn("AW-P001", ids(f))
        hits = [x for x in f if x.rule_id == "AW-P001"]
        self.assertEqual(hits[0].severity, "high")  # binds all interfaces

    def test_loopback_listener_stays_medium(self):
        cur = snap(listeners=[ListenerInfo("tcp", "127.0.0.1", 8123)])
        f = analyze(diff_snapshots(snap(), cur), cur)
        self.assertEqual([x.severity for x in f if x.rule_id == "AW-P001"], ["medium"])

    def test_allow_port(self):
        cur = snap(listeners=[ListenerInfo("tcp", "127.0.0.1", 8123)])
        f = analyze(diff_snapshots(snap(), cur), cur, allow_ports=[8123])
        self.assertEqual(ids(f), [])

    def test_new_egress(self):
        cur = snap(connections=[ConnInfo("tcp", "10.0.0.2", 5000, "93.184.216.34", 443, "ESTABLISHED", 1)])
        f = analyze(diff_snapshots(snap(), cur), cur)
        self.assertIn("AW-P002", ids(f))

    def test_loopback_egress_ignored(self):
        cur = snap(connections=[ConnInfo("tcp", "127.0.0.1", 5000, "127.0.0.1", 8123, "ESTABLISHED", 1)])
        f = analyze(diff_snapshots(snap(), cur), cur)
        self.assertNotIn("AW-P002", ids(f))

    def test_new_process(self):
        cur = snap(processes=[P(7, "newtool.exe", "C:/tools/newtool.exe")])
        f = analyze(diff_snapshots(snap(), cur), cur)
        self.assertIn("AW-P003", ids(f))

    def test_suspicious_process(self):
        cur = snap(processes=[P(8, "evil.exe", "C:/Users/x/AppData/Local/Temp/evil.exe")])
        f = analyze(diff_snapshots(snap(), cur), cur)
        self.assertIn("AW-P004", ids(f))
        self.assertEqual([x.severity for x in f if x.rule_id == "AW-P004"], ["high"])

    def test_lolbin_obfuscation(self):
        cur = snap(processes=[P(9, "powershell.exe", "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
                                cmdline="powershell -nop -w hidden -enc SQBFAFgA")])
        f = analyze(diff_snapshots(snap(), cur), cur)
        self.assertIn("AW-P004", ids(f))

    def test_clean_process_not_suspicious(self):
        self.assertEqual(suspicious_reasons(P(1, "notepad.exe", "C:/Windows/notepad.exe", "notepad notes.txt")), [])

    def test_new_driver(self):
        cur = snap(drivers=[DriverInfo("evil_drv", "C:/Windows/System32/drivers/evil.sys", "Running")])
        f = analyze(diff_snapshots(snap(), cur), cur)
        self.assertIn("AW-P005", ids(f))
        self.assertEqual([x.severity for x in f if x.rule_id == "AW-P005"], ["high"])


class Serialization(unittest.TestCase):
    def test_roundtrip(self):
        s = snap(
            processes=[P(1, "a.exe", "C:/a.exe", "a --x")],
            listeners=[ListenerInfo("tcp", "0.0.0.0", 80, 1)],
            connections=[ConnInfo("tcp", "10.0.0.1", 5, "1.2.3.4", 443, "ESTABLISHED", 1)],
            drivers=[DriverInfo("d1", "C:/d.sys", "Running")],
        )
        s2 = RuntimeSnapshot.from_dict(json.loads(json.dumps(s.to_dict())))
        self.assertEqual(s.hash(), s2.hash())


class Ipv6Decode(unittest.TestCase):
    def test_loopback(self):
        from agentwatch.runtime.collect import _decode_ipv6

        self.assertEqual(_decode_ipv6("00000000000000000000000001000000"), "0000:0000:0000:0000:0000:0000:0000:0001")

    def test_unspecified(self):
        from agentwatch.runtime.collect import _decode_ipv6

        self.assertEqual(_decode_ipv6("0" * 32), "0000:0000:0000:0000:0000:0000:0000:0000")


class ImageHash(unittest.TestCase):
    def test_changed_image(self):
        import dataclasses

        base = snap(processes=[dataclasses.replace(P(1, "svc.exe", "C:/bin/svc.exe"), image_sha256="a" * 64)])
        cur = snap(processes=[ProcessInfo(2, 0, "svc.exe", "C:/bin/svc.exe", "", "b" * 64)])
        d = diff_snapshots(base, cur)
        self.assertEqual(len(d["changed_images"]), 1)
        f = analyze(d, cur)
        self.assertIn("AW-P006", ids(f))
        self.assertEqual([x.severity for x in f if x.rule_id == "AW-P006"], ["high"])

    def test_same_image_no_finding(self):
        p1 = ProcessInfo(1, 0, "svc.exe", "C:/bin/svc.exe", "", "a" * 64)
        p2 = ProcessInfo(2, 0, "svc.exe", "C:/bin/svc.exe", "", "a" * 64)
        f = analyze(diff_snapshots(snap(processes=[p1]), snap(processes=[p2])), snap(processes=[p2]))
        self.assertNotIn("AW-P006", ids(f))

    def test_serialization_with_image_hash(self):
        s = snap(processes=[ProcessInfo(1, 0, "a.exe", "C:/a.exe", "", "c" * 64)])
        s2 = RuntimeSnapshot.from_dict(json.loads(json.dumps(s.to_dict())))
        self.assertEqual(s.hash(), s2.hash())

    def test_old_baseline_still_loads(self):
        d = {"host": "x", "ts": "t", "backend": "b",
             "processes": [{"pid": 1, "ppid": 0, "name": "a.exe", "exe": "", "cmdline": ""}],
             "listeners": [], "connections": [], "drivers": [], "meta": {}}
        s = RuntimeSnapshot.from_dict(d)
        self.assertEqual(s.processes[0].image_sha256, "")


class DefenderBridge(unittest.TestCase):
    def test_unavailable_without_binary(self):
        from agentwatch.scanners.defender import DefenderScanner

        self.assertFalse(DefenderScanner(binary=r"C:\nope\MpCmdRun.exe").available())

    def test_in_default_pack(self):
        from agentwatch.scanners.detector import ScannerDetector

        names = [s.name for s in ScannerDetector().scanners]
        self.assertIn("defender", names)


class LedgerAnchor(unittest.TestCase):
    def test_anchor_and_verify(self):
        from agentwatch.core.ledger import Ledger

        d = tempfile.mkdtemp()
        led = Ledger.init(d)
        for i in range(3):
            led.append({"action": "read", "target": str(i)})
        doc = led.anchor_head()
        self.assertEqual(doc["seq"], 3)
        ok, problems = led.verify_anchor(doc)
        self.assertTrue(ok, problems)

    def test_truncation_detected(self):
        from agentwatch.core.ledger import Ledger

        d = tempfile.mkdtemp()
        led = Ledger.init(d)
        for i in range(3):
            led.append({"action": "read", "target": str(i)})
        doc = led.anchor_head()
        with open(led.path, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
        with open(led.path, "w", encoding="utf-8", newline="\n") as fh:
            fh.writelines(lines[:2])  # drop the anchored record
        ok, problems = led.verify_anchor(doc)
        self.assertFalse(ok)
        self.assertTrue(any("truncated" in p for p in problems))


class BackendGuard(unittest.TestCase):
    def test_mismatch_refused(self):
        from agentwatch.cli.main import main
        import io, contextlib

        d = tempfile.mkdtemp()
        base = RuntimeSnapshot(host="x", ts="t", backend="psutil")
        path = os.path.join(d, "base.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(base.to_dict(), fh)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(["posture", "--baseline", path, "--backend", "linux"])
        self.assertEqual(rc, 2)
        self.assertIn("backend mismatch", buf.getvalue())


class LinuxParsers(unittest.TestCase):
    TCP4 = (
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        "   0: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1\n"
        "   1: 00000000:001B 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2 1\n"
        "   2: 0200010A:9C40 5ED9B8D2:01BB 01 00000000:00000000 00:00000000 00000000     0        0 3 1\n"
    )

    def test_parse_listeners_and_conns(self):
        listeners, conns = parse_proc_net(self.TCP4, "tcp", is_v6=False)
        self.assertEqual([(x.addr, x.port) for x in listeners],
                         [("127.0.0.1", 53), ("0.0.0.0", 27)])
        self.assertEqual(len(conns), 1)
        self.assertEqual(conns[0].remote_addr, "210.184.217.94")
        self.assertEqual(conns[0].remote_port, 443)

    def test_udp_all_are_listeners(self):
        text = ("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
                "   0: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 9 1\n")
        listeners, conns = parse_proc_net(text, "udp", is_v6=False)
        self.assertEqual(len(listeners), 1)
        self.assertEqual(listeners[0].port, 53)
        self.assertEqual(conns, [])

    def test_modules(self):
        drivers = parse_proc_modules("veth 16384 0 - Live 0x0000000000000000\n")
        self.assertEqual(drivers[0].name, "veth")


class WindowsParsers(unittest.TestCase):
    def test_parse_ps_jsonl(self):
        rows = parse_ps_jsonl('{"pid": 4, "name": "System"}\n\n{"pid": 123, "name": "x"}\n')
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["pid"], 4)

    def test_parse_ps_jsonl_ignores_garbage(self):
        self.assertEqual(parse_ps_jsonl("not json\n{\"pid\": 1}\n"), [{"pid": 1}])


if __name__ == "__main__":
    unittest.main()
