"""Frozen rule identities for the M0 detector pack.

Every Lane-A gate names itself here. rule.version is a content hash of the
gate's identity, so a finding recorded today can be matched against the rule
as it stood when the finding was made -- even after the description is
improved. Change a gate's meaning and the version moves with it.

Severity ladder (frozen): info < low < medium < high < critical.
"""

from __future__ import annotations

from dataclasses import replace

from ..core.hashing import hash_obj, short
from ..core.schema import LANE_DETERMINISTIC, Rule


def _rule(rule_id: str, severity: str, title: str, description: str, falsifier: str) -> Rule:
    base = Rule(
        rule_id=rule_id,
        lane=LANE_DETERMINISTIC,
        severity=severity,
        title=title,
        description=description,
        falsifier=falsifier,
    )
    version = short(
        hash_obj(
            {
                "rule_id": rule_id,
                "lane": LANE_DETERMINISTIC,
                "severity": severity,
                "title": title,
                "description": description,
            }
        )
    )
    return replace(base, version=version)


AW_U001 = _rule(
    "AW-U001", "medium",
    "Zero-width / bidi format characters",
    "Invisible Unicode format characters (zero-width space/joiner, bidi overrides, "
    "word joiner, soft hyphen) embedded in text. Used to smuggle hidden content, "
    "break tokenisation, or hide instructions in plain sight.",
    "tests/test_unicode_gates.py::test_zero_width_positive",
)
AW_U002 = _rule(
    "AW-U002", "high",
    "Unicode tag-block characters",
    "Invisible tag-block code points (U+E0000-U+E007F) that encode a hidden ASCII "
    "message inside otherwise normal text. A canonical invisible-instruction channel.",
    "tests/test_unicode_gates.py::test_tag_block_positive",
)
AW_U003 = _rule(
    "AW-U003", "low",
    "Variation-selector smuggling",
    "Runs of Unicode variation selectors, which can carry a few bits per glyph and "
    "are commonly used to hide payloads. Benign in isolation; suspicious in runs.",
    "tests/test_unicode_gates.py::test_variation_selector_positive",
)
AW_U004 = _rule(
    "AW-U004", "medium",
    "Homoglyph / mixed-script confusables",
    "Latin words with an embedded Cyrillic letter: the look-alike-identifier "
    "attack. Greek is excluded because Greek letters are ordinary mathematical "
    "notation in research text and were the dominant false positive on the "
    "first real corpus. Deterministic script-mix detection, not intent.",
    "tests/test_unicode_gates.py::test_confusable_positive",
)
AW_N001 = _rule(
    "AW-N001", "medium",
    "NUL bytes in a text file",
    "A file with a text extension (or single-byte encoding) that contains NUL bytes. "
    "The pattern of injection, truncation, and content-type confusion.",
    "tests/test_null_bytes.py::test_nul_positive",
)
AW_F001 = _rule(
    "AW-F001", "medium",
    "NTFS alternate data streams",
    "One or more non-default NTFS streams attached to a file. A standard hiding place "
    "for data that does not show up in a normal directory listing.",
    "tests/test_hidden_streams.py::test_ads_positive",
)
AW_F002 = _rule(
    "AW-F002", "medium",
    "High-entropy or encoded blob",
    "High Shannon entropy in a file that is not expected to hold compressed or "
    "encrypted bytes, or a long base64/hex blob in text. The shape of packed, "
    "encrypted, or embedded payloads.",
    "tests/test_entropy_blob.py::test_entropy_positive",
)
AW_F003 = _rule(
    "AW-F003", "high",
    "Magic-byte mismatch or double extension",
    "The file's leading bytes disagree with its name, or the name carries a decoy "
    "extension in front of an executable/script extension. Executable magic in a "
    "document is escalated to critical in the finding.",
    "tests/test_magic_mismatch.py::test_magic_positive",
)
AW_S001 = _rule(
    "AW-S001", "medium",
    "Script obfuscation / execution markers",
    "Deterministic markers of script-based execution and obfuscation: encoded "
    "PowerShell, FromBase64String, IEX, certutil -decode, download-pipe-to-shell, "
    "Defender tampering, and similar. Markers are signals for review, not proof.",
    "tests/test_script_obfuscation.py::test_obfuscation_positive",
)
AW_C001 = _rule(
    "AW-C001", "low",
    "Covert whitespace channel",
    "Whitespace used as a carrier: heavy trailing-whitespace patterns, long internal "
    "space/tab runs, or exotic Unicode spaces. Low severity -- legitimate formatting "
    "exists -- but it is stable evidence when it repeats.",
    "tests/test_covert_channel.py::test_trailing_positive",
)
AW_M001 = _rule(
    "AW-M001", "critical",
    "Builtin signature match",
    "A byte pattern in the builtin signature table (EICAR, webshell markers, "
    "reverse-shell markers, miner markers). High-signal and deterministic, "
    "but a small curated set, not a substitute for a full antivirus.",
    "tests/test_scanners.py::test_builtin_eicar_positive",
)
AW_M002 = _rule(
    "AW-M002", "critical",
    "External scanner signature match",
    "A match from a bridged external scanner (ClamAV or YARA). The scanner and "
    "its signature-set version are recorded per hit so the match is "
    "reproducible against the same signatures.",
    "tests/test_scanners.py::test_external_scanner_wiring",
)
AW_M003 = _rule(
    "AW-M003", "critical",
    "Signature-file match",
    "A match against a loaded open-format signature database (ClamAV .hdb/.hsb/"
    ".ndb dropped into signatures/). Hash signatures are critical; body "
    "signatures are high. The database fingerprint and counts are recorded per "
    "hit so a match is reproducible against the same signatures.",
    "tests/test_sigfile.py::test_hash_signature_positive",
)
AW_P001 = _rule(
    "AW-P001", "medium",
    "New listening port",
    "A port is listening now that was not listening in the baseline snapshot: a "
    "network-facing service appeared. A bind on all interfaces (0.0.0.0 / ::) "
    "escalates to high; a risky well-known port also escalates.",
    "tests/test_runtime.py::test_new_listener",
)
AW_P002 = _rule(
    "AW-P002", "low",
    "New outbound connection",
    "An established connection to a remote endpoint not present in the baseline. "
    "Egress appeared. Loopback is ignored by default; enable with --include-loopback.",
    "tests/test_runtime.py::test_new_egress",
)
AW_P003 = _rule(
    "AW-P003", "low",
    "New process not in baseline",
    "A running process whose identity (executable path, else name) was not in the "
    "baseline snapshot. Low severity: new processes are the normal state of a "
    "working machine. It is a review queue, not an alarm.",
    "tests/test_runtime.py::test_new_process",
)
AW_P004 = _rule(
    "AW-P004", "high",
    "Suspicious process characteristics",
    "A running process whose executable or command line carries deterministic "
    "risk markers: execution from a temp/user-writable path, a LOLBin paired "
    "with an obfuscation flag, or encoded/quiet execution markers.",
    "tests/test_runtime.py::test_suspicious_process",
)
AW_P005 = _rule(
    "AW-P005", "high",
    "New kernel driver or module",
    "A kernel driver (Windows) or module (Linux) is loaded that was not in the "
    "baseline snapshot. Kernel-level change is high severity by nature.",
    "tests/test_runtime.py::test_new_driver",
)
AW_P006 = _rule(
    "AW-P006", "high",
    "Process image changed",
    "A process identity (executable path) existed in both snapshots but the "
    "on-disk image hash differs: the binary was replaced. Requires both "
    "snapshots to have been taken with image hashing enabled.",
    "tests/test_runtime.py::test_changed_image",
)
AW_R001 = _rule(
    "AW-R001", "critical",
    "Frozen record mutated",
    "A file whose hash was pinned in a freeze manifest no longer matches. The one "
    "control the program may never relax (MODEL_ONBOARDING section 3).",
    "tests/test_frozen_guard.py::test_frozen_positive",
)
AW_T001 = _rule(
    "AW-T001", "medium",
    "Thinking / containment leak tokens",
    "Channel and self-correction tokens (channel tags, thought tags, self-correction, "
    "toggle-content, conditional-leak phrasing) appearing in visible text. Planning "
    "and reasoning content escaping into the response channel.",
    "tests/test_thinking_gate.py::test_leak_positive",
)
AW_T002 = _rule(
    "AW-T002", "medium",
    "Prompt-injection / override markers",
    "Lexical markers of instruction override in scanned text: 'ignore previous "
    "instructions', role reassignment, injected system role, jailbreak markers, "
    "exfiltration phrasing. Deterministic pattern; may fire on quoted examples.",
    "tests/test_thinking_gate.py::test_injection_positive",
)
AW_T003 = _rule(
    "AW-T003", "medium",
    "Concealment / unauthorized-intent markers",
    "Language of concealment and out-of-scope action in scanned text: covering "
    "tracks, hiding from the operator, bypassing guards, disabling logging, "
    "privilege escalation, persistence. The lexical shadow of the failure mode "
    "MODEL_ONBOARDING section 6 describes.",
    "tests/test_thinking_gate.py::test_intent_positive",
)


ALL_RULES: tuple[Rule, ...] = (
    AW_U001, AW_U002, AW_U003, AW_U004,
    AW_N001,
    AW_F001, AW_F002, AW_F003,
    AW_S001,
    AW_C001,
    AW_M001, AW_M002, AW_M003,
    AW_P001, AW_P002, AW_P003, AW_P004, AW_P005, AW_P006,
    AW_R001,
    AW_T001, AW_T002, AW_T003,
)

RULES: dict[str, Rule] = {r.rule_id: r for r in ALL_RULES}
