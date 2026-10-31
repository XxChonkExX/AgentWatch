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
    "Words mixing Latin with Cyrillic or Greek letters, the shape of a look-alike "
    "domain, identifier, or keyword. Deterministic script-mix detection, not a judgement of intent.",
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
    AW_R001,
    AW_T001, AW_T002, AW_T003,
)

RULES: dict[str, Rule] = {r.rule_id: r for r in ALL_RULES}
