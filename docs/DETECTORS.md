# Detector pack (M0)

All rules are Lane A: deterministic functions of artifact bytes. Each rule
names its severity, the falsifier test that proves it still fires, and the
data it acts on. Rule versions are content hashes of the rule identity, so a
finding recorded today can be matched against the rule as it stood when the
finding was made.

| rule | lane | severity | detects | acts on | falsifier |
|---|---|---|---|---|---|
| AW-U001 | A | medium | zero-width / bidi format characters | `text` | `tests/test_unicode_gates.py::test_zero_width_positive` |
| AW-U002 | A | high | Unicode tag-block smuggling (U+E0000-U+E007F) | `text` | `tests/test_unicode_gates.py::test_tag_block_positive` |
| AW-U003 | A | low | variation-selector smuggling | `text` | `tests/test_unicode_gates.py::test_variation_selector_positive` |
| AW-U004 | A | medium | homoglyph / mixed-script confusables | `text` | `tests/test_unicode_gates.py::test_confusable_positive` |
| AW-N001 | A | medium | NUL bytes in a text file | `sample`, `ext` | `tests/test_null_bytes.py::test_nul_positive` |
| AW-F001 | A | medium | NTFS alternate data streams | `meta.streams` | `tests/test_hidden_streams.py::test_ads_positive` |
| AW-F002 | A | medium | high-entropy / encoded blobs | `sample`, `text`, `ext` | `tests/test_entropy_blob.py::test_entropy_positive` |
| AW-F003 | A | high | magic-byte mismatch / double extension | `sample`, `name`, `ext` | `tests/test_magic_mismatch.py::test_magic_positive` |
| AW-S001 | A | medium | script obfuscation / execution markers | `text` | `tests/test_script_obfuscation.py::test_obfuscation_positive` |
| AW-C001 | A | low | covert whitespace channel | `text` | `tests/test_covert_channel.py::test_trailing_positive` |
| AW-R001 | A | critical | frozen record mutated | `manifest`, `sha256` | `tests/test_frozen_guard.py::test_frozen_positive` |
| AW-T001 | A | medium | thinking / containment leak tokens | `text` | `tests/test_thinking_gate.py::test_leak_positive` |
| AW-T002 | A | medium | prompt-injection / override markers | `text` | `tests/test_thinking_gate.py::test_injection_positive` |
| AW-T003 | A | medium | concealment / unauthorized-intent markers | `text` | `tests/test_thinking_gate.py::test_intent_positive` |

## Frozen thresholds

- Entropy: Shannon entropy > 7.5 bits/byte over >= 256 bytes, excluding files
  with binary/compressed extensions.
- Encoded blobs: base64 runs >= 80 chars; hex runs >= 80 chars.
- Covert whitespace: >= 5 lines with trailing whitespace and >= 40 trailing
  chars total; >= 3 internal runs of 8+ spaces/tabs; >= 3 exotic Unicode spaces.
- Sample cap: 4 MiB per artifact (bytes beyond the cap are hashed but not
  pattern-scanned).

## Known false-positive sources (stated, not hidden)

- AW-S001 and AW-T001/2/3 are lexical. They fire on documents that discuss or
  quote the behaviour (a malware report, a security test suite, a transcript
  of an attack). The finding is a signal for review.
- AW-F002 fires on any high-entropy small file without a binary extension.
  Encrypted or compressed content with a misleading name is exactly what it
  is for; random test data with a `.txt` name will also fire.
- AW-U004 (confusables) fires on any word mixing Latin with Cyrillic or Greek,
  including legitimate multilingual text.

## Coverage gaps (M0)

See the `coverage & limits` block in every report. In brief: no runtime
activity (process/port/network/exec), no NTFS stream content, no anchoring of
the ledger against full-file rewrite, no lane-B classifier.

## Roadmap for the pack

- ScannerBridge: ClamAV + YARA + Defender/AMSI as wrapped integrations.
- Probe-pack port: the Crucible batteries extended to agentic behaviours
  (tool-scope-creep, exfiltration intent, self-preservation, unrequested
  mutation, sandbox-escape attempts), scored with n and coupled-metric gates.
- Runtime detectors: process/port/device diffs, egress, capability exposure.
- Lane-B advisories: local classifier for triage priority, model-stamped.
