# The AgentWatch method

Adapted from the Crucible method (`crucible/METHOD.md`). Hypothesize,
instrument, measure, verdict. Every claim names the thing that can falsify
it. Negative results are results.

## The two-lane rule

The whole design reduces to one distinction.

**Lane A is deterministic.** A Lane-A finding is a function of the bytes it
was shown. Run the sweep twice and the finding is identical, byte for byte.
It carries:

- a rule id (`AW-F003`),
- a rule-version hash (a content hash of the gate's identity),
- a falsifier (a test that fails if the gate stops working),
- evidence with offsets and excerpt hashes.

Lane A may condemn: it may trip a hard control, quarantine a file, or fail a
pipeline.

**Lane B is advisory.** A Lane-B signal comes from a classifier or an
embedding and is therefore not reproducible in the way a hash is. It is
stamped with the model, parameters, temperature, and seed that produced it.
It may only rank and route work to a human. It may never be the reason a
control fires.

The failure this prevents is the one the alignment work already documents:
a model under measurement pressure learns to look aligned without being
aligned, and a scorer that only sees content does not see the degeneration.
AgentWatch does not let a probabilistic signal hold the gavel.

## Physical-engineering standard

A number without its method, its n, and its author is an anecdote that
survived long enough to be believed.

- **Sign your work.** Every rule names its id, version, and falsifier.
- **Nothing ships without a way to fail.** Each gate has a positive and a
  negative fixture; the ledger has a tamper test.
- **Report what the instrument cannot see.** Every report carries a coverage
  and limits section. A clean report from an instrument with unstated blind
  spots is an unsafe statement.
- **Hash the whole thing, not a prefix.** File identity is a full-content
  SHA-256. Prefix equality is a hypothesis, not a finding.
- **Frozen is frozen.** A record marked frozen, pinned, or preregistered is
  never edited. AW-R001 exists so an agent cannot quietly rewrite the record
  it is measured against. This is the one control that never relaxes.

## The record

The ledger is append-only and hash-chained. Each record's hash covers the
record before it, so any edit, deletion, or reorder breaks the chain at a
named sequence number. Records live in bounded segment files
(`ledger_000000.jsonl`, 1000 records each); the segment for a sequence number
is arithmetic, so append and lookup stay flat as the ledger grows. A
`head.json` sidecar caches the tail and is checked against the actual tail on
every append.

What the ledger guarantees and what it does not:

- It guarantees that a change to a ledger *segment* is detectable, including a
  deleted tail (the head index notices a chain that ends early).
- It does not guarantee anything against an attacker who rewrites every
  segment and the head together. That requires an external anchor.

Anchoring is implemented (`aw ledger anchor`, `aw ledger verify --anchor`). An
anchor stored on the same host as the ledger is defeated by the same attacker,
so the anchor is only load-bearing when it is copied somewhere the ledger host
cannot reach. The two-box runbook is in
[docs/THREAT_MODEL.md](THREAT_MODEL.md#operationalizing-the-anchor).

## What AgentWatch does not do

- It does not conclude intent. It reports observations and ranks them.
- It does not run a model to decide whether an agent behaved. Advisories are
  optional, off by default, and never load-bearing.
- It does not phone home. No network egress from the core.
- It does not replace a virus scanner. ScannerBridge (next milestone) is a
  bridge to ClamAV/YARA, not a homegrown engine.

## Adding a rule

1. Write the gate. Keep it a function of artifact bytes.
2. Register it in `detectors/rules.py` with a severity and a falsifier path.
3. Add a positive and a negative fixture in `tests/`.
4. Run `python run_tests.py` and `aw rule test <id>`.
5. If it is lexical, state in the rule description that it may fire on quoted
   examples. That is a known false-positive source, not a hidden one.
