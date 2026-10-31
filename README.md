# AgentWatch

Deterministic, local monitoring for agent swarms.

AgentWatch records what agents do, sweeps their workspaces and mail for
hidden or dangerous artifacts, and reports findings that reproduce
bit-for-bit. It is built for operators running local agent swarms who want
observability without a cloud service and without a language model standing
as the judge of another language model.

Nothing here is a product pitch. It is an instrument. See
[docs/METHOD.md](docs/METHOD.md) for the doctrine and
[docs/DETECTORS.md](docs/DETECTORS.md) for the current rule pack.

## What M0 is

The M0 spine: a hash-chained ledger, a filesystem/mailbox sweeper, fourteen
deterministic (Lane-A) detectors, a ranked sweep report, a CLI, and a local
FastAPI surface. It does not watch processes, ports, or network yet, and it
does not conclude intent. It records and it reports.

## The one rule that matters

Every finding is one of two lanes:

- **Lane A (deterministic).** Reproduces bit-for-bit from the bytes it saw.
  It carries a rule id, a rule-version hash, and a falsifier test. It may
  condemn.
- **Lane B (advisory).** A probabilistic signal stamped with the model and
  parameters that produced it. It may only rank work for human review.

M0 ships Lane A only. The Lane-B interface exists and is documented so the
doctrine is enforced before any classifier is allowed in.

## Install (no dependencies for the core)

```bash
pip install -e .
# optional local dashboard/API
pip install -e ".[api]"
```

Python 3.10+. The core uses the standard library only.

## Use

```bash
# create a ledger (the system of record)
aw ledger init ./aw-ledger

# sweep a workspace or mailbox, recording into the ledger
aw sweep "D:\work\agent-workspace" --ledger ./aw-ledger

# verify nothing in the ledger was edited
aw ledger verify ./aw-ledger

# list rules and run a specific rule's falsifier
aw rule list
aw rule test AW-F003

# local dashboard/API on 127.0.0.1:8018
aw serve --ledger ./aw-ledger
```

`aw sweep --json` emits the full ranked report as JSON. `--fail-on high`
makes the command exit non-zero when a high-or-above finding is present, for
use in a pipeline.

## The rules

| rule | sev | detects |
|---|---|---|
| AW-U001 | medium | zero-width / bidi format characters |
| AW-U002 | high | Unicode tag-block smuggling |
| AW-U003 | low | variation-selector smuggling |
| AW-U004 | medium | homoglyph / mixed-script confusables |
| AW-N001 | medium | NUL bytes in a text file |
| AW-F001 | medium | NTFS alternate data streams |
| AW-F002 | medium | high-entropy / encoded blobs |
| AW-F003 | high | magic-byte mismatch / double extension |
| AW-S001 | medium | script obfuscation / execution markers |
| AW-C001 | low | covert whitespace channel |
| AW-R001 | critical | frozen record mutated |
| AW-T001 | medium | thinking / containment leak tokens |
| AW-T002 | medium | prompt-injection / override markers |
| AW-T003 | medium | concealment / unauthorized-intent markers |

Details and falsifiers: [docs/DETECTORS.md](docs/DETECTORS.md).

## Limits

Every report prints its own coverage and limits. Read them. In short: the
detectors see at most 4 MiB per file; lexical gates fire on quoted examples;
encoded operations that never touch disk or mail are invisible at M0; NTFS
stream content is not read; runtime activity is not collected yet; the ledger
detects edits to the ledger file but is not yet externally anchored. A clean
report is not a clearance.

## Tests

```bash
python run_tests.py
```

Every rule ships a positive and a negative fixture; the ledger has tamper and
reordering tests. Falsifier-first is the house rule.

## Layout

```
src/agentwatch/core/        schema, hashing, hash-chained ledger, sweep engine
src/agentwatch/collectors/  filesystem (+ NTFS ADS), mail
src/agentwatch/detectors/   the Lane-A rule pack
src/agentwatch/scoring/     severity ladder, ranking, report rendering
src/agentwatch/cli/         the `aw` command
src/agentwatch/api/         local FastAPI surface
tests/                      falsifier fixtures
docs/                       method and rule documentation
```

## Status

M0. Next: ScannerBridge (ClamAV/YARA), richer rule packs, probe-pack port
from the Crucible batteries, runtime collectors (process/port/exec), and the
browser dashboard. Frozen-record anchoring lands before any of the
"hidden danger" claims are made.
