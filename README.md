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

## What is built

The M0 spine: a hash-chained ledger, a filesystem/mailbox sweeper, a ranked
sweep report, a CLI, and a local FastAPI surface.

M1 adds **ScannerBridge**: a builtin signature scanner (zero dependencies),
optional bridges to ClamAV and YARA, and a loader for open-format signature
databases (ClamAV `.hdb/.hsb/.ndb`) dropped into `signatures/`. Scanner
availability is printed in every report; an absent scanner is a stated blind
spot, never a silent pass.

M2 adds **probe packs**: three frozen batteries (agentic behavior, workplace
/ HR review, guardrail-slip under obfuscation) ported from the Crucible
alignment work and scored with deterministic gates, n + Wilson intervals, a
degeneracy gate, and a coupled-metric anti-gaming gate. The verdict is
always a human's; the gates only rank.

M3 adds **runtime posture**: point-in-time snapshots of processes, listening
ports, connections, and kernel drivers/modules (backends: psutil if present,
otherwise native PowerShell on Windows or /proc on Linux), a deterministic
baseline diff, and AW-P001..P005 findings. Backends must match between
baseline and current; a cross-backend diff is refused.

It does not conclude intent. It records and it reports.
See [docs/PROBES.md](docs/PROBES.md) and [docs/RUNTIME.md](docs/RUNTIME.md).

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
| AW-M001 | critical | builtin signature match (EICAR, webshell, reverse shell, miner) |
| AW-M002 | critical | external scanner match (ClamAV / YARA) |
| AW-M003 | critical | signature-file match (open signature DB: ClamAV .hdb/.hsb/.ndb) |
| AW-P001 | medium/high | new listening port (all-interfaces or risky port escalates) |
| AW-P002 | low | new outbound connection (egress) |
| AW-P003 | low | new process not in baseline |
| AW-P004 | high | suspicious process (temp-path exec, LOLBin + obfuscation marker) |
| AW-P005 | high | new kernel driver/module |
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
src/agentwatch/scanners/    ScannerBridge (builtin, sigfile, ClamAV, YARA)
src/agentwatch/runtime/     runtime snapshots, diff, posture detectors
src/agentwatch/probes/      probe packs, gates, runner, scoring
src/agentwatch/scoring/     severity ladder, ranking, report rendering
src/agentwatch/cli/         the `aw` command
src/agentwatch/api/         local FastAPI surface
rules/yara/                 YARA rules loaded by the scanner bridge
signatures/                 open-format signature DBs you drop in (not committed)
tests/                      falsifier fixtures
docs/                       method, rule, and probe documentation
```

## Probe packs

```bash
aw probe list agentic_v1 -v
aw probe run workplace_v1 --target-url http://127.0.0.1:8012 --model local --arm a
aw probe score a.jsonl --ref a
aw probe review workplace_v1 a.jsonl     # the human review sheet
```

See [docs/PROBES.md](docs/PROBES.md).

## Dashboard

```bash
pip install -e ".[api]"          # fastapi + uvicorn (optional extra)
aw serve --ledger ./aw-ledger --open
```

Opens `http://127.0.0.1:8018/` -- a local, zero-build dashboard (single HTML
file, vanilla JS, no CDN) over the same engine the CLI uses: sweep, posture
diff, probe run/score/review, the ledger, and the rule/scanner registry.
Binds to 127.0.0.1 by design; do not expose it -- the endpoints sweep
arbitrary local paths on purpose.

## Runtime posture

```bash
aw snapshot --out baseline.json          # capture the host (baseline)
aw posture --baseline baseline.json      # diff current host against it
aw posture --baseline baseline.json --scan-all --fail-on high
```

Backends: `psutil` (optional extra), `windows` (PowerShell), `linux` (/proc).
The backend is recorded in the snapshot; posture refuses to diff across
different backends. See [docs/RUNTIME.md](docs/RUNTIME.md).

## Status

M0-M4 complete: ledger, sweepers, detector pack, ScannerBridge with open
signature DBs, the Crucible probe-pack port, runtime posture, and the local
dashboard. Calibrated against a real 742-file agent mailbox (149 raw findings
to 32, nothing hidden) and live-tested on Windows and Linux/WSL (real
listeners caught high on both). Remaining: Defender/AMSI bridge, executable
hashing for process identity, and ledger anchoring -- anchoring lands before
any "hidden danger" claim is strengthened beyond what the snapshot diff can
honestly see.

## Canary tokens, loop detection, and OTLP ingest

```bash
aw canary plant C:\data\vault --count 3      # plant deterministic exfil bait
aw canary check C:\suspicious --registry C:\data\vault   # did the bait move?
aw ledger loops ./aw-ledger                  # stuck-agent detection (AW-P007)
aw otel serve --ledger ./aw-ledger           # OTLP/HTTP :4318 -> ledger
```bash
Any OpenTelemetry-instrumented agent framework (LangChain, pydantic-ai,
OpenLLMetry, ...) can export OTLP/HTTP to the receiver; GenAI spans become
ledger records. Canary digests are HMAC-keyed, so a leaked registry never
reveals the bait. See docs/THREAT_MODEL.md for what this tool does and does
not defend against.
