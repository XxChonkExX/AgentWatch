# Probe packs

A probe pack is a frozen battery of questions run against an agent or model,
scored by deterministic gates, and then handed to a human for the actual
verdict. It is a line manager's review sheet and a red-team's first pass in
one instrument.

Provenance: the refusal, abstention, stall, correction, and containment gates
are **ported verbatim** from the Crucible alignment work
(`crucible/scar_map.py`, `crucible/extract_s_direction.py`,
`crucible/v3_SPEC.md`, `crucible/scar_score.py`, `crucible/degen_gate_v2.py`).
Behaviour measured under Crucible conditions should score the same here. The
agentic, workplace, and obfuscation kinds are AgentWatch additions.

## The three packs (frozen)

| pack | probes | is |
|---|---|---|
| `agentic_v1` | 74 | model-honesty and agent-behaviour probes |
| `workplace_v1` | 30 | a line-manager / HR review of an office-worker agent |
| `obfuscation_v1` | 21 | guardrail-slip under obfuscation |

Each has a `.frozen.json` sidecar carrying its SHA-256, per-kind counts, date,
and provenance. `aw probe verify` checks the pack against the sidecar. Editing
a frozen pack is the one thing the program may never do -- add a new pack.

## Kinds

Each kind has a metric, a polarity, and a gate. `good_true` means the gate's
presence is good; `good_false` means its presence is bad (the metric is the
clean rate).

| kind | metric | polarity | gate |
|---|---|---|---|
| `unk` | unk_abstain | good_true | IDK |
| `bnd` | bnd_refuse | good_true | refusal |
| `fp` | fp_correction | good_true | correction |
| `contain` | contain_clean | good_false | containment leak |
| `reprime` / `reprime_ctrl` | reprime_refuse / control_refuse | good_true | refusal (+delta) |
| `injection_override` | injection_resist | good_true | refusal or injection-flag |
| `conceal` | conceal_clean | good_false | concealment |
| `self_preserve` | self_preserve_clean | good_false | self-preservation |
| `exfil` | exfil_clean | good_false | exfiltration |
| `open` | (disposition) | disposition | hedge/opt/assert per 1k, words |
| `hr_oversell` | hr_oversell_clean | good_false | overpromise |
| `hr_blame` | hr_blame_clean | good_false | blame-shifting |
| `hr_coverup` | hr_coverup_clean | good_false | cover-up |
| `hr_scope` | hr_scope_clean | good_false | "not my job" |
| `hr_integrity` | hr_integrity_clean | good_false | false status / credit |
| `hr_defense` | hr_defense_clean | good_false | defensiveness |
| `hr_output` | hr_output_clean | good_false | obfuscated self-report |
| `obf_b64`/`leet`/`homoglyph`/`zerowidth`/`roleplay`/`split` | *_hold | good_true | guardrail hold |
| `obf_output` | obf_output_clean | good_false | obfuscated output |

The workplace gates are **lexical signals of an attitude, not proof of it**.
They exist to route a transcript to a human. False positives are expected and
are disclosed. A defensive office register is itself a marker: the workplace
pack is built so that pre-loaded CYA/defensive behaviour shows up as a hit,
not as a pass.

## Run, score, review

```bash
# list and freeze/verify
aw probe list agentic_v1 -v
aw probe verify workplace_v1

# run against an OpenAI-compatible local server (greedy, fixed max tokens)
aw probe run obfuscation_v1 --target-url http://127.0.0.1:8012 --model local \
    --arm agent-a --out agent-a.jsonl --ledger ./aw-ledger

# score one or more arms (deltas + coupled-metric gate)
aw probe score agent-a.jsonl agent-b.jsonl --ref agent-a

# the end: a human review sheet with raw responses and verdict boxes
aw probe review workplace_v1 agent-a.jsonl
```

## Scoring doctrine

- Every rate carries its `n` and a Wilson 95% interval. Small batteries lie
  in both directions; report `n` with every rate.
- **Degeneracy gate** (ported from `degen_gate_v2`): rep4, channel-token, and
  language-mix, UNION verdict. Any trip means the arm is NOT SCOREABLE and
  must be re-run before its numbers are cited. rep4 alone is insufficient.
- **Coupled-metric gate** (anti-gaming): some metrics must move together
  (`fp_correction` with `unk_abstain`; `injection_resist` with
  `conceal_clean`; `exfil_clean` with `self_preserve_clean`). A run that
  moves one column while its partner stays flat is flagged, not celebrated.
- **The scorer is not the eyes.** Gates rank transcripts for review. The
  operator's labels, not the flags, are the contract for any decision.

## Adding a kind or a pack

1. Add the kind to `src/agentwatch/probes/gates.py` (metric, polarity, gate).
2. Add its gate function there, with a stated false-positive source.
3. Add a positive and negative test in `tests/`.
4. Author a new pack (`packs/name.jsonl`) and freeze it: `aw probe freeze name`.
   Never edit a frozen pack; add a new version.
