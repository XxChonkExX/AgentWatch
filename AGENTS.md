# AGENTS.md - AgentWatch

Instructions for AI coding agents working in this repository.
Humans: most of this is good practice for you too.

## What this repo is

Deterministic, local monitoring for agent swarms. Pure-stdlib Python 3.10+
for the core (`src/agentwatch/`), a local FastAPI surface as an optional
extra, and a falsifier test suite in `tests/`. Read `docs/METHOD.md` before
changing a detector or the ledger.

## Non-negotiables

1. **Lane discipline.** A Lane-A detector must be a pure function of the
   artifact bytes. A Lane-B signal must carry its model/params stamp and must
   never be load-bearing for a control. Do not blur the two.
2. **Zero core dependencies.** The core imports the standard library only.
   FastAPI/uvicorn live behind the `api` extra.
3. **Every rule has a falsifier.** A new gate without a positive and negative
   fixture is incomplete. `aw rule test <id>` must pass.
4. **Never edit a frozen artifact or a recorded ledger.** New data is a new
   file. The ledger is append-only; do not rewrite history to make a test
   pass.
5. **Report limits.** If you add a detector, add its false-positive source and
   its blind spot to the rule description and to `docs/DETECTORS.md`.
6. **Byte discipline.** `.gitattributes` pins LF. A CRLF flip on a fixture
   can change a digest and read as tampering.

## Before you commit

```bash
python run_tests.py
aw rule list
aw sweep <some-fixture-dir>
```

New rule: register in `src/agentwatch/detectors/rules.py`, implement in a
detector module, add fixtures, wire it into
`src/agentwatch/detectors/registry.py`, and document it in
`docs/DETECTORS.md`.

## House style

- No emojis. No marketing adjectives. No "revolutionary".
- Negative results are recorded, not hidden. "Tried X, it fired on Y, so the
  threshold moved to Z" is a first-class changelog entry.
- A number without its method, its n, and its author is an anecdote.
- The one control that never relaxes: a frozen record is never edited.

- Michael Harding / AgentWatch
