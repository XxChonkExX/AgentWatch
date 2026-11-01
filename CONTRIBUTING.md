# Contributing to AgentWatch

AgentWatch is built to the standard of someone who has to answer for the
structure. Before changing anything, read `AGENTS.md` and `docs/METHOD.md`.

## The rules that govern all changes

1. **Lane discipline.** A Lane-A detector is a pure function of artifact
   bytes. A Lane-B signal carries its model/params stamp and never drives a
   control. Do not blur the two.
2. **Every rule has a falsifier.** A new gate without a positive and negative
   fixture is incomplete. `aw rule test <id>` must pass.
3. **Never edit a frozen artifact or a recorded ledger.** New data is a new
   file. The ledger is append-only.
4. **Report what the instrument cannot see.** If you add a detector, add its
   false-positive source and its blind spot to the rule description and to
   `docs/DETECTORS.md`.
5. **Byte discipline.** `.gitattributes` pins LF. A CRLF flip on a fixture
   can change a digest.
6. **Zero core dependencies.** The core imports the standard library only;
   FastAPI/uvicorn live behind the `api` extra; psutil behind `runtime`.

## Before you commit

```bash
python run_tests.py
aw rule list
aw sweep <some-fixture-dir>
```

New rule: register in `src/agentwatch/detectors/rules.py`, implement in a
detector module, add fixtures, wire into `src/agentwatch/detectors/registry.py`,
and document in `docs/DETECTORS.md`.

New scanner: implement `Scanner` in `src/agentwatch/scanners/`, wire into
`default_scanners`, map to a rule.

New probe kind: add to `src/agentwatch/probes/gates.py` (metric, polarity,
gate), add a gate function, add fixtures, author a new frozen pack
(`aw probe freeze name`). Never edit a frozen pack.

## House style

No emojis. No marketing adjectives. Negative results are recorded, not
hidden. A number without its method, its n, and its author is an anecdote.
The one control that never relaxes: a frozen record is never edited.
