# Threat model

What AgentWatch defends against, what it explicitly does not, and what it
assumes about you.

## Assets protected

1. The host the agents run on (processes, ports, kernel images, files).
2. Sensitive data in agent workspaces (confidentiality, via canaries).
3. The record of what happened (ledger integrity, via hash chain + anchor).
4. The operator's ability to reason (reports that state their own limits).

## Adversaries / failure modes

| threat | defense | residual risk |
|---|---|---|
| Agent exfiltrates data (mail, upload, paste) | AW-T003 markers, canaries (AW-C002), egress diff (AW-P002) | markers are lexical; canaries only prove movement of *baited* data |
| Agent hides its work (ADS, zero-width, whitespace, encoding) | AW-U001/2/3, AW-F001/2, AW-C001 | content in memory never touching disk is invisible |
| Agent tampers with frozen records | AW-R001 (freeze manifest), ledger chain + external anchor | an attacker who steals the anchor key or edits both boxes wins |
| Agent replaces a binary at a known path | AW-P006 image hashes (on by default; `--no-hash-images` to skip) | hashes are recorded, not signature-verified; system paths are skipped |
| Agent runs a listener / opens ports | AW-P001 | user-space enumeration only; rootkits hide from it |
| Agent is stuck / runaway | AW-P007 loop detection | only sees actions that reach the ledger |
| Prompt injection via mail/workspace text | AW-T002, probe packs (obf_*, injection_override) | lexical gates over-fire on documents *about* injection; context tagging mitigates, human decides |
| Model misbehaves (refusal loss, confabulation) | probe packs vs OpenAI-compatible endpoints, n + CI | greedy decode only; the live agent may diverge |
| You misread a clean report as safety | mandatory coverage & limits sections | none; read them |

## Explicitly out of scope

- Preventing determined malware: AgentWatch observes and records; it is not
  an antivirus (it bridges to them) and not an EDR.
- Defending against the operator: the ledger anchor protects the record from
  an agent, not from the human who holds the anchor key.
- Network-level inspection, TLS interception, memory forensics.
- Cloud anything: no telemetry leaves this tool. If your copy phones home,
  it is not this tool.

## Trust assumptions

- The operator runs AgentWatch with at least the privileges of the agents
  being watched (otherwise snapshots under-report).
- Ledger + anchor live on machines with different compromise paths.
- Lexical gates are signals for human review; the final verdict is always a
  person's. The scorer is not the eyes.

## Operationalizing the anchor

The hash chain proves that a ledger file was not edited *in place*. It cannot
prove that the whole file is the one that was written, because an attacker who
can rewrite every record can also produce a self-consistent chain. The anchor
is the only thing that closes that gap, and only if it lives somewhere else.

Minimum viable two-box run:

1. On the agent host, at a known-good moment (before an agent run, after a
   review, on a schedule):

   ```bash
   aw ledger anchor <ledger-dir>
   ```

   The anchor is written to `<ledger-dir>/anchors/anchor_seqNNNNNN.json`. It is
   a small document: last seq, last hash, UTC time, record count.

2. Copy that file to the second box (scp, USB, a paste into a ticket). Delete
   nothing; anchors accumulate and each one pins a moment.

3. Later, or after an incident, verify against the off-box copy:

   ```bash
   aw ledger verify <ledger-dir> --anchor /path/to/copied/anchor_seqNNNNNN.json
   ```

   This re-walks the chain and checks that the anchored sequence still holds
   the anchored hash, and that the chain has not been truncated below it.

4. Treat a mismatch as a finding, not a bug report. Record it, keep the copy,
   and hand it to a person.

What this still does not cover: an attacker who compromises the second box, or
who can make you verify against an anchor they supplied. Signing anchors with a
key held off the agent host is the next step; until then, an anchor is a
witness, not a notary.
