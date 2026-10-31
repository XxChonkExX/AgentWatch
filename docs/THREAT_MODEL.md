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
| Agent replaces a binary at a known path | AW-P006 image hashes | requires `--hash-images` baselines; hashes are not signature-verified |
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
