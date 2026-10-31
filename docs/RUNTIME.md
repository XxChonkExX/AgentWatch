# Runtime posture (M3)

The "hidden danger" question -- is something listening, running, or loaded
that should not be? -- is answered here the only honest way available to a
user-space instrument: **take a snapshot, and diff it against a baseline you
took when the host was known-good.**

## Model

A `RuntimeSnapshot` records four observable surfaces:

| surface | contents |
|---|---|
| processes | pid, ppid, name, exe, cmdline |
| listeners | proto, addr, port, pid |
| connections | proto, local/remote addr+port, state, pid |
| drivers | name, path, state (Windows drivers / Linux modules) |

Snapshots are serializable, hash-stable, and carry their backend and
timestamp. `aw diff` compares by stable identity: executable path (else name)
for processes; (proto, addr, port) for listeners; (proto, local-port,
remote-addr, remote-port) for connections; driver name.

## Backends

| backend | source | notes |
|---|---|---|
| `psutil` | the psutil package (optional) | most robust; auto-selected if installed |
| `windows` | PowerShell CIM + `Get-NetTCPConnection`/`Get-NetUDPEndpoint` | no dependencies |
| `linux` | `/proc` (stat, cmdline, exe, net/tcp[6], net/udp[6], modules) | no dependencies |

The `/proc` network parser and the PowerShell JSONL parser are pure functions
and are unit-tested against fixtures. The backend is recorded in every
snapshot; **posture refuses to diff across different backends** -- backends
see different worlds (driver models, address rendering), and a cross-backend
diff manufactures findings. Override only with `--force`.

## Rules

| rule | severity | fires when |
|---|---|---|
| AW-P001 | medium (high on 0.0.0.0/:: or a risky port) | a listener exists now that was not in the baseline |
| AW-P002 | low | an established connection to a non-loopback remote not in the baseline |
| AW-P003 | low | a process identity not in the baseline |
| AW-P004 | high | a process executes from a temp/user-writable path, or a LOLBin carries an obfuscation marker, or the cmdline has encoded/quiet markers |
| AW-P005 | high | a kernel driver or module not in the baseline |

AW-P003 is deliberately low severity: new processes are the normal state of a
working machine. It is a review queue, not an alarm. Escalation happens only
on the deterministic conditions in AW-P004.

## Use

```bash
# baseline when the host is known-good
aw snapshot --out baseline.json

# later: diff
aw posture --baseline baseline.json
aw posture --baseline baseline.json --scan-all --fail-on high
aw posture --baseline baseline.json --allow-port 8018 --allow-process python.exe
aw posture --baseline baseline.json --ledger ./aw-ledger     # record to the ledger
```

## Limits (stated, not hidden)

- User-space enumeration. A rootkit that hides from the default APIs is
  invisible here; absence is not evidence of absence.
- Process identity is path/name. A replaced binary at the same path is not a
  diff; hash executables to catch that.
- Linux connections carry no pid (no `/proc/<pid>/fd` walk yet).
- Drivers/modules are listed, not verified (no signature check).
- UDP egress, raw sockets, and non-INET families are not fully enumerated.
- A diff is not a verdict. The operator's own tools appear in it.

Verified live: Windows (psutil backend, real listener on 8099 caught high on
both IPv4 and IPv6) and Linux/WSL (native /proc backend, real listener on
8077 caught high, with the two measurement shells appearing as low AW-P003
line items -- which is the honest behavior).
