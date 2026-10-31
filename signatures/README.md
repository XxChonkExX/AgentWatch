# signatures/

Drop open-format signature databases here and ScannerBridge picks them up
(`AW-M003`). Formats supported:

| file | format | line shape |
|---|---|---|
| `*.hdb`, `*.mdb` | ClamAV MD5 hash | `md5:size:name` |
| `*.hsb` | ClamAV SHA256 hash | `sha256:size:name` |
| `*.ndb` | ClamAV body signature | `name:target:offset:hex[:min:max]` |

Loaded recursively. Hash signatures report `critical`; body signatures
report `high`. The database fingerprint and counts are recorded per hit.

## Where to get them (open, free)

- **Neo23x0/signature-base** - https://github.com/Neo23x0/signature-base
  (YARA rules; Detection Rule License). Point `--rules-dir` at it, or convert.
- **Yara-Rules/rules** - https://github.com/Yara-Rules/rules (YARA).
- **ClamAV database** - https://www.clamav.net/documents/updating-clamav-virus-database
  (`.ndb`/`.hdb`/`.hsb`, GPLv2). Extract from `main.cvd`/`daily.cvd` or fetch
  with `freshclam`. **Do not commit these** - they are large, GPL, and stale
  fast.
- **abuse.ch / MalwareBazaar** - https://bazaar.abuse.ch/ (hash lists you can
  convert to `.hsb`).
- **vx-underground** - https://vx-underground.org/ (research corpus; for
  manual red-team validation of your *own* tooling, never committed here).

## Why nothing is bundled

Third-party databases carry their own licenses and expire. AgentWatch ships
only an inert example (`examples/example.hdb`, the public EICAR test hash) so
the loader is exercised on a fresh clone. Everything else is yours to drop in.

## Licensing note

AgentWatch's own code is MIT. Signature files you place here remain under
their own licenses (GPLv2 for ClamAV, DRL for signature-base, etc.). Keep
them out of the repository unless you have cleared redistribution.
