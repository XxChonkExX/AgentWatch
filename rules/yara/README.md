# rules/yara

YARA rules loaded by the ScannerBridge YARA scanner. The `aw` CLI uses this
directory by default when it exists; override with `--rules-dir`.

A rule match becomes an `AW-M002` finding (severity `high` until YARA meta
parsing is implemented). If the `yara` CLI is not installed, the scanner is
reported as UNAVAILABLE and no YARA rules run -- that absence is printed in
the sweep report, never hidden.

Tested with stock YARA syntax. Keep rules high-signal: a YARA hit is a Lane-A
finding and will be treated as evidence for review, not a verdict.
