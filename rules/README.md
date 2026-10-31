# rules/

In M0 the rule pack is code-defined in
`src/agentwatch/detectors/`. This directory is reserved for declarative rule
packs (YAML/JSON) and freeze manifests once the rule loader lands.

Planned contents:

- `*.rules.yaml` - external detector packs (patterns, severities, falsifiers).
- `freeze/*.json` - freeze manifests (`path -> sha256`) for AW-R001.

Until then, add rules in code and document them in `docs/DETECTORS.md`.
