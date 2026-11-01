"""Smoke test for the optional `api` extra.

Run from a clean install (`pip install -e ".[api]"`). Proves the FastAPI layer
imports, builds, and exposes the endpoints the dashboard calls. Kept out of
run_tests.py because the core suite must stay dependency-free.
"""

from __future__ import annotations

import sys
import tempfile

from agentwatch.api.app import _dashboard_html, create_app

REQUIRED = ["/", "/health", "/rules", "/scanners", "/packs", "/sweep", "/snapshot", "/posture"]


def main() -> int:
    ledger_dir = tempfile.mkdtemp(prefix="aw-api-smoke-")
    app = create_app(ledger_dir=ledger_dir)
    paths = app.openapi()["paths"]

    missing = [p for p in REQUIRED if p not in paths]
    if missing:
        print("missing endpoints: %s" % ", ".join(missing))
        return 1

    # The dashboard is served from the package, not from a build step.
    html = _dashboard_html()
    if "AgentWatch" not in html:
        print("dashboard HTML did not load from the package")
        return 1

    print("api smoke ok: %d paths, %d routes" % (len(paths), len(app.routes)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
