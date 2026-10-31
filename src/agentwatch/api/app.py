"""FastAPI app: a thin HTTP surface over the sweep engine and ledger.

The API holds no policy. It runs the same detectors as the CLI and returns
the same report shape. FastAPI/uvicorn are an optional extra; importing this
module without them raises ImportError, which `aw serve` reports cleanly.

Binding note: the default host is 127.0.0.1. Do not expose a ledger of raw
agent activity on a network interface without operator authorization
(MODEL_ONBOARDING section 5.3-5.4).
"""

from __future__ import annotations

from .. import __version__
from ..core.engine import SweepEngine
from ..core.ledger import Ledger
from ..detectors.registry import RULES, build_detectors
from ..scoring import report as report_mod
from ..detectors.frozen_guard import load_manifest


def create_app(
    ledger_dir: str | None = None,
    freeze_manifest: dict | None = None,
    rules_dir: str | None = None,
):
    from fastapi import Body, FastAPI, HTTPException

    app = FastAPI(title="AgentWatch", version=__version__)
    ledger = Ledger(ledger_dir) if ledger_dir else None

    @app.get("/health")
    def health():
        return {
            "status": "ok",
            "version": __version__,
            "rules": len(RULES),
            "ledger": str(ledger.path) if ledger else None,
        }

    @app.get("/rules")
    def rules():
        return [RULES[rid].to_dict() for rid in sorted(RULES)]

    @app.post("/sweep")
    def sweep(payload: dict = Body(...)):
        target = payload.get("target")
        if not target:
            raise HTTPException(status_code=400, detail="'target' is required")
        kind = payload.get("kind")
        freeze = freeze_manifest
        if payload.get("freeze"):
            freeze = load_manifest(payload["freeze"])
        from ..cli.main import pick_collector

        detectors = build_detectors(freeze, rules_dir=rules_dir)
        engine = SweepEngine(detectors, ledger=ledger)
        collector = pick_collector(target, kind)
        result = engine.sweep(collector, target)
        return report_mod.to_dict(result)

    @app.get("/findings")
    def findings():
        if ledger is None:
            raise HTTPException(status_code=400, detail="no ledger configured")
        return [f.to_dict() for f in report_mod.findings_from_ledger(ledger)]

    @app.get("/ledger/{seq}")
    def ledger_event(seq: int):
        if ledger is None:
            raise HTTPException(status_code=400, detail="no ledger configured")
        ev = ledger.get(seq)
        if ev is None:
            raise HTTPException(status_code=404, detail="no such record")
        return ev

    return app
