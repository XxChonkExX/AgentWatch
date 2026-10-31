"""Local HTTP API and dashboard.

The API holds no policy: every endpoint is a thin call into api/payloads.py,
which is plain Python and testable without a web framework.

Binding note: the default host is 127.0.0.1. These endpoints run sweeps and
diffs on arbitrary local paths by design -- that is the operator's own
machine. Do not expose this on a network interface: it would let anyone on
the LAN read files and diff your host (MODEL_ONBOARDING section 5.3-5.4).
"""

from __future__ import annotations

import os

from .. import __version__
from ..api import payloads
from ..core.ledger import Ledger
from ..detectors.registry import RULES


def _dashboard_html() -> str:
    path = os.path.join(payloads.STATIC_DIR, "dashboard.html")
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def create_app(
    ledger_dir: str | None = None,
    freeze_manifest=None,
    rules_dir: str | None = None,
    sig_dir: str | None = None,
    freeze: str | None = None,
):
    """freeze_manifest is a dict; freeze is a path to a manifest JSON."""
    from fastapi import Body, FastAPI, HTTPException
    from fastapi.responses import HTMLResponse

    if freeze and not freeze_manifest:
        from ..detectors.frozen_guard import load_manifest

        freeze_manifest = load_manifest(freeze)

    app = FastAPI(title="AgentWatch", version=__version__)
    html = _dashboard_html()

    @app.get("/", response_class=HTMLResponse)
    def index():
        return html

    @app.get("/health")
    def health():
        return payloads.health_payload(ledger_dir)

    @app.get("/rules")
    def rules():
        return payloads.rules_payload()

    @app.get("/scanners")
    def scanners():
        return payloads.scanner_status_payload(rules_dir=rules_dir, sig_dir=sig_dir)

    @app.get("/packs")
    def packs():
        return payloads.packs_payload()

    @app.post("/sweep")
    def sweep(payload: dict = Body(...)):
        target = payload.get("target")
        if not target:
            raise HTTPException(status_code=400, detail="'target' is required")
        try:
            return payloads.sweep_payload(
                target,
                kind=payload.get("kind"),
                ledger_dir=payload.get("ledger_dir") or ledger_dir,
                freeze=payload.get("freeze"),
                rules_dir=rules_dir,
                sig_dir=sig_dir,
                rule_filter=payload.get("rule"),
            )
        except FileNotFoundError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @app.post("/snapshot")
    def snapshot(payload: dict = Body(default={})):
        try:
            return payloads.snapshot_payload(
                backend=(payload or {}).get("backend", "auto"),
                out=(payload or {}).get("out"),
            )
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc))

    @app.post("/posture")
    def posture(payload: dict = Body(...)):
        baseline = payload.get("baseline")
        if not baseline:
            raise HTTPException(status_code=400, detail="'baseline' is required")
        try:
            result = payloads.posture_payload(
                baseline,
                backend=payload.get("backend", "auto"),
                force=bool(payload.get("force")),
                allow_ports=payload.get("allow_ports") or (),
                allow_process=payload.get("allow_process") or (),
                include_loopback=bool(payload.get("include_loopback")),
                scan_all=bool(payload.get("scan_all")),
                ledger_dir=ledger_dir,
            )
        except FileNotFoundError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        if "error" in result:
            raise HTTPException(status_code=409, detail=result["error"])
        return result

    @app.post("/probes/run")
    def probes_run(payload: dict = Body(...)):
        if not payload.get("pack") or not payload.get("target_url"):
            raise HTTPException(status_code=400, detail="'pack' and 'target_url' are required")
        try:
            return payloads.probe_run_payload(
                payload["pack"],
                payload["target_url"],
                model=payload.get("model", "local"),
                arm=payload.get("arm"),
                limit=payload.get("limit"),
                api_key=payload.get("api_key"),
                out_dir=payload.get("out_dir"),
            )
        except FileNotFoundError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @app.post("/probes/score")
    def probes_score(payload: dict = Body(...)):
        transcripts = payload.get("transcripts") or []
        if not transcripts:
            raise HTTPException(status_code=400, detail="'transcripts' is required")
        try:
            return payloads.probe_score_payload(transcripts, ref=payload.get("ref"))
        except FileNotFoundError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @app.get("/probes/review")
    def probes_review(pack: str, transcripts: str):
        try:
            return payloads.review_payload(pack, transcripts)
        except FileNotFoundError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @app.get("/findings")
    def findings():
        if ledger_dir is None:
            raise HTTPException(status_code=400, detail="no ledger configured")
        from ..scoring.report import findings_from_ledger

        return [f.to_dict() for f in findings_from_ledger(Ledger(ledger_dir))]

    @app.get("/ledger/recent")
    def ledger_recent(limit: int = 100):
        if ledger_dir is None:
            raise HTTPException(status_code=400, detail="no ledger configured")
        return payloads.ledger_recent_payload(ledger_dir, limit=limit)

    @app.get("/ledger/{seq}")
    def ledger_event(seq: int):
        if ledger_dir is None:
            raise HTTPException(status_code=400, detail="no ledger configured")
        ev = Ledger(ledger_dir).get(seq)
        if ev is None:
            raise HTTPException(status_code=404, detail="no such record")
        return ev

    return app
