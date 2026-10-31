"""OTLP/HTTP ingest: agent-framework spans -> ledger.

Every serious agent framework (LangChain, pydantic-ai, OpenLLMetry, anything
OpenTelemetry-native) can export OTLP. This receiver accepts OTLP/JSON traces
on the standard port (4318), maps GenAI-convention spans into ledger records,
and answers the compatibility question once instead of per-framework:

    any instrumented agent  ->  OTLP/HTTP :4318  ->  AgentWatch ledger

Mapping (per span, attributes flattened):
  action    = "span"
  target    = span name (e.g. "chat gpt-4o", "tool write_file")
  agent_id  = service.name / gen_ai.system
  model     = gen_ai.request.model
  details   = prompt/completion/token attrs under meta (truncated)

Only the standard library: an HTTP server that parses OTLP/JSON. Binds
127.0.0.1 by default; this endpoint writes to your ledger, so do not expose it.
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from ..core.ledger import Ledger

GENAI_ATTRS = (
    "gen_ai.system", "gen_ai.request.model", "gen_ai.prompt",
    "gen_ai.completion", "gen_ai.usage.total_tokens", "gen_ai.usage.cost",
)


def span_to_event(span: dict, resource: dict) -> dict:
    attrs = {a["key"]: _attr_value(a.get("value", {})) for a in span.get("attributes", [])}
    model = attrs.get("gen_ai.request.model", "")
    agent = resource.get("service.name") or attrs.get("gen_ai.system") or "unknown"
    meta = {k: attrs[k] for k in GENAI_ATTRS if k in attrs}
    for k in ("gen_ai.prompt", "gen_ai.completion"):
        if k in meta and isinstance(meta[k], str):
            meta[k] = meta[k][:400]
    return {
        "action": "span",
        "target": (span.get("name") or "span")[:200] + ((":" + model) if model else ""),
        "agent_id": agent,
        "model": model,
        "span_id": span.get("span_id", ""),
        "trace_id": span.get("trace_id", ""),
        "meta": meta,
        "ts": _ns_to_iso(span.get("time_unix_nano", 0)) or None,
    }


def otlp_json_to_events(body: dict) -> list:
    events = []
    for rs in body.get("resourceSpans", []):
        resource = {}
        for a in rs.get("resource", {}).get("attributes", []):
            if a.get("key") == "service.name":
                resource["service.name"] = _attr_value(a.get("value", {}))
        for ss in rs.get("scopeSpans", []):
            for span in ss.get("spans", []):
                events.append(span_to_event(span, resource))
    return events


def _attr_value(v: dict):
    for k in ("stringValue", "intValue", "doubleValue", "boolValue"):
        if k in v:
            return v[k]
    if "arrayValue" in v:
        return json.dumps(v["arrayValue"])[:200]
    return ""


def _ns_to_iso(ns: int) -> str:
    if not ns:
        return ""
    from datetime import datetime, timezone

    return datetime.fromtimestamp(ns / 1e9, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class OtlpHandler(BaseHTTPRequestHandler):
    ledger: Ledger = None  # injected by make_server

    def do_POST(self):
        if self.path.split("?")[0] not in ("/v1/traces", "/v1/metrics", "/v1/logs"):
            self.send_response(404)
            self.end_headers()
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length).decode("utf-8", "replace") or "{}")
        except (ValueError, json.JSONDecodeError):
            self.send_response(400)
            self.end_headers()
            return
        count = 0
        for ev in otlp_json_to_events(body):
            ev = {k: v for k, v in ev.items() if v not in ("", None)}
            self.ledger.append(ev)
            count += 1
        # OTLP expects a protobuf ExportTraceServiceResponse; an empty 200 is
        # accepted by the standard OTLP/HTTP JSON exporter.
        self.send_response(200)
        self.send_header("Content-Type", "application/x-protobuf")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            body = json.dumps({"status": "ok", "receiver": "otlp"}).encode()
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *args):  # silence request logging
        pass


def make_server(host: str, port: int, ledger: Ledger) -> ThreadingHTTPServer:
    handler = type("BoundOtlpHandler", (OtlpHandler,), {"ledger": ledger})
    return ThreadingHTTPServer((host, port), handler)
