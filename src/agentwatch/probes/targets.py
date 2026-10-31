"""Probe targets.

A target turns a message list into a response. Three implementations:

  CallableTarget            wraps a Python function (tests, in-process models)
  RecordedTarget            replays recorded outputs (re-scoring without a model)
  OpenAICompatTarget        POSTs to an OpenAI-compatible /v1/chat/completions

The HTTP target uses only the standard library, matching the wiring pattern
of the Afterimage router. Decode parameters are greedy (temperature 0) with a
fixed seed where the server honours it: the comparability contract from the
Crucible method. Long-form prose may still diverge run-to-run through
positional variance; the frozen LABELS are the contract, the raw text is
evidence.
"""

from __future__ import annotations

import json
import os
from urllib import error, request


class Target:
    name = "target"
    model = ""

    def generate(self, messages: list, max_tokens: int = 64, temperature: float = 0.0, seed: int = 0) -> str:
        raise NotImplementedError


class CallableTarget(Target):
    def __init__(self, fn, name: str = "callable"):
        self.fn = fn
        self.name = name

    def generate(self, messages, max_tokens=64, temperature=0.0, seed=0):
        try:
            return self.fn(messages, max_tokens=max_tokens)
        except TypeError:
            return self.fn(messages)


class RecordedTarget(Target):
    """Replay outputs keyed by the last user message (or '__default__')."""

    def __init__(self, outputs: dict, name: str = "recorded"):
        self.outputs = outputs
        self.name = name

    def generate(self, messages, max_tokens=64, temperature=0.0, seed=0):
        key = messages[-1].get("content", "") if messages else ""
        return self.outputs.get(key, self.outputs.get("__default__", ""))


class OpenAICompatTarget(Target):
    def __init__(self, base_url: str, model: str, api_key: str | None = None, timeout: int = 120):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        self.timeout = timeout
        self.name = "openai-compat:%s" % model

    def generate(self, messages, max_tokens=64, temperature=0.0, seed=0):
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "top_p": 1.0,
            "max_tokens": max_tokens,
            "seed": seed,
            "stream": False,
        }
        data = json.dumps(payload).encode("utf-8")
        req = request.Request(
            self.base_url + "/v1/chat/completions",
            data=data,
            headers={"Content-Type": "application/json"},
        )
        if self.api_key:
            req.add_header("Authorization", "Bearer " + self.api_key)
        try:
            with request.urlopen(req, timeout=self.timeout) as resp:
                body = json.loads(resp.read().decode("utf-8", "replace"))
        except error.URLError as exc:
            raise RuntimeError("target request failed: %s" % exc)
        return body["choices"][0]["message"]["content"]
