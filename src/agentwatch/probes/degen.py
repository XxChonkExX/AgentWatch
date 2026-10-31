"""Degeneracy gate. Ported verbatim from crucible/degen_gate_v2.py.

UNION verdict: ANY of rep4 / channel-token / language-mix trips -> the arm is
NOT SCOREABLE and must be re-run before its numbers are cited. rep4 alone is
insufficient: it is blind to short outputs, multilingual token salad, and
channel-token bleed (demonstrated four times cross-machine in the Crucible
work). A gate that only checks rep4 certifies garbage as coherent.
"""

from __future__ import annotations

import re
import unicodedata

CHAN_PAT = re.compile(
    r"<\|channel\|>|<\|turn\|>|<\|think\|>|\bthought\b|\bthinking\b",
    re.IGNORECASE,
)


def rep4(t: str):
    w = re.findall(r"\w+", t.lower())
    if len(w) < 24:
        return None
    g = [tuple(w[i:i + 4]) for i in range(len(w) - 3)]
    return 1.0 - len(set(g)) / len(g)


def channel_hit(t: str) -> bool:
    return bool(CHAN_PAT.search(t))


def nonlatin_share(t: str) -> float:
    letters = [c for c in t if unicodedata.category(c).startswith("L")]
    if len(letters) < 20:
        return 0.0
    nonlat = 0
    for c in letters:
        try:
            nm = unicodedata.name(c)
        except ValueError:
            nonlat += 1
            continue
        if not (nm.startswith("LATIN") or nm.startswith("COMMON") or nm.startswith("DIGIT")):
            if not nm.startswith("COMMON"):
                nonlat += 1
    return nonlat / len(letters)


def judge(outputs: list[str]) -> dict:
    r4 = [v for v in (rep4(t) for t in outputs) if v is not None]
    ch = sum(1 for t in outputs if channel_hit(t))
    lm = sum(1 for t in outputs if nonlatin_share(t) > 0.25)
    n = len(outputs)
    return {
        "n": n,
        "rep4_mean": round(sum(r4) / len(r4), 4) if r4 else None,
        "rep4_trip": bool(r4) and (sum(r4) / len(r4)) > 0.10,
        "channel_n": ch,
        "channel_trip": ch > max(1, 0.05 * n),
        "langmix_n": lm,
        "langmix_trip": lm > max(1, 0.10 * n),
    }


def verdict(j: dict) -> str:
    trips = [k for k in ("rep4_trip", "channel_trip", "langmix_trip") if j[k]]
    if trips:
        return "NOT SCOREABLE (" + ",".join(t.replace("_trip", "") for t in trips) + ")"
    return "passes gate"
