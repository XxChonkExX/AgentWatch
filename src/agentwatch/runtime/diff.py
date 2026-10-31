"""Snapshot diff.

Diffs two snapshots into added/removed sets by stable identity. This is the
whole basis of "hidden danger" detection: something that is present now and
was not present in the baseline.

A diff is not a verdict -- a new process may be the operator's own tool. The
diff is deterministic; the interpretation is a human's.
"""

from __future__ import annotations

from .schema import RuntimeSnapshot


def _by_identity(items):
    out = {}
    for it in items:
        out.setdefault(it.identity(), it)
    return out


def _added(base_map, cur_map):
    return [v for k, v in cur_map.items() if k not in base_map]


def _removed(base_map, cur_map):
    return [v for k, v in base_map.items() if k not in cur_map]


def diff_snapshots(base: RuntimeSnapshot, cur: RuntimeSnapshot) -> dict:
    bp, cp = _by_identity(base.processes), _by_identity(cur.processes)
    bl, cl = _by_identity(base.listeners), _by_identity(cur.listeners)
    bc, cc = _by_identity(base.connections), _by_identity(cur.connections)
    bd, cd = _by_identity(base.drivers), _by_identity(cur.drivers)

    result = {
        "added_processes": _added(bp, cp),
        "removed_processes": _removed(bp, cp),
        "added_listeners": _added(bl, cl),
        "removed_listeners": _removed(bl, cl),
        "added_connections": _added(bc, cc),
        "removed_connections": _removed(bc, cc),
        "added_drivers": _added(bd, cd),
        "removed_drivers": _removed(bd, cd),
    }

    # Binary replacement at a known path: same identity, different image hash.
    # Only comparable when both snapshots carried image hashes.
    changed = []
    for key, cur_proc in cp.items():
        base_proc = bp.get(key)
        if base_proc is None:
            continue
        a, b = base_proc.image_sha256, cur_proc.image_sha256
        if a and b and a != b:
            changed.append({
                "identity": key,
                "name": cur_proc.name,
                "from": a,
                "to": b,
            })
    result["changed_images"] = changed
    result["counts"] = {k: len(v) for k, v in result.items() if k != "counts"}
    return result
