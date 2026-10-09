"""Baseline snapshots - parse SharpHound once, reuse the graph on every change check.

A `.pcsnap` file is gzip-compressed JSON holding the attack graph plus provenance
(where it came from, when it was collected, a content hash). CI jobs keep one as an
artifact so a pull request check takes seconds instead of re-ingesting a ZIP.
"""
from __future__ import annotations

import datetime as dt
import gzip
import hashlib
import json
from pathlib import Path

from . import __version__
from .graph import AttackGraph, ADEdge, ADNode, Deny, NodeType
from .ingest import load_sharphound

FORMAT = "pathcutter.snapshot/1"
SNAPSHOT_SUFFIX = ".pcsnap"


class SnapshotError(ValueError):
    pass


def _source_collected(path: Path) -> dt.date | None:
    """Best-effort collection date: newest modification time under the SharpHound source."""
    try:
        if path.is_dir():
            times = [f.stat().st_mtime for f in path.rglob("*.json")]
            ts = max(times) if times else path.stat().st_mtime
        else:
            ts = path.stat().st_mtime
        return dt.date.fromtimestamp(ts)
    except OSError:
        return None


def _sha256(path: Path) -> str | None:
    if not path.is_file():
        return None
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def save_snapshot(graph: AttackGraph, out_path: str | Path, source: str | Path | None = None,
                  collected: dt.date | None = None) -> dict:
    src = Path(source) if source else None
    meta = {
        "format": FORMAT,
        "tool_version": __version__,
        "created": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": str(src) if src else None,
        "source_sha256": _sha256(src) if src else None,
        "collected": (collected or (_source_collected(src) if src else None) or dt.date.today()).isoformat(),
        "nodes": graph.node_count,
        "edges": graph.edge_count,
    }
    nodes = [[n.object_id, n.name, n.node_type.value, n.domain, n.enabled, n.admin_count, n.properties]
             for n in graph.all_nodes()]
    edges = []
    for u, v, d in graph.all_edges():
        props = {k: val for k, val in d.items() if k not in ("edge_type", "inherited", "weight")}
        edges.append([u, v, d.get("edge_type", ""), bool(d.get("inherited", False)), props] if props
                     else [u, v, d.get("edge_type", ""), bool(d.get("inherited", False))])
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(out, "wt", encoding="utf-8", compresslevel=6) as f:
        denies = sorted([d.principal_id, d.edge_type, d.target_id] for d in graph.denies)
        json.dump({"meta": meta, "nodes": nodes, "edges": edges, "denies": denies, "graph_meta": graph.meta},
                  f, separators=(",", ":"), default=str)
    meta["bytes"] = out.stat().st_size
    return meta


def load_snapshot(path: str | Path) -> tuple[AttackGraph, dict]:
    p = Path(path)
    try:
        with gzip.open(p, "rt", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, EOFError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise SnapshotError(f"{p} is not a readable PathCutter snapshot ({exc})") from None
    meta = data.get("meta", {})
    if meta.get("format") != FORMAT:
        raise SnapshotError(f"{p}: unsupported snapshot format '{meta.get('format')}' (expected {FORMAT})")
    types = {t.value: t for t in NodeType}
    graph = AttackGraph()
    graph.add_nodes_bulk([
        ADNode(object_id=n[0], name=n[1], node_type=types.get(n[2], NodeType.UNKNOWN), domain=n[3],
               enabled=n[4], admin_count=n[5], properties=n[6] or {})
        for n in data.get("nodes", [])])
    graph.add_edges_bulk([
        ADEdge(e[0], e[1], e[2], e[3], e[4] if len(e) > 4 else {}) for e in data.get("edges", [])])
    graph.denies = {Deny(d[0], d[1], d[2]) for d in data.get("denies", [])}
    graph.meta = dict(data.get("graph_meta") or {})
    graph.retier()
    return graph, meta


def is_snapshot(path: str | Path) -> bool:
    p = Path(path)
    if p.suffix.lower() == SNAPSHOT_SUFFIX:
        return True
    try:
        with p.open("rb") as f:
            return f.read(2) == b"\x1f\x8b"
    except OSError:
        return False


def load_baseline(path: str | Path, today: dt.date | None = None) -> tuple[AttackGraph, dict]:
    """Load a baseline from either a .pcsnap snapshot or a raw SharpHound ZIP/directory."""
    p = Path(path)
    if not p.exists():
        raise SnapshotError(f"baseline not found: {p}")
    today = today or dt.date.today()
    if is_snapshot(p):
        graph, meta = load_snapshot(p)
        collected = meta.get("collected")
        kind = "snapshot"
    else:
        try:
            graph = load_sharphound(p)
        except ValueError as exc:
            raise SnapshotError(str(exc)) from None
        collected_date = _source_collected(p)
        collected = collected_date.isoformat() if collected_date else None
        meta = {"source": str(p), "source_sha256": _sha256(p)}
        kind = "sharphound"
    age = None
    if collected:
        try:
            age = max(0, (today - dt.date.fromisoformat(collected)).days)
        except ValueError:
            pass
    info = {"path": str(p), "kind": kind, "nodes": graph.node_count, "edges": graph.edge_count,
            "collected": collected, "age_days": age, "sha256": meta.get("source_sha256"),
            "tool_version": meta.get("tool_version")}
    return graph, info
