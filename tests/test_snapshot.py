"""Reusable baseline snapshots."""
import datetime as dt
import gzip
import json
from pathlib import Path

import pytest

from pathcutter.snapshot import (
    FORMAT, SnapshotError, is_snapshot, load_baseline, load_snapshot, save_snapshot,
)

SHARPHOUND = Path(__file__).parent / "test_sharphound_data"


def edges(g):
    return sorted((u, v, d["edge_type"]) for u, v, d in g.all_edges())


def test_roundtrip_preserves_graph_and_tiers(corp, tmp_path):
    out = tmp_path / "base.pcsnap"
    meta = save_snapshot(corp, out)
    g, loaded = load_snapshot(out)
    assert edges(g) == edges(corp)
    assert {n.object_id: (n.name, n.node_type, n.tier, n.enabled) for n in g.all_nodes()} == \
           {n.object_id: (n.name, n.node_type, n.tier, n.enabled) for n in corp.all_nodes()}
    assert g.tier0_nodes == corp.tier0_nodes
    assert loaded["format"] == FORMAT and meta["nodes"] == corp.node_count and meta["bytes"] > 0


def test_snapshot_records_provenance_and_collection_date(corp, tmp_path):
    out = tmp_path / "b.pcsnap"
    src = tmp_path / "export.zip"
    src.write_bytes(b"zipdata")
    meta = save_snapshot(corp, out, source=src, collected=dt.date(2026, 1, 2))
    assert meta["collected"] == "2026-01-02"
    assert len(meta["source_sha256"]) == 64


def test_edge_properties_survive(corp, tmp_path):
    from pathcutter.graph import ADEdge
    corp.add_edge(ADEdge("u-alice", "g-team", "MemberOf", properties={"note": "x"}))
    save_snapshot(corp, tmp_path / "b.pcsnap")
    g, _ = load_snapshot(tmp_path / "b.pcsnap")
    assert any(d.get("note") == "x" for _, _, d in g.all_edges())


def test_is_snapshot_detects_by_suffix_and_magic(corp, tmp_path):
    a = tmp_path / "x.pcsnap"
    save_snapshot(corp, a)
    renamed = tmp_path / "x.bin"
    renamed.write_bytes(a.read_bytes())
    plain = tmp_path / "x.json"
    plain.write_text("{}")
    assert is_snapshot(a) and is_snapshot(renamed) and not is_snapshot(plain)


@pytest.mark.parametrize("payload", [b"not gzip at all", gzip.compress(b"not json"),
                                     gzip.compress(json.dumps({"meta": {"format": "other/9"}}).encode())])
def test_bad_snapshots_raise_clear_errors(tmp_path, payload):
    f = tmp_path / "bad.pcsnap"
    f.write_bytes(payload)
    with pytest.raises(SnapshotError):
        load_snapshot(f)


def test_load_baseline_reports_age(corp, tmp_path):
    out = tmp_path / "b.pcsnap"
    save_snapshot(corp, out, collected=dt.date(2026, 1, 1))
    _, info = load_baseline(out, today=dt.date(2026, 1, 31))
    assert info["kind"] == "snapshot" and info["age_days"] == 30 and info["nodes"] == corp.node_count


def test_missing_baseline_is_an_error(tmp_path):
    with pytest.raises(SnapshotError):
        load_baseline(tmp_path / "nope.pcsnap")


@pytest.mark.skipif(not SHARPHOUND.exists(), reason="sharphound fixture not generated")
def test_load_baseline_accepts_raw_sharphound(tmp_path):
    g, info = load_baseline(SHARPHOUND)
    assert info["kind"] == "sharphound" and g.node_count > 0 and info["age_days"] is not None
    out = tmp_path / "s.pcsnap"
    save_snapshot(g, out, source=SHARPHOUND)
    g2, _ = load_snapshot(out)
    assert edges(g2) == edges(g) and g2.tier0_nodes == g.tier0_nodes
