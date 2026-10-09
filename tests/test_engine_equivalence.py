"""The production exposure engine against the reference engine (the executable specification).

Same graphs, same answers: exposed sets, minimal hop counts, valid shortest paths, verification outcomes.
Increase EQUIV_SEEDS (env var) for a bigger sweep; CI nightly runs it with 200000.
"""
import os

import pytest

from pathcutter import exposure, exposure_ref
from pathcutter.graph import ADEdge, ADNode, AttackGraph, NodeType

from test_proof_random import random_graph

SEEDS = int(os.environ.get("EQUIV_SEEDS", "3000"))


def assert_same(g, label):
    a, b = exposure.compute_exposure(g), exposure_ref.compute_exposure(g)
    assert a.exposed() == b.exposed(), label
    assert {n: a.hops(n) for n in a.exposed()} == {n: b.hops(n) for n in b.exposed()}, label
    assert a.unverified == b.unverified, label
    for n in list(a.exposed())[:25]:
        steps = a.path(n)
        assert steps[0].node_id == n and steps[-1].node_id in g.tier0_nodes, label
        assert len(steps) - 1 == a.hops(n), label
        for s, t in zip(steps, steps[1:]):
            assert g.has_edge_type(s.node_id, t.node_id, s.edge_type), (label, s)


@pytest.mark.parametrize("seed", range(SEEDS))
def test_fast_engine_equals_reference(seed):
    assert_same(random_graph(seed, dag=(seed % 4 == 0), p=0.18 + (seed % 5) * 0.06), f"seed {seed}")


def test_index_stays_in_sync_through_mutation():
    g = random_graph(7, dag=False)
    exposure.compute_exposure(g)                       # builds the index
    ids = list(g.graph.nodes)
    g.add_node(ADNode("fresh", "FRESH@X", NodeType.USER, "x"))
    g.add_edge(ADEdge("fresh", ids[0], "GenericAll"))
    g.add_edge(ADEdge(ids[1], "fresh", "MemberOf"))
    assert_same(g, "after add")
    for u, v, d in list(g.all_edges())[:6]:
        g.remove_edge(u, v, d["edge_type"])
    assert_same(g, "after remove")
    c = g.clone()
    c.add_edge(ADEdge(ids[2], ids[3], "WriteDacl"))
    assert_same(c, "clone")
    assert_same(g, "original untouched by clone edit")


def test_edges_to_nodes_that_were_never_added_are_handled():
    g = AttackGraph()
    g.add_node(ADNode("da", "DOMAIN ADMINS@X", NodeType.GROUP, "x"))
    g.add_edge(ADEdge("ghost", "da", "GenericAll"))     # `ghost` only exists as an edge endpoint
    g.classify_tiers()
    assert exposure.compute_exposure(g).exposed() == exposure_ref.compute_exposure(g).exposed() == {"ghost"}


def test_clone_is_copy_on_write_in_both_directions():
    g = random_graph(11, dag=False)
    before_edges = sorted((u, v, d["edge_type"]) for u, v, d in g.all_edges())
    c = g.clone()
    ids = list(g.graph.nodes)
    c.add_edge(ADEdge(ids[0], ids[1], "GenericAll"))
    assert sorted((u, v, d["edge_type"]) for u, v, d in g.all_edges()) == before_edges     # clone write does not leak
    d2 = g.clone()
    g.add_edge(ADEdge(ids[2], ids[3], "WriteDacl"))
    assert sorted((u, v, d["edge_type"]) for u, v, d in d2.all_edges()) == before_edges    # original write does not leak
    e = d2.clone()
    e.remove_edge(*next(((u, v, dd["edge_type"]) for u, v, dd in d2.all_edges())))
    assert d2.edge_count == len(before_edges)
    assert_same(c, "clone after write")
    assert_same(g, "original after write")
    assert_same(d2, "second clone")


# ---------------------------------------------------------------- incremental (fork) vs full recomputation

import random as _random

from pathcutter.exposure import fork_with_added_edges

_ADD_TYPES = ["MemberOf", "GenericAll", "WriteDacl", "ForceChangePassword", "AdminTo", "HasSession", "Contains", "GenericWrite"]


@pytest.mark.parametrize("seed", range(max(1500, SEEDS // 2)))
def test_fork_equals_full_recompute(seed):
    rng = _random.Random(seed)
    g = random_graph(seed, dag=(seed % 3 == 0), p=0.15 + (seed % 4) * 0.06)
    g.retier()
    base = exposure.compute_exposure(g)
    ids = list(g.graph.nodes)
    added = []
    for _ in range(rng.randint(1, 3)):
        if rng.random() < 0.15:                                       # an edge to a brand-new object
            nid = f"new{seed}_{len(added)}"
            g.add_node(ADNode(nid, nid.upper() + "@X", NodeType.USER, "x"))
            ids.append(nid)
        u, v, et = rng.choice(ids), rng.choice(ids), rng.choice(_ADD_TYPES)
        if u != v:
            g.add_edge(ADEdge(u, v, et))
            added.append((u, v, et))
    g.retier()
    if frozenset(g.tier0_nodes) != base.tier0:
        pytest.skip("tier 0 changed: production falls back to a full recompute here")
    fork = fork_with_added_edges(base, g, added)
    full = exposure.compute_exposure(g)
    assert fork.exposed() == full.exposed(), f"seed {seed}"
    assert {n: fork.hops(n) for n in fork.exposed()} == {n: full.hops(n) for n in full.exposed()}, f"seed {seed}"
    for n in list(fork.exposed())[:20]:
        steps = fork.path(n)
        assert len(steps) - 1 == fork.hops(n) and steps[-1].node_id in g.tier0_nodes, f"seed {seed}"
        for s, t in zip(steps, steps[1:]):
            assert g.has_edge_type(s.node_id, t.node_id, s.edge_type), (seed, s)
