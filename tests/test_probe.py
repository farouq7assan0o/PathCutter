"""AttackGraph.probe(): trial changes in place, always rolled back exactly."""
import random

import pytest

from pathcutter import exposure, exposure_ref
from pathcutter.changes import load_changes, resolve_changes
from pathcutter.graph import ADEdge, ADNode, Deny, NodeType
from pathcutter.impact import analyze_impact

from test_proof_random import random_graph

TYPES = ["MemberOf", "GenericAll", "WriteDacl", "AdminTo", "HasSession", "Contains", "ForceChangePassword"]


def state(g):
    return {
        "edges": sorted((u, v, d["edge_type"], d.get("inherited", False)) for u, v, d in g.all_edges()),
        "nodes": {k: (n.name, n.tier, n.node_type.value) for k, n in g._nodes.items()},
        "nxnodes": sorted(g.graph.nodes),
        "t0": sorted(g.tier0_nodes),
        "members": {k: sorted(v) for k, v in g._group_members.items() if v},
        "denies": sorted(map(tuple, ((d.principal_id, d.edge_type, d.target_id) for d in g.denies))),
        "fx": (sorted(sorted(r) for r in g._fx.rev) if g._fx is not None else None,
               len(g._fx.ids) if g._fx is not None else None),
    }


def scramble(g, rng):
    ids = list(g.graph.nodes)
    for i in range(rng.randint(2, 10)):
        r = rng.random()
        if r < 0.15:
            nid = f"p{rng.randint(0, 10**6)}"
            g.add_node(ADNode(nid, nid.upper() + "@X", NodeType.USER, "x"))
            ids.append(nid)
        elif r < 0.65:
            u, v = rng.choice(ids), rng.choice(ids)
            if u != v:
                g.add_edge(ADEdge(u, v, rng.choice(TYPES)))
        elif r < 0.9:
            edges = list(g.all_edges())
            if edges:
                u, v, d = rng.choice(edges)
                g.remove_edge(u, v, d["edge_type"])
        else:
            g.denies.add(Deny(rng.choice(ids), "GenericAll", rng.choice(ids)))
    g.retier()


@pytest.mark.parametrize("seed", range(400))
def test_probe_restores_everything(seed):
    rng = random.Random(seed)
    g = random_graph(seed, dag=False, n=rng.randint(6, 12))
    g.retier()
    exposure.compute_exposure(g)                       # build the index so it is journaled too
    c = g.clone()                                      # shared storage: the hardest case
    before, before_c = state(g), state(c)
    with c.probe():
        scramble(c, rng)
    assert state(c) == before_c, f"seed {seed}: clone not restored"
    assert state(g) == before, f"seed {seed}: the shared original changed"
    assert exposure.compute_exposure(c).exposed() == exposure_ref.compute_exposure(c).exposed()


def test_probe_restores_on_exception_and_forbids_bulk():
    g = random_graph(3, dag=False)
    g.retier()
    before = state(g)
    with pytest.raises(ValueError):
        with g.probe():
            scramble(g, random.Random(1))
            raise ValueError("boom")
    assert state(g) == before
    with pytest.raises(RuntimeError):
        with g.probe():
            g.add_edges_bulk([])


def test_analysis_never_mutates_the_baseline(corp):
    corp.fast()
    before = state(corp)
    specs, _ = load_changes(inline=["add-member alice HELPDESK", "remove-member bob 'IT ADMINS'", "create user newhire",
                                    "add-member newhire HELPDESK", "grant alice GenericAll dave", "deny alice GenericAll dave"])
    rc, err = resolve_changes(corp, specs)
    assert not err
    analyze_impact(corp, rc)
    assert state(corp) == before
