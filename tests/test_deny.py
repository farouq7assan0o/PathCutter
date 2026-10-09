"""Deny ACEs: identity-sensitive exposure, proven against a brute-force forward oracle."""
import random

import pytest

from pathcutter.exposure import compute_exposure
from pathcutter.graph import ADEdge, ADNode, AttackGraph, Deny, NodeType
from pathcutter.pathfinder import _ATTACK_EDGES

from test_proof_random import random_graph


def oracle_hops_deny(g):
    """Forward DFS over SIMPLE paths, tracking the landing identity; shortest path containing an attack edge."""
    entries = g.deny_actor_sets()
    tier0 = set(g.tier0_nodes)
    out = {}
    for u, v, d in g.all_edges():
        out.setdefault(u, []).append((v, d["edge_type"]))

    def denied(identity, target, et):
        return any(d.target_id == target and d.edge_type == et and identity in actors for d, actors in entries)

    best = {}
    for start in g.graph.nodes:
        if start in tier0:
            continue
        found = [None]

        def dfs(node, identity, seen, attack, depth):
            if found[0] is not None and depth >= found[0]:
                return
            for v, et in out.get(node, []):
                if v in seen:
                    continue
                if et != "MemberOf" and denied(identity, v, et):
                    continue
                atk = attack or et in _ATTACK_EDGES
                if v in tier0:
                    if atk and (found[0] is None or depth + 1 < found[0]):
                        found[0] = depth + 1
                    continue
                seen.add(v)
                dfs(v, identity if et == "MemberOf" else v, seen, atk, depth + 1)
                seen.discard(v)

        dfs(start, start, {start}, False, 0)
        if found[0] is not None:
            best[start] = found[0]
    return best


def add_random_denies(g, seed):
    rng = random.Random(seed * 7919 + 1)
    ids = list(g.graph.nodes)
    edges = [(u, v, d["edge_type"]) for u, v, d in g.all_edges() if d["edge_type"] not in ("MemberOf", "Contains")]
    for _ in range(rng.randint(1, 3)):
        if not edges:
            break
        _, v, et = rng.choice(edges)
        g.denies.add(Deny(rng.choice(ids), et, v))
    return g


@pytest.mark.parametrize("seed", range(1500))
def test_deny_exposure_equals_bruteforce(seed):
    g = add_random_denies(random_graph(seed, dag=(seed % 3 == 0)), seed)
    exp = compute_exposure(g)
    assert not exp.unverified
    assert {n: exp.hops(n) for n in exp.exposed()} == oracle_hops_deny(g), f"seed {seed}"


def test_denies_actually_change_results():
    changed = 0
    for seed in range(300):
        g = random_graph(seed, dag=True)
        base = {n for n in compute_exposure(g).exposed()}
        add_random_denies(g, seed)
        if {n for n in compute_exposure(g).exposed()} != base:
            changed += 1
    assert changed > 20, "the random harness never exercised a deny that mattered"


def chain():
    """alice -> HELP (member) -GenericAll-> svc -> DOMAIN ADMINS ; bob is also in HELP and in DENYME."""
    g = AttackGraph()
    for i, n, t in [("alice", "ALICE@X", NodeType.USER), ("bob", "BOB@X", NodeType.USER), ("help", "HELP@X", NodeType.GROUP),
                    ("denyme", "DENYME@X", NodeType.GROUP), ("svc", "SVC@X", NodeType.USER),
                    ("da", "DOMAIN ADMINS@X", NodeType.GROUP)]:
        g.add_node(ADNode(i, n, t, "x"))
    for a, b, e in [("alice", "help", "MemberOf"), ("bob", "help", "MemberOf"), ("bob", "denyme", "MemberOf"),
                    ("help", "svc", "GenericAll"), ("svc", "da", "MemberOf")]:
        g.add_edge(ADEdge(a, b, e))
    g.classify_tiers()
    return g


def test_deny_blocks_only_the_denied_identity():
    g = chain()
    assert compute_exposure(g).exposed() >= {"alice", "bob", "help"}  # svc is a DA member, so Tier 0
    g.denies.add(Deny("denyme", "GenericAll", "svc"))
    exp = compute_exposure(g)
    assert "bob" not in exp.exposed(), "bob is in the denied group: the allow via HELP no longer works for him"
    assert {"alice", "help"} <= exp.exposed(), "everyone else keeps the right"
    assert exp.hops("alice") == 2
    assert [s.node_id for s in exp.path("alice")] == ["alice", "help", "svc"]
    assert exp.path("bob") == []


def test_deny_does_not_follow_the_attacker_to_a_new_identity():
    """bob is denied GenericAll on svc, but he can take over alice (a different identity) and use HELP as her."""
    g = chain()
    g.add_edge(ADEdge("bob", "alice", "ForceChangePassword"))
    g.denies.add(Deny("denyme", "GenericAll", "svc"))
    exp = compute_exposure(g)
    assert "bob" in exp.exposed() and exp.hops("bob") == 3
    assert [s.node_id for s in exp.path("bob")][:2] == ["bob", "alice"]


def test_deny_on_a_missing_edge_is_ignored_and_clone_keeps_denies():
    g = chain()
    g.denies.add(Deny("denyme", "WriteDacl", "svc"))
    assert not g.deny_actor_sets()
    g.denies.add(Deny("denyme", "GenericAll", "svc"))
    assert len(g.clone().deny_actor_sets()) == 1
