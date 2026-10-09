"""Randomized proof: the production engine and the gate vs an independent brute-force oracle.

Thousands of random graphs are cheap, and they find the cases a hand-written fixture never thinks of.
Seeds are fixed so a failure is reproducible: the assertion message prints the seed.
"""
import itertools
import random
import shlex

import pytest

from oracle import oracle_hops
from pathcutter.changes import load_changes, resolve_changes
from pathcutter.exposure import compute_exposure
from pathcutter.graph import ADEdge, ADNode, AttackGraph, NodeType
from pathcutter.impact import analyze_impact
from pathcutter.policy import Policy, evaluate

EDGES = ["MemberOf", "MemberOf", "MemberOf", "GenericAll", "WriteDacl", "AdminTo", "ForceChangePassword",
         "Contains", "HasSession", "GenericWrite"]
ATTACK = ["GenericAll", "WriteDacl", "ForceChangePassword", "GenericWrite"]   # valid between any two objects


def random_graph(seed: int, dag: bool, n: int | None = None, p: float = 0.28) -> AttackGraph:
    rng = random.Random(seed)
    n = n or rng.randint(5, 10)
    g = AttackGraph()
    for i in range(n - 2):
        g.add_node(ADNode(f"id{i}", f"G{i}@X", NodeType.GROUP, "x"))
    g.add_node(ADNode(f"id{n - 2}", "DOMAIN ADMINS@X", NodeType.GROUP, "x"))
    g.add_node(ADNode(f"id{n - 1}", "ENTERPRISE ADMINS@X", NodeType.GROUP, "x"))
    for i in range(n):
        for j in range(n):
            if i == j or (dag and j < i):
                continue
            if rng.random() < p:
                g.add_edge(ADEdge(f"id{i}", f"id{j}", rng.choice(EDGES)))
    g.classify_tiers()
    return g


def name(g, node_id):
    return g.get_node(node_id).display_name


def exposed_by_oracle(g):
    c = g.clone()
    c.retier()
    return set(oracle_hops(c)), set(c.tier0_nodes)


# ----------------------------------------------------- engine == brute force

@pytest.mark.parametrize("seed", range(600))
def test_engine_equals_bruteforce_on_random_dags(seed):
    g = random_graph(seed, dag=True)
    exp = compute_exposure(g)
    assert {n: exp.hops(n) for n in exp.exposed()} == oracle_hops(g), f"seed {seed}"


@pytest.mark.parametrize("seed", range(600, 2100))
def test_engine_equals_bruteforce_on_dense_cyclic_graphs(seed):
    """Cycles are where a walk-based search can disagree with real (simple) attack paths. The engine
    re-verifies those cases exactly, so it must match the brute-force oracle on cyclic graphs too."""
    g = random_graph(seed, dag=False)
    exp = compute_exposure(g)
    assert not exp.unverified, f"seed {seed}: verification budget exhausted on a tiny graph"
    assert {n: exp.hops(n) for n in exp.exposed()} == oracle_hops(g), f"seed {seed}"


def test_walk_only_exposure_is_really_removed():
    """u -MemberOf-> v, v -GenericAll-> u (a cycle), v -Contains-> DOMAIN ADMINS.
    The only walk that contains an attack edge loops u -> v -> u -> v -> DA, which a real attacker cannot
    use: the simple routes (u -> v -> DA and v -> DA) contain no attack edge. A walk-based search reports
    both u and v; the exact re-check must drop them."""
    g = AttackGraph()
    g.add_node(ADNode("u", "U@X", NodeType.USER, "x"))
    g.add_node(ADNode("v", "V@X", NodeType.GROUP, "x"))
    g.add_node(ADNode("da", "DOMAIN ADMINS@X", NodeType.GROUP, "x"))
    g.add_edge(ADEdge("u", "v", "MemberOf"))
    g.add_edge(ADEdge("v", "u", "GenericAll"))
    g.add_edge(ADEdge("v", "da", "Contains"))
    g.classify_tiers()
    assert g.get_node("u").tier == 2 and g.get_node("v").tier == 2
    assert compute_exposure(g, verify=False).exposed() == {"u", "v"}     # what a pure walk search would say
    exp = compute_exposure(g)
    assert exp.exposed() == set() and exp.removed == {"u", "v"}


def test_cyclic_exposure_with_a_real_simple_path_is_kept_with_the_true_length():
    g = AttackGraph()
    for i, n in [("u", "U@X"), ("v", "V@X"), ("w", "W@X")]:
        g.add_node(ADNode(i, n, NodeType.GROUP, "x"))
    g.add_node(ADNode("da", "DOMAIN ADMINS@X", NodeType.GROUP, "x"))
    g.add_edge(ADEdge("u", "v", "MemberOf"))
    g.add_edge(ADEdge("v", "u", "GenericAll"))         # loops back: useless
    g.add_edge(ADEdge("v", "w", "GenericAll"))         # the real way out
    g.add_edge(ADEdge("w", "da", "MemberOf"))
    exp = compute_exposure(g)
    assert exp.hops("u") == 3 and exp.hops("v") == 2
    assert [s.node_id for s in exp.path("u")] == ["u", "v", "w", "da"]


def test_paths_returned_by_the_engine_are_real(subtests=None):
    for seed in range(300):
        g = random_graph(seed, dag=False)
        exp = compute_exposure(g)
        t0 = g.tier0_nodes
        for n in exp.exposed():
            steps = exp.path(n)
            assert steps[0].node_id == n and steps[-1].node_id in t0, f"seed {seed}"
            assert len(steps) - 1 == exp.hops(n), f"seed {seed}"
            for a, b in zip(steps, steps[1:]):
                assert g.has_edge_type(a.node_id, b.node_id, a.edge_type), f"seed {seed}: fabricated edge"


# --------------------------------------------------------- gate properties

def random_change(rng, g):
    ids = sorted(g.graph.nodes, key=str)
    n = len(ids)
    a, b = sorted(rng.sample(range(n), 2))                   # a < b keeps a DAG a DAG
    src, dst = name(g, f"id{a}"), name(g, f"id{b}")
    if rng.random() < 0.5:
        return f'add-member "{src}" "{dst}"'
    return f'grant "{src}" {rng.choice(ATTACK)} "{dst}"'


def run(g, lines, policy=None):
    specs, _ = load_changes(inline=lines)
    resolved, errors = resolve_changes(g, specs)
    assert not errors, errors
    report = analyze_impact(g, resolved)
    evaluate(report, policy or Policy(), resolved)
    return report, resolved


def apply_manually(g, lines):
    """Apply changes with plain graph calls (not the production apply path) and re-tier."""
    c = g.clone()
    for line in lines:
        verb, *rest = shlex.split(line)
        if verb == "add-member":
            src, dst, et = rest[0], rest[1], "MemberOf"
        else:
            src, et, dst = rest
        ids = {n.display_name: n.object_id for n in c.all_nodes()}
        c.add_edge(ADEdge(ids[src], ids[dst], et))
    c.retier()
    return c


@pytest.mark.parametrize("seed", range(250))
def test_gate_totals_equal_the_oracle_diff(seed):
    g = random_graph(seed, dag=True)
    rng = random.Random(seed * 7 + 1)
    lines = [random_change(rng, g) for _ in range(rng.randint(1, 3))]
    report, _ = run(g, lines)
    after = apply_manually(g, lines)
    exp_b, t0_b = exposed_by_oracle(g)
    exp_a, t0_a = exposed_by_oracle(after)
    promoted = t0_a - t0_b
    demoted = t0_b - t0_a
    assert report.totals["promoted"] == len(promoted), f"seed {seed} {lines}"
    assert report.totals["newly_exposed"] == len(exp_a - exp_b - promoted - demoted), f"seed {seed} {lines}"
    assert report.totals["newly_secured"] == len(exp_b - exp_a - promoted), f"seed {seed} {lines}"


@pytest.mark.parametrize("seed", range(150))
def test_the_baseline_is_never_modified(seed):
    g = random_graph(seed, dag=True)
    edges = sorted((u, v, d["edge_type"]) for u, v, d in g.all_edges())
    tiers = {n.object_id: n.tier for n in g.all_nodes()}
    rng = random.Random(seed)
    run(g, [random_change(rng, g) for _ in range(3)])
    assert sorted((u, v, d["edge_type"]) for u, v, d in g.all_edges()) == edges
    assert {n.object_id: n.tier for n in g.all_nodes()} == tiers


@pytest.mark.parametrize("seed", range(150))
def test_rechecking_an_applied_change_is_a_noop(seed):
    g = random_graph(seed, dag=True)
    rng = random.Random(seed + 99)
    lines = [random_change(rng, g)]
    applied = apply_manually(g, lines)
    report, _ = run(applied, lines)
    assert all(f.kind == "NOOP" for f in report.findings) or not report.findings
    assert report.totals["newly_exposed"] == 0 and report.totals["promoted"] == 0 and report.verdict == "pass"


@pytest.mark.parametrize("seed", range(120))
def test_result_does_not_depend_on_change_order(seed):
    g = random_graph(seed, dag=True)
    rng = random.Random(seed + 5)
    lines = list({random_change(rng, g) for _ in range(3)})
    keys = ("newly_exposed", "promoted", "newly_secured", "shortened")
    baseline = None
    for perm in itertools.permutations(lines):
        report, _ = run(g, list(perm))
        got = tuple(report.totals[k] for k in keys)
        baseline = baseline or got
        assert got == baseline, f"seed {seed}: order changed the result for {perm}"


@pytest.mark.parametrize("seed", range(250))
def test_fix_first_really_neutralises_the_exposure(seed):
    """If the gate claims its suggested fixes break 100% of the new paths, then removing exactly those
    edges from the baseline must leave none of the flagged objects exposed by the same change."""
    g = random_graph(seed, dag=True, p=0.3)
    rng = random.Random(seed + 3)
    lines = [random_change(rng, g)]
    report, resolved = run(g, lines)
    for f in report.findings:
        if f.kind != "NEW_EXPOSURE" or f.superseded or not f.fix_first or f.fix_first[-1]["cumulative_pct"] < 100:
            continue
        fixed = g.clone()
        ids = {n.display_name: n.object_id for n in fixed.all_nodes()}
        for fx in f.fix_first:
            removed = fixed.remove_edge(ids[fx["source"].split("@")[0]], ids[fx["target"].split("@")[0]], fx["edge_type"])
            assert removed, f"seed {seed}: suggested edge does not exist"
        fixed.retier()
        after = apply_manually(fixed, lines)
        still, _ = exposed_by_oracle(after)
        assert not (set(f.ids) & still), f"seed {seed}: {set(f.ids) & still} still exposed after the suggested fix"


@pytest.mark.parametrize("seed", range(100))
def test_fix_first_never_proposes_undoing_the_change_itself(seed):
    g = random_graph(seed, dag=True, p=0.3)
    rng = random.Random(seed + 11)
    line = random_change(rng, g)
    report, resolved = run(g, [line])
    rc = resolved[0]
    for f in report.findings:
        for fx in f.fix_first:
            same = (fx["edge_type"] == rc.spec.edge_type and fx["source"].startswith(rc.source_name)
                    and fx["target"].startswith(rc.target_name))
            assert not same, f"seed {seed}: suggested removing the change's own edge"
