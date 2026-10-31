"""Derived views: protect-first leaderboard and the unfixable-and-blind intersection."""
from pathcutter import toprisk
from pathcutter.choke import Fix
from pathcutter.graph import ADNode, AttackGraph, NodeType
from pathcutter.pathfinder import AttackPath, PathReport
from pathcutter.scoring import NodeRisk


def _nr(name, ntype, tier, reach, paths=1, risk=10.0):
    return NodeRisk(node_id=name, name=name, node_type=ntype, tier=tier, path_count=paths,
                    centrality=0.0, blast_radius=0, tier0_reach=reach, risk_score=risk)


def test_protect_leaderboard_ranks_actors_by_tier0_reach():
    scores = [
        _nr("WS01", "Computer", 2, reach=9, paths=5),
        _nr("ALICE", "User", 2, reach=12, paths=3),
        _nr("DA-GROUP", "Group", 0, reach=40),        # Tier 0 -> excluded
        _nr("GROUPX", "Group", 2, reach=99),          # not an actor type -> excluded
        _nr("BOB", "User", 2, reach=0),               # reaches no Tier 0 -> excluded
    ]
    lb = toprisk.protect_leaderboard(scores, top=10)
    assert [x["name"] for x in lb] == ["ALICE", "WS01"]       # by tier0_reach desc
    assert lb[0]["tier0_reach"] == 12


def _path(nodes, edges):
    return AttackPath(nodes=nodes, edges=[{"edge_type": e} for e in edges])


def test_blind_spots_is_the_intersection():
    g = AttackGraph()
    for nid in ("a", "b", "c", "dom"):
        g.add_node(ADNode(nid, nid.upper() + "@C.L",
                          NodeType.DOMAIN if nid == "dom" else NodeType.USER, "C.L"))
    # path0: a -GenericAll-> dom  (cut by the fix below)
    # path1: b -WriteDacl-> dom   (NOT cut) and blind  -> a silent blind spot
    # path2: c -Owns-> dom        (NOT cut) but visible -> not blind, excluded
    report = PathReport(paths=[_path(["a", "dom"], ["GenericAll"]),
                               _path(["b", "dom"], ["WriteDacl"]),
                               _path(["c", "dom"], ["Owns"])])
    fixes = [Fix("a", "dom", "GenericAll", "A", "DOM", 1, 1, 50.0, "# fix", "T1222.001", 1)]
    status = ["blind", "blind", "visible"]
    bs = toprisk.blind_spots(g, report, fixes, status)
    assert bs["count"] == 1
    assert bs["groups"][0]["source"] == "B" and "WriteDacl" in bs["groups"][0]["edges"]


def test_blind_spots_empty_when_all_blind_paths_are_fixable():
    g = AttackGraph()
    g.add_node(ADNode("a", "A@C.L", NodeType.USER, "C.L"))
    g.add_node(ADNode("dom", "C.L", NodeType.DOMAIN, "C.L"))
    report = PathReport(paths=[_path(["a", "dom"], ["GenericAll"])])
    fixes = [Fix("a", "dom", "GenericAll", "A", "DOM", 1, 1, 100.0, "# fix", "", 1)]
    assert toprisk.blind_spots(g, report, fixes, ["blind"])["count"] == 0
