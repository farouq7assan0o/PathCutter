"""Attacker cost model: effort and noise per edge and per path, and cheapest / stealthiest selection."""
from pathcutter import cost


def test_effort_is_inverse_of_exploitability():
    # DCSync exploitability 10 -> effort 1 (almost free); ConstrainedDelegation exploitability 6 -> effort 5
    assert cost.edge_cost("DCSync")["effort"] == 1
    assert cost.edge_cost("GenericAll")["effort"] == 2        # exploitability 9
    assert cost.edge_cost("CanRDP")["effort"] == 6            # exploitability 5


def test_noise_is_inverse_of_detection_difficulty():
    # DCSync is easy to detect (detection_difficulty low) -> loud; WriteOwner is hard to detect -> quiet
    assert cost.edge_cost("DCSync")["noise"] == 3            # low difficulty = loud
    assert cost.edge_cost("GenericAll")["noise"] == 2       # medium
    assert cost.edge_cost("WriteOwner")["noise"] == 1       # high difficulty = quiet


def test_structural_edges_are_free():
    for et in ("MemberOf", "Contains", "AZContains"):
        c = cost.edge_cost(et)
        assert c["effort"] == 0 and c["noise"] == 0


def test_fragile_follows_the_evidence_assumption_marker():
    # ADCSESC15 assumes an unpatched CA (evidence source assumption:*) -> fragile
    assert cost.edge_cost("ADCSESC15")["fragile"] is True
    # a plain directory ACL is not fragile
    assert cost.edge_cost("GenericAll")["fragile"] is False


def test_plane_classification():
    assert cost.plane("GenericAll") == "ad"
    assert cost.plane("AZResetPassword") == "entra"
    assert cost.plane("AZOwner") == "azure"
    assert cost.plane("AZMGGrantRole") == "msgraph"
    assert cost.plane("SyncedTo") == "bridge"


def test_path_cost_sums_attack_steps_and_ignores_structure():
    edges = ["MemberOf", "GenericAll", "AdminTo"]
    c = cost.path_cost(edges)
    assert c["steps"] == 2                                   # MemberOf is not a step
    assert c["effort"] == cost.edge_cost("GenericAll")["effort"] + cost.edge_cost("AdminTo")["effort"]
    assert c["noise"] == cost.edge_cost("GenericAll")["noise"] + cost.edge_cost("AdminTo")["noise"]


def test_path_cost_flags_cross_plane():
    onprem = cost.path_cost(["GenericAll", "AdminTo"])
    assert onprem["cross_plane"] is False
    crossing = cost.path_cost(["GenericAll", "SyncedTo", "AZResetPassword"])
    assert crossing["cross_plane"] is True


def test_cheapest_prefers_low_effort_short_route():
    short_loud = ["WriteDacl"]                               # 1 step, effort 3
    long_quiet = ["AdminTo", "HasSession", "GenericAll"]     # 3 steps, higher total effort
    chosen, c = cost.cheapest([short_loud, long_quiet])
    assert chosen is short_loud


def test_stealthiest_prefers_low_noise_even_if_longer():
    loud = ["DCSync"]                                        # noise 3
    quiet = ["WriteOwner", "WriteOwner"]                     # noise 1 + 1 = 2
    chosen, c = cost.stealthiest([loud, quiet])
    assert chosen is quiet


def test_rank_respects_profile():
    cheap_loud = ["DCSync"]      # effort 1, noise 3
    dear_quiet = ["WriteOwner"]  # effort 3, noise 1
    opp = cost.rank([cheap_loud, dear_quiet], "opportunist")
    assert opp[0][0] is cheap_loud    # opportunist minimises effort
    stealth = cost.rank([cheap_loud, dear_quiet], "stealth")
    assert stealth[0][0] is dear_quiet  # stealthy actor minimises noise


def test_accepts_step_dicts_and_attackpath():
    from pathcutter.pathfinder import AttackPath
    p = AttackPath(nodes=["a", "b", "c"], edges=[{"edge_type": "MemberOf"}, {"edge_type": "GenericAll"}])
    c = cost.path_cost(p.edges)
    assert c["steps"] == 1
    chosen, _ = cost.cheapest([p])
    assert chosen is p


def test_label_is_readable():
    c = cost.path_cost(["GenericAll", "SyncedTo", "AZResetPassword"])
    text = cost.label(c)
    assert "effort" in text and "noise" in text and "cross-plane" in text
