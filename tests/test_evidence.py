"""Edge evidence: where an edge came from and what it assumes, and a path being only as strong as its weakest step."""
from pathcutter.evidence import edge_confidence, finding_confidence, path_confidence
from pathcutter.graph import ADEdge, ADNode, AttackGraph, NodeType
from pathcutter.exposure import compute_exposure


def test_directory_facts_are_high():
    assert edge_confidence("GenericAll")[0] == "high"
    assert edge_confidence("AdminTo")[0] == "high"


def test_derived_and_assumed_are_not_high():
    assert edge_confidence("ADCSESC1")[0] == "medium"
    assert edge_confidence("ADCSESC15")[0] == "low"
    assert edge_confidence("AZEligibleRole")[0] == "low"


def test_a_session_gets_more_trustworthy_each_time_it_is_seen():
    assert [edge_confidence("HasSession", {"seen": n})[0] for n in (1, 2, 3, 9)] == ["low", "medium", "high", "high"]


def test_synthesised_unconstrained_delegation_link_is_an_assumption():
    assert edge_confidence("AllowedToDelegate", {"basis": "unconstrained-delegation"})[0] == "low"
    assert edge_confidence("AllowedToDelegate")[0] == "high"          # a real msDS-AllowedToDelegateTo entry


def test_proposed_changes_are_labelled():
    assert edge_confidence("MemberOf", {"proposed": True})[1] == "proposed:change"


def test_path_is_as_strong_as_its_weakest_step_and_structure_is_ignored():
    c = path_confidence([{"edge_type": "MemberOf"}, {"edge_type": "GenericAll"}, {"edge_type": "ADCSESC15"}])
    assert c["level"] == "low" and c["edge"] == "ADCSESC15"
    assert path_confidence([{"edge_type": "MemberOf"}])["level"] == "high"


def test_finding_confidence_takes_the_most_certain_route():
    weak = [{"edge": "ADCSESC15", "conf": {"level": "low", "source": "a", "reason": "r"}}, {"edge": None}]
    strong = [{"edge": "GenericAll", "conf": {"level": "high", "source": "b", "reason": ""}}, {"edge": None}]
    assert finding_confidence([weak])["level"] == "low"
    assert finding_confidence([weak, strong])["level"] == "high"
    assert finding_confidence([])["level"] == "high"


def test_ingest_marks_the_unconstrained_link(tmp_path):
    import json
    from pathcutter.ingest import _link_unconstrained_delegation
    g = AttackGraph()
    g.add_node(ADNode("dc1", "DC1.X.LOCAL", NodeType.COMPUTER, "X.LOCAL", properties={"isdc": True}))
    g.add_node(ADNode("web", "WEB.X.LOCAL", NodeType.COMPUTER, "X.LOCAL", properties={"unconstraineddelegation": True}))
    _link_unconstrained_delegation(g)
    [(u, v, d)] = [(u, v, d) for u, v, d in g.all_edges() if d["edge_type"] == "AllowedToDelegate"]
    assert (u, v, d.get("basis")) == ("web", "dc1", "unconstrained-delegation")
    assert edge_confidence("AllowedToDelegate", d)[0] == "low"


def test_check_report_shows_trust_on_a_weak_finding(tmp_path):
    from pathcutter.impact import Finding
    f = Finding(id="F1", kind="NEW_EXPOSURE", severity="high", title="t", detail="d",
                paths=[[{"edge": "ADCSESC15", "conf": {"level": "low", "source": "assumption:unpatched-ca",
                                                       "reason": "assumes the CA has not been patched for CVE-2024-49019"}}, {"edge": None}]])
    d = f.to_dict()
    assert d["confidence"]["level"] == "low" and d["confidence"]["edge"] == "ADCSESC15"
