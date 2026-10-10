"""NTLM relay edge derivation (experimental, NOT applied at load time: see pathcutter/relay.py).

Unit tests on hand-built graphs, then the BloodHound CE integration harnesses in tests/data/harnesses/ (SpecterOps/BloodHound,
Apache-2.0): each harness is an input graph plus the edges BloodHound derives from it. The harness tests build that graph,
RUN `derive_relay_edges` and compare. Known disagreements are strict xfails, so they turn into failures the moment they are
fixed and the marker has to go.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from pathcutter.graph import AttackGraph, ADNode, ADEdge, NodeType
from pathcutter.relay import derive_relay_edges

HARNESS_DIR = Path(__file__).parent / "data" / "harnesses"
DSID = "S-1-5-21-1-2-3"
DOM = "TEST.LOCAL"


def _g() -> AttackGraph:
    return AttackGraph()


def _base_graph(ldapsigning=True, smbsigning_targets=None, webclient_targets=None):
    """Build a standard test graph with a domain, DC, auth users, and target computers."""
    g = _g()
    g.add_node(ADNode(object_id=DOM, name=DOM, node_type=NodeType.DOMAIN,
                       properties={"domainsid": DSID}))
    g.add_node(ADNode(object_id=f"{DSID}-1001", name="DC01$", node_type=NodeType.COMPUTER,
                       properties={"domainsid": DSID, "isdc": True,
                                   "smbsigning": True, "ldapsigning": ldapsigning}))
    g.add_node(ADNode(object_id=f"{DOM}-S-1-5-11", name=f"AUTHENTICATED USERS@{DOM}",
                       node_type=NodeType.GROUP, properties={"domainsid": DSID}))
    g.add_node(ADNode(object_id=f"{DSID}-516", name=f"DOMAIN CONTROLLERS@{DOM}",
                       node_type=NodeType.GROUP, properties={"domainsid": DSID}))
    g.add_edge(ADEdge(source_id=f"{DSID}-1001", target_id=f"{DSID}-516",
                       edge_type="MemberOf", properties={}))

    for i, smb in enumerate(smbsigning_targets or []):
        cid = f"{DSID}-{2001 + i}"
        wc = (webclient_targets or {}).get(i, False)
        g.add_node(ADNode(object_id=cid, name=f"SRV{i:02d}$", node_type=NodeType.COMPUTER,
                           properties={"domainsid": DSID, "smbsigning": smb,
                                       "webclientrunning": wc}))
    return g


# ---------- unit tests for the derivation logic ----------

def test_smb_relay_unsigned_target():
    g = _base_graph(smbsigning_targets=[False, True])
    added = derive_relay_edges(g)
    smb_edges = [(s, t) for s, t, d in g.all_edges() if d.get("edge_type") == "CoerceAndRelayNTLMToSMB"]
    assert len(smb_edges) == 1
    assert smb_edges[0][1] == f"{DSID}-2001"


def test_smb_relay_skips_dcs():
    g = _g()
    g.add_node(ADNode(object_id=DOM, name=DOM, node_type=NodeType.DOMAIN,
                       properties={"domainsid": DSID}))
    g.add_node(ADNode(object_id=f"{DSID}-1001", name="DC01$", node_type=NodeType.COMPUTER,
                       properties={"domainsid": DSID, "isdc": True, "smbsigning": False}))
    g.add_node(ADNode(object_id=f"{DOM}-S-1-5-11", name=f"AUTHENTICATED USERS@{DOM}",
                       node_type=NodeType.GROUP, properties={"domainsid": DSID}))
    g.add_node(ADNode(object_id=f"{DSID}-516", name=f"DOMAIN CONTROLLERS@{DOM}",
                       node_type=NodeType.GROUP, properties={"domainsid": DSID}))
    g.add_edge(ADEdge(source_id=f"{DSID}-1001", target_id=f"{DSID}-516",
                       edge_type="MemberOf", properties={}))
    assert derive_relay_edges(g) == 0


def test_ldap_relay_webclient_and_unsigned_dc():
    g = _base_graph(ldapsigning=False, smbsigning_targets=[True, True],
                    webclient_targets={0: True, 1: False})
    added = derive_relay_edges(g)
    ldap_edges = [(s, t) for s, t, d in g.all_edges() if d.get("edge_type") == "CoerceAndRelayNTLMToLDAP"]
    assert len(ldap_edges) == 1
    assert ldap_edges[0][1] == f"{DSID}-2001"


def test_ldap_relay_requires_unsigned_dc():
    g = _base_graph(ldapsigning=True, smbsigning_targets=[True],
                    webclient_targets={0: True})
    assert derive_relay_edges(g) == 0


def test_no_relay_without_auth_users_node():
    g = _g()
    g.add_node(ADNode(object_id=DOM, name=DOM, node_type=NodeType.DOMAIN,
                       properties={"domainsid": DSID}))
    g.add_node(ADNode(object_id=f"{DSID}-1001", name="DC01$", node_type=NodeType.COMPUTER,
                       properties={"domainsid": DSID, "isdc": True, "ldapsigning": False}))
    g.add_node(ADNode(object_id=f"{DSID}-1002", name="SRV01$", node_type=NodeType.COMPUTER,
                       properties={"domainsid": DSID, "smbsigning": False, "webclientrunning": True}))
    g.add_node(ADNode(object_id=f"{DSID}-516", name=f"DOMAIN CONTROLLERS@{DOM}",
                       node_type=NodeType.GROUP, properties={"domainsid": DSID}))
    g.add_edge(ADEdge(source_id=f"{DSID}-1001", target_id=f"{DSID}-516",
                       edge_type="MemberOf", properties={}))
    assert derive_relay_edges(g) == 0


def test_combined_smb_and_ldap_relay():
    g = _base_graph(ldapsigning=False, smbsigning_targets=[False],
                    webclient_targets={0: True})
    added = derive_relay_edges(g)
    assert added == 2
    edge_types = {d.get("edge_type") for _, _, d in g.all_edges() if "Relay" in d.get("edge_type", "")}
    assert edge_types == {"CoerceAndRelayNTLMToSMB", "CoerceAndRelayNTLMToLDAP"}


# ---------- harness oracle: build the harness graph, run the derivation, compare with BloodHound's edges ----------

def _harness_graph(name: str, kind: str):
    d = json.loads((HARNESS_DIR / f"{name}.json").read_text())
    g = AttackGraph()
    ids = {}
    for n in d["nodes"]:
        p, cap = n["properties"], n["caption"]
        nt = NodeType.COMPUTER if cap.startswith("Computer") else NodeType.DOMAIN if cap.startswith("Domain") else NodeType.GROUP
        oid = p["ObjectID"] if nt == NodeType.GROUP and p.get("ObjectID") else cap
        ids[n["id"]] = oid
        props = {k.lower(): (True if v == "True" else False if v == "False" else v) for k, v in p.items()}
        props["domainsid"] = p.get("DomainSID", "")
        g.add_node(ADNode(object_id=oid, name=p.get("Name") or cap, node_type=nt, properties=props))
    expected = set()
    for r in d["relationships"]:
        a, b, t = ids[r["fromId"]], ids[r["toId"]], r["type"]
        if t == kind:
            expected.add((a, b))
        elif t in ("MemberOf", "AdminTo"):
            g.add_edge(ADEdge(source_id=a, target_id=b, edge_type=t, properties={}))
        elif t == "DCFor":
            g.get_node(a).properties["isdc"] = True
    return g, expected


def _derived(g, kind):
    derive_relay_edges(g)
    return {(u, v) for u, v, d in g.all_edges() if d.get("edge_type") == kind}


@pytest.mark.parametrize("name,kind", [("CoerceAndRelayNTLMToSMB", "CoerceAndRelayNTLMToSMB"),
                                       ("CoerceAndRelayNTLMToLDAP", "CoerceAndRelayNTLMToLDAP")])
def test_every_edge_bloodhound_derives_is_derived(name, kind):
    g, expected = _harness_graph(name, kind)
    assert expected and expected <= _derived(g, kind), "a relay path BloodHound finds is missed"


@pytest.mark.xfail(strict=True, reason="over-reports: ignores Protected Users (functional level >= 2012R2) and RestrictOutboundNTLM")
@pytest.mark.parametrize("name,kind", [("CoerceAndRelayNTLMToSMB", "CoerceAndRelayNTLMToSMB"),
                                       ("CoerceAndRelayNTLMToLDAP", "CoerceAndRelayNTLMToLDAP")])
def test_no_edge_bloodhound_does_not_derive(name, kind):
    g, expected = _harness_graph(name, kind)
    assert _derived(g, kind) == expected


def test_relay_is_not_applied_at_load_time():
    """It over-reports, so it must not change exposure scores until the xfail above passes."""
    import inspect
    from pathcutter import ingest
    assert "derive_relay_edges" not in inspect.getsource(ingest._finish)
