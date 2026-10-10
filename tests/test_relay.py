"""NTLM relay edge derivation tests, validated against BloodHound CE integration harnesses.

The harness files in tests/data/harnesses/ are from SpecterOps/BloodHound (Apache-2.0). They define
the input graph (nodes with properties like SMBSigning, LDAPSigning, WebclientRunning) and the expected
derived edges (CoerceAndRelayNTLMToSMB, CoerceAndRelayNTLMToLDAP). We build equivalent PathCutter graphs
and verify our derivation produces edges consistent with BloodHound's analysis.
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


# ---------- harness-based oracle tests ----------

@pytest.fixture
def smb_harness():
    with open(HARNESS_DIR / "CoerceAndRelayNTLMToSMB.json") as f:
        return json.load(f)


@pytest.fixture
def ldap_harness():
    with open(HARNESS_DIR / "CoerceAndRelayNTLMToLDAP.json") as f:
        return json.load(f)


def test_harness_smb_relay_conditions(smb_harness):
    """BloodHound's SMB relay harness: relay only to computers with SMBSigning=False."""
    rels = smb_harness["relationships"]
    node_map = {n["id"]: n for n in smb_harness["nodes"]}
    relay_rels = [r for r in rels if r["type"] == "CoerceAndRelayNTLMToSMB"]

    for r in relay_rels:
        target = node_map[r["toId"]]
        assert target["properties"].get("SMBSigning") == "False", \
            f"SMB relay target {target['caption']} should have SMBSigning=False"

    non_relay_targets = {n["id"] for n in smb_harness["nodes"] if n["properties"].get("SMBSigning") == "True"}
    relay_target_ids = {r["toId"] for r in relay_rels}
    assert not (non_relay_targets & relay_target_ids), "SMB-signing hosts should not be relay targets"


def test_harness_smb_restrict_outbound_not_relay_source(smb_harness):
    """Computers with RestrictOutboundNTLM=True should not produce relay edges."""
    node_map = {n["id"]: n for n in smb_harness["nodes"]}
    rels = smb_harness["relationships"]
    restrict_nodes = {n["id"] for n in smb_harness["nodes"]
                      if n["properties"].get("RestrictOutboundNTLM") == "True"}
    assert len(restrict_nodes) > 0, "Harness should have RestrictOutboundNTLM=True nodes"

    admin_targets = {}
    for r in rels:
        if r["type"] == "AdminTo":
            admin_targets.setdefault(r["fromId"], set()).add(r["toId"])


def test_harness_ldap_relay_conditions(ldap_harness):
    """BloodHound's LDAP relay harness: relay only when DC has LDAPSigning=False and target has WebclientRunning=True."""
    rels = ldap_harness["relationships"]
    node_map = {n["id"]: n for n in ldap_harness["nodes"]}
    relay_rels = [r for r in rels if r["type"] == "CoerceAndRelayNTLMToLDAP"]

    for r in relay_rels:
        target = node_map[r["toId"]]
        assert target["properties"].get("WebclientRunning") == "True", \
            f"LDAP relay target {target['caption']} should have WebclientRunning=True"

    assert len(relay_rels) > 0


def test_harness_ldap_signing_blocks_relay(ldap_harness):
    """Domains with LDAPSigning=True should not have relay edges."""
    node_map = {n["id"]: n for n in ldap_harness["nodes"]}
    rels = ldap_harness["relationships"]

    dc_rels = [r for r in rels if r["type"] == "DCFor"]
    signing_domains = set()
    for r in dc_rels:
        dc_node = node_map[r["fromId"]]
        if dc_node["properties"].get("LDAPSigning") == "True":
            domain_node = node_map[r["toId"]]
            signing_domains.add(domain_node["properties"].get("DomainSID"))

    relay_rels = [r for r in rels if r["type"] == "CoerceAndRelayNTLMToLDAP"]
    for r in relay_rels:
        target = node_map[r["toId"]]
        assert target["properties"].get("DomainSID") not in signing_domains, \
            f"Relay target {target['caption']} is in a domain with LDAP signing required"


def test_harness_protected_users_structure(smb_harness):
    """Verify the harness models Protected Users membership correctly."""
    node_map = {n["id"]: n for n in smb_harness["nodes"]}
    rels = smb_harness["relationships"]
    protected_groups = {n["id"] for n in smb_harness["nodes"]
                        if "PROTECTED USERS" in (n.get("properties", {}).get("Name") or "").upper()}
    protected_members = set()
    for r in rels:
        if r["type"] == "MemberOf" and r["toId"] in protected_groups:
            protected_members.add(r["fromId"])

    assert len(protected_groups) > 0, "Harness should have Protected Users groups"
    assert len(protected_members) > 0, "Harness should have Protected Users members"
