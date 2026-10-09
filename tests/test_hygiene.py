"""pathcutter audit: each rule on a constructed graph, then real data and the CLI."""
from pathlib import Path

import pytest

from pathcutter.cli import main
from pathcutter.graph import ADEdge, ADNode, AttackGraph, NodeType
from pathcutter.hygiene import audit

REAL = Path(__file__).parent / "data" / "real" / "specterops_ad_sampledata.zip"
NOW = 1_700_000_000
DAY = 86400


def g_with(*nodes, edges=()):
    g = AttackGraph()
    g.add_node(ADNode("da", "DOMAIN ADMINS@X.LOCAL", NodeType.GROUP, "X.LOCAL"))
    for n in nodes:
        g.add_node(n)
    for e in edges:
        g.add_edge(ADEdge(*e))
    g.classify_tiers()
    return g


def user(i, name, **props):
    return ADNode(i, f"{name}@X.LOCAL", NodeType.USER, "X.LOCAL", admin_count=props.pop("admin", False),
                  enabled=props.pop("enabled", True), properties={"lastlogontimestamp": NOW, **props})


def comp(i, name, **props):
    return ADNode(i, f"{name}.X.LOCAL", NodeType.COMPUTER, "X.LOCAL", properties={"lastlogontimestamp": NOW, **props})


def rules(g):
    return {f.rule: f for f in audit(g)}


def test_kerberoast_severity_depends_on_privilege():
    g = g_with(user("a", "SVC", hasspn=True), user("b", "ADM", hasspn=True, admin=True), user("c", "OFF", hasspn=True, enabled=False),
               user("k", "KRBTGT", hasspn=True), user("m", "GM", hasspn=True, gmsa=True))
    r = rules(g)
    assert r["kerberoast"].objects == ["SVC"] and r["kerberoast"].severity == "medium"
    assert r["kerberoast-privileged"].objects == ["ADM"] and r["kerberoast-privileged"].severity == "critical"


def test_asrep_passwd_notreqd_and_never_expires():
    g = g_with(user("a", "ROAST", dontreqpreauth=True), user("b", "NOPW", passwordnotreqd=True),
               user("c", "FOREVER", pwdneverexpires=True, admin=True), user("d", "FINE", pwdneverexpires=True))
    r = rules(g)
    assert r["asrep"].objects == ["ROAST"] and r["passwd-notreqd"].objects == ["NOPW"]
    assert r["priv-pwd-never-expires"].objects == ["FOREVER"]


@pytest.mark.parametrize("text,hit", [("Password: Summer2024!", True), ("pwd=abc123", True), ("temp password is Welcome1", True),
                                      ("Service account for backups", False), ("Passwords are rotated monthly", False)])
def test_password_in_description(text, hit):
    r = rules(g_with(user("a", "U", description=text)))
    assert ("pwd-in-description" in r) is hit


def test_credential_attributes_and_sid_history():
    r = rules(g_with(user("a", "UNIX", unixpassword="b64stuff"), user("b", "MIG", sidhistory=["S-1-5-21-9-9-9-500"]), user("c", "CLEAN")))
    assert r["pwd-attributes"].objects == ["UNIX"] and r["sid-history"].objects == ["MIG"]


def test_time_based_rules_use_the_collection_clock():
    g = g_with(user("a", "OLDADM", admin=True, lastlogontimestamp=NOW - 200 * DAY), user("b", "NEWADM", admin=True),
               user("k", "KRBTGT", pwdlastset=NOW - 400 * DAY), comp("c1", "OLDPC", lastlogontimestamp=NOW - 120 * DAY), comp("c2", "NEWPC"))
    r = rules(g)
    assert r["stale-privileged"].objects == ["OLDADM"]
    assert r["krbtgt-old"].objects == ["KRBTGT"]
    assert r["stale-computers"].objects == ["OLDPC.X.LOCAL"]


def test_delegation_and_os_and_laps():
    g = g_with(comp("a", "WEB", unconstraineddelegation=True, operatingsystem="Windows Server 2008 R2", haslaps=False),
               comp("b", "DC1", unconstraineddelegation=True, isdc=True, haslaps=False), comp("c", "OK", operatingsystem="Windows Server 2022", haslaps=True),
               comp("d", "NODATA"), user("u", "PT", trustedtoauth=True))
    r = rules(g)
    assert r["unconstrained-delegation"].objects == ["WEB.X.LOCAL"], "domain controllers are expected to be trusted for delegation"
    assert r["old-os"].objects == ["WEB.X.LOCAL"]
    assert r["no-laps"].objects == ["WEB.X.LOCAL"], "uncollected LAPS data is not evidence of missing LAPS; DCs are exempt"
    assert r["protocol-transition"].objects == ["PT"]


def test_orphaned_admincount_and_unprotected_tier0():
    g = g_with(user("a", "ORPHAN", admin=True), user("b", "REALADM", admin=True), user("c", "SAFE", sensitive=True),
               edges=[("b", "da", "MemberOf"), ("c", "da", "MemberOf")])
    r = rules(g)
    assert r["admincount-orphan"].objects == ["ORPHAN"]
    assert r["priv-not-protected"].objects == ["REALADM"]


def test_broad_group_rights_and_adcs():
    g = g_with(ADNode("au", "AUTHENTICATED USERS@X.LOCAL", NodeType.GROUP, "X.LOCAL"), user("v", "VICTIM"),
               edges=[("au", "v", "GenericWrite")])
    g.add_edge(ADEdge("au", "da", "ADCSESC1"))
    r = rules(g)
    assert any(f.rule == "broad-rights" and "GenericWrite" in f.title for f in audit(g))
    assert r["adcs-everyone"].severity == "critical" and "ADCSESC1" in r["adcs-everyone"].title


def test_clean_graph_has_no_findings():
    assert audit(g_with(user("a", "ALICE"), comp("c", "PC", haslaps=True, operatingsystem="Windows 11"))) == []


@pytest.mark.skipif(not REAL.exists(), reason="real data missing")
def test_real_collection_and_cli(capsys):
    r = rules(__import__("pathcutter.ingest", fromlist=["load_sharphound"]).load_sharphound(REAL))
    assert {"kerberoast-privileged", "asrep", "passwd-notreqd"} <= set(r)
    assert main(["audit", str(REAL), "--min-severity", "high"]) == 0
    assert "Kerberoastable" in capsys.readouterr().out
    assert main(["audit", str(REAL), "--fail-on", "critical"]) == 2
    assert main(["audit", str(REAL), "--json", "--min-severity", "critical"]) == 0
