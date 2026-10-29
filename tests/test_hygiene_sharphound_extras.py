"""New SharpHound-sourced hygiene findings: machine account quota, weak Kerberos encryption, Tier 0 session exposure."""
from pathcutter.graph import ADEdge, ADNode, AttackGraph, NodeType
from pathcutter.hygiene import _enc_class, audit


def _rules(g):
    g.classify_tiers()
    return {f.rule: f for f in audit(g)}


# ----------------------------------------------------------------- machine account quota
def test_maq_nonzero_flagged_zero_not():
    g = AttackGraph()
    g.add_node(ADNode("dom", "CORP.LOCAL", NodeType.DOMAIN, "CORP.LOCAL", properties={"machineaccountquota": 10}))
    f = _rules(g).get("machine-account-quota")
    assert f and "10" in f.title and f.severity == "medium"

    g2 = AttackGraph()
    g2.add_node(ADNode("dom", "CORP.LOCAL", NodeType.DOMAIN, "CORP.LOCAL", properties={"machineaccountquota": 0}))
    assert "machine-account-quota" not in _rules(g2)

    g3 = AttackGraph()                       # not collected -> no finding
    g3.add_node(ADNode("dom", "CORP.LOCAL", NodeType.DOMAIN, "CORP.LOCAL"))
    assert "machine-account-quota" not in _rules(g3)


# ----------------------------------------------------------------- encryption classification
def test_enc_class():
    assert _enc_class(["RC4-HMAC-MD5"]) == "rc4only"
    assert _enc_class(["AES256-CTS-HMAC-SHA1-96", "RC4-HMAC-MD5"]) == "aes"
    assert _enc_class(["Not defined"]) == "notdefined"
    assert _enc_class(4) == "rc4only"         # RC4 bit only
    assert _enc_class(24) == "aes"            # AES128|AES256
    assert _enc_class(0) == "notdefined"
    assert _enc_class(None) is None


def _acct(oid, name, admincount=False, **props):
    return ADNode(oid, name, NodeType.USER, "CORP.LOCAL", admin_count=admincount, properties=props)


def test_weak_kerberos_encryption_buckets():
    g = AttackGraph()
    g.add_node(ADNode("da", "DOMAIN ADMINS@CORP.LOCAL", NodeType.GROUP, "CORP.LOCAL"))
    g.add_node(_acct("admin", "ADMIN@CORP.LOCAL", admincount=True, supportedencryptiontypes=["RC4-HMAC-MD5"]))
    g.add_node(_acct("svc", "SVC@CORP.LOCAL", supportedencryptiontypes=4, hasspn=True))
    g.add_node(_acct("joe", "JOE@CORP.LOCAL", supportedencryptiontypes=["RC4-HMAC-MD5"]))
    g.add_node(_acct("ok", "OK@CORP.LOCAL", supportedencryptiontypes=["AES256-CTS-HMAC-SHA1-96"]))
    g.add_node(_acct("krbtgt", "KRBTGT@CORP.LOCAL", supportedencryptiontypes=0))      # 'Not defined' still flagged for krbtgt
    r = _rules(g)
    assert "KRBTGT" in r["weak-kerberos-enc-privileged"].objects and "ADMIN" in r["weak-kerberos-enc-privileged"].objects
    assert "SVC" in r["weak-kerberos-enc-spn"].objects
    assert "JOE" in r["weak-kerberos-enc"].objects
    # the AES-only account is never flagged
    allobjs = sum((f.objects for f in r.values()), [])
    assert "OK" not in allobjs


def test_notdefined_does_not_flag_ordinary_accounts():
    g = AttackGraph()
    g.add_node(_acct("joe", "JOE@CORP.LOCAL", supportedencryptiontypes=0))            # default, not a finding
    r = _rules(g)
    assert "weak-kerberos-enc" not in r and "weak-kerberos-enc-spn" not in r and "weak-kerberos-enc-privileged" not in r


# ----------------------------------------------------------------- Tier 0 session on a lower-tier host
def test_tier0_session_on_lower_tier_host():
    g = AttackGraph()
    g.add_node(ADNode("da", "DOMAIN ADMINS@CORP.LOCAL", NodeType.GROUP, "CORP.LOCAL"))
    g.add_node(ADNode("admin", "ADMIN@CORP.LOCAL", NodeType.USER, "CORP.LOCAL"))
    g.add_node(ADNode("ws", "WS01@CORP.LOCAL", NodeType.COMPUTER, "CORP.LOCAL"))
    g.add_edge(ADEdge("admin", "da", "MemberOf"))          # admin becomes Tier 0
    g.add_edge(ADEdge("ws", "admin", "HasSession"))        # its creds sit on a Tier 2 host
    f = _rules(g).get("tier0-exposed-on-lower-tier")
    assert f and f.severity == "critical" and "WS01" in f.objects
    assert "ADMIN" in f.why


def test_no_finding_when_tier0_session_is_on_a_tier0_host():
    g = AttackGraph()
    g.add_node(ADNode("da", "DOMAIN ADMINS@CORP.LOCAL", NodeType.GROUP, "CORP.LOCAL"))
    g.add_node(ADNode("admin", "ADMIN@CORP.LOCAL", NodeType.USER, "CORP.LOCAL"))
    g.add_node(ADNode("dc", "DC01@CORP.LOCAL", NodeType.COMPUTER, "CORP.LOCAL", properties={"isdc": True}))
    g.add_edge(ADEdge("admin", "da", "MemberOf"))
    g.add_edge(ADEdge("dc", "da", "MemberOf"))             # make the DC Tier 0 too
    g.add_edge(ADEdge("dc", "admin", "HasSession"))
    assert "tier0-exposed-on-lower-tier" not in _rules(g)
