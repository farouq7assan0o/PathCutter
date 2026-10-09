"""Synthetic AD graph fixtures for testing."""
import pytest
from pathcutter.graph import AttackGraph, ADNode, ADEdge, NodeType


@pytest.fixture
def tiny_graph():
    """10 nodes, 3 known paths to DA, 1 clear chokepoint (helpdesk group).

    Paths to Domain Admins:
    1. jsmith -> HelpDesk -> GenericAll -> Server01 -> AdminTo -> DC01 -> MemberOf -> DA
       (wait, this isn't quite right - let me make clearer paths)

    Graph:
    - jsmith (user, tier 2)
    - bwayne (user, tier 2)
    - svc_backup (user, tier 1, service account)
    - HelpDesk (group)
    - IT Admins (group)
    - Domain Admins (group, tier 0)
    - WS01 (computer, workstation)
    - SERVER01 (computer, server)
    - DC01 (computer, domain controller)
    - YOURCOMPANY.LOCAL (domain)

    Attack paths to Domain Admins:
    1. jsmith -> MemberOf -> HelpDesk -> GenericAll -> svc_backup -> MemberOf -> Domain Admins
    2. jsmith -> MemberOf -> HelpDesk -> ForceChangePassword -> bwayne -> MemberOf -> IT Admins -> GenericWrite -> DC01
    3. bwayne -> MemberOf -> IT Admins -> GenericWrite -> DC01

    Chokepoint: HelpDesk group (removing GenericAll from HelpDesk kills path 1,
                removing ForceChangePassword kills path 2)
    """
    g = AttackGraph()

    # Nodes
    g.add_node(ADNode("S-1-5-21-1234-1001", "jsmith@corp.local", NodeType.USER, "corp.local"))
    g.add_node(ADNode("S-1-5-21-1234-1002", "bwayne@corp.local", NodeType.USER, "corp.local"))
    g.add_node(ADNode("S-1-5-21-1234-1003", "svc_backup@corp.local", NodeType.USER, "corp.local"))
    g.add_node(ADNode("S-1-5-21-1234-1100", "HELPDESK@CORP.LOCAL", NodeType.GROUP, "corp.local"))
    g.add_node(ADNode("S-1-5-21-1234-1101", "IT ADMINS@CORP.LOCAL", NodeType.GROUP, "corp.local"))
    g.add_node(ADNode("S-1-5-21-1234-512", "DOMAIN ADMINS@CORP.LOCAL", NodeType.GROUP, "corp.local"))
    g.add_node(ADNode("S-1-5-21-1234-2001", "WS01.CORP.LOCAL", NodeType.COMPUTER, "corp.local"))
    g.add_node(ADNode("S-1-5-21-1234-2002", "SERVER01.CORP.LOCAL", NodeType.COMPUTER, "corp.local"))
    g.add_node(ADNode("S-1-5-21-1234-2003", "DC01.CORP.LOCAL", NodeType.COMPUTER, "corp.local"))
    g.add_node(ADNode("S-1-5-21-1234-0", "CORP.LOCAL", NodeType.DOMAIN, "corp.local"))

    # Group memberships
    g.add_edge(ADEdge("S-1-5-21-1234-1001", "S-1-5-21-1234-1100", "MemberOf"))  # jsmith -> HelpDesk
    g.add_edge(ADEdge("S-1-5-21-1234-1002", "S-1-5-21-1234-1101", "MemberOf"))  # bwayne -> IT Admins
    g.add_edge(ADEdge("S-1-5-21-1234-1003", "S-1-5-21-1234-512", "MemberOf"))   # svc_backup -> Domain Admins

    # Attack edges
    g.add_edge(ADEdge("S-1-5-21-1234-1100", "S-1-5-21-1234-1003", "GenericAll"))       # HelpDesk -> GenericAll -> svc_backup
    g.add_edge(ADEdge("S-1-5-21-1234-1100", "S-1-5-21-1234-1002", "ForceChangePassword"))  # HelpDesk -> ForceChangePassword -> bwayne
    g.add_edge(ADEdge("S-1-5-21-1234-1101", "S-1-5-21-1234-2003", "GenericWrite"))      # IT Admins -> GenericWrite -> DC01

    # Sessions
    g.add_edge(ADEdge("S-1-5-21-1234-1001", "S-1-5-21-1234-2001", "HasSession"))  # jsmith has session on WS01
    g.add_edge(ADEdge("S-1-5-21-1234-1003", "S-1-5-21-1234-2002", "AdminTo"))     # svc_backup is admin on SERVER01

    g.classify_tiers()
    return g


@pytest.fixture
def delegation_graph():
    """Tests unconstrained/constrained/RBCD delegation chains.

    web_svc -> AllowedToDelegate (unconstrained) -> DC01
    sql_svc -> constrained delegation to sql_server
    attacker -> AddAllowedToAct -> app_server (RBCD)
    """
    g = AttackGraph()

    g.add_node(ADNode("S-1-5-21-9999-1001", "web_svc@test.local", NodeType.USER, "test.local"))
    g.add_node(ADNode("S-1-5-21-9999-1002", "sql_svc@test.local", NodeType.USER, "test.local"))
    g.add_node(ADNode("S-1-5-21-9999-1003", "attacker@test.local", NodeType.USER, "test.local"))
    g.add_node(ADNode("S-1-5-21-9999-2001", "DC01.TEST.LOCAL", NodeType.COMPUTER, "test.local"))
    g.add_node(ADNode("S-1-5-21-9999-2002", "SQL01.TEST.LOCAL", NodeType.COMPUTER, "test.local"))
    g.add_node(ADNode("S-1-5-21-9999-2003", "APP01.TEST.LOCAL", NodeType.COMPUTER, "test.local"))
    g.add_node(ADNode("S-1-5-21-9999-512", "DOMAIN ADMINS@TEST.LOCAL", NodeType.GROUP, "test.local"))

    # Unconstrained delegation on web_svc
    g.add_edge(ADEdge("S-1-5-21-9999-1001", "S-1-5-21-9999-2001", "AllowedToDelegate"))

    # RBCD: attacker can write msDS-AllowedToActOnBehalfOfOtherIdentity on APP01
    g.add_edge(ADEdge("S-1-5-21-9999-1003", "S-1-5-21-9999-2003", "AddAllowedToAct"))

    # sql_svc is admin on DC01 (through SQL)
    g.add_edge(ADEdge("S-1-5-21-9999-1002", "S-1-5-21-9999-2001", "SQLAdmin"))

    g.classify_tiers()
    return g


@pytest.fixture
def nested_groups():
    """5-level group nesting with inherited permissions.

    user1 -> G1 -> G2 -> G3 -> G4 -> G5 -> GenericAll -> DA
    Tests transitive group membership expansion.
    """
    g = AttackGraph()

    g.add_node(ADNode("S-user1", "user1@deep.local", NodeType.USER, "deep.local"))
    g.add_node(ADNode("S-g1", "G1@DEEP.LOCAL", NodeType.GROUP, "deep.local"))
    g.add_node(ADNode("S-g2", "G2@DEEP.LOCAL", NodeType.GROUP, "deep.local"))
    g.add_node(ADNode("S-g3", "G3@DEEP.LOCAL", NodeType.GROUP, "deep.local"))
    g.add_node(ADNode("S-g4", "G4@DEEP.LOCAL", NodeType.GROUP, "deep.local"))
    g.add_node(ADNode("S-g5", "G5@DEEP.LOCAL", NodeType.GROUP, "deep.local"))
    g.add_node(ADNode("S-da", "DOMAIN ADMINS@DEEP.LOCAL", NodeType.GROUP, "deep.local"))

    # Nesting: user1 -> G1 -> G2 -> G3 -> G4 -> G5
    g.add_edge(ADEdge("S-user1", "S-g1", "MemberOf"))
    g.add_edge(ADEdge("S-g1", "S-g2", "MemberOf"))
    g.add_edge(ADEdge("S-g2", "S-g3", "MemberOf"))
    g.add_edge(ADEdge("S-g3", "S-g4", "MemberOf"))
    g.add_edge(ADEdge("S-g4", "S-g5", "MemberOf"))

    # G5 has GenericAll on Domain Admins
    g.add_edge(ADEdge("S-g5", "S-da", "GenericAll"))

    g.classify_tiers()
    return g


# ---------------------------------------------------------------------------
# Fixtures for the change-impact gate (pathcutter check)
# ---------------------------------------------------------------------------

def _corp():
    """A small AD with one known weakness.

    users:   alice, bob, carol (disabled), dave, svc_backup (member of Domain Admins)
    groups:  HELPDESK (GenericAll on svc_backup), IT ADMINS, TEAM, DOMAIN ADMINS (Tier 0), BACKUP OPERATORS (Tier 0)
    hosts:   SRV01 (IT ADMINS are admins), DC01
    bob is in IT ADMINS; nobody is in HELPDESK; alice/dave/carol have no privileges.
    """
    g = AttackGraph()
    add = lambda i, n, t: g.add_node(ADNode(i, n, t, "corp.local"))  # noqa: E731
    for i, n in [("u-alice", "alice@corp.local"), ("u-bob", "bob@corp.local"), ("u-dave", "dave@corp.local"),
                 ("u-svc", "svc_backup@corp.local")]:
        add(i, n, NodeType.USER)
    g.add_node(ADNode("u-carol", "carol@corp.local", NodeType.USER, "corp.local", enabled=False))
    for i, n in [("g-help", "HELPDESK@CORP.LOCAL"), ("g-it", "IT ADMINS@CORP.LOCAL"), ("g-team", "TEAM@CORP.LOCAL"),
                 ("g-da", "DOMAIN ADMINS@CORP.LOCAL"), ("g-bo", "BACKUP OPERATORS@CORP.LOCAL")]:
        add(i, n, NodeType.GROUP)
    add("c-srv01", "SRV01.CORP.LOCAL", NodeType.COMPUTER)
    add("c-dc01", "DC01.CORP.LOCAL", NodeType.COMPUTER)
    add("d-corp", "CORP.LOCAL", NodeType.DOMAIN)
    g.add_edge(ADEdge("u-svc", "g-da", "MemberOf"))
    g.add_edge(ADEdge("g-help", "u-svc", "GenericAll"))
    g.add_edge(ADEdge("u-bob", "g-it", "MemberOf"))
    g.add_edge(ADEdge("g-it", "c-srv01", "AdminTo"))
    g.classify_tiers()
    return g


@pytest.fixture
def corp():
    return _corp()


@pytest.fixture
def run_check():
    """run_check(graph, ["add-member alice HELPDESK", ...], policy=None) -> (report, resolved)."""
    from pathcutter.changes import load_changes, resolve_changes
    from pathcutter.impact import analyze_impact
    from pathcutter.policy import Policy, evaluate

    def _run(graph, lines, policy=None, today=None, on_unresolved="error", **kw):
        specs, warns = load_changes(inline=lines)
        resolved, errors = resolve_changes(graph, specs, on_unresolved)
        assert not errors, errors
        report = analyze_impact(graph, resolved, unmodeled=kw.pop("unmodeled", warns), **kw)
        evaluate(report, policy or Policy(), resolved, today)
        return report, resolved

    return _run
