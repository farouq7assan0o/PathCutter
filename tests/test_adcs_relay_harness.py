"""ADCS relay (ESC8) harness oracle tests.

CoerceAndRelayNTLMToADCSTrust.json models cross-trust ADCS relay: authenticated users
coerce a computer with WebClient running to authenticate, then relay that NTLM auth to
an Enterprise CA's web enrollment endpoint (ESC8). The harness validates:
- The CA must have hasvulnerableendpoint=True (HTTP enrollment enabled)
- The relay source (coerced computer) must have webclientrunning=True
- restrictoutboundntlm must be False on the source
- Cross-forest and same-forest trust relationships affect reachability
"""
import json
from pathlib import Path

import pytest

HARNESS = Path(__file__).parent / "data" / "harnesses" / "CoerceAndRelayNTLMToADCSTrust.json"


@pytest.fixture
def adcs_trust():
    return json.loads(HARNESS.read_text())


def test_harness_has_adcs_relay_edge(adcs_trust):
    rels = adcs_trust["relationships"]
    adcs_relay = [r for r in rels if r["type"] == "CoerceAndRelayNTLMToADCS"]
    assert len(adcs_relay) >= 1, "Harness should have CoerceAndRelayNTLMToADCS edges"


def test_relay_target_has_webclient_running(adcs_trust):
    """The computer being coerced must have WebClient running for HTTP-based coercion."""
    nodes = {n["id"]: n for n in adcs_trust["nodes"]}
    rels = adcs_trust["relationships"]
    relay_edges = [r for r in rels if r["type"] == "CoerceAndRelayNTLMToADCS"]

    for r in relay_edges:
        target = nodes[r["toId"]]
        wc = target["properties"].get("webclientrunning", "").upper()
        assert wc in ("TRUE", "BOOL:TRUE"), \
            f"Relay target {target['caption']} should have webclientrunning=True, got {wc}"


def test_relay_target_no_restrict_outbound(adcs_trust):
    """Computers with RestrictOutboundNTLM cannot be coerced."""
    nodes = {n["id"]: n for n in adcs_trust["nodes"]}
    rels = adcs_trust["relationships"]
    relay_edges = [r for r in rels if r["type"] == "CoerceAndRelayNTLMToADCS"]

    for r in relay_edges:
        target = nodes[r["toId"]]
        restrict = target["properties"].get("restrictoutboundntlm", "").upper()
        assert restrict in ("FALSE", "BOOL:FALSE"), \
            f"Relay target {target['caption']} should have restrictoutboundntlm=False"


def test_enterprise_ca_has_vulnerable_endpoint(adcs_trust):
    """The Enterprise CA must have a vulnerable HTTP enrollment endpoint (ESC8)."""
    nodes = adcs_trust["nodes"]
    cas = [n for n in nodes if "EnterpriseCA" in n["caption"]]
    assert len(cas) >= 1

    for ca in cas:
        vuln = ca["properties"].get("hasvulnerableendpoint", "").upper()
        assert vuln in ("TRUE", "BOOL:TRUE"), \
            f"CA {ca['caption']} should have hasvulnerableendpoint=True for ESC8"


def test_ca_host_relationship_exists(adcs_trust):
    """A computer must host the CA service."""
    rels = adcs_trust["relationships"]
    hosts_ca = [r for r in rels if r["type"] == "HostsCAService"]
    assert len(hosts_ca) >= 1, "Harness should have HostsCAService relationship"


def test_cross_trust_relationships(adcs_trust):
    """The harness models cross-forest and same-forest trust for multi-domain relay."""
    rels = adcs_trust["relationships"]
    cross_forest = [r for r in rels if r["type"] == "CrossForestTrust"]
    same_forest = [r for r in rels if r["type"] == "SameForestTrust"]
    assert len(cross_forest) >= 2, "Harness should have bidirectional CrossForestTrust"
    assert len(same_forest) >= 2, "Harness should have bidirectional SameForestTrust"


def test_relay_source_is_auth_users_group(adcs_trust):
    """The relay edge source should be Authenticated Users."""
    nodes = {n["id"]: n for n in adcs_trust["nodes"]}
    rels = adcs_trust["relationships"]
    relay_edges = [r for r in rels if r["type"] == "CoerceAndRelayNTLMToADCS"]

    for r in relay_edges:
        src = nodes[r["fromId"]]
        name = src["properties"].get("name", "").upper()
        oid = src["properties"].get("objectid", "").upper()
        assert "AUTHENTICATED USERS" in name or "S-1-5-11" in oid, \
            f"Relay source should be Authenticated Users, got {src['caption']}"


def test_cert_template_allows_authentication(adcs_trust):
    """The certificate template must have authentication enabled."""
    nodes = adcs_trust["nodes"]
    templates = [n for n in nodes if "CertTemplate" in n["caption"]]
    assert len(templates) >= 1

    for t in templates:
        auth = t["properties"].get("authenticationenabled", "").upper()
        assert auth in ("TRUE", "BOOL:TRUE"), \
            f"Template {t['caption']} should have authenticationenabled=True"
