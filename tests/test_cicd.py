"""CI/CD to cloud: parse the federation subject into risk, and ingest the who-can-push sidecar into pipeline edges."""
from pathcutter import azure, cicd
from pathcutter.graph import AttackGraph, NodeType

GH = "https://token.actions.githubusercontent.com"


def test_parse_github_branch_tight():
    i = cicd.parse_subject(GH, "repo:acme/infra:ref:refs/heads/main")
    assert i["provider"] == "github" and i["repo"] == "acme/infra"
    assert i["ref"] == "refs/heads/main" and i["broad"] is False and i["pull_request"] is False
    assert i["label"] == "github:acme/infra@main"


def test_parse_github_pull_request_is_broad():
    i = cicd.parse_subject(GH, "repo:acme/infra:pull_request")
    assert i["pull_request"] is True and i["broad"] is True


def test_parse_github_wildcard_and_no_ref_are_broad():
    assert cicd.parse_subject(GH, "repo:acme/infra:*")["broad"] is True
    assert cicd.parse_subject(GH, "repo:acme/infra")["broad"] is True        # no ref pin
    assert cicd.parse_subject(GH, "repo:acme/infra:environment:prod")["environment"] == "prod"


def test_parse_provider_from_issuer():
    assert cicd.parse_subject("https://vstoken.dev.azure.com/x", "sc://o/p/c")["provider"] == "azuredevops"
    assert cicd.parse_subject("https://gitlab.com", "project_path:g/p:ref_type:branch:ref:main")["provider"] == "gitlab"
    assert cicd.parse_subject("https://login.microsoftonline.com/t/v2.0", "x")["provider"] == "entra"
    # an unknown external issuer is treated as broad (conservative)
    assert cicd.parse_subject("https://evil.example", "whatever")["broad"] is True


def _fic_graph(subject):
    items = [
        {"kind": "AZApp", "data": {"id": "APP1", "appId": "aaa", "displayName": "deployer"}},
        {"kind": "AZUser", "data": {"id": "U1", "userPrincipalName": "dev@x"}},
        {"kind": "AZFederatedIdentityCredential",
         "data": {"appId": "aaa", "fics": [{"appId": "aaa", "fic": {
             "id": "FIC1", "name": "gh", "issuer": GH, "subject": subject}}]}},
    ]
    g = AttackGraph()
    azure.parse_azure_file({"data": items}, g)
    azure.finalize_azure(g)
    return g


def test_enrich_fic_nodes_stores_parsed_subject():
    g = _fic_graph("repo:acme/infra:ref:refs/heads/main")
    assert g.get_node("FIC1").properties["_cicd"]["repo"] == "acme/infra"


def test_sidecar_builds_pipeline_path_and_counts_unresolved():
    g = _fic_graph("repo:acme/infra:ref:refs/heads/main")
    side = {"meta": {"type": "cicd", "provider": "github"},
            "data": [{"repo": "acme/infra", "principals": [{"id": "U1", "access": "write"},
                                                           {"id": "octocat", "access": "admin"}]}]}
    cicd.apply_cicd(side, g)
    src = "CICD:GITHUB:ACME/INFRA"
    assert g.get_node(src) is not None
    edges = {(u, v, d.get("edge_type")) for u, v, d in g.all_edges()}
    assert (src, "APP1", "AZAuthenticatesTo") in edges       # the repo can act as the app
    assert ("U1", src, "MemberOf") in edges                  # a resolved pusher reaches the pipeline
    assert g.meta.get("cicd_unresolved_principals") == 1     # octocat is a GitHub-only identity, not invented


def test_sidecar_skips_repo_with_no_matching_fic():
    g = _fic_graph("repo:acme/infra:ref:refs/heads/main")
    side = {"meta": {"type": "cicd", "provider": "github"}, "data": [{"repo": "other/repo", "principals": []}]}
    cicd.apply_cicd(side, g)
    assert g.get_node("CICD:GITHUB:OTHER/REPO") is None


def test_audit_flags_pull_request_and_no_ref():
    from pathcutter.hygiene import audit
    rules_pr = {f.rule for f in audit(_fic_graph("repo:acme/infra:pull_request"))}
    assert "fic-pull-request-trigger" in rules_pr
    rules_noref = {f.rule for f in audit(_fic_graph("repo:acme/infra"))}
    assert "fic-no-ref-pin" in rules_noref
    rules_tight = {f.rule for f in audit(_fic_graph("repo:acme/infra:ref:refs/heads/main"))}
    assert "fic-pull-request-trigger" not in rules_tight and "fic-no-ref-pin" not in rules_tight
