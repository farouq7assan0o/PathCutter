"""CI/CD to cloud: read what a workload-identity federation actually trusts, and (optionally) who can drive it.

PathCutter already turns an Entra federated identity credential into an `AZAuthenticatesTo` edge (FIC -> application):
whoever can make the external issuer mint a token for the trusted subject can sign in as the app, with no secret. The
subject string says exactly which pipeline that is - a GitHub repository and branch, a pull request, an environment, an
Azure DevOps service connection. This module parses that subject so the risk is explicit (a single protected branch is
tight; `pull_request` or a wildcard is wide open to any contributor), and ingests an optional `*_cicd.json` sidecar that
names the repositories and who can push to them, so the attack path reaches from the pipeline into the cloud.

The subject grammars are the providers' own (GitHub Actions OIDC `repo:ORG/REPO:ref:refs/heads/BRANCH`,
`...:pull_request`, `...:environment:ENV`; GitLab `project_path:...:ref:...`; Azure DevOps service connections). Nothing
is invented: an unrecognised subject is reported as-is and treated as broad, which can only over-report.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

# issuer host -> provider
_ISSUERS = {
    "token.actions.githubusercontent.com": "github",
    "vstoken.dev.azure.com": "azuredevops",
    "vstoken.visualstudio.com": "azuredevops",
    "gitlab.com": "gitlab",
}

_GH_REPO = re.compile(r"^repo:(?P<repo>[^:]+/[^:]+)(?::(?P<rest>.*))?$", re.I)
_GL_PROJECT = re.compile(r"project_path:(?P<repo>[^:]+)", re.I)


def provider_of(issuer: str) -> str:
    host = str(issuer or "")
    if "//" in host:
        host = host.split("//", 1)[1].split("/", 1)[0]
    host = host.lower()
    for key, prov in _ISSUERS.items():
        if key in host:
            return prov
    if "login.microsoftonline.com" in host or not host:
        return "entra"
    return "other"


def parse_subject(issuer: str, subject: str) -> dict:
    """Structured view of a federation subject: {provider, repo, ref, environment, pull_request, wildcard, broad, label}.

    `broad` is True when the trust is not pinned to a single branch or environment (a wildcard, a pull request, or a
    repo with no ref), meaning many identities can satisfy it."""
    prov = provider_of(issuer)
    subj = str(subject or "")
    out = {"provider": prov, "repo": None, "ref": None, "environment": None,
           "pull_request": False, "wildcard": "*" in subj, "broad": False, "label": subj}

    if prov == "github":
        m = _GH_REPO.match(subj)
        if m:
            out["repo"] = m.group("repo")
            rest = (m.group("rest") or "").strip()
            if rest in ("", "*"):
                out["broad"] = True
            elif rest.lower().startswith("pull_request"):
                out["pull_request"] = out["broad"] = True
            elif rest.lower().startswith("environment:"):
                out["environment"] = rest.split(":", 1)[1]
            elif rest.lower().startswith("ref:"):
                out["ref"] = rest.split(":", 1)[1]
            else:
                out["broad"] = "*" in rest
            out["label"] = f"github:{out['repo']}" + (
                f"@{out['ref'].split('/')[-1]}" if out["ref"] else
                f" env:{out['environment']}" if out["environment"] else
                " (pull_request)" if out["pull_request"] else " (any ref)" if out["broad"] else "")
    elif prov == "gitlab":
        m = _GL_PROJECT.search(subj)
        if m:
            out["repo"] = m.group("repo")
        out["broad"] = out["wildcard"] or "ref_type:branch" not in subj.lower()
        out["label"] = f"gitlab:{out['repo'] or subj}"
    elif prov == "azuredevops":
        out["broad"] = out["wildcard"]
        out["label"] = f"azuredevops:{subj}"
    else:
        out["broad"] = True              # an unrecognised external issuer/subject: treat as broad (conservative)
    return out


def enrich_fic_nodes(graph) -> int:
    """Attach the parsed subject fields to every federated-credential node. Returns how many were enriched."""
    from .graph import NodeType
    n = 0
    for fic in graph.nodes_by_type(NodeType.AZ_FIC):
        info = parse_subject(fic.properties.get("issuer", ""), fic.properties.get("subject", ""))
        fic.properties["_cicd"] = info
        n += 1
    return n


# --------------------------------------------------------------------- optional sidecar: who can drive the pipeline

def is_cicd_file(data: dict) -> bool:
    return str((data.get("meta") or {}).get("type", "")).lower() == "cicd"


def apply_cicd(data: dict, graph) -> int:
    """Ingest a `*_cicd.json` sidecar: repositories and who can push to them, linked to the apps they can authenticate as.

    Shape: {"meta": {"type": "cicd", "provider": "github"},
            "data": [{"repo": "org/name", "principals": [{"id": "<existing graph id>", "access": "write"}], ...}]}
    For each repo that a collected federated credential trusts, a CI/CD source node is created with an AZAuthenticatesTo
    edge to that application (the repo can mint a token and act as the app), and every listed principal that resolves to
    an existing graph object gets an edge to the source (they can run the workflow). Principals that do not resolve are
    recorded but not invented as nodes - GitHub/ADO identities are a separate plane and only correlate when you map them.
    """
    from .graph import ADEdge, ADNode, NodeType
    # index FIC subjects by repo -> the app NODES they authenticate to (resolved earlier into AZAuthenticatesTo edges)
    repo_apps: dict[str, set[str]] = {}
    for fic in graph.nodes_by_type(NodeType.AZ_FIC):
        info = fic.properties.get("_cicd") or parse_subject(fic.properties.get("issuer", ""), fic.properties.get("subject", ""))
        repo = info.get("repo")
        if not repo:
            continue
        apps = {v for _u, v, d in graph.out_edges(fic.object_id) if d.get("edge_type") == "AZAuthenticatesTo"}
        if apps:
            repo_apps.setdefault(repo.lower(), set()).update(apps)
    provider = str((data.get("meta") or {}).get("provider", "github")).lower()
    added = 0
    for rec in data.get("data", []) or []:
        repo = str(rec.get("repo") or "").strip()
        if not repo:
            continue
        apps = repo_apps.get(repo.lower())
        if not apps:
            continue                                   # no collected FIC trusts this repo: nothing to connect
        src = f"CICD:{provider}:{repo}".upper()
        if graph.get_node(src) is None:
            graph.add_node(ADNode(src, f"CICD:{provider}:{repo}".upper(), NodeType.UNKNOWN, "",
                                  properties={"_cicd_source": True, "repo": repo, "provider": provider}))
        for app in apps:
            if graph.get_node(app) is not None and not graph.has_edge_type(src, app, "AZAuthenticatesTo"):
                graph.add_edge(ADEdge(src, app, "AZAuthenticatesTo"))
                added += 1
        unresolved = 0
        for p in rec.get("principals") or []:
            pid = str((p or {}).get("id") or "").upper()
            if pid and graph.get_node(pid) is not None:
                if not graph.has_edge_type(pid, src, "MemberOf"):
                    graph.add_edge(ADEdge(pid, src, "MemberOf"))   # they can run the workflow -> inherit the source's reach
                    added += 1
            elif pid:
                unresolved += 1
        if unresolved:
            graph.meta.setdefault("cicd_unresolved_principals", 0)
            graph.meta["cicd_unresolved_principals"] += unresolved
    return added


def load_cicd(path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))
