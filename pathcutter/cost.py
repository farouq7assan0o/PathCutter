"""Attacker economics: what a path costs to walk and how loud it is, so the cheapest and stealthiest routes stand out.

Fewest hops is not how an attacker chooses. A two-hop route that needs a coercion to fire and lights up a DCSync alert is
worse, for them, than a three-hop route of quiet ACL abuse. Two forces decide which route a rational attacker takes:

  effort   how much work, tooling or privilege each step needs. Derived from the edge's exploitability (1-10): an
           exploitability-10 step is almost free (effort 1), an exploitability-1 step is hard (effort 10). Structural
           hops (MemberOf, Contains) are free.
  noise    how likely the step is to be seen. Derived from the edge's detection difficulty: a step that is easy to
           detect is loud (noise 3), a hard-to-detect step is quiet (noise 1). Each step is a fresh chance to be caught,
           so a path's noise is the sum over its steps.

A path also carries whether any step is *fragile* (rests on an unverified precondition such as coercion or a PIM
activation - cheap on paper, may not fire) and which identity *planes* it crosses (on-premises AD, Entra, Azure
resources, Microsoft Graph). A route that crosses from on-prem into the cloud, or vice versa, is called out, because those
hops are the ones defenders most often have no single team watching.

Nothing here hides or reweights an edge in the graph: it reads the same registry the rest of PathCutter uses and labels
the routes that are already there. `cheapest`, `stealthiest` and `rank` pick among a set of paths; the report shows the
numbers; `breach.py` uses them for assume-breach analysis.
"""
from __future__ import annotations

from .edges import get_edge_type
from .evidence import edge_confidence

_STRUCTURE = {"MemberOf", "Contains", "AZContains", "AZRunsAs", "OIDGroupLink"}

# detection difficulty (how hard to catch) -> noise (how loud for the attacker). Easy to detect = loud.
_NOISE = {"low": 3, "medium": 2, "high": 1}

# the identity plane each edge lives on. Everything unlisted is on-premises AD.
_AZURE_RESOURCE = {"AZOwner", "AZContributor", "AZUserAccessAdmin", "AZVMAdminLogin", "AZManagedIdentity"}
_BRIDGE = {"SyncedTo": ("ad", "entra"), "AZAuthenticatesTo": ("external", "entra")}


def plane(edge_type: str) -> str:
    """Which identity plane a single edge lives on: ad | entra | azure | msgraph | bridge."""
    if edge_type in _BRIDGE:
        return "bridge"
    if edge_type in _AZURE_RESOURCE:
        return "azure"
    if edge_type.startswith("AZMG"):
        return "msgraph"
    if edge_type.startswith("AZ"):
        return "entra"
    return "ad"


def edge_cost(edge_type: str, props: dict | None = None) -> dict:
    """{effort, noise, fragile, plane} for one edge. Structural edges cost nothing."""
    if edge_type in _STRUCTURE:
        return {"effort": 0, "noise": 0, "fragile": False, "plane": plane(edge_type)}
    info = get_edge_type(edge_type)
    expl = info.exploitability if info else 0
    diff = info.detection_difficulty if info else "medium"
    effort = (11 - expl) if expl > 0 else 0        # exploitability 10 -> effort 1; 0 (structural/input) -> free
    noise = _NOISE.get(diff, 2) if expl > 0 else 0
    _lvl, src, _why = edge_confidence(edge_type, props or {})
    fragile = src.startswith("assumption:")        # an unverified precondition: may not fire when attempted
    return {"effort": effort, "noise": noise, "fragile": fragile, "plane": plane(edge_type)}


def _edge_name(e) -> str:
    if isinstance(e, str):
        return e
    return e.get("edge_type") or e.get("edge") or "?"


def path_cost(edges: list) -> dict:
    """Cost of a path from its edges (edge-type strings, or step dicts with edge_type/edge).

    Returns effort, noise and steps summed over the attack steps (structural hops are free and not counted),
    plus the fragile flag, the loudest and dearest single step, and the planes the path crosses.
    """
    effort = noise = steps = 0
    fragile = False
    planes: set[str] = set()
    loudest = dearest = None
    loud_n = dear_e = -1
    for e in edges:
        et = _edge_name(e)
        if et in _STRUCTURE:
            planes.add(plane(et))
            continue
        c = edge_cost(et, e if isinstance(e, dict) else None)
        if c["effort"] == 0 and c["noise"] == 0:
            continue                                   # a recognised non-step (e.g. input edge): nothing to walk
        effort += c["effort"]
        noise += c["noise"]
        steps += 1
        fragile = fragile or c["fragile"]
        planes.add(c["plane"])
        if c["noise"] > loud_n:
            loud_n, loudest = c["noise"], et
        if c["effort"] > dear_e:
            dear_e, dearest = c["effort"], et
    on_prem = "ad" in planes
    cloud = bool(planes & {"entra", "azure", "msgraph"})
    cross = (on_prem and cloud) or ("bridge" in planes)
    return {"effort": effort, "noise": noise, "steps": steps, "fragile": fragile,
            "loudest": loudest, "dearest": dearest, "planes": sorted(planes), "cross_plane": cross}


# profile -> (effort weight, noise weight). An opportunist minimises work; a stealthy actor minimises noise.
_PROFILES = {"opportunist": (1.0, 0.25), "stealth": (0.25, 1.0), "balanced": (1.0, 1.0)}


def attractiveness(cost: dict, profile: str = "balanced") -> float:
    """Lower = more attractive to an attacker under this profile. A fragile step adds a penalty."""
    we, wn = _PROFILES.get(profile, _PROFILES["balanced"])
    return we * cost["effort"] + wn * cost["noise"] + (3.0 if cost["fragile"] else 0.0)


def _as_edges(path) -> list:
    """Accept an AttackPath, a list of step dicts, or a list of edge-type strings."""
    if hasattr(path, "edges"):
        return path.edges
    return path


def _key_cheapest(cost: dict) -> tuple:
    return (cost["effort"], cost["steps"], cost["noise"], 1 if cost["fragile"] else 0)


def _key_stealthiest(cost: dict) -> tuple:
    return (cost["noise"], cost["steps"], cost["effort"], 1 if cost["fragile"] else 0)


def cheapest(paths: list):
    """The path that takes the least attacker effort (then fewest steps, then quietest). None if no paths."""
    best = None
    for p in paths:
        c = path_cost(_as_edges(p))
        k = _key_cheapest(c)
        if best is None or k < best[0]:
            best = (k, p, c)
    return None if best is None else (best[1], best[2])


def stealthiest(paths: list):
    """The quietest path (then fewest steps, then least effort). None if no paths."""
    best = None
    for p in paths:
        c = path_cost(_as_edges(p))
        k = _key_stealthiest(c)
        if best is None or k < best[0]:
            best = (k, p, c)
    return None if best is None else (best[1], best[2])


def rank(paths: list, profile: str = "balanced") -> list:
    """Paths sorted most-attractive-first for the given attacker profile; each as (path, cost)."""
    scored = [(p, path_cost(_as_edges(p))) for p in paths]
    scored.sort(key=lambda pc: (attractiveness(pc[1], profile), pc[1]["steps"]))
    return scored


def label(cost: dict) -> str:
    """One-line human summary of a path cost."""
    bits = [f"effort {cost['effort']}", f"noise {cost['noise']}", f"{cost['steps']} step{'s' if cost['steps'] != 1 else ''}"]
    if cost["fragile"]:
        bits.append("fragile")
    if cost["cross_plane"]:
        bits.append("cross-plane")
    return ", ".join(bits)
