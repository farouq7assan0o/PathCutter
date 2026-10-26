"""Crown jewels and business value: weight risk by what an asset is worth, not only by how many hops away Tier 0 is.

PathCutter measures reachability to Tier 0 (domain / Global Admin takeover). Tier 0 is objective. But every organisation
also has assets whose compromise is a crisis even when it is not domain takeover: in a university, the student-records
system (SIS), the finance ERP, the research file servers, an exam-results database. PathCutter cannot know which objects
these are - you declare them, in a small JSON file or in the policy's `crown_jewels` section.

A declared crown jewel becomes a target (so the exposure search measures who can reach it) and carries a value
(critical / high / medium) and a human label. The report then ranks and names them, and leadership sees
"3 of your 5 crown jewels can be reached by a standard user", not just a hop count. PathCutter never invents business
value: an asset counts only because you declared it.

File shape (either a bare list or under a "crown_jewels" key):
  {"crown_jewels": [
     {"match": "SQL-SIS-PROD",            "value": "critical", "label": "Student records (SIS)"},
     {"match": "ERP-FINANCE",             "value": "critical", "label": "Finance ERP"},
     {"ou":    "OU=Research,DC=uni,DC=edu","value": "high",     "label": "Research systems"}
  ]}
`match` is a name, short name or object id (resolved like a policy name); `ou` values every object whose
distinguishedName sits under that OU. An object matched by several entries keeps the highest value.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .changes import NameIndex
from .graph import AttackGraph, NodeType

VALUES = ("medium", "high", "critical")
_RANK = {v: i for i, v in enumerate(VALUES)}
ACTOR_TYPES = {NodeType.USER.value, NodeType.COMPUTER.value, NodeType.AZ_USER.value, NodeType.AZ_SP.value}


class ValueError_(Exception):
    pass


@dataclass
class CrownJewelSpec:
    value: str = "high"
    label: str = ""
    match: str | None = None       # a name / short name / object id
    ou: str | None = None          # a distinguishedName suffix (everything under this OU)


def load(path: str | Path) -> list[CrownJewelSpec]:
    """Read a crown-jewels JSON file into specs (tolerant of a bare list or a {"crown_jewels": [...]} object)."""
    p = Path(path)
    try:
        data = json.loads(p.read_text(encoding="utf-8-sig"))
    except OSError as exc:
        raise ValueError_(f"cannot read crown-jewels file {p}: {exc.strerror or exc}") from None
    except json.JSONDecodeError as exc:
        raise ValueError_(f"{p}: invalid JSON ({exc})") from None
    return parse(data, str(p))


def parse(data, source: str = "<crown-jewels>") -> list[CrownJewelSpec]:
    items = data.get("crown_jewels", data) if isinstance(data, dict) else data
    if not isinstance(items, list):
        raise ValueError_(f"{source}: expected a list of crown jewels (or a 'crown_jewels' key)")
    specs: list[CrownJewelSpec] = []
    for i, it in enumerate(items):
        if not isinstance(it, dict):
            raise ValueError_(f"{source}: entry {i} must be an object")
        val = str(it.get("value", "high")).lower()
        if val not in VALUES:
            raise ValueError_(f"{source}: entry {i} has value '{val}' (use one of {', '.join(VALUES)})")
        match, ou = it.get("match"), it.get("ou")
        if not match and not ou:
            raise ValueError_(f"{source}: entry {i} needs a 'match' (name/id) or an 'ou'")
        specs.append(CrownJewelSpec(value=val, label=str(it.get("label", "")), match=match, ou=ou))
    return specs


def resolve(graph: AttackGraph, specs: list[CrownJewelSpec]) -> tuple[dict[str, dict], list[str]]:
    """Resolve specs to {object_id: {"value", "label"}} (highest value wins) and a list of non-fatal errors."""
    index = NameIndex(graph)
    out: dict[str, dict] = {}
    errors: list[str] = []

    def assign(nid: str, value: str, label: str) -> None:
        cur = out.get(nid)
        if cur is None or _RANK[value] > _RANK[cur["value"]]:
            out[nid] = {"value": value, "label": label or (cur or {}).get("label", "")}

    for spec in specs:
        hit = False
        if spec.match:
            for n in index.lookup(str(spec.match)):
                assign(n.object_id, spec.value, spec.label)
                hit = True
        if spec.ou:
            suffix = str(spec.ou).upper().lstrip(",")
            for n in graph.all_nodes():
                dn = str(n.properties.get("distinguishedname") or "").upper()
                if dn and dn.endswith(suffix) and dn != suffix:          # under the OU, not the OU object itself
                    assign(n.object_id, spec.value, spec.label)
                    hit = True
        if not hit:
            where = spec.match or spec.ou
            errors.append(f"crown jewel '{where}' matched nothing in the baseline")
    return out, errors


def target_ids(value_by_id: dict[str, dict]) -> set[str]:
    return set(value_by_id)


def analyse(graph: AttackGraph, value_by_id: dict[str, dict], *, max_paths: int = 1500, max_depth: int = 20) -> list[dict]:
    """Per crown jewel: is it reachable, by how many actors, in how few hops, and by the cheapest route.

    Ranked most-critical and most-reachable first. Reachability is reverse search from the jewel; the cheapest route is
    scored by cost.py (effort then noise)."""
    from . import cost as costmod
    from .breach import _node_ref, _paths_to_targets
    from .pathfinder import nodes_reaching_targets

    out = []
    for nid, meta in value_by_id.items():
        node = graph.get_node(nid)
        if node is None:
            continue
        reachers = nodes_reaching_targets(graph, {nid}, max_depth=max_depth)
        actors = sum(1 for r in reachers if (g := graph.get_node(r)) is not None and g.node_type.value in ACTOR_TYPES)
        ref = _node_ref(graph, nid)
        ref["value"], ref["label"] = meta["value"], meta.get("label", "")
        ref["reachable"] = bool(reachers)
        ref["reachers"] = actors
        ref["cheapest"] = None
        if reachers:
            routes = []
            for src in _bounded_sources(graph, reachers):
                routes += _paths_to_targets(graph, src, {nid}, max_depth, max(max_paths // 8, 1)).get(nid, [])
                if len(routes) >= max_paths:
                    break
            if routes:
                route, c = costmod.cheapest(routes)
                ref["cheapest"] = {"route": route, "cost": c}
        out.append(ref)
    out.sort(key=lambda r: (-_RANK[r["value"]], not r["reachable"], -r["reachers"], r["name"].lower()))
    return out


def _bounded_sources(graph: AttackGraph, reachers: set[str], cap: int = 40) -> list[str]:
    """A bounded set of non-Tier-0 actor sources to search routes from (keeps the cheapest-route search cheap)."""
    actors = [r for r in reachers if (n := graph.get_node(r)) is not None
              and n.node_type.value in ACTOR_TYPES and n.tier != 0]
    return actors[:cap] if actors else list(reachers)[:cap]


# --------------------------------------------------------------------- per-OU grouping (for the departmental breakdown)

def ou_path(dn: str) -> str:
    """The organisational-unit path of a distinguishedName, top-down (e.g. 'Research/Labs'); '' if it has no OU."""
    ous = [p[3:] for p in str(dn).split(",") if p.strip().upper().startswith("OU=")]
    return "/".join(reversed(ous))


def group_by_ou(graph: AttackGraph, ids) -> dict[str, list[dict]]:
    """Group object ids by their OU path for a departmental breakdown. Objects with no OU go under '(no OU)'."""
    from .breach import _node_ref
    groups: dict[str, list[dict]] = {}
    for nid in ids:
        n = graph.get_node(nid)
        if n is None:
            continue
        ou = ou_path(n.properties.get("distinguishedname") or "") or "(no OU)"
        groups.setdefault(ou, []).append(_node_ref(graph, nid))
    return groups
