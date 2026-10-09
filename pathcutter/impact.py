"""Change impact analysis - what would these AD changes do to attack paths?

Given a baseline graph and a set of resolved changes, measure (exactly, via
exposure.py) who gains or loses a route to Tier 0, attribute each effect to the
change that caused it, catch effects that only appear when changes are combined,
and suggest which existing edges to fix so a risky change becomes safe.

The module is pure analysis: it never reads files and knows nothing about policy.
policy.py decides what blocks; check_report.py decides how it is shown.
"""
from __future__ import annotations

import copy
import time
from dataclasses import dataclass, field

from .changes import ResolvedChange, apply_change, undo_change, replace_node
from .choke import find_chokepoints
from .edges import get_edge_type
from .exposure import Exposure, compute_exposure, fork_with_added_edges, fork_with_removed_edges, shortened_nodes
from .graph import AttackGraph, NodeType
from .pathfinder import AttackPath, PathReport, find_all_paths
from .safety import assess_fixes
from .scoring import score_posture

SCHEMA = "pathcutter.check/1"
SEVERITIES = ["info", "low", "medium", "high", "critical"]
ACTOR_TYPES = {NodeType.USER.value, NodeType.COMPUTER.value, NodeType.AZ_USER.value, NodeType.AZ_SP.value}
MAX_PRINCIPALS_LISTED = 25
MAX_PATHS_CAPTURED = 5


def finding_context(f: "Finding") -> list[str]:
    """Plain-text lines explaining why a finding's severity differs from the raw measurement."""
    out = []
    if f.temporary:
        out.append(f"Time-bound grant ({f.temporary['label']}): the exposure window is real but ends by itself; "
                   "it is not removed.")
    c = f.control
    if c:
        if c["status"] == "applied":
            out.append(f"Severity lowered {f.original_severity} -> {f.severity} by declared control {c['id']} "
                       f"({c['type']}; owner {c['owner']}; evidence: {c['evidence']}"
                       + (f"; expires {c['expires']}" if c.get("expires") else "")
                       + "). PathCutter cannot verify this control; the path itself still exists.")
        else:
            out.append(f"Declared control {c['id']} EXPIRED {c['expires']}: it no longer lowers this finding.")
    return out


def severity_rank(sev: str) -> int:
    return SEVERITIES.index(sev)


# ------------------------------------------------------------------ data model

@dataclass
class Finding:
    id: str
    kind: str            # TIER0_PROMOTION | NEW_EXPOSURE | PATH_SHORTENED | COMBINED_EFFECT | RISK_REDUCTION | NOOP | NOTE | UNMODELED
    severity: str
    title: str
    detail: str
    changes: list[int] = field(default_factory=list)
    principals: list[dict] = field(default_factory=list)
    principal_total: int = 0
    actors_total: int = 0
    paths: list[list[dict]] = field(default_factory=list)   # concrete attack paths for the diagram
    why: list[str] = field(default_factory=list)            # what each attack edge on the path allows
    mitre: list[str] = field(default_factory=list)
    fix_first: list[dict] = field(default_factory=list)
    fix_note: str = ""
    origin: str = ""
    waiver: dict | None = None
    control: dict | None = None      # a declared compensating control that lowered the severity (not verified)
    temporary: dict | None = None    # every change is a time-bound (JIT/PAM) grant
    original_severity: str = ""      # severity before a control or JIT window lowered it
    blocking: bool = False
    superseded: bool = False     # cancelled by other changes in the same set
    ids: list[str] = field(default_factory=list, repr=False)   # every affected object id (internal)

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if k != "ids"}


@dataclass
class ChangeResult:
    index: int
    describe: str
    op: str
    origin: str
    note: str
    raw: str
    effect: str = "neutral"        # increases_exposure | reduces_exposure | neutral | noop
    noop_reason: str = ""
    assumed_new: list[str] = field(default_factory=list)
    newly_exposed: int = 0
    newly_exposed_actors: int = 0
    promoted: int = 0
    newly_secured: int = 0
    shortened: int = 0
    finding_ids: list[str] = field(default_factory=list)
    verdict: str = "ok"            # ok | review | block | waived (set by policy)

    def to_dict(self) -> dict:
        return dict(self.__dict__)


@dataclass
class ImpactReport:
    schema: str = SCHEMA
    generated: str = ""
    baseline: dict = field(default_factory=dict)
    posture: dict = field(default_factory=dict)
    totals: dict = field(default_factory=dict)
    changes: list[ChangeResult] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    verdict: str = "pass"
    verdict_reason: str = ""
    policy: dict = field(default_factory=dict)
    violations: list[dict] = field(default_factory=list)
    methodology: list[str] = field(default_factory=list)
    newly_exposed_actor_ids: set = field(default_factory=set, repr=False)
    posture_reliable: bool = True

    def to_dict(self) -> dict:
        return {
            "schema": self.schema, "generated": self.generated, "baseline": self.baseline,
            "verdict": self.verdict, "verdict_reason": self.verdict_reason,
            "posture": self.posture, "posture_reliable": self.posture_reliable, "totals": self.totals,
            "changes": [c.to_dict() for c in self.changes],
            "findings": [f.to_dict() for f in self.findings],
            "violations": self.violations, "warnings": self.warnings,
            "policy": self.policy, "methodology": self.methodology,
        }


# ---------------------------------------------------------------------- helpers

def _node_ref(graph: AttackGraph, nid: str) -> dict:
    n = graph.get_node(nid)
    if n is None:
        return {"id": nid, "name": nid, "type": "Unknown", "tier": 2, "enabled": True, "new": False}
    return {"id": nid, "name": n.display_name, "type": n.node_type.value, "tier": n.tier,
            "enabled": n.enabled, "new": nid.startswith("NEW:")}


def _path_dicts(graph: AttackGraph, exp: Exposure, nid: str,
                change_edges: set[tuple[str, str, str]]) -> list[dict]:
    steps = exp.path(nid)
    out = []
    for i, st in enumerate(steps):
        d = _node_ref(graph, st.node_id)
        d["edge"] = st.edge_type
        nxt_id = steps[i + 1].node_id if i + 1 < len(steps) else None
        d["new_edge"] = bool(st.edge_type and nxt_id and (st.node_id, nxt_id, st.edge_type) in change_edges)
        out.append(d)
    return out


def _explain(path: list[dict]) -> list[str]:
    seen, lines = set(), []
    for step in path:
        et = step.get("edge")
        if not et or et in seen:
            continue
        info = get_edge_type(et)
        if info and info.exploitability > 0:
            seen.add(et)
            lines.append(f"{et}: {info.abuse}")
    return lines


def _mitre(path: list[dict]) -> list[str]:
    out = []
    for step in path:
        info = get_edge_type(step.get("edge") or "")
        if info and info.mitre and info.mitre not in out and info.exploitability > 0:
            out.append(info.mitre)
    return out


def _principal(graph: AttackGraph, nid: str, hops_before: int | None, hops_after: int | None) -> dict:
    d = _node_ref(graph, nid)
    d["hops_before"], d["hops_after"] = hops_before, hops_after
    return d


def _sort_principals(items: list[dict]) -> list[dict]:
    return sorted(items, key=lambda p: (p["hops_after"] if p["hops_after"] is not None else 99,
                                        0 if p["type"] in ACTOR_TYPES else 1, p["name"].lower()))


def _exposure_severity(principals: list[dict]) -> str:
    actors = [p for p in principals if p["type"] in ACTOR_TYPES]
    if not actors:
        return "medium"     # latent: only groups/containers, e.g. an empty group
    min_hops = min(p["hops_after"] for p in principals if p["hops_after"] is not None)
    if min_hops <= 2 or len(actors) >= 100:
        sev = "critical"
    elif min_hops <= 4 or len(actors) >= 10:
        sev = "high"
    else:
        sev = "medium"
    if all(not a["enabled"] for a in actors):
        sev = SEVERITIES[max(severity_rank(sev) - 1, 2)]   # disabled accounts can be re-enabled
    return sev


def _membership_chain(graph: AttackGraph, start: str, tier0: set[str]) -> list[dict]:
    """Shortest MemberOf chain from a principal up to a Tier 0 group."""
    from collections import deque
    prev: dict[str, str | None] = {start: None}
    q = deque([start])
    goal = None
    while q:
        cur = q.popleft()
        if cur != start and cur in tier0:
            goal = cur
            break
        for _, tgt, data in graph.out_edges(cur):
            if data.get("edge_type") == "MemberOf" and tgt not in prev:
                prev[tgt] = cur
                q.append(tgt)
    if goal is None:
        return []
    chain, cur = [], goal
    while cur is not None:
        chain.append(cur)
        cur = prev[cur]
    chain.reverse()
    out = []
    for i, nid in enumerate(chain):
        d = _node_ref(graph, nid)
        d["edge"] = "MemberOf" if i + 1 < len(chain) else None
        d["new_edge"] = False
        out.append(d)
    return out


# ------------------------------------------------------------------ operational reality

_ACL_EDGES = {"GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "Owns", "ForceChangePassword", "AddMember",
              "WriteSPN", "AddAllowedToAct", "WriteKeyCredentialLink", "ReadLAPSPassword", "ReadGMSAPassword",
              "WriteGPLink", "DCSync"}
_REVOKABLE = {"MemberOf", "AdminTo", "CanRDP", "CanPSRemote", "ExecuteDCOM", "HasSession", "AllowedToDelegate", "AllowedToAct"}


def _operational_notes(resolved: list, before: AttackGraph, new_finding) -> None:
    """Facts about how AD behaves that the graph cannot show, attached to the changes they affect."""
    revoked: list[int] = []
    for rc in resolved:
        spec = rc.spec
        if rc.noop or spec.op in ("create", "move") or spec.deny:
            continue
        # SDProp: ACL edits on protected (adminCount=1) objects are rewritten from AdminSDHolder about hourly
        if spec.edge_type in _ACL_EDGES or spec.edge_type == "*":
            protected = []
            for _, t in rc.edge_pairs():
                n = before.get_node(t)
                if n and (n.admin_count or n.display_name.upper() == "ADMINSDHOLDER"):
                    protected.append(n.display_name)
            if protected and spec.op == "add":
                names = ", ".join(sorted(set(protected))[:3])
                new_finding(kind="NOTE", severity="low", changes=[spec.index],
                            title=f"SDProp: {names} is a protected object, so this grant may be reverted within about an hour",
                            detail=(f"{spec.describe()} targets an object with adminCount=1. SDProp rewrites the ACL of protected "
                                    "objects from AdminSDHolder roughly every 60 minutes, so the ACE will usually disappear again "
                                    "unless it is ALSO set on AdminSDHolder, which would grant it on every protected object. "
                                    "Treat it as a short-lived exposure, not as none."))
            elif protected and spec.op == "remove" and rc.removed_edges:
                names = ", ".join(sorted(set(protected))[:3])
                new_finding(kind="NOTE", severity="low", changes=[spec.index],
                            title=f"SDProp: the same ACE may return on {names}",
                            detail=(f"{spec.describe()} edits a protected object (adminCount=1). If the ACE also exists on "
                                    "AdminSDHolder, SDProp restores it within about 60 minutes. Check and fix AdminSDHolder too."))
        if spec.op == "remove" and rc.removed_edges and (spec.edge_type in _REVOKABLE or spec.edge_type in ("*", "")):
            revoked.append(spec.index)
        if spec.op == "delete" and rc.removed_edges:
            revoked.append(spec.index)
    if revoked:
        new_finding(kind="NOTE", severity="low", changes=revoked,
                    title=f"Revocation is not instant ({len(revoked)} change{'s' if len(revoked) != 1 else ''})",
                    detail=("Removing a membership or right does not end sessions that already exist: a user who is logged on keeps "
                            "the access in their current token and Kerberos tickets (TGT lifetime defaults to 10 hours, renewable "
                            "7 days) until they sign out or the tickets expire, and changes take time to replicate between domain "
                            "controllers. To cut off a compromised account now, also reset its password twice (and krbtgt for a "
                            "domain-wide compromise), and end its sessions."))


# ------------------------------------------------------------------ main entry

def analyze_impact(baseline: AttackGraph, resolved: list[ResolvedChange], **kw) -> ImpactReport:
    from contextlib import ExitStack
    with ExitStack() as stack:                        # the in-place probe on the working copy is undone on the way out
        return _analyze_impact(baseline, resolved, stack, **kw)


def _analyze_impact(baseline: AttackGraph, resolved: list[ResolvedChange], stack, *,
                    extra_tier0: set[str] | None = None,
                    unmodeled: list | None = None,
                    max_depth: int = 20, max_paths: int = 10000,
                    max_marginal: int = 150) -> ImpactReport:
    t_start = time.time()
    rep = ImpactReport(generated=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))

    before = baseline.clone()
    before.retier(extra_tier0)
    exp_b = compute_exposure(before)
    t0_b = frozenset(before.tier0_nodes)
    if not t0_b:
        rep.warnings.append("The baseline has no Tier 0 objects, so no attack path can exist. Check that the baseline is a complete SharpHound collection.")

    after = before.clone()
    for rc in resolved:
        apply_change(after, rc)
    after.retier(extra_tier0)
    exp_a = compute_exposure(after)
    t0_a = frozenset(after.tier0_nodes)

    change_edges_all = set().union(*(rc.edge_keys() for rc in resolved)) if resolved else set()

    exposed_b, exposed_a = exp_b.exposed(), exp_a.exposed()
    unverified = exp_b.unverified | exp_a.unverified
    if unverified:
        rep.warnings.append(f"{len(unverified)} object(s) are flagged because of a cyclic route that could not be fully verified "
                            "within the search budget; they are kept as exposed to stay on the safe side.")
    promoted = t0_a - t0_b
    demoted = {n for n in (t0_b - t0_a) if after.get_node(n)}
    newly_exposed = exposed_a - exposed_b - promoted - demoted
    newly_secured = exposed_b - exposed_a - promoted
    shortened = {n for n in exposed_a & exposed_b
                 if exp_a.hops(n) is not None and exp_b.hops(n) is not None and exp_a.hops(n) < exp_b.hops(n)}

    # ---- posture (same scoring as `analyze`, so the numbers are comparable)
    pr_b = find_all_paths(before, before.tier0_nodes, max_depth, max_paths)
    pr_a = find_all_paths(after, after.tier0_nodes, max_depth, max_paths)
    ps_b, ps_a = score_posture(before, pr_b), score_posture(after, pr_a)
    sig = lambda p: (tuple(p.nodes), tuple(p.edge_types))  # noqa: E731
    sigs_b, sigs_a = {sig(p) for p in pr_b.paths}, {sig(p) for p in pr_a.paths}
    truncated = pr_b.total_paths >= max_paths or pr_a.total_paths >= max_paths
    if truncated:
        rep.warnings.append(f"Path enumeration hit the {max_paths}-path cap: path counts and the risk score are approximate and "
                            "path add/remove counts are not shown. Exposure results (who can reach Tier 0) are exact and unaffected.")

    def actors(ids) -> int:
        return sum(1 for n in ids if (after.get_node(n) or before.get_node(n)) and
                   (after.get_node(n) or before.get_node(n)).node_type.value in ACTOR_TYPES)

    rep.posture = {
        "before": {"score": ps_b.score, "grade": ps_b.grade, "paths": ps_b.total_paths,
                   "exposed": len(exposed_b), "exposed_actors": actors(exposed_b), "tier0": len(t0_b)},
        "after": {"score": ps_a.score, "grade": ps_a.grade, "paths": ps_a.total_paths,
                  "exposed": len(exposed_a), "exposed_actors": actors(exposed_a), "tier0": len(t0_a)},
        "score_delta": ps_a.score - ps_b.score,
    }
    rep.totals = {
        "changes": len(resolved), "newly_exposed": len(newly_exposed),
        "newly_exposed_actors": actors(newly_exposed), "newly_secured": len(newly_secured),
        "newly_secured_actors": actors(newly_secured), "promoted": len(promoted), "demoted": len(demoted),
        "shortened": len(shortened),
        # When enumeration is capped, which paths fit under the cap is arbitrary, so a diff of path sets is noise.
        "paths_added": None if truncated else len(sigs_a - sigs_b),
        "paths_removed": None if truncated else len(sigs_b - sigs_a),
        "paths_truncated": truncated,
    }
    rep.posture_reliable = not truncated
    rep.changes = [
        ChangeResult(rc.spec.index, rc.spec.describe(), rc.spec.op, rc.spec.origin, rc.spec.note, rc.spec.raw,
                     noop_reason=rc.noop_reason, assumed_new=list(rc.assumed_new),
                     effect="noop" if rc.noop else "neutral")
        for rc in resolved
    ]
    by_index = {c.index: c for c in rep.changes}

    # ---- per-change (marginal) attribution on a scratch copy of the baseline
    findings: list[Finding] = []
    finding_sources: dict[str, set[str]] = {}
    counter = [0]

    def new_finding(sources: set[str] | None = None, **kw) -> Finding:
        counter[0] += 1
        f = Finding(id=f"F{counter[0]}", **kw)
        if sources:
            finding_sources[f.id] = set(sources)
        findings.append(f)
        for idx in f.changes:
            if idx in by_index:
                by_index[idx].finding_ids.append(f.id)
        return f

    marginal_exposed: set[str] = set()
    edge_changes = [rc for rc in resolved if rc.spec.op != "create" and not rc.noop]
    do_marginal = len(edge_changes) <= max_marginal
    if not do_marginal:
        rep.warnings.append(f"{len(edge_changes)} changes exceed the per-change attribution limit ({max_marginal}); "
                            "totals are exact but effects are not attributed to individual changes.")

    if do_marginal:
        scratch = stack.enter_context(before.probe(extra_tier0))      # in place: no copy of the graph per trial
        for rc in resolved:
            for node in rc.new_nodes:
                if scratch.get_node(node.object_id) is None:
                    scratch.add_node(replace_node(node))
        for rc in edge_changes:
            probe = copy.copy(rc)
            probe.removed_edges = []
            probe.noop = False
            if not apply_change(scratch, probe):
                continue
            scratch.retier(extra_tier0)
            t0_i = frozenset(scratch.tier0_nodes)
            if (probe.spec.op == "add" and not probe.spec.deny and t0_i == t0_b and not scratch.denies
                    and getattr(exp_b, "fx", None) is not None):
                # adding edges only shortens or creates routes: derive the result from the baseline instead of recomputing
                exp_i = fork_with_added_edges(exp_b, scratch, [(s, t, probe.spec.edge_type) for s, t in probe.added_pairs])
            elif (probe.spec.op in ("remove", "delete") and not probe.spec.deny and t0_i == t0_b and not scratch.denies
                  and getattr(exp_b, "fx", None) is not None and probe.removed_edges):
                # removing edges can only lengthen or cut routes: re-attach just the states that used them
                exp_i = fork_with_removed_edges(exp_b, scratch, [(s, t, d.get("edge_type", probe.spec.edge_type))
                                                                 for s, t, d in probe.removed_edges])
            else:
                exp_i = compute_exposure(scratch)
            prom_i = t0_i - t0_b
            dem_i = {n for n in (t0_b - t0_i) if scratch.get_node(n)}
            exposed_i = exp_i.exposed()
            new_i = exposed_i - exposed_b - prom_i - dem_i
            sec_i = exposed_b - exposed_i - prom_i
            short_i = shortened_nodes(exp_b, exp_i, exposed_b, exposed_i)
            marginal_exposed |= new_i
            edge = probe.edge_keys()
            cr = by_index[rc.spec.index]
            cr.newly_exposed, cr.newly_exposed_actors = len(new_i), actors(new_i)
            cr.promoted, cr.newly_secured, cr.shortened = len(prom_i), len(sec_i), len(short_i)

            if prom_i:
                plist, paths = [], []
                for nid in sorted(prom_i, key=lambda n: (scratch.get_node(n).display_name.lower() if scratch.get_node(n) else n)):
                    p = _principal(scratch, nid, None, 0)
                    plist.append(p)
                    chain = _membership_chain(scratch, nid, set(t0_i))
                    if chain and len(paths) < MAX_PATHS_CAPTURED:
                        paths.append(chain)
                names = ", ".join(p["name"] for p in plist[:3]) + (f" and {len(plist) - 3} more" if len(plist) > 3 else "")
                groups = {s["name"] for pth in paths for s in pth[1:]}
                new_finding(
                    sources=prom_i, kind="TIER0_PROMOTION", severity="critical",
                    title=f"{names} would become Tier 0",
                    detail=(f"{rc.spec.describe()} makes {names} a member of a Tier 0 group"
                            f"{' (' + ', '.join(sorted(groups)[:3]) + ')' if groups else ''}. "
                            "Tier 0 principals can take over the whole domain, and anyone able to control them gains the same reach."),
                    changes=[rc.spec.index], principals=_sort_principals(plist)[:MAX_PRINCIPALS_LISTED],
                    principal_total=len(plist), actors_total=actors(prom_i), paths=paths,
                    why=["Membership of a Tier 0 group grants domain-wide control."], mitre=["T1098"])
            if new_i:
                plist = _sort_principals([_principal(scratch, n, exp_b.hops(n), exp_i.hops(n)) for n in new_i])
                top = [p["id"] for p in plist[:MAX_PATHS_CAPTURED]]
                paths = [_path_dicts(scratch, exp_i, n, edge) for n in top]
                sev = _exposure_severity(plist)
                lead = paths[0] if paths else []
                n_act = actors(new_i)
                new_finding(
                    sources=new_i, kind="NEW_EXPOSURE", severity=sev,
                    title=f"{len(new_i)} object{'s' if len(new_i) != 1 else ''} gain{'s' if len(new_i) == 1 else ''} a path to Tier 0"
                          + (f" ({n_act} user/computer account{'s' if n_act != 1 else ''})" if n_act else " (groups only)"),
                    detail=(f"After {rc.spec.describe()}, {plist[0]['name']}"
                            f"{' and ' + str(len(plist) - 1) + ' more' if len(plist) > 1 else ''} can reach Tier 0 in "
                            f"{plist[0]['hops_after']} hop{'s' if plist[0]['hops_after'] != 1 else ''}. "
                            "Before this change none of them had a route."),
                    changes=[rc.spec.index], principals=plist[:MAX_PRINCIPALS_LISTED],
                    principal_total=len(plist), actors_total=n_act, paths=paths,
                    why=_explain(lead), mitre=_mitre(lead))
            if short_i and not new_i:
                plist = _sort_principals([_principal(scratch, n, exp_b.hops(n), exp_i.hops(n)) for n in short_i])
                paths = [_path_dicts(scratch, exp_i, plist[0]["id"], edge)]
                biggest = max(p["hops_before"] - p["hops_after"] for p in plist)
                sev = "high" if (plist[0]["hops_after"] <= 2 and len(plist) >= 10) else "medium"
                new_finding(
                    sources=short_i, kind="PATH_SHORTENED", severity=sev,
                    title=f"Attack paths get shorter for {len(plist)} object{'s' if len(plist) != 1 else ''}",
                    detail=(f"{rc.spec.describe()} gives existing attackers a shortcut: up to {biggest} fewer hop"
                            f"{'s' if biggest != 1 else ''} to Tier 0. Shorter paths are easier to find and to abuse."),
                    changes=[rc.spec.index], principals=plist[:MAX_PRINCIPALS_LISTED], principal_total=len(plist),
                    actors_total=actors(short_i), paths=paths, why=_explain(paths[0]), mitre=_mitre(paths[0]))
            if sec_i and not new_i and not prom_i:
                plist = _sort_principals([_principal(scratch, n, exp_b.hops(n), None) for n in sec_i])
                new_finding(
                    sources=sec_i, kind="RISK_REDUCTION", severity="info",
                    title=f"Removes the path to Tier 0 for {len(plist)} object{'s' if len(plist) != 1 else ''}",
                    detail=f"{rc.spec.describe()} cuts every route to Tier 0 for these objects. This is a risk reduction.",
                    changes=[rc.spec.index], principals=plist[:MAX_PRINCIPALS_LISTED], principal_total=len(plist),
                    actors_total=actors(sec_i))
            cr.effect = ("increases_exposure" if (new_i or prom_i or short_i)
                         else "reduces_exposure" if sec_i else "neutral")
            undo_change(scratch, probe)

    # ---- effects that only exist when changes are combined
    combined_only = newly_exposed - marginal_exposed
    if do_marginal and combined_only:
        plist = _sort_principals([_principal(after, n, exp_b.hops(n), exp_a.hops(n)) for n in combined_only])
        paths = [_path_dicts(after, exp_a, p["id"], change_edges_all) for p in plist[:MAX_PATHS_CAPTURED]]
        on_paths = {(s["id"], paths[j][k + 1]["id"], s["edge"]) for j, pth in enumerate(paths)
                    for k, s in enumerate(pth[:-1]) if s.get("new_edge")}
        involved = sorted({rc.spec.index for rc in resolved if rc.edge_keys() & on_paths})
        sev = SEVERITIES[max(severity_rank(_exposure_severity(plist)), severity_rank("high"))]
        new_finding(
            sources=combined_only, kind="COMBINED_EFFECT", severity=sev,
            title=f"{len(plist)} object{'s' if len(plist) != 1 else ''} become exposed only when changes are combined",
            detail=("Each change looks harmless on its own, but together they open a route to Tier 0"
                    f" (changes {', '.join('#' + str(i) for i in involved) if involved else 'in this set'}). "
                    "Review them as one unit, not as separate tickets."),
            changes=involved or [c.index for c in rep.changes], principals=plist[:MAX_PRINCIPALS_LISTED],
            principal_total=len(plist), actors_total=actors(combined_only), paths=paths,
            why=_explain(paths[0] if paths else []), mitre=_mitre(paths[0] if paths else []))
    elif not do_marginal and newly_exposed:
        plist = _sort_principals([_principal(after, n, exp_b.hops(n), exp_a.hops(n)) for n in newly_exposed])
        paths = [_path_dicts(after, exp_a, p["id"], change_edges_all) for p in plist[:MAX_PATHS_CAPTURED]]
        new_finding(sources=newly_exposed, kind="NEW_EXPOSURE", severity=_exposure_severity(plist),
                    title=f"{len(plist)} object{'s' if len(plist) != 1 else ''} gain{'s' if len(plist) == 1 else ''} a path to Tier 0",
                    detail="The change set as a whole opens routes to Tier 0.",
                    changes=[c.index for c in rep.changes], principals=plist[:MAX_PRINCIPALS_LISTED],
                    principal_total=len(plist), actors_total=actors(newly_exposed), paths=paths,
                    why=_explain(paths[0] if paths else []), mitre=_mitre(paths[0] if paths else []))

    # ---- no-ops and unmodeled input
    for rc in resolved:
        if rc.noop:
            by_index[rc.spec.index].effect = "noop"
            new_finding(kind="NOOP", severity="low", title=f"Change #{rc.spec.index} has no effect",
                        detail=f"{rc.spec.describe()}: {rc.noop_reason}.", changes=[rc.spec.index])
        if rc.assumed_new:
            rep.warnings.append(f"#{rc.spec.index}: assumed {', '.join(rc.assumed_new)} to be new object(s) with no existing permissions.")
    for w in unmodeled or []:
        if getattr(w, "level", "review") == "note":
            new_finding(kind="NOTE", severity="low", title=w.message[:110],
                        detail="Recognised in the script; it does not change who can reach Tier 0, or its "
                               "effect is described here for your review.", origin=w.origin)
            continue
        new_finding(kind="UNMODELED", severity="medium",
                    title=("Not analyzed: " + w.message)[:110],
                    detail=("This part of the script was NOT analyzed, so its effect on attack paths is unknown. "
                            "Express it as an explicit change line (grant/revoke/add-member) or review it by hand."),
                    origin=w.origin)

    _operational_notes(resolved, before, new_finding)

    # ---- judge the FINAL state: drop or trim effects that other changes in the set cancel
    final_for = {"NEW_EXPOSURE": exposed_a | promoted, "PATH_SHORTENED": shortened,
                 "TIER0_PROMOTION": promoted, "RISK_REDUCTION": newly_secured}
    all_idx = {c.index for c in rep.changes}
    for f in findings:
        src = finding_sources.get(f.id)
        if f.kind not in final_for or not src:
            continue
        remaining = src & final_for[f.kind]
        if remaining == src:
            continue
        others = sorted(all_idx - set(f.changes))
        if not remaining:
            f.superseded, f.severity, f.fix_first = True, "info", []
            f.detail += (" However, the other changes in this set"
                         f" ({', '.join('#' + str(i) for i in others)}) cancel it, so the final state is not affected.")
            continue
        finding_sources[f.id] = remaining
        if f.kind == "TIER0_PROMOTION":
            plist = _sort_principals([_principal(after, n, None, 0) for n in remaining])
        elif f.kind == "RISK_REDUCTION":
            plist = _sort_principals([_principal(after, n, exp_b.hops(n), None) for n in remaining])
        else:
            plist = _sort_principals([_principal(after, n, exp_b.hops(n), exp_a.hops(n)) for n in remaining])
            f.paths = [_path_dicts(after, exp_a, p["id"], change_edges_all) for p in plist[:MAX_PATHS_CAPTURED]]
            f.why, f.mitre = _explain(f.paths[0]), _mitre(f.paths[0])
            if f.kind == "NEW_EXPOSURE":
                f.severity = _exposure_severity(plist)
        f.principals, f.principal_total, f.actors_total = plist[:MAX_PRINCIPALS_LISTED], len(plist), actors(remaining)
        f.detail += f" (Partly cancelled by other changes in the set; {len(remaining)} of {len(src)} remain.)"
    for cr in rep.changes:
        mine = [f for f in findings if cr.index in f.changes and len(f.changes) == 1]
        live = [f for f in mine if not f.superseded]
        if any(f.kind in ("TIER0_PROMOTION", "NEW_EXPOSURE", "PATH_SHORTENED") for f in live):
            cr.effect = "increases_exposure"
        elif any(f.kind == "RISK_REDUCTION" for f in live):
            cr.effect = "reduces_exposure"
        elif cr.effect != "noop":
            cr.effect = "neutral"

    for f in findings:
        f.ids = sorted(finding_sources.get(f.id, ()))
    rep.newly_exposed_actor_ids = {n for n in newly_exposed
                                   if (after.get_node(n) and after.get_node(n).node_type.value in ACTOR_TYPES)}

    # ---- "fix these first" for every exposure finding
    _attach_fixes(after, pr_a, [f for f in findings if not f.superseded], finding_sources, change_edges_all)

    order = {"TIER0_PROMOTION": 0, "NEW_EXPOSURE": 1, "COMBINED_EFFECT": 2, "PATH_SHORTENED": 3,
             "UNMODELED": 4, "NOTE": 5, "NOOP": 5, "RISK_REDUCTION": 6}
    findings.sort(key=lambda f: (-severity_rank(f.severity), order.get(f.kind, 9), f.id))
    rep.findings = findings
    rep.methodology = _methodology(truncated)
    rep.totals["analysis_seconds"] = round(time.time() - t_start, 2)
    return rep


def _attach_fixes(after: AttackGraph, pr_a: PathReport, findings: list[Finding],
                  finding_sources: dict[str, set[str]],
                  change_edges: set[tuple[str, str, str]]) -> None:
    """Which existing edges would, if removed first, make the new exposure disappear?"""
    for f in findings:
        sources = finding_sources.get(f.id)
        if f.kind not in ("NEW_EXPOSURE", "COMBINED_EFFECT") or not sources:
            continue
        paths = [p for p in pr_a.paths if p.source in sources and
                 any((p.nodes[i], p.nodes[i + 1], e.get("edge_type")) in change_edges
                     for i, e in enumerate(p.edges))]
        if not paths:
            f.fix_note = "No other edge to cut was found within the enumerated paths."
            continue
        choke = find_chokepoints(after, PathReport(paths=paths), max_fixes=3, exclude_edges=change_edges)
        if not choke.fixes:
            f.fix_note = ("The only edge on these paths is the one this change introduces, so there is "
                          "nothing else to remediate first. Re-scope the change or accept the risk with a waiver.")
            continue
        safety = assess_fixes(after, choke.fixes)
        f.fix_first = [{
            "description": fx.description, "source": fx.source_name, "target": fx.target_name,
            "edge_type": fx.edge_type, "paths_eliminated": fx.paths_eliminated,
            "cumulative_pct": fx.cumulative_pct, "command": fx.fix_command,
            "safety": sa.risk_level.value, "warnings": sa.warnings,
        } for fx, sa in zip(choke.fixes, safety)]
        last = choke.fixes[-1].cumulative_pct
        f.fix_note = (f"Removing {'this edge' if len(choke.fixes) == 1 else 'these ' + str(len(choke.fixes)) + ' edges'} first "
                      f"breaks {last:.0f}% of the new paths, after which the change is much safer.")


def _methodology(truncated: bool) -> list[str]:
    notes = [
        "Exposure is computed exactly by reverse search from Tier 0: an object is exposed if a route to Tier 0 exists that contains at least one attack edge (not only MemberOf/Contains).",
        "Tier assignment is recomputed identically for the baseline and the modified graph, so group-membership changes correctly promote or demote principals.",
        "Each change is also evaluated alone against the baseline; effects present only in the combined result are reported as combined effects.",
        "The model covers what SharpHound collects. It does not model deny ACEs, conditional access, PAM/JIT elevation, or replication delay.",
        "Findings describe reachability, not exploitation: a path means an attacker who controls the starting object could reach Tier 0 by abusing the listed edges.",
    ]
    if truncated:
        notes.append("Path counts are capped and therefore lower bounds; exposure results are not affected by the cap.")
    return notes
