"""Gate policy - turn an ImpactReport into a verdict, with auditable waivers.

impact.py measures; this module decides. Keeping them apart means the same
analysis can be judged by different policies (strict for the domain team,
advisory for a pilot) without recomputing anything.

A waiver is an accepted risk: it names a ticket, a reason, an approver and an
expiry date, matches changes by glob, and is shown in every report. An expired
waiver stops applying and is flagged, so a risk acceptance cannot quietly become
permanent.
"""
from __future__ import annotations

import datetime as dt
import fnmatch
import json
from dataclasses import dataclass, field
from pathlib import Path

from .changes import NameIndex, ResolvedChange
from .graph import AttackGraph
from .impact import ACTOR_TYPES, SEVERITIES, ImpactReport, Finding, severity_rank

POLICY_SCHEMA = "pathcutter.policy/1"
GATED_KINDS = ("TIER0_PROMOTION", "NEW_EXPOSURE", "COMBINED_EFFECT", "PATH_SHORTENED", "UNMODELED")
ALL_KINDS = GATED_KINDS + ("RISK_REDUCTION", "NOOP", "NOTE")
_KNOWN_KEYS = {"schema", "block_severity", "block_kinds", "review_severity", "max_new_exposed_actors",
               "max_score_increase", "fail_on_unmodeled", "extra_tier0", "max_baseline_age_days",
               "require_waiver_expiry", "waivers", "controls", "jit_max_minutes"}
CONTROL_TYPES = ("conditional-access", "mfa", "pim", "vault", "tiering", "network", "monitoring", "other")
_KNOWN_CONTROL_KEYS = {"id", "type", "owner", "evidence", "expires", "source", "edge", "target", "kinds", "steps", "reason"}
_KNOWN_WAIVER_KEYS = {"id", "reason", "approver", "expires", "source", "edge", "target", "kinds", "origin"}


class PolicyError(ValueError):
    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__("\n".join(errors))


@dataclass
class Waiver:
    id: str
    reason: str
    approver: str = ""
    expires: dt.date | None = None
    source: str = "*"
    edge: str = "*"
    target: str = "*"
    kinds: tuple[str, ...] = ("*",)
    origin: str = "*"

    def is_expired(self, today: dt.date) -> bool:
        return self.expires is not None and self.expires < today

    def matches(self, rc: ResolvedChange) -> bool:
        def hit(pattern: str, *values: str) -> bool:
            return any(fnmatch.fnmatchcase(v.lower(), pattern.lower()) for v in values if v)
        s = rc.spec
        if not hit(self.edge, s.edge_type) and not (s.op in ("create", "delete") and self.edge == "*"):
            return False
        # a fan-out change (e.g. @members(HELPDESK)) matches only if EVERY expanded pair matches, or the
        # waiver names the selector itself: a waiver for one member must not cover the whole group.
        sel_src = hit(self.source, s.source)
        sel_tgt = hit(self.target, s.target)
        infos = rc.pair_info or [(rc.source_name, rc.source_id, rc.target_name, rc.target_id)]
        src_ok = sel_src or all(hit(self.source, a, b) for a, b, _, _ in infos)
        tgt_ok = sel_tgt or all(hit(self.target, c, d) for _, _, c, d in infos)
        return src_ok and tgt_ok

    def to_dict(self) -> dict:
        return {"id": self.id, "reason": self.reason, "approver": self.approver,
                "expires": self.expires.isoformat() if self.expires else None,
                "source": self.source, "edge": self.edge, "target": self.target, "kinds": list(self.kinds)}


@dataclass
class Control:
    """A DECLARED compensating control (Conditional Access, PIM approval, vaulting, tiering, ...).

    PathCutter cannot see these. A control may lower the severity of the findings it covers, but never below
    `low` (`medium` for a Tier 0 promotion or a combined effect), never hides a finding, and always says in every
    report that it was declared and not verified. It needs an owner and evidence, and ideally an expiry.
    """
    id: str
    type: str
    owner: str
    evidence: str
    reason: str = ""
    expires: dt.date | None = None
    source: str = "*"
    edge: str = "*"
    target: str = "*"
    kinds: tuple[str, ...] = ("*",)
    steps: int = 1

    def is_expired(self, today: dt.date) -> bool:
        return self.expires is not None and self.expires < today

    def matcher(self) -> Waiver:
        return Waiver(id=self.id, reason=self.reason, source=self.source, edge=self.edge, target=self.target,
                      kinds=self.kinds)

    def to_dict(self, status: str = "applied") -> dict:
        return {"id": self.id, "type": self.type, "owner": self.owner, "evidence": self.evidence,
                "reason": self.reason, "expires": self.expires.isoformat() if self.expires else None,
                "steps": self.steps, "status": status}


@dataclass
class Policy:
    block_severity: str = "high"
    block_kinds: tuple[str, ...] = ("TIER0_PROMOTION", "NEW_EXPOSURE", "COMBINED_EFFECT")
    review_severity: str = "medium"
    max_new_exposed_actors: int | None = None
    max_score_increase: int | None = None
    fail_on_unmodeled: bool = False
    extra_tier0: tuple[str, ...] = ()
    max_baseline_age_days: int | None = None
    require_waiver_expiry: bool = False
    waivers: tuple[Waiver, ...] = ()
    controls: tuple[Control, ...] = ()
    jit_max_minutes: int | None = None
    source: str = "built-in default"

    def to_dict(self) -> dict:
        return {"source": self.source, "block_severity": self.block_severity,
                "block_kinds": list(self.block_kinds), "review_severity": self.review_severity,
                "max_new_exposed_actors": self.max_new_exposed_actors,
                "max_score_increase": self.max_score_increase, "fail_on_unmodeled": self.fail_on_unmodeled,
                "extra_tier0": list(self.extra_tier0), "max_baseline_age_days": self.max_baseline_age_days,
                "require_waiver_expiry": self.require_waiver_expiry, "jit_max_minutes": self.jit_max_minutes,
                "controls": [c.to_dict("declared") for c in self.controls]}


def load_policy(path: str | Path | None) -> Policy:
    if path is None:
        return Policy()
    p = Path(path)
    try:
        data = json.loads(p.read_text(encoding="utf-8-sig"))
    except OSError as exc:
        raise PolicyError([f"cannot read policy {p}: {exc.strerror or exc}"]) from None
    except json.JSONDecodeError as exc:
        raise PolicyError([f"{p}: invalid JSON ({exc})"]) from None
    return parse_policy(data, str(p))


def parse_policy(data: dict, source: str = "<policy>") -> Policy:
    errors: list[str] = []
    if not isinstance(data, dict):
        raise PolicyError([f"{source}: policy must be a JSON object"])
    for key in data:
        if key not in _KNOWN_KEYS:
            errors.append(f"{source}: unknown key '{key}' (known: {', '.join(sorted(_KNOWN_KEYS))})")
    if data.get("schema", POLICY_SCHEMA) != POLICY_SCHEMA:
        errors.append(f"{source}: unsupported schema '{data.get('schema')}' (expected {POLICY_SCHEMA})")

    def severity(key: str, default: str) -> str:
        v = str(data.get(key, default)).lower()
        if v not in SEVERITIES:
            errors.append(f"{source}: {key} must be one of {', '.join(SEVERITIES)} (got '{v}')")
            return default
        return v

    def kinds(raw, key: str, allowed: tuple[str, ...]) -> tuple[str, ...]:
        out = []
        for k in raw:
            k = str(k).upper()
            if k != "*" and k not in allowed:
                errors.append(f"{source}: {key} contains unknown kind '{k}' (known: {', '.join(allowed)})")
            else:
                out.append(k)
        return tuple(out)

    def optional_int(key: str) -> int | None:
        v = data.get(key)
        if v is None:
            return None
        if isinstance(v, bool) or not isinstance(v, int) or v < 0:
            errors.append(f"{source}: {key} must be a non-negative integer")
            return None
        return v

    waivers: list[Waiver] = []
    require_expiry = bool(data.get("require_waiver_expiry", False))
    for n, w in enumerate(data.get("waivers", []), 1):
        where = f"{source}: waivers[{n}]"
        if not isinstance(w, dict):
            errors.append(f"{where}: must be an object")
            continue
        for k in w:
            if k not in _KNOWN_WAIVER_KEYS:
                errors.append(f"{where}: unknown key '{k}'")
        if not w.get("id") or not w.get("reason"):
            errors.append(f"{where}: 'id' (ticket) and 'reason' are required")
            continue
        expires = None
        if w.get("expires"):
            try:
                expires = dt.date.fromisoformat(str(w["expires"]))
            except ValueError:
                errors.append(f"{where}: expires must be YYYY-MM-DD (got '{w['expires']}')")
                continue
        elif require_expiry:
            errors.append(f"{where}: policy requires every waiver to have an 'expires' date")
            continue
        waivers.append(Waiver(
            id=str(w["id"]), reason=str(w["reason"]), approver=str(w.get("approver", "")), expires=expires,
            source=str(w.get("source", "*")), edge=str(w.get("edge", "*")), target=str(w.get("target", "*")),
            kinds=kinds(w.get("kinds", ["*"]), f"{where}.kinds", ALL_KINDS) or ("*",),
            origin=str(w.get("origin", "*"))))
    controls: list[Control] = []
    for n, c in enumerate(data.get("controls", []), 1):
        where = f"{source}: controls[{n}]"
        if not isinstance(c, dict):
            errors.append(f"{where}: must be an object")
            continue
        for k in c:
            if k not in _KNOWN_CONTROL_KEYS:
                errors.append(f"{where}: unknown key '{k}'")
        missing = [k for k in ("id", "type", "owner", "evidence") if not c.get(k)]
        if missing:
            errors.append(f"{where}: {', '.join(missing)} required (a control without an owner and evidence is a guess)")
            continue
        ctype = str(c["type"]).lower()
        if ctype not in CONTROL_TYPES:
            errors.append(f"{where}: type must be one of {', '.join(CONTROL_TYPES)} (got '{ctype}')")
            continue
        steps = c.get("steps", 1)
        if isinstance(steps, bool) or not isinstance(steps, int) or not 1 <= steps <= 2:
            errors.append(f"{where}: steps must be 1 or 2 (a control lowers severity by at most two levels)")
            continue
        cexp = None
        if c.get("expires"):
            try:
                cexp = dt.date.fromisoformat(str(c["expires"]))
            except ValueError:
                errors.append(f"{where}: expires must be YYYY-MM-DD (got '{c['expires']}')")
                continue
        elif require_expiry:
            errors.append(f"{where}: policy requires every control to have an 'expires' date")
            continue
        controls.append(Control(
            id=str(c["id"]), type=ctype, owner=str(c["owner"]), evidence=str(c["evidence"]),
            reason=str(c.get("reason", "")), expires=cexp, source=str(c.get("source", "*")),
            edge=str(c.get("edge", "*")), target=str(c.get("target", "*")),
            kinds=kinds(c.get("kinds", ["*"]), f"{where}.kinds", ALL_KINDS) or ("*",), steps=steps))
    block_severity = severity("block_severity", "high")
    block_kinds = kinds(data.get("block_kinds", ["TIER0_PROMOTION", "NEW_EXPOSURE", "COMBINED_EFFECT"]),
                        "block_kinds", GATED_KINDS)
    review_severity = severity("review_severity", "medium")
    max_exposed = optional_int("max_new_exposed_actors")
    max_score = optional_int("max_score_increase")
    max_age = optional_int("max_baseline_age_days")
    jit_max = optional_int("jit_max_minutes")
    if errors:
        raise PolicyError(errors)
    return Policy(
        block_severity=block_severity, block_kinds=block_kinds or Policy.block_kinds,
        review_severity=review_severity, max_new_exposed_actors=max_exposed, max_score_increase=max_score,
        fail_on_unmodeled=bool(data.get("fail_on_unmodeled", False)),
        extra_tier0=tuple(str(x) for x in data.get("extra_tier0", [])),
        max_baseline_age_days=max_age, require_waiver_expiry=require_expiry,
        waivers=tuple(waivers), controls=tuple(controls), jit_max_minutes=jit_max, source=source)


def resolve_extra_tier0(graph: AttackGraph, names: tuple[str, ...]) -> tuple[set[str], list[str]]:
    """Resolve crown-jewel names declared in the policy to object ids."""
    index = NameIndex(graph)
    ids: set[str] = set()
    errors: list[str] = []
    for name in names:
        found = index.lookup(name)
        if not found:
            errors.append(f"policy extra_tier0: '{name}' not found in the baseline")
        else:
            ids.update(n.object_id for n in found)
    return ids, errors


# --------------------------------------------------------------------- evaluation

def evaluate(report: ImpactReport, policy: Policy, resolved: list[ResolvedChange],
             today: dt.date | None = None) -> ImpactReport:
    """Annotate the report in place with waivers, blocking flags, per-change verdicts and a verdict."""
    today = today or dt.date.today()
    by_index = {rc.spec.index: rc for rc in resolved}
    review_floor = severity_rank(policy.review_severity)
    block_floor = severity_rank(policy.block_severity)
    expired_seen: dict[str, Waiver] = {}
    applied: dict[str, Waiver] = {}
    controls_applied: dict[str, Control] = {}
    controls_expired: dict[str, Control] = {}
    _soften_findings(report, policy, by_index, today, controls_applied, controls_expired)

    def waiver_for(f: Finding) -> tuple[Waiver | None, Waiver | None]:
        """(valid waiver covering every change in the finding, an expired one that would have)."""
        valid_hit = expired_hit = None
        if not f.changes:
            for w in policy.waivers:
                if f.kind in (w.kinds if "*" not in w.kinds else ALL_KINDS) and fnmatch.fnmatchcase(f.origin.lower(), w.origin.lower()) and w.origin != "*":
                    if w.is_expired(today):
                        expired_hit = expired_hit or w
                    else:
                        valid_hit = valid_hit or w
            return valid_hit, expired_hit
        covering: list[Waiver] = []
        any_expired: Waiver | None = None
        for idx in f.changes:
            rc = by_index.get(idx)
            hits = [w for w in policy.waivers if rc and ("*" in w.kinds or f.kind in w.kinds) and w.matches(rc)]
            live = [w for w in hits if not w.is_expired(today)]
            if not live:
                any_expired = any_expired or next((w for w in hits if w.is_expired(today)), None)
                return None, any_expired
            covering.append(live[0])
        return covering[0], None

    blocking_ids, review_ids, waived_ids = [], [], []
    waived_principals: set[str] = set()
    for f in report.findings:
        if f.superseded or f.kind == "RISK_REDUCTION":
            continue
        gated = ((f.kind in policy.block_kinds and severity_rank(f.severity) >= block_floor)
                 or (f.kind == "UNMODELED" and policy.fail_on_unmodeled))
        reviewable = severity_rank(f.severity) >= review_floor
        if not gated and not reviewable:
            continue
        waiver, expired = waiver_for(f)
        if waiver:
            applied[waiver.id] = waiver
            f.waiver = {**waiver.to_dict(), "status": "applied"}
            waived_ids.append(f.id)
            waived_principals.update(f.ids)
            continue
        if expired:
            expired_seen[expired.id] = expired
            f.waiver = {**expired.to_dict(), "status": "expired"}
        if gated:
            f.blocking = True
            blocking_ids.append(f.id)
        else:
            review_ids.append(f.id)

    violations: list[dict] = []
    if policy.max_new_exposed_actors is not None:
        remaining = len(report.newly_exposed_actor_ids - waived_principals)
        if remaining > policy.max_new_exposed_actors:
            violations.append({"rule": "max_new_exposed_actors", "blocking": True,
                               "message": f"{remaining} user/computer accounts gain a path to Tier 0 (limit {policy.max_new_exposed_actors})."})
    if policy.max_score_increase is not None:
        delta = report.posture.get("score_delta", 0)
        if delta > policy.max_score_increase:
            reliable = report.posture_reliable
            violations.append({"rule": "max_score_increase", "blocking": reliable,
                               "message": f"Risk score rises by {delta} points (limit {policy.max_score_increase})."
                                          + ("" if reliable else " Path enumeration was capped, so the score is approximate; treated as advisory.")})
    age = report.baseline.get("age_days")
    if policy.max_baseline_age_days is not None and age is not None and age > policy.max_baseline_age_days:
        violations.append({"rule": "max_baseline_age_days", "blocking": False,
                           "message": f"The baseline is {age} days old (limit {policy.max_baseline_age_days}); re-collect before trusting this result."})
    for wid, w in expired_seen.items():
        violations.append({"rule": "expired_waiver", "blocking": False,
                           "message": f"Waiver {wid} expired on {w.expires} and no longer applies."})
    for cid, c in controls_expired.items():
        violations.append({"rule": "expired_control", "blocking": False,
                           "message": f"Declared control {cid} expired on {c.expires}; it no longer lowers any finding."})

    # per-change verdicts
    by_finding = {f.id: f for f in report.findings}
    for cr in report.changes:
        mine = [by_finding[i] for i in cr.finding_ids if i in by_finding]
        if any(f.blocking for f in mine):
            cr.verdict = "block"
        elif any(f.id in review_ids for f in mine):
            cr.verdict = "review"
        elif any(f.waiver and f.waiver.get("status") == "applied" for f in mine):
            cr.verdict = "waived"
        else:
            cr.verdict = "ok"

    blocking_violation = any(v["blocking"] for v in violations)
    if blocking_ids or blocking_violation:
        report.verdict = "block"
        parts = []
        if blocking_ids:
            sev = [by_finding[i].severity for i in blocking_ids]
            parts.append(f"{len(blocking_ids)} blocking finding{'s' if len(blocking_ids) != 1 else ''} "
                         f"({', '.join(f'{sev.count(s)} {s}' for s in reversed(SEVERITIES) if s in sev)})")
        parts += [v["message"] for v in violations if v["blocking"]]
        report.verdict_reason = "; ".join(parts)
    elif review_ids or any(not v["blocking"] for v in violations) or report.warnings:
        report.verdict = "review"
        bits = []
        if review_ids:
            bits.append(f"{len(review_ids)} finding{'s' if len(review_ids) != 1 else ''} need a human decision")
        bits += [v["message"] for v in violations if not v["blocking"]]
        if not bits:
            bits.append("analysis completed with warnings")
        report.verdict_reason = "; ".join(bits)
    else:
        report.verdict = "pass"
        report.verdict_reason = (f"No new path to Tier 0. {len(waived_ids)} finding(s) waived." if waived_ids
                                 else "No change introduces a new path to Tier 0.")
    report.violations = violations
    report.policy = {**policy.to_dict(),
                     "waivers_applied": [w.to_dict() for w in applied.values()],
                     "waivers_expired": [w.to_dict() for w in expired_seen.values()],
                     "controls_applied": [c.to_dict("applied") for c in controls_applied.values()],
                     "controls_expired": [c.to_dict("expired") for c in controls_expired.values()],
                     "waived_findings": waived_ids}
    return report


def _lower(f: Finding, steps: int) -> None:
    """Lower severity by `steps`, never below `low` (`medium` for a Tier 0 promotion / combined effect)."""
    floor = severity_rank("medium") if f.kind in ("TIER0_PROMOTION", "COMBINED_EFFECT") else severity_rank("low")
    new = max(severity_rank(f.severity) - steps, floor)
    if new < severity_rank(f.severity):
        f.original_severity = f.original_severity or f.severity
        f.severity = SEVERITIES[new]


def _soften_findings(report: ImpactReport, policy: Policy, by_index: dict, today: dt.date,
                     applied: dict, expired: dict) -> None:
    """Time-bound (JIT) grants and declared compensating controls: lower severity, annotate, never suppress."""
    from .changes import format_ttl
    for f in report.findings:
        if f.superseded or f.kind in ("RISK_REDUCTION", "NOOP", "NOTE", "UNMODELED") or not f.changes:
            continue
        rcs = [by_index.get(i) for i in f.changes]
        if any(rc is None for rc in rcs):
            continue
        ttls = [rc.spec.ttl_minutes for rc in rcs]
        if all(ttls):
            longest = max(ttls)
            f.temporary = {"minutes": longest, "label": format_ttl(longest)}
            if policy.jit_max_minutes is not None and longest <= policy.jit_max_minutes:
                _lower(f, 1)
        if not policy.controls:
            continue
        per_change: list[tuple[int, list[Control]]] = []
        expired_hit: Control | None = None
        for rc in rcs:
            hits = [c for c in policy.controls if ("*" in c.kinds or f.kind in c.kinds) and c.matcher().matches(rc)]
            live = [c for c in hits if not c.is_expired(today)]
            if not live:
                expired_hit = expired_hit or next((c for c in hits if c.is_expired(today)), None)
                per_change = []
                break
            best = max(live, key=lambda c: c.steps)
            per_change.append((best.steps, live))
        if per_change:
            steps = min(s for s, _ in per_change)
            ctl = max(per_change[0][1], key=lambda c: c.steps)
            applied[ctl.id] = ctl
            _lower(f, steps)
            f.control = ctl.to_dict("applied")
        elif expired_hit:
            expired[expired_hit.id] = expired_hit
            f.control = expired_hit.to_dict("expired")


def baseline_age_days(path: str | Path, today: dt.date | None = None) -> int | None:
    try:
        mtime = dt.date.fromtimestamp(Path(path).stat().st_mtime)
    except OSError:
        return None
    return max(0, ((today or dt.date.today()) - mtime).days)
