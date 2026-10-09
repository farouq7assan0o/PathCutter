"""Terraform: the `ad` and `azuread` providers, from HCL configuration or from `terraform show -json` plans.

Configuration mode reads what the code WANTS (adds are judged against the baseline: a member who is already in the group is
a no-op). Plan mode reads exactly what will change (creates, updates and destroys), so removals are real removals.
Resources it does not model but that change identities are reported, never skipped, and so are count / for_each
expansions and values it cannot evaluate.
"""
from __future__ import annotations

import json

from ..azure import KNOWN_ROLES
from .common import Sink, is_guid, short_name
from .hcl import Block, HclError, Ref, Unresolved, parse

# resource type -> how it connects a member to a target (the whole Terraform surface that changes who can reach what)
RELATIONS = {
    "ad_group_membership":                  dict(target="group_id", members="group_members", edge="MemberOf"),
    "azuread_group_member":                 dict(target="group_object_id", members="member_object_id", edge="MemberOf"),
    "azuread_directory_role_assignment":    dict(target="role_id", members="principal_object_id", edge="MemberOf", role=True),
    "azuread_directory_role_member":        dict(target="role_object_id", members="member_object_id", edge="MemberOf", role=True),
    "azuread_group_owner":                  dict(target="group_object_id", members="owner_object_id", edge="AZOwns"),
    "azuread_application_owner":            dict(target="application_id", members="owner_object_id", edge="AZOwns"),
    "azuread_service_principal_owner":      dict(target="service_principal_id", members="owner_object_id", edge="AZOwns"),
}
# resources that create an object we can name
CREATES = {"ad_group": ("group", ("sam_account_name", "name")), "ad_user": ("user", ("sam_account_name", "principal_name", "display_name")),
           "ad_computer": ("computer", ("name", "sam_account_name"))}
# the label an object is known by, per resource type (to resolve `azuread_user.alice.object_id`)
NAME_ATTRS = {"ad_group": ("sam_account_name", "name"), "ad_user": ("sam_account_name", "principal_name"), "ad_computer": ("name",),
              "azuread_user": ("user_principal_name", "display_name"), "azuread_group": ("display_name",),
              "azuread_application": ("display_name",), "azuread_service_principal": ("display_name", "client_id"),
              "azuread_directory_role": ("display_name",)}
# declaring these changes no access by itself
OBJECTS_ONLY = {"azuread_user", "azuread_group", "azuread_application", "azuread_service_principal", "azuread_directory_role",
                "azuread_invitation", "azuread_administrative_unit", "azuread_named_location", "ad_ou"}
# identity-changing resources we recognise but do not model (named so the report says exactly what was skipped)
UNMODELED = {"ad_gpo_security": "GPO security settings", "ad_gplink": "GPO links", "ad_gpo": "GPO",
             "azuread_conditional_access_policy": "Conditional Access policy", "azuread_app_role_assignment": "app role assignment",
             "azuread_service_principal_delegated_permission_grant": "delegated permission grant",
             "azuread_directory_role_eligibility_schedule_request": "PIM eligibility schedule",
             "azuread_administrative_unit_role_member": "administrative unit role membership",
             "azuread_application_password": "application secret", "azuread_application_certificate": "application certificate",
             "azuread_service_principal_password": "service principal secret"}


class _Env:
    """Everything needed to turn a value into a name: resource attributes, data sources, variable defaults."""

    def __init__(self, blocks: list[Block]):
        self.resources: dict[str, Block] = {}
        self.variables: dict[str, object] = {}
        for b in blocks:
            if b.kind in ("resource", "data") and len(b.labels) == 2:
                prefix = "data." if b.kind == "data" else ""
                self.resources[f"{prefix}{b.labels[0]}.{b.labels[1]}"] = b
            elif b.kind == "variable" and b.labels:
                self.variables[b.labels[0]] = b.attrs.get("default")
            elif b.kind == "locals":
                for k, v in b.attrs.items():
                    self.variables[f"local:{k}"] = v

    def name_of(self, v, depth: int = 0):
        """str (a name / id), or None when it cannot be determined."""
        if isinstance(v, str):
            return v
        if isinstance(v, Ref) and depth < 6:
            parts = v.path.split(".")
            if parts[0] == "var" and len(parts) >= 2:
                return self.name_of(self.variables.get(parts[1]), depth + 1) if parts[1] in self.variables else None
            if parts[0] == "local" and len(parts) >= 2:
                return self.name_of(self.variables.get(f"local:{parts[1]}"), depth + 1)
            key = ".".join(parts[:3]) if parts[0] == "data" else ".".join(parts[:2])
            res = self.resources.get(key)
            if res is not None:
                typ = res.labels[0]
                for attr in NAME_ATTRS.get(typ, ()):
                    val = res.attrs.get(attr)
                    got = self.name_of(val, depth + 1) if val is not None else None
                    if got:
                        return got
        return None


def _members(env: _Env, v):
    """(list of names, list of unresolved descriptions) for a scalar or list value."""
    items = v if isinstance(v, list) else [v]
    names, bad = [], []
    for it in items:
        n = env.name_of(it)
        (names if n else bad).append(n or (it.path if isinstance(it, Ref) else getattr(it, "text", repr(it))))
    return names, bad


def _role_name(n: str) -> str:
    return KNOWN_ROLES.get(n.upper(), n) if is_guid(n) else n


def extract(text: str, origin: str, start_index: int = 1):
    sink = Sink(origin, start_index)
    stripped = text.lstrip()
    if stripped.startswith("{") and ('"resource_changes"' in text or '"planned_values"' in text):
        _from_plan(text, sink)
        return sink.result()
    try:
        blocks = parse(text)
    except HclError as exc:
        sink.warn(1, f"could not parse the Terraform file: {exc}")
        return sink.result()
    env = _Env(blocks)
    for b in blocks:
        if b.kind != "resource" or len(b.labels) != 2:
            continue
        typ = b.labels[0]
        if typ in RELATIONS:
            _relation(env, sink, b, RELATIONS[typ])
        elif typ in CREATES:
            kind, attrs = CREATES[typ]
            name = next((env.name_of(b.attrs.get(a)) for a in attrs if b.attrs.get(a) is not None and env.name_of(b.attrs.get(a))), None)
            if name:
                sink.create(kind, short_name(name.split("@")[0]) if "@" in name else short_name(name), b.line)
            else:
                sink.warn(b.line, f"{typ}.{b.labels[1]}: the name could not be determined")
        elif typ in UNMODELED:
            sink.warn(b.line, f"{typ}.{b.labels[1]} ({UNMODELED[typ]}) changes identity configuration that PathCutter does not model")
        elif typ in OBJECTS_ONLY:
            sink.warn(b.line, f"{typ}.{b.labels[1]} declares an object; it only matters once something grants it access", level="note")
        elif typ.startswith(("ad_", "azuread_")):
            sink.warn(b.line, f"{typ}.{b.labels[1]} is an identity resource PathCutter has no model for", level="review")
    return sink.result()


def _relation(env: _Env, sink: Sink, b: Block, rel: dict) -> None:
    where = f"{b.labels[0]}.{b.labels[1]}"
    if "count" in b.attrs or "for_each" in b.attrs:
        sink.warn(b.line, f"{where} uses count/for_each: the instances are not expanded, so its effect is not analyzed. "
                          "Analyze `terraform show -json` of the plan instead.")
        return
    target_v, members_v = b.attrs.get(rel["target"]), b.attrs.get(rel["members"])
    if target_v is None or members_v is None:
        sink.warn(b.line, f"{where}: missing {rel['target']} or {rel['members']}")
        return
    target = env.name_of(target_v)
    members, bad = _members(env, members_v)
    if target is None:
        sink.warn(b.line, f"{where}: {rel['target']} cannot be resolved ({getattr(target_v, 'path', getattr(target_v, 'text', target_v))})")
        return
    for u in bad:
        sink.warn(b.line, f"{where}: member {u} cannot be resolved to a name; it was not analyzed")
    tgt = _role_name(target) if rel.get("role") else (short_name(target) if rel["edge"] == "MemberOf" and not is_guid(target) else target)
    for m in members:
        src = m if (is_guid(m) or "@" in m) else short_name(m)
        sink.add("add", src, rel["edge"], tgt, b.line, f"{where}: {src} -> {tgt}")


# ------------------------------------------------------------------------------------------ plan JSON

def _from_plan(text: str, sink: Sink) -> None:
    try:
        plan = json.loads(text)
    except json.JSONDecodeError as exc:
        sink.warn(1, f"the plan is not valid JSON: {exc}")
        return
    for n, rc in enumerate(plan.get("resource_changes") or [], 1):
        typ, addr = rc.get("type", ""), rc.get("address", "")
        ch = rc.get("change") or {}
        actions = ch.get("actions") or []
        if actions in (["no-op"], ["read"]):
            continue
        before, after = ch.get("before") or {}, ch.get("after") or {}
        unknown = ch.get("after_unknown") or {}
        if typ in RELATIONS:
            rel = RELATIONS[typ]
            tb, ta = before.get(rel["target"]), after.get(rel["target"])
            old = _as_list(before.get(rel["members"])) if "delete" in actions or "update" in actions else []
            new = _as_list(after.get(rel["members"])) if "create" in actions or "update" in actions else []
            if unknown.get(rel["members"]) or unknown.get(rel["target"]):
                sink.warn(n, f"{addr}: a value is only known after apply, so its effect is not analyzed")
                continue
            tgt_new, tgt_old = _plan_target(rel, ta), _plan_target(rel, tb)
            for m in new:
                if not (tgt_old == tgt_new and m in old):
                    sink.add("add", _plan_name(m), rel["edge"], tgt_new, n, f"{addr}: add {m}")
            for m in old:
                if not (tgt_old == tgt_new and m in new) and tgt_old:
                    sink.add("remove", _plan_name(m), rel["edge"], tgt_old, n, f"{addr}: remove {m}")
        elif typ in CREATES and "create" in actions:
            kind, attrs = CREATES[typ]
            name = next((after.get(a) for a in attrs if after.get(a)), None)
            if name:
                sink.create(kind, short_name(str(name).split("@")[0]), n, addr)
        elif typ in OBJECTS_ONLY:
            continue
        elif typ in UNMODELED or (typ.startswith(("ad_", "azuread_")) and typ not in RELATIONS and typ not in CREATES):
            sink.warn(n, f"{addr} ({UNMODELED.get(typ, typ)}) changes identity configuration that PathCutter does not model")


def _as_list(v) -> list:
    return [x for x in (v if isinstance(v, list) else [v]) if x is not None]


def _plan_name(m) -> str:
    m = str(m)
    return m if (is_guid(m) or "@" in m) else short_name(m)


def _plan_target(rel: dict, v):
    if v is None:
        return None
    v = str(v)
    return _role_name(v) if rel.get("role") else (v if is_guid(v) else short_name(v))
