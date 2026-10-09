"""Ansible playbooks: the microsoft.ad / ansible.windows / community.windows modules that change who is in what.

The playbook is read, never run. Variables are resolved from play, task and `set_fact` literals; `loop` / `with_items` over
a literal list expand; embedded PowerShell (`win_shell`, `win_powershell`, `win_command`) goes through the PowerShell
extractor. A task with `when:` is analyzed as if it runs (the safe direction for a gate) and noted. Anything that changes
Active Directory but cannot be evaluated is reported by name.

Needs PyYAML (`pip install pathcutter[yaml]`).
"""
from __future__ import annotations

import re

from .common import Sink, short_name

try:                                                         # optional dependency, checked at use
    import yaml
except ImportError:                                          # pragma: no cover
    yaml = None

_VAR = re.compile(r"\{\{\s*([A-Za-z_][\w.]*)\s*\}\}")
_ANY_JINJA = re.compile(r"\{\{|\{%")

# module -> kind; short names are accepted as well as fully qualified ones
def _mod(fqcn: str) -> tuple[str, ...]:
    return (fqcn, fqcn.rsplit(".", 1)[-1])


GROUP_MODS = _mod("microsoft.ad.group") + _mod("community.windows.win_domain_group")
USER_MODS = _mod("microsoft.ad.user") + _mod("community.windows.win_domain_user")
COMPUTER_MODS = _mod("microsoft.ad.computer") + _mod("community.windows.win_domain_computer")
MEMBERSHIP_MODS = _mod("ansible.windows.win_domain_group_membership") + _mod("community.windows.win_domain_group_membership")
LOCAL_GROUP_MODS = _mod("ansible.windows.win_group_membership")
POWERSHELL_MODS = ("ansible.windows.win_shell", "win_shell", "ansible.windows.win_powershell", "win_powershell",
                   "ansible.windows.win_command", "win_command")
# local group name -> the edge it gives on the host
LOCAL_GROUP_EDGE = {"administrators": "AdminTo", "remote desktop users": "CanRDP", "remote management users": "CanPSRemote",
                    "distributed com users": "ExecuteDCOM"}
AD_PREFIXES = ("microsoft.ad.", "community.windows.win_domain", "ansible.windows.win_domain", "ansible.windows.win_user_right",
               "ansible.windows.win_acl", "community.windows.win_dsc", "ansible.windows.win_dsc", "ansible.windows.win_user",
               "ansible.windows.win_group")
NOTE_ONLY = {"microsoft.ad.membership", "ansible.windows.win_domain", "ansible.windows.win_domain_controller",
             "ansible.windows.win_domain_membership", "microsoft.ad.domain", "microsoft.ad.domain_controller"}


def _loader():
    class L(yaml.SafeLoader):
        pass

    def construct(loader, node):
        loader.flatten_mapping(node)
        m = {}
        for k, v in node.value:
            m[loader.construct_object(k, deep=True)] = loader.construct_object(v, deep=True)
        m["__line__"] = node.start_mark.line + 1
        return m
    L.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, construct)
    return L


def extract(text: str, origin: str, start_index: int = 1):
    sink = Sink(origin, start_index)
    if yaml is None:
        sink.warn(1, "PyYAML is not installed (pip install pathcutter[yaml]): this Ansible file was NOT analyzed")
        return sink.result()
    try:
        doc = yaml.load(text, Loader=_loader())
    except yaml.YAMLError as exc:
        sink.warn(1, f"could not parse the YAML: {str(exc).splitlines()[0]}")
        return sink.result()
    plays = doc if isinstance(doc, list) else [doc]
    for play in plays:
        if not isinstance(play, dict):
            continue
        if "tasks" in play or "roles" in play or "pre_tasks" in play or "post_tasks" in play or "hosts" in play:
            _play(play, sink)
        else:
            _tasks([play], {}, [], sink)               # a bare task list file (role tasks/main.yml)
    return sink.result()


def _play(play: dict, sink: Sink) -> None:
    env = dict(play.get("vars") or {})
    hosts = _hosts(play.get("hosts"))
    if play.get("roles"):
        sink.warn(play.get("__line__", 1), "roles are not followed: tasks inside roles were not analyzed (point at the role's tasks/main.yml)")
    if play.get("vars_files"):
        sink.warn(play.get("__line__", 1), "vars_files are not read: variables defined there are treated as unresolved")
    for key in ("pre_tasks", "tasks", "post_tasks", "handlers"):
        _tasks(play.get(key) or [], env, hosts, sink)


def _hosts(v) -> list[str]:
    if isinstance(v, str):
        return [h.strip() for h in v.split(",") if h.strip()]
    if isinstance(v, list):
        return [str(h) for h in v]
    return []


def _tasks(tasks: list, env: dict, hosts: list[str], sink: Sink) -> None:
    for t in tasks:
        if not isinstance(t, dict):
            continue
        if any(k in t for k in ("block", "rescue", "always")):
            for k in ("block", "rescue", "always"):
                _tasks(t.get(k) or [], {**env, **(t.get("vars") or {})}, hosts, sink)
            continue
        if "set_fact" in t and isinstance(t["set_fact"], dict):
            env.update({k: v for k, v in t["set_fact"].items() if k != "__line__"})
            continue
        local = {**env, **(t.get("vars") or {})}
        items = _loop_items(t, local, sink)
        if items is None:
            continue
        for item in items:
            _task(t, {**local, "item": item} if item is not _NOITEM else local, hosts, sink)


_NOITEM = object()


def _loop_items(t: dict, env: dict, sink: Sink):
    for key in ("loop", "with_items", "with_list"):
        if key in t:
            v = t[key]
            if isinstance(v, str):
                m = _VAR.fullmatch(v.strip())
                v = env.get(m.group(1)) if m else None
            if isinstance(v, list):
                return v
            sink.warn(t.get("__line__", 1), f"loop over a value that cannot be expanded ({key}): the task was not analyzed")
            return None
    return [_NOITEM]


def _subst(v, env: dict):
    """Resolve {{ var }} in a string; returns (value, ok). Lists are resolved element-wise by the caller."""
    if not isinstance(v, str) or not _ANY_JINJA.search(v):
        return v, True
    full = _VAR.fullmatch(v.strip())
    if full:
        val = _lookup(env, full.group(1))
        if val is None or (isinstance(val, str) and _ANY_JINJA.search(val)):
            return v, False
        return val, True
    ok = True

    def rep(m):
        nonlocal ok
        val = _lookup(env, m.group(1))
        if isinstance(val, (str, int)) and not _ANY_JINJA.search(str(val)):
            return str(val)
        ok = False
        return m.group(0)
    out = _VAR.sub(rep, v)
    return out, ok and not _ANY_JINJA.search(out)


def _lookup(env: dict, dotted: str):
    cur = env
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _names(v, env, line, sink, what) -> list[str]:
    """A scalar or list of names -> resolved strings; unresolvable entries are reported."""
    items = v if isinstance(v, list) else ([] if v is None else [v])
    out = []
    for it in items:
        val, ok = _subst(it, env)
        if isinstance(val, list):
            out.extend(str(x) for x in val)
        elif ok and isinstance(val, (str, int)):
            out.append(str(val))
        else:
            sink.warn(line, f"{what}: '{it}' cannot be resolved to a name; it was not analyzed")
    return out


def _one(v, env, line, sink, what):
    n = _names(v, env, line, sink, what)
    return n[0] if n else None


def _task(t: dict, env: dict, hosts: list[str], sink: Sink) -> None:
    line = t.get("__line__", 1)
    module = next((k for k in t if k not in _TASK_KEYS and k != "__line__"), None)
    if module is None:
        return
    args = t[module]
    label = t.get("name") or module
    if t.get("when") is not None:
        sink.warn(line, f"'{label}' has a when: condition; it is analyzed as if it runs", level="note")
    if module in GROUP_MODS:
        _group(args, env, line, sink, label)
    elif module in USER_MODS:
        _user(args, env, line, sink, label)
    elif module in COMPUTER_MODS:
        _computer(args, env, line, sink, label)
    elif module in MEMBERSHIP_MODS:
        _membership(args, env, line, sink, label)
    elif module in LOCAL_GROUP_MODS:
        _local_group(args, env, hosts, line, sink, label)
    elif module in POWERSHELL_MODS:
        _embedded_powershell(args, env, line, sink, label)
    elif module in NOTE_ONLY:
        sink.warn(line, f"{module} ({label}) is recognised and does not change who can reach what", level="note")
    elif module.startswith(AD_PREFIXES):
        sink.warn(line, f"{module} ({label}) changes directory or access configuration that PathCutter does not model")


_TASK_KEYS = {"name", "when", "register", "vars", "loop", "with_items", "with_list", "loop_control", "tags", "become", "become_user",
              "delegate_to", "ignore_errors", "changed_when", "failed_when", "no_log", "notify", "environment", "args", "retries",
              "delay", "until", "check_mode", "diff", "run_once", "any_errors_fatal", "throttle", "timeout", "connection",
              "block", "rescue", "always", "listen", "collections", "module_defaults"}


def _state(args: dict, default="present") -> str:
    return str(args.get("state", default)).lower()


def _create(kind: str, name: str, line: int, sink: Sink, raw: str) -> None:
    sink.create(kind, short_name(name.split("@")[0]) if "@" in name else short_name(name), line, raw)


def _group(args, env, line, sink, label):
    if not isinstance(args, dict):
        return
    name = _one(args.get("name"), env, line, sink, label)
    if not name:
        return
    if _state(args) == "absent":
        sink.add("delete", name, "", "", line, f"{label}: delete group {name}")
        return
    _create("group", name, line, sink, label)
    m = args.get("members")
    if isinstance(m, dict):
        for who in _names(m.get("add"), env, line, sink, label) + _names(m.get("set"), env, line, sink, label):
            sink.add("add", short_name(who), "MemberOf", name, line, f"{label}: {who} -> {name}")
        for who in _names(m.get("remove"), env, line, sink, label):
            sink.add("remove", short_name(who), "MemberOf", name, line, f"{label}: remove {who} from {name}")
        if m.get("set") is not None:
            sink.warn(line, f"{label}: members.set replaces the whole membership; members not listed are removed, which is not analyzed")
    elif m is not None:
        sink.warn(line, f"{label}: members has an unexpected shape and was not analyzed")


def _user(args, env, line, sink, label):
    if not isinstance(args, dict):
        return
    name = _one(args.get("name") or args.get("sam_account_name"), env, line, sink, label)
    if not name:
        return
    if _state(args) == "absent":
        sink.add("delete", name, "", "", line, f"{label}: delete user {name}")
        return
    _create("user", name, line, sink, label)
    groups = args.get("groups")
    if isinstance(groups, dict):                                    # microsoft.ad.user
        for g in _names(groups.get("add"), env, line, sink, label) + _names(groups.get("set"), env, line, sink, label):
            sink.add("add", name, "MemberOf", short_name(g), line, f"{label}: {name} -> {g}")
        for g in _names(groups.get("remove"), env, line, sink, label):
            sink.add("remove", name, "MemberOf", short_name(g), line, f"{label}: remove {name} from {g}")
        if groups.get("set") is not None:
            sink.warn(line, f"{label}: groups.set replaces the user's memberships; groups not listed are left, which is not analyzed")
    elif groups is not None:                                        # community.windows.win_domain_user
        action = str(args.get("groups_action", "replace")).lower()
        for g in _names(groups, env, line, sink, label):
            sink.add("remove" if action == "remove" else "add", name, "MemberOf", short_name(g), line, f"{label}: {name} / {g}")
        if action == "replace":
            sink.warn(line, f"{label}: groups_action=replace also removes other memberships, which is not analyzed")


def _computer(args, env, line, sink, label):
    if not isinstance(args, dict):
        return
    name = _one(args.get("name") or args.get("sam_account_name"), env, line, sink, label)
    if name and _state(args) != "absent":
        _create("computer", name.rstrip("$"), line, sink, label)
    elif name:
        sink.add("delete", name, "", "", line, f"{label}: delete computer {name}")


def _membership(args, env, line, sink, label):
    if not isinstance(args, dict):
        return
    group = _one(args.get("name"), env, line, sink, label)
    members = _names(args.get("members"), env, line, sink, label)
    state = _state(args)
    if not group:
        return
    for who in members:
        sink.add("remove" if state == "absent" else "add", short_name(who), "MemberOf", short_name(group), line, f"{label}: {who} / {group}")
    if state == "pure":
        sink.warn(line, f"{label}: state=pure also removes everyone not listed from {group}, which is not analyzed")


def _local_group(args, env, hosts, line, sink, label):
    if not isinstance(args, dict):
        return
    group = (_one(args.get("name"), env, line, sink, label) or "").lower()
    edge = LOCAL_GROUP_EDGE.get(group)
    members = _names(args.get("members"), env, line, sink, label)
    if edge is None:
        sink.warn(line, f"{label}: local group '{group}' is not one PathCutter models (Administrators, Remote Desktop Users, ...)", level="note")
        return
    literal = [h for h in hosts if re.fullmatch(r"[A-Za-z0-9_.$-]+", h) and h.lower() not in ("all", "localhost", "windows", "ungrouped")]
    if not literal:
        sink.warn(line, f"{label}: the target hosts ({', '.join(hosts) or 'none'}) are inventory groups or patterns that cannot be resolved "
                        f"without the inventory; the {edge} grant to {', '.join(members) or 'its members'} was not analyzed")
        return
    for host in literal:
        for who in members:
            sink.add("remove" if _state(args) == "absent" else "add", short_name(who), edge, host, line, f"{label}: {who} -> {host}")


def _embedded_powershell(args, env, line, sink, label):
    script = args if isinstance(args, str) else (args.get("script") or args.get("_raw_params") or args.get("cmd")) if isinstance(args, dict) else None
    if not isinstance(script, str):
        return
    script, ok = _subst(script, env)
    from ..powershell import extract as ps_extract
    specs, warns = ps_extract(script, sink.origin, sink.index)
    from dataclasses import replace
    for s in specs:
        sink.specs.append(replace(s, origin=f"{sink.origin}:{line}", index=sink.index))
        sink.index += 1
    for w in warns:
        sink.warns.append(replace(w, origin=f"{sink.origin}:{line}"))
    if not ok:
        sink.warn(line, f"{label}: the script uses variables that could not be resolved; the analysis of it may be incomplete")
