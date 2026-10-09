"""PowerShell DSC configurations (ActiveDirectoryDsc / PSDscResources): which group memberships, local groups and
directory ACL entries a configuration enforces.

The configuration is read, never compiled or applied. Resources: ADGroup / xADGroup (members and `Ensure`),
ADUser / ADComputer (creation), Group / xGroup (local groups on the `Node` machines), ADObjectPermissionEntry
(directory ACL entries, including Deny). Values that are variables or expressions are reported, not guessed.
DSC v3 YAML documents are not analyzed.
"""
from __future__ import annotations

import re

from .common import Sink, short_name

_HEAD = re.compile(r"^[ \t]*([A-Za-z][A-Za-z0-9_]*)[ \t]+(?:'([^']*)'|\"([^\"]*)\"|([A-Za-z_$][\w.$]*))[ \t]*\{", re.M)
_NODE = re.compile(r"^[ \t]*Node[ \t]+(.+?)[ \t]*\{", re.M | re.I)
_ASSIGN = re.compile(r"^[ \t]*([A-Za-z][A-Za-z0-9_]*)[ \t]*=[ \t]*(.+?)[ \t]*$", re.M)

AD_GROUP = {"adgroup", "xadgroup"}
AD_USER = {"aduser", "xaduser"}
AD_COMPUTER = {"adcomputer", "xadcomputer"}
LOCAL_GROUP = {"group", "xgroup"}
PERMISSION = {"adobjectpermissionentry", "xadobjectpermissionentry"}
NOTE_ONLY = {"windowsfeature", "xwindowsfeature", "file", "service", "registry", "script", "log", "package", "environment",
             "addomain", "xaddomain", "addomaincontroller", "xaddomaincontroller", "waitforaddomain", "xwaitforaddomain",
             "adorganizationalunit", "xadorganizationalunit", "dnsserveraddress", "computer", "xcomputer", "wmiaccess"}
LOCAL_EDGE = {"administrators": "AdminTo", "remote desktop users": "CanRDP", "remote management users": "CanPSRemote",
              "distributed com users": "ExecuteDCOM"}


def _balanced(text: str, open_idx: int) -> int:
    """Index just past the brace that matches text[open_idx] == '{' (strings and comments respected)."""
    depth, i, n = 0, open_idx, len(text)
    while i < n:
        c = text[i]
        if c in "'\"":
            j = i + 1
            while j < n and text[j] != c:
                j += 2 if text[j] == "`" else 1
            i = j + 1
            continue
        if c == "#":
            while i < n and text[i] != "\n":
                i += 1
            continue
        depth += {"{": 1, "}": -1}.get(c, 0)
        i += 1
        if depth == 0:
            return i
    return n


def _value(raw: str):
    """A DSC value -> str | list[str] | None (None = not a literal)."""
    raw = raw.strip().rstrip(";").strip()
    if raw.startswith("@(") and raw.endswith(")"):
        parts = _split_top(raw[2:-1])
        out = [_value(p) for p in parts if p.strip()]
        return None if any(not isinstance(o, str) for o in out) else out
    m = re.fullmatch(r"'((?:[^']|'')*)'", raw)
    if m:
        return m.group(1).replace("''", "'")
    m = re.fullmatch(r'"([^"$`]*)"', raw)
    if m:
        return m.group(1)
    if re.fullmatch(r"[A-Za-z][\w.-]*", raw):                    # a bare word, e.g. Ensure = Present
        return raw
    return None


def _split_top(s: str) -> list[str]:
    parts, cur, q = [], "", ""
    for c in s:
        if q:
            cur += c
            q = "" if c == q else q
        elif c in "'\"":
            cur += c
            q = c
        elif c in ",\n":
            parts.append(cur)
            cur = ""
        else:
            cur += c
    return parts + [cur]


def _fields(body: str) -> dict[str, tuple[str, int]]:
    """key -> (raw value, line offset). Arrays may span lines: join continuation lines first."""
    out = {}
    lines = body.split("\n")
    i = 0
    while i < len(lines):
        m = _ASSIGN.match(lines[i])
        if m:
            raw, start = m.group(2), i
            while raw.count("(") > raw.count(")") and i + 1 < len(lines):
                i += 1
                raw += "\n" + lines[i].strip()
            out[m.group(1).lower()] = (raw, start)
        i += 1
    return out


def extract(text: str, origin: str, start_index: int = 1):
    sink = Sink(origin, start_index)
    nodes = [(m.start(), m.end(), m.group(1)) for m in _NODE.finditer(text)]
    spans = []
    for s, e, label in nodes:
        spans.append((s, _balanced(text, e - 1), label))
    handled = 0
    for m in _HEAD.finditer(text):
        rtype = m.group(1).lower()
        if rtype in ("configuration", "node", "if", "else", "elseif", "foreach", "while", "switch", "function", "param", "dscresource"):
            continue
        name = m.group(2) or m.group(3) or m.group(4) or ""
        end = _balanced(text, m.end() - 1)
        body = text[m.end():end - 1]
        line0 = text.count("\n", 0, m.end()) + 1
        fields = _fields(body)
        node_label = next((lbl for s, e, lbl in spans if s < m.start() < e), None)
        if rtype in AD_GROUP:
            handled += _ad_group(sink, name, fields, line0)
        elif rtype in AD_USER:
            _create(sink, "user", fields, "username", name, line0)
        elif rtype in AD_COMPUTER:
            _create(sink, "computer", fields, "computername", name, line0)
        elif rtype in LOCAL_GROUP:
            _local_group(sink, name, fields, node_label, line0)
        elif rtype in PERMISSION:
            _permission(sink, name, fields, line0)
        elif rtype in NOTE_ONLY:
            continue
        elif rtype.startswith(("ad", "xad")):
            sink.warn(line0, f"DSC resource {m.group(1)} '{name}' changes directory configuration that PathCutter does not model")
    return sink.result()


def _get(fields, key, sink, line, what):
    if key not in fields:
        return None
    v = _value(fields[key][0])
    if v is None:
        sink.warn(line + fields[key][1], f"{what}: {key} = {fields[key][0].strip()[:60]} is not a literal; it was not analyzed")
    return v


def _as_list(v):
    return [] if v is None else (v if isinstance(v, list) else [v])


def _ensure_absent(fields, sink, line) -> bool:
    v = _get(fields, "ensure", sink, line, "Ensure")
    return isinstance(v, str) and v.lower() == "absent"


def _ad_group(sink, name, fields, line) -> int:
    group = _get(fields, "groupname", sink, line, f"ADGroup '{name}'") or name
    if _ensure_absent(fields, sink, line):
        sink.add("delete", short_name(group), "", "", line, f"ADGroup '{name}' Ensure=Absent")
        return 1
    sink.create("group", short_name(group), line, f"ADGroup '{name}'")
    for who in _as_list(_get(fields, "membertoinclude" if "membertoinclude" in fields else "memberstoinclude", sink, line, f"ADGroup '{name}'")):
        sink.add("add", short_name(who), "MemberOf", short_name(group), line, f"ADGroup '{name}': {who}")
    for who in _as_list(_get(fields, "memberstoexclude", sink, line, f"ADGroup '{name}'")):
        sink.add("remove", short_name(who), "MemberOf", short_name(group), line, f"ADGroup '{name}': remove {who}")
    members = _get(fields, "members", sink, line, f"ADGroup '{name}'")
    for who in _as_list(members):
        sink.add("add", short_name(who), "MemberOf", short_name(group), line, f"ADGroup '{name}': {who}")
    if "members" in fields:
        sink.warn(line, f"ADGroup '{name}': Members enforces the exact membership; members not listed are removed, which is not analyzed")
    return 1


def _create(sink, kind, fields, key, name, line):
    n = _get(fields, key, sink, line, f"AD{kind.title()} '{name}'") or _get(fields, "name", sink, line, name) or name
    if _ensure_absent(fields, sink, line):
        sink.add("delete", short_name(n), "", "", line, f"AD{kind.title()} '{name}' Ensure=Absent")
    else:
        sink.create(kind, short_name(n), line, f"AD{kind.title()} '{name}'")


def _local_group(sink, name, fields, node_label, line):
    group = str(_get(fields, "groupname", sink, line, f"Group '{name}'") or name).lower()
    edge = LOCAL_EDGE.get(group)
    if edge is None:
        sink.warn(line, f"Group '{name}': local group '{group}' is not one PathCutter models", level="note")
        return
    node = (node_label or "").strip()
    hosts = re.findall(r"'([^']+)'|\"([^\"$]+)\"", node)
    hosts = [a or b for a, b in hosts] or ([node] if re.fullmatch(r"[A-Za-z0-9_.-]+", node) and node.lower() not in ("localhost", "*") else [])
    if not hosts:
        sink.warn(line, f"Group '{name}': the target machines ({node or 'no Node block'}) cannot be resolved; the {edge} grant was not analyzed")
        return
    absent = _ensure_absent(fields, sink, line)
    include = _as_list(_get(fields, "memberstoinclude", sink, line, f"Group '{name}'")) + _as_list(_get(fields, "members", sink, line, f"Group '{name}'"))
    exclude = _as_list(_get(fields, "memberstoexclude", sink, line, f"Group '{name}'"))
    for h in hosts:
        for who in include:
            sink.add("remove" if absent else "add", short_name(who), edge, h, line, f"Group '{name}' on {h}: {who}")
        for who in exclude:
            sink.add("remove", short_name(who), edge, h, line, f"Group '{name}' on {h}: remove {who}")
    if "members" in fields:
        sink.warn(line, f"Group '{name}': Members enforces the exact membership; members not listed are removed, which is not analyzed")


def _permission(sink, name, fields, line):
    from ..ps_rules import PROP_GUIDS, rights_to_edges
    path = _get(fields, "path", sink, line, f"ADObjectPermissionEntry '{name}'")
    ident = _get(fields, "identityreference", sink, line, f"ADObjectPermissionEntry '{name}'")
    rights = _get(fields, "activedirectoryrights", sink, line, f"ADObjectPermissionEntry '{name}'")
    if not (path and ident and rights):
        return
    deny = str(_get(fields, "accesscontroltype", sink, line, name) or "Allow").lower() == "deny"
    guid = str(_get(fields, "objecttype", sink, line, name) or "").lower()
    edges, note = rights_to_edges(", ".join(_as_list(rights)), PROP_GUIDS.get(guid, ""), deny)
    absent = _ensure_absent(fields, sink, line)
    for e in edges:
        op = ("undeny" if absent else "deny") if deny else ("remove" if absent else "add")
        sink.add({"deny": "add", "undeny": "remove"}.get(op, op), short_name(ident), e, short_name(path), line,
                 f"ADObjectPermissionEntry '{name}'", deny=deny)
    if not edges:
        sink.warn(line, f"ADObjectPermissionEntry '{name}': {note or 'no modeled right'}", level="note")
