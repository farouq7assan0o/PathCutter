"""Change sets - describe a proposed Active Directory change, resolve it against a
baseline graph, and apply it to a copy so its attack-path impact can be measured.

Three ways to express a change (all produce the same ChangeSpec list):

* a small line-based DSL            add-member alice "DOMAIN ADMINS"  # CHG-1042
* JSON                              {"changes": [{"op": "add", ...}]}
* a PowerShell script               Add-ADGroupMember -Identity ... -Members ...

Anything the PowerShell extractor cannot model is reported as a warning rather than
silently ignored, because a gate that skips what it cannot read gives false assurance.
"""
from __future__ import annotations

import difflib
import json
import re
import shlex
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from .edges import EDGE_REGISTRY
from .graph import AttackGraph, ADEdge, ADNode, NodeType

SCHEMA = "pathcutter.changes/1"
DOMAIN_SENTINEL = "<domain>"
# Change files are untrusted input in a CI gate (the pull request author is the adversary).
MAX_CHANGE_FILE_BYTES = 2_000_000
MAX_CHANGES = 5000


class ChangeSetError(ValueError):
    """Raised with every problem found, so a user fixes the whole file in one pass."""

    def __init__(self, errors: list[str]):
        self.errors = list(errors)
        super().__init__("\n".join(self.errors))


@dataclass(frozen=True)
class ChangeSpec:
    """One proposed change, exactly as the author wrote it."""
    index: int
    op: str                    # add | remove | create
    source: str = ""
    edge_type: str = ""
    target: str = ""
    new_type: str = ""         # create only: user | group | computer
    note: str = ""
    origin: str = ""           # "file:line" for traceability
    raw: str = ""

    def describe(self) -> str:
        if self.op == "create":
            return f"create {self.new_type} {self.source}"
        verb = "grant" if self.op == "add" else "revoke"
        if self.edge_type == "MemberOf":
            return f"{'add' if self.op == 'add' else 'remove'} {self.source} {'to' if self.op == 'add' else 'from'} group {self.target}"
        return f"{verb} {self.edge_type}: {self.source} -> {self.target}"


@dataclass
class ChangeWarning:
    origin: str
    message: str
    line: str = ""


# ---------------------------------------------------------------- edge names

_EDGE_BY_LOWER = {name.lower(): et.name for name, et in EDGE_REGISTRY.items()}
_NODE_TYPE_BY_WORD = {"user": NodeType.USER, "group": NodeType.GROUP, "computer": NodeType.COMPUTER}


def canonical_edge(name: str) -> str | None:
    return _EDGE_BY_LOWER.get(name.strip().lower())


def _edge_suggestion(name: str) -> str:
    close = difflib.get_close_matches(name.lower(), list(_EDGE_BY_LOWER), n=3, cutoff=0.6)
    return f" (did you mean {', '.join(_EDGE_BY_LOWER[c] for c in close)}?)" if close else ""


# ---------------------------------------------------------------- DSL parsing

# verb -> (op, fixed edge type or None when the edge is an argument, argument count range)
_VERBS: dict[str, tuple[str, str | None, tuple[int, int]]] = {
    "add-member": ("add", "MemberOf", (2, 2)),
    "remove-member": ("remove", "MemberOf", (2, 2)),
    "local-admin": ("add", "AdminTo", (2, 2)),
    "remove-local-admin": ("remove", "AdminTo", (2, 2)),
    "delegate": ("add", "AllowedToDelegate", (2, 2)),
    "undelegate": ("remove", "AllowedToDelegate", (2, 2)),
    "rbcd": ("add", "AllowedToAct", (2, 2)),
    "remove-rbcd": ("remove", "AllowedToAct", (2, 2)),
    "session": ("add", "HasSession", (2, 2)),
    "rdp": ("add", "CanRDP", (2, 2)),
    "psremote": ("add", "CanPSRemote", (2, 2)),
    "grant-dcsync": ("add", "DCSync", (1, 2)),
    "revoke-dcsync": ("remove", "DCSync", (1, 2)),
    "grant": ("add", None, (3, 3)),
    "revoke": ("remove", None, (3, 3)),
    "add": ("add", None, (3, 3)),
    "remove": ("remove", None, (3, 3)),
}

VERB_HELP = """\
add-member <principal> <group>            remove-member <principal> <group>
local-admin <principal> <computer>        remove-local-admin <principal> <computer>
delegate <principal> <target>             undelegate <principal> <target>
rbcd <allowed-principal> <resource>       remove-rbcd <allowed-principal> <resource>
grant-dcsync <principal> [<domain>]       revoke-dcsync <principal> [<domain>]
session <user> <computer>                 rdp / psremote <principal> <computer>
grant <principal> <Right> <object>        revoke <principal> <Right> <object>
add <src> <EdgeType> <dst>                remove <src> <EdgeType> <dst>
create user|group|computer <name>
(append "# note" to attach a ticket or reason)"""


def _tokenize(line: str) -> list[str]:
    lex = shlex.shlex(line, posix=True)
    lex.whitespace_split = True
    lex.commenters = ""
    lex.escape = ""          # keep DOMAIN\user backslashes literal
    return list(lex)


def parse_line(line: str, index: int, origin: str) -> ChangeSpec | None:
    """Parse one DSL line. Returns None for blanks/comments, raises ValueError on a bad line."""
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    try:
        tokens = _tokenize(stripped)
    except ValueError as exc:
        raise ValueError(f"unbalanced quotes ({exc})") from None
    note = ""
    for i, tok in enumerate(tokens):
        if tok.startswith("#"):
            note = " ".join([tok.lstrip("#").strip()] + tokens[i + 1:]).strip()
            tokens = tokens[:i]
            break
    if not tokens:
        return None
    verb, args = tokens[0].lower(), tokens[1:]

    if verb == "create":
        if len(args) != 2 or args[0].lower() not in _NODE_TYPE_BY_WORD:
            raise ValueError("expected: create user|group|computer <name>")
        return ChangeSpec(index, "create", source=args[1], new_type=args[0].lower(),
                          note=note, origin=origin, raw=stripped)

    if verb not in _VERBS:
        close = difflib.get_close_matches(verb, list(_VERBS) + ["create"], n=2, cutoff=0.6)
        hint = f" (did you mean {' or '.join(close)}?)" if close else ""
        raise ValueError(f"unknown verb '{verb}'{hint}")
    op, fixed_edge, (lo, hi) = _VERBS[verb]
    if not lo <= len(args) <= hi:
        want = str(lo) if lo == hi else f"{lo}-{hi}"
        raise ValueError(f"'{verb}' takes {want} argument(s), got {len(args)}")

    if fixed_edge:
        edge = fixed_edge
        source = args[0]
        target = args[1] if len(args) > 1 else DOMAIN_SENTINEL
    else:
        source, edge_word, target = args
        edge = canonical_edge(edge_word)
        if edge is None:
            raise ValueError(f"unknown edge type '{edge_word}'{_edge_suggestion(edge_word)}")
    return ChangeSpec(index, op, source=source, edge_type=edge, target=target,
                      note=note, origin=origin, raw=stripped)


def parse_text(text: str, origin: str = "<changes>", start_index: int = 1) -> list[ChangeSpec]:
    specs: list[ChangeSpec] = []
    errors: list[str] = []
    idx = start_index
    for lineno, line in enumerate(text.splitlines(), 1):
        where = f"{origin}:{lineno}"
        try:
            spec = parse_line(line, idx, where)
        except ValueError as exc:
            errors.append(f"{where}: {exc}")
            continue
        if spec is not None:
            specs.append(spec)
            idx += 1
    if errors:
        raise ChangeSetError(errors)
    return specs


def parse_json(text: str, origin: str = "<changes>", start_index: int = 1) -> list[ChangeSpec]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ChangeSetError([f"{origin}: invalid JSON ({exc})"]) from None
    items = data.get("changes") if isinstance(data, dict) else data
    if not isinstance(items, list):
        raise ChangeSetError([f"{origin}: expected a list or an object with a 'changes' list"])
    specs: list[ChangeSpec] = []
    errors: list[str] = []
    idx = start_index
    for n, item in enumerate(items, 1):
        where = f"{origin}[{n}]"
        try:
            if isinstance(item, str):
                spec = parse_line(item, idx, where)
                if spec is None:
                    continue
            elif isinstance(item, dict):
                op = str(item.get("op", "add")).lower()
                note = str(item.get("note", ""))
                if op == "create":
                    ntype = str(item.get("type", "")).lower()
                    if ntype not in _NODE_TYPE_BY_WORD or not item.get("name"):
                        raise ValueError("create needs 'type' (user|group|computer) and 'name'")
                    spec = ChangeSpec(idx, "create", source=str(item["name"]), new_type=ntype,
                                      note=note, origin=where, raw=json.dumps(item))
                else:
                    if op not in ("add", "remove"):
                        raise ValueError(f"op must be add, remove or create (got '{op}')")
                    edge_word = str(item.get("edge") or item.get("edge_type") or "")
                    edge = canonical_edge(edge_word)
                    if edge is None:
                        raise ValueError(f"unknown edge type '{edge_word}'{_edge_suggestion(edge_word)}")
                    if not item.get("source") or not (item.get("target") or edge == "DCSync"):
                        raise ValueError("'source' and 'target' are required")
                    spec = ChangeSpec(idx, op, source=str(item["source"]), edge_type=edge,
                                      target=str(item.get("target") or DOMAIN_SENTINEL),
                                      note=note, origin=where, raw=json.dumps(item))
            else:
                raise ValueError("each change must be an object or a DSL string")
        except ValueError as exc:
            errors.append(f"{where}: {exc}")
            continue
        specs.append(spec)
        idx += 1
    if errors:
        raise ChangeSetError(errors)
    return specs


# ------------------------------------------------------------ PowerShell input

_PS_SWITCHES = {"passthru", "confirm", "whatif", "force", "verbose", "debug", "erroraction"}
_PS_TOKEN = re.compile(r'(?:"[^"]*"|\'[^\']*\'|[^\s"\',]+|,)+')
_PS_VALUE = re.compile(r'"[^"]*"|\'[^\']*\'|[^,]+')


def _strip_ps_comment(line: str) -> str:
    quote = ""
    for i, ch in enumerate(line):
        if quote:
            if ch == quote:
                quote = ""
        elif ch in "\"'":
            quote = ch
        elif ch == "#":
            return line[:i]
    return line


def _ps_values(token: str) -> list[str]:
    out = []
    for m in _PS_VALUE.findall(token):
        v = m.strip().strip("\"'").strip()
        if v:
            out.append(v)
    return out


_PS_VAR = re.compile(r"\$[\w{(]")


def _has_var(values: list[str]) -> bool:
    """True if any value is a PowerShell variable/expression ($user, ${x}, $($y)); WEB01$ is not."""
    return any(_PS_VAR.search(v) for v in values)


def _normalise_ref(value: str) -> str:
    """CN=Domain Admins,CN=Users,DC=corp,DC=local -> Domain Admins ; CORP\\alice -> alice"""
    v = value.strip()
    if v.upper().startswith(("CN=", "OU=")):
        return v.split(",")[0].split("=", 1)[1].strip()
    if "\\" in v and "@" not in v:
        return v.split("\\", 1)[1]
    return v


def _ps_args(rest: str) -> tuple[dict[str, list[str]], list[list[str]]]:
    """Split a cmdlet argument string into named params and positional values."""
    tokens = _PS_TOKEN.findall(rest)
    named: dict[str, list[str]] = {}
    positional: list[list[str]] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok.startswith("-") and len(tok) > 1 and not tok[1].isdigit():
            name, _, inline = tok[1:].partition(":")
            name = name.lower()
            if inline:
                named[name] = _ps_values(inline)
            elif name in _PS_SWITCHES or i + 1 >= len(tokens) or tokens[i + 1].startswith("-"):
                named[name] = []
            else:
                named[name] = _ps_values(tokens[i + 1])
                i += 1
        else:
            positional.append(_ps_values(tok))
        i += 1
    return named, positional


_PS_NET_GROUP = re.compile(r'\bnet\s+group\s+("[^"]+"|\S+)\s+("[^"]+"|\S+)\s+/(add|delete)\b', re.I)
_PS_ACL_HINT = re.compile(r"\b(Set-Acl|dsacls|Add-ADPermission|ActiveDirectoryAccessRule)\b", re.I)
_PS_AD_CMDLET = re.compile(
    r"\b(Add-ADGroupMember|Remove-ADGroupMember|Add-ADPrincipalGroupMembership|Remove-ADPrincipalGroupMembership|"
    r"Set-ADComputer|Set-ADUser|Set-ADObject|Set-ADAccountControl|Add-LocalGroupMember|Set-Acl|Add-ADPermission|dsacls)\b", re.I)


def _ps_statement_end(text: str, start: int) -> int:
    """Index of the first statement terminator (; | } newline) outside quotes."""
    quote = ""
    for i in range(start, len(text)):
        ch = text[i]
        if quote:
            if ch == quote:
                quote = ""
        elif ch in "\"'":
            quote = ch
        elif ch in ";|}":
            return i
    return len(text)


def from_powershell(text: str, origin: str = "<script>", start_index: int = 1
                    ) -> tuple[list[ChangeSpec], list[ChangeWarning]]:
    """Extract the AD changes a PowerShell script would make.

    Every statement is scanned, wherever it sits (after ';' or '|', inside if/foreach
    blocks). It models group membership, RBCD and `net group`, and reports everything
    else it recognises as AD-changing (ACL edits, unconstrained delegation, anything
    that uses variables or pipeline input) as an unmodeled warning. It never skips
    a recognised AD change silently.
    """
    specs: list[ChangeSpec] = []
    warns: list[ChangeWarning] = []
    idx = start_index

    logical: list[tuple[int, str]] = []
    pending, first_line = "", 0
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = _strip_ps_comment(raw).rstrip()
        if not pending:
            first_line = lineno
        if line.endswith("`"):
            pending += line[:-1] + " "
            continue
        logical.append((first_line, (pending + line).strip()))
        pending = ""
    if pending:
        logical.append((first_line, pending.strip()))

    def emit(op: str, src: str, edge: str, tgt: str, lineno: int, line: str):
        nonlocal idx
        specs.append(ChangeSpec(idx, op, source=_normalise_ref(src), edge_type=edge,
                                target=_normalise_ref(tgt), origin=f"{origin}:{lineno}", raw=line))
        idx += 1

    def warn(lineno: int, message: str, line: str):
        warns.append(ChangeWarning(f"{origin}:{lineno}", message, line))

    for lineno, line in logical:
        if not line:
            continue
        handled_net = False
        for m_net in _PS_NET_GROUP.finditer(line):
            grp, usr, mode = (g.strip('"') for g in m_net.groups())
            emit("add" if mode.lower() == "add" else "remove", usr, "MemberOf", grp, lineno, line)
            handled_net = True
        for m in _PS_AD_CMDLET.finditer(line):
            cmd = m.group(1).lower()
            rest = line[m.end():_ps_statement_end(line, m.end())]
            named, pos = _ps_args(rest)
            shown = m.group(1)

            def values(*names: str, position: int | None = None) -> list[str]:
                for n in names:
                    if n in named and named[n]:
                        return named[n]
                if position is not None and len(pos) > position:
                    return pos[position]
                return []

            if cmd in ("add-adgroupmember", "remove-adgroupmember"):
                group = values("identity", "group", position=0)
                members = values("members", "member", position=1)
                op = "add" if cmd.startswith("add") else "remove"
                if not group or not members or _has_var(group + members):
                    warn(lineno, f"{shown} uses a variable, pipeline input or is missing -Identity/-Members, so who is affected cannot be determined", line)
                    continue
                for member in members:
                    emit(op, member, "MemberOf", group[0], lineno, line)
            elif cmd in ("add-adprincipalgroupmembership", "remove-adprincipalgroupmembership"):
                principal = values("identity", "principal", position=0)
                groups = values("memberof", position=1)
                op = "add" if cmd.startswith("add") else "remove"
                if not principal or not groups or _has_var(principal + groups):
                    warn(lineno, f"{shown} uses a variable, pipeline input or is missing arguments, so who is affected cannot be determined", line)
                    continue
                for grp in groups:
                    emit(op, principal[0], "MemberOf", grp, lineno, line)
            elif cmd in ("set-adcomputer", "set-aduser", "set-adobject") and "principalsallowedtodelegatetoaccount" in named:
                resource = values("identity", position=0)
                allowed = named.get("principalsallowedtodelegatetoaccount", [])
                if not resource or not allowed or _has_var(resource + allowed):
                    warn(lineno, "RBCD change uses a variable, pipeline input or $null, so the principals cannot be determined", line)
                    continue
                for principal in allowed:
                    emit("add", principal, "AllowedToAct", resource[0], lineno, line)
            elif cmd == "set-adaccountcontrol" and "trustedfordelegation" in named:
                warn(lineno, "Unconstrained delegation change is not modeled by the attack graph; treat as HIGH risk and review manually", line)
            elif cmd in ("set-acl", "add-adpermission", "dsacls"):
                warn(lineno, "ACL change detected but not modeled; add an explicit 'grant'/'revoke' line to analyze it", line)
            elif cmd == "add-localgroupmember":
                warn(lineno, "Local group change affects access outside the AD graph and is not modeled", line)
        if not handled_net and _PS_ACL_HINT.search(line) and not _PS_AD_CMDLET.search(line):
            warn(lineno, "ACL change detected but not modeled; add an explicit 'grant'/'revoke' line to analyze it", line)
    return specs, warns


# ------------------------------------------------------------- source loading

def display_path(path: str | Path) -> str:
    """Repo-relative POSIX path when possible (what SARIF and PR annotations need)."""
    p = Path(path)
    try:
        return p.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except (ValueError, OSError):
        return p.as_posix()


def _read_untrusted(p: Path) -> str:
    try:
        size = p.stat().st_size
        if size > MAX_CHANGE_FILE_BYTES:
            raise ChangeSetError([f"{p}: {size:,} bytes exceeds the {MAX_CHANGE_FILE_BYTES:,}-byte limit for a change file"])
        return p.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise ChangeSetError([f"cannot read {p}: {exc.strerror or exc}"]) from None
    except UnicodeDecodeError:
        raise ChangeSetError([f"{p}: not valid UTF-8 text"]) from None


def load_change_file(path: str | Path, start_index: int = 1
                     ) -> tuple[list[ChangeSpec], list[ChangeWarning]]:
    p = Path(path)
    text = _read_untrusted(p)
    suffix, shown = p.suffix.lower(), display_path(p)
    if suffix == ".json":
        return parse_json(text, shown, start_index), []
    if suffix in (".ps1", ".psm1"):
        return from_powershell(text, shown, start_index)
    return parse_text(text, shown, start_index), []


_DIR_SUFFIXES = (".changes", ".chg", ".changes.json", ".ps1", ".psm1")


def _expand_dirs(paths: list[str], suffixes: tuple[str, ...]) -> list[tuple[str, bool]]:
    """Expand directories into their change files (sorted, so results are deterministic)."""
    out: list[tuple[str, bool]] = []
    for path in paths:
        p = Path(path)
        if p.is_dir():
            found = sorted(f for f in p.rglob("*") if f.is_file() and f.name.lower().endswith(suffixes))
            if not found:
                raise ChangeSetError([f"{path}: directory has no {'/'.join(suffixes)} files"])
            out.extend((str(f), False) for f in found)
        else:
            out.append((str(path), False))
    return out


def load_changes(files: list[str] = (), inline: list[str] = (), powershell: list[str] = ()
                 ) -> tuple[list[ChangeSpec], list[ChangeWarning]]:
    """Combine every input source into one ordered, 1-indexed change list.

    `files` and `powershell` may name directories; every change file inside is used.
    """
    specs: list[ChangeSpec] = []
    warns: list[ChangeWarning] = []
    errors: list[str] = []
    try:
        sources = [(p, False) for p, _ in _expand_dirs(list(files), _DIR_SUFFIXES)] +                   [(p, True) for p, _ in _expand_dirs(list(powershell), (".ps1", ".psm1"))]
    except ChangeSetError as exc:
        raise ChangeSetError(exc.errors) from None
    for path, is_ps in sources:
        try:
            if is_ps:
                text = _read_untrusted(Path(path))
                s, w = from_powershell(text, display_path(path), len(specs) + 1)
            else:
                s, w = load_change_file(path, len(specs) + 1)
        except ChangeSetError as exc:
            errors.extend(exc.errors)
            continue
        except OSError as exc:
            errors.append(f"cannot read {path}: {exc.strerror or exc}")
            continue
        specs.extend(s)
        warns.extend(w)
    for n, line in enumerate(inline, 1):
        try:
            spec = parse_line(line, len(specs) + 1, f"--change #{n}")
        except ValueError as exc:
            errors.append(f"--change #{n}: {exc}")
            continue
        if spec:
            specs.append(spec)
    if errors:
        raise ChangeSetError(errors)
    if len(specs) > MAX_CHANGES:
        raise ChangeSetError([f"{len(specs):,} changes exceeds the limit of {MAX_CHANGES:,} per check; split the change set"])
    return specs, warns


# ------------------------------------------------------------------ resolution

# Which node types make sense at each end of an edge (used to disambiguate names).
_ENDPOINTS: dict[str, tuple[set[NodeType] | None, set[NodeType] | None]] = {
    "MemberOf": ({NodeType.USER, NodeType.COMPUTER, NodeType.GROUP}, {NodeType.GROUP}),
    "AdminTo": (None, {NodeType.COMPUTER}),
    "HasSession": (None, {NodeType.COMPUTER}),
    "CanRDP": (None, {NodeType.COMPUTER}),
    "CanPSRemote": (None, {NodeType.COMPUTER}),
    "DCSync": (None, {NodeType.DOMAIN}),
}


@dataclass
class ResolvedChange:
    spec: ChangeSpec
    source_id: str = ""
    target_id: str = ""
    source_name: str = ""
    target_name: str = ""
    new_nodes: list[ADNode] = field(default_factory=list)   # nodes this change introduces
    assumed_new: list[str] = field(default_factory=list)    # names assumed to be new objects
    noop: bool = False
    noop_reason: str = ""
    removed_edges: list[dict] = field(default_factory=list)  # restored on undo


class NameIndex:
    """Case-insensitive lookup of baseline objects by id, name, short name or host."""

    def __init__(self, graph: AttackGraph):
        self.by_id: dict[str, ADNode] = {}
        self.by_full: dict[str, list[ADNode]] = {}
        self.by_display: dict[str, list[ADNode]] = {}
        self.by_host: dict[str, list[ADNode]] = {}
        for n in graph.all_nodes():
            self.add(n)

    def add(self, n: ADNode) -> None:
        self.by_id[n.object_id.lower()] = n
        self.by_full.setdefault(n.name.lower(), []).append(n)
        self.by_display.setdefault(n.display_name.lower(), []).append(n)
        if n.node_type == NodeType.COMPUTER:
            host = n.display_name.lower().split(".")[0]
            self.by_host.setdefault(host, []).append(n)

    def lookup(self, ref: str, allowed: set[NodeType] | None = None) -> list[ADNode]:
        r = _normalise_ref(ref).strip().lower()
        stages: list[list[ADNode]] = []
        if r in self.by_id:
            stages.append([self.by_id[r]])
        stages.append(self.by_full.get(r, []))
        stages.append(self.by_display.get(r, []))
        stages.append(self.by_host.get(r.rstrip("$").split(".")[0], []) if "@" not in r else [])
        for cands in stages:
            if allowed:
                narrowed = [c for c in cands if c.node_type in allowed]
                cands = narrowed or []
            if cands:
                seen, uniq = set(), []
                for c in cands:
                    if c.object_id not in seen:
                        seen.add(c.object_id)
                        uniq.append(c)
                return uniq
        return []

    def suggestions(self, ref: str, allowed: set[NodeType] | None = None) -> list[str]:
        pool: dict[str, str] = {}
        for key, nodes in self.by_display.items():
            if not allowed or any(n.node_type in allowed for n in nodes):
                pool[key] = nodes[0].display_name
        for host, nodes in self.by_host.items():       # computers are also known by their short name
            if not allowed or NodeType.COMPUTER in allowed:
                pool.setdefault(host, nodes[0].display_name)
        close = difflib.get_close_matches(_normalise_ref(ref).lower().rstrip("$"), list(pool), n=3, cutoff=0.6)
        out: list[str] = []
        for c in close:
            if pool[c] not in out:
                out.append(pool[c])
        return out


def _infer_domain(graph: AttackGraph) -> str:
    domains = Counter(n.domain.upper() for n in graph.all_nodes() if n.domain)
    return domains.most_common(1)[0][0] if domains else ""


def _new_node(name: str, ntype: NodeType, domain: str) -> ADNode:
    clean = _normalise_ref(name)
    full = clean if "@" in clean or not domain else f"{clean.upper()}@{domain}"
    if ntype == NodeType.COMPUTER and domain and "@" not in clean:
        full = f"{clean.upper()}.{domain}"
    return ADNode(object_id=f"NEW:{ntype.value}:{full.upper()}", name=full, node_type=ntype,
                  domain=domain.lower(), enabled=True)


def resolve_changes(graph: AttackGraph, specs: list[ChangeSpec], on_unresolved: str = "error"
                    ) -> tuple[list[ResolvedChange], list[str]]:
    """Bind each spec to concrete baseline objects.

    Returns (resolved, errors). An unknown or ambiguous name is an error by default:
    skipping it would let a change through unexamined. With on_unresolved="assume-new"
    unknown names are treated as brand-new objects with no existing permissions.
    """
    index = NameIndex(graph)
    domain = _infer_domain(graph)
    domain_nodes = graph.nodes_by_type(NodeType.DOMAIN)
    resolved: list[ResolvedChange] = []
    errors: list[str] = []

    for spec in specs:
        rc = ResolvedChange(spec)
        if spec.op == "create":
            ntype = _NODE_TYPE_BY_WORD[spec.new_type]
            if index.lookup(spec.source, {ntype}):
                errors.append(f"{spec.origin}: cannot create {spec.new_type} '{spec.source}': it already exists in the baseline")
                continue
            node = _new_node(spec.source, ntype, domain)
            index.add(node)
            rc.new_nodes.append(node)
            rc.source_id, rc.source_name = node.object_id, node.display_name
            resolved.append(rc)
            continue

        src_types, tgt_types = _ENDPOINTS.get(spec.edge_type, (None, None))
        ok = True
        for side, ref, allowed in (("source", spec.source, src_types), ("target", spec.target, tgt_types)):
            if side == "target" and ref == DOMAIN_SENTINEL:
                if len(domain_nodes) == 1:
                    node = domain_nodes[0]
                else:
                    errors.append(f"{spec.origin}: name the domain explicitly ({len(domain_nodes)} domain objects in the baseline)")
                    ok = False
                    continue
            else:
                found = index.lookup(ref, allowed)
                if len(found) > 1:
                    options = ", ".join(f"{c.name} [{c.node_type.value}]" for c in found[:4])
                    errors.append(f"{spec.origin}: {side} '{ref}' is ambiguous: {options}. Use the full NAME@DOMAIN or the SID.")
                    ok = False
                    continue
                if not found:
                    if on_unresolved == "assume-new":
                        ntype = (list(allowed)[0] if allowed and len(allowed) == 1
                                 else NodeType.USER if side == "source" else NodeType.GROUP)
                        node = _new_node(ref, ntype, domain)
                        index.add(node)
                        rc.new_nodes.append(node)
                        rc.assumed_new.append(node.name)
                    else:
                        hint = index.suggestions(ref, allowed)
                        extra = f" Did you mean: {', '.join(hint)}?" if hint else ""
                        errors.append(
                            f"{spec.origin}: {side} '{ref}' not found in the baseline.{extra} "
                            f"If it is a new object, declare it with 'create' or pass --on-unresolved assume-new.")
                        ok = False
                        continue
                else:
                    node = found[0]
            if side == "source":
                rc.source_id, rc.source_name = node.object_id, node.display_name
            else:
                rc.target_id, rc.target_name = node.object_id, node.display_name
        if ok:
            resolved.append(rc)
    return resolved, errors


# ------------------------------------------------------------------ application

def apply_change(graph: AttackGraph, rc: ResolvedChange) -> bool:
    """Apply one resolved change in place. Returns True if the graph actually changed."""
    for node in rc.new_nodes:
        if graph.get_node(node.object_id) is None:
            graph.add_node(replace_node(node))
    spec = rc.spec
    if spec.op == "create":
        return True
    if spec.op == "add":
        if graph.has_edge_type(rc.source_id, rc.target_id, spec.edge_type):
            rc.noop, rc.noop_reason = True, "already present in the baseline"
            return False
        graph.add_edge(ADEdge(rc.source_id, rc.target_id, spec.edge_type))
        return True
    saved = [dict(d) for d in graph.get_edge_data(rc.source_id, rc.target_id)
             if d.get("edge_type") == spec.edge_type]
    if not graph.remove_edge(rc.source_id, rc.target_id, spec.edge_type):
        rc.noop, rc.noop_reason = True, "not present in the baseline (stale baseline or wrong name?)"
        return False
    rc.removed_edges = saved
    return True


def undo_change(graph: AttackGraph, rc: ResolvedChange) -> None:
    """Reverse apply_change for edge operations (creates are left in place; they are inert)."""
    spec = rc.spec
    if spec.op == "add" and not rc.noop:
        graph.remove_edge(rc.source_id, rc.target_id, spec.edge_type)
    elif spec.op == "remove" and rc.removed_edges:
        for d in rc.removed_edges:
            props = {k: v for k, v in d.items() if k not in ("edge_type", "inherited", "weight")}
            graph.add_edge(ADEdge(rc.source_id, rc.target_id, spec.edge_type, d.get("inherited", False), props))
        rc.removed_edges = []


def replace_node(node: ADNode) -> ADNode:
    return ADNode(node.object_id, node.name, node.node_type, node.domain, node.enabled,
                  node.admin_count, 2, dict(node.properties))
