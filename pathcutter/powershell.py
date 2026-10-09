"""PowerShell change extraction: what AD changes would this script make?

This is a static analysis, not an interpreter: nothing is ever executed. It understands enough of the
language to follow real automation scripts:

* statements split correctly across strings, here-strings, comments, backtick continuations and
  `;`, with `{...}` blocks parsed recursively (if/else/try/function/foreach/ForEach-Object);
* variables bound to literals (`$g = "HelpDesk"`, `$users = 'a','b'`), `foreach ($u in 'a','b')` loops
  expanded, `$_` inside ForEach-Object over a literal list, `(Get-ADUser x).SamAccountName`;
* pipelines (`Get-ADUser bob | Add-ADPrincipalGroupMembership -MemberOf G`) and group expansion from the
  baseline (`Get-ADGroupMember HelpDesk | ...` becomes `@members(HelpDesk)`, resolved against the graph);
* ACL grants through `dsacls`, `ActiveDirectoryAccessRule` objects + `Set-Acl`, PowerView, Add-ADPermission,
  GPO permissions and links, delegation (RBCD, unconstrained, constrained), gMSA, object creation/deletion/move,
  and PathCutter's own generated remediation scripts;
* `#pc: <change>` directives, so an author can state the effect of a line the parser cannot read.

Anything recognised as an AD-modifying command that cannot be modeled is reported (never skipped), with
the reason, so a gate built on this never gives false assurance.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .changes import ChangeSpec, ChangeWarning, parse_line

MAX_FOREACH = 500
MAX_DEPTH = 14
_DIRECTIVE = re.compile(r"^#\s*(?:pc|pathcutter)\s*:\s*(.+?)\s*$", re.I)


# ------------------------------------------------------------------------ scanning

@dataclass
class Raw:
    line: int
    head: str
    block: str | None = None
    block_line: int = 0


def _skip_string(text: str, i: int) -> tuple[int, int]:
    """text[i] opens a quote (or a here-string). Returns (index after the string, newlines inside)."""
    n = len(text)
    q = text[i]
    start = i
    if text.startswith(("@'", '@"'), i) and i + 2 < n and text[i + 2] in "\r\n":
        close = "'@" if text[i + 1] == "'" else '"@'
        j = i + 2
        while j < n:
            if text.startswith(close, j) and (j == 0 or text[j - 1] == "\n"):
                end = j + 2
                return end, text.count("\n", start, end)
            j += 1
        return n, text.count("\n", start, n)
    i += 1
    while i < n:
        c = text[i]
        if q == '"' and c == "`":
            i += 2
            continue
        if c == q:
            if i + 1 < n and text[i + 1] == q:      # doubled quote is an escaped quote
                i += 2
                continue
            return i + 1, text.count("\n", start, i + 1)
        i += 1
    return n, text.count("\n", start, n)


def _read_block(text: str, i: int) -> tuple[str, int, int]:
    """text[i] == '{'. Returns (inner text, index after the matching '}', newlines consumed)."""
    n = len(text)
    depth, j = 0, i
    while j < n:
        c = text[j]
        if c in "'\"":
            j, _ = _skip_string(text, j)
            continue
        if c == "@" and j + 1 < n and text[j + 1] in "'\"" and j + 2 < n and text[j + 2] in "\r\n":
            j, _ = _skip_string(text, j)
            continue
        if c == "#" and (j == 0 or text[j - 1] in " \t\n\r;{(") :
            while j < n and text[j] != "\n":
                j += 1
            continue
        if c == "<" and text.startswith("<#", j):
            k = text.find("#>", j + 2)
            j = n if k < 0 else k + 2
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[i + 1:j], j + 1, text.count("\n", i, j)
        j += 1
    return text[i + 1:], n, text.count("\n", i, n)


_BLOCK_KEYWORDS = re.compile(r"^(if|elseif|else|foreach|for|while|do|until|switch|try|catch|finally|function|"
                             r"filter|trap|begin|process|end|workflow|parallel)\b", re.I)


def scan(text: str, base_line: int = 1) -> tuple[list[Raw], list[tuple[int, str]]]:
    """Split a script into raw statements (with their blocks) and `#pc:` directives."""
    stmts: list[Raw] = []
    directives: list[tuple[int, str]] = []
    n, i, line = len(text), 0, base_line
    buf: list[str] = []
    stmt_line = [0]
    depth = 0          # () and []
    hdepth = 0         # @{ } and ${ }

    def flush(block: str | None = None, block_line: int = 0) -> None:
        head = "".join(buf).strip()
        if head or block is not None:
            stmts.append(Raw(stmt_line[0] or line, head, block, block_line))
        buf.clear()
        stmt_line[0] = 0

    def push(ch: str) -> None:
        if not stmt_line[0] and not ch.isspace():
            stmt_line[0] = line
        buf.append(ch)

    while i < n:
        c = text[i]
        if c == "\r":
            i += 1
            continue
        if c == "`":
            if i + 1 < n and text[i + 1] == "\n":
                line += 1
                i += 2
                buf.append(" ")
                continue
            if i + 1 < n and text[i + 1] == "\r" and i + 2 < n and text[i + 2] == "\n":
                line += 1
                i += 3
                buf.append(" ")
                continue
            push(c)
            if i + 1 < n:
                push(text[i + 1])
            i += 2
            continue
        if c == "\n":
            line += 1
            i += 1
            if depth or hdepth:
                buf.append(" ")
                continue
            head = "".join(buf).strip()
            if head.endswith(("|", ",")):
                buf.append(" ")
                continue
            j = i
            while j < n and text[j] in " \t\r\n":
                j += 1
            if head and j < n and text[j] == "{" and (_BLOCK_KEYWORDS.match(head) or head.endswith(")")
                                                      or head.lower() in ("else", "try", "finally", "do")):
                buf.append(" ")                  # Allman-style brace on the next line
                continue
            flush()
            continue
        if c == "#" and (not buf or buf[-1] in " \t;{(" or not "".join(buf).strip()):
            j = i
            while j < n and text[j] != "\n":
                j += 1
            m = _DIRECTIVE.match(text[i:j].rstrip("\r"))
            if m:
                directives.append((line, m.group(1)))
            i = j
            continue
        if c == "<" and text.startswith("<#", i):
            k = text.find("#>", i + 2)
            end = n if k < 0 else k + 2
            line += text.count("\n", i, end)
            i = end
            continue
        if c in "'\"" or (c == "@" and i + 2 < n and text[i + 1] in "'\"" and text[i + 2] in "\r\n"):
            end, nl = _skip_string(text, i)
            for ch in text[i:end]:
                push(ch)
            line += nl
            i = end
            continue
        if c in "([":
            depth += 1
        elif c in ")]":
            depth = max(0, depth - 1)
        elif c == "{":
            prev = buf[-1] if buf else ""
            if depth == 0 and hdepth == 0 and prev not in ("@", "$"):
                inner, end, nl = _read_block(text, i)
                k = end
                while k < n and text[k] in " \t\r\n":
                    k += 1
                if k < n and text[k] == "|":
                    # `Where-Object { ... } | ForEach-Object { ... }`: the pipeline continues past this block
                    push("{")
                    for ch in inner:
                        push(ch)
                    push("}")
                    line += nl
                    i = end
                    continue
                flush(inner, line)
                line += nl
                i = end
                continue
            hdepth += 1
        elif c == "}":
            hdepth = max(0, hdepth - 1)
        elif c == ";" and depth == 0 and hdepth == 0:
            flush()
            i += 1
            continue
        push(c)
        i += 1
    flush()
    return stmts, directives


# ---------------------------------------------------------------- small text helpers

def split_top(text: str, sep: str) -> list[str]:
    """Split on a single-character separator outside quotes and brackets."""
    out, buf = [], []
    depth = 0
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c in "'\"":
            end, _ = _skip_string(text, i)
            buf.append(text[i:end])
            i = end
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth = max(0, depth - 1)
        elif c == sep and depth == 0:
            out.append("".join(buf))
            buf = []
            i += 1
            continue
        buf.append(c)
        i += 1
    out.append("".join(buf))
    return out


def split_args(text: str) -> list[str]:
    """Split a command's argument string into tokens, keeping quotes, (..), @(..), @{..} intact."""
    toks, buf = [], []
    depth = 0
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c in "'\"":
            end, _ = _skip_string(text, i)
            buf.append(text[i:end])
            i = end
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth = max(0, depth - 1)
        if c.isspace() and depth == 0:
            if buf:
                toks.append("".join(buf))
                buf = []
            i += 1
            continue
        buf.append(c)
        i += 1
    if buf:
        toks.append("".join(buf))
    merged: list[str] = []                      # `"a", "b"` is one array argument
    for t in toks:
        if merged and (merged[-1].endswith(",") or t.startswith(",")):
            merged[-1] += t
        else:
            merged.append(t)
    return merged


_VAR = re.compile(r"\$\{?(?:(?:script|global|local|private):)?(\w+)\}?")
_IDENTITY_PROPS = {"name", "samaccountname", "distinguishedname", "userprincipalname", "dnsroot",
                   "dnshostname", "objectsid", "sid"}
_GETTERS = {"get-aduser", "get-adgroup", "get-adcomputer", "get-adobject", "get-adserviceaccount",
            "get-adgroupmember", "get-domainuser", "get-domaingroup", "get-domaincomputer", "get-domainobject"}


class HashLit(dict):
    """A hashtable literal bound to a variable, used for splatting: Add-ADGroupMember @params."""


class Acl:
    """A security descriptor under edit: $acl = Get-Acl 'AD:\\<dn>'."""

    def __init__(self, dn: str):
        self.dn = dn
        self.ops: list[tuple[str, dict, int, str]] = []     # (add|remove|owner, rule/filter, line, raw)


class Rule:
    def __init__(self, identity: list[str] | None, rights: str, deny: bool, guid: str):
        self.identity, self.rights, self.deny, self.guid = identity, rights, deny, guid


class AclAccess:
    def __init__(self, acl: Acl):
        self.acl, self.filter = acl, None


Value = "list[str] | Acl | Rule | AclAccess | None"


class Ctx:
    def __init__(self, origin: str):
        self.origin = origin
        self.items: list[tuple] = []        # (op, source, edge, target, new_type, line, raw)
        self.warns: list[ChangeWarning] = []
        self.why: list[str] = []            # unresolved things found by the last evaluation
        self.computer: str | None = None    # target of an enclosing Invoke-Command -ComputerName

    def emit(self, op, source, edge, target, line, raw, new_type="", ttl=None):
        # op may also be "deny" / "undeny" (a Deny ACE); ttl is minutes for a time-bound (JIT) grant
        self.items.append((op, source, edge, target, new_type, line, raw, ttl))

    def warn(self, line, message, raw="", level="review"):
        self.warns.append(ChangeWarning(f"{self.origin}:{line}", message, raw, level))


# ------------------------------------------------------------------- evaluation

def _unquote(tok: str, env: dict, ctx: Ctx) -> list[str] | None:
    if tok.startswith("'") and tok.endswith("'") and len(tok) >= 2:
        return [tok[1:-1].replace("''", "'")]
    if tok.startswith('"') and tok.endswith('"') and len(tok) >= 2:
        body = tok[1:-1].replace('""', '"')
        if "$(" in body:
            ctx.why.append("a sub-expression")
            return None
        unresolved = False

        def sub(m: re.Match) -> str:
            nonlocal unresolved
            v = env.get(m.group(1).lower())
            if isinstance(v, list) and len(v) == 1:
                return v[0]
            unresolved = True
            ctx.why.append("$" + m.group(1))
            return ""
        out = _VAR.sub(sub, body)
        return None if unresolved else [out]
    return None


def ev(text: str, env: dict, ctx: Ctx):
    """Evaluate an argument expression to a list of strings, or None when it cannot be known."""
    t = text.strip()
    if not t:
        return []
    parts = split_top(t, ",")
    if len(parts) > 1:
        out: list[str] = []
        for p in parts:
            v = ev(p, env, ctx)
            if not isinstance(v, list):
                return None
            out.extend(v)
        return out
    cast = re.match(r"^\[[\w\.\[\]]+\]\s*(.+)$", t, re.S)
    if cast and not t.startswith("[void]"):
        return ev(cast.group(1), env, ctx)
    if t.startswith("@(") and t.endswith(")"):
        inner = t[2:-1]
        if "\n" in inner:
            inner = ",".join(x for x in inner.splitlines() if x.strip())
        return ev(inner, env, ctx)
    prop = re.match(r"^\((.*)\)\.(\w+)$", t, re.S)
    if prop:
        inner = ev(prop.group(1), env, ctx)
        return inner if prop.group(2).lower() in _IDENTITY_PROPS else None
    if t.startswith("(") and t.endswith(")"):
        return ev(t[1:-1], env, ctx)
    if t[0] in "'\"":
        return _unquote(t, env, ctx)
    if t[0] == "$":
        m = re.match(r"^\$\{?(?:(?:script|global|local|private):)?(\w+)\}?(?:\.(\w+))?$", t)
        if not m:
            ctx.why.append(t.split()[0][:30])
            return None
        name = m.group(1).lower()
        if t.lower().startswith("$env:"):
            ctx.why.append(t)
            return None
        if m.group(2) and m.group(2).lower() not in _IDENTITY_PROPS:
            ctx.why.append(t)
            return None
        v = env.get(name)
        if isinstance(v, list):
            return v
        ctx.why.append("$" + m.group(1))
        return None
    word = t.split(None, 1)[0].lower()
    if word in _GETTERS:
        return identity_of_getter(t, env, ctx)
    if re.match(r"^[\w\-\.\\@/:=~%&*+]+\$?$", t):
        return [t]
    ctx.why.append(t[:40])
    return None


def identity_of_getter(text: str, env: dict, ctx: Ctx):
    """`Get-ADUser bob` / `Get-ADGroup -Identity 'X'` used as a value: the identity it names."""
    from . import ps_rules
    parts = split_args(text)
    name = parts[0].lower()
    named, positional = ps_rules.parse_params(parts[1:], ps_rules.GETTER_PARAMS)
    ident = named.get("identity") or named.get("name")
    raw = ident[0] if ident else (positional[0] if positional else None)
    if raw is None:
        ctx.why.append(f"{parts[0]} without a literal -Identity")
        return None
    v = ev(raw, env, ctx)
    if v is None:
        return None
    if name == "get-adgroupmember":
        recursive = "recursive" in named
        return [f"@members{'*' if recursive else ''}({x})" for x in v]
    return v


# ------------------------------------------------------------------- execution

_ASSIGN = re.compile(r"^(?:\[[\w\.\[\]]+\]\s*)?\$\{?(?:(?:script|global|local|private):)?(\w+)\}?\s*(\+?=)\s*(.+)$", re.S)
_FOREACH = re.compile(r"^foreach\s*\(\s*\$(\w+)\s+in\s+(.*)\)\s*$", re.I | re.S)
_ACL_METHOD = re.compile(r"^\$(\w+)\.(AddAccessRule|SetAccessRule|ResetAccessRule|RemoveAccessRule|RemoveAccessRuleAll|"
                         r"RemoveAccessRuleSpecific|PurgeAccessRules|SetOwner)\s*\((.*)\)\s*$", re.I | re.S)


def run(stmts: list[Raw], env: dict, ctx: Ctx, depth: int = 0) -> None:
    for st in stmts:
        run_stmt(st, env, ctx, depth)


def _run_block(block: str, line: int, env: dict, ctx: Ctx, depth: int) -> None:
    if depth >= MAX_DEPTH:
        ctx.warn(line, "script nesting is too deep to analyze", level="review")
        return
    inner, _ = scan(block, line)
    run(inner, env, ctx, depth + 1)


def run_stmt(st: Raw, env: dict, ctx: Ctx, depth: int) -> None:
    pm = re.match(r"^param\s*\((.*?)\)\s*(.*)$", st.head, re.I | re.S)
    if pm and st.block is None:                    # param(...) binds unknown values; any statement after it still runs
        for v in re.findall(r"\$(\w+)", pm.group(1)):
            env[v.lower()] = None
        if not pm.group(2).strip():
            return
        st = Raw(st.line, pm.group(2).strip(), st.block, st.block_line)
    head, low = st.head, st.head.lower()
    if st.block is not None:
        fe = _FOREACH.match(head)
        if fe:
            var = fe.group(1).lower()
            vals = ev(fe.group(2), env, ctx)
            ctx.why.clear()
            if vals is None:
                e2 = dict(env)
                e2[var] = None
                _run_block(st.block, st.block_line, e2, ctx, depth)
                return
            for v in vals[:MAX_FOREACH]:
                e2 = dict(env)
                e2[var] = [v]
                _run_block(st.block, st.block_line, e2, ctx, depth)
            if len(vals) > MAX_FOREACH:
                ctx.warn(st.line, f"loop over {len(vals)} items analyzed only for the first {MAX_FOREACH}")
            return
        if head == "" or head in ("&", ".") or _BLOCK_KEYWORDS.match(head):
            e2 = dict(env)
            fn = re.match(r"^(?:function|filter)\s+[\w\-:]+", low)
            if fn:
                for pname in re.findall(r"\$(\w+)", st.block[:st.block.lower().find(")") + 1] if "param" in st.block.lower()[:40] else ""):
                    e2[pname.lower()] = None
            _run_block(st.block, st.block_line, e2, ctx, depth)
            return
    if not head:
        return
    am = _ACL_METHOD.match(head)
    if am:
        from . import ps_rules
        ps_rules.acl_method(ctx, env, am, st.line, head)
        return
    asg = _ASSIGN.match(head)
    if asg and not head.startswith(("$_",)):
        name = asg.group(1).lower()
        rhs = asg.group(3).strip()
        if rhs.startswith("@{") and rhs.endswith("}"):
            from . import ps_rules
            env[name] = HashLit(ps_rules.parse_hashtable(rhs))
            return
        val = run_pipeline(asg.group(3), st.block, st.block_line, env, ctx, st.line, capture=True)
        if asg.group(2) == "+=" and isinstance(env.get(name), list) and isinstance(val, list):
            val = env[name] + val
        elif asg.group(2) == "+=":
            val = None
        env[name] = val
        return
    run_pipeline(head, st.block, st.block_line, env, ctx, st.line)


def run_pipeline(text: str, block: str | None, block_line: int, env: dict, ctx: Ctx, line: int,
                 capture: bool = False):
    from . import ps_rules
    segs = [s.strip() for s in split_top(text, "|")]
    pipe = None
    for k, seg in enumerate(segs):
        last = k == len(segs) - 1
        pipe = ps_rules.run_segment(seg, block if last else None, block_line, pipe, k == 0, env, ctx, line, text)
    return pipe if capture else None


def extract(text: str, origin: str = "<script>", start_index: int = 1
            ) -> tuple[list[ChangeSpec], list[ChangeWarning]]:
    """Entry point: the AD changes a PowerShell script would make, plus everything it could not model."""
    ctx = Ctx(origin)
    stmts, directives = scan(text)
    run(stmts, {}, ctx)
    from . import ps_rules
    ps_rules.flush_pending(ctx)

    seen: set[tuple] = set()
    specs: list[ChangeSpec] = []
    idx = start_index

    def norm(ref: str) -> str:
        from .changes import _normalise_ref
        m = re.match(r"^(@members\*?)\((.+)\)$", ref, re.I)
        if m:
            return f"{m.group(1)}({_normalise_ref(m.group(2))})"
        return ref if ref.startswith("@") else _normalise_ref(ref)

    def add(op, source, edge, target, new_type, line, raw, ttl=None):
        nonlocal idx
        source, target = norm(source), norm(target) if target else target
        key = (op, source.lower(), edge, target.lower(), new_type)
        if key in seen:
            return
        seen.add(key)
        deny = op in ("deny", "undeny")
        specs.append(ChangeSpec(idx, {"deny": "add", "undeny": "remove"}.get(op, op), source=source, edge_type=edge,
                                target=target, new_type=new_type, origin=f"{origin}:{line}", raw=raw,
                                deny=deny, ttl_minutes=ttl))
        idx += 1

    ordered: list[tuple[int, int, tuple]] = []
    for n, item in enumerate(ctx.items):
        ordered.append((item[5], n, item))
    for dline, dtext in directives:
        try:
            spec = parse_line(dtext, 0, f"{origin}:{dline}")
        except ValueError as exc:
            ctx.warn(dline, f"invalid #pc directive: {exc}", dtext)
            continue
        if spec is not None:
            ordered.append((dline, 10 ** 6 + dline, (("deny" if spec.op == "add" else "undeny") if spec.deny else spec.op,
                                                       spec.source, spec.edge_type, spec.target,
                                                       spec.new_type, dline, dtext, spec.ttl_minutes)))
    ordered.sort(key=lambda x: (x[0], x[1]))
    broad = {(norm(i[2][1]).lower(), norm(i[2][3]).lower()) for i in ordered if i[2][0] == "remove" and i[2][2] == "*"}
    for _, _, (op, source, edge, target, new_type, line, raw, ttl) in ordered:
        if op == "remove" and edge not in ("*", "MemberOf") and (norm(source).lower(), norm(target).lower()) in broad:
            continue                      # a specific revoke is already covered by the broader one on the same pair
        add(op, source, edge, target, new_type, line, raw, ttl)
    return specs, ctx.warns
