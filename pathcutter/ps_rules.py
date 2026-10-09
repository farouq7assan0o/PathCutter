"""Cmdlet handlers for the PowerShell change extractor (see powershell.py).

Each handler turns one recognised command into `ctx.emit(...)` calls (changes) or `ctx.warn(...)` calls
(things it could not model). The table at the bottom (`SUPPORTED`) is the single source of truth for
what is covered; `pathcutter syntax` prints it, so documentation cannot drift from behaviour.
"""
from __future__ import annotations

import re

from .changes import _normalise_ref
from .powershell import Acl, AclAccess, HashLit, Rule, ev, run, scan, split_args, split_top

UNKNOWN = object()

GETTER_PARAMS = {"identity": "val", "name": "val", "recursive": "switch", "filter": "val", "searchbase": "val",
                 "ldapfilter": "val", "properties": "val", "server": "val", "credential": "val"}
_SWITCHES = {"passthru", "confirm", "whatif", "force", "verbose", "debug", "recursive", "reset", "enabled",
             "unlock", "erroraction", "warningaction", "outvariable"}
_GUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")

# parameter aliases PowerShell accepts (alias -> canonical), only applied when the cmdlet's spec has the target
_ALIAS_NAMES = {"member": "members", "membername": "members", "group": "identity", "principal": "identity",
                "targetname": "targetname", "users": "user"}

# ObjectType GUID -> what write/extended right it represents
PROP_GUIDS = {
    "bf9679c0-0de6-11d0-a285-00aa003049e2": "member",
    "f3a64788-5306-11d1-a9c5-0000f80367c1": "serviceprincipalname",
    "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79": "msds-allowedtoactonbehalfofotheridentity",
    "5b47d60f-6090-40b2-9f37-2a4de88f3063": "msds-keycredentiallink",
    "00299570-246d-11d0-a768-00aa006e0529": "user-force-change-password",
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "ds-replication-get-changes",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "ds-replication-get-changes-all",
    "89e95b76-444d-4c62-991a-0facbeda640c": "ds-replication-get-changes-in-filtered-set",
    "e362ed86-b728-0842-b27d-2dea7a9df218": "msds-managedpassword",
    "d15ef7d8-f226-46db-ae79-b34e560bd12c": "mspki-enrollment-flag",
    "ea1dddc4-60ff-416e-8cc0-17cee534bce7": "mspki-certificate-name-flag",
}
# right-name / property-name -> edge, per kind of right
_WRITE_PROP = {"member": "AddMember", "serviceprincipalname": "WriteSPN",
               "msds-allowedtoactonbehalfofotheridentity": "AddAllowedToAct",
               "msds-keycredentiallink": "WriteKeyCredentialLink",
               "mspki-enrollment-flag": "WritePKIEnrollmentFlag", "mspki-certificate-name-flag": "WritePKINameFlag"}
_EXT_RIGHT = {"user-force-change-password": "ForceChangePassword", "ds-replication-get-changes": "DCSync",
              "ds-replication-get-changes-all": "DCSync", "ds-replication-get-changes-in-filtered-set": "DCSync"}
_READ_PROP = {"msds-managedpassword": "ReadGMSAPassword", "ms-mcs-admpwd": "ReadLAPSPassword",
              "mslaps-password": "ReadLAPSPassword", "mslaps-encryptedpassword": "ReadLAPSPassword"}


def rights_to_edges(rights: str, prop: str = "", deny: bool = False) -> tuple[list[str], str]:
    """Map an ActiveDirectoryRights string (+ property/extended-right name) to edge types.

    Returns (edges, note). `note` explains a right that has no modeled effect.
    """
    r = rights.lower().replace(" ", "")
    prop = prop.lower()
    edges: list[str] = []
    if "genericall" in r or "fullcontrol" in r:
        edges.append("GenericAll")
    if "genericwrite" in r:
        edges.append("GenericWrite")
    if "writedacl" in r:
        edges.append("WriteDacl")
    if "writeowner" in r:
        edges.append("WriteOwner")
    if "writeproperty" in r:
        if prop in _WRITE_PROP:
            edges.append(_WRITE_PROP[prop])
        elif not prop:
            edges.append("GenericWrite")
    if "extendedright" in r:
        if prop in _EXT_RIGHT:
            edges.append(_EXT_RIGHT[prop])
        elif not prop:
            edges.append("GenericAll")
    if "self" in r and prop == "member":
        edges.append("AddMember")
    if "readproperty" in r and prop in _READ_PROP:
        edges.append(_READ_PROP[prop])
    seen, out = set(), []
    for e in edges:
        if e not in seen:
            seen.add(e)
            out.append(e)
    note = "" if out else "no attack-relevant right (not modeled)"
    return out, note


# --------------------------------------------------------------- parameter parsing

def parse_params(tokens: list[str], spec: dict) -> tuple[dict[str, list[str]], list[str]]:
    """Split tokens into {canonical-name: [raw value tokens]} and positional tokens.

    PowerShell accepts any unambiguous prefix of a parameter name (-Ident for -Identity), which scripts
    use a lot, so names are matched by prefix against `spec`.
    """
    names = list(spec) + list(_ALIAS_NAMES)
    named: dict[str, list[str]] = {}
    positional: list[str] = []
    i = 0
    while i < len(tokens):
        t = tokens[i]
        if t.startswith("-") and len(t) > 1 and not t[1].isdigit() and not t.startswith("--"):
            raw, _, inline = t[1:].partition(":")
            low = raw.lower()
            def res(n: str) -> str:
                return n if n in spec else (_ALIAS_NAMES[n] if _ALIAS_NAMES.get(n) in spec else n)
            cands = [n for n in names if n == low] or [n for n in names if n.startswith(low)]
            targets = {res(n) for n in cands}
            canon = res(cands[0]) if cands and len(targets) == 1 else low
            kind = spec.get(canon, "switch" if canon in _SWITCHES else "val")
            if inline:
                named[canon] = [inline]
            elif kind == "switch" or canon in _SWITCHES or i + 1 >= len(tokens) or tokens[i + 1].startswith("-"):
                named[canon] = []
            else:
                named[canon] = [tokens[i + 1]]
                i += 1
        else:
            positional.append(t)
        i += 1
    return named, positional


class Args:
    def __init__(self, ctx, env, line, raw, name, named, positional, pipe):
        self.ctx, self.env, self.line, self.raw, self.name = ctx, env, line, raw, name
        self.named, self.positional, self.pipe = named, positional, pipe
        self.problems: list[str] = []

    def has(self, canon: str) -> bool:
        return canon in self.named

    def values(self, canon: str, pos: int | None = None, pipe_ok: bool = False):
        """('absent', None) | ('unknown', None) | ('ok', [str])."""
        raw = None
        if canon in self.named and self.named[canon]:
            raw = self.named[canon][0]
        elif pos is not None and len(self.positional) > pos:
            raw = self.positional[pos]
        if raw is None:
            if pipe_ok and self.pipe is not None:
                if isinstance(self.pipe, list):
                    return "ok", self.pipe
                return "unknown", None
            return "absent", None
        self.ctx.why.clear()
        v = ev(raw, self.env, self.ctx)
        if not isinstance(v, list):
            self.problems.extend(self.ctx.why or [raw[:30]])
            return "unknown", None
        return "ok", v

    def need(self, *specs):
        """Resolve several (canon, pos, pipe_ok) specs; warn and return None if any is missing/unknown."""
        out = []
        for canon, pos, pipe_ok in specs:
            status, v = self.values(canon, pos, pipe_ok)
            if status == "ok":
                out.append(v)
                continue
            if status == "unknown":
                why = ", ".join(dict.fromkeys(self.problems)) or "a value that is not a literal"
                self.ctx.warn(self.line, f"{self.name} depends on {why}, so who is affected cannot be determined", self.raw)
            else:
                self.ctx.warn(self.line, f"{self.name} has no literal -{canon.capitalize()} argument, so who is affected cannot be determined", self.raw)
            return None
        return out

    def hashtable(self, canon: str) -> dict[str, list[str]] | None:
        raw = self.named.get(canon, [None])[0] if self.named.get(canon) else None
        if raw is None:
            return None
        return parse_hashtable(raw)


def parse_hashtable(raw: str) -> dict[str, list[str]]:
    t = raw.strip()
    if t.startswith("@{") and t.endswith("}"):
        t = t[2:-1]
    out: dict[str, list[str]] = {}
    for part in re.split(r"[;\n]", t) if ";" in t or "\n" in t else [t]:
        if "=" not in part:
            continue
        k, _, v = part.partition("=")
        out.setdefault(k.strip().strip("'\"").lower(), []).append(v.strip())
    return out


def _values_of(ctx, env, raws: list[str]):
    out = []
    for r in raws:
        ctx.why.clear()
        v = ev(r, env, ctx)
        if not isinstance(v, list):
            return None
        out.extend(v)
    return out


# ------------------------------------------------------------------- handlers

def ps_ttl(raw: str | None) -> int | None:
    """-MemberTimeToLive: (New-TimeSpan -Hours 4) | [timespan]'04:00:00' | '04:00:00'  ->  minutes (None if unknowable)."""
    if not raw:
        return None
    from .changes import parse_ttl
    m = re.search(r"New-TimeSpan", raw, re.I)
    if m:
        total = 0
        for unit, mult in (("days", 1440), ("hours", 60), ("minutes", 1)):
            u = re.search(r"-" + unit[0] + r"\w*\s+(\d+)", raw, re.I)
            if u and re.search(r"-" + unit, raw, re.I):
                total += int(u.group(1)) * mult
        return total or None
    t = re.sub(r"^\(?\s*(\[timespan\])?\s*", "", raw, flags=re.I).strip("()'\" ")
    try:
        return parse_ttl(t)
    except ValueError:
        return None


def h_group_member(op: str):
    def h(ctx, A: Args):
        res = A.need(("identity", 0, True), ("members", 1, False))
        if res is None:
            return
        groups, members = res
        ttl = None
        if op == "add" and A.has("membertimetolive"):
            raw = " ".join(A.named.get("membertimetolive") or [])
            ttl = ps_ttl(raw)
            if ttl is None:
                ctx.warn(A.line, "-MemberTimeToLive could not be read (not a literal timespan): "
                                 "treated as a permanent membership", A.raw, "note")
        for m in members:
            for g in groups:
                ctx.emit(op, m, "MemberOf", g, A.line, A.raw, ttl=ttl)
    return h


def h_principal_membership(op: str):
    def h(ctx, A: Args):
        res = A.need(("identity", 0, True), ("memberof", 1, False))
        if res is None:
            return
        principals, groups = res
        for p in principals:
            for g in groups:
                ctx.emit(op, p, "MemberOf", g, A.line, A.raw)
    return h


def _member_values(ctx, A: Args, key: str, table: dict[str, list[str]]):
    vals = _values_of(ctx, A.env, table.get(key, []))
    if vals is None:
        ctx.warn(A.line, f"{A.name} sets '{key}' from a variable or expression that could not be resolved", A.raw)
        return []
    return vals


def h_set_object(ctx, A: Args):
    """Set-ADObject/Set-ADGroup/Set-ADUser/Set-ADComputer/Set-ADServiceAccount/Set-ADAccountControl."""
    status, ident = A.values("identity", 0, True)
    modeled = False
    if status != "ok":
        if A.has("add") or A.has("replace") or A.has("remove") or A.has("principalsallowedtodelegatetoaccount") \
                or A.has("trustedfordelegation") or A.has("principalsallowedtoretrievemanagedpassword"):
            ctx.warn(A.line, f"{A.name} targets an object that is not a literal identity, so the change cannot be determined", A.raw)
        return
    target = ident[0]

    for mode, op in (("add", "add"), ("replace", "add"), ("remove", "remove")):
        table = A.hashtable(mode)
        if not table:
            continue
        for key in table:
            if key == "member":
                modeled = True
                for dn in _member_values(ctx, A, key, table):
                    ctx.emit(op, dn, "MemberOf", target, A.line, A.raw)
                if mode == "replace":
                    ctx.warn(A.line, "Replace on 'member' also removes current members; only the additions are modeled", A.raw, "review")
            elif key == "msds-allowedtodelegateto":
                modeled = True
                for spn in _member_values(ctx, A, key, table):
                    host = spn.split("/", 1)[-1].split(":")[0].split(".")[0]
                    ctx.emit(op, target, "AllowedToDelegate", host, A.line, A.raw)
            elif key == "msds-allowedtoactonbehalfofotheridentity":
                ctx.warn(A.line, "raw msDS-AllowedToActOnBehalfOfOtherIdentity write; use -PrincipalsAllowedToDelegateToAccount or '#pc: rbcd <principal> <resource>'", A.raw)
            elif key == "useraccountcontrol":
                modeled = True
                for v in _member_values(ctx, A, key, table):
                    if v.strip().isdigit() and int(v) & 0x80000:
                        ctx.emit("add", target, "AllowedToDelegate", "@dcs", A.line, A.raw)
                    elif v.strip().isdigit() and int(v) & 0x400000:
                        ctx.warn(A.line, "pre-authentication disabled (AS-REP roastable) is a credential risk, not a graph edge", A.raw, "note")
            elif key == "sidhistory":
                ctx.warn(A.line, "SID history injection grants the source SID's privileges; not modeled, review by hand", A.raw)
            elif key == "ntsecuritydescriptor":
                ctx.warn(A.line, "raw ntSecurityDescriptor write; express the ACL change with 'grant'/'revoke'", A.raw)
            elif key in ("serviceprincipalname", "serviceprincipalnames"):
                ctx.warn(A.line, "setting an SPN makes the account Kerberoastable; this is a credential risk, not a graph edge", A.raw, "note")
            elif key in ("admincount", "scriptpath", "msds-keycredentiallink"):
                ctx.warn(A.line, f"'{key}' is security-relevant but not modeled", A.raw, "review" if key == "msds-keycredentiallink" else "note")

    if A.has("principalsallowedtodelegatetoaccount"):
        modeled = True
        raws = A.named["principalsallowedtodelegatetoaccount"]
        vals = _values_of(ctx, A.env, raws) if raws else None
        if raws and raws[0].strip().lower() == "$null":
            ctx.warn(A.line, "clears RBCD; removals are not modeled without the prior list", A.raw, "note")
        elif vals is None:
            ctx.warn(A.line, "RBCD principals come from a variable or expression that could not be resolved", A.raw)
        else:
            for p in vals:
                ctx.emit("add", p, "AllowedToAct", target, A.line, A.raw)
    if A.has("principalsallowedtoretrievemanagedpassword"):
        modeled = True
        vals = _values_of(ctx, A.env, A.named["principalsallowedtoretrievemanagedpassword"])
        if vals is None:
            ctx.warn(A.line, "gMSA password readers come from a variable that could not be resolved", A.raw)
        else:
            for p in vals:
                ctx.emit("add", p, "ReadGMSAPassword", target, A.line, A.raw)
    if A.has("trustedfordelegation"):
        modeled = True
        raw = (A.named["trustedfordelegation"] or ["$true"])[0].strip().lower()
        ctx.emit("remove" if raw in ("$false", "0") else "add", target, "AllowedToDelegate", "@dcs", A.line, A.raw)
    if A.has("trustedtoauthfordelegation"):
        ctx.warn(A.line, "protocol transition changes how delegation is used, not who can delegate", A.raw, "note")
    if A.name.lower() in ("set-adobject",) and not modeled:
        ctx.warn(A.line, "Set-ADObject can write any attribute; nothing in this call is modeled", A.raw)


def h_move(ctx, A: Args):
    res = A.need(("identity", 0, True), ("targetpath", 1, False))
    if res:
        ctx.emit("move", res[0][0], "Contains", res[1][0], A.line, A.raw)


def h_delete(ctx, A: Args):
    res = A.need(("identity", 0, True))
    if res:
        for x in res[0]:
            ctx.emit("delete", x, "", "", A.line, A.raw)


def h_create(kind: str):
    def h(ctx, A: Args):
        name = None
        for canon, pos in (("samaccountname", None), ("name", 0)):
            status, v = A.values(canon, pos)
            if status == "ok":
                name = v[0]
                break
        if name is None:
            ctx.warn(A.line, f"{A.name} creates an object whose name is not a literal; it cannot be analyzed", A.raw)
            return
        ctx.emit("create", name, "if-missing", "", A.line, A.raw, new_type=kind)
        if A.has("principalsallowedtoretrievemanagedpassword"):
            vals = _values_of(ctx, A.env, A.named["principalsallowedtoretrievemanagedpassword"])
            if vals:
                for p in vals:
                    ctx.emit("add", p, "ReadGMSAPassword", name, A.line, A.raw)
        if A.has("principalsallowedtodelegatetoaccount"):
            vals = _values_of(ctx, A.env, A.named["principalsallowedtodelegatetoaccount"])
            if vals:
                for p in vals:
                    ctx.emit("add", p, "AllowedToAct", name, A.line, A.raw)
        if A.has("trustedfordelegation") and (A.named["trustedfordelegation"] or ["$true"])[0].lower() != "$false":
            ctx.emit("add", name, "AllowedToDelegate", "@dcs", A.line, A.raw)
    return h


# ---- ACLs ------------------------------------------------------------------

_DSACLS_RIGHTS = {"GA": "GenericAll", "GW": "GenericWrite", "WD": "WriteDacl", "WO": "WriteOwner", "WP": "WriteProperty",
                  "CA": "ExtendedRight", "SW": "Self", "RP": "ReadProperty"}


def _dsacls_edges(spec: str) -> tuple[str, list[str], str]:
    """`CORP\\bob:WP;member` -> (principal, [edges], note)"""
    principal, _, rest = spec.rpartition(":")
    if not principal:
        return spec, [], "unrecognised dsacls entry"
    perms, _, obj = rest.partition(";")
    obj = obj.split(";")[0]
    letters = [perms[i:i + 2].upper() for i in range(0, len(perms), 2)]
    rights = ",".join(_DSACLS_RIGHTS[x] for x in letters if x in _DSACLS_RIGHTS)
    edges, note = rights_to_edges(rights, obj.strip().lower())
    return principal, edges, note


def h_dsacls(ctx, A: Args):
    toks = [t for t in A.positional]
    if not toks:
        return
    first = ev(toks[0], A.env, ctx)
    target = _normalise_ref(first[0]) if isinstance(first, list) and first else None
    if target is None:
        ctx.warn(A.line, "dsacls on an object that is not a literal", A.raw)
        return
    mode = None
    for t in toks[1:]:
        low = t.lower()
        if low in ("/g", "/d", "/r"):
            mode = low
            continue
        if t.startswith("/"):
            mode = mode if low.startswith(("/i", "/p")) else None
            continue
        spec = (ev(t, A.env, ctx) or [t])[0] if t.startswith(("'", '"')) else t
        if mode == "/d":
            principal, edges, note = _dsacls_edges(spec)
            for e in edges:
                ctx.emit("deny", principal, e, target, A.line, A.raw)
            if not edges:
                ctx.warn(A.line, f"dsacls deny for {principal}: {note}", A.raw, "note")
        elif mode == "/r":
            ctx.emit("remove", spec, "*", target, A.line, A.raw)
            ctx.warn(A.line, f"dsacls /R removes ALL entries of {spec} on {target}", A.raw, "note")
        elif mode == "/g":
            principal, edges, note = _dsacls_edges(spec)
            for e in edges:
                ctx.emit("add", principal, e, target, A.line, A.raw)
            if not edges:
                ctx.warn(A.line, f"dsacls grant to {principal}: {note}", A.raw, "note")


def _identity_from_expr(text: str, env: dict, ctx) -> list[str] | None:
    m = re.search(r'NTAccount\s*\(\s*["\']([^"\']*)["\']\s*,\s*["\']([^"\']*)["\']\s*\)', text, re.I)
    if m:
        return [m.group(2)]
    m = re.search(r'NTAccount\s*\(?\s*["\']([^"\']+)["\']', text, re.I)
    if m:
        return [_normalise_ref(m.group(1))]
    m = re.search(r'SecurityIdentifier\s*\(?\s*["\'](S-[\d\-]+)["\']', text, re.I)
    if m:
        return [m.group(1)]
    m = re.search(r'\[System\.Security\.Principal\.NTAccount\]\s*["\']([^"\']+)["\']', text, re.I)
    if m:
        return [_normalise_ref(m.group(1))]
    v = ev(text, env, ctx)
    return [_normalise_ref(x) for x in v] if isinstance(v, list) else None


def make_rule(argtext: str, env: dict, ctx) -> Rule | None:
    """Parse the constructor arguments of ActiveDirectoryAccessRule (identity, rights, type[, guid, ...])."""
    inner = argtext.strip()
    args = split_top(inner, ",")
    if len(args) < 3:
        return None
    ident = _identity_from_expr(args[0], env, ctx)
    rm = re.search(r"ActiveDirectoryRights\]\s*::\s*([\w,\s]+)", args[1]) or re.search(r"['\"]([\w,\s]+)['\"]", args[1])
    rights = rm.group(1) if rm else (ev(args[1], env, ctx) or [""])[0] if isinstance(ev(args[1], env, ctx), list) else ""
    deny = "deny" in args[2].lower()
    guid = ""
    for a in args[3:]:
        g = _GUID.search(a)
        if not g:
            v = ev(a, env, ctx)
            g = _GUID.search(v[0]) if isinstance(v, list) and v else None
        if g:
            guid = g.group(0).lower()
            break
    return Rule(ident, rights, deny, guid)


def _match_paren(text: str, i: int) -> int:
    """text[i] == '('. Index of the matching ')' (quote-aware), or len(text) if unbalanced."""
    from .powershell import _skip_string
    depth, n = 0, len(text)
    while i < n:
        c = text[i]
        if c in "'\"":
            i, _ = _skip_string(text, i)
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return n


def rule_args(s: str) -> str | None:
    """The constructor arguments of `New-Object ...ActiveDirectoryAccessRule` found anywhere in s."""
    m = re.search(r"ActiveDirectoryAccessRule", s, re.I)
    if not m:
        return None
    rest = s[m.end():].lstrip()
    if rest.lower().startswith("-argumentlist"):
        rest = rest[len("-argumentlist"):].lstrip()
    if rest.startswith("("):
        end = _match_paren(rest, 0)
        return rest[1:end]
    return rest


def acl_method(ctx, env, m: re.Match, line: int, raw: str) -> None:
    var, method, argtext = m.group(1).lower(), m.group(2).lower(), m.group(3)
    acl = env.get(var)
    if not isinstance(acl, Acl):
        ctx.warn(line, f"${m.group(1)}.{m.group(2)} on an ACL that is not read from a literal 'AD:\\...' path", raw)
        return
    if method == "setowner":
        ident = _identity_from_expr(argtext, env, ctx)
        if ident:
            acl.ops.append(("owner", {"identity": ident}, line, raw))
        else:
            ctx.warn(line, "SetOwner with an owner that could not be resolved", raw)
        return
    if method == "purgeaccessrules":
        ident = _identity_from_expr(argtext, env, ctx)
        ctx.warn(line, "PurgeAccessRules removes every entry for the principal; model specific edges with 'revoke'", raw)
        return
    rule_obj = None
    arg = argtext.strip()
    if arg.startswith("$") and re.match(r"^\$\w+$", arg):
        rule_obj = env.get(arg[1:].lower())
    else:
        inner = rule_args(arg)
        if inner is not None:
            rule_obj = make_rule(inner, env, ctx)
    if not isinstance(rule_obj, Rule) or not rule_obj.identity:
        ctx.warn(line, "access rule could not be resolved to literal values; express it with 'grant'/'revoke'", raw)
        return
    op = "remove" if method.startswith("remove") else "add"
    acl.ops.append((op, {"rule": rule_obj}, line, raw))


def flush_acl(ctx, acl: Acl, commit_line: int) -> None:
    for op, data, line, raw in acl.ops:
        target = _normalise_ref(acl.dn)
        if op == "owner":
            for who in data["identity"]:
                ctx.emit("add", who, "Owns", target, line, raw)
            continue
        flt = data.get("filter")
        if flt is not None:
            edges = _filter_edges(flt)
            who_list = flt.get("identity") or []
            if edges:
                for who in who_list:
                    for e in edges:
                        ctx.emit("remove", who, e, target, line, raw)
            elif who_list and not flt.get("rights") and not flt.get("guid"):
                # No right or ObjectType filter: the script strips EVERY ACE the principal holds on the object.
                for who in who_list:
                    ctx.emit("remove", who, "*", target, line, raw)
                ctx.warn(line, f"this removes ALL access entries of {', '.join(who_list)} on {target}, "
                               "not only one right: broader than a single-edge fix", raw, "note")
            else:
                ctx.warn(line, "RemoveAccessRule filter has no recognised right or ObjectType", raw)
            continue
        rule: Rule = data["rule"]
        prop = PROP_GUIDS.get(rule.guid, "")
        edges, note = rights_to_edges(rule.rights, prop, rule.deny)
        if rule.guid and not prop and not edges:
            note = f"rule on an unrecognised property/right GUID {rule.guid} (not modeled)"
        eop = (("deny" if op == "add" else "undeny") if rule.deny else op)
        for who in rule.identity or []:
            for e in edges:
                ctx.emit(eop, who, e, target, line, raw)
        if not edges:
            ctx.warn(line, f"access rule: {note}", raw, "note")
    acl.ops = []


def _filter_edges(flt: dict) -> list[str]:
    prop = PROP_GUIDS.get(flt.get("guid", ""), "")
    edges, _ = rights_to_edges(flt.get("rights", ""), prop)
    if not edges and flt.get("guid") and prop in _WRITE_PROP:
        edges = [_WRITE_PROP[prop]]
    if not edges and prop in _EXT_RIGHT:
        edges = [_EXT_RIGHT[prop]]
    return edges


def h_get_acl(ctx, A: Args):
    return None


def h_set_acl(ctx, A: Args):
    status, vals = A.values("aclobject", 1)
    raw_obj = A.named.get("aclobject", [None])[0] if A.named.get("aclobject") else (A.positional[1] if len(A.positional) > 1 else None)
    if raw_obj and raw_obj.startswith("$"):
        acl = A.env.get(raw_obj[1:].lower())
        if isinstance(acl, Acl):
            flush_acl(ctx, acl, A.line)
            return
    ctx.warn(A.line, "Set-Acl with a security descriptor that is not built from a literal 'AD:\\...' path", A.raw)


def flush_pending(ctx) -> None:
    """ACLs edited but never committed with Set-Acl have no effect, so nothing is emitted for them."""
    return None


def h_dom_acl(op: str):
    """PowerView Add-DomainObjectAcl / Remove-DomainObjectAcl."""
    rmap = {"all": ["GenericAll"], "fullcontrol": ["GenericAll"], "allextendedrights": ["GenericAll"],
            "resetpassword": ["ForceChangePassword"], "writemembers": ["AddMember"], "dcsync": ["DCSync"],
            "genericall": ["GenericAll"], "genericwrite": ["GenericWrite"], "writedacl": ["WriteDacl"],
            "writeowner": ["WriteOwner"]}

    def h(ctx, A: Args):
        res = A.need(("targetidentity", 0, True), ("principalidentity", 1, False))
        if res is None:
            return
        targets, principals = res
        status, rights = A.values("rights")
        if status != "ok":
            rights = ["All"]
        edges = []
        for r in rights:
            edges += rmap.get(r.lower().replace(" ", ""), [])
        if not edges:
            ctx.warn(A.line, f"{A.name} -Rights {rights} is not modeled", A.raw)
            return
        for t in targets:
            for p in principals:
                for e in edges:
                    ctx.emit(op, p, e, t, A.line, A.raw)
    return h


def h_owner(ctx, A: Args):
    res = A.need(("identity", 0, True), ("owneridentity", 1, False))
    if res:
        for t in res[0]:
            for o in res[1]:
                ctx.emit("add", o, "Owns", t, A.line, A.raw)


def h_add_adpermission(ctx, A: Args):
    res = A.need(("identity", 0, True), ("user", None, False))
    if res is None:
        return
    status, rights = A.values("accessrights")
    edges, note = rights_to_edges(",".join(rights) if status == "ok" else "", "")
    if A.has("extendedrights"):
        _, ex = A.values("extendedrights")
        for x in ex or []:
            e = _EXT_RIGHT.get(x.lower().replace(" ", "-"))
            if e:
                edges.append(e)
    if not edges:
        ctx.warn(A.line, f"Add-ADPermission: {note or 'rights not recognised'}", A.raw, "note")
        return
    for t in res[0]:
        for u in res[1]:
            for e in dict.fromkeys(edges):
                ctx.emit("add", u, e, t, A.line, A.raw)


def h_gp_permission(ctx, A: Args):
    res = A.need(("name", 0, False), ("targetname", None, False))
    if res is None:
        return
    status, lvl = A.values("permissionlevel")
    level = (lvl[0].lower() if status == "ok" else "")
    gpo, who = res[0][0], res[1]
    if level in ("gpoedit",):
        edges, op = ["GenericWrite"], "add"
    elif level in ("gpoeditdeletemodifysecurity",):
        edges, op = ["GenericAll"], "add"
    elif level == "none":
        edges, op = ["GenericAll", "GenericWrite"], "remove"
    elif level in ("gporead", "gpoapply", "gporeadapply"):
        return
    else:
        ctx.warn(A.line, f"{A.name} permission level '{level or 'unknown'}' is not modeled", A.raw)
        return
    for w in who:
        for e in edges:
            ctx.emit(op, w, e, gpo, A.line, A.raw)


def h_gplink(op: str):
    def h(ctx, A: Args):
        res = A.need(("name", 0, False), ("target", None, False))
        if res:
            ctx.emit(op, res[0][0], "GPOControlsObject", res[1][0], A.line, A.raw)
    return h


# ---- local groups / legacy commands ---------------------------------------------------------

_LOCAL_GROUP_EDGE = {"administrators": "AdminTo", "remote desktop users": "CanRDP",
                     "remote management users": "CanPSRemote", "distributed com users": "ExecuteDCOM"}


def h_local_group(op: str):
    def h(ctx, A: Args):
        res = A.need(("group", 0, False), ("member", 1, False))
        if res is None:
            return
        edge = _LOCAL_GROUP_EDGE.get(res[0][0].lower())
        if edge is None:
            ctx.warn(A.line, f"local group '{res[0][0]}' is not modeled", A.raw, "note")
            return
        host = ctx.computer
        if not host:
            ctx.warn(A.line, f"{A.name} changes a local group on a host that is not named; wrap it in Invoke-Command -ComputerName <host> to model it", A.raw)
            return
        for m in res[1]:
            ctx.emit(op, m, edge, host, A.line, A.raw)
    return h


def h_net(ctx, A: Args):
    words = [w.strip('"\'') for w in A.positional]
    low = [w.lower() for w in words]
    flags = {w.lower() for w in A.raw.split() if w.startswith("/")}
    if len(low) >= 2 and low[0] == "group" and (flags & {"/add", "/delete"}):
        who, grp = (words[2], words[1]) if len(words) >= 3 else (None, None)
        if who:
            ctx.emit("add" if "/add" in flags else "remove", who, "MemberOf", grp, A.line, A.raw)
        return
    if len(low) >= 2 and low[0] == "localgroup" and (flags & {"/add", "/delete"}):
        edge = _LOCAL_GROUP_EDGE.get(low[1])
        who = words[2] if len(words) >= 3 else None
        if edge and who and ctx.computer:
            ctx.emit("add" if "/add" in flags else "remove", who, edge, ctx.computer, A.line, A.raw)
        else:
            ctx.warn(A.line, "net localgroup changes a local group on a host that is not named; wrap it in Invoke-Command -ComputerName <host>", A.raw)
        return
    if len(low) >= 2 and low[0] == "user" and "/add" in flags and "/domain" in flags:
        ctx.emit("create", words[1], "if-missing", "", A.line, A.raw, new_type="user")


def h_dsmod(ctx, A: Args):
    toks = A.positional
    if len(toks) >= 2 and toks[0].lower() == "group":
        grp = _normalise_ref(toks[1].strip('"\''))
        for flag, op in (("-addmbr", "add"), ("-rmmbr", "remove")):
            if flag in A.named or flag.lstrip("-") in A.named:
                for m in A.named.get(flag.lstrip("-"), []):
                    ctx.emit(op, _normalise_ref(m.strip('"\'')), "MemberOf", grp, A.line, A.raw)
        return
    ctx.warn(A.line, "dsmod on an object type that is not modeled", A.raw)


def h_note(text: str):
    def h(ctx, A: Args):
        ctx.warn(A.line, f"{A.name}: {text}", A.raw, "note")
    return h


# ------------------------------------------------------------------ dispatch

P_GROUP = {"identity": "val", "members": "val", "partition": "val", "server": "val", "credential": "val",
           "membertimetolive": "val"}
P_PRINC = {"identity": "val", "memberof": "val", "partition": "val", "server": "val", "credential": "val"}
P_SET = {"identity": "val", "add": "val", "remove": "val", "replace": "val", "clear": "val", "server": "val",
         "principalsallowedtodelegatetoaccount": "val", "principalsallowedtoretrievemanagedpassword": "val",
         "trustedfordelegation": "val", "trustedtoauthfordelegation": "val", "serviceprincipalnames": "val",
         "partition": "val", "credential": "val", "enabled": "val", "path": "val", "description": "val"}
P_NEW = {"name": "val", "samaccountname": "val", "path": "val", "memberof": "val", "type": "val",
         "principalsallowedtoretrievemanagedpassword": "val", "principalsallowedtodelegatetoaccount": "val",
         "trustedfordelegation": "val", "groupscope": "val", "groupcategory": "val", "accountpassword": "val",
         "enabled": "val", "server": "val", "credential": "val", "dnshostname": "val"}
P_MOVE = {"identity": "val", "targetpath": "val", "targetserver": "val", "server": "val"}
P_ID = {"identity": "val", "server": "val", "partition": "val", "credential": "val"}
P_DOMACL = {"targetidentity": "val", "principalidentity": "val", "rights": "val", "domain": "val", "targetsearchbase": "val",
            "principaldomain": "val", "rightsguid": "val"}
P_OWNER = {"identity": "val", "owneridentity": "val", "domain": "val"}
P_ADPERM = {"identity": "val", "user": "val", "accessrights": "val", "extendedrights": "val", "properties": "val",
            "inheritancetype": "val", "deny": "switch"}
P_GPPERM = {"name": "val", "guid": "val", "targetname": "val", "targettype": "val", "permissionlevel": "val",
            "replace": "switch", "domain": "val", "server": "val"}
P_GPLINK = {"name": "val", "guid": "val", "target": "val", "enforced": "val", "linkenabled": "val", "order": "val",
            "domain": "val", "server": "val"}
P_LOCAL = {"group": "val", "member": "val", "name": "val", "sid": "val"}
P_ACL = {"path": "val", "aclobject": "val", "inputobject": "val"}
P_ANY = {}

# name -> (handler, parameter spec, human description for `pathcutter syntax`)
SUPPORTED: dict[str, tuple] = {
    "add-adgroupmember": (h_group_member("add"), P_GROUP, "group membership: add"),
    "remove-adgroupmember": (h_group_member("remove"), P_GROUP, "group membership: remove"),
    "add-domaingroupmember": (h_group_member("add"), P_GROUP, "PowerView: add group member"),
    "remove-domaingroupmember": (h_group_member("remove"), P_GROUP, "PowerView: remove group member"),
    "add-adprincipalgroupmembership": (h_principal_membership("add"), P_PRINC, "membership of one principal in groups: add"),
    "remove-adprincipalgroupmembership": (h_principal_membership("remove"), P_PRINC, "membership of one principal in groups: remove"),
    "set-adgroup": (h_set_object, P_SET, "member via -Add/-Remove/-Replace @{member=...}"),
    "set-aduser": (h_set_object, P_SET, "RBCD, delegation, UAC delegation bit, SID history/SPN notes"),
    "set-adcomputer": (h_set_object, P_SET, "RBCD (-PrincipalsAllowedToDelegateToAccount), delegation flags, msDS-AllowedToDelegateTo"),
    "set-adserviceaccount": (h_set_object, P_SET, "gMSA readers (-PrincipalsAllowedToRetrieveManagedPassword), RBCD"),
    "set-adaccountcontrol": (h_set_object, P_SET, "unconstrained delegation (-TrustedForDelegation)"),
    "set-adobject": (h_set_object, P_SET, "member, msDS-AllowedToDelegateTo, userAccountControl; other attributes are reported"),
    "move-adobject": (h_move, P_MOVE, "re-parent an object under another OU/container"),
    "new-aduser": (h_create("user"), P_NEW, "create a user"),
    "new-adgroup": (h_create("group"), P_NEW, "create a group"),
    "new-adcomputer": (h_create("computer"), P_NEW, "create a computer (RBCD/delegation parameters honoured)"),
    "new-adserviceaccount": (h_create("user"), P_NEW, "create a gMSA and its readers"),
    "remove-aduser": (h_delete, P_ID, "delete a user (all its edges disappear)"),
    "remove-adgroup": (h_delete, P_ID, "delete a group"),
    "remove-adcomputer": (h_delete, P_ID, "delete a computer"),
    "remove-adobject": (h_delete, P_ID, "delete an object"),
    "dsacls": (h_dsacls, P_ANY, "/G grants (GA GW WD WO WP CA SW RP with ;property), /D and /R reported"),
    "set-acl": (h_set_acl, P_ACL, "commits $acl edits (AddAccessRule/RemoveAccessRule/SetOwner)"),
    "get-acl": (h_get_acl, P_ACL, "starts an ACL edit on a literal AD:\\<object> path"),
    "add-domainobjectacl": (h_dom_acl("add"), P_DOMACL, "PowerView: -Rights All|ResetPassword|WriteMembers|DCSync|..."),
    "remove-domainobjectacl": (h_dom_acl("remove"), P_DOMACL, "PowerView: revoke"),
    "set-domainobjectowner": (h_owner, P_OWNER, "PowerView: change owner (Owns)"),
    "add-adpermission": (h_add_adpermission, P_ADPERM, "Exchange-style permission grants"),
    "set-gppermission": (h_gp_permission, P_GPPERM, "GPO rights: GpoEdit -> GenericWrite, GpoEditDeleteModifySecurity -> GenericAll"),
    "set-gppermissions": (h_gp_permission, P_GPPERM, "alias of Set-GPPermission"),
    "new-gplink": (h_gplink("add"), P_GPLINK, "link a GPO to an OU/domain/site"),
    "remove-gplink": (h_gplink("remove"), P_GPLINK, "unlink a GPO"),
    "add-localgroupmember": (h_local_group("add"), P_LOCAL, "local Administrators/RDP/WinRM/DCOM on a host named by Invoke-Command -ComputerName"),
    "remove-localgroupmember": (h_local_group("remove"), P_LOCAL, "local group: remove"),
    "net": (h_net, P_ANY, "net group ... /add|/delete, net localgroup, net user /add /domain"),
    "dsmod": (h_dsmod, P_ANY, "dsmod group <dn> -addmbr/-rmmbr"),
}
SUPPORTED["set-aduser"] = (h_set_object, P_SET, SUPPORTED["set-aduser"][2])
_ALIASES = {"net.exe": "net", "dsacls.exe": "dsacls", "dsmod.exe": "dsmod", "net1": "net", "icm": "invoke-command",
            "%": "foreach-object", "foreach": "foreach-object", "?": "where-object", "where": "where-object"}

NOTES = {   # recognised, harmless to the attack graph: reported at "note" level
    "enable-adaccount": "enabling an account does not change attack paths (it can make a dormant exposed account usable)",
    "disable-adaccount": "disabling an account does not remove its permissions from the graph",
    "unlock-adaccount": "no graph effect",
    "set-adaccountpassword": "credential change, no graph effect",
    "set-adaccountexpiration": "no graph effect",
    "rename-adobject": "renaming does not change relationships",
    "new-adorganizationalunit": "creates an OU; relationships appear only when objects are moved or linked",
    "set-adorganizationalunit": "no modeled effect",
    "set-addefaultdomainpasswordpolicy": "password policy, no graph effect",
    "new-adfinegrainedpasswordpolicy": "password policy, no graph effect",
    "set-adfinegrainedpasswordpolicy": "password policy, no graph effect",
    "add-adfinegrainedpasswordpolicysubject": "password policy scope, no graph effect",
    "setspn": "setting an SPN makes an account Kerberoastable (a credential risk), not a graph edge",
    "set-adreplicationsite": "no graph effect", "new-adreplicationsite": "no graph effect",
}
_AD_MODIFYING = re.compile(r"^(set|new|add|remove|move|rename|enable|disable|unlock|grant|revoke|install|reset|restore|clear)-"
                           r"(ad\w+|domain\w+|gp\w+|localgroup\w*|acl)$", re.I)
_PASS_THROUGH = {"select-object", "select", "sort-object", "sort", "out-null", "out-host", "out-file", "out-string",
                 "tee-object", "format-table", "format-list", "write-host", "write-output", "write-verbose",
                 "write-warning", "write-error", "start-sleep", "import-module", "set-strictmode", "set-location",
                 "get-date", "measure-object", "convertto-json", "unique", "get-unique", "select-string", "ft", "fl",
                 "sleep", "cd", "echo", "write"}
_EXTERNAL_DATA = {"import-csv", "get-content", "read-host", "get-childitem", "invoke-restmethod", "invoke-webrequest",
                  "convertfrom-json", "get-item", "gc", "ipcsv", "import-clixml", "get-variable"}
_GROUP_KEYS = {"identity", "name"}


def _canon_name(tok: str) -> str:
    n = tok.lstrip("&. ").strip().lower().replace("\\", "/")
    n = n.rsplit("/", 1)[-1] if "/" in n else n
    return _ALIASES.get(n, n)


def run_segment(seg: str, block: str | None, block_line: int, pipe, first: bool, env: dict, ctx, line: int, fulltext: str):
    s = seg.strip()
    if not s:
        return pipe
    # ---- plain expressions at the start of a pipeline
    if first and (s[0] in "'\"$(@[" or s[0].isdigit()):
        am = re.match(r"^\$(\w+)\.Access$", s, re.I)
        if am and isinstance(env.get(am.group(1).lower()), Acl):
            return AclAccess(env[am.group(1).lower()])
        ctx.why.clear()
        if s.startswith("[void]") or s.startswith("$null"):
            return None
        v = ev(s, env, ctx)
        ctx.why.clear()
        return v if isinstance(v, list) else UNKNOWN

    toks = split_args(s)
    while toks and toks[0] in ("&", "."):
        toks = toks[1:]
    if not toks:
        return pipe
    name = _canon_name(toks[0])
    args = _expand_splat(toks[1:], env)

    # ---- pipeline plumbing
    if name == "foreach-object":
        return _foreach_object(block, block_line, args, pipe, env, ctx, line)
    if name == "where-object":
        if isinstance(pipe, AclAccess):
            flt = {}
            body = (block or " ".join(args))
            m = re.search(r"IdentityReference\s+-(?:match|like|eq|contains)\s+[\"']([^\"']*)[\"']", body, re.I)
            if m:
                flt["identity"] = [_normalise_ref(m.group(1).strip("*"))]
            m = re.search(r"ActiveDirectoryRights\s+-(?:match|like|eq|contains)\s+[\"']([^\"']*)[\"']", body, re.I)
            if m:
                flt["rights"] = m.group(1).strip("*")
            m = _GUID.search(body)
            if m:
                flt["guid"] = m.group(0).lower()
            pipe.filter = flt
            return pipe
        return pipe if pipe is not None else UNKNOWN
    if name in _PASS_THROUGH:
        return pipe
    if name == "invoke-command":
        return _invoke_command(block, block_line, args, env, ctx, line)
    if name in _EXTERNAL_DATA:
        return UNKNOWN
    if name == "new-object":
        return _new_object(s, args, env, ctx, line)
    if name in ("get-aduser", "get-adgroup", "get-adcomputer", "get-adobject", "get-adserviceaccount",
                "get-domainuser", "get-domaingroup", "get-domaincomputer", "get-domainobject", "get-adgroupmember"):
        ctx.why.clear()
        v = _getter(s, env, ctx)
        ctx.why.clear()
        return v if isinstance(v, list) else UNKNOWN
    if name == "get-acl":
        return _get_acl(args, env, ctx, line, s)

    # ---- modeled and noted cmdlets
    if name in SUPPORTED:
        handler, spec, _ = SUPPORTED[name]
        named, positional = parse_params(args, spec)
        if "whatif" in named:
            return None
        A = Args(ctx, env, line, s, toks[0], named, positional, pipe)
        # `net` and friends take slash switches as plain arguments
        handler(ctx, A)
        return None
    if name in NOTES:
        ctx.warn(line, f"{toks[0]}: {NOTES[name]}", s, "note")
        return None
    if _AD_MODIFYING.match(name) and "-whatif" not in s.lower():
        ctx.warn(line, f"{toks[0]} changes Active Directory but is not modeled by PathCutter; review it by hand", s)
        return None
    return None


def _expand_splat(args: list[str], env: dict) -> list[str]:
    """`Add-ADGroupMember @p` where $p = @{Identity='G'; Members='a'}  ->  -Identity 'G' -Members 'a'."""
    out: list[str] = []
    for a in args:
        m = re.match(r"^@(\w+)$", a)
        table = env.get(m.group(1).lower()) if m else None
        if isinstance(table, HashLit):
            for k, vals in table.items():
                out.append("-" + k)
                out.append(vals[0] if vals else "$true")
        else:
            out.append(a)
    return out


def _getter(s: str, env: dict, ctx):
    from .powershell import identity_of_getter
    return identity_of_getter(s, env, ctx)


def _get_acl(args: list[str], env: dict, ctx, line: int, raw: str):
    named, positional = parse_params(args, P_ACL)
    pth = (named.get("path") or [None])[0] or (positional[0] if positional else None)
    if pth is None:
        return UNKNOWN
    v = ev(pth, env, ctx)
    ctx.why.clear()
    if not isinstance(v, list) or not v:
        return UNKNOWN
    m = re.match(r"^AD:[\\/]*(.+)$", v[0], re.I)
    if not m:
        return UNKNOWN
    return Acl(m.group(1))


def _new_object(s: str, args: list[str], env: dict, ctx, line: int):
    if re.search(r"ActiveDirectoryAccessRule", s, re.I):
        inner = rule_args(s)
        rule = make_rule(inner, env, ctx) if inner is not None else None
        return rule if rule is not None else UNKNOWN
    if re.search(r"NTAccount|SecurityIdentifier", s, re.I):
        ident = _identity_from_expr(s, env, ctx)
        return ident if ident else UNKNOWN
    return UNKNOWN


def _foreach_object(block, block_line, args, pipe, env, ctx, line):
    body = block
    if body is None:
        for a in args:
            if a.startswith("{") and a.endswith("}"):
                body = a[1:-1]
    if body is None:
        return pipe
    if isinstance(pipe, AclAccess):
        if re.search(r"RemoveAccessRule", body, re.I) and pipe.filter is not None:
            pipe.acl.ops.append(("remove", {"filter": pipe.filter}, line, body.strip()[:120]))
        return None
    items = pipe if isinstance(pipe, list) else None
    if items is None:
        e2 = dict(env)
        e2["_"] = None
        e2["psitem"] = None
        inner, _ = scan(body, block_line or line)
        run(inner, e2, ctx, 1)
        return None
    for it in items[:500]:
        e2 = dict(env)
        e2["_"] = [it]
        e2["psitem"] = [it]
        inner, _ = scan(body, block_line or line)
        run(inner, e2, ctx, 1)
    return None


def _invoke_command(block, block_line, args, env, ctx, line):
    named, positional = parse_params(args, {"computername": "val", "scriptblock": "val", "credential": "val",
                                            "argumentlist": "val", "session": "val", "asjob": "switch"})
    body = block
    if body is None and named.get("scriptblock"):
        sb = named["scriptblock"][0]
        body = sb[1:-1] if sb.startswith("{") and sb.endswith("}") else None
    if body is None:
        return None
    host = None
    if named.get("computername"):
        v = ev(named["computername"][0], env, ctx)
        ctx.why.clear()
        if isinstance(v, list) and len(v) == 1:
            host = v[0]
    prev, ctx.computer = ctx.computer, host
    inner, _ = scan(body, block_line or line)
    run(inner, dict(env), ctx, 1)
    ctx.computer = prev
    return None
