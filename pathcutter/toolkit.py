"""`pathcutter doctor` (is this export complete enough to trust?) and `pathcutter anonymize` (share it safely)."""
from __future__ import annotations

import hashlib
import json
import re
import secrets
import zipfile
from collections import Counter
from pathlib import Path

from .edges import TIER0_GROUPS
from .graph import NodeType
from .ingest import _ACE_MAP, _CE_EDGE_MAP, _TYPE_MAP, load_sharphound


# ------------------------------------------------------------------------------------------------ raw access

def iter_raw(path):
    """Yield (entry_name, parsed_json) for every JSON file in a SharpHound zip or directory (or a list of them)."""
    if isinstance(path, (list, tuple)):
        for p in path:
            yield from iter_raw(p)
        return
    path = Path(path)
    from . import adexplorer
    if adexplorer.is_adexplorer_ndjson(path):
        for data in adexplorer.load_ndjson(path):
            yield f"adexplorer_{data['meta']['type']}.json", data
        return
    if path.is_file() and path.suffix.lower() == ".zip":
        with zipfile.ZipFile(path) as zf:
            for entry in zf.namelist():
                if entry.lower().endswith(".json"):
                    try:
                        yield entry, json.loads(zf.read(entry).decode("utf-8-sig"))
                    except (ValueError, UnicodeDecodeError):
                        yield entry, None
    elif path.is_dir():
        for f in sorted(path.glob("*.json")):
            try:
                yield f.name, json.loads(f.read_text(encoding="utf-8-sig"))
            except (ValueError, UnicodeDecodeError):
                yield f.name, None
    else:
        raise ValueError(f"expected a .zip or a directory, got: {path}")


def file_type(entry: str, data) -> str:
    meta = (data or {}).get("meta", {}) if isinstance(data, dict) else {}
    t = str(meta.get("type", "")).lower()
    if t in _TYPE_MAP or t in ("azure", "adcsrelay", "gporights", "conditional_access"):
        return t
    if isinstance(data, dict) and isinstance(data.get("value"), list) and any(
            isinstance(x, dict) and "conditions" in x and "grantControls" in x for x in data["value"][:5]):
        return "conditional_access"
    low = entry.lower()
    return next((k for k in _TYPE_MAP if k in low), "unknown")


def _objects(data):
    return data.get("data", []) if isinstance(data, dict) and isinstance(data.get("data"), list) else []


def _results(v):
    return v.get("Results", []) if isinstance(v, dict) else (v if isinstance(v, list) else [])


# ------------------------------------------------------------------------------------------------ doctor

# rights that exist in collector output but carry no attack edge by design (shown, not flagged)
_BENIGN_RIGHTS = {"GenericRead", "ReadProperty", "WriteProperty", "ReadControl", "Synchronize", "ListChildren", "Delete",
                  "DeleteChild", "CreateChild", "Self", "ExtendedRight", "ListObject", "DeleteTree", "ControlAccess",
                  "AccessSystemSecurity", "Read", "Write", "Execute"}


def diagnose(path, graph=None) -> dict:
    """Inspect a collection without trusting it. Returns a dict of findings (see render_doctor)."""
    files, objs, rights_seen, unmapped = Counter(), Counter(), Counter(), Counter()
    comp = {"total": 0, "sessions": 0, "localgroups": 0, "dc": 0}
    users = {"total": 0, "stale": 0, "never": 0, "with_ace": 0}
    ace_objs = Counter()
    latest = 0
    unreadable, formats = [], Counter()
    trusts: list[dict] = []
    for entry, data in iter_raw(path):
        if data is None or not isinstance(data, dict):
            unreadable.append(entry)
            continue
        ft = file_type(entry, data)
        files[ft] += 1
        meta = data.get("meta", {})
        formats[f"v{meta.get('version', '?')}" if meta else "legacy"] += 1
        for o in _objects(data):
            objs[ft] += 1
            for ace in o.get("Aces", []) or []:
                r = ace.get("RightName") or ace.get("right") or ""
                rights_seen[r] += 1
                ace_objs[ft] += 1
                if r and r not in _ACE_MAP and r not in _CE_EDGE_MAP and r not in _BENIGN_RIGHTS:
                    unmapped[r] += 1
            p = o.get("Properties", {}) or {}
            ts = p.get("lastlogontimestamp") or p.get("lastlogon") or 0
            if isinstance(ts, (int, float)) and ts > 0:
                latest = max(latest, ts)
            if ft == "computers":
                comp["total"] += 1
                comp["dc"] += bool(o.get("IsDC") or p.get("isdc"))
                s = o.get("Sessions") or o.get("PrivilegedSessions")
                if isinstance(s, dict) and s.get("Collected"):
                    comp["sessions"] += 1
                lg = o.get("LocalGroups")
                if isinstance(lg, list) and any(isinstance(x, dict) and x.get("Collected") for x in lg):
                    comp["localgroups"] += 1
            if ft == "users":
                users["total"] += 1
            if ft == "domains":
                for tr in o.get("Trusts", []) or []:
                    trusts.append({"to": tr.get("TargetDomainName"), "type": tr.get("TrustType"),
                                   "direction": tr.get("TrustDirection"), "sid_filtering": tr.get("SidFilteringEnabled")})
    result = {"files": dict(files), "objects": dict(objs), "formats": dict(formats), "unreadable": unreadable,
              "unmapped_rights": dict(unmapped.most_common(15)), "rights_seen": sum(rights_seen.values()),
              "computers": comp, "users": users, "latest_activity": latest, "trusts": trusts}
    graph = graph if graph is not None else load_sharphound(path)
    t0 = graph.tier0_nodes
    result["collections"] = graph.meta.get("collections", 1)
    seen = [d.get("seen", 1) for _, _, d in graph.all_edges() if d.get("edge_type") == "HasSession"]
    result["sessions"] = {"edges": len(seen), "seen_once": sum(1 for s in seen if s == 1)}
    edge_types = Counter(d.get("edge_type") for _, _, d in graph.all_edges())
    result["graph"] = {
        "nodes": graph.node_count, "edges": graph.edge_count, "edge_types": dict(edge_types.most_common()),
        "unknown_nodes": len(graph.nodes_by_type(NodeType.UNKNOWN)), "tier0": len(t0),
        "dcs": sum(1 for n in graph.nodes_by_type(NodeType.COMPUTER) if n.properties.get("isdc")),
        "domains": sorted({n.name for n in graph.nodes_by_type(NodeType.DOMAIN)}),
        "has_krbtgt": any(n.display_name.upper() == "KRBTGT" for n in graph.nodes_by_type(NodeType.USER)),
        "adcs": len(graph.nodes_by_type(NodeType.CERT_TEMPLATE)) + len(graph.nodes_by_type(NodeType.ENTERPRISE_CA)),
        "ca_policies": len(graph.meta.get("conditional_access", [])), "trusts": edge_types.get("TrustedBy", 0), "synced": edge_types.get("SyncedTo", 0),
    }
    result["findings"] = _findings(result)
    return result


def _findings(r: dict) -> list[tuple[str, str, str]]:
    """(severity, what, how to fix). severity: ERROR means results would mislead; WARN means a blind spot."""
    f, g, c = [], r["graph"], r["computers"]
    if not r["files"]:
        f.append(("ERROR", "no recognisable SharpHound/BloodHound JSON files", "point at the collector ZIP or its extracted folder"))
        return f
    if r["unreadable"]:
        f.append(("WARN", f"{len(r['unreadable'])} file(s) could not be parsed: {', '.join(r['unreadable'][:3])}", "re-run the collection; a truncated ZIP is the usual cause"))
    _ad_types = {"users", "groups", "computers", "domains", "ous", "gpos", "containers", "certtemplates", "enterprisecas",
                 "rootcas", "aiacas", "ntauthstores", "issuancepolicies"}
    azure_only = bool(r["files"].get("azure")) and not (set(r["files"]) & _ad_types)
    if r["files"].get("azure") and not azure_only and not r["graph"].get("synced"):
        f.append(("WARN", "Entra ID data is present but no on-premises user is linked to an Entra user (no sync links)",
                  "check onPremisesSecurityIdentifier in the AzureHound output and that the AD collection covers the synced domain"))
    for need in (() if azure_only else ("users", "groups", "computers", "domains")):
        if not r["files"].get(need):
            f.append(("ERROR", f"no {need} file", "collect with `-c Default,ACL,Container,GPOLocalGroup` at least"))
    if r["files"].get("azure"):
        et = g["edge_types"]
        if not et.get("MemberOf"):
            f.append(("ERROR", "Entra data has no group, membership or role-assignment relationships", "collect with `azurehound list` (all objects), not just users"))
        if not et.get("AZOwner") and not et.get("AZContributor") and not et.get("AZUserAccessAdmin"):
            f.append(("WARN", "no Azure resource role assignments (subscriptions / resource groups)", "run AzureHound with an account that has Reader on the subscriptions"))
        f.append(("INFO", ("Entra data does not include administrative-unit membership or Azure deny assignments" if g.get("ca_policies") else
                  "Entra data does not include Conditional Access policies, administrative-unit membership or Azure deny assignments"),
                  ("collect them only if you use administrative units or Azure deny assignments" if g.get("ca_policies") else
                   "export Conditional Access with tools/Export-EntraSidecars.ps1 and keep conditional_access.json next to azure.json")))
    if g["unknown_nodes"]:
        f.append(("WARN", f"{g['unknown_nodes']} principal(s) referenced but not collected (typed Unknown)", "collect from a DC with full LDAP access, or include the other domains in scope"))
    if not azure_only and not r["rights_seen"]:
        f.append(("ERROR", "no ACL data at all: attack paths through permissions are invisible", "re-collect with `-c ACL` (or `All`)"))
    if not azure_only and r["unmapped_rights"]:
        top = ", ".join(f"{k} x{v}" for k, v in list(r["unmapped_rights"].items())[:5])
        f.append(("WARN", f"ACE rights this tool does not model: {top}", "harmless unless one of them is an attack right for you; report it"))
    if not azure_only and g["dcs"] == 0:
        f.append(("ERROR", "no domain controller identified (IsDC / Domain Controllers membership)", "Tier 0 would be incomplete; collect computers with LDAP"))
    if not azure_only and not g["has_krbtgt"]:
        f.append(("WARN", "krbtgt account not present", "Tier 0 anchor missing; collect the Users container"))
    if r.get("collections", 1) == 1 and r.get("sessions", {}).get("edges"):
        f.append(("WARN", f"all {r['sessions']['edges']} session edges come from a single collection (a snapshot of one moment)",
                  "collect sessions several times over days and pass each with --also; sessions seen in more than one collection are more likely to recur"))
    if c["total"]:
        if c["sessions"] == 0:
            f.append(("WARN", "no session data: HasSession paths (credential theft) are not modeled", "re-collect with `-c Session` (and run it more than once, sessions are transient)"))
        elif c["sessions"] < c["total"] * 0.5:
            f.append(("WARN", f"sessions collected on only {c['sessions']}/{c['total']} computers", "firewall or SMB access likely blocked; sessions underreport exposure"))
        if c["localgroups"] == 0:
            f.append(("WARN", "no local group data: AdminTo/CanRDP paths are not modeled", "re-collect with `-c LocalGroup` using an account with remote SAM access"))
        elif c["localgroups"] < c["total"] * 0.5:
            f.append(("WARN", f"local groups collected on only {c['localgroups']}/{c['total']} computers", "unreachable hosts hide their admins; exposure is a floor, not a ceiling"))
    if not azure_only and not r["files"].get("gpos"):
        f.append(("WARN", "no GPO file: policy-driven local admin and GPO control paths are not modeled", "collect with `-c GPOLocalGroup,Container`"))
    if r["files"].get("gpos") and not r["files"].get("gporights"):
        f.append(("INFO", "GPO user-rights assignments (SeBackupPrivilege, SeDebugPrivilege ...) are not in this data",
                  "run tools/Export-AdGpoRights.ps1 and add its *_gporights.json to the collection"))
    if g["adcs"] and not r["files"].get("adcsrelay"):
        f.append(("INFO", "AD CS ESC8 and ESC11 (NTLM relay to the CA's enrollment endpoints) cannot be assessed from this data",
                  "run tools/Export-AdCsRelay.ps1 and add its *_adcsrelay.json to the collection"))
    if not azure_only and not g["adcs"]:
        f.append(("WARN", "no AD CS objects: ESC1-ESC8 style certificate paths cannot be seen", "use a SharpHound/BloodHound CE collector that gathers certificate templates"))
    unfiltered = [t for t in r.get("trusts", []) if t["sid_filtering"] is False and t["type"] in ("External", "Forest")]
    if unfiltered:
        f.append(("WARN", f"{len(unfiltered)} external/forest trust(s) without SID filtering ("
                          + ", ".join(str(t['to']) for t in unfiltered[:3]) + "): SID-history abuse across the trust is possible",
                  "enable SID filtering (netdom trust ... /quarantine:yes); PathCutter treats every trust as traversable regardless"))
    if g["trusts"] == 0 and len(g["domains"]) > 1:
        f.append(("WARN", "several domains but no trust edges", "collect the Domains file from each domain"))
    return f


def render_doctor(r: dict) -> str:
    g, c = r["graph"], r["computers"]
    out = ["", "  pathcutter doctor", "  " + "-" * 60]
    if r.get("collections", 1) > 1:
        s = r["sessions"]
        out.append(f"  merged:   {r['collections']} collections; {s['edges']} session edges, {s['seen_once']} seen only once")
    out.append(f"  files:    " + ", ".join(f"{k} x{v}" for k, v in sorted(r["files"].items())) + f"   ({', '.join(r['formats'])})")
    out.append(f"  graph:    {g['nodes']} nodes, {g['edges']} edges, {g['tier0']} Tier 0, {g['dcs']} DC(s), domains: {', '.join(g['domains']) or '-'}")
    if c["total"]:
        out.append(f"  hosts:    sessions on {c['sessions']}/{c['total']}, local groups on {c['localgroups']}/{c['total']}")
    out.append("  edges:    " + ", ".join(f"{k} {v}" for k, v in list(g["edge_types"].items())[:10]))
    out.append("")
    errs = [x for x in r["findings"] if x[0] == "ERROR"]
    warns = [x for x in r["findings"] if x[0] == "WARN"]
    for sev, what, fix in r["findings"]:
        out.append(f"  [{sev:<5}] {what}")
        out.append(f"          fix: {fix}")
    verdict = "NOT TRUSTWORTHY" if errs else ("USABLE WITH BLIND SPOTS" if warns else "COMPLETE")
    out += ["", f"  verdict: {verdict}   ({len(errs)} error(s), {len(warns)} warning(s))",
            "  Results from this export are a floor: paths through uncollected data are invisible, not absent.", ""]
    return "\n".join(out)


# ------------------------------------------------------------------------------------------------ anonymize

_GUID = re.compile(r"\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\b")
_WORD = re.compile(r"[A-Za-z0-9_]+")
_NAME_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")
_OID = re.compile(r"((?<![\w.])\d+(?:\.\d+){2,}(?![\w.]))")
_DOM_SID = re.compile(r"S-1-5-21-(\d+)-(\d+)-(\d+)")
_DROP = {"description", "email", "mail", "homedirectory", "scriptpath", "title", "department", "info", "telephonenumber",
         "userpassword", "unixpassword", "unicodepassword", "sfupassword", "gpcpath", "company", "streetaddress",
         "homephone", "mobile", "manager", "comment", "logonscript", "profilepath", "displayname", "givenname", "sn"}
_DROP_AZ = {"mail", "givenname", "surname", "jobtitle", "department", "mobilephone", "businessphones", "othermails",
            "proxyaddresses", "streetaddress", "city", "postalcode", "state", "country", "officelocation", "employeeid",
            "aboutme", "imaddresses", "identities", "faxnumber", "companyname", "mailnickname", "preferredname",
            "onpremisesimmutableid", "onpremisesdistinguishedname", "onpremisessamaccountname", "onpremisesuserprincipalname",
            "description", "notes", "info", "homepage", "subject", "loginurl", "logouturl", "replyurls", "tags", "employeeorgdata"}
_PROTECTED_KEYS = {"RightName", "ObjectType", "PrincipalType", "type", "kind", "Type", "LocalGroupType", "ObjectClass",
                   "version", "methods", "collected", "Collected"}
_KEEP_WORDS = (set(TIER0_GROUPS) | {"MICROSOFT GRAPH", "USERS", "COMPUTERS", "DOMAIN CONTROLLERS", "BUILTIN", "NT AUTHORITY", "SYSTEM", "EVERYONE",
               "AUTHENTICATED USERS", "ADMINISTRATOR", "GUEST", "KRBTGT", "DOMAIN USERS", "DOMAIN GUESTS", "DOMAIN COMPUTERS",
               "PROTECTED USERS", "CLONEABLE DOMAIN CONTROLLERS", "GROUP POLICY CREATOR OWNERS", "RAS AND IAS SERVERS",
               "DNSADMINS", "DNSUPDATEPROXY", "DEFAULT DOMAIN POLICY", "DEFAULT DOMAIN CONTROLLERS POLICY", "USER", "GROUP",
               "COMPUTER", "DOMAIN", "OU", "GPO", "CONTAINER", "BUILTIN", "PROGRAM DATA", "MANAGED SERVICE ACCOUNTS",
               "FOREIGNSECURITYPRINCIPALS", "KEYS", "CONFIGURATION", "SCHEMA", "SERVICES", "SYSTEM", "NTAUTHCERTIFICATES",
               "CERTIFICATE TEMPLATES", "PUBLIC KEY SERVICES", "DOMAIN ADMINS", "REMOTE DESKTOP USERS", "REMOTE MANAGEMENT USERS",
               "DISTRIBUTED COM USERS", "REPLICATOR", "NETWORK CONFIGURATION OPERATORS", "PERFORMANCE MONITOR USERS",
               "PERFORMANCE LOG USERS", "INCOMING FOREST TRUST BUILDERS", "WINDOWS AUTHORIZATION ACCESS GROUP",
               "TERMINAL SERVER LICENSE SERVERS", "PRE-WINDOWS 2000 COMPATIBLE ACCESS", "ALLOWED RODC PASSWORD REPLICATION GROUP",
               "DENIED RODC PASSWORD REPLICATION GROUP", "CERTIFICATE SERVICE DCOM ACCESS", "STORAGE REPLICA ADMINISTRATORS",
               "HYPER-V ADMINISTRATORS", "ACCESS CONTROL ASSISTANCE OPERATORS", "RDS REMOTE ACCESS SERVERS", "RDS ENDPOINT SERVERS",
               "RDS MANAGEMENT SERVERS", "EVENT LOG READERS", "CRYPTOGRAPHIC OPERATORS", "IIS_IUSRS", "INCOMING FOREST TRUST BUILDERS",
               "ENTERPRISE DOMAIN CONTROLLERS", "LOCAL SYSTEM", "NETWORK SERVICE", "SERVICE"})


class Anonymizer:
    """Deterministic, salted pseudonyms. Structure (RIDs, memberships, ACE rights, flags) is preserved, so analysis
    results on the anonymized copy match the original object for object."""

    def __init__(self, salt: str | None = None):
        self.salt = salt or secrets.token_hex(8)
        self.tokens: dict[str, str] = {}          # UPPER token -> replacement
        self.domains: dict[str, str] = {}
        self._dom_sid: dict[str, str] = {}
        self._rx = None

    def _h(self, s: str, n=6) -> str:
        return hashlib.sha256(f"{self.salt}|{s.upper()}".encode()).hexdigest()[:n].upper()

    def _dom_label(self, dom: str) -> str:
        if dom.upper() not in self.domains:
            self.domains[dom.upper()] = f"DOM{self._h(dom, 4)}"
        return self.domains[dom.upper()]

    # ---- pass 1: learn what to replace
    def learn_azure(self, data) -> None:
        for it in data.get("data", []):
            d = it.get("data") if isinstance(it, dict) else None
            if not isinstance(d, dict):
                continue
            kind = it.get("kind", "")
            if kind == "AZRole" and d.get("isBuiltIn") and d.get("id"):
                self.__dict__.setdefault("_builtin_roles", set()).add(str(d["id"]).upper())     # a role template id is public
                self._public = None
            prefix = {"AZUser": "AZU", "AZGroup": "AZG", "AZApp": "AZA", "AZServicePrincipal": "AZS", "AZRole": "AZR"}.get(kind, "AZO")
            upn = str(d.get("userPrincipalName") or "")
            if "@" in upn:
                local, dom = upn.split("@", 1)
                self._dom_label(dom)
                if local.upper() not in _KEEP_WORDS:
                    self.tokens.setdefault(local.upper(), f"{prefix}{self._h(local)}")
            for key in ("displayName",):
                v = str(d.get(key) or "")
                if v and kind != "AZRole" and v.upper() not in _KEEP_WORDS:
                    self.tokens.setdefault(v.upper(), f"{prefix}{self._h(v)}")
            for key in ("defaultDomain",):
                if d.get(key):
                    self._dom_label(str(d[key]))
        for m in _DOM_SID.finditer(json.dumps(data)):
            self._dom_sid_for(m)

    def learn(self, entry: str, data) -> None:
        from .azure import is_azure_file
        if is_azure_file(data):
            self.learn_azure(data)
            return
        ft = file_type(entry, data)
        prefix = {"users": "USER", "computers": "HOST", "groups": "GRP"}.get(ft, "OBJ")
        for o in _objects(data):
            p = o.get("Properties", {}) or {}
            oid = str(o.get("ObjectIdentifier", ""))
            builtin = bool(re.search(r"-\d{1,3}$", oid)) or oid.startswith("S-1-5-32-") or oid.startswith("S-1-1-") \
                or bool(re.match(r"^S-1-5-\d+$", oid))
            name = str(p.get("name", ""))
            dom = str(p.get("domain", ""))
            if "@" in name:
                local, d = name.split("@", 1)
            elif "." in name and ft == "computers":
                local, d = name.split(".", 1)
            else:
                local, d = name, dom
            for dd in (dom, d):
                if dd and "." in dd:
                    self._dom_label(dd)
            for t in {local, str(p.get("samaccountname", "")).rstrip("$")}:
                if t and ft != "domains" and t.upper() not in _KEEP_WORDS and not builtin and t.upper() not in self.tokens:
                    self.tokens[t.upper()] = f"{prefix}{self._h(t)}"
            for t in o.get("Trusts") or []:                     # partner domains named only inside a trust
                tn = str(t.get("TargetDomainName") or "")
                if "." in tn:
                    self._dom_label(tn)
                elif tn and tn.upper() not in _KEEP_WORDS:
                    self.tokens.setdefault(tn.upper(), f"DOM{self._h(tn, 4)}")
                for m in _DOM_SID.finditer(str(t.get("TargetDomainSid") or "")):
                    self._dom_sid_for(m)
            for m in _DOM_SID.finditer(oid):
                self._dom_sid_for(m)
            for m in _DOM_SID.finditer(str(p.get("domainsid", ""))):
                self._dom_sid_for(m)
            if "." in str(p.get("domain", "")):
                self._dom_label(p["domain"])

    def _dom_sid_for(self, m):
        key = "-".join(m.groups())
        if key not in self._dom_sid:
            h = int(self._h(key, 12), 16)
            self._dom_sid[key] = f"{1000000000 + h % 3000000000}-{1000000000 + (h // 7) % 3000000000}-{1000000000 + (h // 13) % 3000000000}"

    def finalize(self) -> None:
        alts = {}
        for d, lbl in self.domains.items():
            alts[d] = lbl + ".LOCAL"
            first = d.split(".")[0]
            if first and first not in _KEEP_WORDS:
                alts.setdefault(first, lbl)                       # NetBIOS name
        alts.update(self.tokens)
        self._alts = alts
        # index every token by its first word: scanning a string is then linear in its length, not in the number of names
        by_first: dict[str, list[tuple[str, int]]] = {}
        for k in alts:
            m = _WORD.search(k)                              # names such as $141000-ABC start with a non-word character
            if m:
                by_first.setdefault(m.group(0), []).append((k, m.start()))
        for lst in by_first.values():
            lst.sort(key=lambda t: len(t[0]), reverse=True)  # longest first: NORTH.SEVENKINGDOMS.LOCAL before NORTH
        self._by_first = by_first
        self._rx = bool(by_first)

    # ---- pass 2: rewrite
    def text(self, s: str) -> str:
        s = _DOM_SID.sub(lambda m: "S-1-5-21-" + self._dom_sid.get("-".join(m.groups()), "-".join(m.groups())), s)
        s = _GUID.sub(lambda m: self._guid(m.group(0)), s)
        if self._rx:
            # OIDs (1.3.6.1.5.5.7.3.2 ...) are public identifiers: a user called "1" must not rewrite them
            parts = _OID.split(s)
            for i in range(0, len(parts), 2):
                parts[i] = self._replace_names(parts[i])
            s = "".join(parts)
        return s

    def _replace_names(self, s: str) -> str:
        up = s.upper()
        if len(up) != len(s):                              # a character whose upper case is longer: keep it simple and exact
            up = s
        out, last, n = [], 0, len(s)
        for m in _WORD.finditer(up):
            cands = self._by_first.get(m.group(0))
            if not cands:
                continue
            for tok, off in cands:
                a = m.start() - off
                b = a + len(tok)
                if a < last or a < 0 or (a > 0 and up[a - 1] in _NAME_CHARS):
                    continue
                if up.startswith(tok, a) and (b >= n or not (up[b].isalnum() or up[b] == "_" or (up[b] == "-" and not up.startswith("-S-1-", b)))):
                    out.append(s[last:a])
                    out.append(self._alts[tok])
                    last = b
                    break
        if not out:
            return s
        out.append(s[last:])
        return "".join(out)

    def _guid(self, g: str) -> str:
        if g.upper() in self._public_guids():             # built-in role ids and Graph permission ids are public and carry meaning
            return g
        h = hashlib.sha256(f"{self.salt}|{g.upper()}".encode()).hexdigest().upper()
        return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"

    def _public_guids(self) -> set:
        got = getattr(self, "_public", None)
        if got is None:
            from .azure import ADD_MEMBER_PERMS, ADD_SECRET_PERMS, GRANT_ROLE_PERMS, KNOWN_ROLES, RESET_PW_PERMS, _ROLE_DEF_EDGE
            got = self._public = (set(KNOWN_ROLES) | set(ADD_MEMBER_PERMS) | set(ADD_SECRET_PERMS) | set(GRANT_ROLE_PERMS)
                                  | set(RESET_PW_PERMS) | set(_ROLE_DEF_EDGE) | getattr(self, "_builtin_roles", set()))
        return got

    def _thumb(self, t: str) -> str:
        return hashlib.sha256(f"{self.salt}|{t.upper()}".encode()).hexdigest()[:40].upper()

    def walk(self, v, key="", az=False):
        if key.lower() in ("certthumbprint", "certthumbprints", "certchain") and isinstance(v, (str, list)):
            return self._thumb(v) if isinstance(v, str) else [self._thumb(str(x)) for x in v]     # equal stays equal
        if isinstance(v, dict):
            out = {}
            for k, x in v.items():
                if az:
                    if k.lower() in _DROP_AZ:
                        continue
                elif k.lower() in _DROP and not isinstance(x, (dict, list)):
                    continue
                out[k] = self.walk(x, k, az)
            return out
        if isinstance(v, list):
            return [self.walk(x, key, az) for x in v]
        if isinstance(v, str) and key not in _PROTECTED_KEYS:
            return self.text(v)
        return v


def anonymize(src, dst, salt: str | None = None):
    """Write an anonymized copy of a collection to dst (.zip). Returns (Anonymizer, files_written)."""
    items = [(e, d) for e, d in iter_raw(src) if d is not None]
    an = Anonymizer(salt)
    for e, d in items:
        an.learn(e, d)
    an.finalize()
    dst = Path(dst)
    dst.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zf:
        for i, (e, d) in enumerate(items):          # file names carry the domain and a timestamp: replace them
            from .azure import is_azure_file
            az = is_azure_file(d)
            zf.writestr(f"anon_{'azure' if az else file_type(e, d)}_{i:02d}.json", json.dumps(an.walk(d, az=az)))
    return an, len(items)


# ------------------------------------------------------------------------------------------------ CLI

def add_parsers(sub) -> None:
    p = sub.add_parser("doctor", help="Check whether a SharpHound export is complete enough to trust")
    p.add_argument("input", help="SharpHound ZIP or directory")
    p.add_argument("--also", action="append", default=[], metavar="PATH", help="Another collection of the same environment (repeatable)")
    p.add_argument("--json", action="store_true", help="Machine-readable output")
    p.add_argument("--strict", action="store_true", help="Exit 1 on warnings too (default: only on errors)")
    au = sub.add_parser("audit", help="AD hygiene findings from collected attributes (roastable accounts, passwords in attributes, LAPS, ...)")
    au.add_argument("input", help="SharpHound ZIP or directory")
    au.add_argument("--also", action="append", default=[], metavar="PATH", help="Another collection of the same environment (repeatable)")
    au.add_argument("--min-severity", choices=["info", "low", "medium", "high", "critical"], default="low")
    au.add_argument("--json", action="store_true")
    au.add_argument("--fail-on", choices=["low", "medium", "high", "critical"], help="exit 2 if a finding at or above this severity exists")
    a = sub.add_parser("anonymize", help="Make a shareable copy of your export (pseudonyms, no free text), same attack paths")
    a.add_argument("input", help="SharpHound ZIP or directory")
    a.add_argument("-o", "--output", default="anonymized.zip", help="Output ZIP (default ./anonymized.zip)")
    a.add_argument("--salt", help="Fixed salt for reproducible output (default: random, not stored)")
    a.add_argument("--map", metavar="FILE", help="Also write the pseudonym -> original map (KEEP PRIVATE)")


def cmd_doctor(args) -> int:
    try:
        r = diagnose([args.input, *args.also] if args.also else args.input)
    except (ValueError, OSError, zipfile.BadZipFile) as exc:
        print(f"[!] {exc}", file=__import__("sys").stderr)
        return 1
    if args.json:
        print(json.dumps(r, indent=2, default=str))
    else:
        print(render_doctor(r))
    sev = {s for s, _, _ in r["findings"]}
    return 1 if "ERROR" in sev or (args.strict and "WARN" in sev) else 0


def cmd_audit(args) -> int:
    import sys
    from .hygiene import SEVERITIES, audit, render
    try:
        graph = load_sharphound([args.input, *args.also] if args.also else args.input)
    except (ValueError, OSError, zipfile.BadZipFile) as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1
    findings = audit(graph)
    shown = [f for f in findings if SEVERITIES.index(f.severity) >= SEVERITIES.index(args.min_severity)]
    if args.json:
        print(json.dumps([f.to_dict() for f in shown], indent=2))
    else:
        print(render(findings, args.min_severity))
    if args.fail_on and any(SEVERITIES.index(f.severity) >= SEVERITIES.index(args.fail_on) for f in findings):
        return 2
    return 0


def cmd_anonymize(args) -> int:
    import sys
    try:
        an, n = anonymize(args.input, args.output, args.salt)
    except (ValueError, OSError, zipfile.BadZipFile) as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1
    print(f"[+] {n} file(s) anonymized -> {args.output}")
    print(f"    {len(an.tokens)} names, {len(an.domains)} domain(s) pseudonymized; GUIDs and domain SIDs rehashed")
    print("    dropped: descriptions, emails, paths, phone/title/department, password-ish attributes")
    if args.map:
        inv = {v: k for k, v in {**an.tokens, **{d: l + '.LOCAL' for d, l in an.domains.items()}}.items()}
        Path(args.map).write_text(json.dumps(inv, indent=2), encoding="utf-8")
        print(f"[!] {args.map} reverses the pseudonyms - keep it private")
    print("    Review it before sharing: free-text fields not on the drop list could still hold identifying text.")
    return 0
