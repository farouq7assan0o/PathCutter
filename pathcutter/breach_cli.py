"""CLI for `pathcutter breach`: assume an object is compromised and show what it reaches, cheapest and quietest first."""
from __future__ import annotations

import json
import sys

from .breach import analyse_breach, render
from .snapshot import SnapshotError, load_baseline


def add_parser(sub) -> None:
    p = sub.add_parser("breach", help="Assume breach: if one object is compromised, what Tier 0 can it reach and by the cheapest / stealthiest route?")
    p.add_argument("input", help="A .pcsnap snapshot or a SharpHound/AzureHound/AD Explorer ZIP/directory")
    p.add_argument("--also", nargs="+", metavar="PATH", default=[],
                   help="Additional collections to merge (e.g. an Entra export alongside an on-prem one), as `analyze --also`")
    p.add_argument("--from", dest="start", required=True, metavar="OBJECT",
                   help="The compromised object: an exact name (e.g. 'BOB@CORP.LOCAL'), a short name, or an object id")
    p.add_argument("--profile", choices=["opportunist", "stealth", "balanced"], default="balanced",
                   help="Attacker profile used when ranking (opportunist favours low effort, stealth favours low noise)")
    p.add_argument("--top", type=int, default=10, help="How many reachable Tier 0 objects to show")
    p.add_argument("--json", metavar="FILE", help="Also write the result as JSON")
    p.add_argument("--max-depth", type=int, default=12)
    p.add_argument("--max-paths", type=int, default=4000)


def cmd_breach(args) -> int:
    try:
        if args.also:
            from .ingest import load_sharphound
            graph = load_sharphound([args.input, *args.also])
        else:
            graph, _ = load_baseline(args.input)
    except SnapshotError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1
    rep = analyse_breach(graph, args.start, profile=args.profile, max_depth=args.max_depth, max_paths=args.max_paths)
    print(render(rep, args.top))
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(rep.to_dict(), f, indent=2)
        print(f"[+] wrote {args.json}")
    if not rep.start:
        return 1                                  # unmatched or ambiguous start
    return 2 if rep.reachable_tier0 else 0        # 2 = this object can reach Tier 0 (useful for gating)
