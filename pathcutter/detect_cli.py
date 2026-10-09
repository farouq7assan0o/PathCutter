"""CLI for `pathcutter detect`: detections for the attack paths you have not fixed."""
from __future__ import annotations

import argparse
import sys

from .detect_pack import FORMATS, build_pack, residual_points, write_pack
from .snapshot import SnapshotError, load_baseline


def add_parser(sub) -> None:
    p = sub.add_parser("detect", help="Generate detections (Sigma, SPL, KQL) for the attack paths you have not fixed")
    p.add_argument("input", help="Baseline: a .pcsnap snapshot or a SharpHound ZIP/directory")
    p.add_argument("--assume-fixed", type=int, default=0, metavar="N",
                   help="Plan to apply the top N fixes; generate detections for what REMAINS (default 0: everything)")
    p.add_argument("--top", type=int, default=25, metavar="K", help="Residual choke points to monitor (default 25)")
    p.add_argument("-o", "--output", default="detections", help="Output directory (default ./detections)")
    p.add_argument("--formats", default=",".join(FORMATS), help=f"Comma list of: {', '.join(FORMATS)} (default all)")
    p.add_argument("--index", default="wineventlog", help="Splunk index holding Windows Security events")
    p.add_argument("--no-watches", action="store_true",
                   help="Skip the always-on watches (Tier 0 groups, groups that can reach Tier 0)")
    p.add_argument("--max-depth", type=int, default=20)
    p.add_argument("--max-paths", type=int, default=10000)


def cmd_detect(args) -> int:
    formats = tuple(f.strip().lower() for f in args.formats.split(",") if f.strip())
    bad = [f for f in formats if f not in FORMATS]
    if bad:
        print(f"[!] unknown format(s): {', '.join(bad)} (choose from {', '.join(FORMATS)})", file=sys.stderr)
        return 1
    try:
        graph, base = load_baseline(args.input)
    except SnapshotError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1
    work, points, info = residual_points(graph, args.assume_fixed, args.top, args.max_depth, args.max_paths)
    pack = build_pack(work, points, info, include_watches=not args.no_watches)
    files = write_pack(pack, args.output, formats, args.index)
    print(f"[*] {info['paths_total']} attack paths; assuming the top {args.assume_fixed} fixes leaves {info['paths_residual']}")
    print(f"[*] {len(points)} residual monitor points cover {info['coverage_pct']}% of them")
    print(f"[+] {len(pack.rules)} rules ({', '.join(formats)}) written to {args.output}  ({len(files)} files)")
    for r in pack.rules:
        print(f"    [{r.level:<8}] {r.slug:<40} events {','.join(map(str, r.event_ids)):<16} {len(r.objects)} object(s)")
    print(f"[+] Read {args.output}/prerequisites.md first: rules only fire if the audit policy is enabled.")
    return 0
