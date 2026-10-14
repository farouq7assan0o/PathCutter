"""CLI for `pathcutter coverage`: would anyone see the attack paths that remain?"""
from __future__ import annotations

import json
import sys

from .coverage import Inventory, analyse, render, template, to_dict
from .detect_pack import residual_points
from .snapshot import SnapshotError, load_baseline


def add_parser(sub) -> None:
    p = sub.add_parser("coverage", help="Which attack paths would be detected, which only visible, which blind (needs your telemetry list)")
    p.add_argument("input", nargs="?", help="Baseline: a .pcsnap snapshot or a SharpHound ZIP/directory")
    p.add_argument("--telemetry", metavar="FILE", help="JSON: {\"telemetry\": [...], \"rules\": [...]} (see --template)")
    p.add_argument("--assume-pack", action="store_true", help="Count the rules `pathcutter detect` would generate as deployed")
    p.add_argument("--assume-fixed", type=int, default=0, metavar="N", help="Evaluate only what remains after the top N fixes")
    p.add_argument("--template", action="store_true", help="Print a telemetry file template with every telemetry name and exit")
    p.add_argument("--json", metavar="FILE", help="Also write the result as JSON")
    p.add_argument("--fail-on-blind", action="store_true", help="Exit 2 if any path is blind (for CI)")
    p.add_argument("--top", type=int, default=8)
    p.add_argument("--max-depth", type=int, default=20)
    p.add_argument("--max-paths", type=int, default=10000)


def cmd_coverage(args) -> int:
    if args.template:
        print(json.dumps(template(), indent=2))
        return 0
    if not args.input:
        print("[!] an input is required (a snapshot or a collection); use --template for the telemetry file format", file=sys.stderr)
        return 1
    try:
        graph, _ = load_baseline(args.input)
    except SnapshotError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1
    inv = Inventory.load(args.telemetry) if args.telemetry else Inventory()
    if args.assume_pack:
        inv = inv.with_pack()
    if args.assume_fixed:
        graph, _points, info = residual_points(graph, args.assume_fixed, 1, args.max_depth, args.max_paths)
        print(f"[*] assuming the top {args.assume_fixed} fixes are applied: {info['paths_residual']} path(s) remain")
    rep = analyse(graph, inv, args.max_paths, args.max_depth)
    if not args.telemetry:
        print("[i] no --telemetry file given: nothing is assumed to be collected, so every step is blind.\n    Run with --template to see the names.")
    print(render(rep, args.top))
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(to_dict(rep), f, indent=2)
        print(f"[+] wrote {args.json}")
    return 2 if (args.fail_on_blind and rep.counts["blind"]) else 0
