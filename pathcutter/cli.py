"""Pathcutter CLI - AD Attack Path Risk Engine."""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from . import __version__
from .ingest import load_sharphound
from .pathfinder import find_all_paths
from .scoring import score_nodes, score_posture
from .choke import find_chokepoints, find_node_chokepoints
from .remediate import build_plan


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pathcutter",
        description="AD Attack Path Risk Engine - find what to fix, in what order",
    )
    parser.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command")

    # analyze
    p_analyze = sub.add_parser("analyze", help="Full analysis of a SharpHound export")
    p_analyze.add_argument("input", help="SharpHound ZIP or directory")
    p_analyze.add_argument("--top", type=int, default=10, help="Top N fixes to show")
    p_analyze.add_argument("--max-depth", type=int, default=20, help="Max path depth")
    p_analyze.add_argument("--max-paths", type=int, default=10000, help="Max paths to enumerate")
    p_analyze.add_argument("-o", "--output", help="Output directory for reports")
    p_analyze.add_argument("--html", action="store_true", help="Generate HTML report")
    p_analyze.add_argument("--json", action="store_true", dest="json_out", help="Generate JSON snapshot")
    p_analyze.add_argument("--markdown", action="store_true", help="Generate markdown summary")

    # score
    p_score = sub.add_parser("score", help="Quick risk score")
    p_score.add_argument("input", help="SharpHound ZIP or directory")
    p_score.add_argument("--max-depth", type=int, default=20)
    p_score.add_argument("--max-paths", type=int, default=10000)

    # fix
    p_fix = sub.add_parser("fix", help="Generate remediation script")
    p_fix.add_argument("input", help="SharpHound ZIP or directory")
    p_fix.add_argument("--top", type=int, default=10, help="Top N fixes")
    p_fix.add_argument("--max-depth", type=int, default=20)
    p_fix.add_argument("--max-paths", type=int, default=10000)
    p_fix.add_argument("-o", "--output", help="Output .ps1 file")
    p_fix.add_argument("--no-rollback", action="store_true", help="Skip rollback section")

    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 1

    if args.command == "analyze":
        return _cmd_analyze(args)
    elif args.command == "score":
        return _cmd_score(args)
    elif args.command == "fix":
        return _cmd_fix(args)

    return 0


def _load_and_analyze(args):
    t0 = time.time()
    print(f"[*] Loading SharpHound data from {args.input}...")
    graph = load_sharphound(args.input)
    print(f"    {graph.node_count} nodes, {graph.edge_count} edges")

    summary = graph.summary()
    print(f"    Tier 0: {summary['tier_0_count']} | Tier 1: {summary['tier_1_count']} | Tier 2: {summary['tier_2_count']}")

    print(f"[*] Finding attack paths (depth={args.max_depth}, cap={args.max_paths})...")
    targets = graph.tier0_nodes
    report = find_all_paths(graph, targets, max_depth=args.max_depth, max_paths=args.max_paths)
    print(f"    {report.total_paths} paths from {report.unique_sources} sources")

    elapsed = time.time() - t0
    print(f"    Completed in {elapsed:.1f}s")
    return graph, report


def _cmd_analyze(args) -> int:
    graph, report = _load_and_analyze(args)

    posture = score_posture(graph, report)
    print(f"\n[*] Risk Score: {posture.score}/100 (Grade: {posture.grade})")
    print(f"    Exposure: {posture.exposure_pct:.1f}% of Tier 2 can reach Tier 0")
    print(f"    Path density: {posture.path_density:.2f} paths/node")
    print(f"    Avg path length: {posture.avg_path_length}")

    node_scores = score_nodes(graph, report)
    if node_scores:
        n = min(args.top, len(node_scores))
        print(f"\n[*] Top {n} Riskiest Nodes:")
        print(f"    {'Name':<40} {'Type':<10} {'Tier':<5} {'Score':<8} {'Paths':<8} {'T0 Reach'}")
        for ns in node_scores[:n]:
            print(f"    {ns.display_name:<40} {ns.node_type:<10} T{ns.tier:<4} {ns.risk_score:<8.1f} {ns.path_count:<8} {ns.tier0_reach}")

    choke = find_chokepoints(graph, report, max_fixes=args.top)
    if choke.fixes:
        print(f"\n[*] Top {len(choke.fixes)} Fixes ({choke.elimination_pct:.0f}% path elimination):")
        print(f"    {'#':<4} {'Fix':<60} {'Cut':<8} {'Cumul'}")
        for fix in choke.fixes:
            desc = f"{fix.source_name} -> {fix.target_name} [{fix.edge_type}]"
            if len(desc) > 58:
                desc = desc[:55] + "..."
            print(f"    {fix.rank:<4} {desc:<60} {fix.paths_eliminated:<8} {fix.cumulative_pct}%")

    out_dir = Path(args.output) if args.output else None
    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True)

    if args.json_out:
        snapshot = _build_json_snapshot(graph, report, posture, node_scores, choke)
        if out_dir:
            path = out_dir / "pathcutter-report.json"
            path.write_text(json.dumps(snapshot, indent=2))
            print(f"\n[+] JSON report: {path}")
        else:
            print(json.dumps(snapshot, indent=2))

    if args.markdown:
        plan = build_plan(choke, top_n=args.top)
        md = plan.markdown_summary()
        if out_dir:
            path = out_dir / "pathcutter-report.md"
            path.write_text(md)
            print(f"\n[+] Markdown report: {path}")
        else:
            print(md)

    if args.html:
        try:
            from .report import generate_html_report
            html = generate_html_report(graph, report, posture, node_scores, choke)
            if out_dir:
                path = out_dir / "pathcutter-report.html"
                path.write_text(html, encoding="utf-8")
                print(f"\n[+] HTML report: {path}")
            else:
                print(html)
        except ImportError:
            print("\n[!] HTML report generation not yet available.", file=sys.stderr)

    return 0


def _cmd_score(args) -> int:
    graph, report = _load_and_analyze(args)
    posture = score_posture(graph, report)
    print(f"\n{'=' * 40}")
    print(f"  AD Risk Score: {posture.score}/100")
    print(f"  Grade:         {posture.grade}")
    print(f"  Total paths:   {posture.total_paths}")
    print(f"  Sources:       {posture.unique_sources}")
    print(f"  Exposure:      {posture.exposure_pct:.1f}%")
    print(f"{'=' * 40}")
    return 0


def _cmd_fix(args) -> int:
    graph, report = _load_and_analyze(args)
    choke = find_chokepoints(graph, report, max_fixes=args.top)
    plan = build_plan(choke, top_n=args.top)

    script = plan.powershell_script(include_rollback=not args.no_rollback)

    if args.output:
        Path(args.output).write_text(script)
        print(f"\n[+] Remediation script: {args.output}")
        print(f"    {len(plan.fixes)} fixes | {plan.paths_eliminated}/{plan.total_paths} paths ({plan.elimination_pct:.0f}%)")
    else:
        print(script)

    return 0


def _build_json_snapshot(graph, report, posture, node_scores, choke) -> dict:
    return {
        "version": __version__,
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "summary": graph.summary(),
        "posture": {
            "score": posture.score,
            "grade": posture.grade,
            "total_paths": posture.total_paths,
            "unique_sources": posture.unique_sources,
            "avg_path_length": posture.avg_path_length,
            "exposure_pct": round(posture.exposure_pct, 1),
            "path_density": posture.path_density,
        },
        "top_risks": [
            {
                "name": ns.name,
                "type": ns.node_type,
                "tier": ns.tier,
                "risk_score": ns.risk_score,
                "path_count": ns.path_count,
                "blast_radius": ns.blast_radius,
                "tier0_reach": ns.tier0_reach,
            }
            for ns in node_scores[:20]
        ],
        "fixes": [
            {
                "rank": f.rank,
                "source": f.source_name,
                "target": f.target_name,
                "edge_type": f.edge_type,
                "paths_eliminated": f.paths_eliminated,
                "cumulative_pct": f.cumulative_pct,
                "mitre": f.mitre,
                "fix_command": f.fix_command,
            }
            for f in choke.fixes
        ],
    }


if __name__ == "__main__":
    sys.exit(main())
