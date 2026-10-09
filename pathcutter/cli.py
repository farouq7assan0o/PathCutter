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
from .diff import compare_snapshots
from .chains import detect_chains
from .safety import assess_fixes, summarize_safety


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
    p_analyze.add_argument("--graph-nodes", type=int, default=6000, metavar="N",
                           help="Max nodes drawn in the HTML attack graph (default 6000)")

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

    # graph - show paths to a specific target
    p_graph = sub.add_parser("graph", help="Show attack paths to a specific target node")
    p_graph.add_argument("input", help="SharpHound ZIP or directory")
    p_graph.add_argument("--target", required=True, help="Target node name (e.g. 'DOMAIN ADMINS')")
    p_graph.add_argument("--top", type=int, default=20, help="Max paths to show")
    p_graph.add_argument("--max-depth", type=int, default=20)
    p_graph.add_argument("--max-paths", type=int, default=10000)

    # diff
    p_diff = sub.add_parser("diff", help="Compare two SharpHound snapshots")
    p_diff.add_argument("old", help="Before snapshot (SharpHound ZIP or directory)")
    p_diff.add_argument("new", help="After snapshot (SharpHound ZIP or directory)")
    p_diff.add_argument("--max-depth", type=int, default=20)
    p_diff.add_argument("--max-paths", type=int, default=10000)
    p_diff.add_argument("--html", action="store_true", help="Generate HTML diff report")
    p_diff.add_argument("-o", "--output", help="Output directory for reports")

    # export (CI/CD)
    p_export = sub.add_parser("export", help="CI/CD-friendly JSON output with threshold gating")
    p_export.add_argument("input", help="SharpHound ZIP or directory")
    p_export.add_argument("--top", type=int, default=10, help="Top N fixes")
    p_export.add_argument("--max-depth", type=int, default=20)
    p_export.add_argument("--max-paths", type=int, default=10000)
    p_export.add_argument("-o", "--output", help="Output JSON file (default: stdout)")
    p_export.add_argument("--fail-above", type=int, default=None, metavar="SCORE",
                           help="Exit non-zero if risk score exceeds this threshold (0-100)")
    p_export.add_argument("--fail-exposure", type=float, default=None, metavar="PCT",
                           help="Exit non-zero if Tier 2 exposure exceeds this percentage")
    p_export.add_argument("--compact", action="store_true", help="Minimal JSON (no indentation)")

    # demo
    p_demo = sub.add_parser("demo", help="Generate a realistic demo AD environment and run full analysis")
    p_demo.add_argument("-o", "--output", default=".", help="Output directory for reports")
    p_demo.add_argument("--size", choices=["small", "medium", "large", "huge"], default="medium",
                         help="Environment size: small (~50 nodes), medium (~200), large (~1000), huge (~12000)")

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
    elif args.command == "graph":
        return _cmd_graph(args)
    elif args.command == "diff":
        return _cmd_diff(args)
    elif args.command == "export":
        return _cmd_export(args)
    elif args.command == "demo":
        return _cmd_demo(args)

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

    # Attack chain detection
    chains = detect_chains(graph, report)
    if chains:
        print(f"\n[!] Attack Chains Detected ({len(chains)}):")
        for chain in chains:
            severity_mark = {"critical": "!!!", "high": "!!", "medium": "!"}.get(chain.severity, "")
            print(f"    [{severity_mark} {chain.severity.upper()}] {chain.chain_type}: {chain.description}")
            if chain.involved_nodes:
                print(f"        Involved: {', '.join(chain.involved_nodes[:5])}")
            print(f"        Fix: {chain.remediation[:120]}")

    choke = find_chokepoints(graph, report, max_fixes=args.top)
    assessments = assess_fixes(graph, choke.fixes) if choke.fixes else []
    if choke.fixes:
        safety = summarize_safety(assessments)

        print(f"\n[*] Top {len(choke.fixes)} Fixes ({choke.elimination_pct:.0f}% path elimination):")
        print(f"    Safety: {safety['safe']} safe, {safety['caution']} caution, {safety['dangerous']} dangerous")
        print(f"    {'#':<4} {'Fix':<50} {'Cut':<8} {'Cumul':<8} {'Safety'}")
        for fix, assessment in zip(choke.fixes, assessments):
            desc = f"{fix.source_name} -> {fix.target_name} [{fix.edge_type}]"
            if len(desc) > 48:
                desc = desc[:45] + "..."
            safety_icon = {"safe": "OK", "caution": "WARN", "dangerous": "RISK"}[assessment.risk_level.value]
            print(f"    {fix.rank:<4} {desc:<50} {fix.paths_eliminated:<8} {fix.cumulative_pct}%{'':<4} {safety_icon}")
            if assessment.warnings:
                for w in assessment.warnings:
                    print(f"         -> {w}")

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
            html = generate_html_report(
                graph, report, posture, node_scores, choke,
                chains=chains, safety=assessments if choke.fixes else None,
                max_graph_nodes=args.graph_nodes,
            )
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


def _cmd_graph(args) -> int:
    """Show attack paths to a specific target node."""
    from .pathfinder import shortest_paths_to_targets

    t0 = time.time()
    print(f"[*] Loading SharpHound data from {args.input}...")
    graph = load_sharphound(args.input)
    print(f"    {graph.node_count} nodes, {graph.edge_count} edges")

    # Find the target node by name (case-insensitive partial match)
    target_name = args.target.upper()
    matches = []
    for node in graph.all_nodes():
        if target_name in node.name.upper():
            matches.append(node)

    if not matches:
        print(f"\n[!] No node matching '{args.target}' found.", file=sys.stderr)
        return 1

    if len(matches) > 1:
        print(f"\n[*] Multiple matches for '{args.target}':")
        for m in matches[:10]:
            print(f"    {m.name} ({m.node_type.value}, T{m.tier})")
        print(f"    Using first match: {matches[0].name}")

    target = matches[0]
    target_ids = {target.object_id}
    print(f"\n[*] Finding paths to {target.name}...")

    report = find_all_paths(graph, target_ids, max_depth=args.max_depth, max_paths=args.max_paths)
    print(f"    {report.total_paths} paths from {report.unique_sources} sources")

    if report.total_paths == 0:
        print("\n[+] No attack paths found to this target.")
        return 0

    print(f"\n[*] Top {min(args.top, report.total_paths)} Shortest Paths:")
    sorted_paths = sorted(report.paths, key=lambda p: p.length)[:args.top]
    for i, path in enumerate(sorted_paths, 1):
        parts = []
        for j, edge in enumerate(path.edges):
            node = graph.get_node(path.nodes[j])
            name = node.display_name if node else path.nodes[j]
            parts.append(f"{name} -[{edge.get('edge_type', '?')}]->")
        parts.append(target.display_name)
        print(f"    {i:>3}. {' '.join(parts)}")

    elapsed = time.time() - t0
    print(f"\n    Completed in {elapsed:.1f}s")
    return 0


def _cmd_diff(args) -> int:
    print(f"[*] Loading BEFORE snapshot: {args.old}")
    graph_before = load_sharphound(args.old)
    print(f"    {graph_before.node_count} nodes, {graph_before.edge_count} edges")

    print(f"[*] Loading AFTER snapshot: {args.new}")
    graph_after = load_sharphound(args.new)
    print(f"    {graph_after.node_count} nodes, {graph_after.edge_count} edges")

    print("[*] Comparing snapshots...")
    result = compare_snapshots(graph_before, graph_after,
                               max_depth=args.max_depth, max_paths=args.max_paths)

    print(f"\n{'=' * 50}")
    print(f"  {result.summary}")
    print(f"  Edges eliminated: {len(result.eliminated_edges)}")
    print(f"  New edges:        {len(result.new_edges)}")
    print(f"{'=' * 50}")

    if result.eliminated_edges:
        print("\n[+] Eliminated edges:")
        for e in result.eliminated_edges[:20]:
            print(f"    {e['source']} -> {e['target']} [{e['type']}]")

    if result.new_edges:
        print("\n[!] New edges (regression):")
        for e in result.new_edges[:20]:
            print(f"    {e['source']} -> {e['target']} [{e['type']}]")

    if args.html:
        from .report import generate_diff_html
        html = generate_diff_html(result, graph_before, graph_after)
        out_dir = Path(args.output) if args.output else None
        if out_dir:
            out_dir.mkdir(parents=True, exist_ok=True)
            path = out_dir / "pathcutter-diff.html"
            path.write_text(html, encoding="utf-8")
            print(f"\n[+] HTML diff report: {path}")
        else:
            print(html)

    return 0


def _cmd_export(args) -> int:
    """CI/CD export: JSON output with optional threshold gating."""
    graph, report = _load_and_analyze(args)
    posture = score_posture(graph, report)
    node_scores = score_nodes(graph, report)
    choke = find_chokepoints(graph, report, max_fixes=args.top)
    chains = detect_chains(graph, report)
    assessments = assess_fixes(graph, choke.fixes) if choke.fixes else []

    snapshot = _build_json_snapshot(graph, report, posture, node_scores, choke)
    snapshot["chains"] = [
        {"type": c.chain_type, "severity": c.severity, "description": c.description,
         "mitre": c.mitre, "path_count": c.path_count}
        for c in chains
    ]

    # Threshold gating
    gate_failed = False
    gates = {}
    if args.fail_above is not None:
        passed = posture.score <= args.fail_above
        gates["score"] = {"threshold": args.fail_above, "actual": posture.score, "passed": passed}
        if not passed:
            gate_failed = True
    if args.fail_exposure is not None:
        actual = round(posture.exposure_pct, 1)
        passed = actual <= args.fail_exposure
        gates["exposure"] = {"threshold": args.fail_exposure, "actual": actual, "passed": passed}
        if not passed:
            gate_failed = True

    if gates:
        snapshot["gates"] = gates
        snapshot["gate_passed"] = not gate_failed

    indent = None if args.compact else 2
    output = json.dumps(snapshot, indent=indent)

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(output, encoding="utf-8")
        print(f"[+] Export: {out_path}", file=sys.stderr)
    else:
        print(output)

    if gate_failed:
        failed_gates = [k for k, v in gates.items() if not v["passed"]]
        print(f"[!] Gate FAILED: {', '.join(failed_gates)}", file=sys.stderr)
        return 2

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


def _cmd_demo(args) -> int:
    """Generate a realistic demo AD environment and run full analysis."""
    import random
    from .graph import AttackGraph, ADNode, ADEdge, NodeType

    sizes = {"small": (50, 12, 8), "medium": (200, 30, 20), "large": (1000, 80, 50), "huge": (9000, 400, 2600)}
    n_users, n_groups, n_computers = sizes[args.size]

    print(f"[*] Generating demo AD environment ({args.size}: ~{n_users + n_groups + n_computers} objects)...")
    random.seed(42)
    domain = "MEGACORP.LOCAL"
    g = AttackGraph()

    # Tier 0 groups
    t0_groups = [
        ("S-DA", f"DOMAIN ADMINS@{domain}", NodeType.GROUP),
        ("S-EA", f"ENTERPRISE ADMINS@{domain}", NodeType.GROUP),
        ("S-SA", f"SCHEMA ADMINS@{domain}", NodeType.GROUP),
        ("S-BA", f"ADMINISTRATORS@{domain}", NodeType.GROUP),
    ]
    for sid, name, nt in t0_groups:
        g.add_node(ADNode(sid, name, nt, domain))

    # Tier 0 users
    admin = ADNode("S-500", f"ADMINISTRATOR@{domain}", NodeType.USER, domain)
    krbtgt = ADNode("S-502", f"KRBTGT@{domain}", NodeType.USER, domain)
    g.add_node(admin)
    g.add_node(krbtgt)
    g.add_edge(ADEdge("S-500", "S-DA", "MemberOf"))

    # Domain controllers
    dcs = []
    for i in range(max(2, n_computers // 20)):
        sid = f"S-DC{i}"
        name = f"DC{i+1:02d}.{domain}"
        g.add_node(ADNode(sid, name, NodeType.COMPUTER, domain))
        g.add_edge(ADEdge(sid, "S-DA", "MemberOf"))
        dcs.append(sid)

    # Organizational groups
    first_names = ["Engineering", "Finance", "HR", "Sales", "Marketing", "Legal", "IT",
                   "Operations", "Security", "DevOps", "Support", "Research"]
    groups = []
    for i in range(n_groups):
        sid = f"S-G{i}"
        dept = first_names[i % len(first_names)]
        suffix = f" {i // len(first_names) + 1}" if i >= len(first_names) else ""
        name = f"{dept.upper()}{suffix}@{domain}"
        g.add_node(ADNode(sid, name, NodeType.GROUP, domain))
        groups.append(sid)

    # Privileged groups
    priv_groups = []
    for name in ["SERVER ADMINS", "HELPDESK", "SERVICE ACCOUNTS", "BACKUP OPERATORS",
                  "DB ADMINS", "EXCHANGE ADMINS"]:
        sid = f"S-PG-{name.replace(' ', '')}"
        g.add_node(ADNode(sid, f"{name}@{domain}", NodeType.GROUP, domain))
        priv_groups.append(sid)

    # Users
    user_names = ["JSMITH", "BWILSON", "AGARCIA", "MCHEN", "DJONES", "KPATEL",
                  "LGREEN", "THARRIS", "RMARTIN", "CWILLIAMS", "NLEE", "PHALL",
                  "JDAVIS", "MBROWN", "KTAYLOR"]
    users = []
    for i in range(n_users):
        sid = f"S-U{i}"
        if i < len(user_names):
            name = f"{user_names[i]}@{domain}"
        else:
            name = f"USER{i:03d}@{domain}"
        props = {}
        if random.random() < 0.03:
            props["dontreqpreauth"] = True
        g.add_node(ADNode(sid, name, NodeType.USER, domain, properties=props))
        users.append(sid)
        # Assign to a group
        g.add_edge(ADEdge(sid, random.choice(groups), "MemberOf"))
        if random.random() < 0.15:
            g.add_edge(ADEdge(sid, random.choice(groups), "MemberOf"))

    # Service accounts
    svc_accounts = []
    for name in ["SVC_SQL", "SVC_BACKUP", "SVC_WEB", "SVC_EXCHANGE", "SVC_SCOM",
                  "SVC_SCCM", "SVC_ADFS", "SVC_WSUS"]:
        sid = f"S-SVC-{name}"
        g.add_node(ADNode(sid, f"{name}@{domain}", NodeType.USER, domain))
        svc_accounts.append(sid)
        g.add_edge(ADEdge(sid, random.choice(priv_groups), "MemberOf"))

    # Admin accounts
    admin_accounts = []
    for i in range(min(8, n_users // 10)):
        name = user_names[i] if i < len(user_names) else f"USER{i:03d}"
        sid = f"S-ADM{i}"
        g.add_node(ADNode(sid, f"ADMIN.{name}@{domain}", NodeType.USER, domain))
        admin_accounts.append(sid)

    # Computers (servers + workstations)
    servers = []
    workstations = []
    for i in range(n_computers):
        sid = f"S-C{i}"
        if i < n_computers // 4:
            name = f"SRV{i+1:02d}.{domain}"
            servers.append(sid)
        else:
            name = f"WS{i+1:03d}.{domain}"
            workstations.append(sid)
        g.add_node(ADNode(sid, name, NodeType.COMPUTER, domain))

    # Attack edges - realistic patterns

    # Helpdesk has ForceChangePassword on many users
    for u in random.sample(users, min(len(users), n_users // 3)):
        g.add_edge(ADEdge(priv_groups[1], u, "ForceChangePassword"))

    # Server admins have AdminTo on servers
    for s in servers:
        g.add_edge(ADEdge(priv_groups[0], s, "AdminTo"))

    # Some admin accounts in DA
    for adm in admin_accounts[:2]:
        g.add_edge(ADEdge(adm, "S-DA", "MemberOf"))

    # Service accounts with dangerous permissions
    g.add_edge(ADEdge(svc_accounts[0], dcs[0], "SQLAdmin"))
    g.add_edge(ADEdge(svc_accounts[1], "S-DA", "GenericAll"))
    if len(svc_accounts) > 2:
        g.add_edge(ADEdge(svc_accounts[2], dcs[0], "AllowedToDelegate"))

    # ACL abuse paths
    edge_types = ["GenericAll", "GenericWrite", "WriteDacl", "WriteOwner",
                  "AddMember", "ForceChangePassword", "WriteSPN"]
    for _ in range(n_users // 5):
        src = random.choice(groups + priv_groups)
        tgt = random.choice(svc_accounts + admin_accounts + priv_groups)
        if src != tgt:
            g.add_edge(ADEdge(src, tgt, random.choice(edge_types)))

    # Shadow credentials
    for _ in range(max(1, n_users // 50)):
        src = random.choice(users + svc_accounts)
        tgt = random.choice(admin_accounts + svc_accounts)
        if src != tgt:
            g.add_edge(ADEdge(src, tgt, "WriteKeyCredentialLink"))

    # Sessions
    for u in random.sample(users, min(len(users), n_users // 4)):
        g.add_edge(ADEdge(u, random.choice(workstations + servers), "HasSession"))
    for adm in admin_accounts:
        g.add_edge(ADEdge(adm, random.choice(servers), "HasSession"))
        g.add_edge(ADEdge(adm, random.choice(servers), "AdminTo"))

    # RDP/PSRemote
    for _ in range(n_users // 10):
        g.add_edge(ADEdge(random.choice(users), random.choice(servers), random.choice(["CanRDP", "CanPSRemote"])))

    # LAPS/gMSA
    for pg in priv_groups[:2]:
        g.add_edge(ADEdge(pg, random.choice(servers), "ReadLAPSPassword"))
    g.add_edge(ADEdge(random.choice(users), random.choice(svc_accounts), "ReadGMSAPassword"))

    # Group nesting
    for i in range(len(groups) - 1):
        if random.random() < 0.2:
            g.add_edge(ADEdge(groups[i], groups[i + 1], "MemberOf"))

    g.classify_tiers()
    summary = g.summary()
    print(f"    {g.node_count} nodes, {g.edge_count} edges")
    print(f"    Tier 0: {summary['tier_0_count']} | Tier 1: {summary['tier_1_count']} | Tier 2: {summary['tier_2_count']}")

    # Run full analysis
    print("[*] Running full analysis...")
    report = find_all_paths(g, g.tier0_nodes, max_depth=20, max_paths=10000)
    print(f"    {report.total_paths} paths from {report.unique_sources} sources")

    posture = score_posture(g, report)
    node_scores = score_nodes(g, report)
    chains = detect_chains(g, report)
    choke = find_chokepoints(g, report, max_fixes=10)

    print(f"\n[*] Risk Score: {posture.score}/100 (Grade: {posture.grade})")
    print(f"    Exposure: {posture.exposure_pct:.1f}% of Tier 2 can reach Tier 0")

    if chains:
        print(f"\n[!] {len(chains)} attack chains detected")

    if choke.fixes:
        print(f"\n[*] Top fixes: {len(choke.fixes)} fixes eliminate {choke.elimination_pct:.0f}% of paths")

    # Generate HTML
    from .report import generate_html_report
    assessments = assess_fixes(g, choke.fixes) if choke.fixes else None
    html = generate_html_report(g, report, posture, node_scores, choke,
                                chains=chains, safety=assessments)
    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "pathcutter-demo.html"
    path.write_text(html, encoding="utf-8")
    print(f"\n[+] Demo report: {path}")
    print(f"    Open in a browser to explore the interactive dashboard")

    return 0


if __name__ == "__main__":
    sys.exit(main())
