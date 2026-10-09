"""CLI handlers for `pathcutter snapshot` and `pathcutter check`.

Exit codes (stable, for CI):
  0  pass (or review/block when --fail-on is looser)
  1  input error: bad change syntax, unknown object, unreadable baseline or policy
  2  blocked by policy
  3  needs review (only when --fail-on review)
"""
from __future__ import annotations

import datetime as dt
import sys
from pathlib import Path

from .changes import ChangeSetError, VERB_HELP, load_changes, resolve_changes
from .check_html import render_html
from .check_report import render_json, render_markdown, render_sarif, render_text
from .impact import analyze_impact
from .policy import PolicyError, evaluate, load_policy, resolve_extra_tier0
from .snapshot import SnapshotError, load_baseline, save_snapshot

EXIT_OK, EXIT_INPUT, EXIT_BLOCK, EXIT_REVIEW = 0, 1, 2, 3


def add_parsers(sub) -> None:
    p = sub.add_parser("snapshot", help="Save a reusable baseline (.pcsnap) from a SharpHound export")
    p.add_argument("input", help="SharpHound ZIP or directory")
    p.add_argument("-o", "--output", default="baseline.pcsnap", help="Snapshot file to write")
    p.add_argument("--collected", metavar="YYYY-MM-DD", help="Collection date, if different from the file dates")
    p.add_argument("--also", action="append", default=[], metavar="PATH",
                   help="Another collection of the same environment (repeatable): objects are unioned and sessions record how often they were seen")

    c = sub.add_parser(
        "check", help="Check proposed AD changes for new attack paths to Tier 0 BEFORE they are applied",
        formatter_class=__import__("argparse").RawDescriptionHelpFormatter,
        epilog="Change syntax (one per line in a --changes file, or repeat --change):\n" + VERB_HELP)
    c.add_argument("--baseline", required=True, help="Baseline: a .pcsnap snapshot or a SharpHound ZIP/directory")
    c.add_argument("--changes", action="append", default=[], metavar="FILE",
                   help="Change file (.changes DSL, .json, or .ps1). Repeatable.")
    c.add_argument("--change", action="append", default=[], metavar="LINE",
                   help='One change in DSL form, e.g. --change "add-member alice HELPDESK". Repeatable.')
    c.add_argument("--powershell", action="append", default=[], metavar="FILE",
                   help="Extract AD changes from a PowerShell script. Repeatable.")
    from .extractors import EXTRACTORS
    for name, ex in EXTRACTORS.items():
        if name != "powershell":
            c.add_argument(f"--{name}", action="append", default=[], metavar="FILE_OR_DIR", help=f"Extract AD changes from {ex.describe}. Repeatable.")
    c.add_argument("--policy", metavar="FILE", help="Policy JSON (thresholds, extra Tier 0 assets, waivers)")
    c.add_argument("--on-unresolved", choices=["error", "assume-new"], default="error",
                   help="What to do with a name not in the baseline (default: error)")
    c.add_argument("--fail-on", choices=["block", "review", "never"], default="block",
                   help="Exit non-zero on this verdict or worse (default: block)")
    c.add_argument("--html", metavar="FILE", help="Write the HTML review page")
    c.add_argument("--json", dest="json_out", metavar="FILE", help="Write machine-readable JSON")
    c.add_argument("--markdown", metavar="FILE", help="Write a Markdown summary (for PR comments)")
    c.add_argument("--sarif", metavar="FILE", help="Write SARIF 2.1.0 (GitHub code scanning annotations)")
    c.add_argument("--detections", metavar="DIR",
                   help="Also write detections (Sigma/SPL/KQL) that watch the risk this change set creates or keeps open")
    c.add_argument("-q", "--quiet", action="store_true", help="Do not print the text report")
    c.add_argument("--max-depth", type=int, default=20)
    c.add_argument("--max-paths", type=int, default=10000)
    c.add_argument("--today", metavar="YYYY-MM-DD", help=__import__("argparse").SUPPRESS)


def _err(msg: str) -> None:
    print(f"[!] {msg}", file=sys.stderr)


def cmd_snapshot(args) -> int:
    print(f"[*] Loading SharpHound data from {args.input}...", file=sys.stderr)
    try:
        from .ingest import load_sharphound
        graph = load_sharphound([args.input, *args.also] if args.also else args.input)
        collected = dt.date.fromisoformat(args.collected) if args.collected else None
        meta = save_snapshot(graph, args.output, source=args.input, collected=collected)
    except (ValueError, OSError) as exc:
        _err(str(exc))
        return EXIT_INPUT
    print(f"[+] Snapshot: {args.output} ({meta['nodes']:,} nodes, {meta['edges']:,} edges, "
          f"{meta['bytes'] / 1024:.0f} KiB, collected {meta['collected']})")
    return EXIT_OK


def _write(path: str, text: str) -> None:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text, encoding="utf-8")
    print(f"[+] Wrote {out}", file=sys.stderr)


_RISK_KINDS = ("TIER0_PROMOTION", "NEW_EXPOSURE", "COMBINED_EFFECT", "PATH_SHORTENED")


def _write_detections(graph, resolved, report, out_dir: str, extra_ids) -> None:
    """Compensating detections: watch every attack edge on the paths this change set creates or leaves open."""
    from .changes import apply_change
    from .detect_pack import build_pack, write_pack
    after = graph.clone()
    after.retier(extra_ids or None)
    for rc in resolved:
        apply_change(after, rc)
    after.retier(extra_ids or None)
    ids = {n.object_id for n in after.all_nodes()}
    counts: dict[tuple, int] = {}
    for f in report.findings:
        if f.kind not in _RISK_KINDS or f.superseded:
            continue
        for path in f.paths:
            for a, b in zip(path, path[1:]):
                edge = a.get("edge")
                if edge and edge not in ("MemberOf", "Contains") and a["id"] in ids and b["id"] in ids:
                    counts[(a["id"], b["id"], edge)] = counts.get((a["id"], b["id"], edge), 0) + 1
    points = [{"source_id": s, "target_id": t, "edge_type": e, "paths": n} for (s, t, e), n in
              sorted(counts.items(), key=lambda kv: -kv[1])]
    pack = build_pack(after, points, {"paths_total": "n/a", "paths_residual": "n/a", "assumed_fixed": [],
                                      "monitor_points": len(points), "coverage_pct": "the paths in this report"})
    files = write_pack(pack, out_dir)
    print(f"[+] {len(pack.rules)} compensating detection rule(s) in {out_dir} ({len(files)} files); "
          f"read {out_dir}/prerequisites.md first", file=sys.stderr)


def cmd_check(args) -> int:
    today = dt.date.fromisoformat(args.today) if args.today else dt.date.today()
    try:
        policy = load_policy(args.policy)
        from .extractors import EXTRACTORS
        extra = {n: getattr(args, n) for n in EXTRACTORS if n != "powershell" and getattr(args, n, None)}
        specs, warns = load_changes(args.changes, args.change, args.powershell, extra)
        graph, base_info = load_baseline(args.baseline, today)
    except (ChangeSetError, PolicyError) as exc:
        for line in exc.errors:
            _err(line)
        return EXIT_INPUT
    except SnapshotError as exc:
        _err(str(exc))
        return EXIT_INPUT
    if not specs and not warns:
        _err("no changes given: use --changes FILE, --change \"...\", --powershell, --terraform, --ansible or --dsc")
        return EXIT_INPUT

    resolved, errors = resolve_changes(graph, specs, args.on_unresolved)
    extra_ids, extra_errors = resolve_extra_tier0(graph, policy.extra_tier0)
    errors += extra_errors
    if errors:
        for line in errors:
            _err(line)
        _err(f"{len(errors)} problem(s); nothing was analyzed. A change that cannot be resolved cannot be judged.")
        return EXIT_INPUT

    report = analyze_impact(graph, resolved, extra_tier0=extra_ids or None, unmodeled=warns,
                            max_depth=args.max_depth, max_paths=args.max_paths)
    report.baseline = base_info
    evaluate(report, policy, resolved, today)

    if not args.quiet:
        print(render_text(report))
    if args.json_out:
        _write(args.json_out, render_json(report))
    if args.markdown:
        _write(args.markdown, render_markdown(report))
    if args.sarif:
        _write(args.sarif, render_sarif(report))
    if args.html:
        _write(args.html, render_html(report))

    if args.detections:
        _write_detections(graph, resolved, report, args.detections, extra_ids)

    if args.fail_on == "never":
        return EXIT_OK
    if report.verdict == "block":
        return EXIT_BLOCK
    if report.verdict == "review" and args.fail_on == "review":
        return EXIT_REVIEW
    return EXIT_OK
