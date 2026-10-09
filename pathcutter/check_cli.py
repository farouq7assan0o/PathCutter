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
    c.add_argument("--policy", metavar="FILE", help="Policy JSON (thresholds, extra Tier 0 assets, waivers)")
    c.add_argument("--on-unresolved", choices=["error", "assume-new"], default="error",
                   help="What to do with a name not in the baseline (default: error)")
    c.add_argument("--fail-on", choices=["block", "review", "never"], default="block",
                   help="Exit non-zero on this verdict or worse (default: block)")
    c.add_argument("--html", metavar="FILE", help="Write the HTML review page")
    c.add_argument("--json", dest="json_out", metavar="FILE", help="Write machine-readable JSON")
    c.add_argument("--markdown", metavar="FILE", help="Write a Markdown summary (for PR comments)")
    c.add_argument("--sarif", metavar="FILE", help="Write SARIF 2.1.0 (GitHub code scanning annotations)")
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
        graph = load_sharphound(args.input)
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


def cmd_check(args) -> int:
    today = dt.date.fromisoformat(args.today) if args.today else dt.date.today()
    try:
        policy = load_policy(args.policy)
        specs, warns = load_changes(args.changes, args.change, args.powershell)
        graph, base_info = load_baseline(args.baseline, today)
    except (ChangeSetError, PolicyError) as exc:
        for line in exc.errors:
            _err(line)
        return EXIT_INPUT
    except SnapshotError as exc:
        _err(str(exc))
        return EXIT_INPUT
    if not specs and not warns:
        _err("no changes given: use --changes FILE, --change \"...\" or --powershell FILE")
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

    if args.fail_on == "never":
        return EXIT_OK
    if report.verdict == "block":
        return EXIT_BLOCK
    if report.verdict == "review" and args.fail_on == "review":
        return EXIT_REVIEW
    return EXIT_OK
