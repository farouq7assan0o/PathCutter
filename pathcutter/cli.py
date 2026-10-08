"""Pathcutter CLI - AD Attack Path Risk Engine."""
from __future__ import annotations

import argparse
import sys

from . import __version__


def main():
    parser = argparse.ArgumentParser(
        prog="pathcutter",
        description="Pathcutter - AD Attack Path Risk Engine. Finds attack paths to Domain Admin and tells you exactly what to fix first.",
    )
    parser.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command")

    p_analyze = sub.add_parser("analyze", help="Analyze SharpHound export for attack paths")
    p_analyze.add_argument("input", help="SharpHound ZIP or directory")
    p_analyze.add_argument("-o", "--output", help="Output directory (default: current)")
    p_analyze.add_argument("--html", action="store_true", help="Generate HTML dashboard")
    p_analyze.add_argument("--json", action="store_true", help="Generate JSON snapshot")
    p_analyze.add_argument("--markdown", action="store_true", help="Generate Markdown report")
    p_analyze.add_argument("--top", type=int, default=10, help="Number of top fixes to show (default: 10)")
    p_analyze.add_argument("--max-depth", type=int, default=20, help="Maximum path depth (default: 20)")

    p_diff = sub.add_parser("diff", help="Compare two snapshots for posture drift")
    p_diff.add_argument("old", help="Path to older snapshot JSON")
    p_diff.add_argument("new", help="Path to newer snapshot JSON")
    p_diff.add_argument("-o", "--output", help="Save diff report to file")

    p_fix = sub.add_parser("fix", help="Generate remediation script for top N fixes")
    p_fix.add_argument("snapshot", help="Path to snapshot JSON")
    p_fix.add_argument("--top", type=int, default=5, help="Number of top fixes (default: 5)")
    p_fix.add_argument("-o", "--output", help="Output PowerShell script path")

    p_score = sub.add_parser("score", help="Quick risk score without full report")
    p_score.add_argument("input", help="SharpHound ZIP or directory")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(0)

    print(f"[*] Pathcutter v{__version__}")
    print(f"[!] Module not yet implemented: {args.command}")
    print("[*] See CLAUDE.md for build plan and priority order.")
    sys.exit(1)


if __name__ == "__main__":
    main()
