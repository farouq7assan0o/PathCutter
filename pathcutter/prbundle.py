"""Fix-as-code: turn the remediation plan into a pull-request bundle a reviewer can open and PathCutter can re-verify.

PathCutter stays offline and never touches your git remote or credentials. It writes a self-contained bundle:

  remediation.ps1   the fix script (same as `pathcutter fix`), each fix carrying a machine-readable `# pc: revoke ...`
  fixes.changes     those revokes as the change DSL, so `pathcutter check --changes fixes.changes` re-verifies the effect
  PR.md             the pull-request / merge-request description: what it removes, per-fix safety, how to verify, rollback
  apply.sh          creates a branch, commits the files, and opens the PR with the reviewer's own `gh` (GitHub)
  apply.ps1         the same for Windows / PowerShell
  (--pr-platform gitlab uses `glab` instead of `gh`; --pr-platform none omits the opener)

The apply script runs with the reviewer's authentication, inside their repo. It opens the PR; a human merges it. The PR
description tells them to run `pathcutter check` against the latest collection first, and to re-collect and re-run after
merge to confirm the paths are gone.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from .changes import _ENDPOINTS
from .edges import EdgeCategory, get_edge_type
from .remediate import RemediationPlan

_SAFE_LABEL = {"safe": "safe", "caution": "caution - review", "dangerous": "DANGEROUS - do not merge unreviewed"}

# edge types the `revoke` change verb can express (so `pathcutter check --changes` can re-verify them)
_DSL_REVOCABLE = {"MemberOf", "AdminTo", "HasSession", "CanRDP", "CanPSRemote", "DCSync",
                  "AllowedToDelegate", "AllowedToAct", "SQLAdmin"}


def _change_line(plan_fix, graph) -> str | None:
    """A `revoke` DSL line for one fix in the direction the change grammar expects, or None if it cannot be expressed.

    Most edges revoke as `revoke <source> <Edge> <target>`. A few (notably HasSession) constrain the object end to a
    specific type, so the principal/object are the other way round; _ENDPOINTS drives that without hardcoding."""
    edge = plan_fix.edge_type
    et = get_edge_type(edge)
    revocable = edge in _DSL_REVOCABLE or (et is not None and et.category == EdgeCategory.ACL)
    if not revocable or graph is None:
        return None
    s, t = graph.get_node(plan_fix.source_id), graph.get_node(plan_fix.target_id)
    obj_allowed = _ENDPOINTS.get(edge, (None, None))[1]
    if obj_allowed is None or (t is not None and t.node_type in obj_allowed):
        prin, obj = plan_fix.source_name, plan_fix.target_name
    elif s is not None and s.node_type in obj_allowed:
        prin, obj = plan_fix.target_name, plan_fix.source_name        # object end is type-constrained; swap
    else:
        return None
    return f'revoke "{prin}" {edge} "{obj}"'


def _slug_date() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d")


def _changes_dsl(plan: RemediationPlan, graph) -> tuple[str, int]:
    """The fixes as the change DSL, so `pathcutter check` can re-verify them. Returns (text, number_of_verifiable_lines).

    A fix whose edge the DSL cannot express (e.g. an ADCS escalation fixed on the template) is written as a comment, so
    the file always resolves cleanly and the reviewer can see which fixes are confirmed by re-collection instead."""
    out = ["# PathCutter proposed remediation, as change lines. Verify against your latest baseline:",
           "#   pathcutter check --baseline baseline.pcsnap --changes fixes.changes",
           "# A safe remediation REMOVES exposure, so check reports a risk reduction, not new exposure.", ""]
    verifiable = 0
    for fix in plan.fixes:
        line = _change_line(fix, graph)
        if line:
            out.append(line)
            verifiable += 1
        else:
            out.append(f'# (not expressible as a change line; verify by re-collection) {fix.source_name} '
                       f'-{fix.edge_type}-> {fix.target_name}')
    return "\n".join(out) + "\n", verifiable


def _pr_markdown(plan: RemediationPlan, safety: list | None, baseline: str, title: str, verifiable: int) -> str:
    sev = {}
    if safety:
        sev = {f.rank: s for f, s in zip(plan.fixes, safety)}
    lines = [
        f"# {title}",
        "",
        f"Proposed by PathCutter. These {len(plan.fixes)} change(s) remove **{plan.paths_eliminated} of "
        f"{plan.total_paths}** attack paths to Tier 0 ({plan.elimination_pct:.0f}%), highest-impact first.",
        "",
        "| # | Fix | Edge | Paths cut | Cumulative | Safety |",
        "|---|-----|------|-----------|------------|--------|",
    ]
    for fix in plan.fixes:
        s = sev.get(fix.rank)
        label = _SAFE_LABEL.get(s.risk_level.value, "") if s else ""
        lines.append(f"| {fix.rank} | {fix.source_name} -> {fix.target_name} | {fix.edge_type} | "
                     f"{fix.paths_eliminated} | {fix.cumulative_pct}% | {label} |")
    if safety:
        notes = [(f.rank, w) for f, s in zip(plan.fixes, safety) for w in s.warnings]
        if notes:
            lines += ["", "## Review notes", ""]
            lines += [f"- Fix #{r}: {w}" for r, w in notes]
    if plan.warnings:
        lines += ["", "## Warnings", ""] + [f"- {w}" for w in plan.warnings]
    lines += ["", "## Verify before merge", ""]
    if verifiable:
        lines += [
            f"{verifiable} of {len(plan.fixes)} fix(es) re-verify directly against your latest baseline - the gate "
            "should report a **risk reduction**, not new exposure:",
            "```", f"pathcutter check --baseline {baseline} --changes fixes.changes", "```",
        ]
    if verifiable < len(plan.fixes):
        lines.append(f"The remaining {len(plan.fixes) - verifiable} fix(es) are not expressible as a change line "
                     "(e.g. an ADCS escalation fixed on the template); confirm them by re-collecting and re-running "
                     "`pathcutter analyze` after merge.")
    lines += [
        "", "## After merge", "",
        "Run the script in a change window, then re-collect and re-run `pathcutter analyze` to confirm the paths are gone.",
        "Export the ACLs first (see the ROLLBACK section of `remediation.ps1`) so the change can be reverted.",
        "",
        "_Generated by PathCutter. Review every fix: removing a right can break a legitimate dependency._",
    ]
    return "\n".join(lines) + "\n"


def _apply_sh(platform: str, title: str, branch: str, base: str) -> str:
    opener = {
        "github": f'gh pr create --base "$BASE" --head "$BRANCH" --title "$TITLE" --body-file PR.md',
        "gitlab": f'glab mr create --source-branch "$BRANCH" --target-branch "$BASE" --title "$TITLE" --description "$(cat PR.md)"',
        "none": 'echo "Branch pushed. Open the PR manually using PR.md as the description."',
    }[platform]
    return f"""#!/usr/bin/env bash
# Open the remediation PR with your own credentials, from inside your target git repository.
# Run this from the repo you want the PR in; it copies the bundle files in, commits, pushes and opens the PR.
set -euo pipefail
BRANCH="${{BRANCH:-{branch}}}"
BASE="${{BASE:-{base}}}"
TITLE="${{TITLE:-{title}}}"
DEST="${{DEST:-pathcutter-remediation}}"
HERE="$(cd "$(dirname "$0")" && pwd)"

git switch -c "$BRANCH"
mkdir -p "$DEST"
cp "$HERE/remediation.ps1" "$HERE/fixes.changes" "$HERE/PR.md" "$DEST/"
git add "$DEST"
git commit -m "$TITLE"
git push -u origin "$BRANCH"
{opener}
"""


def _apply_ps1(platform: str, title: str, branch: str, base: str) -> str:
    opener = {
        "github": 'gh pr create --base $Base --head $Branch --title $Title --body-file PR.md',
        "gitlab": 'glab mr create --source-branch $Branch --target-branch $Base --title $Title --description (Get-Content PR.md -Raw)',
        "none": 'Write-Host "Branch pushed. Open the PR manually using PR.md as the description."',
    }[platform]
    return f"""# Open the remediation PR with your own credentials, from inside your target git repository.
$ErrorActionPreference = "Stop"
$Branch = if ($env:BRANCH) {{ $env:BRANCH }} else {{ "{branch}" }}
$Base   = if ($env:BASE)   {{ $env:BASE }}   else {{ "{base}" }}
$Title  = if ($env:TITLE)  {{ $env:TITLE }}  else {{ "{title}" }}
$Dest   = if ($env:DEST)   {{ $env:DEST }}   else {{ "pathcutter-remediation" }}
$Here   = Split-Path -Parent $MyInvocation.MyCommand.Path

git switch -c $Branch
New-Item -ItemType Directory -Force -Path $Dest | Out-Null
Copy-Item "$Here\\remediation.ps1","$Here\\fixes.changes","$Here\\PR.md" $Dest
git add $Dest
git commit -m $Title
git push -u origin $Branch
{opener}
"""


def write_pr_bundle(plan: RemediationPlan, out_dir, *, graph=None, safety: list | None = None,
                    baseline: str = "baseline.pcsnap", platform: str = "github", title: str | None = None,
                    branch: str | None = None, base: str = "main", include_rollback: bool = True) -> list[str]:
    """Write the fix-as-code bundle to out_dir and return the file paths written."""
    if platform not in ("github", "gitlab", "none"):
        raise ValueError(f"unknown PR platform '{platform}' (use github, gitlab or none)")
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    title = title or f"PathCutter: remove {plan.paths_eliminated} attack path(s) to Tier 0 ({len(plan.fixes)} fix(es))"
    branch = branch or f"pathcutter/remediate-{_slug_date()}"
    written = []

    def _w(name: str, text: str, mode: int | None = None) -> None:
        p = out / name
        p.write_text(text, encoding="utf-8", newline="\n")
        if mode is not None:
            try:
                p.chmod(mode)
            except OSError:
                pass
        written.append(str(p))

    changes_text, verifiable = _changes_dsl(plan, graph)
    _w("remediation.ps1", plan.powershell_script(include_rollback=include_rollback))
    _w("fixes.changes", changes_text)
    _w("PR.md", _pr_markdown(plan, safety, baseline, title, verifiable))
    _w("apply.sh", _apply_sh(platform, title, branch, base), mode=0o755)
    _w("apply.ps1", _apply_ps1(platform, title, branch, base))
    return written
