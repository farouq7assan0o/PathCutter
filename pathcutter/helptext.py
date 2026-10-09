"""All help text in one place, so `pathcutter -h` stays the single front door to the tool."""
from __future__ import annotations

from .changes import VERB_HELP

TOP = """\
PathCutter - Active Directory attack path engine.
Find the few changes that cut the most paths to Domain Admin, and stop new ones before they ship.

START HERE (no SharpHound data needed)
  pathcutter demo --size medium --snapshot demo.pcsnap
  pathcutter check --baseline demo.pcsnap --change 'add-member jsmith "BACKUP OPERATORS"' --html review.html

COMMANDS
  Analyze an existing environment                       (input: a SharpHound ZIP or directory)
    analyze    full analysis: risk score, attack paths, prioritised fixes, HTML report
    score      quick risk score only
    graph      every attack path to one target, e.g. --target "DOMAIN ADMINS"
    fix        a PowerShell remediation script for the top N fixes (with rollback notes)
    diff       compare two collections: did the fixes work, did anything regress?
    export     JSON + exit code for CI gating on score / exposure thresholds

  Trust the data / share it
    doctor     is this export complete enough to trust? lists blind spots and the collector flags that fix them
    anonymize  a shareable copy of your export: pseudonyms, no free text, identical attack paths

  Gate changes BEFORE they ship
    snapshot   save a reusable baseline (.pcsnap) from a SharpHound collection
    check      will these proposed AD changes open a path to Tier 0?   exit 2 = blocked
    detect     detections (Sigma/SPL/KQL) for the attack paths you have NOT fixed
    syntax     full reference: change language, PowerShell coverage, edge types, policy

  Try and learn
    demo       generate a realistic lab environment (and a baseline) to experiment with
    help       help <command> | help syntax [topic]

TYPICAL WORKFLOW
  collect with SharpHound --> pathcutter snapshot export.zip -o baseline.pcsnap       (nightly)
  a ticket / script / pull request proposes AD changes
     --> pathcutter check --baseline baseline.pcsnap --changes ad-changes/ --policy policy.json
     --> PASS (exit 0)   REVIEW (exit 3 with --fail-on review)   BLOCK (exit 2)
  fix what the report says to fix first, re-run, ship.
  for the paths you cannot fix:  pathcutter detect baseline.pcsnap --assume-fixed 5 -o detections/

EXIT CODES   0 ok | 1 could not run (bad input) | 2 blocked / gate failed | 3 needs review

MORE   pathcutter <command> -h          options and examples for one command
       pathcutter syntax                how to write changes, supported PowerShell, edge names
       docs/ad-change-gate.md           the full guide
"""

ANALYZE = """\
Examples:
  pathcutter analyze export.zip --html -o ./report --top 10
  pathcutter analyze ./sharphound-dir --json --markdown -o ./out
  pathcutter analyze export.zip --html --graph-nodes 3000 -o ./report     # smaller graph for huge domains
"""

SCORE = """\
Example:
  pathcutter score export.zip
"""

FIX = """\
Examples:
  pathcutter fix export.zip --top 10 -o remediation.ps1
  pathcutter check --baseline baseline.pcsnap --powershell remediation.ps1     # verify the script BEFORE running it
The script is annotated so `check` can predict its exact effect.
"""

GRAPH = """\
Examples:
  pathcutter graph export.zip --target "DOMAIN ADMINS"
  pathcutter graph export.zip --target "KINGSLANDING" --top 5
"""

DIFF = """\
Examples:
  pathcutter diff before.zip after.zip
  pathcutter diff before.zip after.zip --html -o ./report
"""

EXPORT = """\
Examples:
  pathcutter export export.zip --fail-above 50 -o report.json          # exit 2 if the risk score is above 50
  pathcutter export export.zip --fail-exposure 30 --compact            # exit 2 if >30% of Tier 2 reaches Tier 0
"""

SNAPSHOT = """\
Examples:
  pathcutter snapshot export.zip -o baseline.pcsnap
  pathcutter snapshot ./sharphound-dir -o baseline.pcsnap --collected 2026-06-01
A snapshot holds your full AD topology: store it like the sensitive data it is (it is git-ignored by default).
"""

DEMO = """\
Examples:
  pathcutter demo --size medium -o ./demo --snapshot demo.pcsnap     # synthetic MEGACORP environment
  pathcutter demo --lab goad-sevenkingdoms -o ./goad --snapshot goad.pcsnap
      the GOAD sevenkingdoms.local lab rebuilt as SharpHound JSON, with its documented ACL attack chain
"""

CHECK = """\
BUILD A COMMAND IN THREE STEPS
  1. a baseline     --baseline baseline.pcsnap          (from `pathcutter snapshot`) or a SharpHound ZIP/dir
  2. the changes    --changes ad-changes/               a file or a directory of .changes / .json / .ps1
                    --change "add-member alice HELPDESK"   one change inline (repeatable)
                    --powershell deploy.ps1              extract the changes a script would make
  3. what to emit   --html review.html --markdown comment.md --sarif out.sarif --json out.json

EXAMPLES
  pathcutter check --baseline baseline.pcsnap --change "add-member alice HELPDESK"
  pathcutter check --baseline baseline.pcsnap --powershell deploy.ps1 --html review.html
  pathcutter check --baseline baseline.pcsnap --changes ad-changes/ --policy policy.json \\
                   --markdown comment.md --sarif check.sarif --fail-on review
  pathcutter check --baseline baseline.pcsnap --powershell remediation.ps1      # verify a fix script

CHANGE SYNTAX (one per line in a file, or one per --change)
""" + "\n".join("  " + line for line in VERB_HELP.splitlines()) + """

EXIT CODES   0 pass | 1 could not run | 2 blocked by policy | 3 needs review (only with --fail-on review)

FULL REFERENCE   pathcutter syntax            (changes, PowerShell coverage, edge names, policy)
"""

DETECT = """Examples:
  pathcutter detect baseline.pcsnap -o detections/                        # monitor every residual choke point
  pathcutter detect baseline.pcsnap --assume-fixed 5 --top 15 -o detections/    # I will fix the top 5; watch what remains
  pathcutter detect baseline.pcsnap --formats sigma,sentinel -o detections/
  pathcutter check --baseline baseline.pcsnap --changes ad-changes/ --policy policy.json --detections detections/
      (accepted or waived risk ships with the detections that watch it)

Output: sigma/*.yml  splunk/*.spl  sentinel/*.kql  elastic/*.kql  coverage.md  coverage.json  prerequisites.md
Read prerequisites.md first: a rule only fires if the matching Advanced Audit Policy is enabled.
"""

DOCTOR = """Examples:
  pathcutter doctor export.zip                 # verdict + what is missing + the SharpHound flag that fixes each gap
  pathcutter doctor export.zip --strict        # exit 1 on warnings too (CI: refuse to gate on a thin collection)
  pathcutter doctor export.zip --json

Exit: 0 usable, 1 errors (results would mislead) or unreadable input.
"""

ANONYMIZE = """Examples:
  pathcutter anonymize export.zip -o shareable.zip
  pathcutter anonymize export.zip -o shareable.zip --salt myteam --map private-map.json

Names, domains, domain SIDs and GUIDs become salted pseudonyms; RIDs, memberships, ACE rights and flags are kept,
so `pathcutter analyze shareable.zip` finds the same paths. Descriptions, emails, paths and password-ish attributes
are dropped. Always review before sharing: unusual free-text attributes are not guaranteed to be covered.
"""

DESCRIPTIONS = {
    "analyze": "Full analysis of a SharpHound export: risk score, attack paths, prioritised fixes with commands, HTML report.",
    "score": "Quick risk score for a SharpHound export.",
    "fix": "Generate a PowerShell remediation script for the top N fixes, with safety notes and rollback guidance.",
    "graph": "Show every attack path to one target node.",
    "diff": "Compare two SharpHound collections to verify remediation and catch regressions.",
    "export": "Machine-readable JSON with threshold gating for CI/CD (exit 2 when a threshold is exceeded).",
    "snapshot": "Save a reusable baseline (.pcsnap) from a SharpHound export so `check` runs in seconds.",
    "check": "Check proposed Active Directory changes for new attack paths to Tier 0 BEFORE they are applied.",
    "demo": "Generate a realistic lab environment, with a ready-made baseline, to try PathCutter without real data.",
    "doctor": "Inspect a SharpHound export for missing data (sessions, local groups, ACLs, ADCS) before you trust its results.",
    "anonymize": "Write a pseudonymized copy of an export that gives the same attack paths and can be shared safely.",
    "detect": "Generate detections scoped to the exact objects on the attack paths you have not fixed.",
}
EPILOGS = {"analyze": ANALYZE, "score": SCORE, "fix": FIX, "graph": GRAPH, "diff": DIFF, "export": EXPORT,
           "snapshot": SNAPSHOT, "demo": DEMO, "check": CHECK, "detect": DETECT,
           "doctor": DOCTOR, "anonymize": ANONYMIZE}
