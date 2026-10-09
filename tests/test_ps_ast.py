"""Cross-check our PowerShell static analysis against the REAL PowerShell parser.

For every script in tests/data/ps_corpus, the real AST tells us which cmdlet calls exist and on which lines.
Two properties must hold:
  * nothing is invented: every change or warning we report points at a line where the real parser sees a call
    to a cmdlet we claim to understand (or at a `# pc:` directive);
  * nothing is silently dropped: every real call to a cmdlet we claim to understand ends up as a change or a
    warning, never as nothing (except -WhatIf calls, which change nothing).
Skipped when PowerShell is not installed.
"""
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from pathcutter.changes import from_powershell
from pathcutter.ps_rules import SUPPORTED

DATA = Path(__file__).parent / "data"
CORPUS = sorted((DATA / "ps_corpus").glob("*.ps1"))
PWSH = shutil.which("pwsh") or shutil.which("powershell")
pytestmark = pytest.mark.skipif(not PWSH, reason="PowerShell not installed")

_ALIASES = {"dsacls": "dsacls", "net": "net"}


def real_commands(path: Path) -> dict:
    out = subprocess.run([PWSH, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(DATA / "ps_ast_commands.ps1"), str(path)],
                         capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


_METHODS = {".addaccessrule", ".removeaccessrule", ".removeaccessrulespecific", ".setaccessrule", ".purgeaccessrules",
            ".setowner", ".removeaccessruleall"}
_PLUMBING = {"get-acl", "set-acl"}      # building and committing an ACL; the effect is reported at the rule lines


def supported(name: str | None) -> bool:
    return bool(name) and (name.lower() in SUPPORTED or name.lower() in _METHODS)


def lines_of(items, origin_prefix) -> set[int]:
    got = set()
    for it in items:
        origin = getattr(it, "origin", "")
        m = re.search(r":(\d+)$", origin)
        if m:
            got.add(int(m.group(1)))
    return got


@pytest.mark.parametrize("script", CORPUS, ids=lambda p: p.name)
def test_every_script_parses_cleanly_in_real_powershell(script):
    assert real_commands(script)["errors"] == 0


@pytest.mark.parametrize("script", CORPUS, ids=lambda p: p.name)
def test_nothing_is_invented(script):
    text = script.read_text(encoding="utf-8")
    ast = real_commands(script)["commands"]
    ast = ast if isinstance(ast, list) else [ast]
    spans = [(c["start"], c["end"]) for c in ast if supported(c["name"])]
    specs, warns = from_powershell(text, script.name)
    for line in lines_of(specs, script.name) | lines_of(warns, script.name):
        assert any(a <= line <= b for a, b in spans), f"{script.name}:{line} reported but the real parser sees no supported command there"


@pytest.mark.parametrize("script", CORPUS, ids=lambda p: p.name)
def test_nothing_is_silently_dropped(script):
    text = script.read_text(encoding="utf-8").splitlines()
    ast = real_commands(script)["commands"]
    ast = ast if isinstance(ast, list) else [ast]
    specs, warns = from_powershell("\n".join(text), script.name)
    reported = lines_of(specs, script.name) | lines_of(warns, script.name)
    missing = []
    for c in ast:
        if not supported(c["name"]) or c["name"].lower() in _PLUMBING:
            continue
        block = "\n".join(text[c["start"] - 1:c["end"]])
        if re.search(r"-WhatIf\b", block, re.I):
            continue
        if not any(c["start"] <= ln <= c["end"] for ln in reported):
            missing.append(f"{c['name']} at line {c['start']}")
    assert not missing, f"{script.name}: real calls we understand but reported nothing for: {missing}"
