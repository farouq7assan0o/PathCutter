"""The deny-ACE collector script: syntax and its offline self-test, run in real PowerShell (skipped if absent)."""
import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parent.parent / "tools" / "Export-AdDenyAces.ps1"
PWSH = shutil.which("pwsh") or shutil.which("powershell")
pytestmark = pytest.mark.skipif(not PWSH, reason="PowerShell not installed")


def test_collector_parses_without_errors():
    cmd = ("$e=$null;$t=$null;[void][System.Management.Automation.Language.Parser]::ParseFile("
           f"'{SCRIPT}',[ref]$t,[ref]$e);$e.Count")
    out = subprocess.run([PWSH, "-NoProfile", "-Command", cmd], capture_output=True, text=True, timeout=60)
    assert out.stdout.strip() == "0", out.stdout + out.stderr


def test_collector_self_test_maps_rights_and_reads_a_real_descriptor():
    out = subprocess.run([PWSH, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(SCRIPT), "-SelfTest"],
                         capture_output=True, text=True, timeout=120)
    assert "SELFTEST OK" in out.stdout, out.stdout + out.stderr
