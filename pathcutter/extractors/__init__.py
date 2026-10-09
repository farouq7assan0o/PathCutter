"""Change extractors: turn infrastructure-as-code into the same change list `pathcutter check` already judges.

Each extractor reads a file (never runs it) and returns (ChangeSpec list, ChangeWarning list). Anything it recognises as
an identity-changing construct but cannot evaluate becomes a warning (reported, can block with `fail_on_unmodeled`),
never a silent skip. To add a source: write `extract(text, origin, start_index) -> (specs, warnings)` and add one entry
to EXTRACTORS; the CLI flag, directory expansion, help and tests pick it up from this table.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class Extractor:
    name: str                       # also the --<name> CLI flag
    suffixes: tuple[str, ...]       # file types when a directory is given
    describe: str
    extract: Callable               # (text, origin, start_index) -> (list[ChangeSpec], list[ChangeWarning])


def _powershell(text, origin, start):
    from ..powershell import extract
    return extract(text, origin, start)


def _terraform(text, origin, start):
    from .terraform import extract
    return extract(text, origin, start)


def _ansible(text, origin, start):
    from .ansible import extract
    return extract(text, origin, start)


def _dsc(text, origin, start):
    from .dsc import extract
    return extract(text, origin, start)


EXTRACTORS: dict[str, Extractor] = {e.name: e for e in (
    Extractor("powershell", (".ps1", ".psm1"), "PowerShell scripts (ActiveDirectory module, dsacls, net, PowerView, ...)", _powershell),
    Extractor("terraform", (".tf", ".tf.json", ".tfplan.json", "plan.json"),
              "Terraform configuration (.tf) or `terraform show -json` plans: ad and azuread providers", _terraform),
    Extractor("ansible", (".yml", ".yaml"), "Ansible playbooks: microsoft.ad / ansible.windows / community.windows modules", _ansible),
    Extractor("dsc", (".dsc.ps1", ".configuration.ps1"),
              "PowerShell DSC configurations (ActiveDirectoryDsc / PSDscResources)", _dsc),
)}
