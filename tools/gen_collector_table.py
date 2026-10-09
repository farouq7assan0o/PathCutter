"""Regenerate the GUID table inside tools/Export-AdDenyAces.ps1 from pathcutter/data/rights.json.

    python tools/gen_collector_table.py          # rewrite the block
    python tools/gen_collector_table.py --check  # exit 1 if the script is out of date (used by tests)
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from pathcutter import rights  # noqa: E402

PS1 = ROOT / "tools" / "Export-AdDenyAces.ps1"
BEGIN = "# BEGIN GENERATED (tools/gen_collector_table.py from pathcutter/data/rights.json)"
END = "# END GENERATED"


def block() -> str:
    ids = rights.deny_collector_ids()
    width = max(len(v) for v in ids.values())
    rows = "\n".join(f"    {v.ljust(width)} = '{g}'" for g, v in ids.items())
    return f"{BEGIN}\n$Ids = @{{\n{rows}\n}}\n{END}"


def current(text: str) -> str:
    m = re.search(re.escape(BEGIN) + r".*?" + re.escape(END), text, re.S)
    return m.group(0) if m else ""


def main() -> int:
    text = PS1.read_text(encoding="utf-8")
    new = block()
    nl = "\r\n" if "\r\n" in text else "\n"
    norm = text.replace("\r\n", "\n")
    if current(norm) == new:
        print("collector table is current")
        return 0
    if "--check" in sys.argv:
        print("collector table is OUT OF DATE: run python tools/gen_collector_table.py")
        return 1
    if BEGIN in norm:
        norm = norm.replace(current(norm), new)
    else:
        norm = re.sub(r"\$Ids = @\{.*?\n\}", lambda m: new, norm, count=1, flags=re.S)
    PS1.write_text(norm.replace("\n", nl), encoding="utf-8", newline="")
    print("collector table regenerated")
    return 0


if __name__ == "__main__":
    sys.exit(main())
