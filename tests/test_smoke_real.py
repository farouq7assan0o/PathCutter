"""Every command on every real fixture: nothing may crash, whatever the data looks like."""
from pathlib import Path

import pytest

from pathcutter.cli import main

DATA = Path(__file__).parent / "data"
FIXTURES = sorted(list((DATA / "real").glob("*.zip")) + list((DATA / "vendor").glob("*.zip")))
pytestmark = pytest.mark.skipif(not FIXTURES, reason="fixtures missing")


@pytest.mark.parametrize("zip_path", FIXTURES, ids=lambda p: p.name[:24])
def test_every_command_runs(zip_path, tmp_path, capsys):
    snap = tmp_path / "b.pcsnap"
    assert main(["snapshot", str(zip_path), "-o", str(snap)]) == 0
    assert main(["doctor", str(zip_path)]) in (0, 1)
    assert main(["audit", str(zip_path), "--min-severity", "info"]) == 0
    assert main(["score", str(zip_path)]) == 0
    assert main(["analyze", str(zip_path), "--top", "3", "-o", str(tmp_path / "out"), "--html", "--json", "--markdown"]) == 0
    assert main(["export", str(zip_path), "--compact"]) == 0
    assert main(["detect", str(snap), "-o", str(tmp_path / "det"), "--assume-fixed", "2"]) == 0
    assert main(["anonymize", str(zip_path), "-o", str(tmp_path / "anon.zip")]) == 0
    assert main(["doctor", str(tmp_path / "anon.zip")]) in (0, 1)
    capsys.readouterr()


@pytest.mark.parametrize("zip_path", FIXTURES, ids=lambda p: p.name[:24])
def test_check_with_a_real_group_and_user(zip_path, tmp_path, capsys):
    from pathcutter.ingest import load_sharphound
    from pathcutter.graph import NodeType
    g = load_sharphound(zip_path)
    users = [n for n in g.nodes_by_type(NodeType.USER) if n.display_name.upper() not in ("KRBTGT", "GUEST")]
    groups = [n for n in g.nodes_by_type(NodeType.GROUP) if n.object_id not in g.tier0_nodes and "@" in n.name]
    if not users or not groups:
        pytest.skip("fixture has no ordinary users or groups")
    u, grp = users[0], groups[0]
    code = main(["check", "--baseline", str(zip_path), "--change", f'add-member "{u.name}" "{grp.name}"', "--fail-on", "never",
                 "--json", str(tmp_path / "r.json"), "--html", str(tmp_path / "r.html")])
    assert code == 0 and (tmp_path / "r.html").exists()
    capsys.readouterr()
