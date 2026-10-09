"""Several collections of one environment merge into one graph; sessions remember how often they were seen."""
import json
import zipfile

from pathcutter.cli import main
from pathcutter.exposure import compute_exposure
from pathcutter.ingest import load_sharphound
from pathcutter.toolkit import diagnose

SID = "S-1-5-21-1-2-3"


def collection(tmp_path, name, sessions, users=("alice", "bob"), extra_groups=()):
    z = tmp_path / name
    obj = lambda rid, n, **kw: {"ObjectIdentifier": f"{SID}-{rid}", "Properties": {"name": f"{n}@CORP.LOCAL", "domain": "CORP.LOCAL"}, **kw}   # noqa: E731
    comps = [{"ObjectIdentifier": f"{SID}-2001", "Properties": {"name": "PC1.CORP.LOCAL", "domain": "CORP.LOCAL"},
              "Sessions": {"Results": [{"UserSID": f"{SID}-{rid}", "ComputerSID": f"{SID}-2001"} for rid in sessions], "Collected": True}},
             {"ObjectIdentifier": f"{SID}-2002", "Properties": {"name": "PC2.CORP.LOCAL", "domain": "CORP.LOCAL"}}]
    ulist = [obj(1105 + i, u) for i, u in enumerate(users)]
    groups = [obj(512, "DOMAIN ADMINS", Members=[{"ObjectIdentifier": f"{SID}-1106", "ObjectType": "User"}])] + list(extra_groups)
    with zipfile.ZipFile(z, "w") as zf:
        for n, items in (("users", ulist), ("computers", comps), ("groups", groups)):
            zf.writestr(f"1_{n}.json", json.dumps({"meta": {"type": n, "version": 4}, "data": items}))
    return z


def sess(g):
    return {(g.get_node(u).display_name, g.get_node(v).display_name): d.get("seen") for u, v, d in g.all_edges() if d["edge_type"] == "HasSession"}


def test_sessions_count_the_collections_that_saw_them(tmp_path):
    a = collection(tmp_path, "a.zip", [1105])
    b = collection(tmp_path, "b.zip", [1105, 1106])
    g = load_sharphound([a, b])
    assert g.meta["collections"] == 2
    seen = sess(g)
    assert seen == {("PC1.CORP.LOCAL", "alice"): 2, ("PC1.CORP.LOCAL", "bob"): 1}


def test_union_finds_paths_neither_collection_has_alone(tmp_path):
    a = collection(tmp_path, "a.zip", [])                       # no sessions: PC1 is a dead end
    b = collection(tmp_path, "b.zip", [1106])                   # BOB (a Domain Admin) was logged on at PC1
    ga, gb, gm = load_sharphound(a), load_sharphound(b), load_sharphound([a, b])
    pc1 = f"{SID}-2001"
    assert pc1 not in compute_exposure(ga).exposed() and pc1 in compute_exposure(gb).exposed()
    assert pc1 in compute_exposure(gm).exposed() and gm.node_count == ga.node_count


def test_single_input_list_behaves_like_a_path(tmp_path):
    a = collection(tmp_path, "a.zip", [1105])
    assert sess(load_sharphound([a])) == sess(load_sharphound(a))
    assert "collections" not in load_sharphound(a).meta


def test_doctor_reports_single_moment_sessions_and_merges(tmp_path, capsys):
    a = collection(tmp_path, "a.zip", [1105])
    b = collection(tmp_path, "b.zip", [1105, 1106])
    assert any("single collection" in f[1] for f in diagnose(a)["findings"])
    r = diagnose([a, b])
    assert r["collections"] == 2 and r["sessions"] == {"edges": 2, "seen_once": 1}
    assert not any("single collection" in f[1] for f in r["findings"])
    assert main(["doctor", str(a), "--also", str(b)]) in (0, 1)
    assert "merged:   2 collections" in capsys.readouterr().out


def test_snapshot_accepts_also(tmp_path):
    a = collection(tmp_path, "a.zip", [1105])
    b = collection(tmp_path, "b.zip", [1106])
    out = tmp_path / "m.pcsnap"
    assert main(["snapshot", str(a), "--also", str(b), "-o", str(out)]) == 0
    from pathcutter.snapshot import load_snapshot
    g, _ = load_snapshot(out)
    assert set(sess(g)) == {("PC1.CORP.LOCAL", "alice"), ("PC1.CORP.LOCAL", "bob")}
    assert {v for v in sess(g).values()} == {1}
