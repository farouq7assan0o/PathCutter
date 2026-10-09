"""doctor and anonymize, proven on real collector output."""
import json
import zipfile
from collections import Counter
from pathlib import Path

import pytest

from pathcutter.cli import main
from pathcutter.exposure import compute_exposure
from pathcutter.ingest import load_sharphound
from pathcutter.toolkit import diagnose, iter_raw

DATA = Path(__file__).parent / "data" / "real"
ZIPS = sorted(DATA.glob("*.zip"))
pytestmark = pytest.mark.skipif(not ZIPS, reason="real datasets not present")


def fingerprint(g):
    e = compute_exposure(g)
    return {
        "nodes": Counter(n.node_type.value for n in g.all_nodes()),
        "edges": Counter(d.get("edge_type") for _, _, d in g.all_edges()),
        "tier0": len(g.tier0_nodes),
        "hops": Counter(e.hops(n) for n in e.exposed()),
        "exposed": len(e.exposed()),
        "admin_count": sum(1 for n in g.all_nodes() if n.admin_count),
        "enabled": sum(1 for n in g.all_nodes() if n.enabled),
    }


@pytest.mark.parametrize("src", ZIPS, ids=lambda p: p.name[:12])
def test_anonymized_copy_has_identical_attack_paths(src, tmp_path):
    out = tmp_path / "anon.zip"
    assert main(["anonymize", str(src), "-o", str(out), "--salt", "t"]) == 0
    assert fingerprint(load_sharphound(src)) == fingerprint(load_sharphound(out))


@pytest.mark.parametrize("src", ZIPS, ids=lambda p: p.name[:12])
def test_anonymized_copy_leaks_no_names_or_free_text(src, tmp_path):
    out = tmp_path / "anon.zip"
    main(["anonymize", str(src), "-o", str(out), "--salt", "t"])
    blob = "".join(json.dumps(d) for _, d in iter_raw(out)).upper()
    g = load_sharphound(src)
    import re
    from pathcutter.toolkit import _KEEP_WORDS
    from pathcutter.ingest import _ACE_MAP
    rights = {r.upper() for r in _ACE_MAP}              # a group named like an ACE right is fine: the right name is protected
    names = {n.display_name.split(".")[0].upper() for n in g.all_nodes()
             if n.node_type.value in ("User", "Computer", "Group") and not re.search(r"-\d{1,3}$", n.object_id)}
    leaked = [x for x in names if x not in _KEEP_WORDS and x not in rights and len(x) > 3
              and re.search(r"(?<![A-Z0-9_-])" + re.escape(x) + r"(?![A-Z0-9_-])", blob)][:5]
    assert not [e for e, _ in iter_raw(out) if any(d[:6] in e.upper() for d in domains_of(g))], "file names leak the domain"
    domains = {n.name.upper() for n in g.nodes_by_type(__import__("pathcutter.graph", fromlist=["NodeType"]).NodeType.DOMAIN)}
    assert not [d for d in domains if d in blob], "a real domain name survived"
    for _, d in iter_raw(src):
        for o in d.get("data", []):
            for k in ("description", "email", "homedirectory"):
                v = (o.get("Properties") or {}).get(k)
                if isinstance(v, str) and len(v) > 12:
                    assert v.upper() not in blob, f"{k} leaked"
    assert not leaked, leaked
    sids = {n.object_id.rsplit("-", 1)[0] for n in g.all_nodes() if n.object_id.startswith("S-1-5-21-")}
    assert not [s for s in sids if s in blob], "a real domain SID survived"


def domains_of(g):
    return {n.name.upper() for n in g.all_nodes() if n.node_type.value == "Domain"}


def test_anonymize_is_deterministic_per_salt_and_differs_across_salts(tmp_path):
    a, b, c = (tmp_path / f"{i}.zip" for i in "abc")
    main(["anonymize", str(ZIPS[0]), "-o", str(a), "--salt", "x"])
    main(["anonymize", str(ZIPS[0]), "-o", str(b), "--salt", "x"])
    main(["anonymize", str(ZIPS[0]), "-o", str(c), "--salt", "y"])
    read = lambda p: zipfile.ZipFile(p).read(zipfile.ZipFile(p).namelist()[0])  # noqa: E731
    assert read(a) == read(b) and read(a) != read(c)


def test_doctor_reports_real_blind_spots_honestly():
    r = diagnose(DATA / "specterops_ad_sampledata.zip")
    assert r["computers"]["total"] == 34 and r["computers"]["sessions"] < 34
    whats = " ".join(w for _, w, _ in r["findings"])
    assert "sessions collected on only" in whats and "local groups collected on only" in whats
    assert not [f for f in r["findings"] if f[0] == "ERROR"]


def test_doctor_exit_codes(tmp_path, capsys):
    assert main(["doctor", str(ZIPS[0])]) == 0
    assert main(["doctor", str(ZIPS[0]), "--strict"]) in (0, 1)
    bad = tmp_path / "empty"
    bad.mkdir()
    assert main(["doctor", str(bad)]) == 1
    assert "NOT TRUSTWORTHY" in capsys.readouterr().out


def test_doctor_json_is_valid(capsys):
    main(["doctor", str(ZIPS[0]), "--json"])
    assert "findings" in json.loads(capsys.readouterr().out)
