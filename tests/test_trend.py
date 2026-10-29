"""Posture history / trend and SLA windows."""
import types

from pathcutter import trend


def _posture(score, exp_pct, exposed, total, tier0=5, paths=100, grade="C"):
    return types.SimpleNamespace(score=score, grade=grade, exposure_pct=exp_pct,
                                 tier2_with_path_count=exposed, tier2_total=total,
                                 tier0_count=tier0, total_paths=paths)


def test_sla_due():
    assert trend.sla_due("critical", "2026-10-10") == {"days": 0, "due": "2026-10-10"}
    assert trend.sla_due("high", "2026-10-10")["due"] == "2026-10-17"
    assert trend.sla_due("medium", "2026-10-10")["due"] == "2026-11-09"
    assert trend.sla_due("info", "2026-10-10") == {"days": None, "due": None}
    assert trend.sla_due("high", None) == {"days": 7, "due": None}


def test_build_record_counts_audit_by_severity():
    f = [types.SimpleNamespace(severity="high"), types.SimpleNamespace(severity="high"),
         types.SimpleNamespace(severity="medium")]
    rec = trend.build_record("2026-10-10", _posture(40, 12.5, 10, 80), f, crown_reachable=2)
    assert rec["collected"] == "2026-10-10" and rec["score"] == 40 and rec["exposed"] == 10
    assert rec["audit"] == {"high": 2, "medium": 1} and rec["crown_reachable"] == 2


def test_append_history_dedupes_by_date_and_sorts(tmp_path):
    p = tmp_path / "h.jsonl"
    trend.append_history(p, trend.build_record("2026-09-01", _posture(60, 20, 20, 100)))
    trend.append_history(p, trend.build_record("2026-10-01", _posture(40, 12, 12, 100)))
    trend.append_history(p, trend.build_record("2026-10-01", _posture(35, 10, 10, 100)))   # same date -> replace
    hist = trend.load_history(p)
    assert [r["collected"] for r in hist] == ["2026-09-01", "2026-10-01"]
    assert hist[-1]["score"] == 35                   # the replacement won


def test_render_and_summary():
    hist = [trend.build_record("2026-09-01", _posture(60, 20, 20, 100)),
            trend.build_record("2026-10-01", _posture(35, 10, 10, 100))]
    text = trend.render_trend(hist)
    assert "60 -> 35" in text and "down (better)" in text
    line = trend.summary_line(hist)
    assert "60 -> 35" in line and "down" in line
    assert trend.summary_line(hist[:1]) is None       # need at least two points
    assert "No posture history" in trend.render_trend([])
