"""Posture over time: keep a small history of each run's risk numbers so you can prove exposure went down, not just
look at one snapshot, and attach remediation SLA windows to findings by severity.

PathCutter is otherwise point-in-time. A nightly `analyze --history posture.jsonl` appends one line per run - risk score,
Tier 0 exposure, path count, crown jewels reachable, audit counts by severity - and `pathcutter trend posture.jsonl`
renders the series with deltas, so a team can show a committee "Tier 0 exposure fell from 41% to 6% over the quarter".
Everything is plain JSON lines; no database. The history holds only aggregate numbers, never object names, so it is far
less sensitive than a snapshot.

SLA windows follow the common tiering (critical now, high 7 days, medium 30, low 90); `sla_due` turns a severity plus the
collection date into a deadline. With a history the age of a finding could be tracked too; today the window is advisory.
"""
from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

SEVERITIES = ["info", "low", "medium", "high", "critical"]
SLA_DAYS = {"critical": 0, "high": 7, "medium": 30, "low": 90, "info": None}


def sla_due(severity: str, collected: str | None) -> dict:
    """{days, due} for a finding: the remediation window and, from the collection date, the due date."""
    days = SLA_DAYS.get(severity)
    out = {"days": days, "due": None}
    if days is not None and collected:
        try:
            out["due"] = (dt.date.fromisoformat(collected[:10]) + dt.timedelta(days=days)).isoformat()
        except ValueError:
            pass
    return out


def build_record(collected: str, posture, audit_findings=None, crown_reachable=None) -> dict:
    """One posture history point. `posture` is a PostureScore; audit_findings an optional list of HygieneFinding."""
    counts: dict[str, int] = {}
    for f in audit_findings or []:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return {
        "collected": (collected or dt.date.today().isoformat())[:10],
        "generated": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "score": posture.score, "grade": posture.grade,
        "exposure_pct": round(posture.exposure_pct, 1),
        "exposed": posture.tier2_with_path_count, "tier2_total": posture.tier2_total,
        "tier0": posture.tier0_count, "paths": posture.total_paths,
        "crown_reachable": crown_reachable,
        "audit": counts,
    }


def load_history(path) -> list[dict]:
    p = Path(path)
    if not p.exists():
        return []
    out = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except ValueError:
                pass
    out.sort(key=lambda r: str(r.get("collected", "")))
    return out


def append_history(path, record: dict) -> list[dict]:
    """Append a record, replacing any existing record with the same `collected` date. Returns the full history."""
    hist = [r for r in load_history(path) if r.get("collected") != record.get("collected")]
    hist.append(record)
    hist.sort(key=lambda r: str(r.get("collected", "")))
    Path(path).write_text("\n".join(json.dumps(r) for r in hist) + "\n", encoding="utf-8")
    return hist


def _spark(values: list[float]) -> str:
    if not values:
        return ""
    blocks = "_.-=+*#"
    lo, hi = min(values), max(values)
    rng = (hi - lo) or 1
    return "".join(blocks[min(len(blocks) - 1, int((v - lo) / rng * (len(blocks) - 1)))] for v in values)


def _delta(cur, prev) -> str:
    if prev is None:
        return ""
    d = cur - prev
    return "  (=)" if d == 0 else f"  ({'+' if d > 0 else ''}{d})"


def render_trend(records: list[dict]) -> str:
    if not records:
        return "No posture history yet. Run `analyze --history <file>` on each collection to build it.\n"
    out = ["pathcutter trend", "=" * 64,
           f"{'date':<12}{'score':>7}{'grade':>7}{'exposed':>10}{'tier0':>7}{'paths':>9}"]
    prev = None
    for r in records:
        exp = f"{r.get('exposed', 0)}/{r.get('tier2_total', 0)}"
        line = f"{r.get('collected', '?'):<12}{r.get('score', 0):>7}{r.get('grade', '?'):>7}{exp:>10}{r.get('tier0', 0):>7}{r.get('paths', 0):>9}"
        line += _delta(r.get("score", 0), prev.get("score") if prev else None)
        out.append(line)
        prev = r
    first, last = records[0], records[-1]
    out.append("")
    out.append("score  " + _spark([r.get("score", 0) for r in records]) + f"   {first.get('score')} -> {last.get('score')} over {len(records)} run(s)")
    out.append("expo%  " + _spark([r.get("exposure_pct", 0) for r in records]) + f"   {first.get('exposure_pct')}% -> {last.get('exposure_pct')}%")
    direction = "down (better)" if last.get("score", 0) < first.get("score", 0) else \
                "up (worse)" if last.get("score", 0) > first.get("score", 0) else "flat"
    out.append(f"\nRisk is {direction}. SLA windows: critical now, high 7d, medium 30d, low 90d.")
    return "\n".join(out) + "\n"


def summary_line(records: list[dict]) -> str | None:
    """One line for the exec summary: movement since the previous run."""
    if len(records) < 2:
        return None
    prev, cur = records[-2], records[-1]
    ds = cur.get("score", 0) - prev.get("score", 0)
    word = "down" if ds < 0 else "up" if ds > 0 else "unchanged"
    return (f"Since {prev.get('collected')}: risk score {prev.get('score')} -> {cur.get('score')} ({word}), "
            f"Tier 0 exposure {prev.get('exposure_pct')}% -> {cur.get('exposure_pct')}%.")
