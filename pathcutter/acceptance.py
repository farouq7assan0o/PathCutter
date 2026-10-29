"""Risk acceptance for `audit`: the running report stops nagging about a finding the org has formally accepted, but
records who accepted it, why, and until when - and resurfaces it the moment the acceptance expires.

`check` already has waivers for proposed changes; this is the same idea for the standing hygiene findings. An acceptance
file lists entries keyed by finding rule (optionally narrowed to objects), each with a reason, an owner and an optional
expiry. It is governance, not a fix: an accepted finding still exists, so it is shown, labelled, and left out of the
`--fail-on` gate only while the acceptance is valid. Nothing is accepted silently and nothing is accepted forever by
accident - an entry with no expiry is reported as such.

File shape (bare list or under "accepted"):
  {"accepted": [
     {"rule": "machine-account-quota", "reason": "legacy join process, ticket OPS-1421", "owner": "ad-team", "expires": "2026-12-31"},
     {"rule": "weak-kerberos-enc-spn", "object": "SVC-LEGACY", "reason": "vendor app pending upgrade", "owner": "appsec"}
  ]}
"""
from __future__ import annotations

import datetime as dt
import json
from dataclasses import dataclass
from pathlib import Path


class AcceptanceError(Exception):
    pass


@dataclass
class Acceptance:
    rule: str
    reason: str = ""
    owner: str = ""
    expires: dt.date | None = None
    object: str | None = None        # optional: only accept the finding when it names this object (case-insensitive substring)


def load(path) -> list[Acceptance]:
    p = Path(path)
    try:
        data = json.loads(p.read_text(encoding="utf-8-sig"))
    except OSError as exc:
        raise AcceptanceError(f"cannot read acceptance file {p}: {exc.strerror or exc}") from None
    except json.JSONDecodeError as exc:
        raise AcceptanceError(f"{p}: invalid JSON ({exc})") from None
    return parse(data, str(p))


def parse(data, source: str = "<acceptance>") -> list[Acceptance]:
    items = data.get("accepted", data) if isinstance(data, dict) else data
    if not isinstance(items, list):
        raise AcceptanceError(f"{source}: expected a list of acceptances (or an 'accepted' key)")
    out = []
    for i, it in enumerate(items):
        if not isinstance(it, dict) or not it.get("rule"):
            raise AcceptanceError(f"{source}: entry {i} needs at least a 'rule'")
        exp = None
        if it.get("expires"):
            try:
                exp = dt.date.fromisoformat(str(it["expires"])[:10])
            except ValueError:
                raise AcceptanceError(f"{source}: entry {i} has an invalid 'expires' date (use YYYY-MM-DD)") from None
        out.append(Acceptance(rule=str(it["rule"]), reason=str(it.get("reason", "")), owner=str(it.get("owner", "")),
                              expires=exp, object=(str(it["object"]) if it.get("object") else None)))
    return out


def apply(findings, acceptances: list[Acceptance], today: dt.date | None = None) -> list:
    """Annotate findings in place with any matching acceptance (f.accepted set to status accepted / expired). Returns findings."""
    today = today or dt.date.today()
    for f in findings:
        for a in acceptances:
            if a.rule != f.rule:
                continue
            if a.object and not any(a.object.lower() in str(o).lower() for o in f.objects):
                continue
            status = "expired" if (a.expires and a.expires < today) else "accepted"
            f.accepted = {"reason": a.reason, "owner": a.owner,
                          "expires": a.expires.isoformat() if a.expires else None, "status": status}
            break
    return findings


def is_live(f) -> bool:
    """A finding still counts for gating unless it is accepted and not expired."""
    return not (f.accepted and f.accepted.get("status") == "accepted")
