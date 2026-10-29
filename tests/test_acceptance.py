"""Risk acceptance for audit findings: match, expiry, gating."""
import datetime as dt

import pytest

from pathcutter import acceptance
from pathcutter.hygiene import HygieneFinding

TODAY = dt.date(2026, 10, 30)


def _f(rule, severity="high", objects=None):
    return HygieneFinding(rule, "t", severity, "why", "fix", objects=objects or [], total=len(objects or []))


def test_parse_errors():
    with pytest.raises(acceptance.AcceptanceError):
        acceptance.parse([{"reason": "x"}])                      # no rule
    with pytest.raises(acceptance.AcceptanceError):
        acceptance.parse([{"rule": "r", "expires": "not-a-date"}])


def test_valid_acceptance_marks_and_delists_from_gate():
    f = _f("machine-account-quota")
    accs = acceptance.parse([{"rule": "machine-account-quota", "reason": "ticket OPS-1", "owner": "ad", "expires": "2027-01-01"}])
    acceptance.apply([f], accs, today=TODAY)
    assert f.accepted and f.accepted["status"] == "accepted" and f.accepted["owner"] == "ad"
    assert acceptance.is_live(f) is False                        # accepted -> does not gate


def test_expired_acceptance_resurfaces_and_gates():
    f = _f("tier0-exposed-on-lower-tier", severity="critical")
    accs = acceptance.parse([{"rule": "tier0-exposed-on-lower-tier", "reason": "x", "expires": "2026-01-01"}])
    acceptance.apply([f], accs, today=TODAY)
    assert f.accepted["status"] == "expired"
    assert acceptance.is_live(f) is True                         # expired -> still gates


def test_object_filter():
    f1 = _f("weak-kerberos-enc-spn", objects=["SVC-LEGACY"])
    f2 = _f("weak-kerberos-enc-spn", objects=["SVC-MODERN"])
    accs = acceptance.parse([{"rule": "weak-kerberos-enc-spn", "object": "legacy", "reason": "vendor"}])
    acceptance.apply([f1, f2], accs, today=TODAY)
    assert f1.accepted and f1.accepted["status"] == "accepted"
    assert f2.accepted is None                                   # object did not match


def test_no_expiry_is_accepted_but_noted():
    f = _f("old-os")
    acceptance.apply([f], acceptance.parse([{"rule": "old-os", "reason": "eol lab"}]), today=TODAY)
    assert f.accepted["status"] == "accepted" and f.accepted["expires"] is None
