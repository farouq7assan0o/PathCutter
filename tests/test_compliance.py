"""Compliance mapping: findings carry control references, and the rollup groups them per framework."""
from pathcutter import compliance
from pathcutter.hygiene import HygieneFinding


def _f(rule, sev="high"):
    return HygieneFinding(rule, "t", sev, "why", "fix")


def test_known_finding_gets_control_refs():
    f = _f("tier0-exposed-on-lower-tier", "critical")
    compliance.tag([f])
    assert f.compliance and "AC-6(5)" in f.compliance["nist"]
    assert any("Access Control" in c for c in f.compliance["cis"])
    assert "Restrict administrative privileges" in f.compliance["e8"]
    assert isinstance(f.compliance["stig"], str) and f.compliance["stig"]


def test_unknown_finding_is_not_tagged():
    f = _f("azure-roles-unevaluated", "info")
    compliance.tag([f])
    assert f.compliance is None


def test_rollup_groups_and_counts():
    findings = [_f("tier0-exposed-on-lower-tier", "critical"), _f("ea-sa-populated"), _f("weak-kerberos-enc-privileged")]
    r = compliance.rollup(findings)
    nist = {row["control"]: row["count"] for row in r["nist"]}
    assert nist["AC-6(5)"] == 3                           # all three map to AC-6(5)
    e8 = {row["control"]: row["count"] for row in r["e8"]}
    assert e8["Restrict administrative privileges"] == 3
    # rows are sorted most-implicated first
    assert r["nist"][0]["control"] == "AC-6(5)"


def test_render_mentions_frameworks():
    text = compliance.render([_f("machine-account-quota", "medium")])
    assert "NIST SP 800-53 Rev5" in text and "CIS Controls v8" in text and "Essential Eight" in text


def test_every_mapped_rule_has_all_framework_keys():
    for rule, m in compliance.MAP.items():
        assert set(m) == {"nist", "cis", "e8", "stig"}, rule
        assert isinstance(m["stig"], str) and m["stig"]
