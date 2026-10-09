"""Tests for SharpHound JSON ingestion."""
import json
import tempfile
import zipfile
from pathlib import Path

import pytest
from pathcutter.ingest import load_sharphound
from pathcutter.graph import NodeType


def _write_sharphound_files(tmpdir: Path) -> Path:
    """Create minimal SharpHound JSON files for testing."""
    users = {
        "data": [
            {
                "ObjectIdentifier": "S-1-5-21-TEST-1001",
                "Properties": {
                    "name": "ADMIN@TEST.LOCAL",
                    "domain": "TEST.LOCAL",
                    "enabled": True,
                    "admincount": True,
                },
                "Aces": [
                    {
                        "PrincipalSID": "S-1-5-21-TEST-1001",
                        "RightName": "GenericAll",
                        "IsInherited": False,
                    }
                ],
            },
            {
                "ObjectIdentifier": "S-1-5-21-TEST-1002",
                "Properties": {
                    "name": "JDOE@TEST.LOCAL",
                    "domain": "TEST.LOCAL",
                    "enabled": True,
                },
                "Aces": [],
            },
        ],
        "meta": {"type": "users", "count": 2, "version": 5},
    }

    groups = {
        "data": [
            {
                "ObjectIdentifier": "S-1-5-21-TEST-512",
                "Properties": {
                    "name": "DOMAIN ADMINS@TEST.LOCAL",
                    "domain": "TEST.LOCAL",
                    "admincount": True,
                },
                "Aces": [],
                "Members": [
                    {"MemberId": "S-1-5-21-TEST-1001", "MemberType": "User"},
                ],
            },
            {
                "ObjectIdentifier": "S-1-5-21-TEST-1100",
                "Properties": {
                    "name": "HELPDESK@TEST.LOCAL",
                    "domain": "TEST.LOCAL",
                },
                "Aces": [
                    {
                        "PrincipalSID": "S-1-5-21-TEST-1002",
                        "RightName": "ForceChangePassword",
                        "IsInherited": False,
                    }
                ],
                "Members": [
                    {"MemberId": "S-1-5-21-TEST-1002", "MemberType": "User"},
                ],
            },
        ],
        "meta": {"type": "groups", "count": 2, "version": 5},
    }

    computers = {
        "data": [
            {
                "ObjectIdentifier": "S-1-5-21-TEST-2001",
                "Properties": {
                    "name": "DC01.TEST.LOCAL",
                    "domain": "TEST.LOCAL",
                    "unconstraineddelegation": False,
                },
                "Aces": [],
                "LocalAdmins": [
                    {"MemberId": "S-1-5-21-TEST-512"},
                ],
                "Sessions": [
                    {"UserId": "S-1-5-21-TEST-1001"},
                ],
                "RemoteDesktopUsers": [],
                "PSRemoteUsers": [],
                "DcomUsers": [],
            },
        ],
        "meta": {"type": "computers", "count": 1, "version": 5},
    }

    # Write files
    (tmpdir / "test_users.json").write_text(json.dumps(users), encoding="utf-8")
    (tmpdir / "test_groups.json").write_text(json.dumps(groups), encoding="utf-8")
    (tmpdir / "test_computers.json").write_text(json.dumps(computers), encoding="utf-8")

    return tmpdir


def test_load_from_directory(tmp_path):
    data_dir = _write_sharphound_files(tmp_path)
    graph = load_sharphound(data_dir)

    assert graph.node_count == 5  # 2 users + 2 groups + 1 computer
    assert graph.edge_count > 0


def test_nodes_parsed_correctly(tmp_path):
    data_dir = _write_sharphound_files(tmp_path)
    graph = load_sharphound(data_dir)

    admin = graph.get_node("S-1-5-21-TEST-1001")
    assert admin is not None
    assert admin.name == "ADMIN@TEST.LOCAL"
    assert admin.node_type == NodeType.USER
    assert admin.domain == "TEST.LOCAL"
    assert admin.enabled is True


def test_group_membership_edges(tmp_path):
    data_dir = _write_sharphound_files(tmp_path)
    graph = load_sharphound(data_dir)

    # admin should be MemberOf Domain Admins
    succs = graph.successors("S-1-5-21-TEST-1001")
    assert "S-1-5-21-TEST-512" in succs

    # jdoe should be MemberOf HelpDesk
    succs = graph.successors("S-1-5-21-TEST-1002")
    assert "S-1-5-21-TEST-1100" in succs


def test_ace_edges(tmp_path):
    data_dir = _write_sharphound_files(tmp_path)
    graph = load_sharphound(data_dir)

    # an ACE a principal holds on itself is dropped (BloodHound does the same)
    edges = graph.out_edges("S-1-5-21-TEST-1001")
    edge_types = [d["edge_type"] for _, _, d in edges]
    assert "GenericAll" not in edge_types

    # jdoe has ForceChangePassword on HelpDesk (from ACE on group object)
    edges = graph.out_edges("S-1-5-21-TEST-1002")
    edge_types = [d["edge_type"] for _, _, d in edges]
    assert "ForceChangePassword" in edge_types


def test_local_admin_edges(tmp_path):
    data_dir = _write_sharphound_files(tmp_path)
    graph = load_sharphound(data_dir)

    # DA group should be AdminTo DC01
    edges = graph.out_edges("S-1-5-21-TEST-512")
    targets_with_type = [(v, d["edge_type"]) for _, v, d in edges]
    assert ("S-1-5-21-TEST-2001", "AdminTo") in targets_with_type


def test_session_edges(tmp_path):
    data_dir = _write_sharphound_files(tmp_path)
    graph = load_sharphound(data_dir)

    # admin has a session on DC01: the edge runs computer -> user (whoever controls DC01 can harvest it)
    edges = graph.out_edges("S-1-5-21-TEST-2001")
    has_session = any(d["edge_type"] == "HasSession" and v == "S-1-5-21-TEST-1001" for _, v, d in edges)
    assert has_session
    assert not any(d["edge_type"] == "HasSession" for _, _, d in graph.out_edges("S-1-5-21-TEST-1001"))


def test_tier0_classified(tmp_path):
    data_dir = _write_sharphound_files(tmp_path)
    graph = load_sharphound(data_dir)

    # Domain Admins should be Tier 0
    assert "S-1-5-21-TEST-512" in graph.tier0_nodes
    # admin (member of DA) should be Tier 0
    assert "S-1-5-21-TEST-1001" in graph.tier0_nodes
    # jdoe should NOT be Tier 0
    assert "S-1-5-21-TEST-1002" not in graph.tier0_nodes


def test_load_from_zip(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    _write_sharphound_files(data_dir)

    zip_path = tmp_path / "sharphound.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        for f in data_dir.glob("*.json"):
            zf.write(f, f.name)

    graph = load_sharphound(zip_path)
    assert graph.node_count == 5
    assert graph.edge_count > 0


def test_invalid_path():
    with pytest.raises(ValueError):
        load_sharphound(Path("nonexistent.txt"))


def test_empty_directory(tmp_path):
    graph = load_sharphound(tmp_path)
    assert graph.node_count == 0


def test_malformed_json_skipped(tmp_path):
    (tmp_path / "bad_users.json").write_text("not valid json {{{", encoding="utf-8")
    graph = load_sharphound(tmp_path)
    assert graph.node_count == 0  # no crash


def test_summary_after_ingest(tmp_path):
    data_dir = _write_sharphound_files(tmp_path)
    graph = load_sharphound(data_dir)

    s = graph.summary()
    assert s["total_nodes"] == 5
    assert "User" in s["node_types"]
    assert "Group" in s["node_types"]
    assert "Computer" in s["node_types"]
    assert s["tier_0_count"] >= 2  # DA group + admin user
