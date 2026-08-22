import json
from pathlib import Path

from agentcapdiff.diffing import compare_snapshots


def test_old_snapshot_without_scopes_remains_readable(tmp_path: Path):
    base = tmp_path / "base.json"
    head = tmp_path / "head.json"
    old = {"risk_score": 10, "capabilities": ["filesystem.read"], "tools": ["read_file"]}
    base.write_text(json.dumps(old), encoding="utf-8")
    head.write_text(json.dumps(old), encoding="utf-8")
    diff = compare_snapshots(base, head)
    assert diff["scope_changes"] == []
    assert diff["scope_expansions"] == []
