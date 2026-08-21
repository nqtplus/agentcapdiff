import json
from pathlib import Path

from agentcapdiff.diffing import compare_snapshots


def test_snapshot_diff(tmp_path: Path):
    a = tmp_path / "a.json"
    b = tmp_path / "b.json"
    a.write_text(json.dumps({"risk_score": 10, "capabilities": ["filesystem.read"], "tools": ["read_file"]}))
    b.write_text(json.dumps({"risk_score": 45, "capabilities": ["filesystem.read", "shell.execute"], "tools": ["read_file", "shell_execute"]}))
    diff = compare_snapshots(a, b)
    assert diff["capabilities_added"] == ["shell.execute"]
    assert diff["risk_delta"] == 35
