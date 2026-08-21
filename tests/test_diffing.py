import json
from pathlib import Path

from agentcapdiff.diffing import compare_snapshots


def test_snapshot_diff(tmp_path: Path):
    a = tmp_path / "a.json"
    b = tmp_path / "b.json"
    a_payload = {
        "risk_score": 10,
        "capabilities": ["filesystem.read"],
        "tools": ["read_file"],
    }
    b_payload = {
        "risk_score": 45,
        "capabilities": ["filesystem.read", "shell.execute"],
        "tools": ["read_file", "shell_execute"],
    }
    a.write_text(json.dumps(a_payload), encoding="utf-8")
    b.write_text(json.dumps(b_payload), encoding="utf-8")
    diff = compare_snapshots(a, b)
    assert diff["capabilities_added"] == ["shell.execute"]
    assert diff["risk_delta"] == 35
