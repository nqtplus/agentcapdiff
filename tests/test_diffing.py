import json
from pathlib import Path

from agentcapdiff.diffing import compare_snapshots


def test_snapshot_diff(tmp_path: Path):
    a = tmp_path / "a.json"
    b = tmp_path / "b.json"
    a_payload = {
        "risk_score": 10,
        "max_severity": "INFO",
        "capabilities": ["filesystem.read"],
        "tools": ["read_file"],
        "findings": [],
    }
    b_payload = {
        "risk_score": 45,
        "max_severity": "MEDIUM",
        "capabilities": ["filesystem.read", "shell.execute"],
        "tools": ["read_file", "shell_execute"],
        "findings": [
            {
                "severity": "MEDIUM",
                "rule_id": "capability.review_required",
                "message": "Capability requires human review: shell.execute",
                "capability": "shell.execute",
                "tool": "shell_execute",
            }
        ],
    }
    a.write_text(json.dumps(a_payload), encoding="utf-8")
    b.write_text(json.dumps(b_payload), encoding="utf-8")
    diff = compare_snapshots(a, b)
    assert diff["capabilities_added"] == ["shell.execute"]
    assert diff["risk_delta"] == 35
    assert diff["base_risk_score"] == 10
    assert diff["head_risk_score"] == 45
    assert diff["head_max_severity"] == "MEDIUM"
    assert len(diff["head_findings"]) == 1


def test_snapshot_diff_is_backward_compatible(tmp_path: Path):
    a = tmp_path / "a.json"
    b = tmp_path / "b.json"
    a.write_text('{"risk_score": 0, "capabilities": [], "tools": []}')
    b.write_text('{"risk_score": 0, "capabilities": [], "tools": []}')
    diff = compare_snapshots(a, b)
    assert diff["head_findings"] == []
    assert diff["head_max_severity"] == "INFO"
