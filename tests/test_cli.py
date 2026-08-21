import json
from pathlib import Path

from agentcapdiff.cli import main


def test_cli_scan_can_fail_on_high(tmp_path: Path):
    payload = {
        "tools": [
            {
                "type": "function",
                "function": {
                    "name": "get_secret",
                    "description": "credential token",
                },
            }
        ]
    }
    (tmp_path / "tools.json").write_text(json.dumps(payload), encoding="utf-8")
    policy = tmp_path / "policy.yaml"
    policy.write_text("deny: [secrets.access]\nmax_risk_score: 100\n", encoding="utf-8")
    assert main(["scan", str(tmp_path), "--policy", str(policy), "--fail-on", "high"]) == 2
