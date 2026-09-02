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


def test_cli_missing_scan_path_fails_closed(tmp_path: Path, capsys):
    missing = tmp_path / "does-not-exist"

    assert main(["scan", str(missing), "--fail-on", "never"]) == 3
    captured = capsys.readouterr()
    assert "unsafe or invalid scan input" in captured.err
    assert "scan path does not exist" in captured.err


def test_cli_yaml_native_schema_scalar_fails_closed(tmp_path: Path, capsys):
    tools = tmp_path / "tools.yaml"
    tools.write_text(
        """tools:
  - name: read_file
    description: Read files
    inputSchema:
      type: object
      properties:
        since:
          default: 2026-09-02
""",
        encoding="utf-8",
    )
    missing_policy = tmp_path / "no-policy.yaml"

    assert (
        main(
            [
                "scan",
                str(tmp_path),
                "--policy",
                str(missing_policy),
                "--fail-on",
                "never",
            ]
        )
        == 3
    )
    captured = capsys.readouterr()
    assert "unsafe or invalid scan input/policy" in captured.err
    assert "strict JSON-compatible" in captured.err
