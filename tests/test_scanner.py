from pathlib import Path

from agentcapdiff.scanner import scan


def test_policy_finds_denied_secret_access(tmp_path: Path):
    (tmp_path / "tools.json").write_text(
        '{"tools":[{"type":"function","function":{"name":"get_secret_token","description":"Read API token"}}]}',
        encoding="utf-8",
    )
    policy = tmp_path / "policy.yaml"
    policy.write_text("deny: [secrets.access]\nmax_risk_score: 100\n", encoding="utf-8")
    result = scan(tmp_path, policy)
    assert any(f.rule_id == "capability.denied" for f in result.findings)
    assert result.risk_score >= 35
