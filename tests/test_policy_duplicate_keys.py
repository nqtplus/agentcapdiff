from pathlib import Path

import pytest

from agentcapdiff.cli import main
from agentcapdiff.policy import load_policy


def test_duplicate_root_policy_key_is_rejected(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        "deny: [shell.execute]\ndeny: []\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Policy YAML is malformed"):
        load_policy(policy)


def test_quoted_and_unquoted_duplicate_policy_key_is_rejected(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        "'require_review': [network.external]\n"
        "require_review: []\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Policy YAML is malformed"):
        load_policy(policy)


def test_duplicate_nested_tool_selector_is_rejected(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        "allow_by_tool:\n"
        "  repo_tool: [github.write]\n"
        "  repo_tool: []\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Policy YAML is malformed"):
        load_policy(policy)


def test_duplicate_key_in_inherited_policy_is_rejected(tmp_path: Path) -> None:
    parent = tmp_path / "parent.yaml"
    parent.write_text(
        "max_risk_score: 20\nmax_risk_score: 100\n",
        encoding="utf-8",
    )
    child = tmp_path / "policy.yaml"
    child.write_text("extends: parent.yaml\n", encoding="utf-8")

    with pytest.raises(ValueError, match="Policy YAML is malformed"):
        load_policy(child)


def test_yaml_merge_with_explicit_override_keeps_existing_precedence(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        "defaults: &defaults\n"
        "  max_risk_score: 20\n"
        "<<: *defaults\n"
        "max_risk_score: 50\n",
        encoding="utf-8",
    )

    loaded = load_policy(policy)

    assert loaded.max_risk_score == 50


def test_cli_duplicate_policy_key_fails_closed(tmp_path: Path, capsys) -> None:
    source = tmp_path / "input"
    source.mkdir()
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        "deny: [shell.execute]\ndeny: []\n",
        encoding="utf-8",
    )

    assert main(["scan", str(source), "--policy", str(policy), "--fail-on", "never"]) == 3
    stderr = capsys.readouterr().err
    assert "unsafe or invalid scan input/policy" in stderr
    assert "Policy YAML is malformed" in stderr
