from pathlib import Path

import pytest
import yaml

from agentcapdiff.cli import main
from agentcapdiff.policy import load_policy


def test_malformed_policy_yaml_fails_closed_through_cli(tmp_path: Path, capsys) -> None:
    source = tmp_path / "input"
    source.mkdir()
    policy = tmp_path / "agentcapdiff.yml"
    policy.write_text("deny: [", encoding="utf-8")

    assert main(["scan", str(source), "--policy", str(policy), "--fail-on", "never"]) == 3
    stderr = capsys.readouterr().err
    assert "unsafe or invalid scan input/policy" in stderr
    assert "Policy YAML is malformed" in stderr


def test_oversized_policy_file_is_rejected_before_parsing(tmp_path: Path) -> None:
    policy = tmp_path / "agentcapdiff.yml"
    policy.write_text("note: " + ("x" * 300_000), encoding="utf-8")

    with pytest.raises(ValueError, match="Policy file exceeds"):
        load_policy(policy)


def test_policy_structure_depth_is_bounded(tmp_path: Path) -> None:
    nested: object = {"leaf": True}
    for _ in range(70):
        nested = {"nested": nested}
    policy = tmp_path / "agentcapdiff.yml"
    policy.write_text(yaml.safe_dump({"metadata": nested}), encoding="utf-8")

    with pytest.raises(ValueError, match="Policy nesting exceeds depth limit"):
        load_policy(policy)


def test_policy_inheritance_has_aggregate_file_budget(tmp_path: Path) -> None:
    parents = []
    for index in range(65):
        name = f"parent-{index}.yml"
        parents.append(name)
        (tmp_path / name).write_text("deny: []\n", encoding="utf-8")

    policy = tmp_path / "agentcapdiff.yml"
    policy.write_text(yaml.safe_dump({"extends": parents}), encoding="utf-8")

    with pytest.raises(ValueError, match="Policy inheritance exceeds file limit"):
        load_policy(policy)
